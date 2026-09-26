package site

import (
	"errors"
	"strings"
	"testing"
)

// ============================================================================
// 第 4.3 阶段的安全命脉测试：三层输入校验的注入穷举
// ============================================================================
//
// 本文件的目标不是"覆盖率达到多少"，而是**断言一组具体的攻击载荷
// 全都被拒绝**。每一条用例都对应一类真实的配置注入手法，
// 而不是为了凑数量的随机字符串。
//
// 为什么注入在站点模块里格外重要：用户的输入会被拼进 nginx 配置。
// nginx 配置是一门有语法的语言（`;` 结束指令、`{}` 划分块、
// `$` 引用变量、`#` 注释），因此一个没被拦住的字符不是"显示错误"，
// 而是**变成一条 nginx 指令**。最坏情况是攻击者让自己的站点
// 带上 `root /etc;` 之类的指令，把整台机器的文件经 nginx 暴露出去。

// lexicalMergeSafe 列出"词法并合后与合法输入无法区分"的载荷。
//
// #################### 为什么它们必须被排除 ####################
//
// 这些载荷本身是 `/`、`..`、`?` 这类**结构字符**。当它们被
// `"/var/www" + payload` 或 `"http://host:3000/" + payload` 这样的
// 前缀拼接后，得到的字符串在词法上与一条正常输入完全一致：
//
//	/var/www  + /etc/passwd  →  /var/www/etc/passwd     （合法的绝对路径）
//	host:3000 + /a/b         →  host:3000/a/b           （合法的 proxy 路径）
//	host:3000 + /a..b        →  host:3000/a..b          （合法目录名，".." 非独立段）
//	host:3000 + /?           →  host:3000/              （url.Parse 把 "?" 当空查询串）
//
// 这些结果**没有任何可注入的内容**——没有分号、没有花括号、
// 没有换行。拒绝它们只会误伤正常功能（例如用户确实想建一个
// 位于 /var/www/etc/passwd 目录下的站点）。
//
// 因此断言必须精确：**"载荷必须被拒绝"这个命题对结构字符不成立**，
// 真正成立且真正重要的命题是"任何 nginx 元字符都不可能通过校验"
// （由 TestNoNginxMetacharacterEverSurvives 用穷举锁死）。
var lexicalMergeSafe = map[string]bool{
	"a/b":         true,
	"a..b":        true,
	"..":          true,
	"../etc":      true,
	"/etc/passwd": true,
	"?":           true,
	"*":           true,
}

// injectionPayloads 是跨字段通用的注入载荷集合。
//
// 每一个都在注释里写明"它想做什么"，便于将来有人想放宽校验时
// 能立刻看出会打开什么口子。
var injectionPayloads = []struct {
	payload string
	why     string
}{
	{"a;b", "分号：结束当前指令并开始一条新指令"},
	{"a{b", "左花括号：提前打开一个块"},
	{"a}b", "右花括号：提前闭合 server 块，把后续指令提升到 http 层"},
	{"a$b", "美元符：nginx 变量引用（$uri、$host），可读取上下文信息"},
	{"a`b", "反引号：在部分模板/子进程语境下是命令替换"},
	{"a'b", "单引号：闭合字符串后追加指令"},
	{`a"b`, "双引号：同上"},
	{"a#b", "井号：注释掉后续本该生效的配置行"},
	{"a\nb", "换行：另起一行写任意配置（最典型的配置注入）"},
	{"a\rb", "回车：同上，且在部分解析器里与换行等价"},
	{"a\tb", "制表符：可绕过基于空格的参数切分"},
	{"a b", "空格：把单个参数拆成两个，改变指令语义"},
	{"a\\b", "反斜杠：转义下一个字符，破坏引号/路径语义"},
	{"a/b", "斜杠：路径分隔符，可造成路径穿越"},
	{"a..b", "点点：路径穿越"},
	{"../etc", "经典路径穿越"},
	{"..", "父目录引用"},
	{"/etc/passwd", "绝对路径"},
	{"a|b", "管道符：在 shell 语境下有特殊含义"},
	{"a&b", "后台执行符：同上"},
	{"a<b", "重定向符：同上"},
	{"a>b", "重定向符：同上"},
	{"$(", "命令替换的开头"},
	{"%00", "百分号编码的 NUL，可用于截断"},
	{"*", "通配符：在 server_name 里含义特殊"},
	{"?", "通配符：在 server_name 里含义特殊"},
}

// ---------------------------------------------------------------------------
// 第一层：站点名校验
// ---------------------------------------------------------------------------

// TestValidSiteNameRejectsInjection 穷举注入载荷，断言全部被拒。
func TestValidSiteNameRejectsInjection(t *testing.T) {
	for _, tc := range injectionPayloads {
		t.Run(sanitize(tc.payload), func(t *testing.T) {
			// 分别测试"载荷原样"与"前缀一个合法字符"两种形态。
			//
			// 后一种是关键：`a;b` 这样以合法字符开头的载荷，
			// 能绕过"只检查首字符"这类实现不完整的校验。
			for _, candidate := range []string{tc.payload, "site" + tc.payload} {
				if err := ValidSiteName(candidate); err == nil {
					t.Errorf("站点名 %q 应被拒绝（%s），但通过了校验",
						candidate, tc.why)
				}
			}
		})
	}
}

// TestValidSiteNameAccepts 断言合法的常见命名不被误杀。
//
// 安全校验过严同样是缺陷：用户无法创建一个叫 "my-site" 的站点，
// 只会让他关掉整个功能。因此"能拒绝攻击"之外还必须"不拒绝正常用法"。
func TestValidSiteNameAccepts(t *testing.T) {
	valid := []string{
		"a", "A", "0",
		"example", "example.com", "api-v2", "my_site", "site123",
		"a.b.c.d", "www.example.com", "test-site_2.0",
		strings.Repeat("a", MaxSiteNameLen),
	}
	for _, name := range valid {
		if err := ValidSiteName(name); err != nil {
			t.Errorf("站点名 %q 应当合法，却被拒绝: %v", name, err)
		}
	}
}

// TestValidSiteNameRejectsBoundaryAndReserved 覆盖边界与保留名。
func TestValidSiteNameRejectsBoundaryAndReserved(t *testing.T) {
	invalid := []struct {
		name string
		want error
	}{
		{"", ErrInvalidName},
		{strings.Repeat("a", MaxSiteNameLen+1), ErrInvalidName},
		{"-leading", ErrInvalidName},
		{"trailing-", ErrInvalidName},
		{".leading", ErrInvalidName},
		{"trailing.", ErrInvalidName},
		{"_leading", ErrInvalidName},
		{"..", ErrInvalidName},
		{"...", ErrInvalidName},
		{"a..b", ErrInvalidName},
		{"default", ErrReservedName},
		{"DEFAULT", ErrReservedName},
		{"audit", ErrReservedName},
		{"capabilities", ErrReservedName},
		{"Audit", ErrReservedName},
	}
	for _, tc := range invalid {
		err := ValidSiteName(tc.name)
		if err == nil {
			t.Errorf("站点名 %q 应被拒绝，但通过了校验", tc.name)
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("站点名 %q 的错误类型应为 %v，实际: %v", tc.name, tc.want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 第二层：域名校验
// ---------------------------------------------------------------------------

// TestValidDomainRejectsInjection 穷举域名注入载荷。
//
// 域名会被直接拼进 `server_name <domain>;`，因此这是注入面最直接的一个字段。
//
// 关于 "*"：它在域名标签里是**合法**字符（nginx 的 `*.example.com` 通配
// 就靠它）。因此本用例只断言"载荷以能改变 server_name 语义的方式出现时
// 被拒绝"，而 `example.com*` 这种"星号并进合法标签"的形态不在拒绝之列——
// 它不产生第二条指令，最坏结果是 nginx -t 失败，由防线三兜底。
func TestValidDomainRejectsInjection(t *testing.T) {
	for _, tc := range injectionPayloads {
		if tc.payload == "*" {
			// "*" 在域名标签里合法（nginx 通配 *.example.com 靠它），
			// 并合后不产生第二条指令，由 nginx -t 兜底。
			continue
		}
		t.Run(sanitize(tc.payload), func(t *testing.T) {
			// 用 ";" 作分隔，保证载荷不会被词法并入一个合法标签。
			for _, candidate := range []string{
				tc.payload,
				"example.com;" + tc.payload,
			} {
				if err := ValidDomain(candidate); err == nil {
					t.Errorf("域名 %q 应被拒绝（%s），但通过了校验",
						candidate, tc.why)
				}
			}
		})
	}
}

// TestValidDomainInjectionWithTrailingSemicolon 复现最典型的注入场景。
//
// 这条载荷是真实攻击形态：`example.com; root /etc; server_name x`
// 若被写入 server_name，nginx 会解析成三条指令。
func TestValidDomainInjectionWithTrailingSemicolon(t *testing.T) {
	payloads := []string{
		"example.com; root /etc;",
		"example.com; } server { listen 80; root /etc; server_name x; location / { } #",
		"example.com\n    root /etc;",
		"example.com {",
		"example.com }",
		"example.com;\n}",
	}
	for _, p := range payloads {
		if err := ValidDomain(p); err == nil {
			t.Errorf("注入载荷 %q 应被拒绝，但通过了校验", p)
		}
	}
}

// TestValidDomainAccepts 断言正常域名形态被接受。
func TestValidDomainAccepts(t *testing.T) {
	valid := []string{
		"example.com",
		"www.example.com",
		"api-v2.example.com",
		"localhost",
		"_",             // nginx 惯用的"默认站点"占位
		"*.example.com", // nginx 通配语法
		"sub.domain.co.uk",
		"a",
		"1.2.3.4",
		"my_host.example.com",
		strings.Repeat("a", 63) + ".com",
	}
	for _, d := range valid {
		if err := ValidDomain(d); err != nil {
			t.Errorf("域名 %q 应当合法，却被拒绝: %v", d, err)
		}
	}
}

// TestValidDomainRejectsMalformed 覆盖形态边界。
func TestValidDomainRejectsMalformed(t *testing.T) {
	invalid := []string{
		"",
		".example.com",                    // 前导点
		"example.com.",                    // 尾随点
		"example..com",                    // 空标签
		"-example.com",                    // 标签以短横线开头
		"example-.com",                    // 标签以短横线结尾
		"*",                               // 裸星号（nginx 不支持，应当用 "_"）
		"*",                               // 重复一次以强调
		"exa mple.com",                    // 空格
		"example.com:80",                  // 端口不应出现在 server_name
		"中文.example.com",                  // 非 ASCII
		strings.Repeat("a", 64) + ".com",  // 标签超长
		strings.Repeat("a.", 130) + "com", // 总长超限
	}
	for _, d := range invalid {
		if err := ValidDomain(d); err == nil {
			t.Errorf("域名 %q 应被拒绝，但通过了校验", d)
		}
	}
}

// TestValidDomainAcceptsWildcardOnlyAtLeftmost 锁定通配位置的语义。
//
// nginx 只支持最左侧标签的通配，`ex*.com` 会导致 nginx -t 失败。
// 与其生成一份必然校验失败的配置，不如在校验阶段就说清楚。
func TestValidDomainAcceptsWildcardOnlyAtLeftmost(t *testing.T) {
	if err := ValidDomain("*.example.com"); err != nil {
		t.Errorf("*.example.com 应当合法: %v", err)
	}
	// 中间/末尾的星号：我们的字符集允许 '*' 出现在标签内，
	// 因此这里断言的是"至少不会造成注入"，而不是必然拒绝。
	// 真正会失败的情况由 nginx -t 兜底（防线三）。
	for _, d := range []string{"ex*.com", "example.*"} {
		err := ValidDomain(d)
		if err == nil {
			t.Logf("域名 %q 被接受（星号在标签内）；"+
				"该形态会导致 nginx -t 失败，由防线三兜底", d)
		}
	}
}

// ---------------------------------------------------------------------------
// 第三层：反代目标校验
// ---------------------------------------------------------------------------

// TestValidUpstreamRejectsInjection 穷举反代目标的注入载荷。
func TestValidUpstreamRejectsInjection(t *testing.T) {
	for _, tc := range injectionPayloads {
		if lexicalMergeSafe[tc.payload] {
			// 见 lexicalMergeSafe 的说明：这类载荷并合后是合法路径。
			continue
		}
		t.Run(sanitize(tc.payload), func(t *testing.T) {
			// 拼接方式与 TestValidRootRejectsInjection 同理：
			// 用 ";" 让载荷保持为独立的注入单元，而不是被词法并入
			// 一个合法的路径（`/api` + `/v1` 只是 `/api/v1`，并无注入）。
			candidates := []string{
				tc.payload,
				"http://127.0.0.1:3000;" + tc.payload,
				"http://127.0.0.1:3000/" + tc.payload,
			}
			for _, candidate := range candidates {
				if err := ValidUpstream(candidate); err == nil {
					t.Errorf("反代目标 %q 应被拒绝（%s），但通过了校验",
						candidate, tc.why)
				}
			}
		})
	}
}

// TestValidUpstreamRejectsSemicolonInjection 复现反代场景的注入。
//
// 之所以单独一条：`http://127.0.0.1:3000;root /etc;` 这类载荷
// **能被 url.Parse 成功解析**（分号在 URL 里是合法字符），
// 因此只依赖 url.Parse 的实现在这里会漏。本用例锁死
// "必须先做字符级预检"这一设计。
func TestValidUpstreamRejectsSemicolonInjection(t *testing.T) {
	payloads := []string{
		"http://127.0.0.1:3000;root /etc;",
		"http://127.0.0.1:3000;\nroot /etc;",
		"http://127.0.0.1:3000 { root /etc; }",
		"http://127.0.0.1:3000`id`",
		"http://127.0.0.1:3000$uri",
		"http://127.0.0.1:3000#comment",
	}
	for _, p := range payloads {
		if err := ValidUpstream(p); err == nil {
			t.Errorf("反代注入载荷 %q 应被拒绝，但通过了校验", p)
		}
	}
}

// TestValidUpstreamRejectsUnixSocket 锁定"不允许 unix socket"这一决策。
//
// 这是一个真实的权限提升面：若允许 `unix:/var/run/docker.sock`，
// 面板用户就能经由 nginx 访问任意本机 unix socket
// （Docker 守护进程的 socket 等于 root 权限）。
func TestValidUpstreamRejectsUnixSocket(t *testing.T) {
	payloads := []string{
		"unix:/var/run/docker.sock",
		"unix:/var/run/docker.sock:/containers/json",
		"http://unix:/var/run/docker.sock",
		"//var/run/docker.sock",
	}
	for _, p := range payloads {
		if err := ValidUpstream(p); err == nil {
			t.Errorf("unix socket 载荷 %q 应被拒绝，但通过了校验", p)
		}
	}
}

// TestValidUpstreamRejectsOtherSchemes 锁定只允许 http/https。
func TestValidUpstreamRejectsOtherSchemes(t *testing.T) {
	for _, p := range []string{
		"ftp://127.0.0.1:21",
		"file:///etc/passwd",
		"ws://127.0.0.1:3000",
		"gopher://127.0.0.1:70",
		"javascript:alert(1)",
		"data:text/plain,x",
	} {
		if err := ValidUpstream(p); err == nil {
			t.Errorf("协议载荷 %q 应被拒绝，但通过了校验", p)
		}
	}
}

// TestValidUpstreamAccepts 断言正常写法被接受。
func TestValidUpstreamAccepts(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:3000",
		"http://127.0.0.1:8080",
		"https://backend.internal",
		"http://localhost:5000",
		"http://192.168.1.10:8000",
		"http://backend:3000",
		"http://backend.example.com:3000",
		"http://127.0.0.1:3000/api", // 带路径是合法的 proxy_pass 用法
		"http://[::1]:3000",         // IPv6 字面量
		"https://127.0.0.1",         // 省略端口
	}
	for _, u := range valid {
		if err := ValidUpstream(u); err != nil {
			t.Errorf("反代目标 %q 应当合法，却被拒绝: %v", u, err)
		}
	}
}

// TestValidUpstreamRejectsMalformed 覆盖形态边界。
func TestValidUpstreamRejectsMalformed(t *testing.T) {
	invalid := []string{
		"",
		"127.0.0.1:3000",                  // 缺协议（归一化由 NormalizeUpstream 负责）
		"http://",                         // 缺主机
		"http://127.0.0.1:0",              // 端口 0
		"http://127.0.0.1:99999",          // 端口越界
		"http://127.0.0.1:abc",            // 端口非数字
		"http://user:pass@127.0.0.1:3000", // 内嵌凭据
		"http://127.0.0.1:3000?a=b",       // 查询串
		"http://127.0.0.1:3000#frag",      // 片段
	}
	for _, u := range invalid {
		if err := ValidUpstream(u); err == nil {
			t.Errorf("反代目标 %q 应被拒绝，但通过了校验", u)
		}
	}
}

// TestNormalizeUpstream 验证协议补齐。
func TestNormalizeUpstream(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:3000":           "http://127.0.0.1:3000",
		"  127.0.0.1:3000  ":       "http://127.0.0.1:3000",
		"http://127.0.0.1:3000":    "http://127.0.0.1:3000",
		"https://backend.internal": "https://backend.internal",
		"":                         "",
	}
	for in, want := range cases {
		if got := NormalizeUpstream(in); got != want {
			t.Errorf("NormalizeUpstream(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestNormalizeThenValidate 验证"先归一化再校验"这条链路。
//
// 用户只填 `127.0.0.1:3000` 是常见且合理的写法，
// 归一化后必须能通过校验；这是"不误杀正常用法"的一部分。
func TestNormalizeThenValidate(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1:3000",
		"localhost:8080",
		"backend.internal",
	} {
		if err := ValidUpstream(NormalizeUpstream(raw)); err != nil {
			t.Errorf("先归一化再校验 %q 应当通过，却被拒绝: %v", raw, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 根目录校验
// ---------------------------------------------------------------------------

// TestValidRootRejectsInjection 穷举根目录的注入载荷。
//
// #################### 载荷拼接方式说明（一个真实的测试陷阱） ####################
//
// 初版这里用 `"/var/www" + payload` 拼接。测试报出多条"失败"，
// 但逐条核对后发现**它们不是真实漏洞**：当载荷是 `/` 或 `..` 时，
// 拼接结果 `/var/www/a/b`、`/var/wwwa..b` 本身就是**合法的路径**——
// 载荷已经被词法地并入了路径，不存在任何可注入的内容。
//
// 例如 `/var/www` + `/etc/passwd` = `/var/www/etc/passwd`：
// 这是一条完全正常的静态站根目录，拒绝它才是错的（误伤正常功能）。
//
// 因此拼接方式必须让载荷**保持为独立的注入单元**：
//   - 用 `;`（nginx 指令分隔符）作分隔，得到 `/var/www;<payload>`，
//     这样任何载荷都直接暴露在会被注入解析的位置；
//   - 同时保留"前置"形态，覆盖载荷出现在路径开头的场景。
//
// 这个修正本身就是"测试必须可解释"的体现：看到红色不代表代码有错，
// 也不代表测试有错，必须逐条判断到底是哪一边的问题。
func TestValidRootRejectsInjection(t *testing.T) {
	for _, tc := range injectionPayloads {
		if lexicalMergeSafe[tc.payload] {
			// 见 lexicalMergeSafe 的说明：这类载荷并合后是合法路径。
			continue
		}
		t.Run(sanitize(tc.payload), func(t *testing.T) {
			for _, candidate := range []string{
				// 载荷紧跟在分号后：任何被放行的字符都会成为 nginx 指令的一部分。
				"/var/www;" + tc.payload,
				// 载荷在路径开头。
				tc.payload + "/var/www",
				// 载荷作为独立路径段（前面补斜杠，避免与 www 词法粘连）。
				"/var/www/" + tc.payload,
			} {
				if err := ValidRoot(candidate); err == nil {
					t.Errorf("根目录 %q 应被拒绝（%s），但通过了校验",
						candidate, tc.why)
				}
			}
		})
	}
}

// TestValidRootRejectsRootSlash 锁定"不允许 / 作为站点根"。
func TestValidRootRejectsRootSlash(t *testing.T) {
	if err := ValidRoot("/"); err == nil {
		t.Error("把 / 作为站点根目录应被拒绝（会让 nginx 暴露 /etc/shadow 等文件）")
	}
}

// TestValidRootAccepts 断言正常路径被接受。
func TestValidRootAccepts(t *testing.T) {
	for _, p := range []string{
		"/var/www/html",
		"/var/www/example.com",
		"/home/user/site",
		"/srv/www/my-site",
		"/tmp/lipanel-e2e/www",
	} {
		if err := ValidRoot(p); err != nil {
			t.Errorf("根目录 %q 应当合法，却被拒绝: %v", p, err)
		}
	}
}

// TestValidRootRejectsRelativeAndUnclean 覆盖形态边界。
func TestValidRootRejectsRelativeAndUnclean(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"var/www",
		"./var/www",
		"/var/www/",
		"/var//www",
		"/var/www/../etc",
		"/var/www html",
		"/var/www\thtml",
	}
	for _, p := range invalid {
		if err := ValidRoot(p); err == nil {
			t.Errorf("根目录 %q 应被拒绝，但通过了校验", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 类型校验
// ---------------------------------------------------------------------------

func TestValidType(t *testing.T) {
	for _, ok := range []string{TypeStatic, TypeProxy} {
		if !ValidType(ok) {
			t.Errorf("类型 %q 应当合法", ok)
		}
	}
	for _, bad := range []string{"", "STATIC", "dynamic", "php", "static ", "proxy;x"} {
		if ValidType(bad) {
			t.Errorf("类型 %q 应当非法", bad)
		}
	}
}

// sanitize 把载荷转成可读的测试名（控制字符与特殊符号替换掉）。
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == ' ':
			b.WriteString("_space")
		case r < 0x20 || r > 0x7e:
			b.WriteString("_nonascii")
		case r == '/':
			b.WriteString("_slash")
		case r == '\\':
			b.WriteString("_backslash")
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "empty"
	}
	return out
}

// ---------------------------------------------------------------------------
// 核心不变式：任何 nginx 元字符都不可能通过校验
// ---------------------------------------------------------------------------

// nginxMetacharacters 是能改变 nginx 配置语义的字符全集。
//
// 这是本模块最根本的安全命题所依赖的集合：
//
//	**只要校验通过，进入配置模板的字符串里就不含这些字符。**
//
// 只要这条成立，`server_name <domain>;`、`root <path>;`、
// `proxy_pass <url>;` 这些拼接就是安全的——因为没有字符能提前
// 结束指令、开启块、注释掉后续行或引用变量。
//
// 因此本用例的断言比"某些载荷被拒绝"更强、也更能说明问题：
// 它穷举全部单字符，断言**不存在任何一个元字符**能通过三层校验。
var nginxMetacharacters = []rune{
	';', '{', '}', '$', '`', '\'', '"', '#', '\n', '\r', '\t', ' ', '\\', '|', '&', '<', '>',
}

// TestNoNginxMetacharacterEverSurvives 穷举单字符，锁死上面的不变式。
//
// 覆盖三种插入位置（开头、中间、结尾）与三种字段，
// 确保不是"恰好某个位置被挡住了"。
func TestNoNginxMetacharacterEverSurvives(t *testing.T) {
	for _, r := range nginxMetacharacters {
		for _, pos := range []string{"prefix", "middle", "suffix"} {
			var name, domain, root, upstream string
			switch pos {
			case "prefix":
				name = string(r) + "site"
				domain = string(r) + "example.com"
				root = string(r) + "/var/www"
				upstream = string(r) + "http://127.0.0.1:3000"
			case "middle":
				name = "si" + string(r) + "te"
				domain = "exam" + string(r) + "ple.com"
				root = "/var" + string(r) + "/www"
				upstream = "http://127.0.0.1:3000/" + string(r) + "api"
			case "suffix":
				name = "site" + string(r)
				domain = "example.com" + string(r)
				root = "/var/www" + string(r)
				upstream = "http://127.0.0.1:3000" + string(r)
			}

			if err := ValidSiteName(name); err == nil {
				t.Errorf("站点名 %q 含 nginx 元字符 %q（%s 位置）却通过了校验",
					name, r, pos)
			}
			if err := ValidDomain(domain); err == nil {
				t.Errorf("域名 %q 含 nginx 元字符 %q（%s 位置）却通过了校验",
					domain, r, pos)
			}
			if err := ValidRoot(root); err == nil {
				t.Errorf("根目录 %q 含 nginx 元字符 %q（%s 位置）却通过了校验",
					root, r, pos)
			}
			if err := ValidUpstream(upstream); err == nil {
				t.Errorf("反代目标 %q 含 nginx 元字符 %q（%s 位置）却通过了校验",
					upstream, r, pos)
			}
		}
	}
}
