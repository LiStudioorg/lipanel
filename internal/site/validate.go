// Package site 提供 Nginx 站点的管理能力（阶段四 4.3，核心自带）。
//
// ############################################################
// 安全设计（必读）：本包会**生成 nginx 配置文件并让 nginx 加载它**
//
// nginx 配置是一门有语法的语言：`;` 结束一条指令、`{}` 划分块、
// `$` 引用变量、`#` 开始注释。因此本模块面对的注入面比 4.1（systemctl argv）
// 和 4.2（文件路径）**更宽**——不是"参数会不会被 shell 解释"，
// 而是"用户输入会不会变成 nginx 的一条指令"。
//
// 三道防线，缺一不可：
//
//	防线一（根除注入）：**所有**进入配置模板的字段都必须先通过本文件的
//	                    校验函数。Render 只接受已经过校验的 Site 值，
//	                    绝不存在"某个字段忘了校验直接拼进模板"的路径。
//	防线二（收敛输入）：字段白名单。域名只允许主机名字符集，
//	                    反代目标必须是合法 URL，根目录必须通过 4.2 的
//	                    路径白名单校验。任何控制字符、分号、花括号、
//	                    美元符、反引号、引号一律拒绝。
//	防线三（执行前验证）：写盘后执行 `nginx -t`，不通过就回滚。
//	                    即使前两道防线被绕过，畸形配置也不会被加载。
//
// ############################################################
package site

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 校验相关的哨兵错误。与 4.1/4.2 同样的做法：分成多个而不是一个笼统的
// ErrInvalid，因为调用方要据此给出**不同的提示**（"站点名非法"与
// "反代目标非法"对用户来说是完全不同的两件事）。
var (
	// ErrInvalidName 表示站点名非法（未通过白名单校验）。
	ErrInvalidName = errors.New("site: 站点名非法")
	// ErrReservedName 表示站点名是保留名。
	ErrReservedName = errors.New("site: 站点名是保留名")
	// ErrInvalidDomain 表示域名非法。
	ErrInvalidDomain = errors.New("site: 域名非法")
	// ErrInvalidRoot 表示静态站根目录非法。
	ErrInvalidRoot = errors.New("site: 静态站根目录非法")
	// ErrInvalidUpstream 表示反向代理目标非法。
	ErrInvalidUpstream = errors.New("site: 反向代理目标非法")
	// ErrInvalidType 表示站点类型非法。
	ErrInvalidType = errors.New("site: 站点类型非法")
)

// ---------------------------------------------------------------------------
// 站点类型
// ---------------------------------------------------------------------------

// 站点类型。
const (
	// TypeStatic 是静态站：nginx 直接读磁盘上的文件。
	TypeStatic = "static"
	// TypeProxy 是反向代理：nginx 把请求转发给上游服务。
	TypeProxy = "proxy"
)

// ValidType 判断站点类型是否受支持。
func ValidType(t string) bool {
	switch t {
	case TypeStatic, TypeProxy:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// 站点名校验
// ---------------------------------------------------------------------------

// siteNamePattern 限定站点名形态。
//
// 站点名会变成**配置文件名**（`<name>.conf`）与 URL 路径段
// （`/api/sites/{name}`），因此它是三重身份：文件名、URL 段、审计主键。
// 白名单只放行这三者都安全的字符集。
//
// 刻意**拒绝**的字符及其原因：
//
//	/  \      路径分隔符——会变成"写到别的目录"，即路径穿越
//	..        路径穿越（"." 本身允许，但 ".." 作为整体被显式拒绝）
//	空格      文件名尾部空格在部分工具下会丢失；也便于隐藏真实文件名
//	;  {  }   nginx 指令分隔符与块边界——直接注入配置
//	$  `       nginx 变量引用与 shell 命令替换
//	'  "      nginx 引号，可用来"闭合"字符串后追加指令
//	#          nginx 注释符，可注释掉后续本该生效的行
//	\n \r \t  换行能凭空插入一条新指令（最典型的配置注入）
//	*  ?  <  >  |  :  通配与重定向符，无合法用途
//
// 允许 [A-Za-z0-9._-]：覆盖 "example.com"、"api-v2"、"my_site" 这类
// 常见命名，同时不引入任何需要转义的字符。
var siteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]$`)

// 站点名长度限制。
//
// 上限 64：配置文件名会加上 ".conf" 后缀，而多数文件系统单个文件名
// 上限是 255 字节；64 留出了充足余量，同时保证 URL 段与日志展示都不至于过长。
// 下限 1：单字符名（如 "a"）是合法的，由单字符分支单独放行。
const (
	MinSiteNameLen = 1
	MaxSiteNameLen = 64
)

// reservedSiteNames 是保留的站点名。
//
// 为什么必须保留：
//   - "default"：Debian 系自带 /etc/nginx/sites-enabled/default，
//     面板若允许用它命名，用户的一条配置就会把系统默认站点覆盖掉，
//     而"默认站点"通常是用户自己也没意识到存在的东西；
//   - "audit"、"capabilities"："审计"、"能力"这两个词在本模块里已经是
//     API 路径段（/api/sites/audit）。虽然路由注册顺序已经保证审计接口
//     优先命中（见 server/site_api.go），但一个叫 audit 的站点会让
//     `/api/sites/audit/enable` 这种路径变得含义模糊。与其依赖路由顺序
//     的隐式保证，不如从命名上直接消除歧义。
var reservedSiteNames = map[string]bool{
	"default":      true,
	"audit":        true,
	"capabilities": true,
}

// ValidSiteName 判断站点名是否合法。
//
// 注意：这里只做**形态**校验，不代表该站点真实存在
// （存在性由 Manager 查文件系统判定）。
func ValidSiteName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: 站点名不能为空", ErrInvalidName)
	}
	if len(name) < MinSiteNameLen || len(name) > MaxSiteNameLen {
		return fmt.Errorf("%w: 长度必须在 %d~%d 之间，当前 %d",
			ErrInvalidName, MinSiteNameLen, MaxSiteNameLen, len(name))
	}
	// 单字符名单独判定：上面的正则要求首尾都是字母数字，
	// 对长度 1 的字符串来说首尾是同一个字符，`^[..]*[..]$` 无法匹配空中间段。
	if len(name) == 1 {
		if !isAlnum(name[0]) {
			return fmt.Errorf("%w: %q 不是合法的首字符", ErrInvalidName, name)
		}
		return checkReserved(name)
	}
	if !siteNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q 只允许字母、数字、点、下划线与短横线，"+
			"且必须以字母或数字开头结尾（不允许 / \\ .. 空格 ; { } $ ` ' \" # 换行 等字符）",
			ErrInvalidName, name)
	}
	// 正则本身已经挡住了 ".."，但这里再显式判一次：
	// 安全性质应当有**冗余**的显式断言，而不是"依赖正则的某条分支恰好覆盖"。
	// 将来若有人放宽正则（例如允许更多符号），这一行仍会拦住路径穿越。
	if strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q 不允许包含 \"..\"（路径穿越）", ErrInvalidName, name)
	}
	return checkReserved(name)
}

// checkReserved 检查保留名（大小写不敏感：文件系统可能不区分大小写）。
func checkReserved(name string) error {
	if reservedSiteNames[strings.ToLower(name)] {
		return fmt.Errorf("%w: %q 是系统或接口保留名，请换一个",
			ErrReservedName, name)
	}
	return nil
}

// isAlnum 判断字节是否为 ASCII 字母或数字。
func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ---------------------------------------------------------------------------
// 域名校验
// ---------------------------------------------------------------------------

// 域名长度上限：RFC 1035 规定完整域名（含点）不超过 253 个字符。
const MaxDomainLen = 253

// domainLabelPattern 是单个域名标签的允许形态。
//
// 允许下划线开头：nginx 里 `_` 是"默认站点"的惯用 server_name，
// 拒绝它会让用户无法创建默认站点。
var domainLabelPattern = regexp.MustCompile(`^[A-Za-z0-9_*][A-Za-z0-9_*-]*$`)

// ValidDomain 校验一个 server_name 值。
//
// 为什么域名必须严格白名单——它会被**直接拼进 `server_name` 指令**：
//
//	server_name example.com;
//	              ^^^^^^^^^^^ 注入点
//
// 若允许 `;`，攻击者提交 `example.com; root /etc;` 就能凭空多出指令；
// 若允许换行，同样能另起一行写任意配置；若允许 `{`/`}`，可以提前闭合
// server 块并在块外写 **http 层的指令**（影响整个 nginx 实例，
// 而不只是自己这一个站点）。因此这里的字符集收敛到主机名本身，
// 任何空白、控制字符与 nginx 元字符一律拒绝。
//
// 支持三种形态：
//   - 普通域名/主机名：example.com、api.example.com、localhost
//   - 通配：*.example.com（nginx server_name 通配语法）
//   - 默认站点占位：_（nginx 惯用写法）
func ValidDomain(domain string) error {
	return validDomain(domain, "域名")
}

// validDomain 是 ValidDomain 的带字段名版本。
//
// 单独抽出 field 参数是为了让**表单校验**能复用同一份实现：
// 前端提交的域名可能带用户写的通配前缀，报错里要指明是哪个字段。
func validDomain(domain, field string) error {
	if domain == "" {
		return fmt.Errorf("%w: %s不能为空", ErrInvalidDomain, field)
	}
	if len(domain) > MaxDomainLen {
		return fmt.Errorf("%w: %s长度不能超过 %d 个字符，当前 %d",
			ErrInvalidDomain, field, MaxDomainLen, len(domain))
	}

	// 逐字符检查控制字符与空白。
	//
	// 这一层是**冗余**的（下面的字符集白名单已经覆盖），但它的价值在于
	// 报错信息精确：用户看到的是"包含非法字符 '\\n'"而不是
	// 一句笼统的"格式不正确"，排查注入尝试时这一点很重要。
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: %s %q 第 %d 个字符是非法的控制字符或空白"+
				"（域名只允许 ASCII 可见字符）",
				ErrInvalidDomain, field, domain, i+1)
		}
	}

	// 默认站点占位符：nginx 里单独一个 "_" 表示"匹配任意主机名"。
	if domain == "_" {
		return nil
	}

	// 通配前缀 "*.example.com"：星号只允许作为**最左侧标签的第一个字符**。
	// nginx 只支持这一种位置的通配，`ex*.com`、`*ample.com` 都是无效语法，
	// 会直接导致 nginx -t 失败。
	rest := domain
	if strings.HasPrefix(rest, "*.") {
		rest = rest[2:]
		if rest == "" {
			return fmt.Errorf("%w: %s %q 缺少通配符后的域名", ErrInvalidDomain, field, domain)
		}
	}
	// 裸 "*" 拒绝：nginx 的 server_name 不支持纯星号（要表达"默认站点"
	// 应当用 "_"），放行它会让用户写出一个 nginx -t 必然失败的配置。
	if rest == "*" {
		return fmt.Errorf("%w: %s %q 非法：通配必须写成 *.example.com 的形式"+
			"（表示默认站点请使用 \"_\"）", ErrInvalidDomain, field, domain)
	}

	// 逐标签校验。
	labels := strings.Split(rest, ".")
	if len(labels) > 0 && labels[len(labels)-1] == "" {
		return fmt.Errorf("%w: %s %q 不能以 \".\" 结尾", ErrInvalidDomain, field, domain)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%w: %s %q 含有空的标签（连续的点）", ErrInvalidDomain, field, domain)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: %s %q 的标签 %q 超过 63 个字符",
				ErrInvalidDomain, field, domain, label)
		}
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("%w: %s %q 的标签 %q 含有非法字符"+
				"（只允许字母、数字、下划线、短横线与通配星号）",
				ErrInvalidDomain, field, domain, label)
		}
		// 标签不能以短横线开头或结尾（RFC 952/1035）。
		// 允许它是为了兼容极少数历史用法，但更主要的是避免生成
		// 一个 nginx 能接受、其它工具却无法解析的怪异主机名。
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: %s %q 的标签 %q 不能以短横线开头或结尾",
				ErrInvalidDomain, field, domain, label)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 根目录校验（静态站）
// ---------------------------------------------------------------------------

// rootAllowedPattern 是站点根目录允许的字符集（白名单）。
//
// #################### 为什么这里必须用白名单而不是黑名单 ####################
//
// 初版实现是"列举危险字符"（; { } $ ` ' " # \ 与空白）。测试立刻抓出了
// 它的漏网之鱼：`|`、`&`、`<`、`>`、`*`、`?`、`%` 全都没被拦住。
//
// 这正说明黑名单在这类场景下是错的：**危险字符的清单永远列不全**，
// 而每漏一个就是一条注入路径。反观文件系统路径的实际需要——
// 字母、数字、点、下划线、短横线、斜杠——白名单能完整覆盖
// 绝大多数真实用法，剩下的（含空格或特殊符号的目录名）虽然合法，
// 但在 nginx 配置里本就需要转义，拒绝它们是**正确**而不是苛刻。
//
// 与 4.2 的呼应：file.Resolver 回答"这个路径在不在白名单目录内"，
// 这里回答"这个字符串会不会破坏 nginx 配置"。两道闸门各自独立。
var rootAllowedPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// ValidRoot 校验静态站的根目录。
//
// 这里只做**形态**校验（绝对路径、字符集、已 Clean）；
// "是否落在白名单根目录内"由 Manager 用 4.2 的 file.Resolver 判定——
// 那需要运行时依赖，不属于纯函数的职责。
//
// 为什么根目录也要防注入：它会被拼进 `root /var/www/x;`。
// 虽然 Manager 会用 file.Resolver 校验，但那道校验回答的是
// "这个路径能不能碰"，而不是"这个字符串会不会破坏 nginx 配置"。
// 两道闸门各自独立，缺一不可（与 4.2 的白名单/权限判定同构）。
func ValidRoot(root string) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("%w: 静态站必须指定根目录", ErrInvalidRoot)
	}
	if strings.ContainsRune(root, 0) {
		return fmt.Errorf("%w: 根目录含 NUL 字节", ErrInvalidRoot)
	}
	// 换行/回车必须显式拒绝并单独报错：它们能在配置里凭空插入一条指令，
	// 是最典型的注入手法，值得一条专门的错误信息。
	if strings.ContainsAny(root, "\n\r") {
		return fmt.Errorf("%w: 根目录不能包含换行符（会导致 nginx 配置注入）", ErrInvalidRoot)
	}
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: %q 必须是绝对路径（以 / 开头）", ErrInvalidRoot, root)
	}
	// 路径穿越：判据是「Clean 前存在 ".." 路径段」。
	//
	// 注意判据的精确性：这里分两件事——
	//   ① 含 ".." 段 → 拒绝（真正会向上跳的路径）；
	//   ② Clean 后与原串不同 → 拒绝并要求规范化。
	// 两条合起来，`/var/../etc` 会因 ① 被拒，`/var//www` 会因 ② 被拒，
	// 而合法目录名 `my..site`（".." 不是独立路径段）不会被误杀。
	// 安全判定要精确到语义，而不是靠字面匹配——字面匹配要么漏、要么误伤。
	for _, seg := range strings.Split(root, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: 根目录不能包含 \"..\" 路径段（路径穿越）", ErrInvalidRoot)
		}
	}
	// 字符集白名单（见 rootAllowedPattern 的说明）。
	//
	// 空格、制表符、; { } $ ` ' " # | & < > * ? % 等字符全部落在这里被拒。
	// 它们要么能直接破坏 nginx 配置语法，要么在 nginx 里需要转义，
	// 而"自动加引号"会引入新的转义语义（引号内 `$` 仍会被 nginx 展开），
	// 与其在模板里做脆弱的转义，不如不接受这类路径。
	if !rootAllowedPattern.MatchString(root) {
		return fmt.Errorf("%w: 根目录含有非法字符——只允许字母、数字、"+
			"点、下划线、短横线与路径分隔符 /。"+
			"（空格、; { } $ ` ' \" # | & < > * ? %% 等字符在 nginx 配置中"+
			"需要转义或会破坏语法，一律拒绝）", ErrInvalidRoot)
	}
	if clean := filepath.Clean(root); clean != root {
		return fmt.Errorf("%w: 路径未规范化，请改用 %q", ErrInvalidRoot, clean)
	}
	if root == "/" {
		// 把整个文件系统作为站点根目录几乎一定是配置错误，
		// 而且会让 nginx 能读到 /etc/shadow 这类文件。
		return fmt.Errorf("%w: 不允许把 / 作为站点根目录", ErrInvalidRoot)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 反向代理目标校验
// ---------------------------------------------------------------------------

// 反代目标的默认协议：用户只填 "127.0.0.1:3000" 时补上 http://。
const DefaultUpstreamScheme = "http"

// upstreamPathPattern 是反代目标路径部分允许的字符集（白名单）。
//
// 依据 RFC 3986 的 path 段可用字符收敛为：unreserved（字母数字 - . _ ~）
// 加路径分隔符 /。刻意**不**放行 pchar 里的 sub-delims（! $ & ' ( ) * + , ; =）
// 与 ":@「」"——那些字符在 nginx 配置里有转义或注释语义，
// 而作为 proxy_pass 的路径前缀，它们没有任何真实用途。
//
// 用白名单而不是"列举危险字符"的原因见 ValidRoot 中 rootAllowedPattern
// 的说明：黑名单永远列不全，实测漏掉了 | & < > * ? 一整批。
var upstreamPathPattern = regexp.MustCompile(`^[A-Za-z0-9._~/-]*$`)

// ValidUpstream 校验反向代理目标。
//
// 它会被拼进 `proxy_pass http://127.0.0.1:3000;`。与域名同理，
// 这里必须确认整个字符串是一个**结构良好的 URL**，而不是
// "看起来像 URL 的任意文本"。
//
// 只允许 http / https 两种协议：
//   - 其它协议（ftp、ws、file…）在 proxy_pass 里要么无效，
//     要么（如 file://）会引入完全不同的语义，属于配置错误；
//   - 尤其要拒绝 `unix:/path` 这类 nginx 专有写法：它会让面板用户
//     经由 nginx 访问本机任意 unix socket（例如 Docker 守护进程的
//     /var/run/docker.sock），这是一个真实的权限提升面。
func ValidUpstream(raw string) error {
	// ⚠️ 先判"首尾空白"，再 TrimSpace。
	//
	// 这个顺序是被测试逼出来的：初版先 trim 再校验，于是
	// ValidUpstream(" http://127.0.0.1:3000 ") 返回**成功**——
	// 而调用方拿到成功之后，手里仍然是那个带空白的原串，
	// 拼进配置就是 `proxy_pass  http://... ;` 里多出来的空白。
	//
	// 更根本的问题是**契约模糊**：一个"校验函数"若默默修整输入，
	// 调用方就永远无法知道"原样写进去安不安全"。
	// 正确做法是让 ValidUpstream 只回答"这个字符串本身能不能用"，
	// 归一化交给显式的 NormalizeUpstream（先归一化、再校验）。
	//
	// （TestNoNginxMetacharacterEverSurvives 用穷举单字符锁死了这条性质。）
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("%w: 后端地址首尾不能有空白字符", ErrInvalidUpstream)
	}
	target := raw
	if target == "" {
		return fmt.Errorf("%w: 反向代理必须指定后端地址，"+
			"例如 http://127.0.0.1:3000", ErrInvalidUpstream)
	}
	if strings.ContainsAny(target, "\n\r") {
		return fmt.Errorf("%w: 后端地址不能包含换行符（会导致 nginx 配置注入）", ErrInvalidUpstream)
	}
	if strings.ContainsAny(target, " \t") {
		return fmt.Errorf("%w: 后端地址不能包含空白字符", ErrInvalidUpstream)
	}
	// URL 解析前先做字符级预检：url.Parse 相当宽容，像
	// `http://127.0.0.1:3000;root /etc;` 这样的输入它能解析成功
	// （分号在 URL 里是合法字符，会被算进 host 的一部分或 path 里），
	// 但那串东西拼进 nginx 就是一条注入指令。因此**不能只依赖 url.Parse**。
	if strings.ContainsAny(target, ";{}`'\"$#\\") {
		return fmt.Errorf("%w: 后端地址含有非法字符（; { } $ ` ' \" # \\ 等不允许出现）",
			ErrInvalidUpstream)
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("%w: %q 不是合法的 URL: %v", ErrInvalidUpstream, target, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	case "":
		return fmt.Errorf("%w: %q 缺少协议前缀，请写成 %s://%s",
			ErrInvalidUpstream, target, DefaultUpstreamScheme, target)
	default:
		return fmt.Errorf("%w: 不支持协议 %q（只允许 http 与 https；"+
			"unix socket 等其它形式不在本期范围内）", ErrInvalidUpstream, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: %q 缺少主机名", ErrInvalidUpstream, target)
	}
	// 拒绝 URL 里的用户信息段（http://user:pass@host）：
	// 面板不接受把凭据写进配置，且 nginx 的 proxy_pass 也不使用它们——
	// 写了只会被静默忽略，让用户以为自己配了 Basic Auth。
	if u.User != nil {
		return fmt.Errorf("%w: 后端地址不应包含用户名/密码（proxy_pass 不会使用它们）",
			ErrInvalidUpstream)
	}
	// 拒绝查询串与片段：proxy_pass 里带上它们既无意义又容易被误当成
	// 路径重写规则，属于典型的"看起来能用其实不生效"的配置。
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: 后端地址不应包含查询串或 # 片段", ErrInvalidUpstream)
	}

	// 校验主机与端口。
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return fmt.Errorf("%w: %q 缺少有效的主机名", ErrInvalidUpstream, target)
	}
	// ⚠️ 显式拒绝 "unix" 这个"假主机名"。
	//
	// 为什么单列一条：`url.Parse("http://unix:/var/run/docker.sock")`
	// 会**成功解析**，并把 host 解成 "unix"、path 解成
	// "/var/run/docker.sock"。若只做通用的域名校验，`unix` 恰好是
	// 一个合法标签形态，于是整串会通过——而它写在配置里实际是
	// nginx 的 unix socket 上游语法。
	//
	// 这是一个真实的权限提升面：`unix:/var/run/docker.sock` 等于
	// 把 Docker 守护进程（root 等价权限）暴露给任何能访问该站点的人。
	// 因此这里必须点名拒绝，而不是指望通用规则恰好覆盖
	// （实测确认：只靠域名白名单覆盖不了）。
	if strings.EqualFold(host, "unix") {
		return fmt.Errorf("%w: 不接受 unix socket 形式的上游地址"+
			"（unix:/path 会让 nginx 访问本机任意 socket，属于越权面）",
			ErrInvalidUpstream)
	}
	// 主机必须是 IP 或主机名形态。
	if net.ParseIP(host) == nil {
		if err := validDomain(host, "后端主机名"); err != nil {
			return fmt.Errorf("%w: %q 的主机名 %q 非法: %v",
				ErrInvalidUpstream, target, host, err)
		}
	}
	if port != "" {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: %q 的端口 %q 非法（应为 1~65535）",
				ErrInvalidUpstream, target, port)
		}
	}
	// 路径部分：允许（例如 http://127.0.0.1:8080/api/），
	// nginx 的 proxy_pass 带路径时会做 URI 替换，这是合法且有意的用法。
	//
	// 但字符集必须是**白名单**——初版用的是"列举危险字符"的黑名单，
	// 测试立刻抓出 `|`、`&`、`<`、`>`、`*`、`?` 全都能溜过去。
	// URL path 段真正需要的字符是 RFC 3986 的 unreserved 集合
	// （字母数字 - . _ ~）加上路径分隔符，其余一律拒绝。
	//
	// 注意"斜杠"本身**不能**拒绝：`http://127.0.0.1:3000/api` 是
	// 完全合法的 proxy_pass 用法，拒绝它属于误伤正常功能。
	// 路径穿越由下面的 ".." 段判定单独负责——这正是"精确到语义"
	// 优于"字面匹配"的地方。
	if p := u.Path; p != "" {
		if !upstreamPathPattern.MatchString(p) {
			return fmt.Errorf("%w: %q 的路径部分 %q 含有非法字符（只允许字母、数字、"+
				"点、下划线、短横线、波浪线与 /）", ErrInvalidUpstream, target, p)
		}
		// 路径穿越：判据是"存在 .. 路径段"，而不是"字符串里出现 .."。
		// 后者会把合法的 `/api/v1..2` 也误杀。
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				return fmt.Errorf("%w: %q 的路径部分包含 \"..\" 段（路径穿越）",
					ErrInvalidUpstream, target)
			}
		}
	}
	return nil
}

// NormalizeUpstream 把用户输入规范化为可直接写入配置的 URL 字符串。
//
// 只做两件事：去首尾空白、在缺协议时补 http://。
// **绝不**做"猜测性纠错"（例如把 127.0.0.1:3000/ 改成别的形态）——
// 规范化与校验一样，越少魔法越安全。
//
// 调用方必须先调用 ValidUpstream 再调用本函数；本函数不重复校验
// （Normalize 只处理协议前缀，若输入非法，校验那一步就该拦下）。
func NormalizeUpstream(raw string) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return ""
	}
	if !strings.Contains(target, "://") {
		return DefaultUpstreamScheme + "://" + target
	}
	return target
}
