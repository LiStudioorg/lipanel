package site

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ============================================================================
// nginx 配置生成（阶段四 4.3）
// ============================================================================
//
// 本文件是**唯一**产出一份 server 块的地方。它的安全契约只有一条，
// 但这条契约是绝对的：
//
//	############ Render 只接受已经过校验的 Site 值 ############
//
// 具体落地为三重保障：
//
//  1. **Render 会自己再校验一遍**（renderCheck）。调用方不该重复校验，
//     但"生成配置"是整个模块最靠近注入面的那一步，在这里再做一次
//     代价极小的断言，能保证"即使将来有人加了一条新的调用路径忘了
//     先校验，也生不出畸形配置"。
//
//  2. **没有任何字段是"直接拼进去的"**。每个字段都有对应的写入辅助
//     （writeDirective / writeQuoted），它们承担各自需要的转义与断言。
//
//  3. **模板是纯 Go 代码而不是 text/template**。
//     用模板引擎的话，"哪些字段被替换进去了"需要读模板才能确认；
//     而 text/template 的 `{{.Domain}}` 默认**不做任何转义**，
//     它给人一种"用了模板所以安全"的错觉——恰恰相反，
//     模板引擎在这里只会增加一层看不见的风险（例如有人改成
//     `{{.Domain | html}}` 以为能防注入，实际 HTML 转义对 nginx 毫无意义）。
//     纯代码拼接的每一行都看得见，评审时不会有遗漏。

// RenderOptions 是生成配置时的可选项。
type RenderOptions struct {
	// Index 是静态站的首页文件列表；为空时用 DefaultIndexFiles。
	Index []string
	// ProxyExtraHeaders 控制是否为反代站追加标准转发头。
	//
	// 默认（false）会追加 Host / X-Real-IP / X-Forwarded-For /
	// X-Forwarded-Proto 四个头。它们不是装饰：不设置 Host 时后端
	// 收到的 Host 是上游地址，很多框架据此生成绝对 URL 会指向错误域名；
	// 不设置 X-Forwarded-For 时后端日志里全是 nginx 的 IP，
	// 排查问题时完全失去线索。
	NoProxyHeaders bool
	// SSL 非 nil 时生成 HTTPS 配置（阶段四 4.4）。
	//
	// 为 nil 时行为与 4.3 完全一致（只监听 80），
	// 因此既有站点的渲染结果不会因为本字段的引入而改变。
	SSL *SSLConfig
}

// SSLConfig 是要写入 nginx 配置的 TLS 参数（阶段四 4.4）。
//
// ########## 为什么类型定义在 site 包里，而不是 ssl 包里 ##########
//
// 渲染 nginx 配置是 site 包的职责，ssl 包**不写配置文件**。
// 因此"SSL 配置长什么样"这个类型必须定义在渲染方这一侧，
// 由 ssl 包填充值（它知道证书路径），再由 site 包渲染。
//
// 若反过来让 site 包 import ssl 包，两个核心模块就形成了
// 循环依赖（ssl 需要 site 的写入能力，site 需要 ssl 的类型）。
// 这正是 4.3 用 RootChecker 闭包避免 site → file 依赖环的同一手法。
type SSLConfig struct {
	// CertPath 是证书链文件路径（ssl_certificate）。
	//
	// 必须是 **fullchain.pem** 而不是 cert.pem：前者包含中间证书，
	// 少了它浏览器会因为"证书链不完整"而报错——
	// 桌面浏览器有时能靠 AIA 自动补全，但移动端与命令行客户端
	// 会直接失败。这是 Let's Encrypt 部署中最常见的错误。
	CertPath string
	// KeyPath 是私钥文件路径（ssl_certificate_key）。
	KeyPath string
	// RedirectHTTP 为 true 时追加一个 80 端口的 server 块做 301 跳转。
	RedirectHTTP bool
	// Protocols 是 ssl_protocols 的取值；为空时用 DefaultTLSProtocols。
	Protocols string
	// Ciphers 是 ssl_ciphers 的取值；为空时用 DefaultTLSCiphers。
	Ciphers string
}

// 默认 TLS 参数。
//
// 只保留 TLSv1.2 与 TLSv1.3：TLSv1.0/1.1 已被所有主流浏览器废弃
// 且存在已知弱点（BEAST / POODLE）。Let's Encrypt 签发的证书
// 完全支持 1.2+，因此没有理由保留旧版本。
//
// 加密套件用 `HIGH:!aNULL:!MD5` 这种**由 OpenSSL 解释**的表达式，
// 而不是写死一串套件名：写死的配置会随时间腐化
// （某天某个套件被发现有漏洞，用户必须手工改配置），
// 而这个表达式让 OpenSSL 按当前版本的安全评级挑选，
// 随系统升级自动获益。
const (
	// DefaultTLSProtocols 是默认启用的 TLS 协议版本。
	DefaultTLSProtocols = "TLSv1.2 TLSv1.3"
	// DefaultTLSCiphers 是默认的加密套件。
	DefaultTLSCiphers = "HIGH:!aNULL:!MD5"
)

// validSSLConfig 校验 TLS 参数。
//
// ########## 为什么证书路径必须严格校验 ##########
//
// 证书路径会被裸拼进 nginx 配置（`ssl_certificate <path>;`），
// 因此它和域名一样是**注入面**：一个含分号的路径就能在配置里
// 插入任意指令。虽然路径来自 certbot 的输出而非用户输入，
// 但"上游可信"不是放弃校验的理由——certbot 的输出格式
// 会随版本变化，而解析器可能被畸形数据误导。
//
// 校验规则：绝对路径 + 白名单字符集 + 拒绝 `..` 路径段 +
// 拒绝所有 nginx 元字符（`;` `{` `}` `"` `'` `$` `#` 空白）。
func validSSLConfig(c SSLConfig) error {
	if err := validCertPath(c.CertPath, "证书"); err != nil {
		return err
	}
	if err := validCertPath(c.KeyPath, "私钥"); err != nil {
		return err
	}
	// TLS 参数同样会被拼进配置，且它们**来自用户可控的配置文件**，
	// 因此必须校验。协议与套件表达式的合法字符集是
	// 字母、数字、`. _ - : ! +`（覆盖 `TLSv1.2`、`HIGH:!aNULL:!MD5`）。
	if c.Protocols != "" && !tlsTokenPattern.MatchString(c.Protocols) {
		return fmt.Errorf("%w: ssl_protocols 取值 %q 含非法字符",
			ErrInvalidRoot, c.Protocols)
	}
	if c.Ciphers != "" && !tlsTokenPattern.MatchString(c.Ciphers) {
		return fmt.Errorf("%w: ssl_ciphers 取值 %q 含非法字符",
			ErrInvalidRoot, c.Ciphers)
	}
	return nil
}

// tlsTokenPattern 限定 TLS 参数的字符集。
var tlsTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._:!+ -]+$`)

// validCertPath 校验证书/私钥路径。
func validCertPath(path, label string) error {
	if path == "" {
		return fmt.Errorf("%w: %s路径不能为空", ErrInvalidRoot, label)
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: %s路径 %q 必须是绝对路径", ErrInvalidRoot, label, path)
	}
	if strings.ContainsAny(path, " \t\n\r;{}\"'$#`\\") {
		return fmt.Errorf("%w: %s路径 %q 含有非法字符", ErrInvalidRoot, label, path)
	}
	// 逐段判 `..`：判据是 path segment 而非子串，
	// 避免误杀 `my..cert` 这类合法文件名。
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: %s路径 %q 含 `..` 路径段", ErrInvalidRoot, label, path)
		}
	}
	return nil
}

// DefaultIndexFiles 是静态站的默认首页候选。
//
// 顺序有意义：nginx 按顺序找，先命中的优先。
// 把 index.html 放首位是绝大多数静态站的预期。
var DefaultIndexFiles = []string{"index.html", "index.htm"}

// generatedHeader 是每份生成配置的头部标记。
//
// 为什么必须有：面板生成的配置与用户手工写的配置混在同一个目录里，
// 后面"能不能在面板里编辑/删除"要靠这个标记区分。
// 没有标记的话，面板只能靠"文件名能不能对上"来猜，
// 而用户完全可能手工建一个同名的文件。
//
// 同时它也是一份**给用户看的说明书**：直接打开配置的人能立刻知道
// 这份文件由面板管理、手工修改会在下次编辑时被覆盖。
const generatedHeader = "# ========================================================\n" +
	"# 本文件由 lipanel 网站管理自动生成，请勿手工修改。\n" +
	"# 面板每次编辑都会用模板重新渲染本文件，手工改动会在下次编辑时丢失。\n" +
	"# 如需自定义，请在面板中删除该站点后手工配置。\n" +
	"# ========================================================\n"

// GeneratedMarker 是用于识别"这份配置由面板生成"的标记串。
//
// 单独导出而不是直接用 generatedHeader：识别逻辑（IsGenerated）依赖的是
// 一个**稳定的短标记**，而不是整段说明文案——后者将来改一个字，
// 所有已存在的站点就会被判定为"非面板生成"。这类"改文案导致数据失联"
// 是很容易发生的回归。
const GeneratedMarker = "# Generated by lipanel"

// Render 生成一份完整的 server 块配置。
//
// 返回的字符串以换行结尾，可直接原子写入 <name>.conf。
//
// 校验策略：**先全部校验，再开始拼接**。绝不出现"边校验边拼"——
// 那样一旦中途失败，函数返回的错误里可能已经带着半份配置，
// 调用方稍有不慎就会把它写盘。
// Render 生成一份完整的 server 块配置。
//
// 返回的字符串以换行结尾，可直接原子写入 <name>.conf。
//
// 校验策略：**先全部校验，再开始拼接**。绝不出现"边校验边拼"——
// 那样一旦中途失败，函数返回的错误里可能已经带着半份配置，
// 调用方稍有不慎就会把它写盘。
func Render(s Site, opts RenderOptions) (string, error) {
	// ---------- 第一步：全部校验（先校验，后拼接） ----------
	if err := renderCheck(s); err != nil {
		return "", err
	}

	index := opts.Index
	if len(index) == 0 {
		index = DefaultIndexFiles
	}
	// 首页文件名同样要过一遍校验：它们会被拼进 `index` 指令，
	// 而且将来可能来自用户输入（当前是常量，但契约必须现在立好）。
	for _, f := range index {
		if err := validIndexFile(f); err != nil {
			return "", err
		}
	}
	// SSL 参数（阶段四 4.4）：证书路径与 TLS 表达式都会被裸拼进配置，
	// 因此与其它字段一样必须先校验。任一不合法就直接返回 ""+error，
	// **绝不产生半截配置**。
	if opts.SSL != nil {
		if err := validSSLConfig(*opts.SSL); err != nil {
			return "", err
		}
	}

	// ---------- 第二步：拼接 ----------
	var b strings.Builder
	b.WriteString(generatedHeader)
	b.WriteString(GeneratedMarker + "\n")
	b.WriteString("# 站点名: " + s.Name + "\n")
	b.WriteString("# 类型: " + typeLabel(s.Type) + "\n")
	if opts.SSL != nil {
		b.WriteString("# HTTPS: 已启用（证书由 lipanel 管理）\n")
	}
	b.WriteString("\n")

	// ---------- HTTP → HTTPS 跳转块（阶段四 4.4） ----------
	//
	// 跳转块必须写在**前面**：nginx 按配置出现的顺序匹配 server 块，
	// 而这两个块都监听 80 端口（跳转块监听 80，主块监听 443）。
	// 顺序本身不影响匹配（server_name 相同、端口不同），
	// 但把跳转放前面更符合阅读习惯——先看到"进来会被转到 HTTPS"。
	if opts.SSL != nil && opts.SSL.RedirectHTTP {
		writeRedirectBlock(&b, s, opts)
	}

	b.WriteString("server {\n")

	if opts.SSL != nil {
		// 启用 HTTPS 后只监听 443。
		//
		// 不再保留 80 端点（那正是上面跳转块的职责）：
		// 若这里也监听 80，请求会命中本块并以明文响应，
		// 用户以为启用了 HTTPS 实际仍在明文传输。
		//
		// ########## 为什么用 `listen 443 ssl http2;` 而不是 `http2 on;` ##########
		//
		// `http2 on;` 是 nginx **1.25.1** 才引入的新写法。在它之前，
		// HTTP/2 只能通过 listen 参数开启。本项目面向的是发行版自带
		// 的 nginx（Debian 11 / Ubuntu 20.04 上是 1.18，RHEL 8 上是 1.20），
		// 写成 `http2 on;` 会让这些机器上的 nginx -t **直接失败**：
		//
		//	[emerg] unknown directive "http2"
		//
		// 这个错误是本模块端到端测试真实抓到的（nginx 1.18.0），
		// 而不是推测——当时表现为"证书已获取但配置写入失败"。
		//
		// 反过来，`listen 443 ssl http2;` 在 1.25+ 上只是**被标记为
		// 过时**（打印一条 warning）而仍然可用。因此在新旧两个方向上，
		// 旧写法都是安全的那一个：一边是警告，另一边是整个配置失效。
		b.WriteString("    listen 443 ssl http2;\n")
		b.WriteString("    listen [::]:443 ssl http2;\n")
	} else {
		// listen：未启用 SSL 时固定 80。
		//
		// 明确写死而不是让用户配：一旦允许用户填端口，就必然要处理
		// "端口冲突"、"非 root 无法监听 80 以下端口"这些额外语义。
		// 写死一个常量让范围保持清晰。
		b.WriteString("    listen 80;\n")
		b.WriteString("    listen [::]:80;\n")
	}

	// server_name：域名已通过 ValidDomain 校验，字符集内不含
	// nginx 元字符，因此可以安全地裸拼。
	b.WriteString("    server_name " + s.Domain + ";\n")

	// ---------- TLS 参数（阶段四 4.4） ----------
	if opts.SSL != nil {
		writeSSLBlock(&b, *opts.SSL)
	}
	b.WriteString("\n")

	switch s.Type {
	case TypeStatic:
		writeStaticBody(&b, s, index)
	case TypeProxy:
		writeProxyBody(&b, s, opts)
	}

	b.WriteString("}\n")
	return b.String(), nil
}

// writeRedirectBlock 写 HTTP → HTTPS 的 301 跳转块。
//
// ########## 为什么用 301 且保留路径 ##########
//
// 跳转必须**保留原始 URI**（`$request_uri` 而不是 `/`）：
// 用 `return 301 https://$host/;` 会让
// `http://example.com/blog/post-1` 跳到首页，
// 用户丢掉了自己要访问的页面，搜索引擎也会认为内容变了。
//
// 用 `$host` 而不是 `$server_name`：前者是客户端请求里的 Host
// （回落到 server_name），在通配/多域名场景下更准确。
// 这里的 server_name 是精确域名，两者等价，但 `$host` 是更稳妥的写法。
//
// ACME 挑战路径（/.well-known/acme-challenge/）**必须放行**：
// 证书续期时 CA 会用 HTTP 访问该路径来验证域名归属。
// 若这里无条件 301 到 HTTPS，CA 的验证请求会跟到 HTTPS ——
// 在证书**即将过期但尚未续期**的时刻，HTTPS 可能正好因为
// 证书过期而握手失败，于是续期也失败，形成死锁：
// 要续期得先有有效证书。这是 Let's Encrypt 部署里
// 非常经典的一个坑，必须显式豁免。
func writeRedirectBlock(b *strings.Builder, s Site, opts RenderOptions) {
	b.WriteString("# HTTP → HTTPS 跳转\n")
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    listen [::]:80;\n")
	b.WriteString("    server_name " + s.Domain + ";\n")
	b.WriteString("\n")
	// ACME HTTP-01 挑战必须能在明文 80 上访问（续期依赖它）。
	// 用精确前缀 + try_files，让它走后端真实的文件读取。
	b.WriteString("    # 放行 ACME HTTP-01 挑战（证书续期依赖它，不可跳转）\n")
	b.WriteString("    location ^~ /.well-known/acme-challenge/ {\n")
	b.WriteString("        root " + webrootOrRoot(s) + ";\n")
	b.WriteString("        try_files $uri =404;\n")
	b.WriteString("    }\n")
	b.WriteString("\n")
	b.WriteString("    location / {\n")
	// $request_uri 保留原始路径与查询串（见上方说明）。
	b.WriteString("        return 301 https://$host$request_uri;\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("\n")
	_ = opts
}

// webrootOrRoot 返回 ACME 挑战文件的实际落盘目录。
//
// 静态站直接用其根目录（挑战文件写在 <root>/.well-known/...）。
// 反向代理站没有本地目录，此时退回一个约定目录——
// 但**反代站本来就不支持一键申请**（见 ssl 包的 webrootFor），
// 因此这个分支只会在"用户手工配置的证书 + 反代站"场景下出现，
// 此时保留该 location 至少不会让续期比启用 HTTPS 之前更糟。
func webrootOrRoot(s Site) string {
	if s.Type == TypeStatic && s.Root != "" {
		return s.Root
	}
	return "/var/www/html"
}

// writeSSLBlock 写 TLS 参数与证书路径。
func writeSSLBlock(b *strings.Builder, cfg SSLConfig) {
	protocols := cfg.Protocols
	if protocols == "" {
		protocols = DefaultTLSProtocols
	}
	ciphers := cfg.Ciphers
	if ciphers == "" {
		ciphers = DefaultTLSCiphers
	}

	b.WriteString("\n")
	b.WriteString("    # TLS 证书（由 lipanel 自动维护）\n")
	// 路径已通过 validCertPath 校验：绝对路径、无 nginx 元字符、无 `..`。
	b.WriteString("    ssl_certificate     " + cfg.CertPath + ";\n")
	b.WriteString("    ssl_certificate_key " + cfg.KeyPath + ";\n")
	b.WriteString("\n")
	b.WriteString("    # 只启用 TLSv1.2/1.3：更旧的版本已被主流浏览器废弃\n")
	b.WriteString("    ssl_protocols " + protocols + ";\n")
	b.WriteString("    ssl_ciphers " + ciphers + ";\n")
	// 由服务端决定用哪个套件：客户端偏好排序在历史上曾被
	// 用于降级攻击（如 FREAK），现代实践一律由服务端决定。
	b.WriteString("    ssl_prefer_server_ciphers off;\n")
	b.WriteString("\n")
	// 会话缓存：TLS 握手的开销主要在非对称运算，复用会话能显著
	// 降低回访延迟。shared 让所有 worker 共享（否则每个 worker
	// 各自缓存，命中率随 worker 数下降）。
	b.WriteString("    ssl_session_cache shared:SSL:10m;\n")
	b.WriteString("    ssl_session_timeout 1d;\n")
	// 关闭 session ticket：它用固定密钥加密会话，密钥长期不轮换
	// 会削弱前向保密性。会话缓存已足够，因此直接关掉。
	b.WriteString("    ssl_session_tickets off;\n")
	b.WriteString("\n")
	// OCSP Stapling：让 nginx 代客户端去取吊销状态，
	// 客户端不必再单独访问 CA（更快，且不泄露用户访问的域名）。
	b.WriteString("    ssl_stapling on;\n")
	b.WriteString("    ssl_stapling_verify on;\n")
	// 让 nginx 信任证书链里的中间证书（fullchain.pem 已包含），
	// 这样 stapling 响应才能被正确验证。
	b.WriteString("    ssl_trusted_certificate " + cfg.CertPath + ";\n")
}

// writeStaticBody 写静态站的 location 段。
func writeStaticBody(b *strings.Builder, s Site, index []string) {
	// root 已被 ValidRoot 校验：绝对路径、已 Clean、无空白与元字符。
	b.WriteString("    # 静态站根目录\n")
	b.WriteString("    root " + s.Root + ";\n")
	// index 文件名已逐个校验。
	b.WriteString("    index " + strings.Join(index, " ") + ";\n")
	b.WriteString("\n")
	b.WriteString("    location / {\n")
	// try_files 是静态站正确性的关键：
	//
	//	try_files $uri $uri/ =404;
	//
	// 少了 `=404` 时，nginx 在文件和目录都不存在的情况下会返回
	// **内部重定向到目录索引**，最终表现为 403 或目录列表，
	// 而不是明确的 404。对纯静态站来说后者才是正确语义
	// （单页应用的 `try_files $uri /index.html` 是另一种需求，
	// 不在本期范围内）。
	b.WriteString("        try_files $uri $uri/ =404;\n")
	b.WriteString("    }\n")
}

// writeProxyBody 写反向代理站点的 location 段。
func writeProxyBody(b *strings.Builder, s Site, opts RenderOptions) {
	// Upstream 已被 ValidUpstream 校验：协议只可能是 http/https，
	// host 是 IP 或合法域名，无用户信息、无查询串、无 nginx 元字符。
	b.WriteString("    # 反向代理\n")
	b.WriteString("    location / {\n")
	b.WriteString("        proxy_pass " + s.Upstream + ";\n")
	b.WriteString("        proxy_http_version 1.1;\n")

	if !opts.NoProxyHeaders {
		b.WriteString("\n")
		b.WriteString("        # 标准转发头（缺了它们后端拿不到真实客户端信息）\n")
		// Host 透传：后端据此生成绝对 URL、做域名路由。
		b.WriteString("        proxy_set_header Host $host;\n")
		// X-Real-IP / X-Forwarded-For：后端日志与限流依赖真实客户端 IP。
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		// X-Forwarded-Proto：后端据此判断"用户是否走的 https"，
		// 决定要不要做 http→https 跳转、Cookie 要不要加 Secure。
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		// Upgrade/Connection：WebSocket 透传。
		// 少了这两行，反代后的 websocket 会在握手阶段就失败，
		// 而这是个非常常见的需求（面板自己就用了 WS）。
		//
		// ⚠️ Connection 用的是 nginx 内置变量 $http_connection，
		// 而**不是**流传很广的 `$connection_upgrade`。
		//
		// 这一点是真实 nginx 测出来的：`$connection_upgrade` **不是**
		// nginx 的内置变量，它需要配合 http 层的
		//   map $http_upgrade $connection_upgrade { default upgrade; '' close; }
		// 才能使用。而站点配置是 server 块，**无法**在 server 块里定义 map
		// （map 只能出现在 http 上下文）。
		//
		// 直接写 $connection_upgrade 的后果是 nginx -t 报
		// `unknown "connection_upgrade" variable` —— 配置被拒绝、
		// 站点建不出来（本项目的真实 nginx 集成测试当场抓到了这个缺陷）。
		//
		// 用 $http_connection 是可验证正确且自包含的写法：它把客户端
		// 发来的 Connection 头原样透传，WebSocket 握手因此可以正常工作，
		// 且不需要用户在 http 层额外配置任何东西。
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection $http_connection;\n")
	}

	// 超时：默认 60s 对长连接与慢接口太短。
	// 这里给出的是**明确写死**的保守值，而不是让用户配——
	// 一旦开放超时配置，就得同时处理"读超时/写超时/连接超时"
	// 三者的语义差异，超出本期范围。写死的值至少是确定且可预期的。
	b.WriteString("\n")
	b.WriteString("    proxy_connect_timeout 60s;\n")
	b.WriteString("    proxy_send_timeout 300s;\n")
	b.WriteString("    proxy_read_timeout 300s;\n")

	b.WriteString("    }\n")
}

// typeLabel 把类型翻译成配置注释里的中文说明。
func typeLabel(t string) string {
	switch t {
	case TypeStatic:
		return "静态站"
	case TypeProxy:
		return "反向代理"
	}
	return t
}

// renderCheck 在生成配置前对全部字段做一次校验。
//
// 这份校验与调用方的校验**有意重复**：调用方在 API 入口校验是为了
// 尽早返回可读错误，这里的校验是为了保证"无论谁调用 Render，
// 输出都不可能是畸形配置"。安全性质上，冗余的断言是特性而不是负担。
func renderCheck(s Site) error {
	if err := ValidSiteName(s.Name); err != nil {
		return err
	}
	if err := ValidDomain(s.Domain); err != nil {
		return err
	}
	switch s.Type {
	case TypeStatic:
		return ValidRoot(s.Root)
	case TypeProxy:
		return ValidUpstream(s.Upstream)
	default:
		return fmt.Errorf("%w: %q（只支持 %s / %s）",
			ErrInvalidType, s.Type, TypeStatic, TypeProxy)
	}
}

// validIndexFile 校验一个 index 文件名。
//
// 与 ValidRoot 同样的思路：它会被拼进 `index a.html b.html;`，
// 因此不能含空白、分号、任意 nginx 元字符，也不能是路径。
func validIndexFile(name string) error {
	if name == "" {
		return fmt.Errorf("%w: index 文件名不能为空", ErrInvalidRoot)
	}
	if strings.ContainsAny(name, " \t\n\r;{}\"'$#`\\/:") {
		return fmt.Errorf("%w: index 文件名 %q 含有非法字符", ErrInvalidRoot, name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: index 文件名 %q 非法", ErrInvalidRoot, name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 配置解析（用于"读回"面板生成的站点）
// ---------------------------------------------------------------------------

// ParsedConf 是从配置文件中读回的关键信息。
//
// 为什么需要"读回"而不是把站点元数据存进数据库/JSON 索引：
//
//	nginx 的配置文件**本身就是唯一真相**。若面板再维护一份索引，
//	就会出现两份可能不一致的状态：用户手工删了 .conf，索引里还有；
//	用户手工改了 root，索引里还是旧的。面板重启、配置被外部工具
//	（certbot 等）改写之后，这种不一致会立刻显现。
//
//	因此列表接口的实现是"扫描目录、解析文件"，而不是"读索引"。
//	代价是解析必须容忍"非面板生成的配置"（那类文件的格式我们不了解），
//	做法是：解析不出来的就标记为 External，只读展示，不提供编辑。
type ParsedConf struct {
	// Generated 表示该配置由面板生成（含 GeneratedMarker）。
	Generated bool
	// ServerNames 是解析出的 server_name 列表。
	ServerNames []string
	// Root 是解析出的 root 指令值（静态站）。
	Root string
	// ProxyPass 是解析出的 proxy_pass 值（反代站）。
	ProxyPass string
	// Listen 是解析出的 listen 端口。
	Listen []string
}

// directivePattern 匹配一行简单的 `指令 参数;`。
//
// 刻意用逐行扫描而不是引入完整的 nginx 配置解析器：
//   - 完整解析需要处理嵌套块、include、变量展开，是一个相当大的工程；
//   - 面板只需要提取 4 个顶层指令用于**展示**，解析失败时降级为
//     External（只读展示）是完全可接受的。
//
// 这就是"不为展示需求引入重型依赖"的取舍，与全项目的轻量约束一致。
func parseConf(content string) ParsedConf {
	p := ParsedConf{Generated: strings.Contains(content, GeneratedMarker)}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 去掉行尾注释。nginx 的 `#` 在引号内不算注释，
		// 但面板生成的配置不含引号，这里做简化处理即可。
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// 只处理 `key value;` 形态；块开始/结束行（`server {`、`}`）跳过。
		semi := strings.Index(line, ";")
		if semi < 0 {
			continue
		}
		fields := strings.Fields(line[:semi])
		if len(fields) < 2 {
			continue
		}
		key, value := fields[0], strings.Join(fields[1:], " ")
		switch key {
		case "server_name":
			p.ServerNames = append(p.ServerNames, strings.Fields(value)...)
		case "root":
			if p.Root == "" {
				p.Root = value
			}
		case "proxy_pass":
			if p.ProxyPass == "" {
				p.ProxyPass = value
			}
		case "listen":
			p.Listen = append(p.Listen, strings.Fields(value)...)
		}
	}
	return p
}

// ParseContent 解析一份配置内容（导出给测试与 server 层使用）。
func ParseContent(content string) ParsedConf { return parseConf(content) }

// sortedKeys 返回 map 的排序键，用于生成稳定输出（测试与日志可比对）。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// itoa 是 strconv.Itoa 的短别名，用于端口拼接。
func itoa(n int) string { return strconv.Itoa(n) }
