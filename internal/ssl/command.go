package ssl

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// certbot 命令组装（纯函数，可单测）
// ============================================================================
//
// 本文件只回答一个问题：**给定这些输入，应该执行哪个命令、argv 是什么？**
// 它不执行任何命令、不碰文件系统，因此可以被穷举测试
// （计划要求「新增 certbot 命令组装测试」，这里是那条要求的落点）。
//
// #################### 安全核心：argv 切片，绝不拼 shell ####################
//
// 与 4.1（systemctl）、4.3（nginx）完全一致的做法：
// name 与 args 分开传递，由 exec.CommandContext 直接构造 argv，
// **不出现 `sh -c`、不出现字符串拼接**。这样 `;`、`$()`、反引号、
// 管道符对 certbot 而言都只是普通的域名字符（进而在校验层被拒），
// 而不会变成 shell 的一条命令。
//
// #################### HTTP-01 为什么用 webroot 而不是 standalone ####################
//
// certbot 的 HTTP-01 有两种落地方式：
//
//	--standalone：certbot 自己起一个临时 HTTP 服务器占用 80 端口。
//	              **但 4.3 的站点本来就在监听 80**，于是 certbot 会因为
//	              端口被占而直接失败；要让它成功就得先停 nginx——
//	              那等于每次申请证书都全站中断几十秒。
//	--webroot   ：把挑战文件写进站点根目录的 .well-known/acme-challenge/，
//	              复用 nginx 现有的 80 监听。**零中断**。
//
// 因此本模块固定使用 `--webroot -w <站点根目录>`。
// 这也是计划里「先用 HTTP-01」的合理落地方式。

// 证书申请/续期相关的哨兵错误。
var (
	// ErrInvalidDomain 表示域名不合法（未通过白名单校验）。
	ErrInvalidDomain = errors.New("ssl: 域名非法")
	// ErrWildcardNotSupported 表示域名是通配符（需要 DNS-01，本期不做）。
	ErrWildcardNotSupported = errors.New("ssl: 不支持通配符域名")
	// ErrInvalidWebroot 表示 webroot 目录不合法。
	ErrInvalidWebroot = errors.New("ssl: webroot 目录不合法")
	// ErrInvalidEmail 表示邮箱不合法。
	ErrInvalidEmail = errors.New("ssl: 邮箱格式非法")
	// ErrInvalidCertName 表示证书名不合法。
	ErrInvalidCertName = errors.New("ssl: 证书名非法")
)

// ============================================================================
// 域名校验
// ============================================================================

// domainLabelPattern 限定单个域名标签的字符集。
//
// 与 4.3 site 包的域名规则一致（仅主机名字符集），但**不含 `*`**：
// 通配符在本模块是显式拒绝的（见 ValidIssueDomain）。
var domainLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$`)

// MaxDomainLen 是域名的最大长度（DNS 规范 253）。
const MaxDomainLen = 253

// ValidIssueDomain 校验「能否为这个域名申请证书」。
//
// 与 4.3 的 ValidDomain 是**两个不同的问题**，因此各有各的函数：
//
//	4.3 ValidDomain    —— 「这个域名能不能写进 nginx 的 server_name」
//	                       （允许 `_` 默认站，允许 `*.example.com`）
//	4.4 ValidIssueDomain —— 「能不能向 Let's Encrypt 为它签发证书」
//	                       （**不允许** `_`，**不允许** `*`）
//
// ########## 为什么必须显式拒绝通配符（而不是让它自然失败）##########
//
// `*.example.com` 在 nginx 里完全合法，用户会理所当然地
// 把站点域名填成它，然后点「申请证书」。如果这里放行，
// 命令会被原样执行，certbot 用 HTTP-01 必然失败，返回的是一段
// 冗长的 ACME 报错（大意是"通配符需要 DNS-01"）。
// 用户要读完那段报错才知道「原来这个功能不支持」。
//
// 明确拒绝并给出「通配符需要 DNS 验证，本版本未支持」，
// 是把一句 ACME 黑话翻译成一句人话——这正是校验层该做的事。
//
// 另外，拒绝 `_`：它是 4.3 用来标记「默认站」的约定值，
// 而不是一个真实可解析的域名，CA 不可能为它签发证书。
func ValidIssueDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("%w: 域名为空", ErrInvalidDomain)
	}
	if len(domain) > MaxDomainLen {
		return fmt.Errorf("%w: 域名长度 %d 超过上限 %d", ErrInvalidDomain, len(domain), MaxDomainLen)
	}
	// 通配符单独判断，给出比"字符集非法"更有用的提示。
	if strings.HasPrefix(domain, "*.") || strings.Contains(domain, "*") {
		return fmt.Errorf("%w: %q 是通配符域名。通配符需要 DNS-01 验证，"+
			"本版本仅支持 HTTP-01（请改用具体域名，或等待后续版本）",
			ErrWildcardNotSupported, domain)
	}
	// 校验函数**只回答能不能用，绝不悄悄改写输入**（4.3 的教训）：
	// 若在这里做 TrimSpace/ToLower，用户提交 `"example.com\n"` 会被
	// 静默接受，而校验看到的已经不是他真正提交的内容。
	if strings.TrimSpace(domain) != domain {
		return fmt.Errorf("%w: 域名首尾不能有空白字符", ErrInvalidDomain)
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		// 单标签（如 `localhost`）无法被公共 CA 签发。
		return fmt.Errorf("%w: %q 不是完整域名（至少需要两级，如 example.com）",
			ErrInvalidDomain, domain)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%w: %q 含有空的域名段（连续的 . ）", ErrInvalidDomain, domain)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: %q 中的域名段 %q 超过 63 字符", ErrInvalidDomain, domain, label)
		}
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("%w: %q 中的域名段 %q 含非法字符"+
				"（只允许字母、数字、连字符，且不能以连字符开头或结尾）",
				ErrInvalidDomain, domain, label)
		}
	}
	return nil
}

// ============================================================================
// webroot 校验
// ============================================================================

// webrootPattern 限定 webroot 的字符集。
//
// 与 4.3 的根目录校验同款：白名单字符集 + 判 `..` 路径段。
// 判据是 path segment 而不是子串，避免误杀 `my..site` 这类合法目录名。
var webrootPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// ValidWebroot 校验 webroot 目录路径。
//
// webroot 会被作为 `-w` 的参数交给 certbot，certbot 会往里写文件。
// 因此它必须是绝对路径，且不含任何元字符。
func ValidWebroot(dir string) error {
	if dir == "" {
		return fmt.Errorf("%w: webroot 目录为空。"+
			"静态站请在站点配置中填写根目录；反向代理站请先配置 webroot", ErrInvalidWebroot)
	}
	if !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("%w: %q 必须是绝对路径", ErrInvalidWebroot, dir)
	}
	if strings.TrimSpace(dir) != dir {
		return fmt.Errorf("%w: 路径首尾不能有空白字符", ErrInvalidWebroot)
	}
	if !webrootPattern.MatchString(dir) {
		return fmt.Errorf("%w: %q 含非法字符（只允许字母、数字、. _ - /）", ErrInvalidWebroot, dir)
	}
	// 逐段判 `..`：`/var/www/../../etc` 这种写法虽然字符集合法，
	// 但会让 certbot 写到预期之外的位置。
	for _, seg := range strings.Split(dir, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: %q 含 `..` 路径段", ErrInvalidWebroot, dir)
		}
	}
	return nil
}

// ============================================================================
// 邮箱与证书名校验
// ============================================================================

// emailPattern 是宽松的邮箱格式校验。
//
// 为什么"宽松"：邮箱只用于 Let's Encrypt 的到期提醒与账号找回，
// 不必做到 RFC 5322 级别的完整校验（那个正则长得没人能维护，
// 而且真实世界里的合法邮箱千奇百怪）。这里只挡住**明显不是邮箱**
// 的输入，以及会破坏 certbot 参数解析的字符（空格、引号、分号）。
var emailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

// ValidEmail 校验邮箱。
//
// 空邮箱是**允许**的：certbot 支持不提供邮箱（会跳过到期提醒）。
// 但此时无法注册 ACME 账号的通知渠道，因此在 Capabilities 里
// 会提示用户配置 -certbot-email 更稳妥。
func ValidEmail(email string) error {
	if email == "" {
		return nil
	}
	if strings.TrimSpace(email) != email {
		return fmt.Errorf("%w: 首尾不能有空白字符", ErrInvalidEmail)
	}
	if !emailPattern.MatchString(email) {
		return fmt.Errorf("%w: %q 不是合法的邮箱地址", ErrInvalidEmail, email)
	}
	return nil
}

// certNamePattern 限定 certbot 的证书名（--cert-name）。
//
// 证书名会成为 letsencrypt/live/<name>/ 的目录名，
// 因此字符集必须收得很紧——它同时是一个路径分量。
var certNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidCertName 校验证书名。
func ValidCertName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: 证书名为空", ErrInvalidCertName)
	}
	if len(name) > 128 {
		return fmt.Errorf("%w: 证书名过长（%d > 128）", ErrInvalidCertName, len(name))
	}
	if !certNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q 只允许字母、数字、. _ -，且不能以符号开头", ErrInvalidCertName, name)
	}
	// `..` 会让路径逃出 live/ 目录（证书名是路径分量）。
	if strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q 不能含连续的 . （会构成路径穿越）", ErrInvalidCertName, name)
	}
	return nil
}

// ============================================================================
// 命令组装
// ============================================================================

// IssueRequest 是一次证书申请的全部输入。
type IssueRequest struct {
	// Domains 是要签发的主域名（第一个为主域名）。
	//
	// 本期只支持单域名（多域名与泛域名一起留给下一阶段），
	// 因此组装命令时会断言长度为 1。
	Domains []string
	// Webroot 是 HTTP-01 挑战文件的落盘目录。
	Webroot string
	// Email 是 ACME 账号邮箱（可为空）。
	Email string
	// CertName 是证书名；为空时用主域名。
	CertName string
	// DryRun 为 true 时走 ACME staging 且不落盘证书。
	DryRun bool
	// Force 为 true 时即使证书仍有效也强制重新签发。
	//
	// ⚠️ 默认 **false**：Let's Encrypt 对同一组域名有
	// 「每周 5 次重复签发」的速率限制，无脑 force 很容易把配额打满，
	// 之后整整一周都申请不了（连正常续期都会失败）。
	Force bool
}

// Command 是一条待执行的命令。
//
// 与 4.1/4.3 的 Executor 接口对接：name 与 args 分开放，
// 由 exec.CommandContext 直接构造 argv。
type Command struct {
	// Name 是可执行文件路径。
	Name string
	// Args 是参数切片（不含 Name）。
	Args []string
	// Label 是人类可读的命令用途（用于日志与审计，不参与执行）。
	Label string
	// Redacted 是可用于展示/落盘的命令文本（已脱敏）。
	//
	// 单独一个字段而不是让调用方自己 join(args)：
	// 展示用的命令文本需要处理"参数含空格要加引号"这类细节，
	// 而且将来若出现敏感参数（如 DNS API 密钥），
	// 脱敏逻辑只需要改这一处。
	Redacted string
}

// String 返回可用于日志的命令文本。
func (c Command) String() string { return c.Redacted }

// ---------------------------------------------------------------------------
// 申请
// ---------------------------------------------------------------------------

// BuildIssueCommand 组装证书申请命令。
//
// 命令形状（实测 certbot 1.21 可用）：
//
//	certbot certonly --webroot -w <webroot> -d <domain>
//	        --cert-name <name> --non-interactive --agree-tos
//	        [--email <email>] [--no-eff-email] [--dry-run] [--force-renewal]
//
// 逐项说明为什么需要：
//
//	certonly         只签发证书，**不改 nginx 配置**。
//	                 这一点至关重要：certbot 自带 `--nginx` 插件会
//	                 直接改写 /etc/nginx 下的文件，而本项目有
//	                 明确红线——配置一律由 4.3 的 site.Manager 经
//	                 "nginx -t + 可回滚"链路写入。用 certonly 把
//	                 certbot 限制为"只发证书"，写配置的活仍由面板负责。
//	--webroot -w     用 HTTP-01，零中断（见文件头说明）。
//	-d               要签发的域名。
//	--cert-name      固定证书名，让后续按站点名精确查找/续期，
//	                 而不是依赖 certbot 自动取名（它取的名是主域名，
//	                 遇到多域名时形态会让人猜不到）。
//	--non-interactive 绝不交互。没有它，certbot 在缺邮箱/未同意条款时
//	                 会**等待标准输入**，而面板是无终端的后台进程——
//	                 表现是请求一直挂到超时，用户只看到"申请超时"。
//	--agree-tos      同意 ACME 用户协议（等价于用户在界面上勾选确认）。
//	--no-eff-email   不把邮箱分享给 EFF。默认 certbot 会询问，
//	                 不加这个参数在非交互模式下同样会卡住。
//	--dry-run        使用 staging 环境且不写证书（测试用）。
func BuildIssueCommand(client string, req IssueRequest) (Command, error) {
	// ---------- 校验（全部通过后才开始拼 argv） ----------
	if len(req.Domains) == 0 {
		return Command{}, fmt.Errorf("%w: 未提供域名", ErrInvalidDomain)
	}
	if len(req.Domains) > 1 {
		// 明确拒绝而不是默默只用第一个：用户提交了多个域名却只签了一个，
		// 他会以为都签好了。
		return Command{}, fmt.Errorf("%w: 本版本一次只能为一个域名申请证书（收到 %d 个）",
			ErrInvalidDomain, len(req.Domains))
	}
	domain := req.Domains[0]
	if err := ValidIssueDomain(domain); err != nil {
		return Command{}, err
	}
	if err := ValidWebroot(req.Webroot); err != nil {
		return Command{}, err
	}
	if err := ValidEmail(req.Email); err != nil {
		return Command{}, err
	}
	certName := req.CertName
	if certName == "" {
		certName = domain
	}
	if err := ValidCertName(certName); err != nil {
		return Command{}, err
	}

	// ---------- 拼 argv ----------
	args := []string{
		"certonly",
		"--webroot",
		"-w", req.Webroot,
		"-d", domain,
		"--cert-name", certName,
		"--non-interactive",
		"--agree-tos",
	}
	if req.Email != "" {
		args = append(args, "--email", req.Email, "--no-eff-email")
	} else {
		// 无邮箱时必须显式 --register-unsafely-without-email，
		// 否则非交互模式下 certbot 会因"没有邮箱"而拒绝注册账号。
		args = append(args, "--register-unsafely-without-email")
	}
	if req.DryRun {
		args = append(args, "--dry-run")
	}
	if req.Force {
		args = append(args, "--force-renewal")
	}

	label := "申请证书"
	if req.DryRun {
		label = "申请证书（试运行）"
	}
	return Command{
		Name:     client,
		Args:     args,
		Label:    label,
		Redacted: RedactCommand(client, args),
	}, nil
}

// ---------------------------------------------------------------------------
// 续期
// ---------------------------------------------------------------------------

// BuildRenewCommand 组装单个证书的续期命令。
//
// 命令形状：
//
//	certbot renew --cert-name <name> --non-interactive [--dry-run] [--force-renewal]
//
// 用 `renew --cert-name` 而不是重新跑一次 `certonly`：
//
//	certonly 会**沿用原证书的续期配置**（renewal/<name>.conf）？
//	  不会——certonly 是"新建一份"，如果参数与当初不一致
//	  （例如 webroot 变了），certbot 会报"证书已存在，参数不同"。
//	renew 则严格按当初落盘的 renewal 配置重新签发，
//	  这才是"续期"的准确语义，也避免了参数漂移。
//
// 不加 --force-renewal 时，certbot 只在证书进入续期窗口
// （默认剩余 30 天）时才真正签发，否则输出"not yet due for renewal"
// 并以 0 退出。这个默认行为正合我们意：手动点"续期"不会
// 白白消耗 Let's Encrypt 的配额。
func BuildRenewCommand(client, certName string, dryRun, force bool) (Command, error) {
	if err := ValidCertName(certName); err != nil {
		return Command{}, err
	}
	args := []string{
		"renew",
		"--cert-name", certName,
		"--non-interactive",
	}
	if dryRun {
		args = append(args, "--dry-run")
	}
	if force {
		args = append(args, "--force-renewal")
	}
	label := "续期证书"
	if dryRun {
		label = "续期证书（试运行）"
	}
	return Command{
		Name:     client,
		Args:     args,
		Label:    label,
		Redacted: RedactCommand(client, args),
	}, nil
}

// BuildRenewAllCommand 组装"续期所有即将到期的证书"命令。
//
// 定时任务用这条：一次调用让 certbot 自己判断哪些证书已进入
// 续期窗口，避免面板为每张证书各起一个进程。
//
// ⚠️ **不加 --force-renewal**：定时器每 12 小时跑一次，
// 加了 force 等于每天把全部证书重新签发一遍，
// 几天内就会撞上 Let's Encrypt 的速率限制，
// 之后连正常的紧急续期都做不了。
func BuildRenewAllCommand(client string, dryRun bool) Command {
	args := []string{"renew", "--non-interactive"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	label := "批量续期"
	if dryRun {
		label = "批量续期（试运行）"
	}
	return Command{
		Name:     client,
		Args:     args,
		Label:    label,
		Redacted: RedactCommand(client, args),
	}
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

// BuildListCommand 组装"列出全部证书"命令。
func BuildListCommand(client string) Command {
	args := []string{"certificates"}
	return Command{
		Name:     client,
		Args:     args,
		Label:    "查询证书",
		Redacted: RedactCommand(client, args),
	}
}

// BuildVersionCommand 组装版本查询命令。
func BuildVersionCommand(client string) Command {
	args := []string{"--version"}
	return Command{
		Name:     client,
		Args:     args,
		Label:    "查询客户端版本",
		Redacted: RedactCommand(client, args),
	}
}

// ============================================================================
// 命令展示
// ============================================================================

// RedactCommand 把命令渲染成可安全展示的字符串。
//
// 拼接规则：含空格或特殊字符的参数加单引号，
// 让用户可以直接复制到终端里执行（便于手工复现问题）。
func RedactCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(name))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// quoteArg 在必要时给参数加引号。
func quoteArg(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n'\"\\$`;|&<>(){}[]*?!#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// ============================================================================
// 执行器
// ============================================================================

// Executor 执行一条外部命令并返回 stdout/stderr。
//
// 与 4.1 service.Executor、4.3 site.Executor 同构：
// name 与 args 分开放，**不经过 shell**。抽成接口是为了可测
// （申请/续期链路要能用假客户端跑通，而不必真的访问 Let's Encrypt）。
type Executor interface {
	// Run 执行命令；实现必须带超时，且 ctx 取消时立即返回。
	Run(ctx context.Context, name string, args []string) (stdout string, stderr string, err error)
}

// execExecutor 是默认执行器，基于 os/exec。
type execExecutor struct{}

func (execExecutor) Run(ctx context.Context, name string, args []string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// LANG/LC_ALL 强制 C：certbot 的输出会被我们解析，
	// 固定语言能让格式稳定（本地化翻译会破坏正则）。
	//
	// 这一条在 certbot 上比在 nginx 上更关键：certbot 是 Python 程序，
	// 它会遵循 locale 输出本地化文案，而我们的解析器匹配的是英文关键字。
	cmd.Env = append(cmd.Environ(), "LANG=C", "LC_ALL=C")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// runCommand 执行一条 Command 并返回合并输出。
//
// 合并 stdout+stderr 而不是分开返回：certbot 把错误写 stderr、
// 把正常信息写 stdout，但**两者都可能包含我们需要的诊断信息**
// （例如 renew 的失败原因在 stderr，而"not yet due"在 stdout）。
// 分开处理只会让调用方在两处各写一遍判断。
func runCommand(ctx context.Context, ex Executor, c Command, timeout time.Duration) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, err := ex.Run(cmdCtx, c.Name, c.Args)
	combined := strings.TrimSpace(strings.TrimSpace(stdout) + "\n" + strings.TrimSpace(stderr))
	combined = strings.TrimSpace(combined)

	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return combined, fmt.Errorf("%w: %s 在 %s 内未返回", ErrTimeout, c.Label, timeout)
	}
	if err != nil {
		return combined, fmt.Errorf("%s 失败: %w", c.Label, err)
	}
	return combined, nil
}
