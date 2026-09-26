package ssl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 证书生命周期管理（阶段四 4.4，核心自带）
// ============================================================================
//
// 本文件编排「申请 → 写入 nginx → 生效」这条链路。
//
// #################### 与 4.3 site.Manager 的分工（关键设计）####################
//
// 本包**不重复实现** nginx 配置写入、nginx -t 校验与回滚——那正是
// 4.3 已经做过并被测试锁死的能力，重复实现等于把"配置写坏导致全站中断"
// 这个风险重新引入一次。
//
//	ssl.Manager  负责：探测客户端、申请证书、查询到期时间、组织 nginx 配置片段
//	site.Manager 负责：快照 → 写盘 → nginx -t → reload → 失败自动回滚
//
// 两者的衔接点是 main.go 注入的 **ConfigRewriter** 闭包：
//
//	ssl.Manager 调 rewriter.Apply(ctx, site, sslMaterial)
//	  └─ main.go 里的实现调用 site.Manager.ApplySSLConfig(...)
//	       └─ 走 site.Manager 已有的回滚链路
//
// 为什么用闭包而不是让 ssl 包 import site 包：
// 那会让两个核心模块形成**循环依赖**（site 需要 ssl 提供证书路径，
// ssl 需要 site 提供写入能力）。同一手法在 4.3 已经用过一次：
// site 用 RootChecker 闭包避免 import file 包。
//
// #################### 申请成功了但配置没写成功，怎么办 ####################
//
// 这是一个**必须显式处理**的部分成功状态：
//
//	certbot 已经从 CA 拿到证书（配额已消耗），
//	但把 ssl_certificate 写进 nginx 时失败（校验不过 / nginx -t 失败）。
//
// 若把整件事简单记成"失败"，用户会反复重试，
// 每次都消耗一次 CA 配额，直到撞上速率限制。
//
// 因此本模块的处理是：
//  1. **不回滚证书**（证书本身是好的，删掉只会浪费配额；
//     下次申请会命中"证书已存在"而跳过签发）；
//  2. 返回的错误里**明确说明**"证书已获取但配置未生效"；
//  3. 审计里 Issued=true / Applied=false，让这个状态可被检索。

// 错误分类。调用方（server 层）据此映射 HTTP 状态码。
var (
	// ErrNotFound 表示站点或证书不存在。
	ErrNotFound = errors.New("ssl: 站点或证书不存在")
	// ErrTimeout 表示命令执行超时。
	ErrTimeout = errors.New("ssl: 操作超时")
	// ErrClientFailed 表示 ACME 客户端执行失败。
	ErrClientFailed = errors.New("ssl: ACME 客户端执行失败")
	// ErrAlreadyValid 表示证书仍在有效期内，无需重新申请。
	ErrAlreadyValid = errors.New("ssl: 证书仍在有效期内")
	// ErrAppliedFailed 表示证书已获取但写入 nginx 配置失败。
	//
	// ⚠️ 这是**部分成功**：CA 配额已被消耗，但站点没有启用 HTTPS。
	// 单独一个哨兵错误，让调用方能给出与"完全失败"不同的提示。
	ErrAppliedFailed = errors.New("ssl: 证书已获取，但写入 nginx 配置失败")
	// ErrNoWebroot 表示站点缺少可用于 HTTP-01 的 webroot 目录。
	ErrNoWebroot = errors.New("ssl: 站点没有可用的 webroot 目录")
)

// SiteRef 是 ssl 模块看到的「站点」最小视图。
//
// ########## 为什么定义一个自己的类型，而不是直接用 site.Site ##########
//
// 直接用 site.Site 会让 ssl 包 import site 包，形成循环依赖
// （site 需要 ssl 的证书路径，ssl 需要 site 的站点信息）。
//
// 更重要的理由是**职责**：证书模块真正需要知道的只有四件事——
// 叫什么、域名是什么、webroot 在哪、当前 nginx 配置长什么样。
// 定义一个恰好这么多字段的类型，让"证书模块会不会顺手改站点"
// 这个问题在类型层面就有了答案：它拿到的信息根本不足以做别的事。
//
// 字段由 main.go 从 site.Site 映射而来。
type SiteRef struct {
	// Name 是站点名（配置文件名）。
	Name string
	// Domain 是站点域名（申请证书的主体）。
	Domain string
	// Root 是静态站根目录，同时用作 HTTP-01 的 webroot。
	Root string
	// Upstream 是反向代理目标（展示用）。
	Upstream string
	// Type 是站点类型（static / proxy）。
	Type string
	// Enabled 表示站点当前是否被 nginx 加载。
	Enabled bool
	// ConfigPath 是站点配置文件的绝对路径。
	ConfigPath string
}

// SSLConfig 是要写入 nginx 的 SSL 配置片段。
//
// 它由 ssl 模块**组织**（因为只有它知道证书路径与到期策略），
// 但由 site 模块**渲染与落盘**（因为只有它有回滚能力）。
type SSLConfig struct {
	// CertPath 是 fullchain.pem 路径（ssl_certificate）。
	CertPath string
	// KeyPath 是 privkey.pem 路径（ssl_certificate_key）。
	KeyPath string
	// RedirectHTTP 表示是否加上 HTTP → HTTPS 的 301 跳转。
	RedirectHTTP bool
	// Protocols 是 ssl_protocols 的取值。
	Protocols string
	// Ciphers 是 ssl_ciphers 的取值。
	Ciphers string
}

// DefaultProtocols 是默认启用的 TLS 协议版本。
//
// 只保留 TLSv1.2 与 TLSv1.3：
//
//	TLSv1.0 / TLSv1.1 已被所有主流浏览器废弃，
//	且存在已知弱点（BEAST / POODLE）。Let's Encrypt 签发的证书
//	完全支持 1.2+，因此没有任何理由保留旧版本。
//
// 这是一处**安全默认值优于兼容性**的取舍：极少数老旧客户端
// （Windows XP 上的 IE、Android 4.x）会连不上，但它们本来
// 也无法安全地建立连接。
const DefaultProtocols = "TLSv1.2 TLSv1.3"

// DefaultCiphers 是默认的加密套件。
//
// 用 `HIGH:!aNULL:!MD5` 这种**由 OpenSSL 解释**的表达式，
// 而不是写死一串套件名：
//
//	写死套件名的配置会随时间腐化（某天某个套件被发现有漏洞，
//	用户必须手工改配置）；而 `HIGH:!aNULL:!MD5` 让 OpenSSL
//	自己按当前版本的安全评级挑选，随系统升级自动获益。
//
// 不写 `!3DES` 这类过细的排除：它们属于 OpenSSL 的 MEDIUM 级别，
// 已被 `HIGH` 排除在外。
const DefaultCiphers = "HIGH:!aNULL:!MD5"

// ConfigRewriter 是 ssl 模块与 site 模块之间的衔接点。
//
// 由 main.go 注入。实现方必须：
//  1. 把 SSLConfig 渲染进站点的 nginx 配置；
//  2. 走「快照 → 写盘 → nginx -t → reload」链路；
//  3. **失败时自动回滚**，并让错误里带上"是否已回滚"的信息。
//
// 第 3 条是这个接口存在的最重要理由：证书配置写坏会让
// **整台机器的 HTTPS 全部不可用**，而回滚只能由持有快照的一方完成。
type ConfigRewriter interface {
	// ApplySSL 把 ssl 配置应用到指定站点。
	//
	// 返回的错误若是 site.ErrRolledBack（或实现了 Unwrap 到它），
	// 调用方应当把它当作"配置已自动回滚，服务未受影响"来处理。
	ApplySSL(ctx context.Context, siteName string, cfg SSLConfig) error
	// RemoveSSL 从站点配置中移除 SSL（用于证书失效后的降级）。
	RemoveSSL(ctx context.Context, siteName string) error
}

// ManagerOptions 是构造 Manager 的配置。
type ManagerOptions struct {
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Detector 是 ACME 客户端探测器；为 nil 时新建一个默认探测器。
	Detector *Detector
	// Sites 提供站点查询能力（由 main.go 从 site.Manager 适配而来）。
	//
	// 为 nil 时 SSL 管理不可用（接口返回 503），而不是 panic。
	Sites SiteProvider
	// Rewriter 负责把 SSL 配置写入 nginx；为 nil 时"申请成功但不改配置"。
	//
	// 允许为 nil 是有意的：它让本模块的**证书能力**可以被独立测试
	// 与独立使用（例如用户只想拿证书、自己配 nginx）。
	// 此时申请结果里会明确标注"未写入 nginx 配置"。
	Rewriter ConfigRewriter
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// Email 是 ACME 账号邮箱。
	Email string
	// RenewDays 是"即将过期"阈值（同时是自动续期的触发条件）。
	// <=0 时用 DefaultRenewDays。
	RenewDays int
	// CommandTimeout 是单次 certbot 命令的超时；<=0 时用 DefaultCommandTimeout。
	CommandTimeout time.Duration
	// Executor 执行 certbot 命令；为 nil 时用 exec.CommandContext。
	Executor Executor
	// DryRun 为 true 时所有申请/续期都走 ACME staging 且不落盘证书。
	//
	// 这个开关的用途是"让用户先在安全的沙箱里跑通流程"：
	// staging 环境签发的证书不被浏览器信任，但**完整走通了
	// ACME 协议流程**（含 HTTP-01 挑战验证），因此能验证
	// 「webroot 配对了没、80 端口通不通」这些真正会出问题的环节，
	// 而不消耗生产配额。
	DryRun bool
}

// DefaultCommandTimeout 是单次 certbot 命令的默认超时。
//
// 120s：真实申请需要与 CA 往返多次（注册账号、下单、写挑战文件、
// 通知 CA 验证、CA 回源抓取挑战文件、取回证书）。
// 网络慢时 30s 不够——而**申请超时的代价比等待更糟**：
// 进程被杀时 CA 那边可能已经签发完成，配额已经消耗，
// 本地却什么都没拿到。
//
// 相比 4.1 service 的 60s、4.3 nginx 的 30s，这里给得更宽，
// 正是因为超时的后果不对称。
const DefaultCommandTimeout = 120 * time.Second

// SiteProvider 提供站点查询能力。
//
// 抽成接口而不是直接依赖 site.Manager：既避免循环依赖，
// 也让 ssl 包的测试可以用一个内存假站点表跑通全部逻辑，
// 不需要真的搭 nginx 目录结构。
type SiteProvider interface {
	// GetSite 返回指定站点；不存在时返回 ErrNotFound 语义的错误。
	GetSite(name string) (SiteRef, error)
	// ListSites 返回全部站点。
	ListSites() ([]SiteRef, error)
}

// Manager 提供 SSL 证书管理能力。
type Manager struct {
	logger    *slog.Logger
	detector  *Detector
	sites     SiteProvider
	rewriter  ConfigRewriter
	auditor   *Auditor
	email     string
	renewDays int
	timeout   time.Duration
	executor  Executor
	dryRun    bool

	// mu 串行化写操作（申请 / 续期）。
	//
	// ########## 为什么必须串行化 ##########
	//
	// 两个并发申请会**互相破坏 ACME 的挑战验证**：
	// 两者都往同一个站点的 .well-known/acme-challenge/ 写文件，
	// 而 certbot 在验证阶段会清理该目录。A 刚写好挑战文件、
	// 还没等 CA 来抓，B 的清理就把它删了 → A 的验证失败。
	//
	// 表现是"随机失败"，且**单独测总是成功、并发时才失败**——
	// 与坑位 16 的形态一致，属于最难排查的一类问题。
	//
	// 用一把全局锁而不是按站点分锁：ACME 的速率限制是**按域名**
	// 而非按站点的，而且 certbot 自己有全局状态（账号、配置目录）。
	// 一次只跑一个申请，是这个模块最稳妥的并发模型。
	mu sync.Mutex
}

// NewManager 构造管理器。
func NewManager(opts ManagerOptions) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	renewDays := opts.RenewDays
	if renewDays <= 0 {
		renewDays = DefaultRenewDays
	}
	timeout := opts.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	executor := opts.Executor
	if executor == nil {
		executor = execExecutor{}
	}
	detector := opts.Detector
	if detector == nil {
		detector = NewDetector(DetectorOptions{Logger: logger})
	}
	auditor := opts.Auditor
	if auditor == nil {
		// 未注入审计器时不报错，建一个仅内存的：
		// SSL 能力本身可用，只是不留盘。
		var err error
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}

	return &Manager{
		logger:    logger,
		detector:  detector,
		sites:     opts.Sites,
		rewriter:  opts.Rewriter,
		auditor:   auditor,
		email:     opts.Email,
		renewDays: renewDays,
		timeout:   timeout,
		executor:  executor,
		dryRun:    opts.DryRun,
	}, nil
}

// Available 表示 SSL 能力是否可用。
//
// 判据是"站点提供器是否注入"——ACME 客户端的可用性由
// Capabilities/Status 单独回答（因为它是**运行期探测**的结果，
// 而不是构造期就能确定的）。
func (m *Manager) Available() bool {
	return m != nil && m.sites != nil
}

// UnavailableReason 返回不可用原因。
func (m *Manager) UnavailableReason() string {
	if m == nil {
		return "SSL 管理器未初始化"
	}
	if m.sites == nil {
		return "未注入站点提供器，无法关联站点与证书"
	}
	return ""
}

// Auditor 返回审计器。
func (m *Manager) Auditor() *Auditor {
	if m == nil {
		return nil
	}
	return m.auditor
}

// Detector 返回探测器。
func (m *Manager) Detector() *Detector {
	if m == nil {
		return nil
	}
	return m.detector
}

// RenewDays 返回续期阈值。
func (m *Manager) RenewDays() int {
	if m == nil {
		return DefaultRenewDays
	}
	return m.renewDays
}

// DryRun 返回是否处于试运行模式。
func (m *Manager) DryRun() bool {
	return m != nil && m.dryRun
}

// ---------------------------------------------------------------------------
// 状态查询
// ---------------------------------------------------------------------------

// SiteStatus 是单个站点的 SSL 状态（API 的主要响应单元）。
type SiteStatus struct {
	// Site 是站点名。
	Site string `json:"site"`
	// Domain 是站点域名。
	Domain string `json:"domain"`
	// SiteType 是站点类型。
	SiteType string `json:"site_type,omitempty"`
	// Enabled 表示站点当前是否被 nginx 加载。
	Enabled bool `json:"enabled"`
	// Webroot 是 HTTP-01 使用的目录。
	Webroot string `json:"webroot,omitempty"`
	// HasWebroot 表示该站点是否具备申请条件。
	//
	// 反向代理站没有本地目录，因此默认不具备申请条件。
	// 前端据此禁用"申请"按钮并给出原因，而不是让用户点了才失败。
	HasWebroot bool `json:"has_webroot"`
	// Issued 表示该域名是否已有证书。
	Issued bool `json:"issued"`
	// Status 见 StatusValid / StatusExpiring / StatusExpired / StatusNone / StatusUnknown。
	Status string `json:"status"`
	// Expiry 是到期时间（RFC3339）。
	Expiry string `json:"expiry,omitempty"`
	// DaysRemaining 是剩余天数。
	DaysRemaining int `json:"days_remaining,omitempty"`
	// CertPath / KeyPath 供界面展示与排查。
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
	// CertName 是 certbot 里的证书名。
	CertName string `json:"cert_name,omitempty"`
	// Note 是值得提示给用户的情况（解析异常、缺少 webroot 等）。
	Note string `json:"note,omitempty"`
}

// StatusResult 是 Status() 的返回。
type StatusResult struct {
	// Sites 是全部站点的 SSL 状态。
	Sites []SiteStatus `json:"sites"`
	// Client 是探测到的 ACME 客户端信息。
	Client ClientInfo `json:"client"`
	// Available 表示 SSL 申请能力是否可用（客户端可用 + 站点提供器已注入）。
	Available bool `json:"available"`
	// UnavailableReason 是不可用原因。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// RenewDays 是"即将过期"阈值。
	RenewDays int `json:"renew_days"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
	// Counts 是按状态分组的统计。
	Counts StatusCounts `json:"counts"`
	// ScannedAt 是本次扫描时间。
	ScannedAt string `json:"scanned_at"`
}

// StatusCounts 是状态统计（前端直接展示，不必自己遍历）。
type StatusCounts struct {
	Total    int `json:"total"`
	Issued   int `json:"issued"`
	Valid    int `json:"valid"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
	None     int `json:"none"`
	Unknown  int `json:"unknown"`
}

// Status 汇总所有站点的 SSL 状态。
//
// 实现要点：
//  1. 站点列表来自 SiteProvider；
//  2. 证书列表来自**一次** `certbot certificates`（不是每站点跑一次）；
//  3. 两者的关联键是**域名**（证书的 Domains 里包含站点域名）。
//
// 第 3 条值得说明：为什么用域名而不是站点名做关联键？
// 因为证书是**按域名**签发的，站点名只是面板内部的标识。
// 用户完全可能把站点命名为 `blog` 而域名是 `blog.example.com`，
// 用站点名去找证书永远找不到。
func (m *Manager) Status(ctx context.Context) (StatusResult, error) {
	res := StatusResult{
		Sites:     []SiteStatus{},
		RenewDays: m.renewDays,
		DryRun:    m.dryRun,
		ScannedAt: time.Now().Format(time.RFC3339),
	}

	if !m.Available() {
		res.UnavailableReason = m.UnavailableReason()
		return res, nil
	}

	// ---------- 探测客户端 ----------
	// 探测失败（无客户端）不算致命：站点的 SSL 状态仍然可以展示
	// （全部为"未申请"），只是"申请"按钮要禁用。
	client, clientErr := m.detector.Detect(ctx)
	res.Client = client
	if clientErr != nil {
		res.UnavailableReason = clientErr.Error()
	} else {
		res.Available = true
	}

	// ---------- 拉取站点 ----------
	sites, err := m.sites.ListSites()
	if err != nil {
		return res, fmt.Errorf("ssl: 读取站点列表失败: %w", err)
	}

	// ---------- 拉取证书 ----------
	certs, certNote := m.listCertificates(ctx, client)

	// ---------- 关联 ----------
	byDomain := make(map[string]Certificate, len(certs))
	for _, c := range certs {
		for _, d := range c.Domains {
			// 域名大小写不敏感（DNS 本身不区分大小写）。
			byDomain[strings.ToLower(d)] = c
		}
		// 证书名也登记一次：certbot 的证书名通常就是主域名，
		// 但用户可能用 --cert-name 指定了别的名字。
		byDomain[strings.ToLower(c.Name)] = c
	}

	for _, s := range sites {
		st := SiteStatus{
			Site:       s.Name,
			Domain:     s.Domain,
			SiteType:   s.Type,
			Enabled:    s.Enabled,
			Webroot:    m.webrootFor(s),
			HasWebroot: m.webrootFor(s) != "",
			Status:     StatusNone,
		}
		if st.Webroot == "" {
			st.Note = "该站点没有本地目录（反向代理站），HTTP-01 验证需要可写入的 webroot"
		}

		if c, ok := byDomain[strings.ToLower(s.Domain)]; ok {
			st.Issued = true
			st.Status = c.Status
			st.Expiry = c.Expiry
			st.DaysRemaining = c.DaysRemaining
			st.CertPath = c.CertPath
			st.KeyPath = c.KeyPath
			st.CertName = c.Name
			if c.ParseNote != "" {
				st.Note = appendNote(st.Note, c.ParseNote)
			}
			// 证书已签发但该站点是否**真的**在用它，取决于
			// 站点配置里有没有 ssl_certificate。这一层不查配置
			// （那需要读文件，属于 site 模块的职责），
			// 因此这里表达的是"证书已存在"，而不是"HTTPS 已启用"。
		}
		res.Sites = append(res.Sites, st)
	}

	// ---------- 统计 ----------
	res.Counts.Total = len(res.Sites)
	for _, st := range res.Sites {
		if st.Issued {
			res.Counts.Issued++
		}
		switch st.Status {
		case StatusValid:
			res.Counts.Valid++
		case StatusExpiring:
			res.Counts.Expiring++
		case StatusExpired:
			res.Counts.Expired++
		case StatusUnknown:
			res.Counts.Unknown++
		case StatusNone:
			res.Counts.None++
		}
	}

	// 证书解析出问题时的提示（例如 certbot 换了输出格式）。
	if certNote != "" {
		res.UnavailableReason = appendNote(res.UnavailableReason, certNote)
	}
	return res, nil
}

// listCertificates 拉取并解析证书列表。
//
// 返回的第二个值是"值得提示的说明"（为空表示一切正常）。
//
// 这里刻意**不把失败当致命错误**：证书查询失败时，
// 站点列表仍然应当展示（全部标记为未申请/未知）。
// 否则 certbot 出问题会让整个 SSL 页面变成一片红，
// 用户连"我有几个站点"都看不到。
func (m *Manager) listCertificates(ctx context.Context, client ClientInfo) ([]Certificate, string) {
	if !client.Available {
		return nil, ""
	}

	cmd := BuildListCommand(client.Path)
	out, err := runCommand(ctx, m.executor, cmd, m.timeout)
	if err != nil {
		m.logger.Warn("查询证书列表失败", "err", err, "output", out)
		return nil, fmt.Sprintf("查询证书失败: %v", err)
	}

	// `No certificates found.` 是**成功**且 exit 0 的输出（实测确认），
	// 表示机器上一张证书都没有。这与"输出格式不认识"必须区分开：
	// 前者是正常的新机器状态，后者说明解析器需要适配新版本。
	certs := ParseCertificates(out, time.Now(), m.renewDays)
	if len(certs) == 0 && !IsNoCertificatesOutput(out) {
		m.logger.Warn("certbot 输出中未解析出任何证书，可能格式有变化",
			"output_head", truncate(out, 200))
		return nil, "证书列表输出格式无法识别（certbot 版本可能已变化），已按未申请处理"
	}
	return certs, ""
}

// webrootFor 返回站点可用于 HTTP-01 的 webroot 目录。
//
// 只对静态站有效：反向代理站没有本地目录。
//
// 为什么不为反代站"自动造一个 webroot"（例如 /var/www/html）：
// 那需要往 nginx 配置里加一条 location 把
// /.well-known/acme-challenge/ 指过去（否则 CA 抓不到文件），
// 而这条 location 又要处理"它会不会与用户自己的 location 冲突"。
// 这是一个有实际复杂度的改动，属于 5.x 的范畴。
// 本期明确的做法是：告诉用户"反代站暂不支持一键申请"，
// 而不是做一个半可靠、失败原因难以解释的自动配置。
func (m *Manager) webrootFor(s SiteRef) string {
	if s.Type != "static" {
		return ""
	}
	return strings.TrimSpace(s.Root)
}

// ---------------------------------------------------------------------------
// 申请
// ---------------------------------------------------------------------------

// IssueResult 是一次证书申请的结果。
type IssueResult struct {
	// Site / Domain 是操作对象。
	Site   string `json:"site"`
	Domain string `json:"domain"`
	// Issued 表示 CA 是否已签发（**配额是否已消耗**）。
	Issued bool `json:"issued"`
	// Applied 表示配置是否已写入 nginx 并 reload。
	Applied bool `json:"applied"`
	// DryRun 表示本次是试运行。
	DryRun bool `json:"dry_run"`
	// Certificate 是申请后的证书信息（成功时）。
	Certificate *Certificate `json:"certificate,omitempty"`
	// Command 是执行的命令（已脱敏，便于复现）。
	Command string `json:"command,omitempty"`
	// Output 是 certbot 的输出（截断后，便于排查）。
	Output string `json:"output,omitempty"`
	// DurationMS 是耗时。
	DurationMS int64 `json:"duration_ms"`
}

// Issue 为指定站点申请证书。
//
// 流程：
//
//	① 找站点 → ② 校验域名与 webroot → ③ 组装命令
//	→ ④ 执行 certbot → ⑤ 解析结果 → ⑥ 写入 nginx 配置
//
// 每一步都在 mu 的保护下（见 Manager.mu 的说明）。
func (m *Manager) Issue(ctx context.Context, siteName string, force bool) (IssueResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	started := time.Now()
	res := IssueResult{Site: siteName, DryRun: m.dryRun}

	if !m.Available() {
		return res, fmt.Errorf("%w: %s", ErrClientUnavailable, m.UnavailableReason())
	}

	// ---------- ① 找站点 ----------
	site, err := m.sites.GetSite(siteName)
	if err != nil {
		return res, fmt.Errorf("%w: %s", ErrNotFound, siteName)
	}
	res.Domain = site.Domain

	// ---------- ② 校验 ----------
	if err := ValidIssueDomain(site.Domain); err != nil {
		return res, err
	}
	webroot := m.webrootFor(site)
	if err := ValidWebroot(webroot); err != nil {
		return res, fmt.Errorf("%w: 站点 %s", ErrNoWebroot, err)
	}
	if err := ValidEmail(m.email); err != nil {
		return res, err
	}

	// ---------- ③ 探测客户端 ----------
	client, err := m.detector.Detect(ctx)
	if err != nil {
		return res, err
	}

	// ---------- ④ 组装命令 ----------
	cmd, err := BuildIssueCommand(client.Path, IssueRequest{
		Domains:  []string{site.Domain},
		Webroot:  webroot,
		Email:    m.email,
		CertName: site.Name,
		DryRun:   m.dryRun,
		Force:    force,
	})
	if err != nil {
		return res, err
	}
	res.Command = cmd.Redacted
	m.logger.Info("开始申请证书",
		"site", site.Name, "domain", site.Domain, "dry_run", m.dryRun, "command", cmd.Redacted)

	// ---------- ⑤ 执行 ----------
	out, runErr := runCommand(ctx, m.executor, cmd, m.timeout)
	res.Output = truncate(out, maxOutputSnapshot)
	res.DurationMS = time.Since(started).Milliseconds()

	if runErr != nil {
		// 超时是特殊情形：CA 那边**可能已经签发成功**（配额已消耗），
		// 只是我们没等到响应。因此不能简单地说"失败了"。
		if errors.Is(runErr, ErrTimeout) {
			res.Issued = true // 保守假设：可能已消耗配额
			m.logger.Error("申请证书超时，CA 侧可能已签发",
				"site", site.Name, "domain", site.Domain, "err", runErr)
			return res, fmt.Errorf("%w: %v。"+
				"请注意：超时**不代表没有签发**——Let's Encrypt 可能已完成签发并计入配额。"+
				"建议稍后点击「查询」确认证书是否已存在，不要立即重试", ErrClientFailed, runErr)
		}
		m.logger.Error("申请证书失败",
			"site", site.Name, "domain", site.Domain, "err", runErr, "output", res.Output)
		// 把 certbot 的原始输出带进错误里，而不是只留一句
		// "exit status 1"。真正的失败原因（HTTP-01 挑战失败、
		// 域名解析不到、速率限制……）全在那段输出里，
		// 丢掉它等于让用户对着一个没有信息的错误发呆。
		return res, fmt.Errorf("%w: %v；certbot 输出: %s",
			ErrClientFailed, runErr, summarizeOutput(out))
	}

	// ---------- ⑥ 确认签发结果 ----------
	// 不直接相信"命令退出码为 0 就是成功"：dry-run 模式下
	// 根本不会留下证书文件，而我们要在响应里给出真实的到期时间。
	// 因此重新查一次证书列表来确认。
	certs, _ := m.listCertificates(ctx, client)
	cert := findCertificate(certs, site.Domain)
	if cert != nil {
		res.Certificate = cert
		// dry-run 不落盘，因此"查到证书"在 dry-run 下说明
		// 之前就已经有证书了，不能据此认为本次签发成功。
		res.Issued = !m.dryRun || cert.Status != StatusNone
	} else if !m.dryRun {
		// 命令成功但查不到证书：这是真实存在的异常
		// （例如 certbot 把证书放到了非默认的 config-dir）。
		// 不能直接报成功，否则用户会以为可以用。
		m.logger.Warn("certbot 报告成功，但未查到证书",
			"site", site.Name, "domain", site.Domain)
		return res, fmt.Errorf("%w: certbot 执行成功，但未能查到该域名的证书。"+
			"可能是 certbot 使用了非默认的 --config-dir，请检查其安装配置", ErrClientFailed)
	}

	// ---------- ⑦ 写入 nginx 配置 ----------
	//
	// ########## 试运行模式必须在这里提前返回 ##########
	//
	// `--dry-run` 的定义就是**不把证书写到磁盘**，因此此时
	// cert 为 nil 是正常的：既然没有证书文件，也就没有任何路径
	// 可以写进 ssl_certificate。
	//
	// 早期实现没有这个分支，于是 dry-run 必然走进下面的
	// applyToNginx 并报「证书已获取但写入配置失败」——
	// 一个**完全错误**的提示：试运行本来就不该写配置。
	// 更糟的是它会误导用户以为自己的 nginx 配置有问题，
	// 从而去排查一个不存在的故障。这个缺陷是被单元测试抓出来的。
	if m.dryRun {
		res.Applied = true // 试运行的"已处理"= 没有需要应用的变更
		res.DurationMS = time.Since(started).Milliseconds()
		m.logger.Info("证书申请试运行完成（未写入证书与 nginx 配置）",
			"site", site.Name, "domain", site.Domain,
			"duration_ms", res.DurationMS)
		return res, nil
	}

	if err := m.applyToNginx(ctx, site, cert); err != nil {
		// ⚠️ 部分成功：证书已拿到（配额已消耗），但配置没生效。
		// 返回专门的哨兵错误，让调用方能给出正确的提示，
		// 而不是让用户以为"什么都没发生"从而反复重试。
		res.DurationMS = time.Since(started).Milliseconds()
		return res, fmt.Errorf("%w: %v。"+
			"证书**已成功获取**（CA 配额已消耗），无需重复申请；"+
			"请修复上述配置问题后，直接重试即可（已存在的证书不会重复签发）",
			ErrAppliedFailed, err)
	}
	res.Applied = true
	res.DurationMS = time.Since(started).Milliseconds()

	m.logger.Info("证书申请完成",
		"site", site.Name, "domain", site.Domain,
		"expiry", res.Certificate.Expiry, "days_remaining", res.Certificate.DaysRemaining,
		"applied", res.Applied, "duration_ms", res.DurationMS)
	return res, nil
}

// applyToNginx 把证书写入站点的 nginx 配置。
func (m *Manager) applyToNginx(ctx context.Context, site SiteRef, cert *Certificate) error {
	if m.rewriter == nil {
		// 未注入 rewriter：证书能力仍然可用，只是不改配置。
		// 这是被允许的用法（用户想自己配 nginx）。
		m.logger.Info("未注入配置写入器，跳过 nginx 配置更新", "site", site.Name)
		return nil
	}
	if cert == nil {
		return fmt.Errorf("ssl: 没有可用的证书信息，无法写入 nginx 配置")
	}
	if cert.CertPath == "" || cert.KeyPath == "" {
		return fmt.Errorf("ssl: 证书路径不完整（cert=%q key=%q），无法写入 nginx 配置",
			cert.CertPath, cert.KeyPath)
	}

	cfg := SSLConfig{
		CertPath:     cert.CertPath,
		KeyPath:      cert.KeyPath,
		RedirectHTTP: true,
		Protocols:    DefaultProtocols,
		Ciphers:      DefaultCiphers,
	}
	if err := m.rewriter.ApplySSL(ctx, site.Name, cfg); err != nil {
		return fmt.Errorf("写入 nginx 配置失败: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 续期
// ---------------------------------------------------------------------------

// RenewResult 是一次续期的结果。
type RenewResult struct {
	// Site / Domain 是操作对象。
	Site   string `json:"site"`
	Domain string `json:"domain"`
	// CertName 是证书名。
	CertName string `json:"cert_name"`
	// Renewed 表示是否真的重新签发（false 表示还未到续期窗口）。
	//
	// ########## 为什么必须区分"续期成功"与"无需续期" ##########
	//
	// certbot renew 对未进入续期窗口的证书会输出
	// "not yet due for renewal" 并以 **exit 0** 退出。
	// 若把退出码 0 一概当作"续期成功"，界面会显示
	// "续期成功"，而到期时间**一点没变**——用户会立刻怀疑功能坏了，
	// 或者更糟：以为已经续过了，实际并没有。
	//
	// 因此这里解析输出判断是否真的签发了。
	Renewed bool `json:"renewed"`
	// DryRun 表示本次是试运行。
	DryRun bool `json:"dry_run"`
	// Skipped 表示未到续期窗口而跳过。
	Skipped bool `json:"skipped"`
	// Certificate 是续期后的证书信息。
	Certificate *Certificate `json:"certificate,omitempty"`
	// Command 是执行的命令（已脱敏）。
	Command string `json:"command,omitempty"`
	// Output 是 certbot 的输出（截断后）。
	Output string `json:"output,omitempty"`
	// Applied 表示配置是否已重新写入（续期后证书文件路径不变，
	// 因此通常无需重写配置；但若证书文件名有变化则需要）。
	Applied bool `json:"applied"`
	// DurationMS 是耗时。
	DurationMS int64 `json:"duration_ms"`
}

// Renew 续期指定站点的证书。
//
// force 为 true 时即使未进入续期窗口也强制重新签发。
// **默认应当为 false**：强制续期会消耗 Let's Encrypt 的配额。
func (m *Manager) Renew(ctx context.Context, siteName string, force bool) (RenewResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	started := time.Now()
	res := RenewResult{Site: siteName, DryRun: m.dryRun}

	if !m.Available() {
		return res, fmt.Errorf("%w: %s", ErrClientUnavailable, m.UnavailableReason())
	}

	site, err := m.sites.GetSite(siteName)
	if err != nil {
		return res, fmt.Errorf("%w: %s", ErrNotFound, siteName)
	}
	res.Domain = site.Domain
	res.CertName = site.Name

	if err := ValidCertName(site.Name); err != nil {
		return res, err
	}

	client, err := m.detector.Detect(ctx)
	if err != nil {
		return res, err
	}

	cmd, err := BuildRenewCommand(client.Path, site.Name, m.dryRun, force)
	if err != nil {
		return res, err
	}
	res.Command = cmd.Redacted
	m.logger.Info("开始续期证书",
		"site", site.Name, "cert", site.Name, "dry_run", m.dryRun, "force", force)

	out, runErr := runCommand(ctx, m.executor, cmd, m.timeout)
	res.Output = truncate(out, maxOutputSnapshot)
	res.DurationMS = time.Since(started).Milliseconds()

	if runErr != nil {
		if errors.Is(runErr, ErrTimeout) {
			m.logger.Error("续期超时", "site", site.Name, "err", runErr)
			return res, fmt.Errorf("%w: %v", ErrTimeout, runErr)
		}
		m.logger.Error("续期失败",
			"site", site.Name, "err", runErr, "output", res.Output)
		// 同 Issue：把 certbot 的原始输出带进错误里，
		// 否则用户只看到 "exit status 1" 而无从判断原因。
		return res, fmt.Errorf("%w: %v；certbot 输出: %s",
			ErrClientFailed, runErr, summarizeOutput(out))
	}

	// 判断是否真的续期了（而不是"未到窗口"）。
	res.Renewed, res.Skipped = classifyRenewOutput(out)
	if res.Skipped {
		m.logger.Info("证书尚未进入续期窗口，跳过",
			"site", site.Name, "domain", site.Domain)
	}

	// 重新查一次证书，给出续期后的真实到期时间。
	certs, _ := m.listCertificates(ctx, client)
	cert := findCertificate(certs, site.Domain)
	if cert != nil {
		res.Certificate = cert
	}

	// 续期后证书文件路径通常不变（certbot 会更新 live/ 下的软链接），
	// 因此一般无需重写 nginx 配置。但若之前配置里没有 SSL
	// （例如证书是手工申请的），这里补写一次能让状态收敛。
	if res.Renewed && cert != nil {
		if err := m.applyToNginx(ctx, site, cert); err != nil {
			res.DurationMS = time.Since(started).Milliseconds()
			return res, fmt.Errorf("%w: %v", ErrAppliedFailed, err)
		}
		res.Applied = true
	}

	res.DurationMS = time.Since(started).Milliseconds()
	m.logger.Info("续期完成",
		"site", site.Name, "renewed", res.Renewed, "skipped", res.Skipped,
		"duration_ms", res.DurationMS)
	return res, nil
}

// RenewAll 对所有已签发且即将过期的站点执行续期。
//
// 这是自动续期调度器与"批量续期"按钮的公共实现。
//
// 返回的结果里包含每次续期的详情；单个站点失败**不中断**其余站点
// （续期是一个批量任务，让一个失败的证书挡住其它证书的续期
// 会导致更多证书过期）。
func (m *Manager) RenewAll(ctx context.Context) ([]RenewResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.Available() {
		return nil, fmt.Errorf("%w: %s", ErrClientUnavailable, m.UnavailableReason())
	}

	client, err := m.detector.Detect(ctx)
	if err != nil {
		return nil, err
	}

	sites, err := m.sites.ListSites()
	if err != nil {
		return nil, fmt.Errorf("ssl: 读取站点列表失败: %w", err)
	}
	certs, _ := m.listCertificates(ctx, client)

	results := make([]RenewResult, 0, len(sites))
	for _, s := range sites {
		cert := findCertificate(certs, s.Domain)
		if cert == nil {
			continue // 未申请证书的站点跳过
		}
		// 只处理已进入续期窗口的证书：这是 certbot renew 自己的
		// 判断逻辑，但在这里先筛一遍能避免为每个站点都起一个进程。
		if cert.DaysRemaining > m.renewDays {
			continue
		}

		res, err := m.renewLocked(ctx, client, s, false)
		if err != nil {
			// 单个失败不影响其余：记录后继续。
			res.Site = s.Name
			res.Domain = s.Domain
			m.logger.Warn("自动续期失败，继续处理其余站点",
				"site", s.Name, "domain", s.Domain, "err", err)
		}
		results = append(results, res)
	}
	return results, nil
}

// renewLocked 是 Renew 的实现主体（已持有 mu）。
//
// 抽出来是为了让 RenewAll 能在**持锁状态下**逐个调用，
// 而不必为每个站点重新加锁（那会死锁）。
func (m *Manager) renewLocked(ctx context.Context, client ClientInfo, site SiteRef, force bool) (RenewResult, error) {
	started := time.Now()
	res := RenewResult{Site: site.Name, Domain: site.Domain, CertName: site.Name, DryRun: m.dryRun}

	cmd, err := BuildRenewCommand(client.Path, site.Name, m.dryRun, force)
	if err != nil {
		return res, err
	}
	res.Command = cmd.Redacted

	out, runErr := runCommand(ctx, m.executor, cmd, m.timeout)
	res.Output = truncate(out, maxOutputSnapshot)
	res.DurationMS = time.Since(started).Milliseconds()
	if runErr != nil {
		return res, fmt.Errorf("%w: %v；certbot 输出: %s",
			ErrClientFailed, runErr, summarizeOutput(out))
	}

	res.Renewed, res.Skipped = classifyRenewOutput(out)
	if res.Renewed {
		certs, _ := m.listCertificates(ctx, client)
		if cert := findCertificate(certs, site.Domain); cert != nil {
			res.Certificate = cert
			if applyErr := m.applyToNginx(ctx, site, cert); applyErr != nil {
				res.DurationMS = time.Since(started).Milliseconds()
				return res, fmt.Errorf("%w: %v", ErrAppliedFailed, applyErr)
			}
			res.Applied = true
		}
	}
	res.DurationMS = time.Since(started).Milliseconds()
	return res, nil
}

// maxOutputSnapshot 是写入审计与 API 响应的最大输出长度。
//
// 8 KiB：certbot 的失败输出动辄上百行（含 Python traceback 与
// ACME 的完整交互记录）。全量塞进审计日志会让 JSONL 迅速膨胀，
// 也会让 API 响应变得难以阅读。截断后保留开头部分——
// 真正的错误原因几乎总在最前面。
const maxOutputSnapshot = 8 * 1024

// maxErrorOutputLen 是塞进 error 消息里的输出长度上限。
//
// 比 maxOutputSnapshot 小得多（1 KiB）：error 消息会被直接展示
// 在前端提示条里，几百行的 traceback 会把提示条撑成一个
// 无法阅读的滚动框。1 KiB 足够容纳 certbot 的关键报错
// （"Some challenges have failed" 及其原因）。
const maxErrorOutputLen = 1024

// summarizeOutput 把命令输出压缩成一行，用于拼接进 error 消息。
//
// 做两件事：
//
//	① 多行压成单行（用 " | " 连接）——error 消息在 JSON 里
//	   会有一串转义的换行符，看起来非常糟糕；
//	② 去掉 certbot 输出里的分隔线与日志路径噪声，
//	   只保留真正的报错内容。
func summarizeOutput(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "(无输出)"
	}

	lines := make([]string, 0, 8)
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// certbot 的装饰性分隔线与日志路径对排查没有价值。
		if strings.HasPrefix(line, "- - -") || strings.HasPrefix(line, "Saving debug log") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "(无输出)"
	}
	joined := strings.Join(lines, " | ")
	return truncate(joined, maxErrorOutputLen)
}

// ---------------------------------------------------------------------------
// 输出解析
// ---------------------------------------------------------------------------

// certbot renew 输出中的关键短语（实测确认）。
//
// 这三个短语的语义完全不同，必须分别识别：
//
//	"not yet due for renewal"     → 未到窗口，exit 0（跳过）
//	"Congratulations! ... renewed" → 真的续期了
//	"Failed to renew"             → 失败（但 certbot 可能仍返回非 0）
var (
	renewSkippedMarkers = []string{
		"not yet due for renewal",
		"Certificate not yet due for renewal",
		"not due for renewal",
	}
	renewSuccessMarkers = []string{
		"Successfully received certificate",
		"Congratulations! Your certificate",
		"renewed successfully",
		"Certificate is due for renewal",
	}
	renewFailureMarkers = []string{
		"Failed to renew certificate",
		"Failed to renew",
		"An unexpected error occurred",
	}
)

// classifyRenewOutput 判断续期输出属于哪种情况。
//
// 返回 (renewed, skipped)。
//
// ########## 为什么不能只看退出码 ##########
//
// `certbot renew` 在"未到续期窗口"时**输出提示并以 exit 0 退出**。
// 只看退出码的实现会把这种情况报告成"续期成功"，
// 而到期时间毫无变化。用户看到"成功"却没有任何变化，
// 会直接怀疑这个功能是假的——这比老实说"还没到时候"糟糕得多。
//
// 判断顺序有讲究：**先判 skipped，再判 success**。
// 因为 certbot 在跳过时也可能输出包含 "renewal" 的说明文字，
// 先判 success 会对某些版本误报。
func classifyRenewOutput(output string) (renewed, skipped bool) {
	lower := strings.ToLower(output)

	for _, m := range renewFailureMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			// 失败时既不算 renewed 也不算 skipped。
			return false, false
		}
	}
	for _, m := range renewSkippedMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return false, true
		}
	}
	for _, m := range renewSuccessMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return true, false
		}
	}
	// 什么都不匹配（输出格式变化）：保守地认为"未续期"，
	// 让界面显示"未确认"，而不是乐观地报成功。
	return false, false
}

// findCertificate 按域名查找证书（域名大小写不敏感）。
func findCertificate(certs []Certificate, domain string) *Certificate {
	target := strings.ToLower(strings.TrimSpace(domain))
	if target == "" {
		return nil
	}
	for i := range certs {
		if strings.ToLower(certs[i].Name) == target || strings.ToLower(certs[i].PrimaryDomain) == target {
			return &certs[i]
		}
		for _, d := range certs[i].Domains {
			if strings.ToLower(d) == target {
				return &certs[i]
			}
		}
	}
	return nil
}

// Capabilities 描述 SSL 能力的探测结果（供 GET /api/ssl/capabilities）。
type Capabilities struct {
	// Available 表示能否申请证书。
	Available bool `json:"available"`
	// Reason 是不可用原因。
	Reason string `json:"reason,omitempty"`
	// Client 是探测到的 ACME 客户端。
	Client ClientInfo `json:"client"`
	// ChallengeType 是使用的验证方式（本期固定 http-01）。
	ChallengeType string `json:"challenge_type"`
	// WebrootRequired 表示是否需要 webroot 目录。
	WebrootRequired bool `json:"webroot_required"`
	// Email 是配置的 ACME 邮箱（可为空）。
	Email string `json:"email,omitempty"`
	// EmailConfigured 表示是否配置了邮箱。
	EmailConfigured bool `json:"email_configured"`
	// RenewDays 是"即将过期"阈值。
	RenewDays int `json:"renew_days"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
	// CanRewriteNginx 表示是否具备写入 nginx 配置的能力。
	CanRewriteNginx bool `json:"can_rewrite_nginx"`
	// Notes 是给用户看的说明。
	Notes []string `json:"notes,omitempty"`
}

// Capabilities 返回能力探测结果。
func (m *Manager) Capabilities(ctx context.Context) Capabilities {
	cap := Capabilities{
		ChallengeType:   "http-01",
		WebrootRequired: true,
		Email:           m.email,
		EmailConfigured: m.email != "",
		RenewDays:       m.renewDays,
		DryRun:          m.dryRun,
	}

	if !m.Available() {
		cap.Reason = m.UnavailableReason()
		return cap
	}

	client, err := m.detector.Detect(ctx)
	cap.Client = client
	if err != nil {
		cap.Reason = err.Error()
		cap.Notes = append(cap.Notes,
			"未检测到 certbot 或 acme.sh。请先安装其中之一："+
				"Debian/Ubuntu 可执行 apt install certbot；"+
				"或用 -certbot-path 指定自定义路径。")
		return cap
	}

	cap.Available = true
	cap.CanRewriteNginx = m.rewriter != nil

	if !cap.EmailConfigured {
		cap.Notes = append(cap.Notes,
			"未配置 ACME 邮箱（-certbot-email）。证书仍可签发，"+
				"但无法收到到期提醒，建议配置。")
	}
	if !cap.CanRewriteNginx {
		cap.Notes = append(cap.Notes,
			"未注入 nginx 配置写入器：证书可以正常获取，"+
				"但不会自动写入站点配置（需要手工配置 ssl_certificate）。")
	}
	if cap.DryRun {
		cap.Notes = append(cap.Notes,
			"当前为试运行模式（-cert-dry-run）：使用 ACME staging 环境，"+
				"签发的证书不被浏览器信任，且不会写入证书文件。"+
				"该模式**不消耗**生产配额，适合验证流程。")
	}
	return cap
}
