package site

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 站点生命周期管理（阶段四 4.3，核心自带）
// ============================================================================
//
// 本文件编排"改配置 → 校验 → 生效"这条链路，其中**回滚**是核心难点。
//
// #################### 为什么必须有自动回滚 ####################
//
// 一个 nginx 配置写坏了的后果不是"站点访问不了"，而是**整台机器上所有
// 站点一起挂掉**：`nginx -s reload` 会让 master 进程重新解析全部配置，
// 任何一处语法错误都导致整个 reload 失败（更糟的情况是旧 worker 被
// 新配置替换后直接退出）。而用户此时正通过面板排查问题，
// 面板本身可能也挂在同一个 nginx 后面——一次误操作就能把用户
// 和管理入口一起弄丢。
//
// 因此本模块的顺序被固定为：
//
//	快照 → 写盘 → nginx -t ─┬─ 通过 → reload ─┬─ 成功 → 完成
//	                        │                 └─ 失败 → 回滚
//	                        └─ 失败 → 回滚
//
// 且回滚之后**必须再跑一次 nginx -t** 确认服务已恢复可用。
// "回滚了但没验证"等于没回滚——用户无从知道现在到底是不是好的。
//
// #################### 快照要记什么 ####################
//
// 只记"文件内容"是不够的，因为 Debian 布局下"启用"是一个**独立的
// 文件系统对象**（符号链接）。因此快照必须覆盖：
//
//	① 站点定义文件（<name>.conf）的内容与是否存在
//	② 启用链接（sites-enabled/<name>.conf）是否存在
//	③ conf.d 布局下的 .conf.disabled 文件是否存在
//
// 三种里漏任何一种，都会出现"配置回滚了、但启用状态没回滚"的
// 半吊子状态——那比不回滚更难排查。

// 默认超时。
const (
	// DefaultCommandTimeout 是单次 nginx 命令（-t / -s reload）的超时。
	//
	// 30s：`nginx -t` 正常在毫秒级返回，`-s reload` 也很快。
	// 但绝不能不给超时——卡住的 nginx 会永久占用一个 HTTP 连接。
	DefaultCommandTimeout = 30 * time.Second
	// nginxTestTimeout 是 `nginx -t` 的专用超时，比 reload 更短：
	// 它只是解析配置，不需要等待 worker 优雅退出。
	nginxTestTimeout = 15 * time.Second
)

// 错误分类。调用方（server 层）据此映射 HTTP 状态码。
var (
	// ErrNotFound 表示站点不存在。
	ErrNotFound = errors.New("site: 站点不存在")
	// ErrExists 表示站点已存在。
	ErrExists = errors.New("site: 站点已存在")
	// ErrTimeout 表示命令执行超时。
	ErrTimeout = errors.New("site: 操作超时")
	// ErrNginxTestFailed 表示 nginx -t 校验失败（配置已被回滚）。
	ErrNginxTestFailed = errors.New("site: nginx 配置校验失败")
	// ErrReloadFailed 表示 nginx reload 失败（配置已被回滚）。
	ErrReloadFailed = errors.New("site: nginx 重载失败")
	// ErrExternal 表示该站点不是面板生成的，不接受面板编辑。
	ErrExternal = errors.New("site: 该站点不是由面板创建")
	// ErrRolledBack 表示操作失败且已回滚，附带回滚结果。
	ErrRolledBack = errors.New("site: 操作失败，配置已回滚")
)

// Site 是一个站点的完整定义。
//
// 字段刻意保持扁平：它同时用于"生成配置"与"API 响应"，
// 扁平结构让两处都不需要额外映射。
type Site struct {
	// Name 是站点名，同时也是配置文件名（<name>.conf）。
	Name string `json:"name"`
	// Domain 是 server_name。
	Domain string `json:"domain"`
	// Type 见 TypeStatic / TypeProxy。
	Type string `json:"type"`
	// Root 是静态站的根目录（TypeStatic 时有效）。
	Root string `json:"root,omitempty"`
	// Upstream 是反向代理目标（TypeProxy 时有效）。
	Upstream string `json:"upstream,omitempty"`
	// Enabled 表示该站点当前是否被 nginx 加载。
	Enabled bool `json:"enabled"`
	// Generated 表示配置由面板生成（false 时为手工配置，只读）。
	Generated bool `json:"generated"`
	// ConfigPath 是配置文件的绝对路径（展示用）。
	ConfigPath string `json:"config_path,omitempty"`
	// ModTime 是配置文件的修改时间（RFC3339）。
	ModTime string `json:"mod_time,omitempty"`
	// Listen 是解析出的监听端口（展示用）。
	Listen []string `json:"listen,omitempty"`
	// ParseNote 记录"解析时遇到的、值得提示给用户的情况"。
	//
	// 例如：文件是面板生成标记但解析不出 root/proxy_pass。
	// 不把它做成错误（那样整个列表接口都会失败），而是作为
	// 一条附着在条目上的说明——列表里其余站点仍然正常可用。
	ParseNote string `json:"parse_note,omitempty"`
}

// ManagerOptions 是构造 Manager 的配置。
type ManagerOptions struct {
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Adapter 是 nginx 目录布局适配器；为 nil 时站点管理不可用。
	Adapter *SystemAdapter
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// CommandTimeout 是 nginx 命令超时；<=0 时用 DefaultCommandTimeout。
	CommandTimeout time.Duration
	// Executor 是执行 nginx 命令的函数；为 nil 时用 exec.CommandContext。
	//
	// 抽出来的唯一目的是**可测**：回滚这类安全性质必须能用单测穷举
	// （断言"nginx -t 失败后文件真的回到原样"），
	// 而真实的 nginx 无法在测试里被安全地随意调用。
	Executor Executor
	// RootChecker 判断静态站根目录是否可用；为 nil 时用默认实现
	// （os.Stat 判断存在且是目录）。
	//
	// 为什么要抽出来：真正的路径白名单校验需要 4.2 的 file.Resolver，
	// 而 site 包不应反向依赖 file 包（那会形成核心模块间的环）。
	// 由 main 注入一个闭包即可——注入的函数同时完成
	// "白名单校验"与"存在性校验"两件事。
	RootChecker func(path string) error
	// RenderOptions 是生成配置时的选项。
	RenderOptions RenderOptions
}

// Executor 执行一条 nginx 命令并返回 stdout/stderr。
//
// 与 service.Executor 同构：name 与 args 分开放，由 exec.CommandContext
// 直接构造 argv，**不经过 shell**。
type Executor interface {
	// Run 执行命令；返回 stdout、stderr 与错误。
	// 约定实现必须带超时，且 ctx 取消时立即返回。
	Run(ctx context.Context, name string, args []string) (stdout string, stderr string, err error)
}

// execExecutor 是默认执行器，基于 os/exec。
type execExecutor struct{}

func (execExecutor) Run(ctx context.Context, name string, args []string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// LANG/LC_ALL 强制 C：nginx 的错误信息会被解析并展示给用户，
	// 固定语言能让错误格式稳定（不同 locale 下的翻译会破坏解析）。
	cmd.Env = append(cmd.Environ(), "LANG=C", "LC_ALL=C")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Manager 提供站点管理能力。
type Manager struct {
	logger      *slog.Logger
	adapter     *SystemAdapter
	auditor     *Auditor
	timeout     time.Duration
	executor    Executor
	rootChecker func(string) error
	renderOpts  RenderOptions

	// mu 串行化写操作。
	//
	// 为什么必须串行化：从"采集快照"到"写盘"再到"校验/回滚"之间
	// 有一段时间窗口，两个并发写会互相踩踏——A 的快照可能记下
	// B 刚写进去的内容，于是 A 回滚时把 B 的修改也一起抹掉。
	//
	// 用一把全局锁而不是按站点名分锁：nginx 的配置是**全局共享**的，
	// 任何一个站点的改动都会触发整实例的 nginx -t 与 reload，
	// 因此"写站点 A"与"写站点 B"本来就不是可并行的操作。
	// 按名分锁会给人"可以并发"的错觉，反而更容易写出竞态。
	mu sync.Mutex

	// pendingSnapshot 保存当前写操作采集的快照。
	//
	// 为什么用一个字段而不是把快照一路透传：回滚的调用点位于
	// verifyAndReload → failAndRollback 两三层之下，
	// 一路透传会让这些函数的签名被一个"只对回滚有用"的参数污染。
	// 写操作已在 mu 的保护下串行执行，因此这里不存在并发覆盖。
	pendingSnapshot *siteSnapshot
}

// NewManager 构造站点管理器。
//
// 与 service.NewManager 一致：适配器不可用时**不返回错误**，
// 只是标记为不可用，让面板其它功能照常工作。
func NewManager(opts ManagerOptions) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := opts.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	executor := opts.Executor
	if executor == nil {
		executor = execExecutor{}
	}
	rootChecker := opts.RootChecker
	if rootChecker == nil {
		rootChecker = defaultRootChecker
	}

	auditor := opts.Auditor
	if auditor == nil {
		var err error
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}

	m := &Manager{
		logger:      logger,
		adapter:     opts.Adapter,
		auditor:     auditor,
		timeout:     timeout,
		executor:    executor,
		rootChecker: rootChecker,
		renderOpts:  opts.RenderOptions,
	}
	return m, nil
}

// defaultRootChecker 是默认的根目录校验：必须存在且是目录。
//
// 为什么必须存在：静态站的 root 指向一个不存在的目录时，nginx
// 能正常启动（配置语法没问题），但访问站点会得到 404 或 500，
// 用户完全看不出是"路径写错了"。在创建时就明确报错，
// 比让用户对着一个 404 页面猜要友好得多。
func defaultRootChecker(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("site: 静态站根目录 %s 不可用: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("site: 静态站根目录 %s 不是目录", path)
	}
	return nil
}

// Available 表示站点管理是否可用。
func (m *Manager) Available() bool {
	return m != nil && m.adapter != nil && m.adapter.Available()
}

// UnavailableReason 返回不可用的原因（可用时为空）。
func (m *Manager) UnavailableReason() string {
	if m == nil || m.adapter == nil {
		return "站点管理未启用（服务启动时未注入 nginx 适配器）。"
	}
	return m.adapter.UnavailableReason()
}

// Adapter 返回适配器（供 server 层展示目录信息）。
func (m *Manager) Adapter() *SystemAdapter { return m.adapter }

// Auditor 返回审计器。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// ---------------------------------------------------------------------------
// 列表
// ---------------------------------------------------------------------------

// fileConfPattern 匹配站点目录里的配置文件。
var fileConfPattern = regexp.MustCompile(`^(.+)\.conf$`)

// fileConfDisabledPattern 匹配被禁用的配置文件。
var fileConfDisabledPattern = regexp.MustCompile(`^(.+)\.conf\.disabled$`)

// List 扫描站点目录并返回全部站点。
//
// 实现方式是**扫描目录 + 解析文件**，而不是读面板自己的索引，
// 理由见 ParsedConf 的注释：配置文件本身就是唯一真相。
//
// 两个目录都要扫（Debian 布局下 sites-available 是"定义"、
// sites-enabled 是"状态"）：
//   - 只扫 sites-available 会不知道哪些是启用的；
//   - 只扫 sites-enabled 会让"已禁用但配置还在"的站点从列表里消失，
//     用户再也无法在面板里重新启用它（这正是 4.1 踩过的
//     "停止后服务从列表消失"的同一个坑）。
func (m *Manager) List() ([]Site, error) {
	if !m.Available() {
		return []Site{}, fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}

	// key 是小写站点名：文件系统大小写不敏感时（macOS、部分挂载选项），
	// Foo.conf 与 foo.conf 是同一个文件，用小写归并可以避免列表里
	// 出现两条指向同一文件的记录。
	sites := map[string]*Site{}

	// ① 扫定义目录。
	availableDir := m.adapter.AvailableDir()
	if err := m.scanDir(availableDir, sites, false); err != nil {
		return nil, err
	}
	// ② 扫启用目录（Debian 布局下与定义目录不同）。
	if enabledDir := m.adapter.EnabledDir(); enabledDir != availableDir && enabledDir != "" {
		if err := m.scanDir(enabledDir, sites, true); err != nil {
			return nil, err
		}
	}

	out := make([]Site, 0, len(sites))
	for _, s := range sites {
		out = append(out, *s)
	}
	// 稳定排序：先按启用状态（启用的在前），再按站点名。
	// 排序放在后端而不是前端：前端可能有多处消费这个列表
	// （表格、下拉框），每处各排一次必然出现不一致。
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Enabled != out[j].Enabled {
			return out[i].Enabled
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// scanDir 扫描一个目录并把条目并入 sites。
func (m *Manager) scanDir(dir string, sites map[string]*Site, enabledDir bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 目录不存在不算错误：sites-enabled 在全新系统上
			// 可能尚未创建。返回空列表比报错更符合用户预期。
			return nil
		}
		return fmt.Errorf("site: 读取站点目录 %s 失败: %w", dir, err)
	}

	for _, entry := range entries {
		filename := entry.Name()
		configPath := filepath.Join(dir, filename)

		// 解析文件名 → 站点名 + 是否禁用。
		var (
			name    string
			disable bool
		)
		if mt := fileConfDisabledPattern.FindStringSubmatch(filename); mt != nil {
			if !enabledDir {
				name, disable = mt[1], true
			}
		} else if mt := fileConfPattern.FindStringSubmatch(filename); mt != nil {
			name = mt[1]
		}
		if name == "" {
			// 不是 .conf 文件：如实跳过。
			//
			// 这里**刻意不用**"名字看着像就认"的宽松匹配：目录里
			// 常见的 .conf.bak、.conf.save、.conf.dpkg-old 都是
			// 备份文件，nginx 只加载 *.conf。把它们显示成站点会让
			// 用户对着一个"存在却改不动"的条目困惑。
			continue
		}
		// 站点名必须合法才纳入列表。
		//
		// 目录里可能有用户手工创建的、名字带空格或中文的配置。
		// 那类配置**不能**进入面板列表：面板对它们的每一次操作
		// （拼接 /api/sites/{name}、拼路径）都依赖名字合法，
		// 放进来只会得到一个"点了就报 400"的条目。
		// 它们的正确归属是"面板管不了的外部配置"，由用户手工维护。
		if err := ValidSiteName(name); err != nil {
			m.logger.Debug("跳过名字不合法的站点配置（非面板管理）",
				"file", configPath, "reason", err.Error())
			continue
		}

		key := strings.ToLower(name)
		s := sites[key]
		if s == nil {
			s = &Site{Name: name}
			sites[key] = s
		}
		if enabledDir {
			s.Enabled = true
			continue
		}

		// 定义目录里的条目：读取内容并解析。
		content, readErr := os.ReadFile(configPath)
		if readErr != nil {
			// 读不了（权限、是目录……）不中断整个列表，
			// 而是把这个条目标记为"面板无法管理"，其余站点照常展示。
			//
			// 权限不足时符号链接会读不到，改用 Lstat 拿时间信息。
			if info, statErr := os.Lstat(configPath); statErr == nil {
				s.ModTime = info.ModTime().Format(time.RFC3339)
			}
			s.ConfigPath = configPath
			s.Generated = false
			s.ParseNote = "无法读取配置文件（" + readErr.Error() + "），" +
				"面板不会修改它，请检查文件权限。"
			continue
		}

		parsed := parseConf(string(content))
		s.Generated = parsed.Generated
		s.ConfigPath = configPath
		s.Listen = parsed.Listen
		s.Enabled = !disable && m.adapter.Enabled(name)

		if info, statErr := os.Stat(configPath); statErr == nil {
			s.ModTime = info.ModTime().Format(time.RFC3339)
		}

		// 从配置内容推断类型与参数。
		switch {
		case parsed.ProxyPass != "":
			s.Type = TypeProxy
			s.Upstream = parsed.ProxyPass
			s.Root = parsed.Root
		case parsed.Root != "":
			s.Type = TypeStatic
			s.Root = parsed.Root
		default:
			// 既没有 root 也没有 proxy_pass：可能是一个纯 return/rewrite
			// 的站点，也可能是面板解析不了的复杂配置。
			// 不猜类型，明确标记为"外部配置"。
			s.Type = ""
			s.ParseNote = "面板未从该配置中解析出 root 或 proxy_pass 指令，" +
				"已标记为只读。若这是面板创建的站点，说明配置文件被外部修改过。"
		}
		if len(parsed.ServerNames) > 0 {
			s.Domain = strings.Join(parsed.ServerNames, " ")
		}
		if !parsed.Generated && s.ParseNote == "" {
			s.ParseNote = "该配置不是由面板创建，面板不会修改它（只读展示）。"
		}
	}
	return nil
}

// Get 返回单个站点。
func (m *Manager) Get(name string) (Site, error) {
	if err := ValidSiteName(name); err != nil {
		return Site{}, err
	}
	list, err := m.List()
	if err != nil {
		return Site{}, err
	}
	for _, s := range list {
		if s.Name == name {
			return s, nil
		}
	}
	return Site{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}

// ---------------------------------------------------------------------------
// 创建
// ---------------------------------------------------------------------------

// SiteInput 是创建/编辑站点的输入。
type SiteInput struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Root     string `json:"root"`
	Upstream string `json:"upstream"`
	// Enabled 表示创建后是否立即启用。
	Enabled bool `json:"enabled"`
}

// normalize 校验并规范化输入。
//
// 这是**所有写操作的唯一校验入口**：Create 与 Update 都先调用它。
// 集中在一处的意义是"不存在一条绕过校验的写路径"——
// 若每个方法各写一遍校验，早晚会出现某个方法漏了某一项。
func (in *SiteInput) normalize() (Site, error) {
	// #################### 为什么不在这里 TrimSpace ####################
	//
	// 初版对 name / domain / root 都做了 strings.TrimSpace 再校验，
	// 于是 `"site\n"` 会被**静默接受**——末尾的换行被无声地丢掉了。
	//
	// 这是测试抓出来的真实缺陷，危害有两层：
	//
	//  1. **安全层面**：换行能在 nginx 配置里凭空插入一条指令。
	//     "先修整再校验"意味着校验看到的不是用户真正提交的内容，
	//     我们无法确定"原样写进配置的东西"是干净的。
	//  2. **可观测层面**：用户提交了带换行的名字，得到的却是一个
	//     正常站点——他不会知道自己的输入被改过。
	//
	// 正确做法与 ValidUpstream 的修正一致：**校验函数只回答
	// "这个字符串能不能用"，绝不悄悄改写它**。
	// 需要容错的地方（例如表单里用户手滑多打了个空格）由前端提示，
	// 而不是由后端的校验层沉默地修正。
	//
	// 因此这里原样传入，让 ValidSiteName / ValidDomain / ValidRoot
	// 自己拒绝任何含空白与元字符的输入。
	name := in.Name
	if err := ValidSiteName(name); err != nil {
		return Site{}, err
	}
	domain := in.Domain
	if err := ValidDomain(domain); err != nil {
		return Site{}, err
	}
	if !ValidType(in.Type) {
		return Site{}, fmt.Errorf("%w: %q（只支持 %s / %s）",
			ErrInvalidType, in.Type, TypeStatic, TypeProxy)
	}

	s := Site{Name: name, Domain: domain, Type: in.Type, Enabled: in.Enabled}

	switch in.Type {
	case TypeStatic:
		root := in.Root
		if err := ValidRoot(root); err != nil {
			return Site{}, err
		}
		s.Root = root
		// 上游字段在有值时明确报错，而不是静默丢弃。
		//
		// 静默丢弃看起来"更宽容"，但它会让用户以为自己的输入生效了：
		// 前端切换类型时若忘了清空另一个字段，用户就会得到一个
		// "看起来配了反代、实际是静态站"的站点。
		if strings.TrimSpace(in.Upstream) != "" {
			return Site{}, fmt.Errorf("%w: 静态站不接受后端地址（upstream），"+
				"请清空该字段或把类型改为反向代理", ErrInvalidUpstream)
		}
	case TypeProxy:
		// NormalizeUpstream 只做两件明确的事（去首尾空白、补协议前缀），
		// 且**结果**必须再过 ValidUpstream —— 见 validate.go 中
		// "先归一化，再校验"的说明。这里的去空白发生在归一化阶段
		// 而不是校验阶段，因此契约是清晰的：存进配置的是归一化后的值。
		normalized := NormalizeUpstream(in.Upstream)
		if err := ValidUpstream(normalized); err != nil {
			return Site{}, err
		}
		s.Upstream = normalized
		if strings.TrimSpace(in.Root) != "" {
			return Site{}, fmt.Errorf("%w: 反向代理不接受根目录（root），"+
				"请清空该字段或把类型改为静态站", ErrInvalidRoot)
		}
	}
	return s, nil
}

// Create 创建一个新站点。
func (m *Manager) Create(ctx context.Context, in SiteInput) (Site, error) {
	s, err := in.normalize()
	if err != nil {
		return Site{}, err
	}
	if !m.Available() {
		return Site{}, fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}
	// 存在性检查放在权限判定之后（由 server 层保证）、写盘之前。
	if m.adapter.Defined(s.Name) {
		return Site{}, fmt.Errorf("%w: %s", ErrExists, s.Name)
	}
	// 静态站根目录必须真实可用（含 4.2 的白名单校验）。
	if s.Type == TypeStatic {
		if err := m.rootChecker(s.Root); err != nil {
			return Site{}, err
		}
	}

	content, err := Render(s, m.renderOpts)
	if err != nil {
		return Site{}, err
	}

	// 快照：此刻站点还不存在，因此"回滚"= 把新建的东西删掉。
	snap := m.snapshot(s.Name)

	if err := m.apply(ctx, s.Name, content, s.Enabled, snap); err != nil {
		return Site{}, err
	}

	s.Enabled = s.Enabled && m.adapter.Enabled(s.Name)
	s.Generated = true
	s.ConfigPath = m.adapter.SiteFilePath(s.Name)
	m.logger.Info("站点已创建",
		"name", s.Name, "domain", s.Domain, "type", s.Type, "enabled", s.Enabled)
	return m.Get(s.Name)
}

// Update 编辑一个已有站点。
//
// AllowRename 语义：本站点不支持改名（Name 是配置文件名的来源，
// 改名等于"删一个建一个"，两者之间失败会留下半个状态）。
// 用户要改名就删除后重建，这是明确且可预期的语义。
func (m *Manager) Update(ctx context.Context, name string, in SiteInput) (Site, error) {
	if err := ValidSiteName(name); err != nil {
		return Site{}, err
	}
	if !m.Available() {
		return Site{}, fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}
	// 编辑时请求体里的 name 必须与路径参数一致，否则拒绝。
	//
	// 若允许不一致，就会出现"改 A 的名字、实际写进 B 的文件"这种
	// 极易误操作的行为；更重要的是，两条不同的真相来源
	// （路径 vs 请求体）本身就是安全隐患。
	if strings.TrimSpace(in.Name) != "" && strings.TrimSpace(in.Name) != name {
		return Site{}, fmt.Errorf("%w: 请求体中的站点名 %q 与路径中的 %q 不一致，"+
			"改名请使用「删除后重建」", ErrInvalidName, in.Name, name)
	}
	in.Name = name

	s, err := in.normalize()
	if err != nil {
		return Site{}, err
	}

	existing, err := m.Get(name)
	if err != nil {
		return Site{}, err
	}
	// 外部配置（非面板生成）拒绝编辑：
	// 面板会用模板整体重写文件，那会把用户手写的配置彻底抹掉。
	// 列表接口已经把这类站点标记为只读，这里做服务端的强制执行
	// （前端的置灰只是体验，真正的强制点必须在后端）。
	if !existing.Generated {
		return Site{}, fmt.Errorf("%w: %s（%s）", ErrExternal, name, existing.ParseNote)
	}
	if s.Type == TypeStatic {
		if err := m.rootChecker(s.Root); err != nil {
			return Site{}, err
		}
	}

	content, err := Render(s, m.renderOpts)
	if err != nil {
		return Site{}, err
	}

	snap := m.snapshot(name)
	if err := m.apply(ctx, name, content, s.Enabled, snap); err != nil {
		return Site{}, err
	}

	m.logger.Info("站点已更新",
		"name", s.Name, "domain", s.Domain, "type", s.Type, "enabled", s.Enabled)
	return m.Get(name)
}

// SetEnabled 启用或禁用一个站点。
func (m *Manager) SetEnabled(ctx context.Context, name string, enabled bool) (Site, error) {
	if err := ValidSiteName(name); err != nil {
		return Site{}, err
	}
	if !m.Available() {
		return Site{}, fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}

	existing, err := m.Get(name)
	if err != nil {
		return Site{}, err
	}

	// 启用/禁用只动"启用入口"，**不改配置内容**。
	// 因此 content 传空串，让 apply 跳过写文件那一步。
	snap := m.snapshot(name)
	if err := m.apply(ctx, name, "", enabled, snap); err != nil {
		return Site{}, err
	}

	action := "禁用"
	if enabled {
		action = "启用"
	}
	m.logger.Info("站点已"+action, "name", name, "domain", existing.Domain)
	return m.Get(name)
}

// Delete 删除一个站点。
//
// 语义：删除定义文件与启用链接，**不做备份**。
// 界面上有二次确认（且写明域名），因此这是用户明确表达的意图。
// 若将来需要"回收站"，应当是一个独立的功能，而不是让"删除"
// 变成"其实没删"——后者会让磁盘上堆积一堆用户以为已删掉的配置。
func (m *Manager) Delete(ctx context.Context, name string) error {
	if err := ValidSiteName(name); err != nil {
		return err
	}
	if !m.Available() {
		return fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}
	existing, err := m.Get(name)
	if err != nil {
		return err
	}
	if !existing.Generated {
		return fmt.Errorf("%w: %s（%s）", ErrExternal, name, existing.ParseNote)
	}

	snap := m.snapshot(name)

	// 先禁用（删链接）再删文件。顺序不能反：
	// 反过来会出现"定义文件已删、链接还在"的悬空状态，
	// 此时 nginx -t 会报"配置文件不存在"而整个 reload 失败。
	if err := m.adapter.Disable(name); err != nil {
		return err
	}
	// 删除定义文件（含 conf.d 布局下的 .disabled 变体）。
	for _, p := range []string{
		m.adapter.SiteFilePath(name),
		m.adapter.DisabledPath(name),
	} {
		if p == "" {
			continue
		}
		if rmErr := os.Remove(p); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			// 删文件失败：把已经删掉的链接补回来，保持状态一致。
			if rbErr := m.rollback(ctx, name, snap); rbErr != nil {
				m.logger.Error("删除失败后回滚也失败",
					"name", name, "rollback_err", rbErr)
			}
			return fmt.Errorf("site: 删除配置文件 %s 失败: %w", p, rmErr)
		}
	}

	if err := m.verifyAndReload(ctx, name, "delete"); err != nil {
		return err
	}
	m.logger.Warn("站点已删除", "name", name, "domain", existing.Domain)
	return nil
}

// apply 是 Create/Update 的公共实现：写内容 + 设置启用状态 + 校验 + reload。
//
// 整个过程在 mu 的保护下进行（见 Manager.mu 的说明）。
func (m *Manager) apply(ctx context.Context, name, content string, enabled bool, snap *siteSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx, name, content, enabled, snap)
}

// applyLocked 是 apply 的实现主体（已持有 mu）。
//
// 参数 content 为空表示"不改配置内容"（SetEnabled 走这条路）。
func (m *Manager) applyLocked(ctx context.Context, name, content string, enabled bool, snap *siteSnapshot) error {
	// ---------- 0. 登记快照 ----------
	//
	// 必须在**任何写操作之前**登记：回滚的调用点在下面两层之下，
	// 它需要拿到"改动前的状态"。若放到写盘之后就晚了——
	// 那时磁盘上已经是新内容，快照会记下错误的状态。
	m.pendingSnapshot = snap
	defer func() { m.pendingSnapshot = nil }()

	// ---------- 1. 写配置内容 ----------
	if content != "" {
		if err := atomicWriteFile(m.adapter.SiteFilePath(name), []byte(content), 0o644); err != nil {
			return err
		}
	}

	// ---------- 2. 设置启用状态 ----------
	//
	// 四个方向都要能走通（Enabled() 与 want 的组合），
	// setEnabledState 内部用"当前状态 == 期望状态则跳过"来实现幂等。
	if err := m.setEnabledState(name, enabled); err != nil {
		// 状态设置失败：立刻回滚（可能是权限、可能是文件被删）。
		if rbErr := m.rollback(ctx, name, snap); rbErr != nil {
			m.logger.Error("设置启用状态失败且回滚失败", "name", name, "rollback_err", rbErr)
			return fmt.Errorf("%w：%v；且回滚失败: %w", ErrRolledBack, err, rbErr)
		}
		m.logger.Warn("设置启用状态失败，已回滚", "name", name, "err", err)
		return fmt.Errorf("%w：%v。配置已回滚到修改前的状态", ErrRolledBack, err)
	}

	// ---------- 3. 校验并 reload ----------
	return m.verifyAndReload(ctx, name, "apply")
}

// setEnabledState 把站点的启用状态设置为期望值。
func (m *Manager) setEnabledState(name string, want bool) error {
	if m.adapter.Enabled(name) == want {
		return nil
	}
	if want {
		return m.adapter.Enable(name)
	}
	return m.adapter.Disable(name)
}

// verifyAndReload 执行 nginx -t → reload，失败则回滚。
//
// 这是整个模块最关键的一段代码。步骤固定为：
//
//	① nginx -t
//	     └─ 失败 → 回滚 → 再 nginx -t 确认恢复 → 返回 ErrNginxTestFailed
//	② nginx -s reload
//	     └─ 失败 → 回滚 → 再 nginx -t 确认恢复 → reload 一次 → 返回 ErrReloadFailed
//	③ 成功
//
// 第 ② 步回滚后**必须再 reload 一次**：reload 失败意味着旧配置可能
// 仍在内核里生效，把文件改回去并不会自动让 nginx 回到旧配置——
// 必须显式 reload 才能让运行态与磁盘态重新一致。
func (m *Manager) verifyAndReload(ctx context.Context, name, action string) error {
	// ---------- ① nginx -t ----------
	if out, err := m.runNginx(ctx, nginxTestTimeout, "-t"); err != nil {
		m.logger.Error("nginx 配置校验失败，开始回滚",
			"name", name, "action", action, "output", out)
		return m.failAndRollback(ctx, name, action, ErrNginxTestFailed, out, err, false)
	}

	// ---------- ② nginx -s reload ----------
	if out, err := m.runNginx(ctx, m.timeout, "-s", "reload"); err != nil {
		m.logger.Error("nginx 重载失败，开始回滚",
			"name", name, "action", action, "output", out)
		// needReloadAfterRollback=true：reload 本身失败了，
		// 回滚文件之后还要再 reload 一次才能让运行态跟上。
		return m.failAndRollback(ctx, name, action, ErrReloadFailed, out, err, true)
	}
	return nil
}

// failAndRollback 回滚并返回带完整上下文的错误。
//
// 错误信息里必须同时包含：① 原始的 nginx 报错；② 回滚是否成功；
// ③ 回滚后的配置是否可用。用户只有拿到这三条信息，
// 才能判断"我现在到底还安不安全"。
func (m *Manager) failAndRollback(
	ctx context.Context, name, action string, sentinel error,
	output string, cause error, needReload bool,
) error {
	// 快照由 applyLocked 在写盘前登记到 pendingSnapshot。
	if rbErr := m.rollback(ctx, name, nil); rbErr != nil {
		m.logger.Error("配置回滚失败，服务可能处于不可用状态",
			"name", name, "action", action, "err", rbErr)
		return fmt.Errorf("%w: %s（原始错误：%s）；"+
			"自动回滚失败：%v。请立即手工检查 nginx 配置",
			sentinel, strings.TrimSpace(output), cause, rbErr)
	}

	// 回滚后重新校验，确认服务已恢复可用。
	//
	// 这一步不能省：回滚本身也可能出错（磁盘满、权限变化），
	// 不复验就告诉用户"已回滚"是一种没有依据的承诺。
	if out, err := m.runNginx(ctx, nginxTestTimeout, "-t"); err != nil {
		m.logger.Error("回滚后配置仍不可用，需人工介入",
			"name", name, "output", out)
		return fmt.Errorf("%w: %s（原始错误：%s）；"+
			"配置已回滚，但回滚后的配置**仍未通过** nginx -t：%s。请立即手工检查",
			sentinel, strings.TrimSpace(output), cause, strings.TrimSpace(out))
	}

	// reload 失败的情形下，回滚后还要再 reload 一次。
	if needReload {
		if out, err := m.runNginx(ctx, m.timeout, "-s", "reload"); err != nil {
			return fmt.Errorf("%w: %s（原始错误：%s）；"+
				"配置已回滚且通过 nginx -t，但重新加载失败：%s。请手工执行 nginx -s reload",
				sentinel, strings.TrimSpace(output), cause, strings.TrimSpace(out))
		}
	}

	m.logger.Warn("已自动回滚到上一个可用的配置",
		"name", name, "action", action)
	return fmt.Errorf("%w: %s（原始错误：%s）。"+
		"配置已自动回滚到修改前的状态，并通过 nginx -t 校验，服务未受影响",
		sentinel, strings.TrimSpace(output), cause)
}

// runNginx 执行一条 nginx 命令并返回合并后的输出。
func (m *Manager) runNginx(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if !m.Available() {
		return "", fmt.Errorf("%w: %s", ErrAdapterUnavailable, m.UnavailableReason())
	}
	executable, fullArgs := m.adapter.command(args...)

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, err := m.executor.Run(cmdCtx, executable, fullArgs)
	combined := strings.TrimSpace(stdout + stderr)
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return combined, fmt.Errorf("%w: nginx %s 在 %s 内未返回",
			ErrTimeout, strings.Join(args, " "), timeout)
	}
	if err != nil {
		return combined, fmt.Errorf("nginx %s 失败: %w", strings.Join(args, " "), err)
	}
	return combined, nil
}

// ---------------------------------------------------------------------------
// 快照与回滚
// ---------------------------------------------------------------------------

// siteSnapshot 是一次写操作前的磁盘状态快照。
//
// 为什么需要它：回滚的本质是"把磁盘恢复到操作前"。若只是"把文件改回去"，
// 遇到"文件本来不存在"（新建场景）就会写出一份空文件，
// 遇到"链接本来不存在"（启用场景）就删不掉链接。
// 因此快照必须精确记录**每一项的存在性与内容**。
type siteSnapshot struct {
	name string
	// confExists 表示操作前定义文件是否存在。
	confExists bool
	// confContent 是操作前定义文件的内容。
	confContent []byte
	// disabledExists 表示操作前 .conf.disabled 是否存在（conf.d 布局）。
	disabledExists bool
	// disabledContent 是操作前 .conf.disabled 的内容。
	disabledContent []byte
	// enabledExists 表示操作前启用链接/文件是否存在。
	enabledExists bool
}

// lastSnapshots 说明：快照保存在 Manager.pendingSnapshot 里，
// 由 applyLocked 在写盘前登记、写操作结束后清除（见 Manager.mu 的说明）。

// snapshot 采集某站点的当前磁盘状态。
func (m *Manager) snapshot(name string) *siteSnapshot {
	snap := &siteSnapshot{name: name}

	confPath := m.adapter.SiteFilePath(name)
	if content, err := os.ReadFile(confPath); err == nil {
		snap.confExists = true
		snap.confContent = content
	}

	if disabledPath := m.adapter.DisabledPath(name); disabledPath != "" && disabledPath != confPath {
		if content, err := os.ReadFile(disabledPath); err == nil {
			snap.disabledExists = true
			snap.disabledContent = content
		}
	}

	snap.enabledExists = m.adapter.Enabled(name)
	return snap
}

// rollback 把站点恢复到快照记录的状态。
//
// snap 为 nil 时使用 m.pendingSnapshot（由 apply2 在写盘前登记）。
func (m *Manager) rollback(ctx context.Context, name string, snap *siteSnapshot) error {
	if snap == nil {
		snap = m.pendingSnapshot
	}
	if snap == nil {
		// 没有快照就没有可回滚的依据。
		//
		// 这是**必须报错**的情形，绝不能"没有快照就跳过回滚"
		// 然后返回成功——那会让调用方以为服务是安全的。
		return errors.New("site: 没有可用的配置快照，无法回滚")
	}

	var errs []string

	// ---------- ① 恢复定义文件 ----------
	confPath := m.adapter.SiteFilePath(name)
	if snap.confExists {
		if err := atomicWriteFile(confPath, snap.confContent, 0o644); err != nil {
			errs = append(errs, "恢复配置文件失败: "+err.Error())
		}
	} else {
		// 操作前不存在 → 删除（新建场景的回滚）。
		if err := os.Remove(confPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, "删除新建的配置文件失败: "+err.Error())
		}
	}

	// ---------- ② 恢复 .conf.disabled ----------
	if disabledPath := m.adapter.DisabledPath(name); disabledPath != "" && disabledPath != confPath {
		if snap.disabledExists {
			if err := atomicWriteFile(disabledPath, snap.disabledContent, 0o644); err != nil {
				errs = append(errs, "恢复禁用文件失败: "+err.Error())
			}
		} else {
			if err := os.Remove(disabledPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, "删除新建的禁用文件失败: "+err.Error())
			}
		}
	}

	// ---------- ③ 恢复启用状态 ----------
	//
	// 注意这里用的是 adapter 的 Enable/Disable，而它们内部会再检查
	// 一次当前状态。顺序有意为"先恢复文件、再恢复链接"：
	// Enable 会检查配置文件是否存在，先恢复文件才能让 Enable 成功。
	if want := snap.enabledExists; m.adapter.Enabled(name) != want {
		var err error
		if want {
			err = m.adapter.Enable(name)
		} else {
			err = m.adapter.Disable(name)
		}
		if err != nil {
			errs = append(errs, "恢复启用状态失败: "+err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

// ---------------------------------------------------------------------------
// 原子写
// ---------------------------------------------------------------------------

// atomicWriteFile 以"临时文件 + fsync + rename"原子写入文件。
//
// 为什么不直接 os.WriteFile：写一半被打断（进程被杀、断电、磁盘满）
// 会留下一个**被截断的 nginx 配置**——对 nginx 来说这意味着
// 整个服务起不来。临时文件 + rename 保证任何时刻磁盘上的那个文件
// 要么是完整的旧版本、要么是完整的新版本，不存在中间态。
//
// rename 在同一目录内进行，因此天然是同文件系统的原子操作。
//
// 文件权限固定 0644：nginx 通常以非 root 的 worker 用户读取配置，
// 0600 会让它读不到；而 0664/0666 又会让同机其它用户能改写配置
// （等于把面板的权限拱手让人）。0644 是这两者之间的唯一合理取值。
func atomicWriteFile(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("site: 创建目录 %s 失败: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".lipanel-*.tmp")
	if err != nil {
		return fmt.Errorf("site: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	// 任何一步失败都要清掉临时文件，否则目录里会堆积
	// .lipanel-*.tmp——它们不带 .conf 后缀，不会被 nginx 加载，
	// 但会污染用户的目录。
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site: 写入临时文件失败: %w", err)
	}
	// fsync：确保数据真正落盘后再 rename。
	// 少了这一步，断电后可能出现"rename 生效了但内容还是空的"
	// ——正是原子写要防的那类事故。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site: 同步临时文件失败: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site: 设置临时文件权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("site: 关闭临时文件失败: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("site: 替换配置文件 %s 失败: %w", path, err)
	}
	tmpName = "" // 已 rename，不再需要清理。

	// 同步目录项：rename 的元数据变化也要落盘。
	// 打不开目录（某些文件系统不支持）只忽略，不影响主流程。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
