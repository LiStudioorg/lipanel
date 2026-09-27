package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 软件商店管理器（阶段四 4.5，核心自带）
// ============================================================================
//
// 本文件编排"安装/卸载"这条链路，并回答状态查询。
//
// #################### 多源回退策略（计划的核心要求）####################
//
//	① 系统源  —— 用已有的 apt/dnf 源直接装。
//	             先**查候选版本**再决定，而不是盲装：
//	             系统源自带的 nodejs 在 Ubuntu 22.04 上是 12.x，
//	             盲装会让用户"选了 22 却装上 12"，而面板还报成功。
//	② 官方源  —— 系统源里没有目标版本时，追加官方源
//	             （ondrej/php、NodeSource、MySQL、nginx.org、redis），
//	             刷新索引后重试。
//	③ 预编译  —— 官方源也没有该版本（或该发行版没有官方源）时，
//	             下载软件官方的预编译归档解包。
//
// 每一步的失败都**不终止流程**，而是记日志后进入下一条策略；
// 三条都失败才把任务标记为失败，并在错误里带上每一步的原因摘要——
// 用户要看到的是"为什么三条路都不通"，而不是最后一条的报错。
//
// #################### 串行化：一次只跑一个任务 ####################
//
// apt 与 dpkg 有全局锁（/var/lib/dpkg/lock），两个并发的安装
// 必然有一个失败并报"Could not get lock"。因此在管理器层
// 串行化：正在跑任务时新的安装请求直接返回 409 并说明原因，
// 而不是排队（排队会让用户对着一个不动的进度条猜"前面还有谁"）。

// 错误分类。调用方（server 层）据此映射 HTTP 状态码。
var (
	// ErrUnavailable 表示环境不具备安装能力（没有包管理器）。
	ErrUnavailable = errors.New("store: 当前环境不具备软件安装能力")
	// ErrNotFound 表示软件或版本不在清单中。
	ErrNotFound = errors.New("store: 软件或版本不存在")
	// ErrInvalidInput 表示输入未通过白名单校验。
	ErrInvalidInput = errors.New("store: 输入非法")
	// ErrBusy 表示已有任务在执行。
	ErrBusy = errors.New("store: 已有安装/卸载任务正在执行")
	// ErrTimeout 表示命令或任务超时。
	ErrTimeout = errors.New("store: 操作超时")
	// ErrCommandFailed 表示命令执行失败。
	ErrCommandFailed = errors.New("store: 命令执行失败")
	// ErrNotInstalled 表示目标软件未安装（卸载时）。
	ErrNotInstalled = errors.New("store: 软件未安装")
	// ErrConflict 表示已安装了同一软件的其它版本。
	ErrConflict = errors.New("store: 已安装同一软件的其它版本")
	// ErrNoStrategy 表示所有安装策略都失败了。
	ErrNoStrategy = errors.New("store: 所有安装策略均失败")
	// ErrVersionMismatch 表示命令成功但装上的不是目标版本。
	//
	// 与"这个包名不存在"必须区分：前者说明**软件已经装上了**
	// （只是版本不对），再换一个包名重试毫无意义，
	// 而且会把真正的原因（版本不符）埋在一堆无用重试里。
	ErrVersionMismatch = errors.New("store: 安装成功但版本不符")
)

// 默认配置。
const (
	// DefaultShutdownGrace 是退出时等待安装任务收尾的默认宽限期。
	//
	// 15 分钟的依据：装 MySQL / PHP 这类软件在慢机器上要几分钟，
	// 加上下载（国内网络下 apt 源可能很慢），10 分钟以内经常不够。
	// 但它**不是**任务超时（那是 TaskTimeout，默认 45m）：
	// 这个值只决定"面板自己愿意等多久才退出"，
	// 超时后包管理器仍会继续跑完——把 apt 打断才是真正的伤害。
	DefaultShutdownGrace = 15 * time.Minute

	// DefaultStepTimeout 是单条命令的默认超时。
	//
	// 600s：一次 apt 安装要下载几十到几百 MB 并运行 postinst，
	// 慢机器上 5 分钟很常见。超时过短会把"正在装"误判成"装失败"，
	// 而部分安装留下的 dpkg 半配置状态比等待更难处理。
	DefaultStepTimeout = 600 * time.Second
	// DefaultTaskTimeout 是整个任务的默认超时（含所有步骤）。
	DefaultTaskTimeout = 45 * time.Minute
	// DefaultLogLimit 是单个任务保留的日志行数。
	DefaultLogLimit = 2000
	// DefaultMaxTasks 是内存中保留的任务数。
	DefaultMaxTasks = 50
	// DefaultStateDir 是预编译安装状态与下载缓存的默认目录。
	DefaultStateDir = "/var/lib/lipanel/store"
)

// Options 是构造 Manager 的配置。
type Options struct {
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Catalog 为 nil 时加载内置清单。
	Catalog *Catalog
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// Executor 为 nil 时使用 os/exec 实现。
	Executor Executor
	// Vars 是环境探测结果；为零值时自动探测。
	//
	// 显式注入的唯一目的是**可测**：测试用一个手写的 Vars
	// 就能穷举 Debian/RHEL/无包管理器三条分支。
	Vars Vars
	// StateDir 是预编译安装状态与下载缓存目录；为空时用 DefaultStateDir。
	StateDir string
	// StepTimeout 是单条命令的超时；<=0 时用 DefaultStepTimeout。
	StepTimeout time.Duration
	// TaskTimeout 是整个任务的超时；<=0 时用 DefaultTaskTimeout。
	TaskTimeout time.Duration
	// LogLimit 是单任务日志行数上限；<=0 时用 DefaultLogLimit。
	LogLimit int
	// MaxTasks 是保留的任务数；<=0 时用 DefaultMaxTasks。
	MaxTasks int
	// DryRun 为 true 时**不执行任何真实命令**，只打印将要执行的命令。
	//
	// ########## 这个开关的用途与边界 ##########
	//
	// 它是给"面板部署在关键机器上、先看一遍会发生什么"用的：
	// 全部步骤照跑一遍（含版本探测与策略选择），但执行器被替换成
	// 只记录不执行的实现。它与 --dry-run 式的"试运行"同义。
	//
	// 它**不是**降级开关，也不影响权限与审计：dry-run 下的任务
	// 同样写审计（且标记 simulated），因为"谁在什么时候试着装了
	// 什么"本身就是有价值的记录。
	DryRun bool
	// ListDirOverride / KeyringDirOverride / YumRepoDirOverride 覆盖
	// apt 源、keyring 与 yum 仓库目录。
	//
	// ########## 仅供测试与隔离环境使用 ##########
	//
	// 生产环境必须留空（用 /etc/apt/sources.list.d、/usr/share/keyrings、
	// /etc/yum.repos.d）。存在的理由：官方源步骤要**真的往磁盘写文件**，
	// 而"写系统路径"这件事在单测里必须被隔离到临时目录，
	// 否则跑一次测试就会污染开发机。
	ListDirOverride    string
	KeyringDirOverride string
	YumRepoDirOverride string

	// SkipDetect 关闭"Vars 为空时自动探测本机环境"的行为。
	//
	// 置为 true 时，Options.Vars 会被原样使用（含其零值，
	// 即"没有可用的包管理器"）。用于测试与把环境探测
	// 交给调用方完成的嵌入场景。
	SkipDetect bool

	// PrebuiltRootOverride 把预编译包的安装目录与软链接目录
	// 整体重定位到该前缀之下（仅供测试与隔离环境使用）。
	//
	// 清单里的预编译路径是 /usr/local/...（生产正确值），
	// 但"解包到 /usr/local + 在 /usr/local/bin 建链接"必须能在
	// 临时目录里被完整测试，否则这条兜底路径就没有测试覆盖。
	PrebuiltRootOverride string
}

// Manager 提供软件商店能力。
type Manager struct {
	logger  *slog.Logger
	cat     *Catalog
	auditor *Auditor
	exec    Executor
	execRaw Executor
	vars    Vars
	dryRun  bool

	stateDir     string
	stepTime     time.Duration
	taskTime     time.Duration
	logLimit     int
	maxTasks     int
	listDir      string
	keyringDir   string
	yumRepoDir   string
	prebuiltRoot string

	// runMu 串行化安装/卸载任务（见文件头说明）。
	//
	// 用 TryLock 而不是 Lock：并发请求必须**立刻**得到
	// "已有任务在执行"的答复，而不是排队等待（排队会让前端
	// 显示一个从 0 开始、实际已经排了很久的进度条）。
	runMu sync.Mutex

	// mu 保护任务表与预编译状态缓存。
	mu    sync.Mutex
	tasks map[string]*taskState
	order []string
	seq   uint64

	// prebuilt 是预编译安装记录（惰性加载）。
	prebuilt map[string]map[string]prebuiltRecord
	loaded   bool
}

// prebuiltRecord 是一条预编译安装记录（落盘于 StateDir/prebuilt.json）。
type prebuiltRecord struct {
	Software    string   `json:"software"`
	Version     string   `json:"version"`
	InstallDir  string   `json:"install_dir"`
	LinkDir     string   `json:"link_dir"`
	Binaries    []string `json:"binaries"`
	URL         string   `json:"url"`
	InstalledAt string   `json:"installed_at"`
}

// NewManager 构造管理器。
func NewManager(opts Options) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cat := opts.Catalog
	if cat == nil {
		var err error
		cat, err = LoadCatalog()
		if err != nil {
			return nil, err
		}
	}
	auditor := opts.Auditor
	if auditor == nil {
		var err error
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}
	exec := opts.Executor
	if exec == nil {
		exec = execExecutor{}
	}
	// ########## 环境描述：注入优先，探测兜底 ##########
	//
	// Options.Vars 零值时自动探测本机环境，这对 main.go 是便利的。
	// 但"探测不到任何包管理器"也是一个必须能被表达的结果：
	// 若这里无脑重探，调用方就无法构造"这台机器上没有 apt/dnf/yum"
	// 的场景（重探只会再次得到同样的结论，而测试与嵌入方
	// 需要的是一个**确定**的输入）。因此提供 SkipDetect 显式关掉兜底。
	vars := opts.Vars
	if vars.Manager == "" && !opts.SkipDetect {
		vars = DetectVars(AdapterOptions{})
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	stepTime := opts.StepTimeout
	if stepTime <= 0 {
		stepTime = DefaultStepTimeout
	}
	taskTime := opts.TaskTimeout
	if taskTime <= 0 {
		taskTime = DefaultTaskTimeout
	}
	logLimit := opts.LogLimit
	if logLimit <= 0 {
		logLimit = DefaultLogLimit
	}
	maxTasks := opts.MaxTasks
	if maxTasks <= 0 {
		maxTasks = DefaultMaxTasks
	}
	listDir := opts.ListDirOverride
	if listDir == "" {
		listDir = ListDir()
	}
	keyringDir := opts.KeyringDirOverride
	if keyringDir == "" {
		keyringDir = KeyringDir()
	}
	yumRepoDir := opts.YumRepoDirOverride
	if yumRepoDir == "" {
		yumRepoDir = YumRepoDir()
	}

	prebuiltRoot := opts.PrebuiltRootOverride
	if prebuiltRoot != "" {
		// 统一去掉尾部斜杠，filepath.Join 才能正确拼接。
		prebuiltRoot = strings.TrimRight(prebuiltRoot, "/")
	}

	m := &Manager{
		logger:       logger,
		cat:          cat,
		auditor:      auditor,
		exec:         exec,
		execRaw:      exec,
		vars:         vars,
		dryRun:       opts.DryRun,
		stateDir:     stateDir,
		stepTime:     stepTime,
		taskTime:     taskTime,
		logLimit:     logLimit,
		maxTasks:     maxTasks,
		listDir:      listDir,
		keyringDir:   keyringDir,
		yumRepoDir:   yumRepoDir,
		prebuiltRoot: prebuiltRoot,
		tasks:        make(map[string]*taskState),
	}
	if m.dryRun {
		// dry-run：把执行器换成"只记录不执行"的实现。
		// 放在这里而不是每个调用点判断，保证**没有任何**路径
		// 能在 dry-run 下真的跑起一条命令。
		m.exec = dryRunExecutor{logger: logger}
	}
	return m, nil
}

// Available 表示软件商店能力是否可用。
func (m *Manager) Available() bool { return m != nil && m.vars.Available() }

// UnavailableReason 返回不可用原因。
func (m *Manager) UnavailableReason() string {
	if m == nil {
		return "软件商店管理器未初始化"
	}
	return m.vars.UnavailableReason()
}

// Vars 返回环境探测结果。
func (m *Manager) Vars() Vars {
	if m == nil {
		return Vars{}
	}
	return m.vars
}

// Catalog 返回软件清单。
func (m *Manager) Catalog() *Catalog {
	if m == nil {
		return nil
	}
	return m.cat
}

// Auditor 返回审计器。
func (m *Manager) Auditor() *Auditor {
	if m == nil {
		return nil
	}
	return m.auditor
}

// DryRun 返回是否为试运行模式。
func (m *Manager) DryRun() bool { return m != nil && m.dryRun }

// ---------------------------------------------------------------------------
// 状态查询
// ---------------------------------------------------------------------------

// VersionStatus 是单个版本的安装状态。
type VersionStatus struct {
	// ID / Label 是版本标识与展示名。
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	// Installed 表示该版本已安装。
	Installed bool `json:"installed"`
	// InstalledVersion 是系统里实际的版本串（可能与 ID 不完全一致：
	// 选 "8.3" 装上的实际是 "8.3.13-1+ubuntu22.04"）。
	InstalledVersion string `json:"installed_version,omitempty"`
	// Via 记录安装来源（system / official / prebuilt）。
	Via string `json:"via,omitempty"`
	// Packages 是该版本对应的包名列表。
	Packages []string `json:"packages,omitempty"`
	// IsDefault 标记默认版本（前端高亮）。
	IsDefault bool `json:"is_default"`
	// Notes 是版本级提示。
	Notes []string `json:"notes,omitempty"`
	// OfficialAvailable 表示该版本在系统源缺失时有无官方源可走。
	OfficialAvailable bool `json:"official_available"`
	// OfficialReason 是官方源不可用的原因。
	OfficialReason string `json:"official_reason,omitempty"`
	// PrebuiltAvailable 表示是否有预编译兜底。
	PrebuiltAvailable bool `json:"prebuilt_available"`
	// PrebuiltNotes 是预编译兜底的已知限制。
	PrebuiltNotes []string `json:"prebuilt_notes,omitempty"`
}

// SoftwareStatus 是单个软件的安装状态（API 的主要响应单元）。
type SoftwareStatus struct {
	// ID / Name / Category / Description 来自清单。
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	// Depends 是依赖的软件 ID。
	Depends []string `json:"depends,omitempty"`
	// DependsInstalled 表示依赖是否都已就绪。
	DependsInstalled bool `json:"depends_installed"`
	// DefaultVersion 是默认版本 ID。
	DefaultVersion string `json:"default_version"`
	// Versions 是各版本的安装状态。
	Versions []VersionStatus `json:"versions"`
	// Installed 表示**任意版本**已安装。
	Installed bool `json:"installed"`
	// InstalledVersions 是已安装的版本 ID 列表。
	InstalledVersions []string `json:"installed_versions,omitempty"`
	// DetectedVersion 是系统里探测到的实际版本（可能不在清单中）。
	//
	// 典型场景：发行版自带的 nginx 1.18 不在我们提供的版本列表里。
	// 此时 InstalledVersions 为空但 DetectedVersion 非空——
	// 前端要如实展示"已安装 1.18（非列表版本）"，
	// 而不是显示成"未安装"让用户以为可以再装一个。
	DetectedVersion string `json:"detected_version,omitempty"`
	// DetectedPackages 是探测到已安装的包名。
	DetectedPackages []string `json:"detected_packages,omitempty"`
	// InstalledVia 是安装来源（system / official / prebuilt / unknown）。
	InstalledVia string `json:"installed_via,omitempty"`
	// CanInstall / CanUninstall 是前端按钮的可用性提示。
	//
	// 注意：它们只是**体验优化**，真正的强制点始终在后端。
	CanInstall   bool `json:"can_install"`
	CanUninstall bool `json:"can_uninstall"`
	// Notes 是值得提示给用户的情况。
	Notes []string `json:"notes,omitempty"`
	// OfficialFamilies 是本软件支持官方源的家族列表（展示用）。
	OfficialFamilies []string `json:"official_families,omitempty"`
}

// StatusCounts 是状态统计（前端直接展示，不必自己遍历）。
type StatusCounts struct {
	Total     int `json:"total"`
	Installed int `json:"installed"`
	Pending   int `json:"pending"`
}

// StatusResult 是 Status() 的返回。
type StatusResult struct {
	// Software 是全部软件的状态。
	Software []SoftwareStatus `json:"software"`
	// Counts 是汇总统计。
	Counts StatusCounts `json:"counts"`
	// Available 表示能否安装（有包管理器）。
	Available bool `json:"available"`
	// UnavailableReason 是不可用原因。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// ScannedAt 是本次扫描时间。
	ScannedAt string `json:"scanned_at"`
	// Running 是当前正在执行的任务（无则为 nil）。
	Running *Task `json:"running,omitempty"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
}

// CapabilityInfo 是单个软件的**能力**摘要（不是安装状态）。
//
// 与 SoftwareStatus 的区别：那个回答"装没装"，这个回答
// "在这台机器上能不能装、靠哪条路装、有哪些已知坑"。
// 排查"为什么装不上"时看的是这一份。
type CapabilityInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	// Supported 表示当前发行版是否在清单声明支持的范围内。
	//
	// 取的是环境级探测结果（Vars.DistroSupported）而不是逐软件标记：
	// 一旦发行版不在支持列表里，所有软件的可信度都下降了，
	// 逐软件标记只会让人误以为"这个软件是特例"。
	Supported bool `json:"supported"`
	// Depends 是依赖的软件 ID。
	Depends []string `json:"depends,omitempty"`
	// Versions 是各版本的能力明细。
	Versions []VersionCapability `json:"versions"`
}

// VersionCapability 是单个版本的安装路径可用性。
type VersionCapability struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	IsDefault bool   `json:"is_default"`
	// SystemPackages 是系统源里的包名（可能为空）。
	SystemPackages []string `json:"system_packages,omitempty"`
	// AlternativePackages 是备选包名（发行版与官方源命名不一致时）。
	AlternativePackages []string `json:"alternative_packages,omitempty"`
	// OfficialAvailable 表示该版本在当前发行版家族下有官方源可走。
	OfficialAvailable bool `json:"official_available"`
	// OfficialKind 是官方源的接入方式（apt-key-source / script / ...）。
	OfficialKind string `json:"official_kind,omitempty"`
	// OfficialReason 是官方源不可用的原因。
	OfficialReason string `json:"official_reason,omitempty"`
	// PrebuiltAvailable 表示有预编译包兜底。
	PrebuiltAvailable bool `json:"prebuilt_available"`
	// PrebuiltNotes 是预编译兜底的已知限制（如"不经过包管理器"）。
	PrebuiltNotes []string `json:"prebuilt_notes,omitempty"`
	// Notes 是版本级提示。
	Notes []string `json:"notes,omitempty"`
}

// Capabilities 返回全部软件的能力摘要。
//
// 这是**纯静态**信息（来自内置清单与环境探测），不查询已安装状态，
// 因此不启动任何外部进程，可以随便调（前端进页面就能拿）。
func (m *Manager) Capabilities() []CapabilityInfo {
	out := make([]CapabilityInfo, 0, len(m.cat.Software))
	for _, sw := range m.cat.Software {
		info := CapabilityInfo{
			ID:          sw.ID,
			Name:        sw.Name,
			Category:    sw.Category,
			Description: sw.Description,
			Supported:   m.vars.DistroSupported,
			Depends:     append([]string(nil), sw.Depends...),
			Versions:    make([]VersionCapability, 0, len(sw.Versions)),
		}
		for _, ver := range sw.Versions {
			official := m.officialFor(sw, m.vars.Family)
			vc := VersionCapability{
				ID:                  ver.ID,
				Label:               ver.Label,
				IsDefault:           ver.ID == sw.DefaultVersion,
				SystemPackages:      append([]string(nil), ver.SystemPackages...),
				AlternativePackages: append([]string(nil), ver.AlternativePackages...),
				PrebuiltAvailable:   ver.Prebuilt != nil && m.prebuiltUsable(),
				Notes:               append([]string(nil), ver.Notes...),
			}
			if ver.Prebuilt != nil {
				vc.PrebuiltNotes = append([]string(nil), ver.Prebuilt.Notes...)
			}
			switch {
			case official == nil:
				vc.OfficialReason = fmt.Sprintf("%s 系列未提供官方源", familyLabel(m.vars.Family))
			case !m.vars.SupportsOfficialSource():
				vc.OfficialReason = m.officialUnavailableReason()
			default:
				vc.OfficialAvailable = true
				vc.OfficialKind = official.Kind
			}
			info.Versions = append(info.Versions, vc)
		}
		out = append(out, info)
	}
	return out
}

// StepTimeout / TaskTimeout / RunningTask 暴露给 server 层做展示。

// StepTimeout 返回单步命令超时。
func (m *Manager) StepTimeout() time.Duration { return m.stepTime }

// TaskTimeout 返回整个任务的超时上限。
func (m *Manager) TaskTimeout() time.Duration { return m.taskTime }

// RunningTask 返回当前正在执行的任务（无则返回 nil）。
func (m *Manager) RunningTask() *Task { return m.runningTask() }

// Idle 表示当前没有正在执行的安装/卸载任务。
//
// 与 "RunningTask() == nil" 等价，但调用点的意思更清楚：
// 关停流程问的是"现在能不能安全退出"，而不是"谁来着"。
func (m *Manager) Idle() bool { return m.runningTask() == nil }

// Status 汇总全部软件的安装状态。
//
// 实现要点：**一次批量查询**所有包名，而不是每个版本各起一个进程。
// 清单里有 5 个软件约 15 个版本、20 多个包名，
// 逐个查询会变成 20 次进程启动（每次 30~80ms），首页要等 1~2 秒。
func (m *Manager) Status(ctx context.Context) (StatusResult, error) {
	res := StatusResult{
		Software:  []SoftwareStatus{},
		Available: m.Available(),
		ScannedAt: time.Now().Format(time.RFC3339),
		DryRun:    m.dryRun,
	}
	if !m.Available() {
		res.UnavailableReason = m.UnavailableReason()
	}

	// 收集全部包名并批量查询已安装状态。
	allPkgs := make([]string, 0, 32)
	for _, sw := range m.cat.Software {
		for _, v := range sw.Versions {
			allPkgs = append(allPkgs, v.SystemPackages...)
			allPkgs = append(allPkgs, v.AlternativePackages...)
		}
	}
	installed := m.queryInstalled(ctx, allPkgs)

	res.Software = make([]SoftwareStatus, 0, len(m.cat.Software))
	for _, sw := range m.cat.Software {
		res.Software = append(res.Software, m.softwareStatus(ctx, sw, installed))
	}

	res.Counts.Total = len(res.Software)
	for _, s := range res.Software {
		if s.Installed {
			res.Counts.Installed++
		}
	}
	if t := m.runningTask(); t != nil {
		res.Running = t
		res.Counts.Pending = 1
	}
	return res, nil
}

// softwareStatus 组装单个软件的状态。
func (m *Manager) softwareStatus(ctx context.Context, sw Software, installed map[string]string) SoftwareStatus {
	st := SoftwareStatus{
		ID:             sw.ID,
		Name:           sw.Name,
		Category:       sw.Category,
		Description:    sw.Description,
		Depends:        append([]string(nil), sw.Depends...),
		DefaultVersion: sw.DefaultVersion,
		Versions:       make([]VersionStatus, 0, len(sw.Versions)),
	}
	for family := range sw.Official {
		st.OfficialFamilies = append(st.OfficialFamilies, family)
	}
	sortStrings(st.OfficialFamilies)

	// 依赖是否就绪。
	st.DependsInstalled = true
	for _, dep := range sw.Depends {
		depSW, ok := m.cat.Get(dep)
		if !ok {
			st.DependsInstalled = false
			continue
		}
		if !m.anyInstalled(depSW, installed) {
			st.DependsInstalled = false
		}
	}

	var (
		detectedPkgs []string
		detectedVer  string
		viaPrebuilt  string
	)
	for _, v := range sw.Versions {
		vs := VersionStatus{
			ID:        v.ID,
			Label:     v.Label,
			IsDefault: v.ID == sw.DefaultVersion,
			Packages:  append(append([]string{}, v.SystemPackages...), v.AlternativePackages...),
			Notes:     append([]string(nil), v.Notes...),
		}
		// 官方源可用性：该家族有官方源 + 环境能走官方源。
		official := m.officialFor(sw, m.vars.Family)
		vs.OfficialAvailable = official != nil && m.vars.SupportsOfficialSource()
		if official == nil {
			vs.OfficialReason = fmt.Sprintf("该软件在 %s 系列未提供官方源", familyLabel(m.vars.Family))
		} else if !m.vars.SupportsOfficialSource() {
			vs.OfficialReason = m.officialUnavailableReason()
		}
		if v.Prebuilt != nil {
			vs.PrebuiltAvailable = m.prebuiltUsable()
			vs.PrebuiltNotes = append([]string(nil), v.Prebuilt.Notes...)
		}

		// 包管理器里探测到的版本。
		for _, pkg := range vs.Packages {
			ver, ok := installed[pkg]
			if !ok {
				continue
			}
			detectedPkgs = appendUnique(detectedPkgs, pkg)
			if detectedVer == "" {
				detectedVer = ver
			}
			if VersionMatches(ver, v.ID) {
				vs.Installed = true
				vs.InstalledVersion = ver
				vs.Via = StrategySystem
			}
		}
		// 预编译安装记录。
		if rec, ok := m.prebuiltRecordFor(sw.ID, v.ID); ok {
			vs.Installed = true
			vs.Via = StrategyPrebuilt
			viaPrebuilt = v.ID
			if vs.InstalledVersion == "" {
				vs.InstalledVersion = rec.URL
			}
		}
		if vs.Installed {
			st.Installed = true
			st.InstalledVersions = append(st.InstalledVersions, v.ID)
		}
		st.Versions = append(st.Versions, vs)
	}

	if len(detectedPkgs) > 0 {
		st.DetectedPackages = detectedPkgs
	}
	if len(st.InstalledVersions) == 0 && len(detectedPkgs) > 0 {
		// 装了，但探测到的版本不在清单里。
		st.Installed = true
		st.DetectedVersion = detectedVer
		st.InstalledVia = StrategySystem
		st.Notes = append(st.Notes, fmt.Sprintf(
			"系统里已安装 %s（版本 %s），但该版本不在面板提供的版本列表中；"+
				"你可以直接卸载它，或安装列表中的版本（安装前需先卸载）",
			strings.Join(detectedPkgs, ", "), detectedVer))
	} else if len(st.InstalledVersions) > 0 {
		st.InstalledVia = StrategySystem
		if viaPrebuilt != "" && len(st.InstalledVersions) == 1 {
			st.InstalledVia = StrategyPrebuilt
		}
	}

	// 可安装：环境可用且没有其它版本占用（同一软件多版本会互相冲突）。
	st.CanInstall = m.Available() && len(st.InstalledVersions) == 0 && len(detectedPkgs) == 0
	st.CanUninstall = m.Available() && (len(st.InstalledVersions) > 0 || len(detectedPkgs) > 0 || len(m.prebuiltVersionsOf(sw.ID)) > 0)

	if len(st.InstalledVersions) > 1 {
		st.Notes = append(st.Notes,
			"检测到同一软件的多个版本同时安装，这通常是手工操作造成的；"+
				"卸载时会一并移除")
	}
	if !m.Available() {
		st.CanInstall = false
		st.CanUninstall = false
		st.Notes = append(st.Notes, m.UnavailableReason())
	}
	_ = ctx
	return st
}

// anyInstalled 判断某软件是否已安装（任意版本）。
func (m *Manager) anyInstalled(sw Software, installed map[string]string) bool {
	for _, v := range sw.Versions {
		for _, pkg := range append(append([]string{}, v.SystemPackages...), v.AlternativePackages...) {
			if _, ok := installed[pkg]; ok {
				return true
			}
		}
	}
	return len(m.prebuiltVersionsOf(sw.ID)) > 0
}

// queryInstalled 批量查询已安装的包版本。
//
// 查询失败**不报错**（退化为"全部未安装"）：状态接口的价值在于
// "能列出可安装的软件"，即使探测失败也应当能展示清单，
// 只是所有软件都显示为未安装。真正的错误留给安装动作去报。
func (m *Manager) queryInstalled(ctx context.Context, pkgs []string) map[string]string {
	pkgs = dedupStrings(pkgs)
	if len(pkgs) == 0 || !m.Available() {
		return map[string]string{}
	}
	switch m.vars.Manager {
	case PackageManagerAPT:
		if m.vars.Tools.DpkgQuery == "" {
			return map[string]string{}
		}
		cmd, err := BuildDpkgQuery(m.vars.Tools.DpkgQuery, pkgs)
		if err != nil {
			return map[string]string{}
		}
		res, err := m.run(ctx, cmd)
		if err != nil && res.Combined() == "" {
			return map[string]string{}
		}
		// 注意：dpkg-query 对不存在的包会返回非零退出码，
		// 但仍会为**已安装的包**正常输出。因此这里先解析输出、
		// 不因退出码非零而整体放弃（否则"装了 3 个、1 个没装"
		// 会被误判成"什么都没装"）。
		return ParseDpkgQuery(res.Stdout)
	default:
		if m.vars.Tools.RPM == "" {
			return map[string]string{}
		}
		cmd, err := BuildRPMQuery(m.vars.Tools.RPM, pkgs)
		if err != nil {
			return map[string]string{}
		}
		res, err := m.run(ctx, cmd)
		if err != nil && res.Combined() == "" {
			return map[string]string{}
		}
		return ParseRPMQuery(res.Stdout)
	}
}

// ---------------------------------------------------------------------------
// 预编译安装记录
// ---------------------------------------------------------------------------

// prebuiltPath 返回预编译状态文件路径。
func (m *Manager) prebuiltPath() string {
	return filepath.Join(m.stateDir, "prebuilt.json")
}

// loadPrebuilt 惰性加载预编译安装记录。
func (m *Manager) loadPrebuilt() map[string]map[string]prebuiltRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return m.prebuilt
	}
	m.loaded = true
	m.prebuilt = map[string]map[string]prebuiltRecord{}

	data, err := os.ReadFile(m.prebuiltPath())
	if err != nil {
		// 文件不存在是正常状态（没装过预编译包）。
		return m.prebuilt
	}
	var parsed map[string]map[string]prebuiltRecord
	if err := jsonUnmarshal(data, &parsed); err != nil {
		m.logger.Warn("预编译安装记录无法解析，已忽略",
			"path", m.prebuiltPath(), "err", err)
		return m.prebuilt
	}
	if parsed != nil {
		m.prebuilt = parsed
	}
	return m.prebuilt
}

// savePrebuilt 原子落盘预编译安装记录。
func (m *Manager) savePrebuilt() error {
	m.mu.Lock()
	data, err := jsonMarshalIndent(m.prebuilt)
	path := m.prebuiltPath()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("store: 创建状态目录失败: %w", err)
	}
	// 临时文件 + rename：避免面板在写一半时退出留下半个 JSON。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: 写入预编译安装记录失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: 保存预编译安装记录失败: %w", err)
	}
	return nil
}

// prebuiltRecordFor 返回某软件某版本的预编译安装记录。
func (m *Manager) prebuiltRecordFor(sw, version string) (prebuiltRecord, bool) {
	all := m.loadPrebuilt()
	vers, ok := all[sw]
	if !ok {
		return prebuiltRecord{}, false
	}
	rec, ok := vers[version]
	return rec, ok
}

// prebuiltVersionsOf 返回某软件已通过预编译方式安装的版本列表。
func (m *Manager) prebuiltVersionsOf(sw string) []string {
	all := m.loadPrebuilt()
	vers, ok := all[sw]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(vers))
	for v := range vers {
		out = append(out, v)
	}
	sortStrings(out)
	return out
}

// prebuiltUsable 表示预编译兜底在当前环境下是否可用。
func (m *Manager) prebuiltUsable() bool {
	return m.vars.Tools.Curl != "" && m.vars.Tools.Tar != "" && m.vars.Arch != ""
}

// ---------------------------------------------------------------------------
// 任务查询
// ---------------------------------------------------------------------------

// runningTask 返回当前正在执行的任务快照（无则 nil）。
func (m *Manager) runningTask() *Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.order {
		ts := m.tasks[id]
		if ts == nil {
			continue
		}
		st := ts.snapshot()
		if st.Status == TaskRunning || st.Status == TaskPending {
			return &st
		}
	}
	return nil
}

// Task 按 ID 返回任务快照。
func (m *Manager) Task(id string) (Task, bool) {
	m.mu.Lock()
	ts := m.tasks[id]
	m.mu.Unlock()
	if ts == nil {
		return Task{}, false
	}
	return ts.snapshot(), true
}

// TaskLogs 返回任务日志（since 为游标，0 表示从头）。
func (m *Manager) TaskLogs(id string, since int) ([]LogLine, bool) {
	m.mu.Lock()
	ts := m.tasks[id]
	m.mu.Unlock()
	if ts == nil {
		return nil, false
	}
	return ts.logsSince(since), true
}

// Tasks 返回最近的任务快照（最新在前）。
func (m *Manager) Tasks(limit int) []Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.order) {
		limit = len(m.order)
	}
	out := make([]Task, 0, limit)
	for i := len(m.order) - 1; i >= 0 && len(out) < limit; i-- {
		if ts := m.tasks[m.order[i]]; ts != nil {
			out = append(out, ts.snapshot())
		}
	}
	return out
}

// newTask 创建并登记一个任务。
func (m *Manager) newTask(kind, sw, swName, version, user, clientIP string) *taskState {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	id := fmt.Sprintf("t%d", m.seq)
	ts := &taskState{
		logs:     make([]LogLine, 0, 64),
		logLimit: m.logLimit,
		done:     make(chan struct{}),
	}
	ts.t = Task{
		ID:           id,
		Kind:         kind,
		Software:     sw,
		SoftwareName: swName,
		Version:      version,
		Status:       TaskPending,
		Stage:        "已创建，等待执行",
		CreatedAt:    time.Now().Format(time.RFC3339),
		User:         user,
		ClientIP:     clientIP,
		Simulated:    m.dryRun,
		Steps:        []StepState{},
	}
	m.tasks[id] = ts
	m.order = append(m.order, id)
	// 超出上限时丢弃最旧的**已结束**任务；若全在跑（不可能，
	// 因为同一时刻只允许一个任务），则丢弃最旧的。
	for len(m.order) > m.maxTasks {
		old := m.order[0]
		m.order = m.order[1:]
		if ts2 := m.tasks[old]; ts2 != nil {
			st := ts2.snapshot()
			if st.Status == TaskRunning || st.Status == TaskPending {
				// 不丢运行中的任务：把它挪到队尾，换下一个候选。
				m.order = append(m.order, old)
				delete(m.tasks, m.order[1])
				m.order = m.order[1:]
				continue
			}
		}
		delete(m.tasks, old)
	}
	return ts
}

// ---------------------------------------------------------------------------
// 安装 / 卸载入口
// ---------------------------------------------------------------------------

// InstallRequest 是一次安装请求。
type InstallRequest struct {
	// Software 是软件 ID（已由 server 层做过形态校验）。
	Software string
	// Version 是版本 ID；为空则用清单里的默认版本。
	Version string
	// User / ClientIP 是发起者（写入任务与审计）。
	User     string
	ClientIP string
	// SkipDependencies 为 true 时不自动安装依赖（默认 false）。
	SkipDependencies bool
}

// StartInstall 创建并启动一个安装任务（**立即返回**，不等待安装完成）。
func (m *Manager) StartInstall(ctx context.Context, req InstallRequest) (Task, error) {
	if !m.Available() {
		return Task{}, fmt.Errorf("%w: %s", ErrUnavailable, m.UnavailableReason())
	}
	// ---------- 校验（全部通过后才创建任务）----------
	if err := ValidSoftwareID(req.Software); err != nil {
		return Task{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	sw, ok := m.cat.Get(req.Software)
	if !ok {
		return Task{}, fmt.Errorf("%w: 软件 %q（可用: %s）",
			ErrNotFound, req.Software, strings.Join(m.cat.SoftwareIDs(), ", "))
	}
	versionID := req.Version
	if versionID == "" {
		versionID = sw.DefaultVersion
	}
	if err := ValidVersionID(versionID); err != nil {
		return Task{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	_, ver, ok := m.cat.FindVersion(req.Software, versionID)
	if !ok {
		return Task{}, fmt.Errorf("%w: 软件 %s 不支持版本 %q（可用: %s）",
			ErrNotFound, req.Software, versionID, strings.Join(versionIDs(sw), ", "))
	}

	// ---------- 串行化 ----------
	//
	// TryLock 成功即"占坑"：任务 goroutine 结束时 Unlock。
	// 这样"检查是否忙"与"开始执行"之间不存在时间窗，
	// 两个并发请求不会都认为自己拿到了执行权。
	if !m.runMu.TryLock() {
		running := m.runningTask()
		id := ""
		if running != nil {
			id = running.ID
		}
		return Task{}, fmt.Errorf("%w（任务 %s）。"+
			"apt/dpkg 与 rpm 都有全局锁，并发安装必然互相失败，"+
			"因此面板一次只执行一个安装/卸载任务", ErrBusy, id)
	}

	ts := m.newTask(TaskInstall, sw.ID, sw.Name, versionID, req.User, req.ClientIP)
	ts.appendLog(LogInfo, "", fmt.Sprintf("任务已创建：安装 %s %s", sw.Name, versionID))
	go func() {
		defer m.runMu.Unlock()
		m.executeInstall(ts, sw, ver, req)
	}()
	return ts.snapshot(), nil
}

// StartUninstall 创建并启动一个卸载任务。
func (m *Manager) StartUninstall(ctx context.Context, req InstallRequest) (Task, error) {
	if !m.Available() {
		return Task{}, fmt.Errorf("%w: %s", ErrUnavailable, m.UnavailableReason())
	}
	if err := ValidSoftwareID(req.Software); err != nil {
		return Task{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	sw, ok := m.cat.Get(req.Software)
	if !ok {
		return Task{}, fmt.Errorf("%w: 软件 %q", ErrNotFound, req.Software)
	}
	versionID := req.Version
	if versionID != "" {
		if err := ValidVersionID(versionID); err != nil {
			return Task{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		if _, _, ok := m.cat.FindVersion(req.Software, versionID); !ok {
			return Task{}, fmt.Errorf("%w: 软件 %s 不支持版本 %q",
				ErrNotFound, req.Software, versionID)
		}
	}

	if !m.runMu.TryLock() {
		running := m.runningTask()
		id := ""
		if running != nil {
			id = running.ID
		}
		return Task{}, fmt.Errorf("%w（任务 %s）", ErrBusy, id)
	}

	ts := m.newTask(TaskUninstall, sw.ID, sw.Name, versionID, req.User, req.ClientIP)
	ts.appendLog(LogInfo, "", fmt.Sprintf("任务已创建：卸载 %s %s", sw.Name, versionID))
	go func() {
		defer m.runMu.Unlock()
		m.executeUninstall(ts, sw, versionID)
	}()
	return ts.snapshot(), nil
}

// Shutdown 等待正在执行的任务结束（best-effort）。
//
// ########## 为什么用 TryLock 轮询而不是直接持锁 ##########
//
// 安装可能还要跑几分钟。直接下 SIGKILL（终止进程组）会留下
// dpkg 半配置状态——那是比"多等一会儿"糟糕得多的结果。
// 因此这里给一个上限：到点就走人，让 dpkg 自己在后台完成
// （它不依赖面板存活）。这与 4.4 的调度器 Close 语义一致：
// 要么真正停下，要么明确超时，绝不假装已经停止。
func (m *Manager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.runMu.TryLock() {
			m.runMu.Unlock()
			return nil
		}
		select {
		case <-ctx.Done():
			if t := m.runningTask(); t != nil {
				return fmt.Errorf("store: 等待任务 %s 结束超时（%s %s 可能仍在安装中，"+
					"包管理器进程不依赖面板存活，可稍后用系统工具确认结果）",
					t.ID, t.Software, t.Version)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// 安装执行
// ---------------------------------------------------------------------------

// executeInstall 执行安装任务（在任务 goroutine 中运行）。
func (m *Manager) executeInstall(ts *taskState, sw Software, ver Version, req InstallRequest) {
	// 任务上下文独立于发起它的 HTTP 请求：
	// 请求在返回 202 时就结束了，若用 r.Context()，安装会被立刻取消。
	ctx, cancel := context.WithTimeout(context.Background(), m.taskTime)
	defer cancel()

	previous := ts.snapshot().Status
	ts.markStatus(TaskRunning)
	ts.mu.Lock()
	ts.startedAt = time.Now()
	ts.t.StartedAt = ts.startedAt.Format(time.RFC3339)
	ts.mu.Unlock()
	_ = previous

	ts.appendLog(LogInfo, "", fmt.Sprintf("环境：%s", m.vars.Describe()))
	if m.dryRun {
		ts.appendLog(LogWarn, "", "试运行模式（-store-dry-run）：只记录将要执行的命令，不会真的安装")
	}
	ts.setProgress(5)

	err := m.installFlow(ctx, ts, sw, ver, req)
	if err != nil {
		hint := installHint(err)
		ts.appendLog(LogError, "", "安装失败："+err.Error())
		ts.fail(err, hint)
		m.recordTaskAudit(ts, AuditFailed, err.Error())
		close(ts.done)
		return
	}
	ts.appendLog(LogInfo, "", fmt.Sprintf("%s %s 安装完成（策略：%s）",
		sw.Name, ver.ID, nonEmpty(ts.snapshot().Strategy, "无")))
	ts.succeed()
	m.recordTaskAudit(ts, AuditAllowed, "")
	close(ts.done)
}

// installFlow 是安装的主流程（多源回退）。
func (m *Manager) installFlow(ctx context.Context, ts *taskState, sw Software, ver Version, req InstallRequest) error {
	// ---------- 0. 幂等与冲突检查 ----------
	//
	// 这一段是**必须**的：用户可能在两个标签页里各点了一次，
	// 也可能上次装到一半失败想重试。若不做检查直接调用包管理器，
	// apt 会给出 "already the newest version" 之类的输出，
	// 而我们无法据此判断"本来就装着"还是"刚装好"。
	installed := m.queryInstalled(ctx, append(append([]string{}, ver.SystemPackages...), ver.AlternativePackages...))
	ts.setStage("检查当前状态")
	for _, pkg := range append(append([]string{}, ver.SystemPackages...), ver.AlternativePackages...) {
		if v, ok := installed[pkg]; ok && VersionMatches(v, ver.ID) {
			ts.appendLog(LogInfo, "", fmt.Sprintf("%s 已经是目标版本（%s），无需重复安装", pkg, v))
			ts.setStrategy(StrategySystem)
			ts.setProgress(100)
			ts.addStep("system", "系统源安装")
			ts.stepSkip(0, "已经是目标版本，无需安装")
			// 依赖仍然要检查：用户可能只装了 php，没有 nginx。
			return m.ensureDependencies(ctx, ts, sw, req)
		}
	}
	if _, ok := m.prebuiltRecordFor(sw.ID, ver.ID); ok {
		ts.appendLog(LogInfo, "", fmt.Sprintf("%s %s 已通过预编译方式安装，无需重复安装", sw.Name, ver.ID))
		ts.setStrategy(StrategyPrebuilt)
		ts.setProgress(100)
		ts.addStep("prebuilt", "预编译兜底")
		ts.stepSkip(0, "已安装")
		return m.ensureDependencies(ctx, ts, sw, req)
	}
	// 同一软件的其它版本在装：先卸载再装，还是直接拒绝？
	//
	// 选择**拒绝并说明**：PHP/Node 这类软件在 apt 里多版本包
	// 会争抢 /usr/bin 下的同名可执行文件与配置文件，
	// 自动"先卸载再装"会让用户在不知情的情况下丢掉现有环境
	// （甚至可能卸掉生产站点依赖的版本）。让用户显式先卸载，
	// 是唯一不会造成意外的做法。
	if other := m.otherInstalledVersions(ctx, sw, ver.ID); len(other) > 0 {
		return fmt.Errorf("%w：%s 已安装 %s；"+
			"请先卸载该版本（同一软件的多个版本会互相覆盖可执行文件与配置）",
			ErrConflict, sw.Name, strings.Join(other, ", "))
	}

	// ---------- 1. 依赖 ----------
	if err := m.ensureDependencies(ctx, ts, sw, req); err != nil {
		return err
	}

	// ---------- 2. 按环境选择流程 ----------
	var err error
	switch m.vars.Manager {
	case PackageManagerAPT:
		err = m.aptInstallFlow(ctx, ts, sw, ver)
	case PackageManagerDNF, PackageManagerYUM:
		err = m.rpmInstallFlow(ctx, ts, sw, ver)
	default:
		err = fmt.Errorf("%w: 未探测到包管理器", ErrUnavailable)
	}
	if err == nil {
		return nil
	}
	// ########## 超时不是"换条路再试"的理由 ##########
	//
	// 单步超时意味着包管理器**可能还在后台跑**（apt/dpkg 有全局锁）。
	// 此时继续往下试官方源，会去写系统源配置并再次抢同一把锁，
	// 把一次可恢复的超时变成一台锁死的机器。
	// 因此超时直接中止，把"先确认 apt 是否还在跑"交给用户。
	if errors.Is(err, ErrTimeout) {
		return err
	}
	// ########## 版本不符要作为**首要原因**上报 ##########
	//
	// 版本不符（"装上了但不是你要的版本"）与其它失败有本质区别：
	// 它说明**软件已经在本机上了**，用户接下来该做的事
	// （卸载旧版本 / 接受现有版本）与"源不通、网络挂了"完全不同。
	//
	// 若把它埋在"（已尝试：system:failed, official:failed）"里，
	// 用户看到的是"三条路都失败"——一个只会引导他反复重试的说法，
	// 而真正有用的信息（实际装的是哪个版本）在步骤详情里。
	var mismatch error
	for _, st := range ts.snapshot().Steps {
		if st.Status == StepFailed && strings.Contains(st.Reason, "版本不符") {
			mismatch = errors.New(st.Reason)
			break
		}
	}
	steps := ts.summary()
	if mismatch != nil {
		return fmt.Errorf("%w（已尝试：%s）", mismatch, strings.Join(steps, ", "))
	}
	// 其它失败才是"此路不通"：把每一步的原因拼进错误，
	// 让用户看到"三条路都不通"，而不是只有最后一条的报错。
	return fmt.Errorf("%w: %v（已尝试：%s）", ErrNoStrategy, err, strings.Join(steps, ", "))
}

// aptInstallFlow 是 apt 系的三级回退。
func (m *Manager) aptInstallFlow(ctx context.Context, ts *taskState, sw Software, ver Version) error {
	sysStep := ts.addStep("system", "系统源安装")

	// ---------- ① 系统源 ----------
	if len(ver.SystemPackages) == 0 && len(ver.AlternativePackages) == 0 {
		ts.stepSkip(sysStep, "该版本未提供系统源包名")
		ts.appendLog(LogWarn, "系统源安装", "该版本没有系统源包名，跳过系统源")
	} else {
		ts.setStage("检查系统源")
		ts.setProgress(15)
		ts.stepStart(sysStep, "系统源安装")
		err := m.tryPackageSets(ctx, ts, sysStep, ver, m.aptPackagesReady)
		if err == nil {
			ts.stepDone(sysStep, true, "")
			ts.setStrategy(StrategySystem)
			ts.setProgress(100)
			return nil
		}
		ts.stepDone(sysStep, false, err.Error())
		// 超时立刻中止：此时 apt 可能还在跑，
		// 继续去写系统源配置并再抢一次全局锁是错误的自救方式。
		if errors.Is(err, ErrTimeout) {
			ts.appendLog(LogError, "系统源安装", timeoutAbortNote)
			return err
		}
		// ########## 失败原因必须如实区分 ##########
		//
		// 这里历史上统一写成"系统源不可用"，但 tryPackageSets 的失败
		// 有两类完全不同的原因：
		//
		//   ① 源里没有目标版本（"不可用"）—— 换官方源是对的；
		//   ② 命令跑成功但**装上的是别的版本**（复验抓到的）——
		//      源是好的，问题是版本对不上。
		//
		// 把 ② 也写成"不可用"会把用户引向错误的排查方向
		// （去查网络与软件源），而真实原因（该源没有目标版本，
		// 装上了默认版本）就藏在下面这行里。
		ts.appendLog(LogWarn, "系统源安装", systemFailureNote(err))
	}

	// ---------- ② 官方源 ----------
	officialStep := ts.addStep("official", "追加官方源后安装")
	official := m.officialFor(sw, m.vars.Family)
	switch {
	case official == nil:
		reason := fmt.Sprintf("%s 系列未提供官方源", familyLabel(m.vars.Family))
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	case !m.vars.SupportsOfficialSource():
		reason := m.officialUnavailableReason()
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	case m.vars.Tools.AptGet == "" || m.vars.Tools.Curl == "":
		reason := "缺少 apt-get 或 curl，无法接入官方源"
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	case len(ver.SystemPackages) == 0 && len(ver.AlternativePackages) == 0:
		reason := "该版本未提供包名，无法用官方源安装"
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	default:
		ts.setStage("追加官方源")
		ts.setProgress(45)
		ts.stepStart(officialStep, "追加官方源后安装")
		if err := m.applyAptOfficialSource(ctx, ts, officialStep, *official, ver); err != nil {
			ts.stepDone(officialStep, false, err.Error())
			ts.appendLog(LogWarn, "追加官方源", "官方源配置失败："+err.Error())
		} else if err := m.tryPackageSets(ctx, ts, officialStep, ver, m.aptPackagesReady); err != nil {
			ts.stepDone(officialStep, false, err.Error())
			if errors.Is(err, ErrTimeout) {
				ts.appendLog(LogError, "追加官方源", timeoutAbortNote)
				return err
			}
			ts.appendLog(LogWarn, "追加官方源", "官方源安装失败："+err.Error())
		} else {
			ts.stepDone(officialStep, true, "")
			ts.setStrategy(StrategyOfficial)
			ts.setProgress(100)
			return nil
		}
	}

	// ---------- ③ 预编译兜底 ----------
	return m.prebuiltFallback(ctx, ts, sw, ver)
}

// rpmInstallFlow 是 rpm 系的回退（系统源 → 官方 release 包 → 预编译）。
func (m *Manager) rpmInstallFlow(ctx context.Context, ts *taskState, sw Software, ver Version) error {
	sysStep := ts.addStep("system", "系统源安装")

	if len(ver.SystemPackages) == 0 && len(ver.AlternativePackages) == 0 {
		ts.stepSkip(sysStep, "该版本未提供系统源包名")
	} else {
		ts.setStage("检查系统源")
		ts.setProgress(15)
		ts.stepStart(sysStep, "系统源安装")
		err := m.tryPackageSets(ctx, ts, sysStep, ver, m.rpmPackagesReady)
		if err == nil {
			ts.stepDone(sysStep, true, "")
			ts.setStrategy(StrategySystem)
			ts.setProgress(100)
			return nil
		}
		ts.stepDone(sysStep, false, err.Error())
		if errors.Is(err, ErrTimeout) {
			ts.appendLog(LogError, "系统源安装", timeoutAbortNote)
			return err
		}
		ts.appendLog(LogWarn, "系统源安装", systemFailureNote(err))
	}

	officialStep := ts.addStep("official", "追加官方源后安装")
	official := m.officialFor(sw, m.vars.Family)
	switch {
	case official == nil:
		reason := fmt.Sprintf("%s 系列未提供官方源", familyLabel(m.vars.Family))
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	case !m.vars.SupportsOfficialSource():
		reason := m.officialUnavailableReason()
		ts.stepSkip(officialStep, reason)
		ts.appendLog(LogWarn, "追加官方源", reason)
	case len(ver.SystemPackages) == 0 && len(ver.AlternativePackages) == 0:
		reason := "该版本未提供包名，无法用官方源安装"
		ts.stepSkip(officialStep, reason)
	default:
		ts.setStage("追加官方源")
		ts.setProgress(45)
		ts.stepStart(officialStep, "追加官方源后安装")
		if err := m.applyRPMOfficialSource(ctx, ts, officialStep, *official, ver); err != nil {
			ts.stepDone(officialStep, false, err.Error())
			ts.appendLog(LogWarn, "追加官方源", "官方源配置失败："+err.Error())
		} else if err := m.tryPackageSets(ctx, ts, officialStep, ver, m.rpmPackagesReady); err != nil {
			ts.stepDone(officialStep, false, err.Error())
			if errors.Is(err, ErrTimeout) {
				ts.appendLog(LogError, "追加官方源", timeoutAbortNote)
				return err
			}
			ts.appendLog(LogWarn, "追加官方源", "官方源安装失败："+err.Error())
		} else {
			ts.stepDone(officialStep, true, "")
			ts.setStrategy(StrategyOfficial)
			ts.setProgress(100)
			return nil
		}
	}

	return m.prebuiltFallback(ctx, ts, sw, ver)
}

// readinessProbe 判断某组包名在**当前源**里是否有目标版本。
//
// 返回 (是否可用, 源里候选的完整版本号)。第二个返回值用于
// **钉住版本**（Version.PinSystemVersion）：清单知道的是 "1.26"，
// 而 apt 需要的完整版本号（1.26.2-1~jammy）只有查询源才知道。
// 不关心钉版本时第二个返回值可以直接忽略。
type readinessProbe func(ctx context.Context, ts *taskState, step int, pkgs []string, wantVersion string) (bool, string)

// tryPackageSets 依次尝试"主包名集合"与"备选包名集合"。
//
// ########## 为什么需要备选包名 ##########
//
// 同一个软件在不同发行版/仓库里的包名并不一致：
//
//	RHEL 9 的 MySQL：remi/官方源叫 mysql-community-server，
//	                 而 AppStream 里叫 mysql-server
//	Debian 的 PHP 8.3：sury 是 php8.3-fpm，remi 是 php83-php-fpm
//
// 清单把它们写成两份列表，安装时先试主列表、再试备选列表。
// 若只试主列表，"发行版自带同名包"这条最容易成功、
// 也最贴近用户预期的路径就被浪费了。
//
// 每组包名都走"先查版本 → 再安装 → 复验"三步，避免上面
// 提到的"选了 22 装成 12"。
func (m *Manager) tryPackageSets(ctx context.Context, ts *taskState, step int, ver Version, ready readinessProbe) error {
	sets := []struct {
		name string
		pkgs []string
	}{
		{"主包名", ver.SystemPackages},
		{"备选包名", ver.AlternativePackages},
	}
	var lastErr error
	tried := 0
	for _, set := range sets {
		if len(set.pkgs) == 0 {
			continue
		}
		tried++
		if tried > 1 {
			ts.appendLog(LogInfo, "系统源安装",
				fmt.Sprintf("尝试%s集合：%s", set.name, strings.Join(set.pkgs, ", ")))
		}
		ok, candidate := ready(ctx, ts, step, set.pkgs, ver.ID)
		if !ok {
			lastErr = fmt.Errorf("%s（%s）中没有版本 %s 的候选",
				set.name, strings.Join(set.pkgs, ", "), ver.ID)
			continue
		}
		// 需要钉版本时，把候选版本号拼进包名（apt/rpm 的 `pkg=ver` 语法）。
		//
		// 只在**源里确实查到了**候选时钉：查不到完整版本号却硬钉，
		// 会造出一个不存在的版本约束而必然失败（比不钉更糟）。
		installPkgs := set.pkgs
		if ver.PinSystemVersion && candidate != "" {
			installPkgs = make([]string, 0, len(set.pkgs))
			for _, pkg := range set.pkgs {
				installPkgs = append(installPkgs, pkg+"="+candidate)
			}
			ts.appendLog(LogInfo, "系统源安装",
				fmt.Sprintf("钉住版本：%s", strings.Join(installPkgs, ", ")))
		} else if ver.PinSystemVersion && candidate == "" {
			// 查不到候选版本时**不钉**，但要如实记录。
			// 静默地退化成"装任意版本"会让"选了 1.26 装成 1.24"
			// 以成功上报；这里的日志是排查该情况的唯一线索。
			ts.appendLog(LogWarn, "系统源安装",
				"未能从源里查到完整版本号，本次不钉版本（可能装上非目标版本）")
		}
		if err := m.runInstallPackages(ctx, ts, step, installPkgs, ver); err != nil {
			// ########## 超时必须立刻中止，不能"换组再试" ##########
			//
			// 超时的含义不是"这组包名不行"，而是**包管理器可能还在跑**。
			// 继续试下一组包名（或下一条策略）会再次调用 apt/dpkg，
			// 与还在持有全局锁的那个进程抢锁：一次可恢复的超时会被
			// 放大成一台需要人工介入的机器。
			// 因此这里不降级为 lastErr，而是直接向上抛。
			if errors.Is(err, ErrTimeout) {
				return err
			}
			// ########## 版本不符也必须立刻返回 ##########
			//
			// 包已经装上了（只是版本不对），换一个包名（nginx-core）
			// 再试一次不会改变结果，却会：
			//   · 把真正的失败原因（期望 1.26，实际 1.20）埋掉，
			//     用户最后只看到一句"备选包名里没有该版本"，
			//     完全猜不到软件其实已经装了；
			//   · 白白多跑一次包管理器。
			if errors.Is(err, ErrVersionMismatch) {
				return err
			}
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("该版本未提供任何包名")
	}
	return lastErr
}

// timeoutAbortNote 是超时中止时写进日志的说明。
//
// 单独抽出来是因为这条信息对用户很重要：它解释了
// "为什么面板没有继续尝试其它办法"，以及"接下来该怎么做"。
const timeoutAbortNote = "命令执行超时，已中止后续策略：" +
	"包管理器可能仍在运行，此时重试会与它抢同一把全局锁。" +
	"请先用 ps 确认 apt/dpkg 是否还在跑，再决定是否重试。"

// prebuiltFallback 走预编译兜底。
func (m *Manager) prebuiltFallback(ctx context.Context, ts *taskState, sw Software, ver Version) error {
	step := ts.addStep("prebuilt", "预编译包兜底")
	if ver.Prebuilt == nil {
		reason := fmt.Sprintf("%s %s 未提供预编译包，无可用安装策略", sw.Name, ver.ID)
		ts.stepSkip(step, reason)
		return errors.New(reason)
	}
	if !m.prebuiltUsable() {
		reason := "缺少 curl / tar，或当前架构没有对应的预编译产物"
		if m.vars.Arch == "" {
			reason = fmt.Sprintf("当前架构（%s）没有对应的预编译产物", m.vars.Arch)
		}
		ts.stepSkip(step, reason)
		return errors.New(reason)
	}

	ts.setStage("下载预编译包")
	ts.setProgress(75)
	ts.stepStart(step, "预编译包兜底")

	url, err := m.resolvePrebuiltURL(ctx, ts, step, sw, ver)
	if err != nil {
		ts.stepDone(step, false, err.Error())
		return err
	}
	ts.setPrebuiltURL(url)
	for _, note := range ver.Prebuilt.Notes {
		ts.appendLog(LogWarn, "预编译包兜底", note)
	}

	archive := filepath.Join(m.stateDir, "cache", fmt.Sprintf("%s-%s.tar.gz", sw.ID, ver.ID))
	installDir := m.rewriteDir(ver.Prebuilt.InstallDir)
	linkDir := m.rewriteDir(ver.Prebuilt.LinkDir)

	// 试运行：把剩下三步（下载 / 解包 / 建链接）作为命令展示出来即结束。
	// 放在这里而不是每个动作里判断，保证**没有任何**目录创建、
	// 文件写入或软链接会在试运行下发生。
	if m.dryRun {
		dlCmd := mustCommand(BuildDownload(m.vars.Tools.Curl, url, archive))
		exCmd := mustCommand(BuildExtract(m.vars.Tools.Tar, archive, installDir))
		ts.stepCommand(step, dlCmd.Redacted)
		ts.stepCommand(step, exCmd.Redacted)
		ts.appendLog(LogWarn, "预编译包兜底", "$ "+dlCmd.Redacted)
		ts.appendLog(LogWarn, "预编译包兜底", "$ "+exCmd.Redacted)
		ts.appendLog(LogWarn, "预编译包兜底",
			fmt.Sprintf("试运行：将下载 %s、解包到 %s，并在 %s 建立软链接 %v",
				url, installDir, linkDir, ver.Prebuilt.Binaries))
		ts.stepDone(step, true, "")
		ts.setStrategy(StrategyPrebuilt)
		ts.setProgress(100)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("store: 创建下载目录失败: %w", err)
	}
	if err := m.execStep(ctx, ts, step, mustCommand(BuildDownload(m.vars.Tools.Curl, url, archive))); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("下载预编译包失败: %w", err)
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("创建安装目录 %s 失败: %w", installDir, err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("创建软链接目录 %s 失败: %w", linkDir, err)
	}
	if err := m.execStep(ctx, ts, step, mustCommand(BuildExtract(m.vars.Tools.Tar, archive, installDir))); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("解压预编译包失败: %w", err)
	}
	// 建立软链接：预编译包解包后不在 PATH 里，不建链接等于"装了个找不到的东西"。
	for _, bin := range ver.Prebuilt.Binaries {
		src := filepath.Join(installDir, "bin", bin)
		dst := filepath.Join(linkDir, bin)
		if err := os.Symlink(src, dst); err != nil && !os.IsExist(err) {
			ts.stepDone(step, false, err.Error())
			return fmt.Errorf("创建软链接 %s 失败: %w", dst, err)
		}
	}
	// 验证：跑一次 `--version`，确认二进制真的能执行。
	// 不做验证的话，"解压成功但架构不匹配/缺动态库"会被报告成安装成功。
	verifyArgs := ver.Prebuilt.VerifyArgs
	if len(verifyArgs) == 0 {
		verifyArgs = []string{"--version"}
	}
	verifyBin := filepath.Join(installDir, "bin", firstNonEmpty(ver.Prebuilt.Binaries, sw.ID))
	if err := m.execStep(ctx, ts, step, mustCommand(BuildVerifyBinary(verifyBin, verifyArgs...))); err != nil {
		ts.stepDone(step, false, err.Error())
		return fmt.Errorf("预编译包验证失败（二进制无法执行）: %w", err)
	}

	// 记录安装来源（状态查询据此显示"已安装（预编译）"）。
	m.mu.Lock()
	if m.prebuilt == nil {
		m.prebuilt = map[string]map[string]prebuiltRecord{}
	}
	if m.prebuilt[sw.ID] == nil {
		m.prebuilt[sw.ID] = map[string]prebuiltRecord{}
	}
	m.prebuilt[sw.ID][ver.ID] = prebuiltRecord{
		Software:    sw.ID,
		Version:     ver.ID,
		InstallDir:  installDir,
		LinkDir:     linkDir,
		Binaries:    append([]string(nil), ver.Prebuilt.Binaries...),
		URL:         url,
		InstalledAt: time.Now().Format(time.RFC3339),
	}
	m.mu.Unlock()
	if err := m.savePrebuilt(); err != nil {
		ts.appendLog(LogWarn, "预编译包兜底", "安装记录落盘失败："+err.Error())
	}

	ts.stepDone(step, true, "")
	ts.setStrategy(StrategyPrebuilt)
	ts.setProgress(100)
	return nil
}

// rewriteDir 把清单里的固定目录映射到 PrebuiltRootOverride 之下。
//
// 未设置 override 时原样返回（生产路径）。
func (m *Manager) rewriteDir(dir string) string {
	if m.prebuiltRoot == "" {
		return dir
	}
	return filepath.Join(m.prebuiltRoot, strings.TrimPrefix(dir, "/"))
}

// resolvePrebuiltURL 解析预编译归档的真实下载地址。
//
// 两种方式（见 VersionPrebuilt 的说明）：
//
//	① 直接模板 —— 文件名固定，渲染占位符即可；
//	② 索引解析 —— 文件名含补丁号，先下载官方索引（如 SHASUMS256.txt），
//	              按 file_prefix/file_suffix 匹配出真实文件名再拼接。
//
// 方式 ② 的索引在 dry-run 下不会真的下载（执行器只记录），
// 因此这里对 dry-run 做一次特殊处理：用一个**合成的**文件名，
// 让整条链路（包括后续的下载与解包命令）能被完整展示出来。
// 否则试运行会在"读索引文件"这一步失败，用户看不到后面会发生什么。
func (m *Manager) resolvePrebuiltURL(ctx context.Context, ts *taskState, step int, sw Software, ver Version) (string, error) {
	pb := ver.Prebuilt
	if pb.URLTemplate != "" {
		url, err := RenderSourceTemplate(pb.URLTemplate, ver.ID, m.vars.Codename, m.vars.Arch)
		if err != nil {
			return "", err
		}
		return url, validHTTPSURL(url)
	}

	indexURL, err := RenderSourceTemplate(pb.IndexURLTemplate, ver.ID, m.vars.Codename, m.vars.Arch)
	if err != nil {
		return "", err
	}
	if err := validHTTPSURL(indexURL); err != nil {
		return "", err
	}
	suffix, err := RenderSourceTemplate(pb.FileSuffix, ver.ID, m.vars.Codename, m.vars.Arch)
	if err != nil {
		return "", err
	}

	indexFile := filepath.Join(m.stateDir, "cache", fmt.Sprintf("%s-%s.index", sw.ID, ver.ID))

	// 试运行：不建缓存目录、不下载索引，直接按规则合成文件名。
	// 目的是让**整条**兜底链路（含下载与解包命令）都能在日志里
	// 完整展示；若在"读索引"这步停住，用户反而看不到后面会发生什么。
	if m.dryRun {
		name := pb.FilePrefix + ver.ID + suffix
		ts.appendLog(LogWarn, "预编译包兜底",
			"试运行模式：未真正读取官方索引，按规则合成文件名 "+name)
		return JoinURLFile(indexURL, name)
	}

	if err := os.MkdirAll(filepath.Dir(indexFile), 0o700); err != nil {
		return "", fmt.Errorf("store: 创建缓存目录失败: %w", err)
	}
	if err := m.execStep(ctx, ts, step, mustCommand(BuildDownload(m.vars.Tools.Curl, indexURL, indexFile))); err != nil {
		return "", fmt.Errorf("下载官方索引失败: %w", err)
	}

	data, err := os.ReadFile(indexFile)
	if err != nil {
		return "", fmt.Errorf("读取官方索引失败: %w", err)
	}
	name := PickIndexedFile(string(data), pb.FilePrefix, suffix)
	if name == "" {
		return "", fmt.Errorf("官方索引中未找到匹配 %s*%s 的文件（官方可能已更换归档命名）",
			pb.FilePrefix, suffix)
	}
	url, err := JoinURLFile(indexURL, name)
	if err != nil {
		return "", err
	}
	ts.appendLog(LogInfo, "预编译包兜底", "从官方索引解析到归档："+name)
	return url, nil
}

// applyAptOfficialSource 配置 apt 官方源（写 keyring 与源条目 + 刷新索引）。
func (m *Manager) applyAptOfficialSource(ctx context.Context, ts *taskState, step int, o OfficialSource, ver Version) error {
	switch o.Kind {
	case OfficialAptKeySource:
		// ---------- GPG key ----------
		keyPath := o.KeyringPath
		if m.keyringDir != KeyringDir() {
			// 测试/隔离环境：把系统路径重定向到临时目录。
			keyPath = filepath.Join(m.keyringDir, filepath.Base(keyPath))
		}
		if m.dryRun {
			// 试运行连**目录都不创建**：一个"看看会发生什么"的开关
			// 留下任何磁盘痕迹，都不配叫试运行。
			ts.appendLog(LogWarn, "追加官方源",
				fmt.Sprintf("试运行：将下载公钥 %s 到 %s", o.KeyURL, keyPath))
		} else {
			if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
				return fmt.Errorf("创建 keyring 目录失败: %w", err)
			}
			if err := m.execStep(ctx, ts, step,
				mustCommand(BuildCurlKeyDownload(m.vars.Tools.Curl, o.KeyURL, keyPath))); err != nil {
				return fmt.Errorf("下载 GPG 公钥失败: %w", err)
			}
			ts.appendLog(LogInfo, "追加官方源", "GPG 公钥已写入 "+keyPath)
		}

		// ---------- 源条目 ----------
		line, err := BuildAptSourceLine(o, ver.ID, m.vars.Codename)
		if err != nil {
			return err
		}
		listPath := filepath.Join(m.listDir, o.ListFile)
		if m.dryRun {
			ts.appendLog(LogWarn, "追加官方源",
				fmt.Sprintf("试运行：将写入源条目 %s：%s", listPath, line))
		} else {
			if err := os.MkdirAll(filepath.Dir(listPath), 0o755); err != nil {
				return fmt.Errorf("创建源目录失败: %w", err)
			}
			// 用 Go 写文件而不是 `sh -c "echo ... > file"`：
			// 写入的内容与写入这个动作都在我们的控制下，
			// 不存在"重定向符被内容影响"的可能。
			if err := os.WriteFile(listPath, []byte(line+"\n"), 0o644); err != nil {
				return fmt.Errorf("写入源条目 %s 失败: %w", listPath, err)
			}
			ts.appendLog(LogInfo, "追加官方源", fmt.Sprintf("源条目已写入 %s：%s", listPath, line))
		}
	case OfficialScript:
		url, err := RenderSourceTemplate(o.ScriptURL, ver.ID, m.vars.Codename, m.vars.Arch)
		if err != nil {
			return err
		}
		pipe, err := BuildOfficialScript(m.vars.Tools.Curl, url)
		if err != nil {
			return err
		}
		// 脚本会自己写 sources.list 与 keyring（这是官方推荐做法）。
		if err := m.execScript(ctx, ts, step, pipe); err != nil {
			return fmt.Errorf("官方安装脚本执行失败: %w", err)
		}
	default:
		return fmt.Errorf("官方源类型 %q 不适用于 apt", o.Kind)
	}

	// ---------- 刷新索引 ----------
	// 追加源之后**必须**刷新索引，否则 apt 仍然看不到新的源。
	if m.vars.Tools.AptGet != "" {
		cmd := BuildAptUpdate(m.vars.Tools.AptGet)
		// 刷新失败不直接判死：某个**无关的**第三方源 404 会让
		// `apt-get update -y` 返回非零，而我们要装的包可能已经
		// 从新源拿到了索引。真正的判断留给下一步的候选版本查询。
		if err := m.execStep(ctx, ts, step, cmd); err != nil {
			ts.appendLog(LogWarn, "追加官方源",
				"apt 索引刷新返回非零（可能是其它源的问题），继续尝试安装："+err.Error())
		}
	}
	return nil
}

// applyRPMOfficialSource 配置 rpm 官方源（安装 release 包 + 刷新元数据）。
func (m *Manager) applyRPMOfficialSource(ctx context.Context, ts *taskState, step int, o OfficialSource, ver Version) error {
	switch o.Kind {
	case OfficialDnfRepo:
		url, err := RenderSourceTemplate(o.RepoURLTemplate, ver.ID, m.vars.Codename, m.vars.Arch)
		if err != nil {
			return err
		}
		cmd, err := BuildRPMInstallLocal(m.vars.ManagerPath, url)
		if err != nil {
			return err
		}
		if err := m.execStep(ctx, ts, step, cmd); err != nil {
			return fmt.Errorf("安装官方源发布包失败: %w", err)
		}
	case OfficialScript:
		url, err := RenderSourceTemplate(o.ScriptURL, ver.ID, m.vars.Codename, m.vars.Arch)
		if err != nil {
			return err
		}
		pipe, err := BuildOfficialScript(m.vars.Tools.Curl, url)
		if err != nil {
			return err
		}
		if err := m.execScript(ctx, ts, step, pipe); err != nil {
			return fmt.Errorf("官方安装脚本执行失败: %w", err)
		}
	case OfficialYumRepo:
		// 公钥先落盘再导入：分两步让"下载失败"与"导入失败"可区分。
		keyPath := o.KeyPath
		if m.yumRepoDir != YumRepoDir() {
			// 测试/隔离环境：把系统路径重定向到临时目录。
			keyPath = filepath.Join(m.yumRepoDir, filepath.Base(keyPath))
		}
		if m.dryRun {
			ts.appendLog(LogWarn, "追加官方源",
				fmt.Sprintf("试运行：将下载并导入公钥 %s 到 %s", o.KeyURL, keyPath))
		} else {
			if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
				return fmt.Errorf("创建公钥目录失败: %w", err)
			}
			if err := m.execStep(ctx, ts, step,
				mustCommand(BuildCurlKeyDownload(m.vars.Tools.Curl, o.KeyURL, keyPath))); err != nil {
				return fmt.Errorf("下载 GPG 公钥失败: %w", err)
			}
			if m.vars.Tools.RPM != "" {
				if err := m.execStep(ctx, ts, step,
					mustCommand(BuildRPMImportKey(m.vars.Tools.RPM, keyPath))); err != nil {
					return fmt.Errorf("导入 GPG 公钥失败: %w", err)
				}
			} else {
				ts.appendLog(LogWarn, "追加官方源", "系统缺少 rpm 命令，跳过公钥导入（签名校验可能失败）")
			}
		}

		content, err := RenderSourceTemplate(o.RepoContentTemplate, ver.ID, m.vars.Codename, m.vars.Arch)
		if err != nil {
			return err
		}
		if err := validRepoContent(content); err != nil {
			return err
		}
		repoFile := o.RepoFile
		if m.yumRepoDir != YumRepoDir() {
			repoFile = filepath.Join(m.yumRepoDir, filepath.Base(repoFile))
		}
		if m.dryRun {
			ts.appendLog(LogWarn, "追加官方源",
				fmt.Sprintf("试运行：将写入仓库配置 %s：%s", repoFile, strings.ReplaceAll(content, "\n", " / ")))
		} else {
			if err := os.MkdirAll(filepath.Dir(repoFile), 0o755); err != nil {
				return fmt.Errorf("创建仓库配置目录失败: %w", err)
			}
			if err := os.WriteFile(repoFile, []byte(content+"\n"), 0o644); err != nil {
				return fmt.Errorf("写入仓库配置 %s 失败: %w", repoFile, err)
			}
			ts.appendLog(LogInfo, "追加官方源", "仓库配置已写入 "+repoFile)
		}
	default:
		return fmt.Errorf("官方源类型 %q 不适用于 rpm", o.Kind)
	}
	cmd := BuildRPMRefresh(m.vars.ManagerPath)
	if err := m.execStep(ctx, ts, step, cmd); err != nil {
		ts.appendLog(LogWarn, "追加官方源", "元数据刷新返回非零，继续尝试安装："+err.Error())
	}
	return nil
}

// aptPackagesReady 判断系统源里是否已有目标版本。
//
// 用 apt-cache policy 查候选版本，再与目标版本比对**版本串前缀**。
// 不查询直接安装是错的：Ubuntu 22.04 的 nodejs 是 12.x，
// 用户选了 22 却会装上 12，而面板会报"安装成功"。
func (m *Manager) aptPackagesReady(ctx context.Context, ts *taskState, step int, pkgs []string, wantVersion string) (bool, string) {
	// ########## 试运行不能"假装探测" ##########
	//
	// 探测靠解析 apt-cache policy 的真实输出。试运行模式下命令
	// 根本不会执行（dryRunExecutor 只回一句 "[dry-run] ..."），
	// 解析结果必然为空 —— 于是每一条策略都被判成"源里没有该版本"，
	// 最后报"所有策略均失败"。
	//
	// 而试运行的用途正是**先看清楚会做什么**：报告一个失败的
	// 探测结果会把用户引向"是不是我的源配错了"，与事实完全相反。
	// 因此试运行下直接认为"可用"，并在日志里说明这是模拟结论。
	if m.dryRun {
		ts.appendLog(LogWarn, "系统源安装",
			fmt.Sprintf("试运行：跳过 %s 的候选版本探测，按「假设源里有 %s」继续推演", pkgs[0], wantVersion))
		// 候选版本返回空串：调用方会因此**不钉版本**，
		// 这正是试运行下唯一诚实的做法 —— 完整版本号只能查源得知。
		return true, ""
	}
	if m.vars.Tools.AptCache == "" {
		ts.appendLog(LogWarn, "系统源安装", "缺少 apt-cache，无法确认版本，直接尝试安装")
		return true, ""
	}
	// 只看第一个包：清单里的同一版本包集合总是同源同版本
	// （php8.3-fpm 与 php8.3-cli 来自同一个 sury 源）。
	cmd, err := BuildAptCandidate(m.vars.Tools.AptCache, pkgs[0])
	if err != nil {
		ts.appendLog(LogWarn, "系统源安装", "版本查询命令组装失败："+err.Error())
		return true, ""
	}
	ts.stepCommand(step, cmd.Redacted)
	res, _ := m.run(ctx, cmd)
	cand := ParseAptPolicyCandidate(res.Stdout)
	ts.appendLog(LogInfo, "系统源安装", fmt.Sprintf("%s 的候选版本：%s", pkgs[0], nonEmpty(cand, "(无)")))
	if cand == "" {
		return false, ""
	}
	// 候选版本原样返回给调用方用于钉版本：它必须与 apt 眼里的
	// 版本字符串**逐字相同**，因此这里不做任何规范化。
	return VersionMatches(cand, wantVersion), cand
}

// rpmPackagesReady 判断 rpm 源里是否已有目标版本。
func (m *Manager) rpmPackagesReady(ctx context.Context, ts *taskState, step int, pkgs []string, wantVersion string) (bool, string) {
	// 同 aptPackagesReady：试运行下不解析不可能的探测输出。
	if m.dryRun {
		ts.appendLog(LogWarn, "系统源安装",
			fmt.Sprintf("试运行：跳过 %s 的可用版本查询，按「假设源里有 %s」继续推演", pkgs[0], wantVersion))
		return true, ""
	}
	cmd, err := BuildRPMAvailable(m.vars.ManagerPath, pkgs[0])
	if err != nil {
		ts.appendLog(LogWarn, "系统源安装", "版本查询命令组装失败："+err.Error())
		return true, ""
	}
	ts.stepCommand(step, cmd.Redacted)
	res, err := m.run(ctx, cmd)
	if err != nil && res.Combined() == "" {
		ts.appendLog(LogWarn, "系统源安装", "可用版本查询失败："+err.Error())
		return false, ""
	}
	versions := ParseRPMAvailable(res.Combined())
	ts.appendLog(LogInfo, "系统源安装",
		fmt.Sprintf("%s 的可用版本：%s", pkgs[0], nonEmpty(strings.Join(versions, ", "), "(无)")))
	for _, v := range versions {
		if VersionMatches(v, wantVersion) {
			return true, v
		}
	}
	return false, ""
}

// runInstallPackages 执行安装命令，并在命令成功后**复验**安装结果。
//
// ########## 为什么必须复验 ##########
//
// `apt-get install` 退出码为 0 只说明"命令没报错"，不说明
// "装上的是我们要的版本"。官方源配置成功但目标版本仍不在源里时，
// apt 可能装上了源里的**另一个**版本（例如 sury 里没有 7.4 时的
// 最新版）。不复验就会把"版本不符"报告成"安装成功"。
func (m *Manager) runInstallPackages(ctx context.Context, ts *taskState, step int, pkgs []string, ver Version) error {
	var cmd Command
	var err error
	switch m.vars.Manager {
	case PackageManagerAPT:
		cmd, err = BuildAptInstall(m.vars.ManagerPath, pkgs)
	default:
		cmd, err = BuildRPMInstall(m.vars.ManagerPath, pkgs)
	}
	if err != nil {
		return err
	}
	// 上报**裸包名**而不是钉版本的 `pkg=ver`：
	// 任务详情与审计记录给用户看的是"装了哪些包"，
	// 而 `nginx=1.26.2-1~jammy` 里的版本号随后续源更新会变，
	// 把它写进审计会让历史记录难以比对。
	ts.setPackages(bareNames(pkgs))
	if err := m.execStep(ctx, ts, step, cmd); err != nil {
		return err
	}

	// 复验：重新查询已安装版本。
	if m.dryRun {
		// 试运行下没有"实际装上的版本"可查，复验必然无法进行。
		// 这里返回 nil 让策略链继续走完并报告"成功（模拟）"：
		// 试运行要回答的是"面板会执行哪些命令"，而不是
		// "这些命令在真实环境下能否成功"（那要真跑才知道）。
		ts.appendLog(LogInfo, "验证", "试运行模式：跳过安装结果复验（不产生任何系统改动）")
		return nil
	}
	// ########## 查询必须用**裸包名** ##########
	//
	// pkgs 可能是钉版本的 `nginx=1.26.2-1~jammy`（apt 的安装语法），
	// 而 dpkg-query/rpm **不接受**这种写法：拿它去查会查不到，
	// 于是"装成功了"被判定为"未检测到已安装的包"，
	// 整条系统源策略被误判为失败并继续往下试官方源——
	// 用户看到的是明明装上了却报失败，还会白写一次系统源配置。
	//
	// 安装用带版本的形式，查询用不带版本的形式，这个区别
	// 必须在**这里**（唯一同时知道两者的地方）消掉。
	queryPkgs := bareNames(pkgs)
	installed := m.queryInstalled(ctx, queryPkgs)
	var got []string
	for _, pkg := range queryPkgs {
		if v, ok := installed[pkg]; ok {
			if VersionMatches(v, ver.ID) {
				return nil
			}
			got = append(got, pkg+"="+v)
		}
	}
	if len(got) == 0 {
		// 包没装上：可能是这组包名不对，换一组试有意义。
		return fmt.Errorf("命令成功但未检测到已安装的包：%s", strings.Join(queryPkgs, ", "))
	}
	// 包装上了但版本不对：**不换包名重试**，如实上报。
	return fmt.Errorf("%w：期望 %s，实际 %s", ErrVersionMismatch, ver.ID, strings.Join(got, ", "))
}

// systemFailureNote 把系统源步骤的失败翻译成给用户看的一句话。
//
// 区分"源里没有这个版本"与"装成了别的版本"：两者的下一步动作
// 完全不同（前者换源，后者要么换源要么接受现有版本）。
func systemFailureNote(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "版本不符") || strings.Contains(msg, "未检测到已安装") {
		return "系统源里有该包，但装上的不是目标版本（" + msg + "）；这通常说明该源只提供其它版本，尝试追加官方源"
	}
	if strings.Contains(msg, "没有版本") || strings.Contains(msg, "中没有版本") {
		return "系统源里没有目标版本（" + msg + "），尝试追加官方源"
	}
	return "系统源安装失败（" + msg + "），尝试追加官方源"
}

// bareNames 去掉 `pkg=version` 里的版本部分。
func bareNames(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		name, _ := splitPinnedName(item)
		out = append(out, name)
	}
	return out
}

// splitPinnedName 拆开 apt 的 `pkg=version`，返回包名与版本。
//
// 不含 = 时版本为空串。放在 store 包里而不是测试里：
// 生产的查询路径也需要它（见 runInstallPackages 的复验）。
func splitPinnedName(item string) (string, string) {
	if i := strings.Index(item, "="); i >= 0 {
		return item[:i], item[i+1:]
	}
	return item, ""
}

// ensureDependencies 确保依赖软件已安装（用默认版本）。
func (m *Manager) ensureDependencies(ctx context.Context, ts *taskState, sw Software, req InstallRequest) error {
	if req.SkipDependencies || len(sw.Depends) == 0 {
		return nil
	}
	order, err := m.cat.DependencyOrder(sw.ID)
	if err != nil {
		return err
	}
	if len(order) == 0 {
		return nil
	}
	for _, depID := range order {
		depSW, ok := m.cat.Get(depID)
		if !ok {
			continue
		}
		installed := m.queryInstalled(ctx, depPackages(depSW))
		if m.anyInstalled(depSW, installed) {
			ts.appendLog(LogInfo, "", fmt.Sprintf("依赖 %s 已安装，跳过", depSW.Name))
			continue
		}
		ts.mu.Lock()
		ts.t.Dependencies = appendUnique(ts.t.Dependencies, depID)
		ts.mu.Unlock()
		ts.appendLog(LogInfo, "", fmt.Sprintf("安装依赖：%s %s", depSW.Name, depSW.DefaultVersion))

		depSWCopy, depVer, ok := m.cat.FindVersion(depID, depSW.DefaultVersion)
		if !ok {
			return fmt.Errorf("依赖 %s 的默认版本 %s 不存在", depID, depSW.DefaultVersion)
		}
		var depErr error
		switch m.vars.Manager {
		case PackageManagerAPT:
			depErr = m.aptInstallFlow(ctx, ts, depSWCopy, depVer)
		default:
			depErr = m.rpmInstallFlow(ctx, ts, depSWCopy, depVer)
		}
		if depErr != nil {
			return fmt.Errorf("依赖 %s 安装失败: %w", depID, depErr)
		}
	}
	return nil
}

// otherInstalledVersions 返回同一软件已安装的**其它**版本。
func (m *Manager) otherInstalledVersions(ctx context.Context, sw Software, version string) []string {
	// 收集所有**其它**版本的包名。
	//
	// 同一软件的多个版本可能是**同一个包名**（nginx 1.26/1.24/1.18
	// 都是包 nginx，靠 `pkg=version` 区分），因此不能靠
	// "包名在不在"来判断装了哪个版本——那会把 nginx 1.18
	// 误判成"1.24 与 1.18 都装着"。
	var installedPkgs []string
	for _, v := range sw.Versions {
		if v.ID == version {
			continue
		}
		installedPkgs = append(installedPkgs, v.SystemPackages...)
		installedPkgs = append(installedPkgs, v.AlternativePackages...)
	}
	installed := m.queryInstalled(ctx, installedPkgs)

	var out []string
	for _, v := range sw.Versions {
		if v.ID == version {
			continue
		}
		for _, pkg := range append(append([]string{}, v.SystemPackages...), v.AlternativePackages...) {
			got, ok := installed[pkg]
			if !ok {
				continue
			}
			// 关键：必须用**实际安装的版本串**去匹配这个版本的
			// 版本号，而不是"包存在就算这个版本装着"。
			// 后者在包名共用时会把所有版本都算上。
			if VersionMatches(got, v.ID) {
				out = appendUnique(out, v.ID)
			}
		}
	}
	sortStrings(out)
	return out
}

// ---------------------------------------------------------------------------
// 卸载执行
// ---------------------------------------------------------------------------

// executeUninstall 执行卸载任务。
func (m *Manager) executeUninstall(ts *taskState, sw Software, versionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), m.taskTime)
	defer cancel()

	ts.markStatus(TaskRunning)
	ts.mu.Lock()
	ts.startedAt = time.Now()
	ts.t.StartedAt = ts.startedAt.Format(time.RFC3339)
	ts.mu.Unlock()
	ts.setProgress(10)

	err := m.uninstallFlow(ctx, ts, sw, versionID)
	if err != nil {
		ts.fail(err, uninstallHint(err))
		m.recordTaskAudit(ts, AuditFailed, err.Error())
		close(ts.done)
		return
	}
	ts.succeed()
	m.recordTaskAudit(ts, AuditAllowed, "")
	close(ts.done)
}

// uninstallFlow 执行卸载。
func (m *Manager) uninstallFlow(ctx context.Context, ts *taskState, sw Software, versionID string) error {
	ts.setStage("检查已安装内容")

	// ---------- 预编译安装 ----------
	if recs := m.prebuiltVersionsOf(sw.ID); len(recs) > 0 {
		step := ts.addStep("prebuilt", "移除预编译安装")
		ts.stepStart(step, "移除预编译安装")
		for _, v := range recs {
			if versionID != "" && v != versionID {
				continue
			}
			rec, ok := m.prebuiltRecordFor(sw.ID, v)
			if !ok {
				continue
			}
			// 先删软链接，再删目录：反过来的话 os.Remove 会
			// 在悬空链接上失败（链接目标已经不存在）。
			for _, bin := range rec.Binaries {
				link := filepath.Join(rec.LinkDir, bin)
				if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
					ts.stepDone(step, false, err.Error())
					return fmt.Errorf("删除软链接 %s 失败: %w", link, err)
				}
			}
			if err := os.RemoveAll(rec.InstallDir); err != nil {
				ts.stepDone(step, false, err.Error())
				return fmt.Errorf("删除安装目录 %s 失败: %w", rec.InstallDir, err)
			}
			ts.appendLog(LogInfo, "移除预编译安装",
				fmt.Sprintf("已删除 %s 及其软链接", rec.InstallDir))
			m.mu.Lock()
			delete(m.prebuilt[sw.ID], v)
			if len(m.prebuilt[sw.ID]) == 0 {
				delete(m.prebuilt, sw.ID)
			}
			m.mu.Unlock()
			ts.setStrategy(StrategyPrebuilt)
		}
		if err := m.savePrebuilt(); err != nil {
			ts.appendLog(LogWarn, "移除预编译安装", "安装记录落盘失败："+err.Error())
		}
		ts.stepDone(step, true, "")
	}

	// ---------- 包管理器卸载 ----------
	// 卸载的包集合：优先用指定版本的包名；未指定版本时，
	// 用**探测到的实际已安装**包名（这样"发行版自带的 nginx 1.18"
	// 也能被正确卸载——它不在我们的版本列表里，但包名是一样的）。
	var pkgs []string
	allPkgs := allPackages(sw)
	installed := m.queryInstalled(ctx, allPkgs)

	// ########## 为什么要按"实际已安装"过滤 ##########
	//
	// 最初这里直接用清单里声明的包名去 remove。问题在于
	// 清单里的包名是**候选名**而不是"这台机器上装了什么"：
	// nginx 1.26 声明了 [nginx1.26, nginx]，但机器上可能一个都没有。
	// 拿着不存在的包名去 `apt-get remove` 有两个后果：
	//   1. 什么都没装时也会真去调包管理器（用户会看到一次无意义的
	//      "卸载成功"或一条 apt 的报错）；
	//   2. apt 对"没有可卸载的包"会返回非 0 退出码，
	//      于是"本来就没装"被报告成"卸载失败"。
	// 因此只对**探测到确实存在**的包动手。
	_ = pkgs
	pkgs = nil
	// 先收指定版本的包名（若确实装着），
	// 再把该软件其它已安装的包一并清掉：否则卸载 php8.3-fpm 之后
	// php8.3-cli 还留着，状态页会继续显示"已安装"。
	if versionID != "" {
		if _, v, ok := m.cat.FindVersion(sw.ID, versionID); ok {
			for _, pkg := range append(append([]string{}, v.SystemPackages...), v.AlternativePackages...) {
				if _, ok := installed[pkg]; ok {
					pkgs = appendUnique(pkgs, pkg)
				}
			}
		}
	}
	for _, pkg := range allPkgs {
		if _, ok := installed[pkg]; ok {
			pkgs = appendUnique(pkgs, pkg)
		}
	}
	if len(pkgs) == 0 {
		if len(m.prebuiltVersionsOf(sw.ID)) == 0 {
			// 什么都没装：这不该被当成失败（用户的意图"让它别装"
			// 已经达成），但必须**如实说明**，不能报"卸载成功"。
			ts.addStep("system", "包管理器卸载")
			ts.stepSkip(0, "未检测到已安装的包")
			ts.appendLog(LogWarn, "", fmt.Sprintf("未检测到 %s 的已安装包，无需卸载", sw.Name))
			ts.setProgress(100)
			return nil
		}
		return nil
	}

	step := ts.addStep("system", "包管理器卸载")
	ts.setStage("卸载软件包")
	ts.setProgress(50)
	ts.stepStart(step, "包管理器卸载")
	ts.setPackages(pkgs)

	var cmd Command
	var err error
	switch m.vars.Manager {
	case PackageManagerAPT:
		cmd, err = BuildAptRemove(m.vars.ManagerPath, pkgs)
	default:
		cmd, err = BuildRPMRemove(m.vars.ManagerPath, pkgs)
	}
	if err != nil {
		ts.stepDone(step, false, err.Error())
		return err
	}
	if err := m.execStep(ctx, ts, step, cmd); err != nil {
		ts.stepDone(step, false, err.Error())
		return err
	}
	ts.setStrategy(StrategySystem)

	// 清理孤儿依赖（apt 专有）。失败不影响卸载结论。
	if m.vars.Manager == PackageManagerAPT && m.vars.Tools.AptGet != "" && !m.dryRun {
		cleanup := BuildAptAutoRemove(m.vars.Tools.AptGet)
		if err := m.execStep(ctx, ts, step, cleanup); err != nil {
			ts.appendLog(LogWarn, "包管理器卸载", "清理孤儿依赖失败（不影响卸载结果）："+err.Error())
		}
	}

	// 复验：确认包真的没了。
	if !m.dryRun {
		after := m.queryInstalled(ctx, pkgs)
		var remain []string
		for _, pkg := range pkgs {
			if _, ok := after[pkg]; ok {
				remain = append(remain, pkg)
			}
		}
		if len(remain) > 0 {
			err := fmt.Errorf("卸载命令成功但以下包仍然存在：%s", strings.Join(remain, ", "))
			ts.stepDone(step, false, err.Error())
			return err
		}
	}
	ts.stepDone(step, true, "")
	ts.setProgress(100)
	ts.appendLog(LogInfo, "", fmt.Sprintf("%s 已卸载：%s", sw.Name, strings.Join(pkgs, ", ")))
	return nil
}

// ---------------------------------------------------------------------------
// 内部工具
// ---------------------------------------------------------------------------

// run 执行一条命令（带单步超时）。
func (m *Manager) run(ctx context.Context, c Command) (ExecResult, error) {
	stepCtx, cancel := context.WithTimeout(ctx, m.stepTime)
	defer cancel()
	return m.exec.Run(stepCtx, c.Name, c.Args)
}

// execStep 执行一条命令并把输出写进任务日志。
func (m *Manager) execStep(ctx context.Context, ts *taskState, step int, c Command) error {
	ts.stepCommand(step, c.Redacted)
	ts.appendLog(LogCommand, ts.stepName(step), "$ "+c.Redacted)

	res, err := m.run(ctx, c)
	m.logCommandOutput(ts, step, res)
	if err != nil {
		// 必须用 %w 保留错误链：上层要靠 errors.Is(err, ErrTimeout)
		// 判断"是超时还是普通失败"。用 %s 拼字符串会把这条信息丢掉，
		// 于是超时被当成"此路不通"继续去试下一条策略 ——
		// 而超时的真实含义是"包管理器可能还在跑，别再抢锁了"。
		if res.ExitCode != 0 {
			return fmt.Errorf("%w（退出码 %d）：%s", err, res.ExitCode, summarize(res.Combined()))
		}
		return fmt.Errorf("%w：%s", err, summarize(res.Combined()))
	}
	return nil
}

// execScript 执行一条脚本管道并把输出写进任务日志。
func (m *Manager) execScript(ctx context.Context, ts *taskState, step int, p ScriptPipeline) error {
	ts.stepCommand(step, p.Redacted)
	ts.appendLog(LogCommand, ts.stepName(step), "$ "+p.Redacted)

	stepCtx, cancel := context.WithTimeout(ctx, m.stepTime)
	defer cancel()
	res, err := m.exec.RunScript(stepCtx, p.Cmd)
	m.logCommandOutput(ts, step, res)
	if err != nil {
		return fmt.Errorf("%w：%s", err, summarize(res.Combined()))
	}
	return nil
}

// logCommandOutput 把命令输出逐行写进任务日志。
func (m *Manager) logCommandOutput(ts *taskState, step int, res ExecResult) {
	name := ts.stepName(step)
	for _, line := range tailLines(res.Stdout, 400) {
		ts.appendLog(LogStdout, name, line)
	}
	for _, line := range tailLines(res.Stderr, 200) {
		ts.appendLog(LogStderr, name, line)
	}
	ts.setOutput(summarize(res.Combined()))
}

// stepName 返回步骤名（越界时为空）。
func (ts *taskState) stepName(idx int) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if idx < 0 || idx >= len(ts.t.Steps) {
		return ""
	}
	return ts.t.Steps[idx].Name
}

// recordTaskAudit 把任务终态写入审计。
//
// ########## 为什么在管理器里写而不是在 server 层 ##########
//
// 安装是异步的：HTTP 请求返回 202 时任务还没结束。
// 若只在 server 层记录"请求被接受"，审计里就永远没有
// "这次安装到底成没成"。因此终态审计由**任务的收尾逻辑**负责——
// 这是唯一知道结果的地方。
func (m *Manager) recordTaskAudit(ts *taskState, outcome, reason string) {
	if m.auditor == nil {
		return
	}
	snap := ts.snapshot()
	action := ActionInstall
	if snap.Kind == TaskUninstall {
		action = ActionUninstall
	}
	status := 200
	if outcome == AuditFailed {
		status = 500
	}
	m.auditor.Record(AuditEvent{
		User:        snap.User,
		Action:      action,
		Target:      snap.Software,
		Version:     snap.Version,
		Required:    RequiredPermission(action),
		Outcome:     outcome,
		Status:      status,
		DurationMS:  snap.DurationMS,
		ClientIP:    snap.ClientIP,
		Reason:      reason,
		TaskID:      snap.ID,
		Strategy:    snap.Strategy,
		Packages:    snap.Packages,
		PrebuiltURL: snap.PrebuiltURL,
		Steps:       ts.summary(),
	})
}

// officialFor 返回某软件在当前家族下的官方源配置。
func (m *Manager) officialFor(sw Software, family string) *OfficialSource {
	if len(sw.Official) == 0 {
		return nil
	}
	if o, ok := sw.Official[family]; ok {
		cp := o
		return &cp
	}
	return nil
}

// officialUnavailableReason 说明官方源为何不可用。
func (m *Manager) officialUnavailableReason() string {
	if m.vars.Codename == "" {
		return "未能识别发行版代号（/etc/os-release 缺少 VERSION_CODENAME），无法安全地追加官方源"
	}
	return "当前环境不支持追加官方源"
}

// familyLabel 把家族名转成人类可读文本。
func familyLabel(family string) string {
	switch family {
	case FamilyDebian:
		return "Debian/Ubuntu"
	case FamilyRHEL:
		return "RHEL/CentOS/Rocky"
	default:
		return "当前发行版"
	}
}

// installHint 给出安装失败后的可操作提示。
func installHint(err error) string {
	switch {
	case errors.Is(err, ErrConflict):
		return "同一软件的多个版本会互相覆盖可执行文件与配置，" +
			"因此需要先卸载已安装的版本。请到列表中点击「卸载」，完成后再安装。"
	case errors.Is(err, ErrTimeout):
		return "命令执行超时。包管理器可能仍在后台运行——请稍后刷新状态，" +
			"确认是否已安装完成，不要立即重试（会与正在运行的 dpkg/rpm 抢锁）。"
	case errors.Is(err, ErrUnavailable):
		return "当前系统没有可用的包管理器，无法安装软件。面板其它功能不受影响。"
	case errors.Is(err, ErrNoStrategy):
		return "系统源、官方源与预编译包三条路径都失败了。" +
			"常见原因：网络不可达、官方源被墙、磁盘空间不足、" +
			"或该版本在你的发行版上确实没有对应产物。" +
			"任务日志里有每一步的完整命令与报错，可据此排查。"
	case errors.Is(err, ErrBusy):
		return "已有任务在执行。apt/dpkg 与 rpm 都有全局锁，并发安装必然互相失败，请等当前任务结束后重试。"
	default:
		return "请展开任务日志查看详细报错；若为网络问题，稍后重试即可。"
	}
}

// uninstallHint 给出卸载失败后的提示。
func uninstallHint(err error) string {
	switch {
	case errors.Is(err, ErrTimeout):
		return "卸载命令超时。请稍后刷新状态确认结果。"
	default:
		return "若有其它进程正在使用该软件（例如正在运行的 php-fpm），" +
			"卸载可能失败；请先停止相关服务后重试。"
	}
}

// summarize 把命令输出压缩成单行摘要（错误信息与前端展示用）。
func summarize(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "(无输出)"
	}
	var lines []string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "(无输出)"
	}
	return truncate(strings.Join(lines, " | "), 1024)
}

// mustCommand 把 (Command, error) 里的错误转为 panic 前的兜底。
//
// 这些构建函数只在参数来自**内置清单**时调用，参数非法属于
// 清单写错（已在解析期拦住）。这里返回一个空命令会让随后的
// 执行直接报"找不到可执行文件"，比 panic 更适合线上；
// 但为了不掩盖构建缺陷，仍然打一条 panic 级别的日志。
func mustCommand(c Command, err error) Command {
	if err != nil {
		// 交给 execStep 去报错（空 Name 会让 exec 立即失败并给出可读信息）。
		return Command{Name: "", Args: nil, Label: "非法命令", Redacted: "（命令组装失败：" + err.Error() + "）"}
	}
	return c
}

// dryRunExecutor 是试运行模式下的执行器：只记录，不执行。
type dryRunExecutor struct {
	logger *slog.Logger
}

func (e dryRunExecutor) Run(_ context.Context, name string, args []string) (ExecResult, error) {
	cmd := RenderCommand(name, args)
	if e.logger != nil {
		e.logger.Info("试运行：跳过命令执行", "command", cmd)
	}
	return ExecResult{Stdout: "[dry-run] " + cmd}, nil
}

func (e dryRunExecutor) RunScript(_ context.Context, cmd string) (ExecResult, error) {
	if e.logger != nil {
		e.logger.Info("试运行：跳过脚本执行", "command", cmd)
	}
	return ExecResult{Stdout: "[dry-run] " + cmd}, nil
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// appendUnique 追加去重（保持顺序）。
func appendUnique(list []string, items ...string) []string {
	for _, it := range items {
		found := false
		for _, ex := range list {
			if ex == it {
				found = true
				break
			}
		}
		if !found {
			list = append(list, it)
		}
	}
	return list
}

// dedupStrings 去重并保持顺序。
func dedupStrings(in []string) []string {
	return appendUnique(nil, in...)
}

// sortStrings 原地排序（升序）。抽出来是为了让"排序意图"显式可见。
func sortStrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// nonEmpty 返回第一个非空字符串。
func nonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstNonEmpty 返回切片里第一个非空元素（空切片时返回 fallback）。
func firstNonEmpty(list []string, fallback string) string {
	for _, v := range list {
		if v != "" {
			return v
		}
	}
	return fallback
}

// versionIDs 返回软件的全部版本 ID。
func versionIDs(sw Software) []string {
	out := make([]string, 0, len(sw.Versions))
	for _, v := range sw.Versions {
		out = append(out, v.ID)
	}
	return out
}

// allPackages 返回软件所有版本涉及的全部包名。
func allPackages(sw Software) []string {
	var out []string
	for _, v := range sw.Versions {
		out = append(out, v.SystemPackages...)
		out = append(out, v.AlternativePackages...)
	}
	return dedupStrings(out)
}

// depPackages 返回某软件全部版本涉及的包名（依赖探测用）。
func depPackages(sw Software) []string { return allPackages(sw) }

// SoftwareIDs 返回清单里全部软件 ID（错误信息里列可用值）。
func (c *Catalog) SoftwareIDs() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Software))
	for _, s := range c.Software {
		out = append(out, s.ID)
	}
	sortStrings(out)
	return out
}
