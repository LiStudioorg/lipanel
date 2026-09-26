// Package service 提供 systemd 服务（unit）的查询与启停能力（阶段四 4.1）。
//
// #################### 安全设计（必读）####################
//
// 本包会以面板进程的权限执行 systemctl，而 systemctl 能启动/停止任意系统服务，
// 属于**敏感命令**。因此这里有双重防线，缺一不可：
//
//	防线一（根除注入）：全程 exec.Command("systemctl", args...) 传 **argv 切片**，
//	                    绝不拼接 shell 字符串，也绝不使用 sh -c。
//	                    参数不经过任何 shell 解析，元字符没有可解释的宿主。
//
//	防线二（收敛输入）：服务名必须通过 [ValidUnitName] 白名单校验。
//	                    防线一已经消除了注入，这一层是为了防止
//	                    「把任意 systemd 参数当服务名传进来」——
//	                    例如名字写成 "--now" 会被 systemctl 当成选项，
//	                    或者名字里带 "/" 去操作任意路径。
//	                    同时一律加 "--" 分隔符，让 - 开头的名字也只当参数。
//
// ##########################################################
package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 操作超时：systemctl start 在服务本身卡住时可能长时间不返回。
//
// 60s 而不是 10s：某些服务（数据库、Web 服务器）的启动脚本
// 确实要等到就绪才返回，超时过短会把「正常但慢」误报成失败。
// 但绝不能不给超时——否则一个卡住的 systemd 会永久占用一个 HTTP 连接。
const DefaultCommandTimeout = 60 * time.Second

// 只读列表命令用的较短超时：list-units 是纯查询，正常在毫秒级返回。
const listCommandTimeout = 15 * time.Second

// unitNamePattern 限定服务名形态。
//
// 依据 systemd 单元名的合法字符集（systemd.unit(5) 允许的字符）：
// 字母、数字、以及 : _ . @ - \ 六种符号。
// 刻意**不接受**空格、斜杠、分号、$、反引号、引号等，
// 它们在 argv 传递下本已无害，但拒绝它们能同时挡住
// 「路径穿越」（.. 与 /）、「选项注入」（名字以 - 开头）与「胡乱输入」。
//
// 长度上限 128：systemd 单元名本身有长度限制，超长名必然是错误输入。
var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+$`)

// MaxUnitNameLen 是服务名长度上限。
const MaxUnitNameLen = 128

// ValidUnitName 判断服务名是否合法。
//
// 注意：这里只做「形态」校验，不代表该服务真实存在
// （存在性由 [Manager.Show] 查 LoadState 判定）。
func ValidUnitName(name string) bool {
	if name == "" || len(name) > MaxUnitNameLen {
		return false
	}
	if !unitNamePattern.MatchString(name) {
		return false
	}
	// 拒绝纯 "." / ".." 与包含 ".." 的名字。
	// 正则允许 "."，因此 "../foo" 已被 "/" 挡住，但 ".." 本身仍会通过，
	// 而 systemd 对它的处理并不明确，直接拒绝最省事。
	if strings.Contains(name, "..") {
		return false
	}
	// 拒绝以 "-" 开头的名字：即使有 "--" 分隔符兜底，
	// 也不该把这种形态当成正常服务名接受。
	if strings.HasPrefix(name, "-") {
		return false
	}
	return true
}

// ServiceState 是服务的运行状态（对 systemd ActiveState 的归一化）。
//
// 归一化的理由：systemd 的 ActiveState 有 active/reloading/activating/
// deactivating/inactive/failed 等取值，前端只需要区分
// 「运行中 / 已停止 / 失败 / 过渡中」四种，多出来的取值让 UI 难以表达。
const (
	// StateRunning 运行中（active 或 reloading）。
	StateRunning = "running"
	// StateStopped 已停止（inactive）。
	StateStopped = "stopped"
	// StateFailed 启动失败（failed）。
	StateFailed = "failed"
	// StateActivating 正在启动或停止（activating/deactivating）。
	StateActivating = "activating"
	// StateUnknown 无法识别的状态。
	StateUnknown = "unknown"
)

// Service 是一个 systemd 服务单元的快照。
type Service struct {
	// Name 是单元名，例如 nginx.service。它是后续操作的唯一标识。
	Name string `json:"name"`
	// LoadState 是 systemd 的加载状态（loaded / not-found / masked ...）。
	LoadState string `json:"load_state"`
	// ActiveState 是 systemd 的原始活动状态（保留原始值便于排查）。
	ActiveState string `json:"active_state"`
	// SubState 是更细的子状态（running / dead / exited / failed ...）。
	// 它比 ActiveState 更有信息量：同是 active，running 与 exited 差别很大。
	SubState string `json:"sub_state"`
	// State 是归一化后的状态，见 StateRunning 等常量，供前端直接使用。
	State string `json:"state"`
	// Description 是单元描述。
	Description string `json:"description"`
	// UnitFileState 是开机自启配置（enabled / disabled / static ...）。
	UnitFileState string `json:"unit_file_state,omitempty"`
}

// Running 表示该服务当前是否处于运行中。
func (s Service) Running() bool { return s.State == StateRunning }

// 错误分类。调用方（server 层）据此映射 HTTP 状态码。
var (
	// ErrSystemdUnavailable 表示系统没有 systemd（未安装 systemctl，
	// 或不是 systemd 作为 PID 1 的环境，例如容器/Alpine/WSL1）。
	ErrSystemdUnavailable = errors.New("service: 系统未提供 systemd")
	// ErrNotFound 表示指定的服务不存在。
	ErrNotFound = errors.New("service: 服务不存在")
	// ErrPermission 表示权限不足（非 root 且无法通过 polkit 认证）。
	ErrPermission = errors.New("service: 权限不足")
	// ErrTimeout 表示命令执行超时。
	ErrTimeout = errors.New("service: 操作超时")
	// ErrInvalidName 表示服务名非法（未通过白名单校验）。
	ErrInvalidName = errors.New("service: 服务名非法")
	// ErrUnsupportedAction 表示不支持的操作。
	ErrUnsupportedAction = errors.New("service: 不支持的操作")
)

// Action 是服务操作类型。
type Action string

// 支持的操作。刻意只提供这三个：
// enable/disable（开机自启）会改变系统的持久状态，风险与能见度都更高，
// 不在 4.1 范围内（计划中亦未要求）。
const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
)

// Valid 判断操作是否受支持。
func (a Action) Valid() bool {
	switch a {
	case ActionStart, ActionStop, ActionRestart:
		return true
	}
	return false
}

// Options 是构造 Manager 的配置。
type Options struct {
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// CommandTimeout 是启停操作的超时；<=0 时用 DefaultCommandTimeout。
	CommandTimeout time.Duration
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// LookPath 用于探测 systemctl 是否可用；为 nil 时用 exec.LookPath。
	// 抽成字段是为了测试能模拟「无 systemd」的环境。
	LookPath func(string) (string, error)
	// Executor 是实际执行 systemctl 的函数；为 nil 时用 exec.CommandContext。
	//
	// 抽出来的唯一目的是**可测**：命令注入这类安全性质必须能用
	// 单测穷举（断言「恶意服务名绝不出现在 argv 里」），
	// 而真实的 systemctl 无法在测试里被安全地调用。
	Executor Executor
}

// Executor 执行一条 systemctl 命令并返回 stdout/stderr。
type Executor interface {
	// Run 执行命令；返回 stdout、stderr 与错误。
	// 约定实现必须带超时，且 ctx 取消时立即返回。
	Run(ctx context.Context, name string, args []string) (stdout string, stderr string, err error)
}

// execExecutor 是默认执行器，基于 os/exec。
//
// 它不是「命令字符串」执行器：name 与 args 分开放，
// 由 exec.CommandContext 直接构造 argv，不经过 shell。
type execExecutor struct{}

func (execExecutor) Run(ctx context.Context, name string, args []string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// LANG/LC_ALL 强制 C：systemctl 的错误信息会被解析
	// （见 classifyError），语言变化会让关键字匹配失效。
	cmd.Env = append(cmd.Environ(), "LANG=C", "LC_ALL=C")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Manager 提供服务查询与管理能力。
type Manager struct {
	logger   *slog.Logger
	timeout  time.Duration
	executor Executor
	lookPath func(string) (string, error)
	auditor  *Auditor

	// systemctlPath 是探测到的 systemctl 绝对路径；为空表示不可用。
	// 启动时探测一次并缓存：既省去每次调用都 LookPath 的开销，
	// 也让「有没有 systemd」这个结论在整个进程生命周期内保持一致。
	systemctlPath string
	// probeErr 记录启动时探测失败的原因，用于给出更准确的提示。
	probeErr error
}

// NewManager 构造服务管理器，并探测 systemd 是否可用。
//
// 探测失败**不返回错误**：没有 systemd 的环境（容器、非 systemd 发行版）
// 依然要能打开面板，只是服务管理页给出明确提示。
// 这正是计划里「无 systemd 时优雅降级并提示」的要求。
func NewManager(opts Options) (*Manager, error) {
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
	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
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
		logger:   logger,
		timeout:  timeout,
		executor: executor,
		lookPath: lookPath,
		auditor:  auditor,
	}

	path, err := lookPath("systemctl")
	if err != nil {
		m.probeErr = err
		logger.Warn("未找到 systemctl，服务管理功能将不可用（面板其它功能不受影响）",
			"err", err,
			"hint", "服务管理需要 systemd 环境；容器内通常不可用")
		return m, nil
	}
	m.systemctlPath = path
	logger.Info("systemd 服务管理已就绪", "systemctl", path, "timeout", timeout)
	return m, nil
}

// Available 表示 systemd 是否可用。
func (m *Manager) Available() bool { return m.systemctlPath != "" }

// UnavailableReason 返回 systemd 不可用的原因（可用时为空）。
func (m *Manager) UnavailableReason() string {
	if m.Available() {
		return ""
	}
	return "系统中未找到 systemctl 命令，服务管理不可用。" +
		"本功能需要 systemd 环境：容器镜像、Alpine、WSL1 等通常不提供 systemd。"
}

// Auditor 返回审计器，供 server 层查询记录与统计。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// run 执行一条 systemctl 命令。
//
// 所有 systemctl 调用都必须经过这里，好处是：
// ① 统一注入 --no-pager（防分页器挂起）、--no-legend、--plain（防 ANSI 控制字符）；
// ② 统一带上超时；
// ③ 统一把「命令不存在」映射成 ErrSystemdUnavailable。
func (m *Manager) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if !m.Available() {
		return "", fmt.Errorf("%w: %s", ErrSystemdUnavailable, m.UnavailableReason())
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 统一前置参数：
	//   --no-pager   ：否则 systemctl 可能把输出交给 less 而永久阻塞；
	//   --no-legend  ：去掉表头与末尾统计行，让解析更简单；
	//   --plain      ：禁用树状/彩色输出，避免 ANSI 转义序列混进 JSON。
	full := append([]string{"--no-pager", "--no-legend", "--plain"}, args...)

	stdout, stderr, err := m.executor.Run(ctx, m.systemctlPath, full)
	if err != nil {
		// 超时要先判断：ctx 超时后 exec 返回的 error 通常是 "signal: killed"，
		// 直接看 errors.Is(err, context.DeadlineExceeded) 未必成立，
		// 因此以 ctx.Err() 为准（它才反映真正的取消原因）。
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return stdout, fmt.Errorf("%w: 命令在 %s 内未返回", ErrTimeout, timeout)
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return stdout, fmt.Errorf("service: 请求已取消: %w", ctx.Err())
		}
		return stdout, classifyError(stderr, err)
	}
	return stdout, nil
}

// classifyError 把 systemctl 的 stderr 翻译成可判定的错误。
//
// 为什么必须分类：面板直接返回 500「内部错误」对用户毫无帮助。
// 「服务不存在」要 404、「权限不足」要 403 并提示用 sudo 运行，
// 这是计划里「不能裸奔报 500」的具体落实。
//
// 匹配的是英文关键字，因为调用方统一注入了 LC_ALL=C。
func classifyError(stderr string, execErr error) error {
	msg := strings.TrimSpace(stderr)
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "not found"),
		strings.Contains(lower, "not loaded"),
		strings.Contains(lower, "no such unit"),
		strings.Contains(lower, "could not be found"):
		return fmt.Errorf("%w: %s", ErrNotFound, firstLine(msg))

	case strings.Contains(lower, "interactive authentication required"),
		strings.Contains(lower, "access denied"),
		strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "authentication is required"),
		strings.Contains(lower, "operation not permitted"):
		return fmt.Errorf("%w: %s", ErrPermission, firstLine(msg))
	}

	if msg == "" {
		// stderr 为空说明是执行层面的错误（二进制被删、权限位异常等），
		// 带上原始 error 才能排查。
		return fmt.Errorf("service: 执行 systemctl 失败: %w", execErr)
	}
	return fmt.Errorf("service: systemctl 执行失败: %s", firstLine(msg))
}

// firstLine 取多行 stderr 的第一行。
//
// systemctl 的权限错误往往附带 "See system logs and ..." 的第二行，
// 那行对用户没有价值，反而让前端提示变得冗长。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// List 返回系统中可供管理的全部服务单元。
//
// 数据来源是**两个** systemctl 查询的并集，这是必须的（实测结论）：
//
//	systemctl list-units      → 只有 systemd **当前已载入内存**的单元。
//	                            它提供最准确的实时状态（active/inactive/failed）。
//	systemctl list-unit-files → 磁盘上**已安装**的全部单元文件，无论是否载入。
//
// 只用 list-units 会有一个严重缺陷（本阶段实测发现）：
// 一个已安装但从未启动过的服务**根本不出现在列表里**，
// 用户因此无法在面板上找到并启动它；更糟的是，
// `systemctl stop` 之后该单元会被 systemd 卸载，于是
// **用户刚在面板上停止的服务会从列表里消失**，看起来像被删除了，
// 也无法再启动。只用 list-unit-files 则拿不到实时状态（它只有 enabled/disabled）。
//
// 因此：以 list-unit-files 为全集，用 list-units 的结果覆盖实时状态。
// 未被载入的单元状态记为 stopped（这正是 systemd 的语义：
// 没载入就意味着没有在运行）。
//
// 排序：按名称升序。systemd 的输出顺序并不稳定，
// 不排序会让前端每次刷新的行序都可能变化，用户会以为列表在跳。
func (m *Manager) List(ctx context.Context) ([]Service, error) {
	// 1. 实时状态（可能不完整，但状态最准）。
	unitsOut, err := m.run(ctx, listCommandTimeout,
		"list-units", "--type=service", "--all", "--full")
	if err != nil {
		return nil, err
	}

	// 2. 已安装的全集（可能不含瞬时状态的细节，但保证不漏单元）。
	filesOut, err := m.run(ctx, listCommandTimeout,
		"list-unit-files", "--type=service", "--full")
	if err != nil {
		return nil, err
	}

	// 以单元名为键合并：先放已安装全集，再用实时状态覆盖。
	byName := make(map[string]Service)
	order := make([]string, 0, 256)

	for _, s := range parseUnitFileList(filesOut) {
		if isInternalUnit(s.Name) {
			continue
		}
		if _, seen := byName[s.Name]; !seen {
			order = append(order, s.Name)
		}
		byName[s.Name] = s
	}

	for _, s := range parseUnitList(unitsOut) {
		if isInternalUnit(s.Name) {
			continue
		}
		if prev, seen := byName[s.Name]; seen {
			// 保留 list-unit-files 提供的 UnitFileState（自启配置），
			// 用实时状态覆盖运行状态。
			s.UnitFileState = prev.UnitFileState
			byName[s.Name] = s
			continue
		}
		order = append(order, s.Name)
		byName[s.Name] = s
	}

	// 3. 收集并按名称排序。
	filtered := make([]Service, 0, len(order))
	for _, name := range order {
		filtered = append(filtered, byName[name])
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Name < filtered[j].Name })
	return filtered, nil
}

// parseUnitFileList 解析 systemctl list-unit-files 的输出。
//
// 格式固定为三列：UNIT  STATE  PRESET（实测 221 个单元全部是 3 列）。
// STATE 是开机自启配置（enabled/disabled/static/generated/masked），
// 与「当前是否在运行」无关，因此状态先记为 stopped——
// 若该单元真的在运行，list-units 的结果会把它覆盖掉。
func parseUnitFileList(out string) []Service {
	var services []Service
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 2 {
			continue
		}
		name, unitFileState := fields[0], fields[1]
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		services = append(services, Service{
			Name:          name,
			LoadState:     "loaded",
			ActiveState:   "inactive",
			SubState:      "dead",
			State:         StateStopped,
			UnitFileState: unitFileState,
		})
	}
	return services
}

// parseUnitList 解析 systemctl list-units 的列对齐输出。
//
// 为什么不用 `--output=json`：JSON 输出依赖 systemd 249+ 的完整实现，
// 且不同发行版字段名有差异；而列对齐输出自 systemd 早期版本就稳定存在
// （实测本机格式为「UNIT LOAD ACTIVE SUB DESCRIPTION」，用空格对齐，
// 前四列不含空格，DESCRIPTION 可含空格）。
//
// 解析策略：每行按「连续空格」切分，前四段固定为固定字段，
// 第五段起（可能被 systemd 截断/补多空格）整体作为描述。
// 少于四段的行（空行、异常输出）一律跳过而不是报错——
// 一个畸形行不该让整个服务列表打不开。
func parseUnitList(out string) []Service {
	var services []Service
	scanner := bufio.NewScanner(strings.NewReader(out))
	// 描述可能很长，放宽单行上限（默认 64KB 已足够，这里显式声明意图）。
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name, load, active, sub := fields[0], fields[1], fields[2], fields[3]
		// 只接受以 .service 结尾的单元：--type=service 理论上已保证，
		// 但显式校验能挡住「systemd 版本行为差异」带来的意外输入。
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		services = append(services, Service{
			Name:        name,
			LoadState:   load,
			ActiveState: active,
			SubState:    sub,
			State:       normalizeState(active, sub),
			Description: strings.Join(fields[4:], " "),
		})
	}
	return services
}

// normalizeState 把 systemd 的 ActiveState/SubState 归一化为前端可用的状态。
func normalizeState(active, sub string) string {
	switch active {
	case "active", "reloading":
		return StateRunning
	case "inactive":
		return StateStopped
	case "failed":
		return StateFailed
	case "activating", "deactivating":
		return StateActivating
	case "":
		// 极少数情况下 ActiveState 为空，退回用 SubState 判断。
		if sub == "dead" {
			return StateStopped
		}
		return StateUnknown
	default:
		return StateUnknown
	}
}

// internalUnitPrefixes 是需要从面板隐藏的内部服务前缀。
//
// 判断依据是「用户不该也不需要在面板里手动启停它们」：
//   - systemd-*：systemd 自身的内部单元，停了会导致系统异常；
//   - user@*/user-runtime-dir@*：每个登录会话的管理器；
//   - *@systemd-*：模板实例化的内部单元。
var internalUnitPrefixes = []string{
	"systemd-",
	"user@",
	"user-runtime-dir@",
	"dbus-",
}

// internalUnitExact 是完全隐藏的内部单元名。
var internalUnitExact = map[string]bool{
	"dbus.service": true,
}

// internalUnitSuffixes 是隐藏的后缀（阶段目标：过滤掉内部服务）。
var internalUnitSuffixes = []string{
	".slice",
	".scope",
	".mount",
	".socket",
	".target",
	".timer",
	".path",
	".device",
}

// isInternalUnit 判断是否是需要从列表中过滤掉的内部服务。
//
// 设计取舍：过滤是**展示层**的便利，不是安全机制。
// 被过滤的服务依然可以被 API 直接操作（只要名字合法且存在），
// 因为「隐藏」与「禁止」是两件事——把它们混为一谈会让人误以为
// 过滤等于保护，而真正的保护是权限校验。
func isInternalUnit(name string) bool {
	if internalUnitExact[name] {
		return true
	}
	for _, p := range internalUnitPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, s := range internalUnitSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// Show 查询单个服务的详情，使用只读查询的短超时。
//
// 用 `systemctl show -p ...` 而不是 list-units：
// 后者对不存在的服务**返回空输出且退出码为 0**（实测 systemd 249），
// 无法据此判断存在性；而 show 会明确给出 LoadState=not-found。
func (m *Manager) Show(ctx context.Context, name string) (Service, error) {
	return m.showWithTimeout(ctx, name, listCommandTimeout)
}

// showWithTimeout 是 Show 的内部实现，允许调用方指定超时。
//
// 为什么需要它：Do 在真正执行操作前会用 Show 检查存在性、
// 执行后又用 Show 回读状态，这两次查询属于「操作的一部分」，
// 应当遵循调用方配置的操作超时（-service-timeout），
// 而不是只读列表的固定短超时。
// 早期版本让 Do 复用 Show 的短超时，导致配置的超时对这两次查询无效
// （实测：配置 50ms 时整体仍耗时 15s）——这是被 TestCommandTimeout 抓出来的。
func (m *Manager) showWithTimeout(ctx context.Context, name string, timeout time.Duration) (Service, error) {
	if !ValidUnitName(name) {
		return Service{}, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}

	out, err := m.run(ctx, timeout, "show",
		"-p", "LoadState",
		"-p", "ActiveState",
		"-p", "SubState",
		"-p", "Description",
		"-p", "UnitFileState",
		// "--" 让后续内容只被当作参数，即使名字以 - 开头。
		"--", name)
	if err != nil {
		return Service{}, err
	}

	svc := Service{Name: name}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState":
			svc.LoadState = value
		case "ActiveState":
			svc.ActiveState = value
		case "SubState":
			svc.SubState = value
		case "Description":
			svc.Description = value
		case "UnitFileState":
			svc.UnitFileState = value
		}
	}

	// LoadState=not-found 才是「服务不存在」的权威判据。
	if svc.LoadState == "not-found" {
		return svc, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	svc.State = normalizeState(svc.ActiveState, svc.SubState)
	return svc, nil
}

// Do 对指定服务执行 start/stop/restart。
//
// 返回执行后的最新服务状态：前端拿到即可直接更新列表行，
// 无需再发一次查询（也避免了「操作成功但列表还是旧状态」的观感问题）。
func (m *Manager) Do(ctx context.Context, action Action, name string) (Service, error) {
	if !action.Valid() {
		return Service{}, fmt.Errorf("%w: %q", ErrUnsupportedAction, string(action))
	}
	if !ValidUnitName(name) {
		return Service{}, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}

	// 先确认服务存在：这样「服务名写错」能稳定返回 404，
	// 而不是把 systemctl 的 "Unit not found" 也当成 404 之外的意外。
	// 更重要的是：提前失败可以让审计记录里出现一条语义明确的 404。
	if _, err := m.showWithTimeout(ctx, name, m.timeout); err != nil {
		return Service{}, err
	}

	// 核心调用：argv 切片，且带 "--" 分隔符。
	if _, err := m.run(ctx, m.timeout, string(action), "--", name); err != nil {
		return Service{}, err
	}

	// 回读真实状态：systemctl 返回 0 只代表「命令被接受」，
	// 服务是否真的起来了要以 ActiveState 为准。
	// 例如 `systemctl start` 一个立即退出的 oneshot 服务，
	// 命令成功但 ActiveState=inactive，此时如实展示比伪造「运行中」更可信。
	svc, err := m.showWithTimeout(ctx, name, m.timeout)
	if err != nil {
		return Service{}, err
	}
	return svc, nil
}

// RunningCount 统计列表中运行中的服务数量。
func RunningCount(list []Service) int {
	n := 0
	for _, s := range list {
		if s.Running() {
			n++
		}
	}
	return n
}

// parseBool 把 systemd 的 yes/no 转成 bool（当前仅测试使用）。
func parseBool(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}
