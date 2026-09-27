package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PluginSubcommandPrefix 是内置插件子命令的前缀。
//
// 主程序启动时检查 os.Args[1]：若形如 "__plugin_sysinfo"，
// 则不启动 HTTP 面板，而是以插件身份运行（见根目录 main.go）。
// 之所以用双下划线前缀，是为了和正常 CLI 参数（-addr 等）绝对不会冲突。
const PluginSubcommandPrefix = "__plugin_"

// Options 是构造 Manager 的配置。
type Options struct {
	// SocketDir 是插件 Unix socket 的存放目录，必须仅属主可访问。
	// 为空时使用默认的 <os.TempDir()>/lipanel-plugins。
	SocketDir string
	// ExecutablePath 是主程序自身可执行文件路径，用于拉起内置插件。
	// 为空时由 os.Executable() 推断（go run 场景下指向临时二进制，同样可用）。
	ExecutablePath string
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// StartTimeout / StopTimeout / RequestTimeout 为 0 时使用包内默认值。
	StartTimeout   time.Duration
	StopTimeout    time.Duration
	RequestTimeout time.Duration
	// DisableWatcher 为 true 时不自动监测插件崩溃。
	// 仅供测试使用（避免测试进程被异步回调干扰）。
	DisableWatcher bool
	// Audit 为 nil 时新建一个仅内存的审计器（容量 DefaultAuditCapacity）。
	// 由 main 注入以支持 -audit-log 落盘；测试可注入自定义实例以断言记录内容。
	Audit *Auditor
	// PluginDir 是外部插件目录，由 -plugin-dir 指定。
	//
	// 为空表示不启用外部插件：扫描直接返回空结果，
	// 安装接口返回明确的错误（而不是写到一个猜出来的默认路径）。
	PluginDir string
}

// entry 是注册表中一个插件条目的运行时记录。
type entry struct {
	desc Descriptor
	// sockPath 是该插件监听的 socket 路径（托管与外部模式共用）。
	sockPath string
	// perms 是解析后的权限集合（注册时解析一次，运行期直接复用）。
	perms PermissionSet
	// proc 仅在 managed 模式下非 nil。
	proc *process

	state     string
	pid       int
	startedAt time.Time
	restarts  int
	lastError string
	healthy   *bool

	// intendedRunning 记录「用户希望它运行」。
	// 用于区分「用户主动停止」与「插件自己崩溃」：
	// 前者不应被自动拉起，后者需要标记为 failed 并允许重启。
	intendedRunning bool
}

// Manager 负责插件的注册、启动、停止与状态查询。
//
// 并发模型：单把互斥锁保护整个注册表。
// 插件操作是低频的管理动作（人手点击），不是高并发热路径，
// 因此不做细粒度分片——简单且不会出错，比性能更重要。
// 注意：任何可能阻塞的操作（等待进程退出）都不能在持锁期间做，
// 否则会卡住所有插件的状态查询接口。
type Manager struct {
	opts     Options
	logger   *slog.Logger
	sockDir  string
	binPath  string
	audit    *Auditor
	mu       sync.RWMutex
	registry map[string]*entry
	// order 保留注册顺序，让 /api/plugins 的列表稳定可预期
	// （map 遍历顺序随机，直接返回会导致前端菜单每次刷新都换位置）。
	order []string
}

// NewManager 构造插件管理器。
func NewManager(opts Options) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if opts.SocketDir == "" {
		opts.SocketDir = filepath.Join(os.TempDir(), "lipanel-plugins")
	}
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = DefaultStartTimeout
	}
	if opts.StopTimeout <= 0 {
		opts.StopTimeout = DefaultStopTimeout
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = DefaultRequestTimeout
	}

	binPath := opts.ExecutablePath
	if binPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("plugin: 无法定位自身可执行文件（拉起内置插件需要）: %w", err)
		}
		binPath = exe
	}

	// socket 目录必须提前建好：既是为了让插件能 bind，
	// 也是为了尽早暴露「目录不可写」这类部署问题。
	if err := os.MkdirAll(opts.SocketDir, socketDirPerm); err != nil {
		return nil, fmt.Errorf("plugin: 创建 socket 目录 %s 失败: %w", opts.SocketDir, err)
	}
	if err := os.Chmod(opts.SocketDir, socketDirPerm); err != nil {
		logger.Warn("收紧 socket 目录权限失败", "dir", opts.SocketDir, "err", err)
	}

	// 审计器：未注入时建一个纯内存的。
	// 这里用内存兜底而不是 nil，是为了让权限拒绝这类事件**永远有记录**——
	// 一个"没有审计"的默认状态会让排查越权问题时两手空空。
	auditor := opts.Audit
	if auditor == nil {
		var err error
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("plugin: 初始化审计器失败: %w", err)
		}
	}

	return &Manager{
		opts:     opts,
		logger:   logger,
		sockDir:  opts.SocketDir,
		binPath:  binPath,
		audit:    auditor,
		registry: make(map[string]*entry),
	}, nil
}

// Audit 返回审计器，供 server 层查询记录与统计。
// 永不返回 nil（NewManager 保证）。
func (m *Manager) Audit() *Auditor { return m.audit }

// Close 释放审计器持有的文件句柄。
// 由 main 在退出时调用；重复调用幂等。
func (m *Manager) Close() error {
	return m.audit.Close()
}

// SocketDir 返回 socket 目录，便于日志与测试断言。
func (m *Manager) SocketDir() string { return m.sockDir }

// ExternalDir 返回外部插件目录（install 接口的落点）。
//
// 与 SocketDir 同样只读：目录由 main 通过 -plugin-dir 指定，
// 运行期不允许改变（改了就意味着一部分插件在旧目录、
// 一部分在新目录，注册表与实际磁盘会对不上）。
func (m *Manager) ExternalDir() string { return m.opts.PluginDir }

// RequestTimeout 返回转发请求的超时上限。
func (m *Manager) RequestTimeout() time.Duration { return m.opts.RequestTimeout }

// Register 注册一个插件描述符。ID 重复或描述符非法都会返回错误，
// 且在启动阶段就报错——一个写错的插件不该等到被点击时才暴露问题。
func (m *Manager) Register(desc Descriptor) error {
	if err := desc.Validate(); err != nil {
		return err
	}

	// 注册时解析一次权限，运行期拦截直接复用解析结果。
	// 解析失败已在 Validate 中拦截过，这里的错误是理论上的兜底。
	perms, err := ParsePermissions(desc.Permissions)
	if err != nil {
		return fmt.Errorf("plugin: %s 的权限声明非法: %w", desc.ID, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.registry[desc.ID]; exists {
		return fmt.Errorf("plugin: 插件 ID %q 已注册，不能重复注册", desc.ID)
	}

	e := &entry{
		desc:     desc,
		sockPath: filepath.Join(m.sockDir, desc.ID+".sock"),
		perms:    perms,
		state:    StateStopped,
	}
	if desc.Mode == ModeManaged {
		e.proc = newProcess(desc, e.sockPath, m.logger)

		// ########## 外部插件的可执行文件在这里绑定 ##########
		//
		// 内置插件留空 execPath，走"主程序自身 + __plugin_<id> 子命令"。
		// 外部插件带上自己的二进制路径与参数，由 process.Start 分支处理。
		//
		// 之所以在**注册时**就算好路径（而不是启动时现算）：
		// 注册发生在启动扫描阶段，此时任何路径问题都能立刻
		// 变成一条加载失败记录；而启动是用户手动触发的，
		// 那时报错只能让用户重试，体验更差。
		if desc.External {
			e.proc.execPath = m.externalExecPath(&desc)
			e.proc.execArgs = m.externalArgs(&desc)
		}
	}
	m.registry[desc.ID] = e
	m.order = append(m.order, desc.ID)

	m.logger.Info("插件已注册",
		"plugin", desc.ID, "name", desc.Name, "version", desc.Version, "mode", desc.Mode,
		"permissions", perms.Strings(), "permission_count", perms.Len())

	// 注册即记录一条审计：插件的权限清单是安全审计的重要上下文，
	// 事后排查「它当初声明了什么」必须有据可查。
	m.audit.Record(AuditEvent{
		Plugin:  desc.ID,
		Method:  "REGISTER",
		Path:    "-",
		Granted: perms.Strings(),
		Outcome: AuditAllowed,
		Status:  0,
		Reason:  fmt.Sprintf("插件注册，声明权限 %d 条", perms.Len()),
	})

	return nil
}

// Permissions 返回指定插件已解析的权限声明。
func (m *Manager) Permissions(id string) ([]Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.registry[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return e.perms.List(), nil
}

// CheckAccess 校验某插件是否可以访问指定子路径，**并记录审计**。
//
// 这是权限体系的唯一入口：Proxy 转发前调用它，返回 denied 时请求
// 不会被转发给插件进程。把「校验 + 审计」放在同一个方法里，
// 是为了从结构上保证「不会有绕过审计的校验」与「不会有没校验的转发」。
//
// 参数 clientIP 只用于审计记录（谁点的这一下）。
func (m *Manager) CheckAccess(id, method, subPath, clientIP string) (PermissionDecision, PermissionSet) {
	m.mu.RLock()
	e, ok := m.registry[id]
	var perms PermissionSet
	if ok {
		perms = e.perms
	}
	m.mu.RUnlock()

	if !ok {
		// 插件不存在：交给上层返回 404，这里不记审计
		// （否则一个扫描器就能把审计缓冲刷满）。
		return PermissionDecision{Allowed: false, Reason: "插件不存在: " + id}, perms
	}

	dec := CheckPermission(id, perms, method, subPath)
	if dec.Allowed {
		// 放行的请求不在这里记审计：转发完成后才知道最终结果
		// （200 还是 502 是两回事），由 Proxy 在收尾时补记。
		return dec, perms
	}

	m.logger.Warn("插件权限校验未通过，请求已被拒绝",
		"plugin", id, "method", method, "path", subPath,
		"required", dec.Required, "granted", perms.Strings())

	m.audit.Record(AuditEvent{
		Plugin:   id,
		Method:   method,
		Path:     subPath,
		Required: dec.Required,
		Granted:  perms.Strings(),
		Outcome:  AuditDenied,
		Status:   403,
		ClientIP: clientIP,
		Reason:   dec.Reason,
	})
	return dec, perms
}

// RecordAccess 记录一条已放行（或转发失败）的审计记录。
//
// 由 Proxy 在转发收尾时调用：此时才知道真实状态码与耗时。
func (m *Manager) RecordAccess(ev AuditEvent) {
	if ev.Granted == nil {
		if perms, err := m.Permissions(ev.Plugin); err == nil {
			ev.Granted = make([]string, 0, len(perms))
			for _, p := range perms {
				ev.Granted = append(ev.Granted, p.Raw)
			}
		}
	}
	m.audit.Record(ev)
}

// List 返回所有插件的状态快照，顺序与注册顺序一致。
func (m *Manager) List() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Status, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.snapshotLocked(m.registry[id]))
	}
	return out
}

// Get 返回指定插件的状态快照。
func (m *Manager) Get(id string) (Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.registry[id]
	if !ok {
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return m.snapshotLocked(e), nil
}

// snapshotLocked 构造状态快照，把内部记录翻译成对外的 Status。
func (m *Manager) snapshotLocked(e *entry) Status {
	if e == nil {
		return Status{}
	}

	st := Status{
		Descriptor: e.desc,
		State:      e.state,
		PID:        e.pid,
		SocketPath: e.sockPath,
		Restarts:   e.restarts,
		LastError:  e.lastError,
		Healthy:    e.healthy,
	}
	if !e.startedAt.IsZero() {
		st.StartedAt = e.startedAt.Format(time.RFC3339)
		if e.state == StateRunning {
			st.UptimeSeconds = int64(time.Since(e.startedAt).Seconds())
		}
	}
	return st
}

// Start 启动指定插件。
//
// 锁策略：拨号与等待 socket 就绪可能耗时（最长 StartTimeout），
// 因此先在锁内完成状态检查与进程拉起，再在锁外等待就绪。
// 否则一个插件的启动会冻结整个面板的插件列表接口。
func (m *Manager) Start(ctx context.Context, id string) (Status, error) {
	m.mu.Lock()
	e, ok := m.registry[id]
	if !ok {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if e.state == StateRunning {
		st := m.snapshotLocked(e)
		m.mu.Unlock()
		return st, fmt.Errorf("%w: %s", ErrAlreadyRunning, id)
	}

	switch e.desc.Mode {
	case ModeExternal:
		// 外部模式：核心不拉起进程，只标记「期望运行」，由 Dial 时按需连接。
		e.intendedRunning = true
		e.state = StateRunning
		e.lastError = ""
		e.startedAt = time.Now()
		st := m.snapshotLocked(e)
		m.mu.Unlock()

		m.logger.Info("外部托管插件已标记为启用", "plugin", id, "socket", e.sockPath)
		return st, nil

	case ModeManaged:
		e.intendedRunning = true
		e.lastError = ""
		// 进程拉起本身很快（fork/exec 立即返回），但这里会进入 waitReady 阻塞，
		// 因此把 proc.Start 放到锁外执行由调用方完成。
	default:
		m.mu.Unlock()
		return Status{}, fmt.Errorf("plugin: 插件 %s 的 Mode = %q 非法", id, e.desc.Mode)
	}

	proc := e.proc
	prevRestarts := e.restarts
	m.mu.Unlock()

	// 锁外执行：等待 socket 就绪最长可达 StartTimeout。
	// res 是不可变快照，后续据此写状态，避免跨 goroutine 读进程字段。
	res, err := proc.Start(ctx, m.binPath, m.pluginEnv(e.desc))
	if err != nil {
		m.mu.Lock()
		e.state = StateFailed
		e.lastError = err.Error()
		e.intendedRunning = false
		m.mu.Unlock()
		return Status{}, err
	}

	m.mu.Lock()
	e.state = StateRunning
	e.pid = res.PID
	e.startedAt = res.StartedAt
	// 首次启动不算重启，只有「停止后再启动」才计入。
	if prevRestarts > 0 || e.restarts > 0 {
		e.restarts++
	}
	st := m.snapshotLocked(e)
	m.mu.Unlock()

	if !m.opts.DisableWatcher {
		proc.crashWatcher(m.onProcessExit)
	}

	m.logger.Info("插件已启动", "plugin", id, "pid", st.PID)
	return st, nil
}

// Stop 停止指定插件。
//
// 同样采用「锁内改状态 → 锁外等进程退出」的顺序：
// 先把 intendedRunning 置 false，这样崩溃回调不会把它误判为异常退出。
func (m *Manager) Stop(id string) (Status, error) {
	m.mu.Lock()
	e, ok := m.registry[id]
	if !ok {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}

	e.intendedRunning = false

	if e.desc.Mode == ModeExternal {
		// 外部模式的进程不归核心管，核心只能「不再拨号」。
		// 这里明确告知调用方，而不是假装已经停掉了别人的进程。
		e.state = StateStopped
		e.startedAt = time.Time{}
		e.healthy = nil
		st := m.snapshotLocked(e)
		m.mu.Unlock()
		return st, fmt.Errorf("%w: 插件 %s 由外部进程管理器托管，核心已停止向其转发请求，但不会结束该进程",
			ErrUnsupported, id)
	}

	if e.state != StateRunning || e.proc == nil {
		// 已经是停止状态：幂等返回，不报错（重复点击「停止」不该是错误）。
		e.state = StateStopped
		e.pid = 0
		e.startedAt = time.Time{}
		e.healthy = nil
		st := m.snapshotLocked(e)
		m.mu.Unlock()
		return st, nil
	}

	proc := e.proc
	m.mu.Unlock()

	// 锁外执行：等待进程退出最多 StopTimeout。
	err := proc.Stop(m.opts.StopTimeout)

	m.mu.Lock()
	e.state = StateStopped
	e.pid = 0
	e.startedAt = time.Time{}
	e.healthy = nil
	if err != nil {
		e.state = StateFailed
		e.lastError = err.Error()
	}
	st := m.snapshotLocked(e)
	m.mu.Unlock()

	if err != nil {
		return st, err
	}
	m.logger.Info("插件已停止", "plugin", id)
	return st, nil
}

// Restart 重启插件（先停后启）。
func (m *Manager) Restart(ctx context.Context, id string) (Status, error) {
	if _, err := m.Stop(id); err != nil && !errors.Is(err, ErrUnsupported) {
		return Status{}, err
	}
	return m.Start(ctx, id)
}

// Dial 拨号到指定插件的 socket，供健康探测等内部用途使用。
// 返回的 net.Conn 由调用方负责关闭。
//
// 这里做一次状态校验：未运行或未启用的插件直接拒绝，
// 免得到处对着一个不存在的 socket 反复连接失败、把错误信息搞得很含糊。
// 注意：HTTP 转发走的不是这个函数，而是 Proxy（它需要按请求动态决定 socket）。
func (m *Manager) Dial(ctx context.Context, id string) (net.Conn, error) {
	m.mu.RLock()
	e, ok := m.registry[id]
	if !ok {
		m.mu.RUnlock()
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if !e.intendedRunning && e.state != StateRunning {
		m.mu.RUnlock()
		return nil, fmt.Errorf("%w: %s", ErrNotRunning, id)
	}
	proc := e.proc
	sockPath := e.sockPath
	m.mu.RUnlock()

	// 托管模式下走 process.Dial（带进程存活语义）；
	// 外部模式直接拨号，socket 存在与否由插件自己负责。
	if proc != nil && proc.alive() {
		return proc.Dial(ctx)
	}
	return dialUnix(ctx, sockPath)
}

// onProcessExit 是插件进程退出时的回调（由 crashWatcher 异步触发）。
//
// 关键语义：只有「用户希望它运行」却退出了，才算崩溃；
// 用户主动 Stop 时 intendedRunning 已提前置 false，此处会安静地跳过。
func (m *Manager) onProcessExit(id string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.registry[id]
	if !ok {
		return
	}
	if !e.intendedRunning {
		return // 用户主动停止，正常流程，无需告警。
	}
	if e.state != StateRunning {
		return // 已被 Stop 处理过，避免重复置错。
	}

	e.state = StateFailed
	e.pid = 0
	e.startedAt = time.Time{}
	e.restarts++
	e.healthy = nil
	e.lastError = fmt.Sprintf("插件进程意外退出: %v", err)
	e.intendedRunning = false

	m.logger.Error("插件进程意外退出", "plugin", id, "err", err, "restarts", e.restarts)
}

// Shutdown 停止所有由核心托管的插件进程。
// 由 main 在收到退出信号后调用，避免主程序退出却留下孤儿插件进程。
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("正在停止所有插件进程")

	m.mu.RLock()
	ids := make([]string, 0, len(m.order))
	for _, id := range m.order {
		if e := m.registry[id]; e != nil && e.desc.Mode == ModeManaged && e.state == StateRunning {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()

	var errs []error
	for _, id := range ids {
		select {
		case <-ctx.Done():
			// 关闭超时：尽力而为，不能因为插件拖住面板退出。
			errs = append(errs, fmt.Errorf("plugin: 停止插件 %s 被取消: %w", id, ctx.Err()))
			return errors.Join(errs...)
		default:
		}
		if _, err := m.Stop(id); err != nil {
			errs = append(errs, fmt.Errorf("plugin: 停止插件 %s 失败: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// pluginEnv 构造传给插件进程的环境变量。
// 插件是独立进程，必须由核心显式告知它「听哪个 socket」。
func (m *Manager) pluginEnv(desc Descriptor) []string {
	sock := filepath.Join(m.sockDir, desc.ID+".sock")
	return []string{
		strings.Join([]string{EnvSocketPath, sock}, "="),
		strings.Join([]string{EnvPluginID, desc.ID}, "="),
	}
}

// 插件进程通过这两个环境变量得知自己的身份与监听地址。
const (
	// EnvSocketPath 指定插件要监听的 Unix socket 路径。
	EnvSocketPath = "LIPANEL_PLUGIN_SOCKET"
	// EnvPluginID 指定插件 ID。
	EnvPluginID = "LIPANEL_PLUGIN_ID"
)

// Health 主动探测插件健康状态并记录到状态里。
//
// 探测方式是向插件的 /healthz 发一个 HEAD 请求——
// 这是约定接口，由插件骨架（见 plugin.Serve）自动提供，
// 插件作者无需自己实现。
func (m *Manager) Health(ctx context.Context, id string) (Status, error) {
	m.mu.RLock()
	e, ok := m.registry[id]
	if !ok {
		m.mu.RUnlock()
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	running := e.state == StateRunning
	m.mu.RUnlock()

	if !running {
		return Status{}, fmt.Errorf("%w: %s", ErrNotRunning, id)
	}

	conn, err := m.Dial(ctx, id)
	healthy := err == nil
	if conn != nil {
		_ = conn.Close()
	}

	m.mu.Lock()
	if e2, ok := m.registry[id]; ok {
		e2.healthy = &healthy
		if !healthy && err != nil {
			e2.lastError = err.Error()
		}
	}
	st := m.snapshotLocked(m.registry[id])
	m.mu.Unlock()

	if err != nil {
		return st, err
	}
	return st, nil
}
