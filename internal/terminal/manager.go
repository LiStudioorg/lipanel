package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// 会话管理器（阶段五 5.1）
// ============================================================================

// 默认配置值。
const (
	// DefaultIdleTimeout 是默认空闲超时（计划要求 30 分钟）。
	DefaultIdleTimeout = 30 * time.Minute

	// DefaultMaxSessions 是同时存在的会话数上限。
	//
	// ########## 为什么必须有一个上限 ##########
	//
	// 每个会话 = 一个 shell 进程 + 一个 PTY + 一个读泵 goroutine。
	// 没有上限的话，一个用户（或一段恶意脚本）在循环里
	// POST /api/terminal/sessions 就能把机器的进程表与内存耗尽——
	// 而终端接口是需要登录的，所以这不是"防外人"而是
	// "防已登录用户的误操作把机器搞挂"。
	//
	// 取 10：真实运维场景下一个人同时开 10 个终端已经很夸张，
	// 而 10 个 shell 的资源占用对服务器完全可忽略。
	DefaultMaxSessions = 10

	// DefaultShutdownGrace 是面板关停时等待会话收尾的时间。
	//
	// 比 4.5 商店的 15m 短得多：终端里跑的东西（比如一个
	// 交互式 shell）**没有**"必须等它跑完"的半完成状态。
	// 用户正在 apt install 的话，那个进程由 PTY 的 SIGHUP
	// 处理，不需要面板等。因此这里只需要给
	// "发 close 帧 + 记录审计"留出时间。
	DefaultShutdownGrace = 5 * time.Second
)

// ManagerOptions 是构造会话管理器的配置。
type ManagerOptions struct {
	// Shell 是显式配置的 shell 路径；为空则按回退链解析。
	Shell string
	// ShellArgs 是传给 shell 的附加参数。
	ShellArgs []string
	// IdleTimeout 是空闲超时；<=0 表示不超时。
	//
	// 注意区分「未设置」与「显式关闭」：本字段是 time.Duration，
	// 零值语义为"用默认值"。要真正关闭超时必须显式传负数。
	IdleTimeout time.Duration
	// MaxSessions 是会话数上限；<=0 时用 DefaultMaxSessions。
	MaxSessions int
	// WorkDir 是终端初始工作目录。
	WorkDir string
	// AllowedOrigins 是允许的 WebSocket Origin 白名单。
	//
	// ########## 为什么 WebSocket 需要额外的 Origin 校验 ##########
	//
	// WebSocket **不受同源策略约束**：浏览器允许任意源的 JS
	// 发起 WebSocket 连接，并且**会自动携带目标域的 Cookie**。
	// 这就是 CSWSH（Cross-Site WebSocket Hijacking）：
	// 用户登录了面板，然后访问了一个恶意页面，该页面
	// 用 JS 连上 /api/terminal/ws —— 请求带上用户的会话 Cookie，
	// RequireAuth 通过，恶意页面获得一个**全权限 root shell**。
	//
	// 普通的 XHR 不会被这样利用（同源策略会拦住读取响应，
	// 且自定义头的预检会失败），但 WebSocket 没有这道防线。
	// 因此在 WS 端点上，Origin 校验不是可选项而是**必需项**。
	//
	// 空列表表示"仅允许同源"（由 server 层按请求 Host 判断）。
	AllowedOrigins []string
	// Auditor 是审计器（必填）。
	//
	// ########## 为什么审计器是构造参数而不是内部 new ##########
	//
	// 与 4.1~4.6 一致：审计器在 main 里创建，**与其它七个模块
	// 共用同一个 -audit-log 文件**（统一落盘、分别查询）。
	// 若在这里自己 new 一个，就会各自打开一个文件句柄，
	// 也拿不到 main 统一的路径与容量配置。
	Auditor *Auditor
	// Logger 是日志器。
	Logger *slog.Logger
	// Now 用于测试注入时间；为 nil 时用 time.Now。
	Now func() time.Time
}

// Manager 管理所有终端会话。
type Manager struct {
	opts   ManagerOptions
	logger *slog.Logger

	// shell 是解析后的 shell 绝对路径。
	shell string

	mu sync.RWMutex
	// sessions 是 id → 会话的索引。
	sessions map[string]*Session

	// closed 标记管理器是否已关停。
	closed bool

	// wg 等待所有会话的读泵与守护 goroutine 退出。
	wg sync.WaitGroup

	// auditor 是与其它模块共用落盘文件的操作审计器。
	auditor *Auditor
}

// Auditor 返回审计器（可能为 nil —— 调用方必须判空）。
//
// 与 4.1~4.6 一致：审计是**旁路能力**，它缺失绝不能让核心功能不可用。
// 因此这里返回可能为 nil 而不是 panic，由调用方决定降级行为
// （server 层的 record 辅助函数会直接返回）。
func (m *Manager) Auditor() *Auditor {
	if m == nil {
		return nil
	}
	return m.auditor
}

// AllowedOrigins 返回允许的 WebSocket Origin 白名单。
func (m *Manager) AllowedOrigins() []string {
	if m == nil {
		return nil
	}
	return m.opts.AllowedOrigins
}

// NewManager 构造会话管理器。
//
// 构造时会**解析 shell**：若连 /bin/sh 都找不到，
// 直接返回错误。这比"等用户点新建才报错"更好——
// 面板启动时就能在日志里看到问题。
func NewManager(opts ManagerOptions) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 平台能力检查（Windows 等无 PTY 平台）。
	//
	// ########## 为什么这里不能直接返回错误 ##########
	//
	// 若 NewManager 在 Windows 上返回错误，main.go 会把它当成
	// "终端模块初始化失败"从而**整个面板启动失败**——而 Windows 用户
	// 其实能用面板的全部其它功能（服务/文件/网站/SSL/商店）。
	// 为了一个不可用的终端让整个面板起不来，是灾难性的降级。
	//
	// 因此：不支持时构造一个**可用但拒绝创建会话**的 Manager。
	// 它的 status 接口会如实报告 supported=false + 原因，
	// 前端据此渲染提示页；create 接口返回 ErrUnsupported。
	if !Supported() {
		logger.Warn("当前平台不支持 Web 终端，该功能将优雅降级",
			"os", runtime.GOOS, "reason", UnsupportedReason())

		maxSessions := opts.MaxSessions
		if maxSessions <= 0 {
			maxSessions = DefaultMaxSessions
		}
		opts.MaxSessions = maxSessions
		if opts.Now == nil {
			opts.Now = time.Now
		}
		return &Manager{
			opts:     opts,
			logger:   logger,
			shell:    "", // 无 shell：本平台不会真的创建会话
			sessions: make(map[string]*Session),
			auditor:  opts.Auditor,
		}, nil
	}

	shell, err := ResolveShell(opts.Shell, DefaultShellCandidates()...)
	if err != nil {
		return nil, err
	}

	maxSessions := opts.MaxSessions
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	opts.MaxSessions = maxSessions

	if opts.Now == nil {
		opts.Now = time.Now
	}

	logger.Info("终端会话管理器已就绪",
		"shell", shell,
		"idle_timeout", opts.IdleTimeout,
		"max_sessions", maxSessions,
	)

	return &Manager{
		opts:     opts,
		logger:   logger,
		shell:    shell,
		sessions: make(map[string]*Session),
		auditor:  opts.Auditor,
	}, nil
}

// Shell 返回解析后的 shell 路径。
func (m *Manager) Shell() string { return m.shell }

// IdleTimeout 返回生效的空闲超时。
func (m *Manager) IdleTimeout() time.Duration { return m.opts.IdleTimeout }

// MaxSessions 返回会话数上限。
func (m *Manager) MaxSessions() int { return m.opts.MaxSessions }

// ErrTooManySessions 表示会话数已达上限。
var ErrTooManySessions = errors.New("terminal: 终端会话数已达上限")

// ErrManagerClosed 表示管理器已关停。
var ErrManagerClosed = errors.New("terminal: 终端服务正在关闭，无法创建新会话")

// ErrSessionNotFound 表示会话不存在。
var ErrSessionNotFound = errors.New("terminal: 会话不存在或已结束")

// Supported 报告本管理器所在的平台是否支持 Web 终端。
//
// 与包级 Supported() 分开一个方法：调用方（server 层）持有的是
// *Manager，让它不必再额外 import 函数式 API，也便于将来在
// 测试里注入一个"假装不支持"的 Manager 来覆盖降级路径。
func (m *Manager) Supported() bool { return Supported() }

// Capability 返回平台能力快照（含不支持时的原因与建议）。
func (m *Manager) Capability() Capability { return CurrentCapability() }

// Create 创建一个新会话。
//
// owner 是发起创建的用户名，会绑定到会话上：
// 只有同一用户才能 attach（见 Attach 的调用方）。
func (m *Manager) Create(owner string, cols, rows int) (*Session, error) {
	// 平台能力前置检查：在无 PTY 的平台上明确拒绝，
	// 而不是让 pty.Start 失败后再翻译错误。
	//
	// 放在锁外：这是一次纯粹的平台判定，不读任何可变状态。
	if !Supported() {
		return nil, fmt.Errorf("%w。%s", ErrUnsupported, UnsupportedReason())
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrManagerClosed
	}
	// 上限检查与插入在同一个锁内完成。
	//
	// ########## 为什么不能"先数再插" ##########
	//
	// 分开做的话，两个并发请求可能同时数到 9（上限 10）
	// 然后都插入，最终变成 11 个。这就是典型的 TOCTOU。
	// 在同一把锁内先回收死会话再判断再插入，可以保证
	// 上限在任何并发下都不会被突破。
	m.reapLocked()

	if len(m.sessions) >= m.opts.MaxSessions {
		n := len(m.sessions)
		m.mu.Unlock()
		return nil, fmt.Errorf("%w（当前 %d/%d，请先关闭不用的终端）",
			ErrTooManySessions, n, m.opts.MaxSessions)
	}
	m.mu.Unlock()

	id, err := newSessionID()
	if err != nil {
		return nil, err
	}

	sess, err := NewSession(id, SessionOptions{
		Shell:       m.shell,
		Args:        m.opts.ShellArgs,
		Env:         CleanEnv(os.Environ()),
		Dir:         m.opts.WorkDir,
		Cols:        cols,
		Rows:        rows,
		IdleTimeout: m.opts.IdleTimeout,
		Owner:       owner,
		Logger:      m.logger,
	})
	if err != nil {
		return nil, err
	}

	// 二次检查 + 插入。这里重新取锁，因为 NewSession 可能耗时
	// （fork+exec）。期间可能有别的会话被创建，需再次确认上限。
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		// 管理器在创建过程中被关停：必须清理刚起的进程，
		// 否则关停后残留一个孤儿 shell。
		_ = sess.Close(CloseReasonServerShutdown)
		return nil, ErrManagerClosed
	}
	m.reapLocked()
	if len(m.sessions) >= m.opts.MaxSessions {
		n := len(m.sessions)
		m.mu.Unlock()
		_ = sess.Close(CloseReasonUser)
		return nil, fmt.Errorf("%w（当前 %d/%d，请先关闭不用的终端）",
			ErrTooManySessions, n, m.opts.MaxSessions)
	}
	m.sessions[id] = sess
	m.mu.Unlock()

	// 会话结束时自动从索引里移除。
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-sess.Done()
		m.remove(id)
	}()

	return sess, nil
}

// Get 按 ID 查找会话。
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// remove 从索引中删除会话。
func (m *Manager) remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// reapLocked 清理已结束的会话。
//
// 正常情况下会话结束时会由 Create 里注册的 goroutine 自动移除，
// 这里只是兜底：防止某个极端的竞态让已结束的会话留在索引里，
// 从而让"会话数上限"被死会话占满，用户永远开不了新终端。
//
// 调用方必须持有写锁。
func (m *Manager) reapLocked() {
	for id, s := range m.sessions {
		select {
		case <-s.Done():
			delete(m.sessions, id)
		default:
		}
	}
}

// List 返回所有会话的快照（按创建时间排序）。
func (m *Manager) List() []SessionInfo {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()

	infos := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		infos = append(infos, s.Snapshot())
	}

	// 按创建时间升序：稳定的展示顺序，避免每次刷新顺序乱跳。
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].CreatedAt < infos[j].CreatedAt
	})
	return infos
}

// Count 返回当前会话数。
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CloseSession 关闭指定会话。
func (m *Manager) CloseSession(id, reason string) error {
	sess, ok := m.Get(id)
	if !ok {
		return ErrSessionNotFound
	}
	return sess.Close(reason)
}

// Shutdown 关闭所有会话。
//
// 用于面板关停：必须**主动**结束所有 shell，
// 否则面板进程退出后，那些 shell 会因为父进程消失
// 而变成孤儿进程（被 init 收养继续运行）——
// 用户在面板里开着的 shell 应该随面板一起消失。
//
// 这里给每个会话发 close 帧并 kill 进程，等待它们收尾，
// 但**不会**无限等：超过 grace 就返回，避免关停卡住。
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	if len(sessions) == 0 {
		return nil
	}
	m.logger.Info("正在关闭所有终端会话", "count", len(sessions))

	for _, s := range sessions {
		_ = s.Close(CloseReasonServerShutdown)
	}

	// 等待所有会话收尾。done 由 finish() 关闭，而 finish 是同步完成的，
	// 因此这里通常立刻返回；ctx 只是防御性的上限。
	waited := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(waited)
	}()

	select {
	case <-waited:
		m.logger.Info("所有终端会话已关闭")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("terminal: 关闭终端会话超时: %w", ctx.Err())
	}
}

// SessionCount 是会话数统计（供状态接口使用）。
type SessionCount struct {
	// Total 是当前会话总数。
	Total int `json:"total"`
	// Max 是上限。
	Max int `json:"max"`
	// Running 是仍在运行的会话数。
	Running int `json:"running"`
}
