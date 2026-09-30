package terminal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
)

// ============================================================================
// PTY 会话（阶段五 5.1）
// ============================================================================

// 会话状态。
const (
	// StatusRunning 表示 PTY 已启动且进程仍在运行。
	StatusRunning = "running"
	// StatusClosed 表示会话已被正常关闭。
	StatusClosed = "closed"
	// StatusExited 表示 shell 进程自己退出了（用户敲了 exit）。
	StatusExited = "exited"
)

// 会话关闭原因，用于审计与前端提示。
//
// 做成稳定常量而不是自由文本：审计里要能按原因聚合
// （"这台机器的终端总是空闲超时断开"本身就是一个信号）。
const (
	// CloseReasonUser 用户主动点击断开。
	CloseReasonUser = "user_closed"
	// CloseReasonIdle 空闲超时。
	CloseReasonIdle = "idle_timeout"
	// CloseReasonExited shell 进程自己退出。
	CloseReasonExited = "process_exited"
	// CloseReasonClientGone 客户端断开（关掉浏览器/网络中断）。
	CloseReasonClientGone = "client_disconnected"
	// CloseReasonServerShutdown 面板关闭。
	CloseReasonServerShutdown = "server_shutdown"
	// CloseReasonProtocol 协议错误。
	CloseReasonProtocol = "protocol_error"
)

// SessionOptions 是创建会话的参数。
type SessionOptions struct {
	// Shell 是要启动的 shell 路径（已由 Manager 解析为绝对路径）。
	Shell string
	// Args 是传给 shell 的附加参数。
	Args []string
	// Env 是子进程环境变量。为空时继承当前进程环境。
	Env []string
	// Dir 是工作目录。
	Dir string
	// Cols / Rows 是初始终端尺寸。
	Cols, Rows int
	// IdleTimeout 是空闲超时；<=0 表示不超时。
	IdleTimeout time.Duration
	// Owner 是创建该会话的用户名。
	Owner string
	// Logger 是日志器。
	Logger *slog.Logger
}

// Session 是一个 PTY 终端会话。
//
// #################### 所有权与并发模型 ####################
//
// 每个 Session 拥有：
//
//	· 一个子进程（shell）与它的 PTY 主设备（ptmx）
//	· 一个后台**读泵** goroutine：ptmx → 客户端
//
// 生命周期上最关键的一点是：**读泵是先于会话存在还是后于会话存在**。
//
// 本实现选择"会话创建即启动 shell，但**不**启动读泵；
// 读泵在第一个（也是唯一一个）客户端 attach 时启动"。
//
// 原因是终端输出是**不可回放**的字节流。如果 shell 在没人连接的
// 情况下就开始产出（比如 .bashrc 里的打印），这些字节会堆在
// PTY 缓冲区里；等到客户端连上，先看到的可能是"半截"内容。
// 更重要的是：PTY 缓冲区满之后，shell 的 write 会**阻塞**，
// 于是 shell 卡死在一个没人看的输出上。
//
// 因此 attach 与读泵的启动是原子的（在 mu 保护下），
// 保证"最多一个读泵、最多一个客户端"这个不变量。
type Session struct {
	id      string
	owner   string
	created time.Time

	cmd  *exec.Cmd
	ptmx *os.File

	// mu 保护下面所有可变字段。
	mu sync.Mutex
	// conn 是当前连接的客户端；nil 表示尚未 attach 或已断开。
	conn *Conn
	// status 见 StatusRunning / StatusClosed / StatusExited。
	status string
	// closeReason 记录会话为何结束。
	closeReason string
	// closedAt / exitCode 用于会话列表展示。
	closedAt time.Time
	exitCode int
	// lastActive 是最后一次活动时间（输入/输出/resize/心跳）。
	lastActive time.Time
	// cols / rows 是当前终端尺寸。
	cols, rows int
	// forceClosed 标记会话已被显式关闭（区别于 shell 自然退出）。
	forceClosed bool

	idleTimeout time.Duration
	logger      *slog.Logger

	// done 在会话彻底结束时关闭，供 Manager 回收时等待。
	done chan struct{}
	// doneOnce 保证 done 只被关闭一次。
	doneOnce sync.Once

	// attachOnce 保证**读泵只启动一次**。
	//
	// 这是"会话不能被多个客户端共享"的**核心执行点**：
	// 谁先把 conn 从 nil 抢到非 nil，谁就拥有了这个会话。
	// 第二个尝试 attach 的客户端会拿到 ErrSessionBusy。
	attachOnce sync.Once
}

// ErrSessionBusy 表示会话已被另一个客户端占用。
//
// ########## 为什么这是一条硬性安全底线 ##########
//
// 计划要求"会话不能被多个客户端共享"。这不仅是体验问题：
//
//	· 共享的终端里，两个人的输入会交错成一个谁也无法
//	  理解的命令（`rm -rf /tmp/x` 被另一个人的按键切断）；
//	· 审计上无法归因——同一个会话里发生了破坏性操作，
//	  日志只能记到"这个会话 ID"，而会话有两个主人；
//	· 终端是全权限 shell，让第二个客户端"搭车"
//	  等于绕过了一次登录校验。
//
// 因此这里在**服务端**强制拒绝（409），而不是靠前端
// 不打开第二个标签页来保证。
var ErrSessionBusy = errors.New("terminal: 该会话已被其它客户端占用，不能共享")

// ErrSessionClosed 表示会话已结束。
var ErrSessionClosed = errors.New("terminal: 会话已结束")

// NewSession 创建一个 PTY 会话并启动 shell。
//
// 返回错误时保证**不留残留资源**（子进程已 kill、ptmx 已关闭），
// 否则反复失败会积累孤儿进程——这正是"系统环境保护"要避免的。
func NewSession(id string, opts SessionOptions) (*Session, error) {
	if opts.Shell == "" {
		return nil, errors.New("terminal: shell 路径不能为空")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 平台能力前置检查（Windows 等无 PTY 平台）。
	//
	// ########## 为什么必须在 pty.Start 之前拦 ##########
	//
	// 不拦的话，pty.Start 会先 fork+exec 出 shell 进程（或至少
	// 走完 exec.Command 的构造），再由库返回 "unsupported"，
	// 我们再去 kill 它——凭空多了一次进程创建与销毁。
	//
	// 在 Windows 上这个代价尤其明显：cmd.Start 会真的尝试启动
	// 一个进程，失败后留下一个需要回收的句柄。提前返回既更快，
	// 也保证"不支持"这条路径**完全不触碰进程管理**，
	// 与项目"不制造孤儿进程"的要求一致。
	if !Supported() {
		return nil, fmt.Errorf("%w。%s", ErrUnsupported, UnsupportedReason())
	}

	cols, rows := ClampSize(opts.Cols, opts.Rows)
	now := time.Now()

	cmd := exec.Command(opts.Shell, opts.Args...)
	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	cmd.Dir = opts.Dir

	// pty.Start 用 setsid + TIOCSCTTY 让子进程成为
	// 控制终端的会话首领。这是 shell 能正常工作的前提：
	// 没有控制终端，job control（Ctrl-C、Ctrl-Z、前后台）
	// 全部失效，vi/top 这类全屏程序也无法运行。
	ptmx, err := pty.Start(cmd)
	if err != nil {
		// 库层面的不支持（例如将来新增的未知平台）也归一化为
		// 本模块的 ErrUnsupported，而不是透出裸的 "unsupported"。
		if unsupported := wrapUnsupported(err); unsupported != nil {
			return nil, fmt.Errorf("%w。%s", unsupported, UnsupportedReason())
		}
		return nil, fmt.Errorf("terminal: 启动 shell %s 失败: %w", opts.Shell, err)
	}

	// 设置初始尺寸。
	//
	// ########## 失败为什么要 kill 而不是继续 ##########
	//
	// 尺寸设置失败通常意味着 PTY 已经异常。此时若继续，
	// 客户端会用错误的尺寸渲染，而用户看到的是一屏
	// 错乱的输出——比直接报错更难排查。
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}); err != nil {
		// 清理：先 kill 子进程再关 ptmx，顺序不能反——
		// 先关 ptmx 会让子进程收到 SIGHUP，但可能来不及回收。
		killProcess(cmd)
		_ = ptmx.Close()
		return nil, fmt.Errorf("terminal: 设置初始终端尺寸失败: %w", err)
	}

	s := &Session{
		id:          id,
		owner:       opts.Owner,
		created:     now,
		cmd:         cmd,
		ptmx:        ptmx,
		status:      StatusRunning,
		lastActive:  now,
		cols:        cols,
		rows:        rows,
		idleTimeout: opts.IdleTimeout,
		logger:      logger,
		done:        make(chan struct{}),
	}

	// 后台等待子进程退出，以便把 status 置为 exited 并唤醒等待者。
	//
	// ########## 为什么必须有人 Wait ##########
	//
	// 在 Linux 上，子进程退出后若无人 Wait，会变成僵尸进程
	// （zombie），一直占用一个进程表项直到父进程退出。
	// 用户每开一次终端就敲一次 exit，就会积累一个僵尸。
	// 因此这里必须有一个 goroutine 专门 Wait。
	go s.waitProcess()

	// 空闲超时守护。
	//
	// 只有配置了超时（>0）才启动，避免 -terminal-idle-timeout=0
	// （显式关闭）时留一个空转的 goroutine。
	if s.idleTimeout > 0 {
		go s.idleWatcher()
	}

	logger.Info("终端会话已创建",
		"session", id, "owner", opts.Owner, "shell", opts.Shell,
		"cols", cols, "rows", rows, "pid", cmd.Process.Pid)

	return s, nil
}

// ID 返回会话 ID。
func (s *Session) ID() string { return s.id }

// Owner 返回会话创建者。
func (s *Session) Owner() string { return s.owner }

// waitProcess 等待 shell 退出并把会话标记为 exited。
func (s *Session) waitProcess() {
	err := s.cmd.Wait()

	s.mu.Lock()
	wasClosed := s.forceClosed
	exitCode := 0
	if s.cmd.ProcessState != nil {
		exitCode = s.cmd.ProcessState.ExitCode()
	} else if err != nil {
		// 进程未正常退出且拿不到 ProcessState：记 -1 表示未知。
		exitCode = -1
	}
	s.exitCode = exitCode
	if !wasClosed {
		// shell 自己退出了（用户敲 exit）。这不是"关闭"而是"结束"，
		// 语义上要能区分：审计里"用户点了断开"与"用户敲了 exit"
		// 是不同的行为，前者可能意味着他发现了异常。
		s.status = StatusExited
		s.closeReason = CloseReasonExited
		s.closedAt = time.Now()
	}
	s.mu.Unlock()

	// 通知读泵与等待者：进程没了，继续读也没有意义。
	s.finish()
}

// Attach 把 WebSocket 客户端绑定到会话。
//
// 只允许一次：第二次调用返回 ErrSessionBusy（HTTP 层映射为 409）。
func (s *Session) Attach(conn *Conn) error {
	var attachErr error

	s.attachOnce.Do(func() {
		s.mu.Lock()
		if s.status != StatusRunning {
			s.mu.Unlock()
			attachErr = ErrSessionClosed
			return
		}
		s.conn = conn
		s.lastActive = time.Now()
		s.mu.Unlock()
	})

	if attachErr != nil {
		return attachErr
	}

	// attachOnce.Do 对第二次调用是空操作，必须显式再判断一次
	// "当前 conn 是不是我"，否则第二个客户端会被静默接受。
	s.mu.Lock()
	if s.conn != conn {
		s.mu.Unlock()
		return ErrSessionBusy
	}
	s.mu.Unlock()

	// 启动唯一的读泵（见 Session 的并发模型注释）。
	go s.pump()
	return nil
}

// pump 是 PTY → 客户端的读泵。
//
// 这是会话的**主循环**：它一直运行到 PTY 关闭或出错。
// 每读到的字节原样作为 WebSocket 文本帧发给客户端
// （见 protocol.go 中"输出走裸字节"的说明）。
func (s *Session) pump() {
	buf := make([]byte, 32*1024)

	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			conn := s.conn
			if conn != nil {
				s.lastActive = time.Now()
			}
			s.mu.Unlock()

			if conn != nil {
				// 写失败（客户端断开）不能中断读泵：
				// shell 还在跑，继续读能防止 PTY 缓冲区满导致
				// shell 阻塞。错误只在下一轮由 conn == nil 处理。
				if werr := conn.WriteText(buf[:n]); werr != nil {
					s.logger.Debug("终端输出写出失败", "session", s.id, "err", werr)
				}
			} else {
				// 没有客户端时丢弃输出（见 Session 注释：
				// 会话只在 attach 后才开始被消费）。
				s.logger.Debug("终端无客户端，丢弃输出", "session", s.id, "bytes", n)
			}
		}

		if err != nil {
			// io.EOF 表示 shell 已退出且 PTY 从端关闭：正常结束路径。
			if !errors.Is(err, io.EOF) {
				s.mu.Lock()
				closed := s.forceClosed
				s.mu.Unlock()
				if !closed {
					s.logger.Debug("终端读取出错", "session", s.id, "err", err)
				}
			}
			// 读到 EOF/错误即认为会话结束。
			s.finish()
			return
		}
	}
}

// HandleMessage 处理客户端发来的一条控制消息。
//
// 返回的错误会以错误提示的形式回给前端（不关闭连接），
// 除非是致命错误（畸形 JSON 反复出现说明客户端有问题，
// 但单条错误不足以断定，因此仍只回错误不关闭）。
func (s *Session) HandleMessage(raw []byte) error {
	msg, err := DecodeClientMessage(raw)
	if err != nil {
		return err
	}

	// 任何合法消息都算"活动"，刷新空闲计时器。
	s.touch()

	switch msg.Type {
	case MsgInput:
		if msg.Data == "" {
			return nil
		}
		// 写入 PTY 主设备即等于"用户敲键"。
		// PTY 的行规程会处理回显、退格、Ctrl-C 等——
		// 这正是必须用 PTY 而不是管道的原因。
		if _, err := s.ptmx.Write([]byte(msg.Data)); err != nil {
			// 写失败通常意味着 shell 已退出。
			// 返回错误但不关闭连接：进程退出会由读泵/waitProcess 收尾。
			return fmt.Errorf("terminal: 写入终端失败: %w", err)
		}
		return nil

	case MsgResize:
		return s.Resize(msg.Cols, msg.Rows)

	case MsgPing:
		// 心跳只用于刷新计时器，已在上面 touch 完成。
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnknownMessageType, msg.Type)
}

// Resize 调整终端窗口大小。
//
// 实现上就是 pty.Setsize。但它的**意义**比"改个数字"大得多：
// shell 里的程序（top、vim、less）靠 SIGWINCH 得知窗口变化并重绘。
// 因此 Setsize 之后不需要我们手动发信号——内核会做。
func (s *Session) Resize(cols, rows int) error {
	if cols < MinCols || cols > MaxCols {
		return fmt.Errorf("terminal: cols 必须在 %d~%d 之间，实际 %d", MinCols, MaxCols, cols)
	}
	if rows < MinRows || rows > MaxRows {
		return fmt.Errorf("terminal: rows 必须在 %d~%d 之间，实际 %d", MinRows, MaxRows, rows)
	}

	s.mu.Lock()
	if s.status != StatusRunning {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.cols, s.rows = cols, rows
	s.mu.Unlock()

	if err := pty.Setsize(s.ptmx, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	}); err != nil {
		return fmt.Errorf("terminal: 调整终端尺寸失败: %w", err)
	}
	return nil
}

// touch 刷新最后活动时间。
func (s *Session) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

// idleWatcher 在空闲超时后关闭会话。
//
// ########## 为什么用轮询而不是 time.AfterFunc 重置 ##########
//
// 每次活动都要重置一个定时器。用 time.AfterFunc 需要在
// 每次输入时 Stop + 重建，而这些调用来自不同 goroutine，
// 容易在 Stop/重建的窗口期漏掉一次触发或产生僵尸定时器。
//
// 轮询的做法简单且行为可预测：每 tick 检查一次
// "now - lastActive > timeout"。检查间隔取超时的 1/10
// （上限 30s、下限 1s），保证误判窗口不超过 10%，
// 同时不会因为超时很长（如 2h）而空转。
func (s *Session) idleWatcher() {
	interval := s.idleTimeout / 10
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			idle := time.Since(s.lastActive)
			status := s.status
			s.mu.Unlock()

			if status != StatusRunning {
				return
			}
			if idle >= s.idleTimeout {
				s.logger.Info("终端会话空闲超时，正在断开",
					"session", s.id, "idle", idle.Round(time.Second),
					"timeout", s.idleTimeout)
				// Close 会关闭 done，从而结束本 goroutine。
				s.Close(CloseReasonIdle)
				return
			}
		}
	}
}

// Close 关闭会话：通知客户端、终止 shell、释放 PTY。
//
// 幂等，可被多个 goroutine 同时调用（用户点断开 + 面板关停）。
//
// ########## 关闭顺序为什么是"先通知、再杀、最后关 fd" ##########
//
//  1. 先给客户端发 close 帧：让浏览器知道这是**有意**断开
//     （1000/1001）而不是网络故障，前端据此显示"已断开"
//     而不是"重连中"。顺序反了的话 TCP 已关，close 帧发不出去，
//     前端只能看到异常断开。
//  2. 再终止 shell 进程。
//  3. 最后关 ptmx：关闭主设备会让从端收到 SIGHUP，
//     这会连带终止 shell 的前台进程组（用户起的 vim、top）。
//     如果先关 ptmx，shell 已经收到 SIGHUP 死了，
//     但第 2 步的 kill 就作用在一个已死的 pid 上（无害但无意义）。
func (s *Session) Close(reason string) error {
	s.mu.Lock()
	if s.status == StatusClosed || s.status == StatusExited {
		s.mu.Unlock()
		return nil
	}
	s.status = StatusClosed
	s.closeReason = reason
	s.closedAt = time.Now()
	s.forceClosed = true
	conn := s.conn
	s.mu.Unlock()

	if conn != nil {
		code := uint16(closeNormal)
		if reason == CloseReasonServerShutdown {
			code = closeGoingAway
		}
		_ = conn.WriteClose(code, reason)
	}

	s.finish()
	return nil
}

// finish 完成会话收尾：终止进程、释放 fd、唤醒等待者。
//
// 由多个路径调用（读泵 EOF、进程退出、显式 Close），
// 因此必须幂等。
func (s *Session) finish() {
	s.doneOnce.Do(func() {
		// 1. 终止 shell 进程。
		//
		// ########## 只 kill 自己启动的进程 ##########
		//
		// s.cmd.Process 是本会话通过 pty.Start 亲自启动的进程，
		// 持有它的 pid 与句柄。这里**绝不**用 pkill/killall
		// 按名字匹配（那会杀掉用户别处的 shell）。
		// 这也满足项目"严禁 kill 非自己启动的进程"的红线。
		killProcess(s.cmd)

		// 2. 关闭 PTY 主设备。
		//
		// 注意：先 kill 再 Close，且 Close 之后从端的
		// 前台进程组会收到 SIGHUP，连带清理用户起的子进程。
		if err := s.ptmx.Close(); err != nil {
			s.logger.Debug("关闭 PTY 失败", "session", s.id, "err", err)
		}

		// 3. 关闭 WebSocket 连接。
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}

		// 4. 唤醒所有等待者。
		close(s.done)
	})
}

// Done 返回一个在会话结束时关闭的 channel。
func (s *Session) Done() <-chan struct{} { return s.done }

// Snapshot 返回会话的当前状态快照（线程安全）。
func (s *Session) Snapshot() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	pid := 0
	if s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}

	return SessionInfo{
		ID:          s.id,
		Owner:       s.owner,
		Status:      s.status,
		CloseReason: s.closeReason,
		PID:         pid,
		Cols:        s.cols,
		Rows:        s.rows,
		CreatedAt:   s.created.Format(time.RFC3339),
		LastActive:  s.lastActive.Format(time.RFC3339),
		IdleSeconds: int(time.Since(s.lastActive).Seconds()),
		ExitCode:    s.exitCode,
		Closed:      s.status != StatusRunning,
	}
}

// SessionInfo 是会话的对外快照（可 JSON 序列化）。
type SessionInfo struct {
	ID string `json:"id"`
	// Owner 是会话创建者。
	//
	// ########## 为什么要暴露 owner ##########
	//
	// 会话列表是"当前有哪些终端开着"的视图。多用户场景下
	// 看到别人的会话 ID 本身不构成越权（attach 会被拒），
	// 但**知道有别人的会话存在**是审计与运维的必要信息
	// （比如"谁还连在这台机器上"）。因此保留该字段，
	// 但 attach 的授权判断严格按用户名做。
	Owner       string `json:"owner"`
	Status      string `json:"status"`
	CloseReason string `json:"close_reason,omitempty"`
	PID         int    `json:"pid"`
	Cols        int    `json:"cols"`
	Rows        int    `json:"rows"`
	CreatedAt   string `json:"created_at"`
	LastActive  string `json:"last_active"`
	IdleSeconds int    `json:"idle_seconds"`
	ExitCode    int    `json:"exit_code"`
	Closed      bool   `json:"closed"`
}

// killProcess 终止会话自己的子进程。
//
// ########## 关于进程终止方式的选择 ##########
//
// 这里用 Process.Kill()（SIGKILL）而不是先 SIGTERM 再等。
// 理由是 PTY 会话的收尾路径很特殊：
//
//	· 用户的交互 shell 大多不处理 SIGTERM 的"优雅退出"
//	  （它会直接终止），先发 SIGTERM 只是多一次系统调用；
//	· 真正需要优雅收尾的是 shell 里的**子进程**
//	  （比如正在跑的 apt），而它们由 ptmx.Close() 触发的
//	  SIGHUP 处理——那一条路径是保留的；
//	· 若先 SIGTERM 再等，就引入了一个"等多久"的悬念：
//	  等太久会让"关闭会话"这个操作显得卡住，
//	  不等则等于没发。
//
// 因此：Kill 本会话的 shell（SIGKILL，必然生效且立即），
// 由 PTY 关闭时的 SIGHUP 负责通知它的子孙。
//
// 注意本函数只操作 s.cmd.Process（自己启动的进程），
// 不涉及任何按名字匹配的全局 kill。
func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// 进程可能已经退出（waitProcess 先跑了一步），
	// 此时 Kill 返回 "os: process already finished"。
	// 这是正常的竞态，不是错误，因此忽略返回值。
	_ = cmd.Process.Kill()
}

// CleanEnv 构造终端子进程的环境变量。
//
// ########## 为什么必须重置 TERM ##########
//
// 面板自身的进程可能是从 systemd 或一个没有终端的上下文启动的，
// 其环境里 TERM 往往是 "dumb" 或干脆没有。子 shell 继承
// 这个值后，所有全屏程序（vim、top、htop、less）会
// **拒绝渲染或降级成纯文本模式**，用户看到的是一个
// "能敲命令但界面全乱"的终端——非常难归因到 TERM。
//
// 因此这里显式设置 TERM=xterm-256color，与前端 xterm.js
// 的默认终端类型一致。
func CleanEnv(base []string) []string {
	env := make([]string, 0, len(base)+3)

	for _, kv := range base {
		key := kv
		if idx := strings.IndexByte(kv, '='); idx >= 0 {
			key = kv[:idx]
		}
		switch key {
		case "TERM", "COLORTERM":
			// 丢弃，稍后统一设置。
			continue
		}
		env = append(env, kv)
	}

	env = append(env,
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		// 标记该会话来自面板，便于用户在 shell 里区分
		// "我在面板里"与"我在 SSH 里"（可用于审计横幅）。
		"LIPANEL_TERMINAL=1",
	)
	return env
}

// ResolveShell 解析要使用的 shell 路径。
//
// 优先级：显式配置 > $SHELL > /bin/bash > /bin/sh。
//
// ########## 为什么显式配置优先于 $SHELL ##########
//
// $SHELL 是**面板进程**的环境变量，而面板多半由 systemd
// 以 root 启动，其 $SHELL 常常是空的或 /bin/sh。
// 用户通过 SSH 登录的 $SHELL 与面板进程的 $SHELL 是两回事。
// 因此允许 -terminal-shell 显式覆盖，避免"我在服务器上
// 用的是 zsh，面板里却给我 sh"这种困惑。
//
// 回退链上的每一个候选都做存在性检查：直接 exec 一个
// 不存在的路径会让会话创建失败并只报 "no such file"。
func ResolveShell(configured string, candidates ...string) (string, error) {
	if configured != "" {
		if !isExecutableFile(configured) {
			return "", fmt.Errorf(
				"terminal: 配置的 shell %q 不存在或不可执行", configured)
		}
		return configured, nil
	}

	for _, cand := range candidates {
		if cand != "" && isExecutableFile(cand) {
			return cand, nil
		}
	}
	return "", errors.New(
		"terminal: 找不到可用的 shell（已尝试 $SHELL、/bin/bash、/bin/sh）")
}

// isExecutableFile 判断路径是否是一个可执行文件。
//
// 用 os.Stat 而不是 os.Executable 类的探测：我们只需要知道
// "能不能 exec 它"。注意这里**不跟随**到目录——
// 一个可执行的目录路径会让 exec 报 EACCES 而不是 ENOENT，
// 提前拦掉能给出更清晰的错误。
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// DefaultShellCandidates 返回 shell 回退链。
//
// $SHELL 放在最前：它最贴近用户的真实偏好。
// 但如 ResolveShell 注释所述，面板进程的 $SHELL 未必可信，
// 因此后面紧跟两个几乎必然存在的绝对路径。
func DefaultShellCandidates() []string {
	return []string{
		os.Getenv("SHELL"),
		"/bin/bash",
		"/bin/sh",
	}
}
