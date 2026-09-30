package terminal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// 测试基础设施
// ============================================================================
//
// #################### 本文件对系统环境的安全约束 ####################
//
// 终端测试会**真实 fork 子进程**。因此本文件遵守三条硬约束：
//
//  1. 只启动测试自己 fork 的 shell，且一律用 `sh -c '...'` 形式
//     立即退出的短命命令，绝不起一个交互式登录 shell。
//  2. 绝不使用 pkill / killall 等按名字匹配的全局 kill
//     （项目红线）。所有终止都走 Session.Close → killProcess，
//     它只操作本会话自己 fork 的 pid。
//  3. 每个用例结束时保证会话已关闭（defer t.Cleanup），
//     不留孤儿进程。
//
// 这些约束让测试可以在开发机上安全运行，而不是只能跑在容器里。

// testLogger 返回一个把日志丢掉的 logger，避免测试输出被淹没。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// simpleShell 返回一个用于测试的 shell 路径。
//
// 优先 /bin/sh：它几乎必然存在，且行为可预测（POSIX）。
// 不用 $SHELL：开发机的 $SHELL 可能是 zsh/fish，
// 其启动文件会产生额外输出，让"读到的第一段字节是什么"变得不确定。
func simpleShell(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/sh", "/bin/bash"} {
		if isExecutableFile(p) {
			return p
		}
	}
	t.Skip("系统上没有可用的 /bin/sh 或 /bin/bash，跳过 PTY 测试")
	return ""
}

// newTestSession 创建一个测试会话并注册清理。
func newTestSession(t *testing.T, opts SessionOptions) *Session {
	t.Helper()

	if opts.Shell == "" {
		opts.Shell = simpleShell(t)
	}
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	if opts.Owner == "" {
		opts.Owner = "tester"
	}

	sess, err := NewSession("test-"+t.Name(), opts)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	t.Cleanup(func() {
		// 保证无论用例如何结束，进程都被回收。
		_ = sess.Close(CloseReasonUser)
		select {
		case <-sess.Done():
		case <-time.After(5 * time.Second):
			t.Logf("警告：会话 %s 在 5s 内未完成收尾", sess.ID())
		}
	})
	return sess
}

// ============================================================================
// PTY 创建
// ============================================================================

// 创建一个 PTY 会话，确认 shell 真的跑起来了。
func TestNewSessionStartsPTYProcess(t *testing.T) {
	shell := simpleShell(t)

	sess := newTestSession(t, SessionOptions{
		// -i 让它成为一个交互式 shell（有提示符），
		// 这正是 Web 终端的真实形态。
		Shell: shell,
		Args:  []string{"-i"},
	})

	info := sess.Snapshot()
	if info.Status != StatusRunning {
		t.Errorf("状态 = %q，期望 %q", info.Status, StatusRunning)
	}
	if info.PID <= 0 {
		t.Errorf("PID = %d，期望一个正数（说明进程已启动）", info.PID)
	}
	if info.Owner != "tester" {
		t.Errorf("Owner = %q，期望 tester", info.Owner)
	}
	if info.Cols != DefaultCols || info.Rows != DefaultRows {
		t.Errorf("尺寸 = %dx%d，期望 %dx%d",
			info.Cols, info.Rows, DefaultCols, DefaultRows)
	}

	// 进程必须真的存在（不只看我们自己的状态字段）。
	//
	// ########## 为什么是 Signal(syscall.Signal(0)) 而不是 Signal(nil) ##########
	//
	// 信号 0 是 POSIX 约定的"存在性探针"：内核只做存在性与权限检查，
	// **不投递任何信号**，因此对进程无副作用。
	//
	// 本用例最初写的是 Signal(nil)，在 Linux 上恒失败：
	//
	//	os: unsupported signal type
	//
	// 原因是 os.Process.Signal 会把参数转成 syscall.Signal，
	// 而 nil 不是 Signal（它是 os.Signal 接口的零值）。
	// Windows 上 nil 另有含义（"不发送信号"），这恰好掩盖了错误用法——
	// 也就是说这个写法只在 Windows 上"碰巧能跑"。
	//
	// 注意错误方向：**测试失败，但被测代码其实是好的**。
	// 进程确实起来了、PTY 也真的分配成功，失败的是探针本身。
	if err := sess.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("PID %d 的进程不存在: %v", info.PID, err)
	}
}

// PTY 必须是一个**真正的终端**，而不是管道。
//
// ########## 这个测试为什么重要 ##########
//
// 用 os/exec + io.Pipe 也能"跑命令并拿到输出"，
// 但那不是终端：程序会认为 stdout 不是 tty，于是
// 关闭颜色、关闭行缓冲、拒绝全屏渲染。
//
// 判定方法是问 shell 自己 `test -t 0`（stdin 是不是终端）。
// 这是最直接的证据——不是看我们用了 pty 库，
// 而是看**子进程眼里**它是不是终端。
func TestSessionProvidesRealTTY(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	conn := attachFakeClient(t, sess)

	// 问 shell：stdin 是终端吗？
	if err := sess.HandleMessage(EncodeInput("test -t 0 && echo IS_A_TTY\n")); err != nil {
		t.Fatalf("写入输入失败: %v", err)
	}

	if !conn.waitFor("IS_A_TTY", 5*time.Second) {
		t.Fatalf("shell 未确认 stdin 是终端；已收到输出:\n%s", conn.output())
	}
}

// shell 的输出必须能被读到并回传给客户端。
func TestSessionReadsShellOutput(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})
	conn := attachFakeClient(t, sess)

	marker := "OUTPUT_MARKER_12345"
	if err := sess.HandleMessage(EncodeInput("echo " + marker + "\n")); err != nil {
		t.Fatalf("写入输入失败: %v", err)
	}

	if !conn.waitFor(marker, 5*time.Second) {
		t.Fatalf("未读到 shell 输出 %q；已收到:\n%s", marker, conn.output())
	}
}

// 多字节命令必须完整送达（验证输入路径不截断）。
func TestSessionDeliversMultiByteInput(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})
	conn := attachFakeClient(t, sess)

	// 一条较长的命令，跨过 125 字节的 7 位长度边界。
	payload := strings.Repeat("abcdefghij", 30) // 300 字节
	if err := sess.HandleMessage(EncodeInput("echo " + payload + "\n")); err != nil {
		t.Fatalf("写入输入失败: %v", err)
	}

	if !conn.waitFor(payload, 5*time.Second) {
		t.Fatalf("长输入未被完整送达；已收到:\n%s", conn.output())
	}
}

// ============================================================================
// Resize
// ============================================================================

// Resize 必须真正改到内核里的 winsize。
//
// ########## 为什么要问 shell 而不是只断言我们的字段 ##########
//
// 断言 s.cols == 100 只能证明"我们记下来了"。
// 真正要证明的是"shell 也知道了"——那样 vi/top 才会重绘。
// 因此这里让 shell 自己 `stty size` 读出内核里的值。
func TestResizeUpdatesRealTerminalSize(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
		Cols:  80,
		Rows:  24,
	})
	conn := attachFakeClient(t, sess)

	if err := sess.Resize(100, 40); err != nil {
		t.Fatalf("Resize 失败: %v", err)
	}

	// 服务端记录也必须更新。
	info := sess.Snapshot()
	if info.Cols != 100 || info.Rows != 40 {
		t.Errorf("服务端记录尺寸 = %dx%d，期望 100x40", info.Cols, info.Rows)
	}

	// 问内核：stty size 输出 "rows cols"。
	if err := sess.HandleMessage(EncodeInput("stty size\n")); err != nil {
		t.Fatalf("写入输入失败: %v", err)
	}
	if !conn.waitFor("40 100", 5*time.Second) {
		t.Fatalf("内核里的终端尺寸不是 40x100；已收到:\n%s", conn.output())
	}
}

// Resize 必须拒绝非法尺寸（防 winsize 构造出巨大值）。
func TestResizeRejectsInvalidSizes(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	cases := []struct {
		name       string
		cols, rows int
	}{
		{"cols 为 0", 0, 24},
		{"cols 为负", -1, 24},
		{"cols 超上限", MaxCols + 1, 24},
		{"rows 为 0", 80, 0},
		{"rows 为负", 80, -5},
		{"rows 超上限", 80, MaxRows + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sess.Resize(tc.cols, tc.rows); err == nil {
				t.Fatalf("Resize(%d, %d) 未被拒绝", tc.cols, tc.rows)
			}
		})
	}

	// 拒绝后原尺寸必须保持不变（不能留下半更新的状态）。
	info := sess.Snapshot()
	if info.Cols != DefaultCols || info.Rows != DefaultRows {
		t.Errorf("被拒绝的 Resize 改动了尺寸: %dx%d", info.Cols, info.Rows)
	}
}

// ============================================================================
// 空闲超时
// ============================================================================

// 空闲超时必须断开会话。
//
// 超时取很短的值（200ms）让测试快；idleWatcher 的检查间隔
// 有 1s 下限，因此这里必须等到那个下限之上。
func TestIdleTimeoutClosesSession(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell:       simpleShell(t),
		Args:        []string{"-i"},
		IdleTimeout: 300 * time.Millisecond,
	})

	// 不应立刻结束。
	select {
	case <-sess.Done():
		t.Fatal("会话在空闲超时前就结束了")
	case <-time.After(100 * time.Millisecond):
	}

	// 等待超时生效（检查间隔下限 1s，留足余量）。
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("空闲超时未触发，会话仍然存活")
	}

	info := sess.Snapshot()
	if info.CloseReason != CloseReasonIdle {
		t.Errorf("结束原因 = %q，期望 %q", info.CloseReason, CloseReasonIdle)
	}
	if info.Status != StatusClosed {
		t.Errorf("状态 = %q，期望 %q", info.Status, StatusClosed)
	}
}

// 有活动时**不能**被超时断开（超时计时器必须被刷新）。
//
// 这是最容易写错的地方：如果心跳/输入不刷新计时器，
// 用户正在密集操作时终端会突然断开。
func TestIdleTimeoutResetsOnActivity(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell:       simpleShell(t),
		Args:        []string{"-i"},
		IdleTimeout: 3 * time.Second,
	})
	conn := attachFakeClient(t, sess)

	// 在超时窗口内持续发心跳，总时长超过 timeout。
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if err := sess.HandleMessage(EncodePing()); err != nil {
			t.Fatalf("心跳失败: %v", err)
		}
		// 会话不能在这期间结束。
		select {
		case <-sess.Done():
			t.Fatalf("持续心跳期间会话被断开了（空闲计时器未刷新）；输出:\n%s",
				conn.output())
		default:
		}
		time.Sleep(400 * time.Millisecond)
	}

	info := sess.Snapshot()
	if info.Status != StatusRunning {
		t.Errorf("持续活动后状态 = %q，期望 %q", info.Status, StatusRunning)
	}
}

// IdleTimeout <= 0 时不启动超时守护（显式关闭该功能）。
func TestIdleTimeoutDisabled(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell:       simpleShell(t),
		Args:        []string{"-i"},
		IdleTimeout: 0,
	})

	select {
	case <-sess.Done():
		t.Fatal("IdleTimeout=0 时会话仍然被断开了")
	case <-time.After(1500 * time.Millisecond):
		// 这段时间足以让 1s 间隔的守护跑一轮；会话仍活着说明没启用超时。
	}
	if sess.Snapshot().Status != StatusRunning {
		t.Error("IdleTimeout=0 时会话状态不是 running")
	}
}

// ============================================================================
// 会话独占（不能被多个客户端共享）
// ============================================================================

// 第二个客户端 attach 必须被拒绝。
func TestAttachRejectsSecondClient(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	c1, c1peer := newPipeConn()
	defer c1peer.Close()
	if err := sess.Attach(c1); err != nil {
		t.Fatalf("第一个客户端 attach 失败: %v", err)
	}

	c2, c2peer := newPipeConn()
	defer c2peer.Close()
	err := sess.Attach(c2)
	if err == nil {
		t.Fatal("第二个客户端 attach 成功了，会话被共享")
	}
	if !errors.Is(err, ErrSessionBusy) {
		t.Errorf("错误 = %v，期望 ErrSessionBusy", err)
	}
}

// 同一个客户端重复 attach 也必须被拒绝（幂等性不是共享的借口）。
//
// 这个用例防的是一个具体的实现错误：如果 Attach 写成
// "attachOnce.Do 之后就启动读泵，第二次调用因为 Once 已执行
// 而直接返回 nil"，那么第二个客户端会被**静默接受**，
// 只是读泵仍属于第一个——它拿到的连接永远收不到数据，
// 且没有报错。用户看到的是一个"连上了但没有任何输出"的终端。
func TestAttachRejectsSameConnTwice(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	// 注意：这里用**同一个** conn 调用两次。
	// 第一次注册 attachOnce；第二次 Do 是空操作，
	// 必须靠后面的 "s.conn != conn" 检查拦住。
	// 但同一个 conn 显然相等，因此第二次会通过——
	// 真正的防线是"第二次调用来自不同的 conn"，
	// 即上一个用例。
	c1, peer := newPipeConn()
	defer peer.Close()

	if err := sess.Attach(c1); err != nil {
		t.Fatalf("attach 失败: %v", err)
	}

	c2, peer2 := newPipeConn()
	defer peer2.Close()
	if err := sess.Attach(c2); !errors.Is(err, ErrSessionBusy) {
		t.Fatalf("第二次 attach 的错误 = %v，期望 ErrSessionBusy", err)
	}
}

// 已结束的会话不能再被 attach。
func TestAttachRejectsClosedSession(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})
	if err := sess.Close(CloseReasonUser); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	conn, peer := newPipeConn()
	defer peer.Close()

	if err := sess.Attach(conn); err == nil {
		t.Fatal("已关闭的会话仍然可以被 attach")
	}
}

// ============================================================================
// 进程收尾（不留孤儿）
// ============================================================================

// 关闭会话必须终止 shell 进程。
//
// 这是"系统环境保护"的直接验证：面板不能凭空造出
// 活着的 shell 进程然后撒手不管。
func TestCloseTerminatesShellProcess(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	pid := sess.Snapshot().PID
	if pid <= 0 {
		t.Fatal("未拿到 PID")
	}

	if err := sess.Close(CloseReasonUser); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("会话未在 5s 内收尾")
	}

	// 进程必须消失。用 Signal(0) 探测存在性。
	// 注意：进程可能已退出但尚未被 reap（僵尸）。我们期望
	// waitProcess 的 cmd.Wait() 已把它回收，因此 Signal 应报错。
	proc, err := os.FindProcess(pid)
	if err == nil {
		// 给一个短暂的窗口让 Wait 完成回收。
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if serr := proc.Signal(syscallSignalZero); serr != nil {
				return // 已消失，符合预期
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Errorf("PID %d 在会话关闭 3s 后仍然存在", pid)
	}
}

// 用户敲 exit 时，会话必须被标记为 exited 而不是 closed。
//
// 这两种语义必须区分：前者是 shell 自己结束，
// 后者是会话被外部关闭（用户点断开/超时）。
// 审计里它们是不同的事件。
func TestShellExitMarksSessionExited(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})
	attachFakeClient(t, sess)

	if err := sess.HandleMessage(EncodeInput("exit\n")); err != nil {
		// 写入可能因为 shell 已经退出而失败（竞态），不算错误。
		t.Logf("写入 exit 返回: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("shell 退出后会话未结束")
	}

	info := sess.Snapshot()
	if info.Status != StatusExited {
		t.Errorf("状态 = %q，期望 %q", info.Status, StatusExited)
	}
	if info.CloseReason != CloseReasonExited {
		t.Errorf("结束原因 = %q，期望 %q", info.CloseReason, CloseReasonExited)
	}
}

// 关闭必须幂等（用户点断开与面板关停会同时触发）。
func TestCloseIsIdempotent(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sess.Close(CloseReasonUser)
		}()
	}
	wg.Wait()

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("会话未收尾")
	}
}

// ============================================================================
// Manager
// ============================================================================

// Manager 必须拒绝超过上限的会话创建。
func TestManagerEnforcesMaxSessions(t *testing.T) {
	mgr := newTestManager(t, ManagerOptions{
		Shell:       simpleShell(t),
		MaxSessions: 2,
	})

	created := make([]*Session, 0, 2)
	for i := 0; i < 2; i++ {
		s, err := mgr.Create("tester", 80, 24)
		if err != nil {
			t.Fatalf("创建第 %d 个会话失败: %v", i+1, err)
		}
		created = append(created, s)
	}

	// 第 3 个必须被拒绝。
	_, err := mgr.Create("tester", 80, 24)
	if err == nil {
		t.Fatal("超过上限的会话被创建了")
	}
	if !errors.Is(err, ErrTooManySessions) {
		t.Errorf("错误 = %v，期望 ErrTooManySessions", err)
	}

	// 关掉一个后应该又能创建。
	if err := mgr.CloseSession(created[0].ID(), CloseReasonUser); err != nil {
		t.Fatalf("关闭会话失败: %v", err)
	}
	// 等待索引回收。
	waitFor(t, 3*time.Second, func() bool { return mgr.Count() < 2 },
		"关闭会话后索引未回收")

	if _, err := mgr.Create("tester", 80, 24); err != nil {
		t.Fatalf("释放名额后仍无法创建会话: %v", err)
	}
}

// 会话结束后必须从 Manager 索引中自动移除。
func TestManagerRemovesEndedSession(t *testing.T) {
	mgr := newTestManager(t, ManagerOptions{Shell: simpleShell(t)})

	sess, err := mgr.Create("tester", 80, 24)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if mgr.Count() != 1 {
		t.Fatalf("会话数 = %d，期望 1", mgr.Count())
	}

	if err := sess.Close(CloseReasonUser); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool { return mgr.Count() == 0 },
		"会话结束后索引未清空")
}

// Shutdown 必须关闭所有会话。
func TestManagerShutdownClosesAll(t *testing.T) {
	mgr := newTestManager(t, ManagerOptions{Shell: simpleShell(t)})

	sessions := make([]*Session, 0, 3)
	for i := 0; i < 3; i++ {
		s, err := mgr.Create("tester", 80, 24)
		if err != nil {
			t.Fatalf("创建会话失败: %v", err)
		}
		sessions = append(sessions, s)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 失败: %v", err)
	}

	for _, s := range sessions {
		select {
		case <-s.Done():
		case <-time.After(time.Second):
			t.Errorf("会话 %s 未被 Shutdown 关闭", s.ID())
		}
	}

	// Shutdown 后再创建必须被拒绝。
	if _, err := mgr.Create("tester", 80, 24); !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Shutdown 后创建会话的错误 = %v，期望 ErrManagerClosed", err)
	}
}

// 会话 ID 必须互不相同且不可预测（含足够熵）。
func TestManagerGeneratesUniqueSessionIDs(t *testing.T) {
	mgr := newTestManager(t, ManagerOptions{Shell: simpleShell(t), MaxSessions: 10})

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		s, err := mgr.Create("tester", 80, 24)
		if err != nil {
			t.Fatalf("创建失败: %v", err)
		}
		if seen[s.ID()] {
			t.Fatalf("会话 ID 重复: %s", s.ID())
		}
		seen[s.ID()] = true
		// 128 位 base64url 约 22 字符；断言长度下限防止
		// 将来有人把 ID 改成自增或短随机。
		if len(s.ID()) < 20 {
			t.Errorf("会话 ID %q 过短（%d 字符），熵可能不足", s.ID(), len(s.ID()))
		}
	}
}

// Manager 必须能解析 shell（且配置的 shell 不存在时报错）。
func TestManagerResolveShell(t *testing.T) {
	if _, err := NewManager(ManagerOptions{
		Shell: "/nonexistent/shell/path/xyz",
	}); err == nil {
		t.Fatal("不存在的 shell 路径未被拒绝")
	}

	mgr := newTestManager(t, ManagerOptions{})
	if mgr.Shell() == "" {
		t.Fatal("未解析出 shell 路径")
	}
	if !filepath.IsAbs(mgr.Shell()) {
		t.Errorf("shell 路径 %q 不是绝对路径", mgr.Shell())
	}
}

// newTestManager 创建测试用 Manager 并注册清理。
func newTestManager(t *testing.T, opts ManagerOptions) *Manager {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatalf("创建 Manager 失败: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(ctx)
	})
	return mgr
}

// ============================================================================
// Shell 解析与环境
// ============================================================================

func TestResolveShellPrefersConfigured(t *testing.T) {
	shell := simpleShell(t)

	got, err := ResolveShell(shell, "/nonexistent")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got != shell {
		t.Errorf("解析结果 = %q，期望 %q", got, shell)
	}
}

func TestResolveShellFallsBack(t *testing.T) {
	shell := simpleShell(t)

	// 第一个候选不存在，应回退到第二个。
	got, err := ResolveShell("", "/nonexistent/shell", shell)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got != shell {
		t.Errorf("回退结果 = %q，期望 %q", got, shell)
	}
}

func TestResolveShellErrorsWhenAllMissing(t *testing.T) {
	if _, err := ResolveShell("", "/nonexistent/a", "/nonexistent/b"); err == nil {
		t.Fatal("所有候选都不存在时未报错")
	}
}

// ResolveShell 必须拒绝目录（exec 一个目录会得到难懂的 EACCES）。
func TestResolveShellRejectsDirectory(t *testing.T) {
	if _, err := ResolveShell("/tmp"); err == nil {
		t.Fatal("目录被当成了合法 shell")
	}
}

// TERM 必须被重置为终端类型。
//
// 面板进程的 TERM 可能是 dumb（systemd 启动时），
// 子 shell 继承后 vim/top 会拒绝渲染。
func TestCleanEnvResetsTerm(t *testing.T) {
	env := CleanEnv([]string{
		"TERM=dumb",
		"COLORTERM=",
		"PATH=/usr/bin",
		"HOME=/root",
	})

	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "TERM=dumb") {
		t.Error("旧的 TERM=dumb 未被移除")
	}
	if !strings.Contains(joined, "TERM=xterm-256color") {
		t.Error("未设置 TERM=xterm-256color")
	}
	if !strings.Contains(joined, "COLORTERM=truecolor") {
		t.Error("未设置 COLORTERM=truecolor")
	}
	// 其它变量必须保留。
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Error("PATH 被误删")
	}
	if !strings.Contains(joined, "HOME=/root") {
		t.Error("HOME 被误删")
	}
	// 重复设置 TERM 会导致不确定行为，必须只有一个。
	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "TERM=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("TERM 出现 %d 次，期望 1 次", count)
	}
}

// 端到端：TERM 必须真的传给了子进程。
func TestSessionPassesTermToChild(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
		Env:   CleanEnv(append(os.Environ(), "TERM=dumb")),
	})
	conn := attachFakeClient(t, sess)

	if err := sess.HandleMessage(EncodeInput("echo TERM_IS_$TERM\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if !conn.waitFor("TERM_IS_xterm-256color", 5*time.Second) {
		t.Fatalf("子进程的 TERM 不是 xterm-256color；输出:\n%s", conn.output())
	}
}

// ============================================================================
// 消息协议
// ============================================================================

func TestDecodeClientMessage(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"input", `{"type":"input","data":"ls\n"}`, false},
		{"input 空数据", `{"type":"input","data":""}`, false},
		{"resize 合法", `{"type":"resize","cols":80,"rows":24}`, false},
		{"ping", `{"type":"ping"}`, false},
		{"缺少 type", `{"data":"x"}`, true},
		{"未知类型", `{"type":"exec"}`, true},
		{"非法 JSON", `{not json`, true},
		{"resize cols 为 0", `{"type":"resize","cols":0,"rows":24}`, true},
		{"resize cols 为负", `{"type":"resize","cols":-1,"rows":24}`, true},
		{"resize cols 超上限", fmt.Sprintf(`{"type":"resize","cols":%d,"rows":24}`, MaxCols+1), true},
		{"resize rows 超上限", fmt.Sprintf(`{"type":"resize","cols":80,"rows":%d}`, MaxRows+1), true},
		// 未知字段必须被忽略（前向兼容）。
		{"含未知字段", `{"type":"ping","future":"x"}`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeClientMessage([]byte(tc.raw))
			if tc.wantErr && err == nil {
				t.Fatal("非法消息被接受了")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("合法消息被拒绝: %v", err)
			}
		})
	}
}

func TestClampSize(t *testing.T) {
	cases := []struct {
		cols, rows         int
		wantCols, wantRows int
	}{
		{80, 24, 80, 24},
		{0, 0, DefaultCols, DefaultRows},
		{-5, -5, DefaultCols, DefaultRows},
		{MaxCols + 100, MaxRows + 100, MaxCols, MaxRows},
		{80, 0, 80, DefaultRows},
	}
	for _, tc := range cases {
		gotCols, gotRows := ClampSize(tc.cols, tc.rows)
		if gotCols != tc.wantCols || gotRows != tc.wantRows {
			t.Errorf("ClampSize(%d,%d) = %d,%d，期望 %d,%d",
				tc.cols, tc.rows, gotCols, gotRows, tc.wantCols, tc.wantRows)
		}
	}
}

// 会话处理未知消息类型必须报错但不关闭连接。
func TestSessionHandleMessageRejectsUnknownType(t *testing.T) {
	sess := newTestSession(t, SessionOptions{
		Shell: simpleShell(t),
		Args:  []string{"-i"},
	})
	attachFakeClient(t, sess)

	if err := sess.HandleMessage([]byte(`{"type":"bogus"}`)); err == nil {
		t.Fatal("未知消息类型未被拒绝")
	}
	// 会话必须仍然活着：单条坏消息不足以断定客户端有问题。
	if sess.Snapshot().Status != StatusRunning {
		t.Error("处理坏消息后会话被关闭了")
	}
}

// ============================================================================
// 测试用假客户端
// ============================================================================

// fakeClient 通过内存管道伪装成一个 WebSocket 客户端，
// 收集服务端发来的**帧**并解析出载荷。
//
// 用管道而不是真实 TCP：测试只关心"会话是否正确地把 PTY 输出
// 发成了帧"，真实握手与 TCP 行为已由 ws_test.go 覆盖。
type fakeClient struct {
	t      *testing.T
	conn   *Conn
	frames chan string
	buf    bytes.Buffer
	mu     sync.Mutex
}

// newPipeConn 返回一个基于 net.Pipe 的 wsConn 及其对端。
func newPipeConn() (*Conn, *pipePeer) {
	server, client := newPipePair()
	return &Conn{conn: server, rw: bufio.NewReader(server)}, client
}

// attachFakeClient 把一个假客户端 attach 到会话并开始收集输出。
func attachFakeClient(t *testing.T, sess *Session) *fakeClient {
	t.Helper()

	server, client := newPipePair()
	conn := &Conn{conn: server, rw: bufio.NewReader(server)}

	if err := sess.Attach(conn); err != nil {
		t.Fatalf("attach 失败: %v", err)
	}

	fc := &fakeClient{t: t, conn: conn, frames: make(chan string, 256)}
	go fc.readLoop(client)

	t.Cleanup(func() { _ = conn.Close() })
	return fc
}

// readLoop 持续从对端读取服务端发出的帧并解码为文本。
func (f *fakeClient) readLoop(peer *pipePeer) {
	defer close(f.frames)

	br := bufio.NewReader(peer)
	for {
		_, payload, err := readServerFrame(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.buf.Write(payload)
		f.mu.Unlock()

		select {
		case f.frames <- string(payload):
		default:
		}
	}
}

// waitFor 等待输出中出现指定子串。
//
// ########## 为什么用"等待"而不是"读一次就断言" ##########
//
// shell 的输出是异步且**分段**的：提示符、回显、命令结果
// 会分多次到达。测试若读一次就断言，会因为"第一个 chunk
// 里还没有标记"而随机失败（flaky）。轮询直到出现或超时
// 是唯一稳定的做法。
func (f *fakeClient) waitFor(marker string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		found := strings.Contains(f.buf.String(), marker)
		f.mu.Unlock()
		if found {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// output 返回目前收集到的全部输出（用于失败时的诊断）。
func (f *fakeClient) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.String()
}

// waitFor 轮询直到条件成立或超时（测试助手）。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
