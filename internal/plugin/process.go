package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// socketDirPerm 是存放插件 socket 的目录权限：仅属主可进入。
const socketDirPerm os.FileMode = 0o700

// process 是一个托管插件进程的运行时句柄。
//
// 并发模型（重要，这里踩过 -race 的坑，记录以备后续参考）：
//
// Manager 的锁**不能**保护本结构体的字段，因为 process.Start 是在锁外调用的
// （等待 socket 就绪最长可达 StartTimeout，持锁会让整个面板的插件接口冻结）。
// 因此本结构体自带一把 mutex，保护 cmd / pid / startedAt / done / waitErr，
// 这些字段会同时被以下三方读写：
//
//   - Start（调用方 goroutine，不持 Manager 锁）
//   - Stop / alive / Dial（调用方 goroutine，可能持有 Manager 锁）
//   - 回收 goroutine（cmd.Wait() 的写入方）
//
// 最初的做法是「不加锁，靠注释约定 close(done) 之后才能读 waitErr」。
// 该约定对 waitErr 本身成立（写入在 close 之前），但漏掉了
// pid / startedAt / done 的写入与读取之间没有任何同步——
// 表现为 go test -race 在全量测试（并发压力更大）下偶发报 data race。
// 现在统一用 mu 保护，并让 Start 返回不可变快照，彻底消除这类隐式约定。
type process struct {
	desc Descriptor
	// sockPath 是该插件监听的 Unix socket 路径。
	sockPath string

	logger *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	pid       int
	done      chan struct{} // cmd.Wait() 返回后关闭
	waitErr   error         // 由回收 goroutine 写入；读取前需 <-done 或持锁
	startedAt time.Time
}

// StartResult 是进程启动成功后的不可变快照。
//
// Start 返回它，而不是让调用方去读 process 的字段——
// 这样从根上消除「启动完成后跨 goroutine 读 pid/startedAt」的竞态：
// 调用方拿到的是一份值拷贝。
type StartResult struct {
	PID       int
	StartedAt time.Time
	Socket    string
}

// newProcess 构造托管进程句柄（不启动）。
func newProcess(desc Descriptor, sockPath string, logger *slog.Logger) *process {
	return &process{
		desc:     desc,
		sockPath: sockPath,
		logger:   logger,
	}
}

// Start 拉起插件进程并等待其 socket 就绪，返回启动快照。
//
// 参数 binPath 是主程序自身的可执行文件路径：内置插件通过
// 「自身二进制 + __plugin_<id> 子命令」的方式启动，因此不需要额外的可执行文件。
//
// 已存在的残留 socket 文件会先被删除：上一次进程被 SIGKILL 时不会
// 清理 socket，残留文件会让新进程 bind 失败（EADDRINUSE）。
func (p *process) Start(ctx context.Context, binPath string, env []string) (StartResult, error) {
	if err := p.prepareSocketPath(); err != nil {
		return StartResult{}, err
	}

	//nolint:gosec // binPath 是主程序自身路径，参数由 Descriptor（已校验 ID）派生，无用户输入拼接。
	cmd := exec.Command(binPath, PluginSubcommandPrefix+p.desc.ID)
	cmd.Env = append(os.Environ(), env...)
	// 插件日志与核心日志共用 stdout/stderr，便于单机排查；
	// 后续阶段可改为按插件分流到独立文件。
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// 独立进程组：停止时可以向整个组发信号，避免插件自己拉起的子进程
	// 变成孤儿。平台差异（Windows/Plan9 无进程组）由 setProcessGroup 吸收，
	// 见 process_unix.go / process_windows.go / process_stub.go。
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return StartResult{}, fmt.Errorf("plugin: 启动插件 %s 进程失败: %w", p.desc.ID, err)
	}

	pid := cmd.Process.Pid
	startedAt := time.Now()
	done := make(chan struct{})

	p.mu.Lock()
	p.cmd = cmd
	p.pid = pid
	p.startedAt = startedAt
	p.done = done
	p.waitErr = nil
	p.mu.Unlock()

	// 回收 goroutine：必须有人调用 Wait，否则进程退出后会留下僵尸。
	// waitErr 的写入发生在 close(done) 之前，因此任何在 <-done 之后
	// 的读取（或持 p.mu 的读取）都能看到正确的值。
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.waitErr = err
		p.mu.Unlock()
		close(done)
	}()

	p.logger.Info("插件进程已拉起",
		"plugin", p.desc.ID, "pid", pid, "socket", p.sockPath)

	// 等待 socket 就绪：进程起来了不等于服务可用，
	// 必须等到能成功拨号才算启动成功。
	if err := p.waitReady(ctx, done); err != nil {
		// 启动失败要立即回收进程，不能留下「已启动但不可用」的假象。
		p.kill()
		return StartResult{}, err
	}

	return StartResult{PID: pid, StartedAt: startedAt, Socket: p.sockPath}, nil
}

// prepareSocketPath 清理残留 socket 并创建父目录。
func (p *process) prepareSocketPath() error {
	dir := filepath.Dir(p.sockPath)
	if err := os.MkdirAll(dir, socketDirPerm); err != nil {
		return fmt.Errorf("plugin: 创建插件 socket 目录 %s 失败: %w", dir, err)
	}
	// 目录存在但权限过宽时收紧（例如被 umask 或人为改过）。
	// 失败不致命，仅告警：某些文件系统（如只读挂载）无法 chmod。
	if err := os.Chmod(dir, socketDirPerm); err != nil {
		p.logger.Warn("收紧插件 socket 目录权限失败", "dir", dir, "err", err)
	}

	info, err := os.Stat(p.sockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("plugin: 检查 socket 路径 %s 失败: %w", p.sockPath, err)
	}
	// 只删除 socket 类型的文件：万一路径被误配成普通文件，
	// 静默删除可能造成数据丢失，此时应报错让人来看。
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("plugin: socket 路径 %s 已被非 socket 文件占用，请检查配置", p.sockPath)
	}
	if err := os.Remove(p.sockPath); err != nil {
		return fmt.Errorf("plugin: 清理残留 socket %s 失败: %w", p.sockPath, err)
	}
	p.logger.Warn("已清理残留的插件 socket 文件", "plugin", p.desc.ID, "socket", p.sockPath)
	return nil
}

// waitReady 轮询直到 socket 可连接，或进程退出，或 ctx/超时到期。
//
// 三重退出条件缺一不可：
//   - 连上 → 成功；
//   - 进程已退出 → 立即失败（否则要白等满超时）；
//   - 超时或 ctx 取消 → 失败。
//
// done 由调用方传入，避免在等待期间反复加锁读取 p.done。
func (p *process) waitReady(ctx context.Context, done <-chan struct{}) error {
	deadline := time.Now().Add(DefaultStartTimeout)

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		select {
		case <-done:
			// 走到这里进程确已退出，waitErr 已由回收 goroutine 写入。
			return fmt.Errorf("plugin: 插件 %s 进程在就绪前退出: %w", p.desc.ID, p.exitReason())
		case <-ctx.Done():
			return fmt.Errorf("plugin: 等待插件 %s 就绪被取消: %w", p.desc.ID, ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("plugin: 等待插件 %s 就绪超时（%s），最后错误: %v",
					p.desc.ID, DefaultStartTimeout, lastErr)
			}
			conn, err := net.DialTimeout("unix", p.sockPath, 200*time.Millisecond)
			if err != nil {
				lastErr = err
				continue
			}
			_ = conn.Close()
			return nil
		}
	}
}

// doneChan 返回退出通知通道；未启动过时返回一个已关闭的通道，
// 调用方据此无需区分「没启动」与「已退出」。
func (p *process) doneChan() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return p.done
}

// Dial 拨号到插件 socket，返回一条已建立的连接。
// 调用方负责关闭连接。
func (p *process) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p.sockPath)
	if err != nil {
		return nil, fmt.Errorf("plugin: 连接插件 %s 失败: %w", p.desc.ID, err)
	}
	return conn, nil
}

// alive 判断进程是否仍在运行。
func (p *process) alive() bool {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// Stop 优雅停止插件进程：先 SIGTERM，超时后 SIGKILL。
//
// 信号发给整个进程组（负 PID），以覆盖插件自己拉起的子进程。
func (p *process) Stop(timeout time.Duration) error {
	p.mu.Lock()
	cmd, pid, done := p.cmd, p.pid, p.done
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil || done == nil {
		p.cleanupSocket()
		return nil
	}
	if !p.alive() {
		p.cleanupSocket()
		p.clear()
		return nil
	}

	if err := terminateProcess(pid); err != nil && !isProcessGone(err) {
		// 进程可能刚好自己退出了（isProcessGone），那不算错误。
		p.logger.Warn("向插件进程发送终止信号失败", "plugin", p.desc.ID, "pid", pid, "err", err)
	}

	select {
	case <-done:
		p.logger.Info("插件进程已优雅退出", "plugin", p.desc.ID, "pid", pid)
	case <-time.After(timeout):
		// 优雅退出超时：强制杀掉，否则停止接口会一直挂住。
		p.logger.Warn("插件未在超时内退出，发送 SIGKILL",
			"plugin", p.desc.ID, "pid", pid, "timeout", timeout)
		if err := killProcess(pid); err != nil && !isProcessGone(err) {
			p.logger.Warn("强制结束插件进程失败", "plugin", p.desc.ID, "pid", pid, "err", err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("plugin: 插件 %s（pid %d）在 SIGKILL 后仍未退出", p.desc.ID, pid)
		}
	}

	p.cleanupSocket()
	p.clear()
	return nil
}

// kill 是启动失败路径上的强制回收：不等优雅退出，直接杀进程组。
func (p *process) kill() {
	p.mu.Lock()
	cmd, pid, done := p.cmd, p.pid, p.done
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil || done == nil {
		p.cleanupSocket()
		return
	}

	select {
	case <-done:
		// 已经退出，无需再杀。
	default:
		if err := killProcess(pid); err != nil && !isProcessGone(err) {
			p.logger.Warn("回收插件进程失败", "plugin", p.desc.ID, "pid", pid, "err", err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			p.logger.Error("插件进程回收超时", "plugin", p.desc.ID, "pid", pid)
		}
	}

	p.cleanupSocket()
	p.clear()
}

// clear 重置进程句柄，表示当前没有托管中的进程。
func (p *process) clear() {
	p.mu.Lock()
	p.cmd = nil
	p.pid = 0
	p.done = nil
	p.waitErr = nil
	p.startedAt = time.Time{}
	p.mu.Unlock()
}

// cleanupSocket 删除插件留下的 socket 文件。
// 删除失败不返回错误：文件可能已被插件自己清理。
func (p *process) cleanupSocket() {
	if err := os.Remove(p.sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.logger.Debug("清理插件 socket 失败", "plugin", p.desc.ID, "socket", p.sockPath, "err", err)
	}
}

// crashWatcher 在进程退出后异步通知 Manager。
//
// 必须是异步的：Start 的调用方（Manager.Start）随后还要重新加锁，
// 若在此同步等待进程退出，就会把启动接口挂在一个可能永不退出的进程上。
//
// done 在调用时刻一次性捕获：这样即使稍后 Stop 流程调用了 clear()
// （把 p.done 置回 nil），本 goroutine 仍持有正确的通道，不会被漏唤醒。
// 退出原因则通过 exitReason() 读取——它在 <-done 之后调用，
// 此时回收 goroutine 已把 waitErr 写好（写入先于 close(done)，见 Start）。
func (p *process) crashWatcher(onExit func(pluginID string, err error)) {
	done := p.doneChan()

	go func() {
		<-done
		onExit(p.desc.ID, p.exitReason())
	}()
}

// exitReason 返回进程退出原因，供崩溃回调使用。
//
// 前提：调用时进程确已退出（waitErr 已被回收 goroutine 写入）。
// 注意不要用它来判断「是否在运行」——那是 alive() 的职责。
func (p *process) exitReason() error {
	p.mu.Lock()
	err := p.waitErr
	p.mu.Unlock()

	if err == nil {
		return errors.New("进程已正常退出（exit 0）")
	}
	return err
}
