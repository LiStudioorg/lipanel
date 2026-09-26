package ssl

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ============================================================================
// 自动续期调度器（阶段四 4.4）
// ============================================================================
//
// 计划要求「续期（定时或手动）」——本文件实现定时那一半。
//
// #################### 为什么必须做自动续期 ####################
//
// Let's Encrypt 证书只有 90 天有效期。手工续期意味着运维必须
// 记得每 90 天做一次同样的事——而"忘记续期导致 HTTPS 挂掉"
// 是这类面板最常见、也最不应该发生的故障。
//
// #################### 调度器的三个设计决定 ####################
//
// **① 用 ticker 而不是 cron 表达式。**
// 本项目的工程约束是单二进制、零外部依赖（go.mod 只有 2 个依赖）。
// 引入 cron 库只为了"每 12 小时跑一次"，成本收益不成比例。
// 用户真正需要的是"别让它过期"，而不是"精确在凌晨 3:15 执行"。
//
// **② 启动后先等一段时间再跑第一次，而不是立刻跑。**
// 理由：面板启动时可能正在处理更重要的事（加载配置、拉起插件），
// 而一次批量续期会拉起多个 certbot 进程、占用网络与磁盘。
// 更实际的问题是——如果续期配置有误（例如 certbot 路径写错），
// 立刻执行会让**每次重启面板都失败一次**，在审计里刷出一堆
// 无意义的记录。延迟一段时间（默认 1 分钟）足以避开启动高峰。
//
// **③ 绝不并发执行（单 goroutine + 内部锁）。**
// 见 Manager.mu 的说明：并发的 ACME 申请会互相破坏挑战验证。

// RenewSchedulerOptions 是构造调度器的配置。
type RenewSchedulerOptions struct {
	// Manager 是执行续期的管理器（必填）。
	Manager *Manager
	// Interval 是检查间隔；<=0 时用 DefaultRenewInterval。
	Interval time.Duration
	// InitialDelay 是启动后首次执行前的等待时间。
	//
	// ########## 为什么这里需要两个字段 ##########
	//
	// 坑位 12 的同一类问题：Go 里 `0` 是 time.Duration 的零值，
	// 因此「没设置」与「明确要求立即执行」无法区分。
	// 早期实现用 `if delay == 0 { delay = 默认值 }`，结果
	// `InitialDelay: 0`（意图是"立刻执行"）被静默替换成 1 分钟——
	// 表现为调度器"不工作"，而且只有跑测试才会发现。
	//
	// 正确做法与 2.6 处理 CLI 参数时一致：用一个显式的布尔
	// 表达"我确实设置了"，而不是靠零值猜意图。
	InitialDelay time.Duration
	// InitialDelaySet 为 true 时 InitialDelay 被采纳（含 0 = 立即执行）；
	// 为 false 时使用 DefaultInitialDelay。
	InitialDelaySet bool
	// DryRun 为 true 时自动续期也走试运行。
	//
	// ⚠️ 这个开关**只影响命令是否真的签发**，不影响调度逻辑：
	// 我们仍然会按真实条件筛选"哪些证书需要续期"并执行命令，
	// 因此它完整验证了调度链路（筛选、执行、解析、审计），
	// 只是不消耗生产配额。这正是"能不能先试一下"的答案。
	DryRun bool
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// DefaultRenewInterval 是自动续期的默认检查间隔。
//
// 12 小时：Let's Encrypt 建议每天检查两次。
// 更频繁没有收益（证书状态不会在几小时内变化），
// 更稀疏则会拉长"发现问题"到"证书过期"之间的窗口。
const DefaultRenewInterval = 12 * time.Hour

// DefaultInitialDelay 是启动后首次续期检查的延迟。
const DefaultInitialDelay = 1 * time.Minute

// RenewScheduler 周期性地为即将过期的证书执行续期。
type RenewScheduler struct {
	mgr      *Manager
	interval time.Duration
	delay    time.Duration
	dryRun   bool
	logger   *slog.Logger

	// 生命周期控制。
	//
	// 用 cancel + done 的组合而不是只用一个 channel：
	// cancel 让阻塞中的 sleep/ticker 立刻返回，
	// done 让 Close 能确认 goroutine **真的退出了**——
	// 只 cancel 不等待的话，Close 返回后 goroutine 可能仍在
	// 拉起 certbot 进程，而 main 已经开始关闭其它组件。
	// 这正是坑位 16 那类"看起来停了、其实还在跑"的问题。
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	// mu 保护 status 字段。
	mu       sync.Mutex
	runs     int
	lastRun  time.Time
	lastErr  string
	started  bool
	stopped  bool
	renewedN int
}

// NewRenewScheduler 构造调度器（不启动）。
func NewRenewScheduler(opts RenewSchedulerOptions) *RenewScheduler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultRenewInterval
	}
	delay := DefaultInitialDelay
	if opts.InitialDelaySet {
		// 显式设置过：采纳其值（含 0 = 立即执行）。
		delay = opts.InitialDelay
	}
	return &RenewScheduler{
		mgr:      opts.Manager,
		interval: interval,
		delay:    delay,
		dryRun:   opts.DryRun,
		logger:   logger,
		done:     make(chan struct{}),
	}
}

// Start 启动后台调度。
//
// 重复调用是安全的（第二次及以后为 no-op）：
// 调用方（main.go）不该因为"可能被调用两次"而需要自己加判重。
func (s *RenewScheduler) Start(ctx context.Context) {
	if s == nil || s.mgr == nil {
		return
	}
	s.once.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel

		s.mu.Lock()
		s.started = true
		s.mu.Unlock()

		go s.loop(runCtx)
		s.logger.Info("证书自动续期调度已启动",
			"interval", s.interval.String(),
			"initial_delay", s.delay.String(),
			"renew_days", s.mgr.RenewDays(),
			"dry_run", s.dryRun)
	})
}

// loop 是调度主循环。
func (s *RenewScheduler) loop(ctx context.Context) {
	defer close(s.done)

	// ---------- 首次执行前的延迟 ----------
	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	// ---------- 立即跑一次，然后按间隔执行 ----------
	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("证书自动续期调度已停止")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce 执行一轮续期检查。
//
// 本轮失败**不会停止调度**：一次网络抖动不应该让自动续期
// 永久失效（那样用户会在 30 天后收到一个"证书已过期"的意外）。
// 失败会被记录到状态里，通过 Stats() 暴露。
func (s *RenewScheduler) runOnce(ctx context.Context) {
	start := time.Now()

	// 未到续期窗口的证书会被 RenewAll 内部筛掉，
	// 因此频繁调用不会消耗配额。
	results, err := s.mgr.RenewAll(ctx)

	renewed := 0
	for _, r := range results {
		if r.Renewed {
			renewed++
		}
	}

	s.mu.Lock()
	s.runs++
	s.lastRun = start
	s.renewedN += renewed
	if err != nil {
		s.lastErr = err.Error()
	} else {
		s.lastErr = ""
	}
	s.mu.Unlock()

	if err != nil {
		s.logger.Warn("自动续期检查失败（将于下个周期重试）",
			"err", err, "duration_ms", time.Since(start).Milliseconds())
		return
	}
	s.logger.Info("自动续期检查完成",
		"candidates", len(results), "renewed", renewed,
		"duration_ms", time.Since(start).Milliseconds())
}

// Close 停止调度并等待 goroutine 退出。
//
// 幂等：重复调用返回 nil（与各 Auditor.Close 的约定一致）。
func (s *RenewScheduler) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.started {
		// 从未启动：直接标记为已停止，不等待也不 panic。
		s.stopped = true
		s.mu.Unlock()
		return nil
	}
	alreadyStopped := s.stopped
	s.stopped = true
	s.mu.Unlock()

	if alreadyStopped {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	// 等待 goroutine 真正退出（它不是 nil：Start 里必然赋值）。
	<-s.done
	return nil
}

// RenewSchedulerStats 是调度器的运行状态（供 /api/ssl/capabilities 展示）。
type RenewSchedulerStats struct {
	// Running 表示调度器是否在运行。
	Running bool `json:"running"`
	// Interval 是检查间隔（人类可读）。
	Interval string `json:"interval,omitempty"`
	// Runs 是已执行的检查轮数。
	Runs int `json:"runs"`
	// RenewedTotal 是累计成功续期的证书数。
	RenewedTotal int `json:"renewed_total"`
	// LastRun 是上次检查时间（RFC3339）。
	LastRun string `json:"last_run,omitempty"`
	// LastError 是上次检查的错误（为空表示正常）。
	LastError string `json:"last_error,omitempty"`
	// DryRun 表示自动续期是否处于试运行模式。
	DryRun bool `json:"dry_run"`
}

// Stats 返回调度器状态快照。
func (s *RenewScheduler) Stats() RenewSchedulerStats {
	if s == nil {
		return RenewSchedulerStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st := RenewSchedulerStats{
		Running:      s.started && !s.stopped,
		Interval:     s.interval.String(),
		Runs:         s.runs,
		RenewedTotal: s.renewedN,
		LastError:    s.lastErr,
		DryRun:       s.dryRun,
	}
	if !s.lastRun.IsZero() {
		st.LastRun = s.lastRun.Format(time.RFC3339)
	}
	return st
}
