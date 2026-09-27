package store

import (
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// 安装/卸载任务模型（异步执行 + 进度查询）
// ============================================================================
//
// ########## 为什么必须异步 ##########
//
// 装一个 MySQL 在真实机器上要 30 秒到 5 分钟（下载 + 解包 + postinst
// 初始化数据目录）。若接口同步等待：
//
//	① 反向代理（nginx 默认 60s）会先超时，用户看到 502，
//	   而机器上 dpkg 还在跑——用户以为失败了，再点一次，
//	   于是两个 apt 进程抢 dpkg 锁，双双失败；
//	② 进度完全不可见。用户唯一能做的就是刷新页面等结果。
//
// 因此安装/卸载一律**立即返回一个任务 ID**（HTTP 202），
// 真实执行在后台 goroutine 里进行，前端轮询进度接口。
//
// ########## 为什么用轮询而不是 SSE ##########
//
// 计划给出的是"SSE 或轮询，先用轮询，简单"。选轮询的实际理由：
//
//	· 安装日志是**追加**语义，轮询带 since 游标即可增量拉取，
//	  与 SSE 的体验差距很小（1.5s 一次）；
//	· 面板可能被放在任意反向代理后面，SSE 需要额外的
//	  proxy_buffering off / X-Accel-Buffering 配置，
//	  而这些配置在 4.3 里由面板自己生成——增加一处跨模块耦合；
//	· 轮询是无状态的：面板重启后前端刷新一下就能继续看到状态，
//	  而 SSE 断线需要重连与补偿逻辑。
//
// 任务状态保存在内存里（环形保留最近 N 个）：面板重启后
// 运行中的任务会丢失。这是**刻意的**——apt/dpkg 的子进程
// 会随面板一起被终止（进程组），保留一个"上一辈子的任务"
// 只会让用户困惑。历史留痕由审计日志承担。

// 任务类型。
const (
	// TaskInstall 是安装任务。
	TaskInstall = "install"
	// TaskUninstall 是卸载任务。
	TaskUninstall = "uninstall"
)

// 任务状态。
const (
	// TaskPending 表示任务已创建、尚未开始执行（等前一个任务让出锁）。
	TaskPending = "pending"
	// TaskRunning 表示任务正在执行。
	TaskRunning = "running"
	// TaskSucceeded 表示任务成功完成。
	TaskSucceeded = "succeeded"
	// TaskFailed 表示任务失败（含"所有策略都失败"）。
	TaskFailed = "failed"
)

// 步骤状态。
const (
	// StepPending 表示尚未执行。
	StepPending = "pending"
	// StepRunning 表示执行中。
	StepRunning = "running"
	// StepSucceeded 表示成功。
	StepSucceeded = "succeeded"
	// StepFailed 表示失败。
	StepFailed = "failed"
	// StepSkipped 表示被跳过（前序步骤已成功、环境不支持等）。
	StepSkipped = "skipped"
)

// 日志行级别。
const (
	// LogInfo 是普通说明。
	LogInfo = "info"
	// LogStep 是步骤边界标记。
	LogStep = "step"
	// LogCommand 是要执行的命令（脱敏后）。
	LogCommand = "command"
	// LogStdout 是命令的标准输出。
	LogStdout = "stdout"
	// LogStderr 是命令的标准错误。
	LogStderr = "stderr"
	// LogError 是错误。
	LogError = "error"
	// LogWarn 是告警（例如某条策略不可用而继续尝试下一条）。
	LogWarn = "warn"
)

// LogLine 是任务日志的一行。
//
// Seq 是**任务内**自增序号，前端用它做增量拉取（?since=N）。
// 不做全局序号：一个任务的日志必须能独立重放。
type LogLine struct {
	Seq  int    `json:"seq"`
	Time string `json:"time"`
	// Level 见 Log* 常量。
	Level string `json:"level"`
	// Step 是当前步骤名（便于前端分组展示）。
	Step string `json:"step,omitempty"`
	// Text 是日志正文。
	Text string `json:"text"`
}

// StepState 是一个策略步骤的执行状态。
type StepState struct {
	// Name 是步骤名（人类可读）。
	Name string `json:"name"`
	// Key 是稳定标识（前端做图标映射用）：system / official / prebuilt / ...
	Key string `json:"key"`
	// Status 见 Step* 常量。
	Status string `json:"status"`
	// Commands 是这一步执行过的命令（脱敏文本，便于复现）。
	Commands []string `json:"commands,omitempty"`
	// Reason 是跳过或失败的原因。
	Reason string `json:"reason,omitempty"`
	// StartedAt / FinishedAt 是步骤时间。
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	// DurationMS 是步骤耗时。
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Task 是一个安装/卸载任务的状态快照。
//
// 它是只读快照：由 Manager 在锁内构造，调用方拿到后可以随意传递。
type Task struct {
	// ID 是任务标识（进程内自增，形如 "t1"）。
	ID string `json:"id"`
	// Kind 见 Task* 常量。
	Kind string `json:"kind"`
	// Software / SoftwareName 是软件 ID 与展示名。
	Software     string `json:"software"`
	SoftwareName string `json:"software_name,omitempty"`
	// Version 是版本 ID（卸载时可能为空，表示"卸载已安装的那个"）。
	Version string `json:"version,omitempty"`
	// Status 见 Task* 常量。
	Status string `json:"status"`
	// Stage 是当前阶段的说明（前端直接显示）。
	Stage string `json:"stage,omitempty"`
	// Progress 是 0~100 的进度（按策略阶段估算，**单调不减**）。
	Progress int `json:"progress"`
	// Steps 是各策略步骤的状态。
	Steps []StepState `json:"steps"`
	// Strategy 是最终实际生效的策略（system / official / prebuilt）。
	Strategy string `json:"strategy,omitempty"`
	// Packages 是实际下发的包名列表。
	Packages []string `json:"packages,omitempty"`
	// PrebuiltURL 是预编译兜底时下载的归档地址。
	PrebuiltURL string `json:"prebuilt_url,omitempty"`
	// Dependencies 是本次自动补齐的依赖（若有）。
	Dependencies []string `json:"dependencies,omitempty"`
	// Error 是失败原因（失败时非空）。
	Error string `json:"error,omitempty"`
	// Hint 是"怎么办"的提示。
	Hint string `json:"hint,omitempty"`
	// Output 是最后一次命令输出的摘要（便于前端直接展示）。
	Output string `json:"output,omitempty"`
	// User / ClientIP 是发起者（审计与排障）。
	User     string `json:"user,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	// CreatedAt / StartedAt / FinishedAt 是任务时间线。
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	// DurationMS 是任务总耗时（未结束时为已耗时）。
	DurationMS int64 `json:"duration_ms"`
	// LogTotal 是日志总行数（前端据此判断是否还有新行）。
	LogTotal int `json:"log_total"`
	// LogDropped 是被环形缓冲丢弃的早期日志行数。
	LogDropped int `json:"log_dropped"`
	// Simulated 标记本次任务运行在**模拟模式**下（-store-dry-run）。
	Simulated bool `json:"simulated,omitempty"`
}

// taskState 是任务的内部状态（含日志缓冲）。
type taskState struct {
	mu   sync.Mutex
	t    Task
	logs []LogLine
	seq  int
	// logLimit 是日志环形缓冲上限（来自 Manager 配置）。
	logLimit int
	// dropped 是被丢弃的早期日志行数。
	dropped int
	// startedAt 是任务**真正开始执行**的时间（用于算 DurationMS）。
	startedAt time.Time

	// done 在任务进入终态时关闭（供测试等待任务结束）。
	done chan struct{}
}

// snapshot 返回任务当前状态的只读快照。
func (ts *taskState) snapshot() Task {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.cloneLocked()
}

// cloneLocked 在持锁状态下复制任务（含 Steps 切片）。
func (ts *taskState) cloneLocked() Task {
	out := ts.t
	// 深拷贝切片，避免调用方拿到内部切片后被后续 append 影响
	// （快照必须是"某一瞬间"的确定状态）。
	out.Steps = append([]StepState(nil), ts.t.Steps...)
	out.Packages = append([]string(nil), ts.t.Packages...)
	out.Dependencies = append([]string(nil), ts.t.Dependencies...)
	out.LogTotal = ts.seq
	out.LogDropped = ts.dropped
	return out
}

// appendLog 追加一行日志。
//
// 日志缓冲是**环形**的：装一次 MySQL 的输出可能上万行
// （下载进度条每 1% 一行），无上限会让内存随任务数增长。
// 丢弃的是最早的日志（Oneshot 的错误通常在最后，但
// 出错时的完整上下文我们用 res.Combined() 单独保存到 Output 里，
// 因此丢早期行不会让排障失去关键信息）。
func (ts *taskState) appendLog(level, step, text string) {
	if text == "" {
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.seq++
	line := LogLine{
		Seq:   ts.seq,
		Time:  time.Now().Format(time.RFC3339),
		Level: level,
		Step:  step,
		Text:  text,
	}
	if len(ts.logs) >= ts.logLimit {
		// 丢弃最早的一行（保留最近 logLimit 行）。
		copy(ts.logs, ts.logs[1:])
		ts.logs[len(ts.logs)-1] = line
		ts.dropped++
	} else {
		ts.logs = append(ts.logs, line)
	}
	ts.t.LogTotal = ts.seq
	ts.t.LogDropped = ts.dropped
}

// logsSince 返回序号大于 since 的日志行。
func (ts *taskState) logsSince(since int) []LogLine {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if since < 0 {
		since = 0
	}
	out := make([]LogLine, 0, 16)
	for _, l := range ts.logs {
		if l.Seq > since {
			out = append(out, l)
		}
	}
	return out
}

// setProgress 更新进度（**单调不减**）。
//
// 单调性是硬要求：安装流程中"官方源失败后回落到预编译"这类
// 分支会让阶段序号回退，如果直接赋值，用户会看到进度条
// 从 70% 跳回 30%——那看起来像卡死重来，而不是"换了一条路"。
func (ts *taskState) setProgress(p int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	if p > ts.t.Progress {
		ts.t.Progress = p
	}
}

// setStage 更新当前阶段说明。
func (ts *taskState) setStage(stage string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Stage = stage
}

// setStrategy 记录最终生效的策略。
func (ts *taskState) setStrategy(strategy string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Strategy = strategy
}

// setPackages 记录实际下发的包名。
func (ts *taskState) setPackages(pkgs []string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Packages = append([]string(nil), pkgs...)
}

// setPrebuiltURL 记录预编译归档地址。
func (ts *taskState) setPrebuiltURL(url string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.PrebuiltURL = url
}

// setOutput 记录最后一次命令输出的摘要。
func (ts *taskState) setOutput(out string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Output = out
}

// fail 把任务置为失败并记录原因。
func (ts *taskState) fail(err error, hint string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Status = TaskFailed
	if err != nil {
		ts.t.Error = err.Error()
	}
	ts.t.Hint = hint
	ts.t.FinishedAt = time.Now().Format(time.RFC3339)
	ts.t.DurationMS = time.Since(ts.startedAt).Milliseconds()
	ts.t.Stage = "失败"
}

// succeed 把任务置为成功。
func (ts *taskState) succeed() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Status = TaskSucceeded
	ts.t.Progress = 100
	ts.t.FinishedAt = time.Now().Format(time.RFC3339)
	ts.t.DurationMS = time.Since(ts.startedAt).Milliseconds()
}

// addStep 追加一个步骤并返回其索引。
func (ts *taskState) addStep(key, name string) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Steps = append(ts.t.Steps, StepState{Key: key, Name: name, Status: StepPending})
	return len(ts.t.Steps) - 1
}

// stepStart 标记步骤开始。
func (ts *taskState) stepStart(idx int, name string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if idx < 0 || idx >= len(ts.t.Steps) {
		return
	}
	ts.t.Steps[idx].Status = StepRunning
	ts.t.Steps[idx].StartedAt = time.Now().Format(time.RFC3339)
	if name != "" {
		ts.t.Steps[idx].Name = name
	}
}

// stepCommand 记录步骤执行的一条命令。
func (ts *taskState) stepCommand(idx int, cmd string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if idx < 0 || idx >= len(ts.t.Steps) {
		return
	}
	ts.t.Steps[idx].Commands = append(ts.t.Steps[idx].Commands, cmd)
}

// stepDone 标记步骤结束（ok=false 时记失败原因）。
func (ts *taskState) stepDone(idx int, ok bool, reason string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if idx < 0 || idx >= len(ts.t.Steps) {
		return
	}
	if ok {
		ts.t.Steps[idx].Status = StepSucceeded
	} else {
		ts.t.Steps[idx].Status = StepFailed
	}
	ts.t.Steps[idx].Reason = reason
	ts.t.Steps[idx].FinishedAt = time.Now().Format(time.RFC3339)
	if s, err := time.Parse(time.RFC3339, ts.t.Steps[idx].StartedAt); err == nil {
		ts.t.Steps[idx].DurationMS = time.Since(s).Milliseconds()
	}
}

// stepSkip 标记步骤被跳过并记原因。
func (ts *taskState) stepSkip(idx int, reason string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if idx < 0 || idx >= len(ts.t.Steps) {
		return
	}
	ts.t.Steps[idx].Status = StepSkipped
	ts.t.Steps[idx].Reason = reason
}

// markStatus 直接设置任务状态（仅内部使用）。
func (ts *taskState) markStatus(status string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.t.Status = status
}

// summary 返回"步骤:结果"的紧凑摘要（写审计用）。
func (ts *taskState) summary() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]string, 0, len(ts.t.Steps))
	for _, s := range ts.t.Steps {
		if s.Status == StepPending {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", s.Key, s.Status))
	}
	return out
}
