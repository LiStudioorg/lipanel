package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 软件商店操作审计（阶段四 4.5）
// ============================================================================
//
// 与本项目其它五个审计器（plugin 3.3 / service 4.1 / file 4.2 /
// site 4.3 / ssl 4.4）完全同构：**统一落盘、分别查询**。
//
//	落盘：写入同一个 -audit-log 文件（JSONL，一行一条），
//	      一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//	查询：独立类型、独立环形缓冲、独立查询接口（/api/store/audit），互不污染。
//
// 用 Kind="store" 与 Source="core" 区分来源，**不伪造插件 ID**。
//
// #################### 本模块审计的独有重点：可还原"装了什么" ####################
//
// 包管理器的操作**没有天然的撤销**：装上 MySQL 之后，
// "谁装的、什么时候、装的哪个版本、走的哪条源、装的哪些包"
// 只存在于两个地方——syslog 里的 dpkg 日志（会被轮转掉），
// 以及我们自己的审计。
//
// 因此每条安装/卸载记录都带上：
//
//	Version   —— 用户选择的版本
//	Strategy  —— 最终**实际生效**的策略（system / official / prebuilt）
//	Packages  —— 实际下发的包名列表（或预编译包的 URL）
//	TaskID    —— 指向任务详情（含完整命令与输出）
//
// 于是事后一句 jq 就能回答"这台机器上的 Redis 是怎么来的"：
//
//	jq 'select(.kind=="store" and .target=="redis" and .action=="install")'

// 审计结果三态，与其它五个审计器保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或输入校验拒绝，**未触碰任何外部命令**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败（包管理器报错等）。
	AuditFailed = "failed"
	// AuditPending 表示操作已发起但尚未结束（异步任务的"进行中"）。
	//
	// 单独立一个状态而不是归入 allowed：安装是异步的，
	// 请求返回 202 时命令**还没跑完**。若记成 allowed，
	// 事后按 allowed 筛"装成功过什么"会把失败的任务也算进去。
	AuditPending = "pending"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindStore 是本模块写入事件的类别标记。
const KindStore = "store"

// 安装策略标识（审计里记录**最终生效**的那一条）。
const (
	// StrategySystem 表示系统源里直接装上了。
	StrategySystem = "system"
	// StrategyOfficial 表示走了官方源（ondrej/php、NodeSource 等）。
	StrategyOfficial = "official"
	// StrategyPrebuilt 表示降级到预编译包。
	StrategyPrebuilt = "prebuilt"
	// StrategyNone 表示没有策略成功（失败记录用）。
	StrategyNone = ""
)

// AuditEvent 是一条软件商店操作审计记录。
//
// 字段刻意保持扁平：它会以 JSONL 形式落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别（固定为 "store"）。
	Kind string `json:"kind"`
	// Source 标记事件由谁产生（核心自带能力固定为 "core"）。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——审计的核心字段。
	User string `json:"user,omitempty"`
	// Action 是操作类型：install / uninstall / list / capabilities / task。
	Action string `json:"action"`
	// Target 是被操作的软件 ID（如 php、nginx）。
	Target string `json:"target"`
	// Version 是用户选择的版本 ID。
	Version string `json:"version,omitempty"`
	// Required 是本次操作所需的权限（被拒绝时尤其重要）。
	Required string `json:"required,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed / AuditPending。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// DurationMS 是处理耗时（毫秒）。
	//
	// 对异步任务而言它是**任务总耗时**（不是请求耗时）：
	// 请求本身几毫秒就返回了 202，而有价值的数字是"装这个包花了多久"。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因（含包管理器的原始报错摘要）。
	Reason string `json:"reason,omitempty"`
	// TaskID 指向任务详情（GET /api/store/tasks/{id}）。
	//
	// 审计里只放摘要是有意的：完整命令与输出有几百 KB，
	// 全塞进 JSONL 会让审计文件迅速膨胀到不可读。
	TaskID string `json:"task_id,omitempty"`
	// Strategy 是最终实际生效的安装策略（system / official / prebuilt）。
	Strategy string `json:"strategy,omitempty"`
	// Packages 是实际下发的包名列表（预编译兜底时为空）。
	Packages []string `json:"packages,omitempty"`
	// PrebuiltURL 是预编译兜底时下载的归档地址。
	PrebuiltURL string `json:"prebuilt_url,omitempty"`
	// Steps 是执行过的策略步骤摘要（如 ["system:fail","official:ok"]）。
	//
	// 它回答的是"为什么装得这么慢/为什么动了官方源"这类问题——
	// 排查一次失败安装时，最有用的信息往往是"它试过哪几条路"。
	Steps []string `json:"steps,omitempty"`
	// SystemChange 标记本次操作**改变了系统软件构成**。
	//
	// 与 Outcome 正交：被拒绝的安装请求 Outcome=denied 且
	// SystemChange=false；一次失败但已经把源文件写进去的安装
	// 则是 failed + true。运维按 `select(.system_change)` 就能
	// 捞出所有真正动过系统的记录。
	SystemChange bool `json:"system_change,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与其它五个审计器**同一个** -audit-log 路径。
	Path string
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// DefaultAuditCapacity 是内存环形缓冲的默认容量。
const DefaultAuditCapacity = 1000

// DefaultAuditQueryLimit 是审计查询的默认返回条数。
const DefaultAuditQueryLimit = 100

// MaxAuditQueryLimit 是单次查询能取到的最大条数。
const MaxAuditQueryLimit = 1000

// Auditor 收集并保存软件商店操作审计记录。
type Auditor struct {
	capacity int
	logger   *slog.Logger

	mu     sync.Mutex
	ring   []AuditEvent
	total  uint64
	seq    uint64
	file   *os.File
	writeW int
	path   string
}

// NewAuditor 构造审计器。
//
// 落盘路径打不开时返回错误（不静默降级）：用户显式配置了 -audit-log
// 却因为目录不可写而悄悄不记录，是最糟的失败方式。
func NewAuditor(opts AuditOptions) (*Auditor, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = DefaultAuditCapacity
	}

	a := &Auditor{
		capacity: capacity,
		logger:   logger,
		ring:     make([]AuditEvent, 0, capacity),
	}
	if opts.Path != "" {
		if err := a.openFile(opts.Path); err != nil {
			return nil, err
		}
		logger.Info("软件商店操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与其它五个审计器共用同一文件时的安全性：所有写入方都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("store: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("store: 打开审计日志 %s 失败: %w", path, err)
	}
	a.file = f
	a.path = path
	return nil
}

// Record 写入一条审计记录。
//
// 与其它审计器同样的取舍：**不返回错误**。审计是旁路能力，
// 它的失败绝不能影响用户的操作本身。落盘失败会被计数并告警，
// 通过 Stats() 暴露给运维排查。
func (a *Auditor) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339Nano)
	}
	if ev.Kind == "" {
		ev.Kind = KindStore
	}
	if ev.Source == "" {
		ev.Source = SourceCore
	}
	if ev.Outcome == "" {
		ev.Outcome = AuditAllowed
	}
	if ev.SystemChange == false {
		// ########## pending 不算"已改系统" ##########
		//
		// 安装是异步的：API 返回 202 时命令还没跑完，系统构成此刻
		// **尚未**改变。若把 pending 也标成 system_change，
		// 一次最终失败、什么都没装上的任务会出现在
		// `select(.system_change)` 的结果里，让"到底动过什么"
		// 这个最需要准确的问题变得不可信。
		ev.SystemChange = WritesSystem(ev.Action) &&
			ev.Outcome != AuditDenied && ev.Outcome != AuditPending
	}

	a.mu.Lock()
	a.seq++
	ev.Seq = a.seq
	a.total++

	if len(a.ring) < a.capacity {
		a.ring = append(a.ring, ev)
	} else {
		copy(a.ring, a.ring[1:])
		a.ring[len(a.ring)-1] = ev
	}

	var line []byte
	if a.file != nil {
		if b, err := json.Marshal(ev); err == nil {
			line = append(b, '\n')
		}
	}
	file := a.file
	path := a.path
	a.mu.Unlock()

	if line == nil || file == nil {
		return
	}
	if _, err := file.Write(line); err != nil {
		a.mu.Lock()
		a.writeW++
		a.mu.Unlock()
		a.logger.Warn("写出软件商店审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// Target 非空时只返回该软件的记录。
	Target string
	// Version 非空时只返回该版本的记录。
	Version string
	// User 非空时只返回该用户发起的记录。
	User string
	// Action 非空时只返回该动作的记录。
	Action string
	// Outcome 非空时只返回该结果的记录。
	Outcome string
	// Limit 是返回条数上限；<=0 时用 DefaultAuditQueryLimit。
	Limit int
}

// Query 按过滤条件返回审计记录（按时间倒序，最新在前）。
func (a *Auditor) Query(f AuditFilter) []AuditEvent {
	if a == nil {
		return []AuditEvent{}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAuditQueryLimit
	}
	if limit > MaxAuditQueryLimit {
		limit = MaxAuditQueryLimit
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]AuditEvent, 0, limit)
	target := strings.TrimSpace(f.Target)
	version := strings.TrimSpace(f.Version)
	user := strings.TrimSpace(f.User)
	action := strings.TrimSpace(f.Action)
	outcome := strings.TrimSpace(f.Outcome)

	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if target != "" && ev.Target != target {
			continue
		}
		if version != "" && ev.Version != version {
			continue
		}
		if user != "" && ev.User != user {
			continue
		}
		if action != "" && ev.Action != action {
			continue
		}
		if outcome != "" && ev.Outcome != outcome {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// AuditStats 是审计器的运行状态。
type AuditStats struct {
	Total uint64 `json:"total"`
	// Retained 是当前内存中保留的条数。
	Retained int `json:"retained"`
	Capacity int `json:"capacity"`
	// Denied 是内存中保留的拒绝条数，用于前端醒目标红。
	Denied int `json:"denied"`
	// Failed 是内存中保留的执行失败条数。
	Failed int `json:"failed"`
	// Pending 是仍在进行中的任务数。
	Pending int `json:"pending"`
	// Installed / Uninstalled 是成功的安装/卸载次数。
	Installed   int `json:"installed"`
	Uninstalled int `json:"uninstalled"`
	// PersistPath 是落盘路径（未启用时为空）。
	PersistPath string `json:"persist_path,omitempty"`
	// WriteErrors 是落盘失败累计次数（>0 说明审计留痕不完整）。
	WriteErrors int `json:"write_errors"`
}

// Stats 返回审计器状态快照。
func (a *Auditor) Stats() AuditStats {
	if a == nil {
		return AuditStats{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	st := AuditStats{
		Total:       a.total,
		Retained:    len(a.ring),
		Capacity:    a.capacity,
		PersistPath: a.path,
		WriteErrors: a.writeW,
	}
	for _, ev := range a.ring {
		switch ev.Outcome {
		case AuditDenied:
			st.Denied++
		case AuditFailed:
			st.Failed++
		case AuditPending:
			st.Pending++
		}
		if ev.Outcome == AuditAllowed && ev.Action == ActionInstall {
			st.Installed++
		}
		if ev.Outcome == AuditAllowed && ev.Action == ActionUninstall {
			st.Uninstalled++
		}
	}
	return st
}

// Close 关闭审计日志文件。未启用落盘或重复调用都返回 nil（幂等）。
func (a *Auditor) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	if err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("store: 关闭审计日志失败: %w", err)
	}
	return nil
}

// ExportAuditJSONL 把内存中的审计记录以 JSONL 写出（按时间正序），
// 供测试与排查使用。
func (a *Auditor) ExportAuditJSONL(w interface{ Write([]byte) (int, error) }) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	events := make([]AuditEvent, len(a.ring))
	copy(events, a.ring)
	a.mu.Unlock()

	sort.SliceStable(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	enc := json.NewEncoder(w)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("store: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
