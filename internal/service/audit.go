package service

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
// 服务操作审计（阶段四 4.1）
// ============================================================================
//
// 目标：记录「**谁**、在**何时**、对**哪个服务**做了什么、结果如何」。
// 这是计划里 3.4 条「操作审计日志」的落地，也是本阶段最有运维价值的产出：
// 「是谁在凌晨三点重启了数据库」这类问题的答案就在这里。
//
// 与插件审计（internal/plugin/audit.go）的关系——「统一落盘、分别查询」：
//
//   - **统一落盘**：两者写入同一个 -audit-log 文件（JSONL，一行一条），
//     便于用一套日志采集器、一条 `tail -f`、一个 `jq` 查询覆盖全部操作留痕。
//   - **分别查询**：各有独立的类型、独立的环形缓冲、独立的查询接口
//     （/api/services/audit 与 /api/plugins/audit），互不污染。
//
// 为什么不复用 plugin.AuditEvent 并伪造一个 Plugin 字段：
// 插件审计以 Plugin 为主键（CountByPlugin、?plugin= 过滤都基于它），
// 若把服务操作塞成 Plugin: "core:systemd"，插件审计页就会冒出一个
// 根本不存在的「插件」，统计也随之失真。**为了复用而扭曲业务语义，
// 代价远大于写这几十行代码。**
//
// 记录类型独立不阻碍统一落盘：两者都是「带 time/outcome 的扁平 JSON 对象」，
// 采集器按字段区分即可（服务事件有 target 字段，插件事件有 plugin 字段）。

// 审计结果三态。与插件审计保持同名同义，便于统一检索。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示操作被权限校验拒绝，**未执行任何 systemctl 命令**。
	AuditDenied = "denied"
	// AuditFailed 表示操作已尝试执行但失败（服务不存在、超时等）。
	AuditFailed = "failed"
)

// AuditEvent 是一条服务操作审计记录。
//
// 字段刻意保持扁平：它会以 JSONL 形式落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序（同一毫秒内的多条也能定序）。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别，用于在同一份 JSONL 里区分来源。
	// 服务事件固定为 "service"，插件事件为 "plugin"（由插件审计写入）。
	Kind string `json:"kind"`
	// User 是**发起操作的登录用户名**——审计的核心字段，
	// 直接回答「谁干的」。未登录调用（理论不可达，接口均有鉴权）为空。
	User string `json:"user,omitempty"`
	// Action 是操作类型：start / stop / restart。
	Action string `json:"action"`
	// Target 是被操作的服务名，例如 nginx.service。
	Target string `json:"target"`
	// Required 是本次操作所需的权限（被拒绝时尤其重要）。
	Required string `json:"required,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// DurationMS 是处理耗时（毫秒）。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因。
	Reason string `json:"reason,omitempty"`
	// StateAfter 是操作后服务的归一化状态（成功时才有意义）。
	StateAfter string `json:"state_after,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与插件审计**同一个** -audit-log 路径。
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

// Auditor 收集并保存服务操作审计记录。
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
		logger.Info("服务操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 注意与插件审计共用同一文件时的安全性：两边都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性，
// 前提是单次 write 不超过 PIPE_BUF 的常识性约束，本场景单行仅数百字节）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 0700：审计日志含操作者与服务名，不该被别人读。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("service: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	// 0600 + 追加写：只应属主可读，且绝不覆盖历史记录。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("service: 打开审计日志 %s 失败: %w", path, err)
	}
	a.file = f
	a.path = path
	return nil
}

// Record 写入一条审计记录。
//
// 与插件审计同样的取舍：**不返回错误**。审计是旁路能力，
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
		ev.Kind = "service"
	}
	if ev.Outcome == "" {
		ev.Outcome = AuditAllowed
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
	// 单次 write：与插件审计共用文件时靠 O_APPEND 保证不交错。
	if _, err := file.Write(line); err != nil {
		a.mu.Lock()
		a.writeW++
		a.mu.Unlock()
		a.logger.Warn("写出服务审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// Target 非空时只返回该服务的记录。
	Target string
	// User 非空时只返回该用户发起的记录。
	User string
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
	user := strings.TrimSpace(f.User)
	outcome := strings.TrimSpace(f.Outcome)

	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if target != "" && ev.Target != target {
			continue
		}
		if user != "" && ev.User != user {
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
		return fmt.Errorf("service: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("service: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
