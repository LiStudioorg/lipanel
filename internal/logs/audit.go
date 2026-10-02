package logs

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ============================================================================
// 日志查看审计（阶段五 5.4.1）
// ============================================================================
//
// 记录「谁、在何时、查了哪个日志源、结果如何」。查询日志本身不产生副作用，
// 但「谁在半夜翻看了生产站点的错误日志」对排障与安全同样有价值——
// 尤其是**越权探测**（未被授权却反复 query），必须留痕。
//
// 与插件审计（internal/plugin/audit.go）、服务审计（internal/service/audit.go）
// 同构：独立类型 + 独立环形缓冲 + 独立查询接口，但共用同一份 -audit-log
// JSONL 文件（统一落盘、分别查询）。

// 审计结果三态（与其它模块保持同名同义）。
const (
	AuditAllowed = "allowed"
	AuditDenied  = "denied"
	AuditFailed  = "failed"
)

// SourceCore 是核心自带能力发起的事件来源标记。
const SourceCore = "core"

// AuditEvent 是一条日志查看审计记录。
type AuditEvent struct {
	Seq    uint64 `json:"seq"`
	Time   string `json:"time"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
	User   string `json:"user,omitempty"`
	Action string `json:"action"`
	// SourceID 是被查看的日志源 ID（system / nginx-access / nginx-error）。
	SourceID string `json:"source_id,omitempty"`
	// Query 是查询参数的脱敏摘要（行数+关键词+级别），**绝不包含敏感内容**
	// （关键词本身可能是日志关键字，这里如实记录用于排障，非凭据）。
	Query      string `json:"query,omitempty"`
	Required   string `json:"required,omitempty"`
	Outcome    string `json:"outcome"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Returned 是返回给前端的行数。
	Returned int `json:"returned,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	Capacity int
	Path     string
	Logger   *slog.Logger
}

// DefaultAuditCapacity 是默认环形缓冲容量。
const DefaultAuditCapacity = 1000

// Auditor 收集并保存日志查看审计记录。
type Auditor struct {
	capacity int
	logger   *slog.Logger

	mu    sync.Mutex
	ring  []AuditEvent
	total uint64
	seq   uint64
	file  *os.File
	path  string
}

// NewAuditor 构造审计器。
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
		logger.Info("日志查看审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("logs: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("logs: 打开审计日志 %s 失败: %w", path, err)
	}
	a.file = f
	a.path = path
	return nil
}

// Record 追加一条审计事件。
func (a *Auditor) Record(ev AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.seq++
	ev.Seq = a.seq
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339)
	}
	if ev.Kind == "" {
		ev.Kind = "log"
	}
	if ev.Source == "" {
		ev.Source = SourceCore
	}

	if len(a.ring) >= a.capacity {
		// 淘汰最旧。
		copy(a.ring, a.ring[1:])
		a.ring = a.ring[:len(a.ring)-1]
	}
	a.ring = append(a.ring, ev)
	a.total++

	if a.file != nil {
		if err := a.writeFile(ev); err != nil {
			// 写失败只告警，绝不影响请求本身。
			a.logger.Warn("写日志查看审计落盘失败", "err", err)
		}
	}
}

func (a *Auditor) writeFile(ev AuditEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := a.file.Write(b); err != nil {
		return err
	}
	return nil
}

// AuditStats 返回审计统计，供状态接口展示。
type AuditStats struct {
	Total   uint64 `json:"total"`
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
	Failed  uint64 `json:"failed"`
}

// Stats 计算审计统计。
func (a *Auditor) Stats() AuditStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	var st AuditStats
	st.Total = a.total
	for _, ev := range a.ring {
		switch ev.Outcome {
		case AuditAllowed:
			st.Allowed++
		case AuditDenied:
			st.Denied++
		case AuditFailed:
			st.Failed++
		}
	}
	return st
}

// AuditQuery 是审计查询参数。
type AuditQuery struct {
	Limit   int
	Outcome string
}

// List 返回审计记录（新的在前），按 limit 截断。
func (a *Auditor) List(q AuditQuery) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	limit := q.Limit
	if limit <= 0 {
		limit = DefaultAuditCapacity
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}

	out := make([]AuditEvent, 0, len(a.ring))
	for i := len(a.ring) - 1; i >= 0; i-- {
		ev := a.ring[i]
		if q.Outcome != "" && ev.Outcome != q.Outcome {
			continue
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// MaxQueryLimit 是单次可返回的审计条数上限。
const MaxQueryLimit = 1000

// Close 关闭审计文件。
func (a *Auditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		err := a.file.Close()
		a.file = nil
		return err
	}
	return nil
}
