package notify

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
// 通知渠道审计（阶段五 5.4.2）
// ============================================================================
//
// 记录渠道的增删改、测试/实际发送等动作。**凭证一个字都不进审计**
// （webhook 地址、SMTP 密码、token 均不被记录）——这是本模块的硬约束。
// 审计只记录渠道类型、名称、动作、结果与耗时。

// 审计结果三态（与其它模块保持同名同义）。
const (
	AuditAllowed = "allowed"
	AuditDenied  = "denied"
	AuditFailed  = "failed"
)

// SourceCore 是核心自带能力发起的事件来源标记。
const SourceCore = "core"

// AuditEvent 是一条通知审计记录。
type AuditEvent struct {
	Seq         uint64 `json:"seq"`
	Time        string `json:"time"`
	Kind        string `json:"kind"`
	Source      string `json:"source,omitempty"`
	User        string `json:"user,omitempty"`
	Action      string `json:"action"`
	ChannelID   string `json:"channel_id,omitempty"`
	ChannelType string `json:"channel_type,omitempty"`
	ChannelName string `json:"channel_name,omitempty"`
	Required    string `json:"required,omitempty"`
	Outcome     string `json:"outcome"`
	Status      int    `json:"status"`
	DurationMS  int64  `json:"duration_ms"`
	ClientIP    string `json:"client_ip,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Sent 是发送成功的渠道数（Send/Test 动作时有效）。
	Sent int `json:"sent,omitempty"`
	// Failed 是发送失败的渠道数。
	Failed int `json:"failed,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	Capacity int
	Path     string
	Logger   *slog.Logger
}

// DefaultAuditCapacity 是默认环形缓冲容量。
const DefaultAuditCapacity = 1000

// Auditor 收集并保存通知审计记录。
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
		logger.Info("通知审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("notify: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("notify: 打开审计日志 %s 失败: %w", path, err)
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
		ev.Kind = "notify"
	}
	if ev.Source == "" {
		ev.Source = SourceCore
	}

	if len(a.ring) >= a.capacity {
		copy(a.ring, a.ring[1:])
		a.ring = a.ring[:len(a.ring)-1]
	}
	a.ring = append(a.ring, ev)
	a.total++

	if a.file != nil {
		if err := a.writeFile(ev); err != nil {
			a.logger.Warn("写通知审计落盘失败", "err", err)
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

// AuditStats 是审计统计。
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

// MaxAuditQueryLimit 是单次可返回的审计条数上限。
const MaxAuditQueryLimit = 1000

// List 返回审计记录（新的在前）。
func (a *Auditor) List(q AuditQuery) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	limit := q.Limit
	if limit <= 0 {
		limit = DefaultAuditCapacity
	}
	if limit > MaxAuditQueryLimit {
		limit = MaxAuditQueryLimit
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
