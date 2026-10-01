package cron

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// 计划任务操作审计（阶段五 5.2）
// ============================================================================
//
// 与其它核心模块同一套「统一落盘、分别查询」纪律：
// 写入同一个 -audit-log JSONL 文件（kind="cron"、source="core"），
// 独立的内存环形缓冲与查询接口（GET /api/cron/audit）。
//
// 本模块审计最重要的字段是 **Command**：计划任务是以面板身份
// （生产上通常是 root）在无人值守的时刻执行任意 shell 命令。
// 「谁在什么时候让这台机器以后每天凌晨跑什么」必须有完整的原文留痕，
// 包括被拒绝的请求——被拒绝的越权尝试同样是安全信号。

// 审计结果三态（与各核心模块同名同义，便于统一检索）。
const (
	AuditAllowed = "allowed"
	AuditDenied  = "denied"
	AuditFailed  = "failed"
)

// SourceCore 标记事件由核心产生（不伪造插件 ID）。
const SourceCore = "core"

// AuditEvent 是一条计划任务操作审计记录（扁平，供 JSONL 消费）。
type AuditEvent struct {
	Seq        uint64 `json:"seq"`
	Time       string `json:"time"`
	Kind       string `json:"kind"`
	Source     string `json:"source,omitempty"`
	User       string `json:"user,omitempty"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Required   string `json:"required,omitempty"`
	Outcome    string `json:"outcome"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// ---- 计划任务特有字段 ----
	// JobID 是任务 id（新增时是新生成的 id）。
	JobID string `json:"job_id,omitempty"`
	// Expression / Command 是任务内容与命令**原文**（安全底线要求）。
	Expression string `json:"expression,omitempty"`
	Command    string `json:"command,omitempty"`
	Comment    string `json:"comment,omitempty"`
	// Mode 是存取模式（crontab / file），排查「改到哪去了」时关键。
	Mode string `json:"mode,omitempty"`
	// RollbackOK / RollbackErr 记录写失败后的回滚结果。
	// 回滚失败必须醒目标出：那意味着 crontab 可能处于半截状态。
	RollbackOK  bool   `json:"rollback_ok,omitempty"`
	RollbackErr string `json:"rollback_error,omitempty"`
	BackupPath  string `json:"backup_path,omitempty"`
	BeforeJobs  int    `json:"before_jobs,omitempty"`
	AfterJobs   int    `json:"after_jobs,omitempty"`
	// Confirmed 表示这次删除是带着显式确认来的。
	//
	// 与 4.6 防火墙同一字段语义：当「误删一条生产备份任务」真的出了事，
	// 第一个要回答的问题是「当时有没有确认过」。
	Confirmed    bool `json:"confirmed,omitempty"`
	SystemChange bool `json:"system_change"`
}

// AuditOptions 构造参数（与其它模块对齐）。
type AuditOptions struct {
	Capacity int
	Path     string
	Logger   *slog.Logger
}

// DefaultAuditCapacity / DefaultAuditQueryLimit / MaxAuditQueryLimit。
const (
	DefaultAuditCapacity   = 1000
	DefaultAuditQueryLimit = 100
	MaxAuditQueryLimit     = 1000
)

// Auditor 收集计划任务操作审计。
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

// NewAuditor 构造审计器；落盘打不开时返回错误（不静默降级）。
func NewAuditor(opts AuditOptions) (*Auditor, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = DefaultAuditCapacity
	}
	a := &Auditor{capacity: capacity, logger: logger, ring: make([]AuditEvent, 0, capacity)}
	if opts.Path != "" {
		dir := filepath.Dir(opts.Path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("cron: 创建审计日志目录 %s 失败: %w", dir, err)
			}
		}
		f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("cron: 打开审计日志 %s 失败: %w", opts.Path, err)
		}
		a.file = f
		a.path = opts.Path
		logger.Info("计划任务审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// Record 写入一条审计（旁路能力，不返回错误；落盘失败计数并告警）。
func (a *Auditor) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339Nano)
	}
	if ev.Kind == "" {
		ev.Kind = "cron"
	}
	if ev.Source == "" {
		ev.Source = SourceCore
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
	file, path := a.file, a.path
	a.mu.Unlock()

	if line == nil || file == nil {
		return
	}
	if _, err := file.Write(line); err != nil {
		a.mu.Lock()
		a.writeW++
		a.mu.Unlock()
		a.logger.Warn("写出计划任务审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
	}
}

// AuditFilter 是审计查询条件。
type AuditFilter struct {
	JobID   string
	User    string
	Outcome string
	Limit   int
}

// Query 按条件返回审计（倒序，最新在前）。
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
	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if f.JobID != "" && ev.JobID != f.JobID {
			continue
		}
		if f.User != "" && ev.User != f.User {
			continue
		}
		if f.Outcome != "" && ev.Outcome != f.Outcome {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// AuditStats 是审计器状态。
type AuditStats struct {
	Total       uint64 `json:"total"`
	Retained    int    `json:"retained"`
	Capacity    int    `json:"capacity"`
	Denied      int    `json:"denied"`
	Failed      int    `json:"failed"`
	PersistPath string `json:"persist_path,omitempty"`
	WriteErrors int    `json:"write_errors"`
}

// Stats 返回状态快照。
func (a *Auditor) Stats() AuditStats {
	if a == nil {
		return AuditStats{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := AuditStats{Total: a.total, Retained: len(a.ring), Capacity: a.capacity,
		PersistPath: a.path, WriteErrors: a.writeW}
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

// Close 关闭落盘文件（幂等）。
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
		return fmt.Errorf("cron: 关闭审计日志失败: %w", err)
	}
	return nil
}

// ExportAuditJSONL 按时间正序导出内存中的审计（测试与排查用）。
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
			return fmt.Errorf("cron: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
