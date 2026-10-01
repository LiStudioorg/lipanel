package backup

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
// 备份操作审计（阶段五 5.3）
// ============================================================================
//
// 与其它核心模块同一套「统一落盘、分别查询」纪律：
// 写入同一个 -audit-log JSONL 文件（kind="backup"、source="core"），
// 独立的内存环形缓冲与查询接口（GET /api/backup/audit）。
//
// ########## 本模块审计最要紧的两件事 ##########
//
// ① **源路径与目标存储必须留痕**。
//    「谁在什么时候把 /etc 打包送到了哪个云上」是事后唯一查得清的线索。
//    备份是本面板里**数据离开这台机器**的唯一出口，因此
//    source_path / storage_id / storage_type 一律进审计，包括被拒绝的请求。
//
// ② **恢复必须留痕，且要记确认情况**。
//    恢复是本模块唯一不可逆的动作（覆盖目标目录里的文件）。
//    「当时有没有确认过、确认文字对不对、往哪个目录恢复的」
//    是出事之后必须能回答的问题。
//
// ########## 绝不进审计的东西 ##########
//
// 凭证（SecretKey / Password）一个字都不写。审计文件是给人看的、
// 会被导出、会被发给同事排查问题——把云存储密钥写进去，
// 等于把一台机器的入侵面扩大到用户所有的备份存储上。

// 审计结果三态（与各核心模块同名同义，便于统一检索）。
const (
	AuditAllowed = "allowed"
	AuditDenied  = "denied"
	AuditFailed  = "failed"
)

// SourceCore 标记事件由核心产生（不伪造插件 ID）。
const SourceCore = "core"

// AuditEvent 是一条备份操作审计记录（扁平，供 JSONL 消费）。
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

	// ---- 备份特有字段 ----
	// TaskID / TaskName 是备份任务（删除后历史仍可读）。
	TaskID   string `json:"task_id,omitempty"`
	TaskName string `json:"task_name,omitempty"`
	// SourcePath 是备份源路径**原文**（安全底线要求，见文件头 ①）。
	SourcePath string `json:"source_path,omitempty"`
	// StorageID / StorageType 是目标存储（**不含任何凭证**）。
	StorageID   string `json:"storage_id,omitempty"`
	StorageType string `json:"storage_type,omitempty"`
	// ArchiveKey / ArchiveBytes 是产出对象与体积。
	ArchiveKey   string `json:"archive_key,omitempty"`
	ArchiveBytes int64  `json:"archive_bytes,omitempty"`
	// Trigger 是 manual / cron。
	Trigger string `json:"trigger,omitempty"`
	// Pruned 是保留策略清理掉的份数。
	Pruned int `json:"pruned,omitempty"`
	// Confirmed 表示这次操作带着显式二次确认。
	Confirmed bool `json:"confirmed,omitempty"`
	// ConfirmTextOK 记录确认文字是否逐字匹配。
	//
	// 它比 Confirmed 更细：Confirmed=true 但 ConfirmTextOK=false
	// 的请求**不会被放行**，但那次尝试本身就值得留痕
	// （有人试图恢复生产数据但输错了目标名，这是一个真实信号）。
	// ⚠️ 刻意**不加 omitempty**：false 在这里是一个有信息量的值
	// （"他试图恢复但确认文字打错了"），而不是"缺省"。
	// 加上 omitempty 会让"文字不匹配"与"本次没有确认环节"在
	// 审计记录里长得一模一样，出事时无法区分。
	ConfirmTextOK bool `json:"confirm_text_ok"`
	// RestoreTarget 是恢复目标目录（恢复专属）。
	RestoreTarget string `json:"restore_target,omitempty"`
	// Restored / Overwritten 是恢复的文件数与覆盖数。
	Restored    int `json:"restored,omitempty"`
	Overwritten int `json:"overwritten,omitempty"`
	// CronJobID 是该任务挂到 crontab 上的 id。
	CronJobID string `json:"cron_job_id,omitempty"`
	// Mode 是运行模式（normal 等），排查「改到哪去了」时关键。
	Mode string `json:"mode,omitempty"`
	// SystemChange 表示这次操作改变了系统上的持久状态。
	SystemChange bool `json:"system_change"`
}

// AuditOptions 构造参数（与其它模块对齐）。
type AuditOptions struct {
	Capacity int
	Path     string
	Logger   *slog.Logger
}

// 审计容量常量。
const (
	DefaultAuditCapacity   = 1000
	DefaultAuditQueryLimit = 100
	MaxAuditQueryLimit     = 1000
)

// Auditor 收集备份操作审计。
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
				return nil, fmt.Errorf("backup: 创建审计日志目录 %s 失败: %w", dir, err)
			}
		}
		f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("backup: 打开审计日志 %s 失败: %w", opts.Path, err)
		}
		a.file = f
		a.path = opts.Path
		logger.Info("备份审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
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
		ev.Kind = "backup"
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
		a.logger.Warn("写出备份审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
	}
}

// AuditFilter 是审计查询条件。
type AuditFilter struct {
	TaskID  string
	User    string
	Outcome string
	Action  string
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
		if f.TaskID != "" && ev.TaskID != f.TaskID {
			continue
		}
		if f.User != "" && ev.User != f.User {
			continue
		}
		if f.Outcome != "" && ev.Outcome != f.Outcome {
			continue
		}
		if f.Action != "" && ev.Action != f.Action {
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
		return fmt.Errorf("backup: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("backup: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
