package file

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
// 文件操作审计（阶段四 4.2）
// ============================================================================
//
// 目标：留下「**谁**、在**何时**、对**哪个路径**做了什么、结果如何」。
// 文件操作比服务启停危险得多——一条 `rm -rf` 就能毁掉整台服务器，
// 因此"谁删的"必须有据可查。
//
// 与插件审计（internal/plugin/audit.go）、服务审计（internal/service/audit.go）
// 的关系仍是**统一落盘、分别查询**：
//
//   - 落盘：三者写入同一个 -audit-log 文件（JSONL，一行一条），
//     一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//   - 查询：各有独立类型、独立环形缓冲、独立查询接口
//     （/api/files/audit 与 /api/services/audit、/api/plugins/audit），互不污染。
//
// 用 Kind="file" 与 Source="core" 区分来源，**不伪造插件 ID**：
// 塞一个 "core:files" 会让插件审计页冒出一个根本不存在的「插件」（3.3/4.1 的同一教训）。
//
// ## 与其它两个审计器的一处有意差异：被拒绝的路径探测也记
//
// 服务审计对"不存在的插件不记审计"，是为了防止扫描器把环形缓冲刷满。
// 文件模块面对的情况不同：**越权路径访问本身就是最值得留痕的安全信号**
// （有人在尝试 /etc/shadow、在构造 ../ 逃逸）。
// 因此这里对所有写操作与新出现的目标路径**一律留痕**，包括被权限拒绝的。
//
// 代价是缓冲可能被探测流量挤占，这一点用两个手段控制：
//  1. 只有**写操作**以及"越权/非法路径"才记，普通的列目录/读文件不记（否则缓冲区毫无意义）；
//  2. capacity 沿用 -audit-buffer 配置，运维可调大，落盘文件则永不丢失。

// 审计结果三态，与插件/服务审计保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或路径校验拒绝，**未触碰任何文件**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败（不存在、权限不足、磁盘满等）。
	AuditFailed = "failed"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindFile 是本模块写入事件的类别标记。
const KindFile = "file"

// AuditEvent 是一条文件操作审计记录。
//
// 字段刻意保持扁平：它以 JSONL 落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 固定为 "file"，用于在同一份 JSONL 里区分来源。
	Kind string `json:"kind"`
	// Source 固定为 "core"。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——直接回答「谁干的」。
	User string `json:"user,omitempty"`
	// Action 是操作类型：list/read/download/write/mkdir/upload/rename/delete。
	Action string `json:"action"`
	// Path 是**用户请求的原始路径**。
	//
	// 刻意记原始值而不是解析后的真实路径：审计要回答的是
	// "用户当时提交了什么"，原始路径里可能就藏着探测意图
	// （`/home/../etc/shadow`）；解析后的真实路径另记在 ResolvedPath。
	Path string `json:"path"`
	// Target 是重命名/移动的目标路径（仅 rename 有意义）。
	Target string `json:"target,omitempty"`
	// ResolvedPath 是通过校验后的真实路径；被拒绝时为空。
	ResolvedPath string `json:"resolved_path,omitempty"`
	// Root 是命中的白名单根目录，便于回答"这次操作落在哪个受管区域"。
	Root string `json:"root,omitempty"`
	// Required 是本次操作所需的权限。
	Required string `json:"required,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// Bytes 是读写的字节数（写/上传/下载有意义）。
	Bytes int64 `json:"bytes,omitempty"`
	// DurationMS 是处理耗时（毫秒）。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因。
	Reason string `json:"reason,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 通常与插件/服务审计传入**同一个** -audit-log 路径。
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

// Auditor 收集并保存文件操作审计记录。
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
// 落盘路径打不开时返回错误，**不静默降级**：用户显式配了 -audit-log
// 却因为目录不可写而悄悄不记录，是最糟的失败方式
// （与 service.NewAuditor 完全一致的取舍）。
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
		logger.Info("文件操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与插件/服务审计共用同一文件时的安全性：三方都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证单次 write 的原子性）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 0700：审计日志含操作者与真实路径，不该被别人读。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("file: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("file: 打开审计日志 %s 失败: %w", path, err)
	}
	a.file = f
	a.path = path
	return nil
}

// Record 写入一条审计记录。
//
// 与其它两个审计器同样的取舍：**不返回错误**。
// 审计是旁路能力，它的失败绝不能影响用户的操作本身；
// 落盘失败会被计数并通过 Stats() 暴露给运维排查。
func (a *Auditor) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339Nano)
	}
	if ev.Kind == "" {
		ev.Kind = KindFile
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
		a.logger.Warn("写出文件审计日志失败（操作不受影响）",
			"path", path, "action", ev.Action, "target", ev.Path, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// User 非空时只返回该用户发起的记录。
	User string
	// Action 非空时只返回该动作的记录。
	Action string
	// Path 非空时按**包含**匹配请求路径（便于"这个文件被谁动过"）。
	Path string
	// Outcome 非空时只返回该结果的记录。
	Outcome string
	// Limit 是返回条数上限；<=0 时用 DefaultAuditQueryLimit。
	Limit int
}

// Query 按过滤条件返回审计记录（时间倒序，最新在前）。
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
	user := strings.TrimSpace(f.User)
	action := strings.TrimSpace(f.Action)
	path := strings.TrimSpace(f.Path)
	outcome := strings.TrimSpace(f.Outcome)

	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if user != "" && ev.User != user {
			continue
		}
		if action != "" && ev.Action != action {
			continue
		}
		if outcome != "" && ev.Outcome != outcome {
			continue
		}
		if path != "" && !strings.Contains(ev.Path, path) && !strings.Contains(ev.Target, path) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// AuditStats 是审计器的运行状态。
type AuditStats struct {
	Total    uint64 `json:"total"`
	Retained int    `json:"retained"`
	Capacity int    `json:"capacity"`
	// Denied 是内存中保留的拒绝条数。在文件模块里这个数字尤其值得关注：
	// 持续增长往往意味着有人在探测越权路径。
	Denied int `json:"denied"`
	// Failed 是内存中保留的执行失败条数。
	Failed int `json:"failed"`
	// PersistPath 是落盘路径（未启用时为空）。
	PersistPath string `json:"persist_path,omitempty"`
	// WriteErrors 是落盘失败累计次数（>0 说明留痕不完整）。
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
		return fmt.Errorf("file: 关闭审计日志失败: %w", err)
	}
	return nil
}

// ExportAuditJSONL 把内存中的审计记录以 JSONL 写出（按时间正序），供测试与排查使用。
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
			return fmt.Errorf("file: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
