package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 操作审计（阶段三 3.3）
// ============================================================================
//
// 目标：记录「哪个插件、在什么时间、请求了什么资源、结果如何」。
//
// 与权限模块同样的能力边界说明：审计记录的是**经过核心转发的调用**。
// 插件进程绕过面板直接做的事（自己 open 文件、自己 fork 进程）不会被这里
// 记录到——核心看不见它们。审计的价值在于让面板侧的行为完全可追溯。
//
// 两段式存储：
//
//  1. **内存环形缓冲**（默认 1000 条）：供前端审计页随时查询，进程退出即丢；
//  2. **可选 JSONL 文件**（-audit-log <path>）：一行一条 JSON，追加写入，
//     便于 `tail -f` / `jq` / 交给日志采集器。落盘失败**只告警不影响请求**，
//     审计是旁路能力，绝不能因为它写不进磁盘就让面板不可用。
//
// 为什么默认不落盘：面板可能跑在只读文件系统或容器里，默认写文件会带来
// 「启动就报错」的部署问题；需要留痕的部署显式开启即可。

// AuditOutcome 是审计结果。
const (
	// AuditAllowed 表示请求通过权限校验并被转发给插件。
	AuditAllowed = "allowed"
	// AuditDenied 表示请求被权限校验拒绝，**未到达插件进程**。
	AuditDenied = "denied"
	// AuditFailed 表示请求已转发但失败（插件未运行、超时、连接失败等）。
	AuditFailed = "failed"
)

// AuditEvent 是一条审计记录。
//
// 字段刻意保持扁平与自解释：它会以 JSONL 形式落盘，也可能被外部日志
// 采集器消费，嵌套结构会让 `jq` 查询变得啰嗦。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序（同一毫秒内的多条也能定序）。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339，带时区）。
	Time string `json:"time"`
	// Plugin 是发起该调用的插件 ID。
	Plugin string `json:"plugin"`
	// Method 是 HTTP 方法。
	Method string `json:"method"`
	// Path 是插件子路径（不含 /api/plugins/<id> 前缀）。
	Path string `json:"path"`
	// Required 是本次调用所需的权限（免校验时为空）。
	Required string `json:"required,omitempty"`
	// Granted 是插件已声明的权限清单，便于直接对照「为什么被拒」。
	Granted []string `json:"granted,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// DurationMS 是处理耗时（毫秒）。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP，便于追溯「谁点的」。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因。
	Reason string `json:"reason,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 目录会自动创建（0700），文件权限 0600。
	Path string
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// DefaultAuditCapacity 是内存环形缓冲的默认容量。
//
// 1000 条足够覆盖「最近发生了什么」，且单条记录约 300 字节，
// 内存占用在数百 KB 量级，不会给面板带来负担。
const DefaultAuditCapacity = 1000

// Auditor 收集并保存操作审计记录。
//
// 并发模型：单把互斥锁保护环形缓冲与文件句柄。审计写入发生在请求路径上，
// 但临界区只有「切片赋值 + 一次 write」这一小段，不会成为瓶颈；
// 相比之下，无锁环形缓冲的复杂度与出错概率都不划算。
type Auditor struct {
	capacity int
	logger   *slog.Logger

	mu     sync.Mutex
	ring   []AuditEvent
	total  uint64 // 累计写入条数（含被环形缓冲覆盖的）
	seq    uint64
	file   *os.File
	writeW int // 累计落盘失败次数，供 /audit 接口暴露健康度
	path   string
}

// NewAuditor 构造审计器。
//
// 落盘路径打不开时**返回错误**（而不是静默降级）：用户显式配置了
// -audit-log 却因为目录不可写而悄悄不记录，是最糟的失败方式——
// 他以为有审计，实际什么都没有。启动阶段就该炸出来。
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
		logger.Info("插件操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	} else {
		logger.Info("插件操作审计仅在内存中保留（未指定 -audit-log）",
			"memory_capacity", capacity,
			"hint", "需要留痕请加 -audit-log /var/log/lipanel/audit.jsonl")
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 0700：审计日志可能包含路径、插件 ID 等敏感信息，目录不该被别人读。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("plugin: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	// 0600 + 追加写：审计日志只应属主可读，且绝不能覆盖历史记录。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("plugin: 打开审计日志 %s 失败: %w", path, err)
	}
	a.file = f
	a.path = path
	return nil
}

// Record 写入一条审计记录。
//
// 该方法**不返回错误**：审计是旁路能力，它的失败绝不能影响请求本身。
// 落盘失败会被计数并记日志，通过 Stats() 暴露给运维排查。
func (a *Auditor) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.RFC3339Nano)
	}
	if ev.Outcome == "" {
		ev.Outcome = AuditAllowed
	}

	a.mu.Lock()
	a.seq++
	ev.Seq = a.seq
	a.total++

	// 环形缓冲：满了就丢弃最旧的一条。
	// 用 copy 而不是 append+切片重切，语义更直白且不保留底层数组外的引用。
	if len(a.ring) < a.capacity {
		a.ring = append(a.ring, ev)
	} else {
		copy(a.ring, a.ring[1:])
		a.ring[len(a.ring)-1] = ev
	}

	var line []byte
	if a.file != nil {
		// 先序列化再持锁写出：序列化几乎不会失败，但失败时也要能跳过落盘
		// 而不影响内存缓冲（内存缓冲已经写好了）。
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
		a.logger.Warn("写出审计日志失败（请求不受影响）",
			"path", path, "plugin", ev.Plugin, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// Plugin 非空时只返回该插件的记录。
	Plugin string
	// Outcome 非空时只返回该结果的记录（allowed/denied/failed）。
	Outcome string
	// Limit 是返回条数上限；<=0 时用 DefaultAuditQueryLimit。
	Limit int
}

// DefaultAuditQueryLimit 是审计查询的默认返回条数。
// 上限远小于容量：前端表格一次渲染上千行既卡又没用。
const DefaultAuditQueryLimit = 100

// MaxAuditQueryLimit 是单次查询能取到的最大条数。
const MaxAuditQueryLimit = 1000

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

	// 倒序遍历（最新在前），命中即收集，收满 limit 就停。
	out := make([]AuditEvent, 0, limit)
	plugin := strings.TrimSpace(f.Plugin)
	outcome := strings.TrimSpace(f.Outcome)
	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if plugin != "" && ev.Plugin != plugin {
			continue
		}
		if outcome != "" && ev.Outcome != outcome {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// AuditStats 是审计器的运行状态，供前端与运维判断「审计是否健康」。
type AuditStats struct {
	// Total 是累计记录条数（含已被环形缓冲覆盖的）。
	Total uint64 `json:"total"`
	// Retained 是当前内存中保留的条数。
	Retained int `json:"retained"`
	// Capacity 是内存环形缓冲容量。
	Capacity int `json:"capacity"`
	// Denied 是内存中保留的拒绝条数，用于前端醒目标红。
	Denied int `json:"denied"`
	// Failed 是内存中保留的转发失败条数。
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

// CountByPlugin 返回每个插件的审计统计（内存中保留的部分）。
//
// 单独一个方法而不是让调用方遍历 Query 结果：Query 有 limit，
// 统计必须基于全量内存数据才准确。
func (a *Auditor) CountByPlugin() map[string]AuditStats {
	out := map[string]AuditStats{}
	if a == nil {
		return out
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ev := range a.ring {
		st := out[ev.Plugin]
		st.Total++
		st.Retained++
		switch ev.Outcome {
		case AuditDenied:
			st.Denied++
		case AuditFailed:
			st.Failed++
		}
		out[ev.Plugin] = st
	}
	return out
}

// Close 关闭审计日志文件。
// 未启用落盘或重复调用都返回 nil（幂等）。
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
		return fmt.Errorf("plugin: 关闭审计日志失败: %w", err)
	}
	return nil
}

// ExportAuditJSONL 把内存中的审计记录以 JSONL 写出，供测试与排查使用。
// 按时间正序输出（与落盘文件一致）。
func (a *Auditor) ExportAuditJSONL(w io.Writer) error {
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
			return fmt.Errorf("plugin: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
