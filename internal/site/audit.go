package site

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
// 站点操作审计（阶段四 4.3）
// ============================================================================
//
// 目标：记录「**谁**、在**何时**、对**哪个站点**做了什么、结果如何」。
//
// 站点操作的危险性介于服务管理与文件管理之间：
//
//   - 它不像 `rm -rf` 那样直接毁数据，但一次写坏的配置会让
//     **整台机器上所有站点同时不可用**（nginx reload 是全局的）；
//   - 它改的是服务器对外提供服务的入口，出问题的可见度最高。
//
// 因此这里对**每一个写操作都留痕**，包括：
//   - 被权限拒绝的（denied）：说明有人在尝试越权；
//   - 被站点名校验拒绝的（denied）：说明有人在探测注入（`;`、`..` 等）；
//   - nginx -t 失败并回滚的（failed）：这是最需要事后复盘的记录——
//     "是谁在几点改了什么导致全站短暂中断"的答案就在这里。
//
// 与其它三个审计器（plugin / service / file）的关系仍是
// **统一落盘、分别查询**：
//
//   - 落盘：写入同一个 -audit-log 文件（JSONL，一行一条），
//     一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//   - 查询：各有独立类型、独立环形缓冲、独立查询接口
//     （/api/sites/audit 与 /api/files/audit 等），互不污染。
//
// 用 Kind="site" 与 Source="core" 区分来源，**不伪造插件 ID**：
// 塞一个 "core:nginx" 会让插件审计页冒出一个根本不存在的「插件」
// （3.3/4.1/4.2 的同一教训）。

// 审计结果三态，与其它三个审计器保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或输入校验拒绝，**未触碰任何文件**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败（nginx -t 失败并回滚、IO 错误等）。
	AuditFailed = "failed"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindSite 是本模块写入事件的类别标记。
const KindSite = "site"

// AuditEvent 是一条站点操作审计记录。
//
// 字段刻意保持扁平：它会以 JSONL 形式落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序（同一毫秒内的多条也能定序）。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别（固定为 "site"，用于在同一份 JSONL 里区分来源）。
	Kind string `json:"kind"`
	// Source 标记事件由谁产生（核心自带能力固定为 "core"）。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——审计的核心字段，直接回答「谁干的」。
	User string `json:"user,omitempty"`
	// Action 是操作类型：create / update / delete / enable / disable。
	Action string `json:"action"`
	// Target 是被操作的站点名。
	Target string `json:"target"`
	// Domain 是站点的域名（便于不查配置就还原现场）。
	Domain string `json:"domain,omitempty"`
	// SiteType 是站点类型（static / proxy）。
	SiteType string `json:"site_type,omitempty"`
	// Required 是本次操作所需的权限（被拒绝时尤其重要）。
	Required string `json:"required,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// DurationMS 是处理耗时（毫秒）。
	//
	// 这个字段在站点模块里比在别处更有用：它包含了一次
	// nginx -t 加一次 reload 的完整耗时。若某次操作耗时异常长，
	// 说明 nginx 侧可能正在抖动。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因（含 nginx 的原始报错）。
	Reason string `json:"reason,omitempty"`
	// RolledBack 表示本次失败触发了自动回滚。
	//
	// 单独一个布尔字段而不是塞进 Reason 文本：回滚是安全性质，
	// 运维需要能用 `jq 'select(.rolled_back)'` 直接筛出
	// "哪些失败真的动过配置"，而不是去正则匹配一句中文描述。
	RolledBack bool `json:"rolled_back,omitempty"`
	// EnabledAfter 是操作后站点的启用状态（成功时才有意义）。
	EnabledAfter *bool `json:"enabled_after,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与其它三个审计器**同一个** -audit-log 路径。
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

// Auditor 收集并保存站点操作审计记录。
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
		logger.Info("站点操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与其它三个审计器共用同一文件时的安全性：多边都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性，
// 前提是单次 write 不超过 PIPE_BUF 的常识性约束，本场景单行仅数百字节）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 0700：审计日志含操作者与站点信息，不该被别人读。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("site: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	// 0600 + 追加写：只应属主可读，且绝不覆盖历史记录。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("site: 打开审计日志 %s 失败: %w", path, err)
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
		ev.Kind = KindSite
	}
	// 来源固定标注为 core：本模块是核心自带能力，不经过插件转发。
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
	// 单次 write：与其它审计器共用文件时靠 O_APPEND 保证不交错。
	if _, err := file.Write(line); err != nil {
		a.mu.Lock()
		a.writeW++
		a.mu.Unlock()
		a.logger.Warn("写出站点审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// Target 非空时只返回该站点的记录。
	Target string
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
	user := strings.TrimSpace(f.User)
	action := strings.TrimSpace(f.Action)
	outcome := strings.TrimSpace(f.Outcome)

	for i := len(a.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := a.ring[i]
		if target != "" && ev.Target != target {
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
	// RolledBack 是触发过自动回滚的条数。
	//
	// 前端把这个数字展示出来是有意义的：只要它不为 0，
	// 就说明这台机器上**真的发生过**"配置写坏又自动恢复"，
	// 用户应当去看具体是哪些操作。
	RolledBack int `json:"rolled_back"`
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
		if ev.RolledBack {
			st.RolledBack++
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
		return fmt.Errorf("site: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("site: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
