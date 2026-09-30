package terminal

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
// 终端操作审计（阶段五 5.1）
// ============================================================================
//
// 与本项目其它七个审计器（plugin 3.3 / service 4.1 / file 4.2 /
// site 4.3 / ssl 4.4 / store 4.5 / firewall 4.6）完全同构：
// **统一落盘、分别查询**。
//
//	落盘：写入同一个 -audit-log 文件（JSONL，一行一条），
//	      一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//	查询：独立类型、独立环形缓冲、独立查询接口（/api/terminal/audit），互不污染。
//
// 用 Kind="terminal" 与 Source="core" 区分来源，**不伪造插件 ID**。
//
// #################### 本模块审计的独有重点：能还原"谁在什么时候拿到了 shell" ####################
//
// 终端审计与其它模块有一个根本区别：
//
//	其它模块的审计记录的是「发生了什么」（装了什么包、删了哪条规则）；
//	终端的审计**无法**记录「发生了什么」——因为终端里跑的
//	是任意命令，我们看不到（也绝不应该去解析）用户敲了什么。
//
// 因此终端审计的目标不是复现操作，而是**还原会话的建立与拆解**：
//
//	· 谁在什么时候开了一个 shell？（这是本面板最高危的事件）
//	· 这个 shell 活了多久？
//	· 它是怎么结束的——用户主动断开、空闲超时、还是进程自己退出？
//	· 从哪个 IP 连进来的？
//
// 事后排查时的价值在于：当发现机器上有异常操作时，
// 先查终端审计能定位到"这个时间窗口有一个 shell 是开着的，
// 属于 user X，来自 IP Y"，从而把排查范围从"任何时间任何人"
// 收窄到具体的会话。之后配合系统日志（auth.log、bash history）
// 才能还原具体命令。
//
// **为什么不做会话录像**：计划明确列为不做项。除实现复杂度外，
// 录像本身是一份包含潜在敏感信息（密码、密钥）的完整副本，
// 它的存储与访问控制会引入新的泄漏面。

// 审计结果三态，与其它七个审计器保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或输入校验拒绝，**未创建任何会话**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败。
	AuditFailed = "failed"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindTerminal 是本模块写入事件的类别标记。
const KindTerminal = "terminal"

// AuditEvent 是一条终端操作审计记录。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别（固定为 "terminal"）。
	Kind string `json:"kind"`
	// Source 标记事件由谁产生（核心自带能力固定为 "core"）。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——审计的核心字段。
	User string `json:"user,omitempty"`
	// Action 是操作类型：status / list_sessions / audit /
	// create_session / connect / disconnect / close_session。
	Action string `json:"action"`
	// Session 是会话 ID。
	//
	// ########## 这个字段是本模块审计的锚点 ##########
	//
	// 一条终端审计记录单独看信息很少（"用户 X 创建了会话"），
	// 但把**同一个 Session ID** 的所有记录串起来，
	// 就得到这个 shell 的完整生命周期：
	//
	//	create_session → connect → disconnect → close_session
	//
	// 于是 jq 一句就能重建现场：
	//
	//	jq 'select(.kind=="terminal" and .session=="<id>")'
	Session string `json:"session,omitempty"`
	// Owner 是会话的创建者（可能与被审计的 User 不同：
	// 例如用户 B 尝试 attach 用户 A 的会话，会被拒绝并留痕）。
	Owner string `json:"owner,omitempty"`
	// Shell 是终端使用的 shell 路径。
	Shell string `json:"shell,omitempty"`
	// PID 是 shell 进程号（会话结束时用于核对）。
	PID int `json:"pid,omitempty"`
	// Cols / Rows 是会话的终端尺寸。
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
	// Reason 是会话结束原因（user_closed / idle_timeout /
	// process_exited / client_disconnected / server_shutdown / protocol_error）。
	//
	// ########## 为什么结束原因要单独统计 ##########
	//
	// "会话总是空闲超时断开"是一个可行动的信号：
	// 说明用户开了终端就离开了（忘记关），
	// 或者面板的刷新/断线重连有问题导致连接悄悄断掉。
	// 把它做成稳定常量而不是自由文本，才能按原因聚合。
	Reason string `json:"reason,omitempty"`
	// IdleSeconds 是会话结束时的空闲秒数（结束时才有意义）。
	IdleSeconds int `json:"idle_seconds,omitempty"`
	// DurationSeconds 是会话存活时长（结束时记录）。
	DurationSeconds int `json:"duration_seconds,omitempty"`
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
	// Reason_ 不可用（已占用），拒绝/失败原因用 Detail。
	//
	// ########## 为什么错误信息字段叫 Detail 而不是 Reason ##########
	//
	// Reason 已经被"会话结束原因"占用，且那是一个**稳定常量**
	// （可聚合、可告警）；而错误详情是自由文本（面向人的描述）。
	// 两者混用会让按 Reason 聚合的查询被中文错误信息污染。
	// 因此拆成两个字段：Reason 是枚举，Detail 是描述。
	Detail string `json:"detail,omitempty"`
	// SystemChange 表示该操作是否真的改变了系统状态。
	SystemChange bool `json:"system_change,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与其它七个审计器**同一个** -audit-log 路径。
	Path string
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// 默认配置。
const (
	// DefaultAuditCapacity 是内存环形缓冲的默认容量。
	DefaultAuditCapacity = 1000
	// DefaultAuditQueryLimit 是审计查询的默认返回条数。
	DefaultAuditQueryLimit = 100
	// MaxAuditQueryLimit 是单次查询能取到的最大条数。
	MaxAuditQueryLimit = 1000
)

// Auditor 收集并保存终端操作审计记录。
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
		logger.Info("终端操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与其它七个审计器共用同一文件时的安全性：所有写入方都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("terminal: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("terminal: 打开审计日志 %s 失败: %w", path, err)
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
		ev.Kind = KindTerminal
	}
	if ev.Source == "" {
		ev.Source = SourceCore
	}
	if ev.Outcome == "" {
		ev.Outcome = AuditAllowed
	}
	if !ev.SystemChange {
		// 被拒绝的请求**没有创建任何会话**：shell 根本没被 fork。
		// 把它标成"改变了系统"会让审计失去可信度。
		ev.SystemChange = WritesSystem(ev.Action) && ev.Outcome != AuditDenied
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
		a.logger.Warn("写出终端审计日志失败（操作不受影响）",
			"path", path, "session", ev.Session, "err", err)
	}
}

// AuditFilter 是审计查询的过滤条件。
type AuditFilter struct {
	// User 非空时只返回该用户发起的记录。
	User string
	// Action 非空时只返回该动作的记录。
	Action string
	// Outcome 非空时只返回该结果的记录。
	Outcome string
	// Session 非空时只返回该会话的记录（用于重建单个 shell 的生命周期）。
	Session string
	// Reason 非空时只返回该结束原因的记录。
	Reason string
	// OnlySystemChange 为 true 时只返回真正改变过系统状态的记录。
	OnlySystemChange bool
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
	user := strings.TrimSpace(f.User)
	action := strings.TrimSpace(f.Action)
	outcome := strings.TrimSpace(f.Outcome)
	session := strings.TrimSpace(f.Session)
	reason := strings.TrimSpace(f.Reason)

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
		if session != "" && ev.Session != session {
			continue
		}
		if reason != "" && ev.Reason != reason {
			continue
		}
		if f.OnlySystemChange && !ev.SystemChange {
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
	// Created / Closed 是成功的会话建立与关闭次数。
	Created int `json:"created"`
	Closed  int `json:"closed"`
	// IdleClosed 是**因空闲超时**而被断开的会话数。
	//
	// ########## 为什么要单独统计 ##########
	//
	// 空闲超时断开可能是正常的（用户忘了关），
	// 也可能是异常的（前端断线重连失败，用户以为还连着）。
	// 把它从 Closed 里分出来，运维一眼能看出比例。
	IdleClosed int `json:"idle_closed"`
	// ExitClosed 是用户敲 exit 导致 shell 自行退出的次数。
	ExitClosed int `json:"exit_closed"`
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
		if ev.Outcome != AuditAllowed {
			continue
		}
		switch ev.Action {
		case ActionCreate:
			st.Created++
		case ActionClose, ActionDisconnect:
			st.Closed++
			if ev.Reason == CloseReasonIdle {
				st.IdleClosed++
			}
			if ev.Reason == CloseReasonExited {
				st.ExitClosed++
			}
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
		return fmt.Errorf("terminal: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("terminal: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
