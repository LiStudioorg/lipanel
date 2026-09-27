package firewall

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
// 防火墙操作审计（阶段四 4.6）
// ============================================================================
//
// 与本项目其它六个审计器（plugin 3.3 / service 4.1 / file 4.2 /
// site 4.3 / ssl 4.4 / store 4.5）完全同构：**统一落盘、分别查询**。
//
//	落盘：写入同一个 -audit-log 文件（JSONL，一行一条），
//	      一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//	查询：独立类型、独立环形缓冲、独立查询接口（/api/firewall/audit），互不污染。
//
// 用 Kind="firewall" 与 Source="core" 区分来源，**不伪造插件 ID**。
//
// #################### 本模块审计的独有重点：能还原"当时删了什么" ####################
//
// 防火墙与其它模块最大的不同在于**后果的不可逆性**：
// 删掉一条 SSH 放行规则之后，用户可能立刻失去连接，
// 再也没机会去看日志。因此审计必须让**事后的人**（包括
// 通过控制台抢救的运维）能回答：
//
//	· 谁在什么时候删了哪条规则？
//	· 那条规则的完整内容是什么（我要把它加回去）？
//	· 他是不是忽略了保护提示？
//	· 删除前系统执行了什么命令？
//
// 为此每条写操作记录都带上：
//
//	RuleSpec    —— 规则的精确规格（iptables 的词元串 / nft 的 handle）
//	Command     —— 实际执行的命令（已脱敏，供人工复现）
//	Protected   —— 是否涉及受保护端口
//	Force       —— 是否用了 force 强行删除受保护端口
//	Backend     —— 哪个后端（不同后端的恢复方式不同）
//
// 于是事后一句 jq 就能重建现场：
//
//	jq 'select(.kind=="firewall" and .outcome=="allowed" and .action=="delete_port")'
//
// **为什么 RuleSpec 必须记录**：防火墙没有"回收站"。
// 恢复一条被删的规则只能靠人重新输入，而人记不住
// "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT" 里那个
// 内核自己补的 "-m tcp"。审计里存着，就能直接复制回去。

// 审计结果三态，与其它六个审计器保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或输入校验拒绝，**未触碰任何外部命令**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败（命令报错等）。
	AuditFailed = "failed"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindFirewall 是本模块写入事件的类别标记。
const KindFirewall = "firewall"

// AuditEvent 是一条防火墙操作审计记录。
//
// 字段刻意保持扁平：它会以 JSONL 形式落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别（固定为 "firewall"）。
	Kind string `json:"kind"`
	// Source 标记事件由谁产生（核心自带能力固定为 "core"）。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——审计的核心字段。
	User string `json:"user,omitempty"`
	// Action 是操作类型：add_port / delete_port / add_ip / delete_ip /
	// status / list_rules / capabilities / audit。
	Action string `json:"action"`
	// Backend 是操作发生时生效的防火墙后端（ufw/firewalld/nftables/iptables）。
	//
	// ########## 为什么后端也要记 ##########
	//
	// 同一台机器可能换过后端（从 iptables 迁到 nftables），
	// 而"删除失败"在不同后端的原因完全不同。
	// 没有这个字段，排查时无法判断当时该用哪个工具去查。
	Backend string `json:"backend,omitempty"`
	// Target 是被操作对象的展示描述（如 "8080/tcp" 或 "1.2.3.4"）。
	Target string `json:"target"`
	// Port 是涉及的端口（IP 规则为空）。
	Port string `json:"port,omitempty"`
	// Protocol 是协议（tcp/udp/any）。
	Protocol string `json:"protocol,omitempty"`
	// Source_ 是来源 IP/网段。字段名用 source_ip 以免与 Source 冲突。
	SourceIP string `json:"source_ip,omitempty"`
	// RuleAction 是规则的语义动作（allow/deny），
	// 与审计的 Outcome（allowed/denied）是两件事，不可混淆。
	RuleAction string `json:"rule_action,omitempty"`
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
	// Reason 是拒绝或失败的原因（含命令的原始报错摘要）。
	Reason string `json:"reason,omitempty"`
	// RuleSpec 是被操作规则的精确规格。
	//
	// ########## 这是本模块审计最有价值的字段 ##########
	//
	// 防火墙没有回收站：恢复被删的规则只能靠人重新输入。
	// iptables 的规格里含内核自己补的匹配器（-m tcp），
	// 人根本记不住，而审计里存着就能直接复制回去。
	RuleSpec string `json:"rule_spec,omitempty"`
	// Command 是实际执行的命令（展示形态，供人工复现与排查）。
	//
	// 注意它是 Command.String() 的结果，可能带引号；
	// 它**仅用于阅读**，绝不能被执行（执行路径始终是 argv 切片）。
	Command string `json:"command,omitempty"`
	// Protected 标记本次操作涉及受保护端口（面板自身或 SSH）。
	Protected bool `json:"protected,omitempty"`
	// Force 标记用户是否用 force 强行删除了受保护端口。
	//
	// ########## 这个字段是事后追责的关键 ##########
	//
	// 用户看到红色警告后仍然强删了 SSH 端口，然后失联——
	// 恢复连接后第一件事就是查"到底发生了什么"。
	// Force=true 明确回答"是的，他看到了警告并选择继续"，
	// 而不是让人怀疑"是不是面板没提示"。
	Force bool `json:"force,omitempty"`
	// Confirmed 标记删除类操作带了二次确认。
	Confirmed bool `json:"confirmed,omitempty"`
	// SystemChange 标记本次操作**改变了系统状态**。
	//
	// 与 Outcome 正交：被拒绝的请求 Outcome=denied 且
	// SystemChange=false；一次执行了命令但失败的请求是
	// failed + true（规则可能已被部分应用）。
	SystemChange bool `json:"system_change,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与其它六个审计器**同一个** -audit-log 路径。
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

// Auditor 收集并保存防火墙操作审计记录。
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
//
// ########## 对本模块尤其重要 ##########
//
// 防火墙操作可能让用户失去连接。若审计也静默失效，
// 事后就没有任何记录能还原"是谁删了那条规则"。
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
		logger.Info("防火墙操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与其它六个审计器共用同一文件时的安全性：所有写入方都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("firewall: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("firewall: 打开审计日志 %s 失败: %w", path, err)
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
		ev.Kind = KindFirewall
	}
	if ev.Source == "" {
		ev.Source = SourceCore
	}
	if ev.Outcome == "" {
		ev.Outcome = AuditAllowed
	}
	if !ev.SystemChange {
		// 被拒绝的请求**没有改变任何东西**：防火墙命令根本没执行。
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
		a.logger.Warn("写出防火墙审计日志失败（操作不受影响）",
			"path", path, "target", ev.Target, "err", err)
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
	// Backend 非空时只返回该后端的记录。
	Backend string
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
	backend := strings.TrimSpace(f.Backend)

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
		if backend != "" && ev.Backend != backend {
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
	// Added / Deleted 是成功的增删次数。
	Added   int `json:"added"`
	Deleted int `json:"deleted"`
	// Forced 是**强行删除受保护端口**的次数（>0 值得运维关注）。
	//
	// ########## 为什么要单独统计 ##########
	//
	// 强删受保护端口是"用户看到了红色警告仍然继续"的行为。
	// 一次可能是误以为需要，两次三次就说明保护提示的位置或
	// 措辞有问题。把它暴露成计数，比埋在几百条记录里更有用。
	Forced int `json:"forced"`
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
		if ev.Outcome == AuditAllowed {
			switch ev.Action {
			case ActionAddPort, ActionAddIP:
				st.Added++
			case ActionDeletePort, ActionDeleteIP:
				st.Deleted++
			}
		}
		if ev.Force {
			st.Forced++
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
		return fmt.Errorf("firewall: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("firewall: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
