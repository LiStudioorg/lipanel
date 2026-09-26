package ssl

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
// SSL 操作审计（阶段四 4.4）
// ============================================================================
//
// 与本项目其它四个审计器（plugin 3.3 / service 4.1 / file 4.2 / site 4.3）
// 完全同构：**统一落盘、分别查询**。
//
//	落盘：写入同一个 -audit-log 文件（JSONL，一行一条），
//	      一套采集器 / 一条 tail -f / 一个 jq 就能覆盖面板的全部操作留痕；
//	查询：独立类型、独立环形缓冲、独立查询接口（/api/ssl/audit），互不污染。
//
// 用 Kind="ssl" 与 Source="core" 区分来源，**不伪造插件 ID**
// （3.3/4.1/4.2/4.3 的同一教训）。
//
// #################### SSL 审计为什么必须记「消耗了多少配额」这件事 ####################
//
// 本模块的失败模式与其它四个不同：其它模块失败最多是"操作没成功"，
// 而本模块有一种**部分成功且后果延迟**的情况——
//
//	向 Let's Encrypt 发起申请 → CA 已签发并计入速率限制
//	→ 但写入 nginx 配置时失败（例如证书路径校验不过）
//
// 此时证书**已经拿到且配额已经消耗**，而站点并没有启用 HTTPS。
// 用户会反复重试，每次都在消耗配额，直到一周内再也申请不了。
//
// 因此审计里有几个字段是专门为这种情况准备的：
//   - Issued：CA 是否已经签发（配额是否已被消耗）
//   - Applied：配置是否已成功写入并 reload
//   - DryRun：本次是否为试运行（试运行**不消耗**生产配额）
//
// 有了这三个字段，运维能用一句 jq 直接捞出
// "签发了但没应用成功"的记录：`jq 'select(.issued and (.applied|not))'`。

// 审计结果三态，与其它四个审计器保持同名同义。
const (
	// AuditAllowed 表示操作被放行并成功执行。
	AuditAllowed = "allowed"
	// AuditDenied 表示被权限校验或输入校验拒绝，**未触碰任何外部命令**。
	AuditDenied = "denied"
	// AuditFailed 表示已尝试执行但失败（certbot 报错、nginx 校验失败等）。
	AuditFailed = "failed"
	// AuditPending 表示操作已发起但结果未知（例如超时后进程被终止）。
	//
	// 单独立一个状态而不是归入 failed：超时的申请**很可能**已经在
	// CA 侧成功了（只是响应没等到），把它记成 failed 会让审计
	// 与真实情况不符，而配额恰恰可能已经被消耗。
	AuditPending = "pending"
)

// SourceCore 标记事件来自核心自带能力（非插件转发）。
const SourceCore = "core"

// KindSSL 是本模块写入事件的类别标记。
const KindSSL = "ssl"

// AuditEvent 是一条 SSL 操作审计记录。
//
// 字段刻意保持扁平：它会以 JSONL 形式落盘，也可能被外部日志采集器消费。
type AuditEvent struct {
	// Seq 是进程内自增序号，用于稳定排序。
	Seq uint64 `json:"seq"`
	// Time 是事件时间（RFC3339Nano，带时区）。
	Time string `json:"time"`
	// Kind 标记事件类别（固定为 "ssl"，用于在同一份 JSONL 里区分来源）。
	Kind string `json:"kind"`
	// Source 标记事件由谁产生（核心自带能力固定为 "core"）。
	Source string `json:"source,omitempty"`
	// User 是发起操作的登录用户名——审计的核心字段。
	// 自动续期固定为 AutomationUser（"system:auto-renew"）。
	User string `json:"user,omitempty"`
	// Action 是操作类型：issue / renew / auto_renew / list / view。
	Action string `json:"action"`
	// Target 是被操作的站点名。
	Target string `json:"target"`
	// Domain 是申请/续期的域名。
	Domain string `json:"domain,omitempty"`
	// CertName 是证书名。
	CertName string `json:"cert_name,omitempty"`
	// Required 是本次操作所需的权限（被拒绝时尤其重要）。
	Required string `json:"required,omitempty"`
	// Outcome 见 AuditAllowed / AuditDenied / AuditFailed / AuditPending。
	Outcome string `json:"outcome"`
	// Status 是返回给调用方的 HTTP 状态码。
	Status int `json:"status"`
	// DurationMS 是处理耗时（毫秒）。
	//
	// 在 SSL 模块里这个字段特别有用：一次真实申请要跟 CA 往返
	// 若干次（含 HTTP-01 挑战验证），正常在 5~30s。
	// 若某条记录只有几百毫秒，说明它在**发起前**就失败了
	// （多半是校验或权限被拒）——不看这个数字很难从日志上区分。
	DurationMS int64 `json:"duration_ms"`
	// ClientIP 是发起请求的浏览器 IP（自动续期为空）。
	ClientIP string `json:"client_ip,omitempty"`
	// Reason 是拒绝或失败的原因（含 certbot 的原始报错）。
	Reason string `json:"reason,omitempty"`
	// Command 是本次执行的命令（已脱敏），便于事后原样复现。
	//
	// 把命令记进审计是有意的：certbot 的报错经常只说
	// "errors occurred"，真正有用的信息在
	// /var/log/letsencrypt/letsencrypt.log 里。
	// 有了完整命令，用户可以自己去翻那次运行的日志。
	Command string `json:"command,omitempty"`
	// DryRun 表示本次是试运行（**不消耗生产配额**）。
	DryRun bool `json:"dry_run,omitempty"`
	// Issued 表示 CA 是否已签发证书（即**配额是否已被消耗**）。
	Issued bool `json:"issued,omitempty"`
	// Applied 表示配置是否已成功写入 nginx 并 reload。
	//
	// Issued=true 且 Applied=false 是最需要关注的组合：
	// 证书拿到了、配额花了，但站点并没有启用 HTTPS。
	Applied bool `json:"applied,omitempty"`
	// Expiry 是操作完成后的证书到期时间（便于对比续期效果）。
	Expiry string `json:"expiry,omitempty"`
	// DaysRemaining 是操作完成后的剩余天数。
	DaysRemaining int `json:"days_remaining,omitempty"`
	// Renewed 表示这是一次自动续期（与手工续期区分）。
	//
	// 与 Outcome 正交：自动续期也可能失败。单独一个布尔让
	// `jq 'select(.renewed)'` 能直接筛出全部续期历史。
	Renewed bool `json:"renewed,omitempty"`
}

// AuditOptions 是构造 Auditor 的配置。
type AuditOptions struct {
	// Capacity 是内存环形缓冲容量；<=0 时用 DefaultAuditCapacity。
	Capacity int
	// Path 非空时把每条记录以 JSONL 追加写入该文件。
	// 这里传入的通常是与其它四个审计器**同一个** -audit-log 路径。
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

// Auditor 收集并保存 SSL 操作审计记录。
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
		logger.Info("SSL 操作审计已启用落盘", "path", opts.Path, "memory_capacity", capacity)
	}
	return a, nil
}

// openFile 打开（或创建）审计日志文件。
//
// 与其它四个审计器共用同一文件时的安全性：所有写入方都以 O_APPEND 打开，
// 且每次写入都是**单次 write 系统调用**（一行 JSON + '\n'），
// 因此并发写入不会互相截断（POSIX 保证 O_APPEND 写的原子性）。
func (a *Auditor) openFile(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 0700：审计日志含操作者与域名信息，不该被别人读。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("ssl: 创建审计日志目录 %s 失败: %w", dir, err)
		}
	}
	// 0600 + 追加写：只应属主可读，且绝不覆盖历史记录。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ssl: 打开审计日志 %s 失败: %w", path, err)
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
		ev.Kind = KindSSL
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
		a.logger.Warn("写出 SSL 审计日志失败（操作不受影响）",
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
	// Pending 是结果未知（超时）的条数。
	Pending int `json:"pending"`
	// Issued 是 CA 已签发（配额已消耗）的次数。
	//
	// 前端把这个数字展示出来是有实际价值的：Let's Encrypt 对
	// 同一组域名有每周 5 次重复签发的限制，用户看到这个数字
	// 就能自己判断"我这一周用掉多少配额了"。
	Issued int `json:"issued"`
	// IssuedNotApplied 是"CA 已签发但配置未应用"的计数。
	//
	// 这个数字尤其值得暴露：它等于
	// "配额花了但 HTTPS 没起来"，是需要立刻处理的状况。
	// 正常情况下它应当恒为 0，一旦不为 0 就说明有站点
	// 浪费了签发配额却没有获得 HTTPS。
	IssuedNotApplied int `json:"issued_not_applied"`
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
		case AuditPending:
			st.Pending++
		}
		if ev.Issued {
			st.Issued++
			if !ev.Applied {
				st.IssuedNotApplied++
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
		return fmt.Errorf("ssl: 关闭审计日志失败: %w", err)
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
			return fmt.Errorf("ssl: 导出审计记录失败: %w", err)
		}
	}
	return nil
}
