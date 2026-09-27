package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 防火墙管理器（阶段四 4.6，核心自带）
// ============================================================================
//
// 本文件编排"查询状态 → 列出规则 → 增删端口 / IP 黑白名单"这条链路。
//
// #################### 写操作的固定顺序（不可调换）####################
//
//	① 输入校验        —— 端口/IP/协议/备注全部过白名单
//	② 保护判定        —— 是否涉及面板端口或 SSH 端口
//	③ 二次确认        —— 删除类操作必须带 confirm
//	④ 权限判定        —— firewall.write（由 server 层完成）
//	⑤ 规则定位        —— 找到可精确删除的目标（否则拒绝）
//	⑥ 命令组装与执行
//	⑦ 审计
//
// 顺序本身就是安全设计：
//	· 校验在权限之前（与 3.3 的教训一致）——输入错误应报 400 而不是 403，
//	  否则用户会以为"我没权限"，实际只是端口写错了；
//	· 保护判定在执行之前——绝不能"先删了再提示你删错了"；
//	· 确认在权限之后——避免用"需要确认"掩盖权限问题。

// Options 是构造 Manager 的配置。
type Options struct {
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Executor 为 nil 时使用 os/exec 实现。
	Executor Executor
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// Detector 为 nil 时按默认配置新建。
	Detector *Detector
	// Protector 为 nil 时不提供端口保护（不推荐）。
	Protector *Protector
	// CommandTimeout 是单条命令的超时；<=0 时用 DefaultCommandTimeout。
	CommandTimeout time.Duration
	// DryRun 为 true 时**不执行任何真实命令**，只记录将要执行的命令。
	//
	// ########## 这个开关对本模块的价值 ##########
	//
	// 防火墙误操作可能让用户失联，因此"先看看会发生什么"
	// 有实实在在的意义。dry-run 下全部步骤照跑（含校验、
	// 保护判定、规则定位与命令组装），只是执行器被替换成
	// 只记录不执行的实现。
	//
	// 它**不影响权限与审计**：dry-run 下的操作同样留痕
	// （标记 simulated），因为"谁在什么时候试着改了什么"
	// 本身就是有价值的记录。
	DryRun bool
}

// DefaultCommandTimeout 是单条防火墙命令的默认超时。
//
// ########## 为什么比 4.5 store 的 600s 短得多 ##########
//
// 防火墙命令是**瞬时**的（内核里改一条规则是微秒级）。
// 15 秒已经足够宽松——超过这个时间说明的不是"命令慢"，
// 而是"被 xtables lock 挡住了"（另一个进程正在操作 iptables），
// 此时应当明确告诉用户去排查锁冲突，而不是继续等。
//
// 把超时设得很长反而有害：用户会对着转圈的界面等待，
// 而真正该做的事（看看是不是有别的 iptables 进程在跑）被耽误了。
const DefaultCommandTimeout = 15 * time.Second

// Manager 是防火墙管理器。
type Manager struct {
	opts    Options
	logger  *slog.Logger
	exec    Executor
	auditor *Auditor
	detect  *Detector
	protect *Protector
	timeout time.Duration

	mu sync.Mutex
	// detection 是最近一次探测结果（缓存，避免每次请求都探测）。
	detection *Detection
	// protection 是最近一次保护判定结果（缓存）。
	protection *Protection
}

// NewManager 构造管理器。
func NewManager(opts Options) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	exec := opts.Executor
	if exec == nil {
		exec = NewExecExecutor()
	}
	auditor := opts.Auditor
	if auditor == nil {
		var err error
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}
	detect := opts.Detector
	if detect == nil {
		detect = NewDetector(DetectOptions{Executor: exec})
	}
	timeout := opts.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	return &Manager{
		opts:    opts,
		logger:  logger,
		exec:    exec,
		auditor: auditor,
		detect:  detect,
		protect: opts.Protector,
		timeout: timeout,
	}, nil
}

// Auditor 返回审计器。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// DryRun 返回是否处于试运行模式。
func (m *Manager) DryRun() bool { return m.opts.DryRun }

// CommandTimeout 返回命令超时。
func (m *Manager) CommandTimeout() time.Duration { return m.timeout }

// Executor 返回执行器（供 server 层展示"哪些命令被执行过"）。
func (m *Manager) Executor() Executor { return m.exec }

// ============================================================================
// 状态与规则查询
// ============================================================================

// StatusResult 是 GET /api/firewall 的核心内容。
type StatusResult struct {
	// Detection 是后端探测结论。
	Detection Detection `json:"detection"`
	// Protection 是端口保护判定。
	Protection Protection `json:"protection"`
	// Detail 是选中后端的详细状态（默认策略、日志级别等）。
	Detail StatusDetail `json:"detail"`
	// RuleCount 是解析出的规则条数（便于页面直接展示）。
	RuleCount int `json:"rule_count"`
	// ScannedAt 是本次扫描时间。
	ScannedAt string `json:"scanned_at"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
	// CommandTimeoutSeconds 是命令超时配置。
	CommandTimeoutSeconds float64 `json:"command_timeout_seconds"`
}

// StatusDetail 是后端的详细状态。
type StatusDetail struct {
	// Enabled 表示防火墙是否真正生效。
	Enabled bool `json:"enabled"`
	// DefaultIncoming 是入站默认策略（ufw / iptables）。
	DefaultIncoming string `json:"default_incoming,omitempty"`
	// DefaultOutgoing 是出站默认策略。
	DefaultOutgoing string `json:"default_outgoing,omitempty"`
	// DefaultPolicies 是 iptables 的各链默认策略。
	DefaultPolicies map[string]string `json:"default_policies,omitempty"`
	// Logging 是日志级别（ufw）。
	Logging string `json:"logging,omitempty"`
	// AllowAllIncoming 表示入站默认放行。
	//
	// ########## 这是一个必须显著提示的状态 ##########
	//
	// 默认放行意味着**防火墙几乎不起作用**：
	// 用户看到一堆"允许"规则会以为自己被保护着，
	// 实际所有端口本来就都开着。前端应把这个状态标红。
	AllowAllIncoming bool `json:"allow_all_incoming"`
	// Notes 是状态说明。
	Notes []string `json:"notes,omitempty"`
}

// Status 返回防火墙状态。
func (m *Manager) Status(ctx context.Context) (StatusResult, error) {
	detection, err := m.Detect(ctx, false)
	if err != nil {
		return StatusResult{}, err
	}

	protection := m.Protection(ctx)

	result := StatusResult{
		Detection:             detection,
		Protection:            protection,
		ScannedAt:             time.Now().Format(time.RFC3339),
		DryRun:                m.opts.DryRun,
		CommandTimeoutSeconds: m.timeout.Seconds(),
	}

	if !detection.Available {
		// 没有防火墙不是错误：返回状态 + 安装指引，
		// 让前端渲染说明页而不是红色错误框
		// （与 4.1 无 systemd、4.4 无 certbot 一致的降级策略）。
		return result, nil
	}

	// 读取详细状态。
	detail, rules, err := m.fetchState(ctx, detection.Backend)
	if err != nil {
		// 状态读取失败也降级：仍返回探测结论，
		// 把失败原因放进 Notes 而不是整页报错。
		result.Detail.Notes = append(result.Detail.Notes,
			"读取防火墙详细状态失败: "+err.Error())
		return result, nil
	}
	result.Detail = detail
	result.RuleCount = len(rules)
	return result, nil
}

// Detect 探测后端（cached 为 true 时使用缓存）。
func (m *Manager) Detect(ctx context.Context, cached bool) (Detection, error) {
	m.mu.Lock()
	if cached && m.detection != nil {
		d := *m.detection
		m.mu.Unlock()
		return d, nil
	}
	m.mu.Unlock()

	d, err := m.detect.Detect(ctx)
	if err != nil {
		return Detection{}, err
	}
	m.mu.Lock()
	m.detection = &d
	m.mu.Unlock()
	return d, nil
}

// Protection 返回保护判定（每次重新评估，因为 SSH 端口可能变化）。
func (m *Manager) Protection(ctx context.Context) Protection {
	if m.protect == nil {
		return Protection{}
	}
	p := m.protect.Evaluate(ctx)
	m.mu.Lock()
	m.protection = &p
	m.mu.Unlock()
	return p
}

// RulesResult 是规则查询的结果。
type RulesResult struct {
	// Rules 是全部规则。
	Rules []Rule `json:"rules"`
	// Ports 是端口规则（前端"端口规则"表格）。
	Ports []Rule `json:"ports"`
	// IPRules 是 IP 黑白名单规则（前端"IP 黑白名单"区域）。
	IPRules []Rule `json:"ip_rules"`
	// Counts 是各类计数。
	Counts RuleCounts `json:"counts"`
	// Backend 是当前后端。
	Backend string `json:"backend"`
	// Available 表示后端可用。
	Available bool `json:"available"`
	// UnavailableReason 是不可用原因。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Protection 是保护判定（前端据此标记受保护行）。
	Protection Protection `json:"protection"`
	// ScannedAt 是扫描时间。
	ScannedAt string `json:"scanned_at"`
}

// RuleCounts 是规则计数。
type RuleCounts struct {
	Total int `json:"total"`
	// Ports / IPs 分类计数。
	Ports int `json:"ports"`
	IPs   int `json:"ips"`
	// Allow / Deny 按动作计数。
	Allow int `json:"allow"`
	Deny  int `json:"deny"`
	// Deletable 是其中可被面板删除的条数。
	Deletable int `json:"deletable"`
	// Protected 是涉及受保护端口的条数。
	Protected int `json:"protected"`
	// Panel / External 按来源计数。
	Panel    int `json:"panel"`
	External int `json:"external"`
}

// ListRules 查询规则列表。
func (m *Manager) ListRules(ctx context.Context) (RulesResult, error) {
	detection, err := m.Detect(ctx, true)
	if err != nil {
		return RulesResult{}, err
	}
	protection := m.Protection(ctx)

	result := RulesResult{
		Rules:      []Rule{},
		Ports:      []Rule{},
		IPRules:    []Rule{},
		Backend:    detection.Backend,
		Available:  detection.Available,
		Protection: protection,
		ScannedAt:  time.Now().Format(time.RFC3339),
	}
	if !detection.Available {
		result.UnavailableReason = detection.Reason
		return result, nil
	}

	_, rules, err := m.fetchState(ctx, detection.Backend)
	if err != nil {
		return RulesResult{}, err
	}

	// 给规则打上保护标记。
	lookup := protection.Lookup()
	for i := range rules {
		if rules[i].Kind != KindPort {
			continue
		}
		if pp, ok := lookup.Find(rules[i].Port); ok {
			rules[i].Protected = true
			rules[i].ProtectedReason = pp.Reason
			// 类型也要传（前端据此区分面板端口与 SSH 端口的
			// 警示级别），只给布尔值不够。
			rules[i].ProtectionKind = pp.Kind
		}
	}

	result.Rules = rules
	for _, r := range rules {
		if r.Kind == KindPort {
			result.Ports = append(result.Ports, r)
		} else {
			result.IPRules = append(result.IPRules, r)
		}
		result.Counts.Total++
		switch r.Kind {
		case KindPort:
			result.Counts.Ports++
		default:
			result.Counts.IPs++
		}
		if r.Action == ActionAllow {
			result.Counts.Allow++
		} else {
			result.Counts.Deny++
		}
		if r.Deletable {
			result.Counts.Deletable++
		}
		if r.Protected {
			result.Counts.Protected++
		}
		if r.Origin == OriginPanel {
			result.Counts.Panel++
		} else {
			result.Counts.External++
		}
	}
	return result, nil
}

// fetchState 读取某后端的详细状态与规则。
//
// 每个后端一次执行一到两条只读命令，然后交给 parse.go 解析。
// 全部是**只读**命令，绝不修改系统状态。
func (m *Manager) fetchState(ctx context.Context, backend string) (StatusDetail, []Rule, error) {
	var detail StatusDetail

	switch backend {
	case BackendUFW:
		cmd := BuildUFWStatus()
		res, err := m.run(ctx, cmd)
		if err != nil {
			return detail, nil, err
		}
		st := ParseUFWStatus(res.Stdout)
		detail.Enabled = st.Active
		detail.DefaultIncoming = st.DefaultIncoming
		detail.DefaultOutgoing = st.DefaultOutgoing
		detail.Logging = st.Logging
		detail.AllowAllIncoming = st.Active && !st.IsDenyAllIncoming()
		if !st.Active {
			detail.Notes = append(detail.Notes,
				"ufw 未启用（Status: inactive），当前规则不会生效。")
		}
		if detail.AllowAllIncoming {
			detail.Notes = append(detail.Notes,
				"入站默认策略为 allow，这意味着**除了显式拒绝的端口，所有端口都是开放的**，"+
					"防火墙实际上没有起到防护作用。建议改为 deny。")
		}
		// 规则用 numbered 版本（编号稳定，且便于与命令行对照）。
		ruleCmd := BuildUFWStatusNumbered()
		ruleRes, err := m.run(ctx, ruleCmd)
		if err != nil {
			return detail, ParseUFWRules(res.Stdout), nil
		}
		return detail, ParseUFWRules(ruleRes.Stdout), nil

	case BackendFirewalld:
		stateCmd := BuildFirewallCmdState()
		res, err := m.run(ctx, stateCmd)
		if err != nil {
			return detail, nil, err
		}
		detail.Enabled = strings.Contains(strings.ToLower(res.Stdout), "running") &&
			!strings.Contains(strings.ToLower(res.Stdout), "not running")
		if !detail.Enabled {
			detail.Notes = append(detail.Notes, "firewalld 未运行，规则不会生效。")
		}
		listCmd := BuildFirewallCmdListAll()
		listRes, err := m.run(ctx, listCmd)
		if err != nil {
			return detail, nil, err
		}
		return detail, ParseFirewallCmdListAll(listRes.Stdout), nil

	case BackendNFTables:
		cmd := BuildNFTListRuleset()
		res, err := m.run(ctx, cmd)
		if err != nil {
			return detail, nil, err
		}
		// nftables 没有"启用/未启用"的概念：规则写了就生效。
		//
		// 但"生效"不等于"有防护"：若没有 input 链或默认策略是 accept，
		// 实际什么都没拦。这一点通过规则列表与说明体现，
		// 而不是伪造一个 Enabled 状态。
		detail.Enabled = true
		detail.Notes = append(detail.Notes,
			"nftables 没有独立的「启用」开关：规则写入即生效。"+
				"请检查 input 链的默认策略是否为 accept（那意味着未匹配的流量全部放行）。")
		return detail, ParseNFTRules(res.Stdout), nil

	case BackendIPTables:
		cmd, err := BuildIPTablesListRules(m.detect.Chain())
		if err != nil {
			return detail, nil, err
		}
		res, err := m.run(ctx, cmd)
		if err != nil {
			return detail, nil, err
		}
		policies := ParseIPTablesDefaultPolicies(res.Stdout)
		detail.DefaultPolicies = policies
		detail.Enabled = true
		if p, ok := policies["INPUT"]; ok {
			detail.DefaultIncoming = strings.ToLower(p)
			detail.AllowAllIncoming = strings.EqualFold(p, "ACCEPT")
		}
		if detail.AllowAllIncoming {
			detail.Notes = append(detail.Notes,
				"INPUT 链默认策略为 ACCEPT，这意味着**未匹配任何规则的流量全部放行**，"+
					"防火墙实际上没有起到防护作用。")
		}
		return detail, ParseIPTablesRules(res.Stdout), nil

	default:
		return detail, nil, fmt.Errorf("%w: 未知后端 %q", ErrUnavailable, backend)
	}
}

// ============================================================================
// 写操作
// ============================================================================

// PortRequest 是"放行/拒绝端口"的请求。
type PortRequest struct {
	// Port 是端口或范围（如 "8080" 或 "8080-8090"）。
	Port string `json:"port"`
	// Protocol 是 tcp / udp / any。
	Protocol string `json:"protocol"`
	// Source 是来源 IP/网段（空 = 任意来源）。
	Source string `json:"source"`
	// Action 是 allow / deny。
	Action string `json:"action"`
	// Comment 是备注。
	Comment string `json:"comment"`
}

// DeletePortRequest 是"删除端口规则"的请求。
type DeletePortRequest struct {
	// Port / Protocol / Source / Action 唯一确定一条规则。
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Action   string `json:"action"`
	// Confirm 是二次确认标记，**必须为 true**。
	//
	// ########## 服务端强制，不依赖前端弹窗 ##########
	//
	// 计划明确要求"删除规则前必须二次确认，避免把 SSH 端口误关导致失联"。
	// 前端弹窗只是体验；真正的边界在这里——
	// 不带 confirm 的请求一律 428，无论前端怎么做。
	Confirm bool `json:"confirm"`
	// Force 表示明知端口受保护仍要删除。
	Force bool `json:"force"`
}

// IPRequest 是"IP 黑白名单"的请求。
type IPRequest struct {
	// IP 是地址或网段。
	IP string `json:"ip"`
	// Direction 是 allow（白名单）或 deny（黑名单）。
	Direction string `json:"direction"`
	// Comment 是备注。
	Comment string `json:"comment"`
}

// DeleteIPRequest 是"删除 IP 规则"的请求。
type DeleteIPRequest struct {
	IP        string `json:"ip"`
	Direction string `json:"direction"`
	// Confirm 必须为 true（同 DeletePortRequest）。
	Confirm bool `json:"confirm"`
}

// OpResult 是一次写操作的结果。
type OpResult struct {
	// Commands 是实际执行（或将要执行）的命令描述。
	//
	// ########## 为什么把命令暴露给用户 ##########
	//
	// 用户改完防火墙后可能想在其他机器上做同样的操作，
	// 或者想确认"面板到底做了什么"。把命令如实列出，
	// 让面板的行为完全可审计、可复现，而不是一个黑盒。
	Commands []string `json:"commands"`
	// Backend 是执行时使用的后端。
	Backend string `json:"backend"`
	// Simulated 表示这是试运行（命令未真正执行）。
	Simulated bool `json:"simulated"`
	// VerificationFailure 非空表示命令执行后**回读校验失败**。
	//
	// ########## 为什么需要回读校验 ##########
	//
	// 命令返回 0 不等于规则真的生效了。例如
	// ufw 在未启用时会拒绝（好），但某些后端在规则已存在时
	// 静默成功。回读一次让"添加成功"这个结论有依据。
	VerificationFailure string `json:"verification_failure,omitempty"`
}

// run 执行一条命令（或试运行）。
func (m *Manager) run(ctx context.Context, cmd Command) (ExecResult, error) {
	if m.opts.DryRun {
		// 试运行：不执行，只记录。
		//
		// 返回一个"成功"的空结果让上层流程继续走下去
		// （这样试运行报告的是"如果执行会怎样"，
		//  而不是"什么都没做因为没执行"）。
		m.logger.Info("防火墙试运行（不执行真实命令）", "command", cmd.String())
		return ExecResult{}, nil
	}
	if len(cmd.Args) > 0 {
		m.assertNoFlush(cmd)
	}
	cctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	return m.exec.Run(cctx, cmd.Name, cmd.Args)
}

// assertNoFlush 是最后一道防线：拒绝执行任何含 flush 的命令。
//
// ########## 为什么在运行时再检查一次 ##########
//
// command.go 的组装函数在类型层面就不产生 flush
// （BuildNFTDeletePort 只接受 handle），并有测试锁死。
// 这里再加一道**运行时**检查看起来冗余，但成本极低，
// 而它挡住的是本模块唯一可能造成灾难的操作：
//
//	`nft flush ruleset` 会清空整台机器的防火墙规则。
//	用户点一下"删除 8080"，结果是 SSH 白名单、ufw 的整套链
//	全部消失——而且**无法撤销**（防火墙没有回收站）。
//
// 一旦将来有人为了"让删除能用"而绕过组装函数直接拼命令，
// 这一层会立刻 panic/拒绝，而不是安静地把机器脱光。
func (m *Manager) assertNoFlush(cmd Command) {
	for _, a := range cmd.Args {
		if strings.Contains(strings.ToLower(a), "flush") {
			// 这是编程错误：组装层保证不会出现 flush。
			// 用 panic 而不是返回错误，是因为"能走到这里"
			// 说明代码有严重缺陷，必须被测试立刻发现。
			panic(fmt.Sprintf(
				"firewall: 内部错误——命令中出现 flush，这会造成清空防火墙的灾难后果: %s",
				cmd.String()))
		}
	}
}

// AddPort 放行/拒绝一个端口。
func (m *Manager) AddPort(ctx context.Context, req PortRequest) (OpResult, error) {
	var result OpResult

	// ① 输入校验。
	port, err := ValidatePortSpec(req.Port)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	protocol, err := ValidateProtocol(req.Protocol)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	action, err := ValidateAction(req.Action)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	comment, err := ValidateComment(req.Comment)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	source := ""
	if req.Source != "" {
		rule, err := ValidateIPRule(req.Source)
		if err != nil {
			return result, fmt.Errorf("%w: 来源地址非法: %v", ErrInvalidRule, err)
		}
		source = rule.String()
	}

	detection, err := m.Detect(ctx, true)
	if err != nil {
		return result, err
	}
	if !detection.Available {
		return result, fmt.Errorf("%w: %s", ErrUnavailable, detection.Reason)
	}
	result.Backend = detection.Backend
	result.Simulated = m.opts.DryRun

	key := RuleKey{Port: port, Protocol: protocol, Source: source, Action: action}
	markedComment := MarkPanelComment(comment)

	// ② 组装命令（可能展开成多条，例如 ufw/iptables 的 any 协议）。
	cmds, err := m.buildAddCommands(detection.Backend, key, markedComment)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}

	// ③ 执行。
	for _, cmd := range cmds {
		if _, err := m.run(ctx, cmd); err != nil {
			return result, m.commandError(cmd, err)
		}
		result.Commands = append(result.Commands, cmd.String())
	}
	return result, nil
}

// buildAddCommands 组装"添加端口规则"的命令（可能需要多条）。
//
// ########## 为什么返回切片而不是单条 ##########
//
// ufw 与 iptables 的一条规则只能有一个协议，
// 因此 "any"（tcp+udp）必须展开成两条。
// 若返回单条并静默只放行 tcp，用户会以为 UDP 也开了
// ——DNS(53)、WireGuard(51820)、游戏服务器都会静默失效。
func (m *Manager) buildAddCommands(backend string, key RuleKey, comment string) ([]Command, error) {
	switch backend {
	case BackendUFW:
		if key.Protocol == ProtoAny {
			var out []Command
			for _, p := range []string{ProtoTCP, ProtoUDP} {
				k := key
				k.Protocol = p
				c, err := BuildUFWAddPort(k, comment)
				if err != nil {
					return nil, err
				}
				out = append(out, c)
			}
			return out, nil
		}
		c, err := BuildUFWAddPort(key, comment)
		if err != nil {
			return nil, err
		}
		return []Command{c}, nil

	case BackendFirewalld:
		if key.Protocol == ProtoAny {
			var out []Command
			for _, p := range []string{ProtoTCP, ProtoUDP} {
				k := key
				k.Protocol = p
				c, err := BuildFirewallCmdAddPort(k, comment)
				if err != nil {
					return nil, err
				}
				out = append(out, c)
			}
			// firewalld 需要 reload 才能生效（--permanent 只写配置）。
			out = append(out, Command{Name: "firewall-cmd", Args: []string{"--reload"}})
			return out, nil
		}
		c, err := BuildFirewallCmdAddPort(key, comment)
		if err != nil {
			return nil, err
		}
		return []Command{c, {Name: "firewall-cmd", Args: []string{"--reload"}}}, nil

	case BackendNFTables:
		c, err := BuildNFTAddPort(m.detect.Table(), m.detect.Chain(), key, comment)
		if err != nil {
			return nil, err
		}
		return []Command{c}, nil

	case BackendIPTables:
		if key.Protocol == ProtoAny {
			var out []Command
			for _, p := range []string{ProtoTCP, ProtoUDP} {
				k := key
				k.Protocol = p
				c, err := BuildIPTablesAddPort(k, comment)
				if err != nil {
					return nil, err
				}
				out = append(out, c)
			}
			return out, nil
		}
		c, err := BuildIPTablesAddPort(key, comment)
		if err != nil {
			return nil, err
		}
		return []Command{c}, nil

	default:
		return nil, fmt.Errorf("不支持的后端 %q", backend)
	}
}

// DeletePort 删除一条端口规则。
//
// ########## 本函数是安全设计的集中体现 ##########
//
// 三道闸门，缺一不可：
//
//	① Confirm —— 服务端强制二次确认（428）
//	② Protect —— 受保护端口默认拒绝（409），需显式 force
//	③ Deletable —— 找不到可精确删除的目标就拒绝（409），
//	              绝不用"清空重来"兜底
func (m *Manager) DeletePort(ctx context.Context, req DeletePortRequest) (OpResult, error) {
	var result OpResult

	// ① 二次确认（在输入校验之前：这是"是否继续"的问题，
	//    与输入是否合法无关，先问清楚更符合用户预期）。
	if !req.Confirm {
		return result, fmt.Errorf("%w: 删除操作需要在请求中显式确认（confirm=true）", ErrConfirmRequired)
	}

	// ② 输入校验。
	port, err := ValidatePortSpec(req.Port)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	protocol, err := ValidateProtocol(req.Protocol)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	action, err := ValidateAction(req.Action)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	source := ""
	if req.Source != "" {
		rule, err := ValidateIPRule(req.Source)
		if err != nil {
			return result, fmt.Errorf("%w: 来源地址非法: %v", ErrInvalidRule, err)
		}
		source = rule.String()
	}

	detection, err := m.Detect(ctx, true)
	if err != nil {
		return result, err
	}
	if !detection.Available {
		return result, fmt.Errorf("%w: %s", ErrUnavailable, detection.Reason)
	}
	result.Backend = detection.Backend
	result.Simulated = m.opts.DryRun

	// ③ 保护判定（在真正删除之前）。
	if m.protect != nil && !req.Force {
		protection := m.Protection(ctx)
		if pp, ok := protection.Lookup().Find(port); ok {
			return result, ProtectPortError(pp)
		}
	}

	key := RuleKey{Port: port, Protocol: protocol, Source: source, Action: action}

	// ④ 定位可精确删除的目标。
	//
	// ########## 为什么不直接用用户给的参数组装删除命令 ##########
	//
	// 因为各后端删除所需的信息不止"端口+协议"：
	//	nft     需要 handle
	//	iptables 需要内核实际的完整规格（含 -m tcp、-m comment 等）
	//	firewalld 的 rich rule 需要逐字节一致的原文
	//
	// 因此必须**先读回规则列表、找到匹配的那一条**，
	// 再用它的原始信息去删除。这也是"只删除能精确识别的规则"
	// 这一要求的落地方式：找不到就明确拒绝。
	_, rules, err := m.fetchState(ctx, detection.Backend)
	if err != nil {
		return result, err
	}
	target, err := m.findRuleToDelete(rules, key)
	if err != nil {
		return result, err
	}

	// ⑤ 组装删除命令。
	cmd, err := m.buildDeleteCommand(detection.Backend, target)
	if err != nil {
		return result, err
	}

	// ⑥ 执行。
	if _, err := m.run(ctx, cmd); err != nil {
		return result, m.commandError(cmd, err)
	}
	result.Commands = append(result.Commands, cmd.String())
	return result, nil
}

// findRuleToDelete 在规则列表里定位要删除的那一条。
//
// ########## 匹配规则：内容相等，而不是下标 ##########
//
// 用户看到第 3 条并点删除，而在他点之前防火墙可能已被别人改过，
// 此时第 3 条已经不是他看到的那条了。
// 因此用**可比较的内容**匹配：端口 + 协议 + 来源 + 动作。
//
// ########## 匹配不上时的语义 ##########
//
// 找不到 -> ErrRuleNotFound（404）：规则可能已被删除。
// 找到但不可删除 -> ErrNotDeletable（409）：给出具体原因。
//
// 两种情况都不允许"退化成清空"。
func (m *Manager) findRuleToDelete(rules []Rule, key RuleKey) (Rule, error) {
	var matched *Rule
	for i := range rules {
		r := &rules[i]
		if r.Kind != KindPort {
			continue
		}
		if r.Port.Start != key.Port.Start || r.Port.End != key.Port.End {
			continue
		}
		if !protocolMatches(r.Protocol, key.Protocol) {
			continue
		}
		if !sourceMatches(r.Source, key.Source) {
			continue
		}
		if r.Action != key.Action {
			continue
		}
		matched = r
		break
	}

	if matched == nil {
		return Rule{}, fmt.Errorf("%w: 未找到匹配的规则 %s（可能已被其它工具删除，请刷新后重试）",
			ErrRuleNotFound, key.String())
	}
	if !matched.Deletable {
		reason := matched.NotDeletableReason
		if reason == "" {
			reason = "该规则无法被精确删除。"
		}
		return Rule{}, fmt.Errorf("%w: %s", ErrNotDeletable, reason)
	}
	return *matched, nil
}

// protocolMatches 比较协议。
//
// "any" 在后端里可能表现为 any，也可能表现为空——
// 两者语义相同，应当匹配上。
func protocolMatches(ruleProto, wantProto string) bool {
	normalize := func(p string) string {
		if p == "" {
			return ProtoAny
		}
		return strings.ToLower(p)
	}
	return normalize(ruleProto) == normalize(wantProto)
}

// sourceMatches 比较来源。
//
// 空串与 "any"/"0.0.0.0/0" 语义相同（任意来源），应当匹配上：
// 用户在界面上看到"来源: 任意"并点删除，
// 而实际规则里的来源被后端写成 0.0.0.0/0 时，
// 严格的字符串比较会让删除失败——那是个很莫名的体验。
func sourceMatches(ruleSource, wantSource string) bool {
	norm := func(s string) string {
		t := strings.TrimSpace(strings.ToLower(s))
		switch t {
		case "", "any", "anywhere", "0.0.0.0/0", "::/0":
			return ""
		}
		return t
	}
	return norm(ruleSource) == norm(wantSource)
}

// buildDeleteCommand 按后端组装删除命令。
func (m *Manager) buildDeleteCommand(backend string, target Rule) (Command, error) {
	switch backend {
	case BackendUFW:
		// ########## IP 规则与端口规则的删除命令形态不同 ##########
		//
		//	端口规则：ufw delete allow proto tcp to any port 8080
		//	IP  规则：ufw delete deny from 203.0.113.5
		//
		// ########## 这个分支是被端到端验证抓出来的 ##########
		//
		// 原先所有 ufw 删除都走 BuildUFWDeletePort，而它会校验协议。
		// IP 规则没有协议（Protocol 为空串），于是删除一个
		// 黑名单条目会返回 500「不支持的协议 ""」——一个用户在界面上
		// 点了"删除"却只看到内部错误，且完全无法理解为什么。
		//
		// 单元测试没抓到它，是因为测试都构造了完整的端口规则；
		// 端到端测试走了真实的"添加 IP → 列出 → 删除"链路才暴露出来。
		comment := ""
		if target.Comment != "" {
			comment = MarkPanelComment(target.Comment)
		} else if target.Origin == OriginPanel {
			comment = PanelCommentMarker
		}

		if target.Kind == KindIP || target.PortText == "" {
			// IP 黑白名单条目。
			verb := "allow"
			if target.Action == ActionDeny {
				verb = "deny"
			}
			args := []string{"delete", verb, "from", target.Source}
			if comment != "" {
				args = append(args, "comment", comment)
			}
			return Command{Name: "ufw", Args: args}, nil
		}

		// 端口规则：ufw 按内容删除，参数必须与添加时一致（含备注）。
		return BuildUFWDeletePort(RuleKey{
			Port:     target.Port,
			Protocol: target.Protocol,
			Source:   target.Source,
			Action:   target.Action,
		}, comment)

	case BackendFirewalld:
		if target.Kind == KindPort {
			key := RuleKey{
				Port:     target.Port,
				Protocol: target.Protocol,
				Source:   target.Source,
				Action:   target.Action,
			}
			cmd, err := BuildFirewallCmdRemovePort(key, "")
			if err != nil {
				return Command{}, err
			}
			// 与添加对应：删除后同样需要 reload。
			return cmd, nil
		}
		cmd := BuildFirewallCmdRemoveSource(RuleKey{Action: target.Action}, target.Source, "")
		return cmd, nil

	case BackendNFTables:
		// ########## nft 只能按 handle 删 ##########
		//
		// handle <= 0 时 BuildNFTDeletePort 会返回错误，
		// 我们把它转成更明确的 ErrNotDeletable。
		// 这里**没有**任何"退化成 flush"的分支，
		// 因为那会清空整台机器的防火墙。
		if target.Handle <= 0 {
			return Command{}, fmt.Errorf("%w: %s", ErrNotDeletable, notDeletableReason(0))
		}
		cmd, err := BuildNFTDeletePort(m.detect.Table(), m.detect.Chain(), target.Handle)
		if err != nil {
			return Command{}, fmt.Errorf("%w: %v", ErrNotDeletable, err)
		}
		return cmd, nil

	case BackendIPTables:
		// ########## iptables 用解析出的原始规格删除 ##########
		//
		// 规格来自 `iptables -S` 的输出，包含内核自己补的匹配器
		// （-m tcp、-m comment 等）。按用户输入重新组装会漏掉它们，
		// 导致 -D 报 "Bad rule (does a matching rule exist in that chain?)"。
		chain := m.detect.Chain()
		if len(target.Spec) >= 2 && !strings.HasPrefix(target.Spec[1], "-") {
			chain = target.Spec[1]
		}
		cmd, err := BuildIPTablesDeleteSpec(chain, target.Spec, target.Comment)
		if err != nil {
			return Command{}, fmt.Errorf("%w: %v", ErrNotDeletable, err)
		}
		return cmd, nil

	default:
		return Command{}, fmt.Errorf("%w: 不支持的后端 %q", ErrUnavailable, backend)
	}
}

// AddIP 添加 IP 黑白名单。
func (m *Manager) AddIP(ctx context.Context, req IPRequest) (OpResult, error) {
	var result OpResult

	rule, err := ValidateIPRule(req.IP)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	direction, err := ValidateDirection(req.Direction)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	comment, err := ValidateComment(req.Comment)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}

	detection, err := m.Detect(ctx, true)
	if err != nil {
		return result, err
	}
	if !detection.Available {
		return result, fmt.Errorf("%w: %s", ErrUnavailable, detection.Reason)
	}
	result.Backend = detection.Backend
	result.Simulated = m.opts.DryRun

	source := rule.String()
	action := ActionAllow
	if direction == DirectionDeny {
		action = ActionDeny
	}
	markedComment := MarkPanelComment(comment)

	var cmd Command
	switch detection.Backend {
	case BackendUFW:
		// ufw 表达"来自某来源的任意端口"：
		//	白名单 -> ufw allow from <ip>
		//	黑名单 -> ufw deny from <ip>
		verb := "allow"
		if action == ActionDeny {
			verb = "deny"
		}
		args := []string{verb, "from", source}
		if markedComment != "" {
			args = append(args, "comment", markedComment)
		}
		cmd = Command{Name: "ufw", Args: args}

	case BackendFirewalld:
		cmd = BuildFirewallCmdAddSource(RuleKey{Action: action}, source, markedComment)

	case BackendNFTables:
		verb := "accept"
		if action == ActionDeny {
			verb = "drop"
		}
		family := "ip"
		if strings.Contains(source, ":") {
			family = "ip6"
		}
		args := []string{"add", "rule", "inet", m.detect.Table(), m.detect.Chain(),
			family, "saddr", source}
		if markedComment != "" {
			args = append(args, "comment", fmt.Sprintf("%q", markedComment))
		}
		args = append(args, verb)
		cmd = Command{Name: "nft", Args: args}

	case BackendIPTables:
		verdict := "ACCEPT"
		if action == ActionDeny {
			verdict = "DROP"
		}
		args := []string{"-A", "INPUT", "-s", source, "-j", verdict}
		if markedComment != "" {
			args = append(args, "-m", "comment", "--comment", fmt.Sprintf("%q", markedComment))
		}
		cmd = Command{Name: "iptables", Args: args}

	default:
		return result, fmt.Errorf("%w: 不支持的后端 %q", ErrUnavailable, detection.Backend)
	}

	if _, err := m.run(ctx, cmd); err != nil {
		return result, m.commandError(cmd, err)
	}
	result.Commands = append(result.Commands, cmd.String())
	return result, nil
}

// DeleteIP 删除 IP 黑白名单。
func (m *Manager) DeleteIP(ctx context.Context, req DeleteIPRequest) (OpResult, error) {
	var result OpResult

	if !req.Confirm {
		return result, fmt.Errorf("%w: 删除操作需要在请求中显式确认（confirm=true）", ErrConfirmRequired)
	}
	rule, err := ValidateIPRule(req.IP)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	direction, err := ValidateDirection(req.Direction)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}

	detection, err := m.Detect(ctx, true)
	if err != nil {
		return result, err
	}
	if !detection.Available {
		return result, fmt.Errorf("%w: %s", ErrUnavailable, detection.Reason)
	}
	result.Backend = detection.Backend
	result.Simulated = m.opts.DryRun

	source := rule.String()
	action := ActionAllow
	if direction == DirectionDeny {
		action = ActionDeny
	}

	// 与端口删除同理：先定位，再删除。
	_, rules, err := m.fetchState(ctx, detection.Backend)
	if err != nil {
		return result, err
	}
	var target *Rule
	for i := range rules {
		r := &rules[i]
		if r.Kind != KindIP {
			continue
		}
		if !sourceMatches(r.Source, source) {
			continue
		}
		if r.PortText != "" {
			// 这是"来自某来源访问某端口"的规则，
			// 不是纯粹的 IP 黑白名单条目。
			continue
		}
		if r.Action != action {
			continue
		}
		target = r
		break
	}
	if target == nil {
		return result, fmt.Errorf("%w: 未找到匹配的 IP 规则 %s（可能已被其它工具删除，请刷新后重试）",
			ErrRuleNotFound, source)
	}
	if !target.Deletable {
		reason := target.NotDeletableReason
		if reason == "" {
			reason = "该规则无法被精确删除。"
		}
		return result, fmt.Errorf("%w: %s", ErrNotDeletable, reason)
	}

	cmd, err := m.buildDeleteCommand(detection.Backend, *target)
	if err != nil {
		return result, err
	}
	if _, err := m.run(ctx, cmd); err != nil {
		return result, m.commandError(cmd, err)
	}
	result.Commands = append(result.Commands, cmd.String())
	return result, nil
}

// commandError 把执行错误包装成带命令上下文的错误。
//
// ########## 为什么要把命令放进错误信息 ##########
//
// 用户看到"命令执行失败"时，第一反应是"我哪里填错了"。
// 而真实原因可能是权限不足、xtables lock 被占、后端未启用。
// 把**实际执行的命令**与**原始输出**一起给出，
// 用户可以直接复制到终端复现，或者据此判断是不是环境问题。
func (m *Manager) commandError(cmd Command, err error) error {
	msg := err.Error()
	// 命令失败但可能有部分输出，尽量带上。
	var hint string
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "permission") || strings.Contains(low, "not permitted"):
		hint = "（提示：防火墙操作需要 root 权限与 CAP_NET_ADMIN，请确认面板以 root 运行）"
	case strings.Contains(low, "xtables") || strings.Contains(low, "resource temporarily unavailable"):
		hint = "（提示：可能另有进程正在操作防火墙（xtables lock），请稍后重试）"
	case errors.Is(err, ErrTimeout):
		hint = "（提示：命令超时，请确认没有其它防火墙操作正在进行）"
	}
	return fmt.Errorf("%w: 执行 `%s` 失败: %s%s", ErrCommandFailed, cmd.String(), msg, hint)
}

// ============================================================================
// 能力探测
// ============================================================================

// CapabilityInfo 是单个后端的能力说明。
type CapabilityInfo struct {
	Backend string `json:"backend"`
	Label   string `json:"label"`
	// Deletion 描述该后端的删除方式（前端展示"为什么这条删不掉"）。
	Deletion string `json:"deletion"`
	// SupportsComment 表示是否支持备注。
	SupportsComment bool `json:"supports_comment"`
	// SupportsSource 表示是否支持来源限定。
	SupportsSource bool `json:"supports_source"`
	// SupportsAnyProtocol 表示一条规则能否同时覆盖 tcp+udp。
	SupportsAnyProtocol bool `json:"supports_any_protocol"`
}

// Capabilities 返回各后端的能力说明。
//
// 这个接口回答的是"为什么某些操作在不同后端表现不同"，
// 是用户理解面板行为的第一入口。
func (m *Manager) Capabilities() []CapabilityInfo {
	return []CapabilityInfo{
		{
			Backend: BackendUFW, Label: BackendLabel(BackendUFW),
			Deletion:            "按规则内容匹配删除（无需句柄）",
			SupportsComment:     true,
			SupportsSource:      true,
			SupportsAnyProtocol: false,
		},
		{
			Backend: BackendFirewalld, Label: BackendLabel(BackendFirewalld),
			Deletion:            "按内容删除；带来源与拒绝规则以 rich rule 表达",
			SupportsComment:     false, // firewalld 的 rich rule 无注释字段
			SupportsSource:      true,
			SupportsAnyProtocol: false,
		},
		{
			Backend: BackendNFTables, Label: BackendLabel(BackendNFTables),
			Deletion:            "**只能按 handle（句柄）删除**；解析不出句柄的规则不可删除，面板绝不使用清空规则集代替",
			SupportsComment:     true,
			SupportsSource:      true,
			SupportsAnyProtocol: true,
		},
		{
			Backend: BackendIPTables, Label: BackendLabel(BackendIPTables),
			Deletion:            "按 iptables -S 解析出的精确规格删除；跳转到自定义链的规则不可删除",
			SupportsComment:     true,
			SupportsSource:      true,
			SupportsAnyProtocol: false,
		},
	}
}
