package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// 防火墙后端探测（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 优先级：ufw → firewalld → nftables → iptables。
//
// #################### 为什么是这个顺序 ####################
//
// 它按"语义层级从高到低"排列，也就是**按用户意图的表达能力**：
//
//	ufw        面向人的高层封装，规则带"允许/拒绝 8080/tcp"的明确语义，
//	           删除可以按内容匹配。是本模块能提供最好体验的后端。
//	firewalld  次高层，有 zone/rich rule 概念，删除可按内容。
//	nftables   内核原生的现代框架，能力强但规则是"表达式"，
//	           删除只能按 handle（见 command.go 的说明）。
//	iptables   最底层、最古老，删除需要精确规格回传。
//
// 顺序不能反：一台机器上可能同时装着 ufw 与 iptables，
// 而 ufw 的规则**就是** iptables 规则（ufw 是 iptables 的前端）。
// 若优先选 iptables，用户在面板上加的规则会与 ufw 的规则混在一起，
// 而 ufw 自己的规则集是它启动时重建的——用户会看到
// "面板上说加成功了，返回列表却没有"，或者更糟：
// 重启 ufw 后规则被 ufw 的默认策略覆盖掉。

// 防火墙后端标识。
const (
	// BackendUFW 是 ufw（Uncomplicated Firewall），Debian/Ubuntu 系常用。
	BackendUFW = "ufw"
	// BackendFirewalld 是 firewalld，RHEL/CentOS/Fedora 系常用。
	BackendFirewalld = "firewalld"
	// BackendNFTables 是 nftables（nft 命令），现代内核原生框架。
	BackendNFTables = "nftables"
	// BackendIPTables 是 iptables（含 nf_tables 后端实现）。
	BackendIPTables = "iptables"
	// BackendNone 表示没有探测到任何可用的防火墙后端。
	BackendNone = "none"
)

// BackendPriority 是后端探测的优先级顺序（从高到低）。
//
// 单独导出而不是藏在函数里：前端要按同样的顺序展示"探测了哪些后端"，
// 两处顺序不一致会让用户看到的探测结果与实际情况对不上。
var BackendPriority = []string{BackendUFW, BackendFirewalld, BackendNFTables, BackendIPTables}

// BackendLabel 返回后端的展示名。
func BackendLabel(backend string) string {
	switch backend {
	case BackendUFW:
		return "ufw"
	case BackendFirewalld:
		return "firewalld"
	case BackendNFTables:
		return "nftables"
	case BackendIPTables:
		return "iptables"
	case BackendNone:
		return "未检测到"
	default:
		return backend
	}
}

// 探测过程中的错误。
var (
	// ErrUnavailable 表示没有可用的防火墙后端。
	ErrUnavailable = errors.New("firewall: 当前系统未安装可用的防火墙")
	// ErrBackendInactive 表示后端存在但未启用。
	//
	// ########## 为什么"未启用"要单独一个错误 ##########
	//
	// ufw 装了但没 enable 时，`ufw status` 输出 "Status: inactive"
	// 且**退出码为 0**。若把它当成"不可用"，用户会看到
	// "未安装防火墙"从而去装一个已经装好的东西；
	// 若当成"可用"，用户以为规则生效了，实际一条都没生效
	// （数据包根本没经过 ufw 的链）。
	//
	// 因此单独一个状态，让前端能明确显示"已安装但未启用，
	// 规则不会生效"并给出启用方式。
	ErrBackendInactive = errors.New("firewall: 防火墙已安装但未启用，规则不会生效")
	// ErrPermission 表示命令存在但没有足够权限执行。
	ErrPermission = errors.New("firewall: 权限不足，操作防火墙需要 root 权限")
	// ErrInvalidRule 表示规则非法。
	ErrInvalidRule = errors.New("firewall: 规则非法")
	// ErrRuleNotFound 表示要删除的规则不存在。
	ErrRuleNotFound = errors.New("firewall: 规则不存在")
	// ErrNotDeletable 表示该规则无法被精确删除。
	//
	// ########## 这个错误是本模块安全设计的核心 ##########
	//
	// 出现它的情形：nftables 规则解析不出 handle、
	// iptables 规则解析不出精确规格（如跳转到自定义链的复杂规则）。
	//
	// 此时**绝不能**用"清空重来"之类的做法兜底——
	// 对 nft 是 flush ruleset（清空全部规则），
	// 对 iptables 是 flush <链>（清空整条链）。
	// 前者会让用户点一下按钮就丢掉 SSH 白名单，
	// 后者会丢掉该链上所有非面板创建的规则。
	//
	// 正确做法是如实拒绝，并在前端标注"该规则由其它工具创建，
	// 请用原工具删除"。
	ErrNotDeletable = errors.New("firewall: 该规则无法被精确删除")
	// ErrProtectedPort 表示试图删除被保护的端口。
	ErrProtectedPort = errors.New("firewall: 该端口受保护，拒绝删除")
	// ErrConfirmRequired 表示缺少二次确认。
	ErrConfirmRequired = errors.New("firewall: 删除操作需要二次确认")
	// ErrTimeout 表示命令超时。
	ErrTimeout = errors.New("firewall: 操作超时")
	// ErrCommandFailed 表示命令执行失败。
	ErrCommandFailed = errors.New("firewall: 命令执行失败")
)

// BackendInfo 描述一个后端在本机上的可用情况。
//
// 之所以对**所有**后端都输出一份（而不只输出选中的那个），
// 是为了让"为什么选它"可被用户验证：一台机器上可能装了两个后端，
// 用户看到面板选了 ufw 而自己习惯 firewalld 时，
// 需要知道 firewalld 到底是没装还是探测失败。
type BackendInfo struct {
	// Backend 是后端标识。
	Backend string `json:"backend"`
	// Label 是展示名。
	Label string `json:"label"`
	// Installed 表示命令是否存在。
	Installed bool `json:"installed"`
	// Available 表示命令存在且可用（能成功执行只读查询）。
	Available bool `json:"available"`
	// Active 表示防火墙是否已启用（规则是否真正生效）。
	//
	// 与 Available 正交：ufw 装好了（Available=true）
	// 但没 enable（Active=false）是极常见的状态，
	// 此时面板必须明确告诉用户"规则不会生效"。
	Active bool `json:"active"`
	// Version 是探测到的版本（拿不到时为空）。
	Version string `json:"version,omitempty"`
	// Reason 是不可用或未启用的原因（可用且启用时为空）。
	Reason string `json:"reason,omitempty"`
	// Hint 是"怎么办"的可操作提示。
	Hint string `json:"hint,omitempty"`
	// Selected 表示这是最终选中的后端。
	Selected bool `json:"selected"`
}

// Detection 是后端探测的完整结论。
type Detection struct {
	// Backend 是选中的后端（BackendNone 表示都不可用）。
	Backend string `json:"backend"`
	// Label 是选中后端的展示名。
	Label string `json:"label"`
	// Available 表示是否存在可用的后端。
	Available bool `json:"available"`
	// Active 表示选中的后端是否已启用。
	Active bool `json:"active"`
	// Candidates 是全部后端的探测结果（含未选中的）。
	Candidates []BackendInfo `json:"candidates"`
	// Reason 是不可用时的原因（`available=false` 时应有值）。
	Reason string `json:"reason,omitempty"`
	// Hint 是安装指引（不可用时给出）。
	Hint string `json:"hint,omitempty"`
	// Notes 是探测过程中的补充说明（如"检测到多个后端，已按优先级选择"）。
	Notes []string `json:"notes,omitempty"`
}

// DetectOptions 是探测的配置。
type DetectOptions struct {
	// Executor 用于执行探测命令；为 nil 时使用真实执行器。
	Executor Executor
	// ForceBackend 非空时跳过自动探测，直接使用该后端。
	//
	// ########## 为什么需要它 ##########
	//
	// 探测靠"命令能否成功执行"判断，而受限环境（容器里没有
	// NET_ADMIN capability）会让所有后端都探测失败，
	// 用户明明知道装了 ufw 却用不了。
	// 显式指定后端可以绕过探测，让命令照常组装
	// （执行失败时给出的是"权限不足"这个更准确的原因）。
	ForceBackend string
	// Table / Chain 是 nftables 的默认表与链（默认 filter / input）。
	Table string
	Chain string
}

// DefaultTable 是 nftables 的默认表名。
//
// "filter" 是 nft 的常规表名，但注意 ufw 用的是 **"filter" 表下的
// 自定义链**（ufw-before-input 等）——它们不与本模块直接冲突，
// 因为本模块默认往 input 链追加，而 ufw 的规则在它自己的链里。
const DefaultTable = "filter"

// DefaultChain 是 nftables 与 iptables 的默认链名。
const DefaultChain = "input"

// Detector 探测本机的防火墙后端。
type Detector struct {
	exec    Executor
	force   string
	table   string
	chain   string
	version map[string]string
}

// NewDetector 构造探测器。
func NewDetector(opts DetectOptions) *Detector {
	exec := opts.Executor
	if exec == nil {
		exec = NewExecExecutor()
	}
	table := opts.Table
	if table == "" {
		table = DefaultTable
	}
	chain := opts.Chain
	if chain == "" {
		chain = DefaultChain
	}
	return &Detector{
		exec:    exec,
		force:   opts.ForceBackend,
		table:   table,
		chain:   chain,
		version: map[string]string{},
	}
}

// Table 返回 nftables 使用的表名。
func (d *Detector) Table() string { return d.table }

// Chain 返回使用的链名。
func (d *Detector) Chain() string { return d.chain }

// Version 返回某后端探测到的版本。
func (d *Detector) Version(backend string) string { return d.version[backend] }

// Detect 执行探测并返回结论。
//
// ########## 探测原则：不猜发行版，只看命令实际行为 ##########
//
// 与 4.3 网站管理的适配器同一思路（"不猜发行版名字，
// 而是解析 nginx.conf 里真实的 include 行"）：
// 这里不判断"这是 Ubuntu 所以应该有 ufw"，
// 而是实际执行一次只读命令看它能否工作。
//
// 理由：发行版名称与实际安装的软件之间没有必然关系
// （Debian 上可以不装 ufw 而用 firewalld），
// 猜错会让用户看到一个"可用"但一操作就失败的后端。
//
// ########## 探测顺序与降级的语义 ##########
//
//	① 命令不存在        -> Installed=false，跳过
//	② 命令存在但执行失败 -> 区分"权限不足"与"未启用"（见 classifyFailure）
//	③ 命令存在且执行成功 -> 可用；再判断 Active
//
// 返回 error 仅在**完全无法探测**时（如执行器本身坏了）。
// "没有防火墙"不是错误，而是 Available=false + 安装指引——
// 与 4.1 无 systemd、4.4 无 certbot 的降级策略一致：
// 面板其它功能必须照常可用。
func (d *Detector) Detect(ctx context.Context) (Detection, error) {
	result := Detection{
		Backend: BackendNone,
		Label:   BackendLabel(BackendNone),
	}

	if d.force != "" {
		info, err := d.probe(ctx, d.force)
		if err != nil {
			return Detection{}, err
		}
		info.Selected = true
		result.Candidates = []BackendInfo{info}
		result.Backend = d.force
		result.Label = info.Label
		result.Available = info.Available
		result.Active = info.Active
		if !info.Available {
			result.Reason = info.Reason
			result.Hint = info.Hint
		}
		result.Notes = append(result.Notes, fmt.Sprintf(
			"已通过 -firewall-backend 显式指定后端 %s，跳过自动探测", BackendLabel(d.force)))
		return result, nil
	}

	for _, backend := range BackendPriority {
		info, err := d.probe(ctx, backend)
		if err != nil {
			return Detection{}, err
		}
		result.Candidates = append(result.Candidates, info)
	}

	// 选择第一个 Available 的后端。
	//
	// 注意：**不要求 Active**。装了但未启用的后端仍是"选中的后端"，
	// 只是 result.Active=false，由前端提示用户去启用。
	// 若因为未启用就跳到下一个后端，用户会看到面板选了 iptables
	// 而他明明装了 ufw——那才是真正令人困惑的行为。
	for i := range result.Candidates {
		c := &result.Candidates[i]
		if !c.Available {
			continue
		}
		c.Selected = true
		result.Backend = c.Backend
		result.Label = c.Label
		result.Available = true
		result.Active = c.Active
		if !c.Active {
			result.Notes = append(result.Notes, fmt.Sprintf(
				"%s 已安装但未启用，规则不会生效。%s", c.Label, c.Hint))
		}
		break
	}

	// 统计可用的后端数量，用于提示"已按优先级选择"。
	var available []string
	for _, c := range result.Candidates {
		if c.Available {
			available = append(available, c.Label)
		}
	}
	if len(available) > 1 {
		result.Notes = append(result.Notes, fmt.Sprintf(
			"检测到多个可用后端（%s），已按优先级 ufw → firewalld → nftables → iptables 选择 %s。"+
				"如需改用其它后端，可用 -firewall-backend 指定。",
			strings.Join(available, "、"), result.Label))
	}

	if !result.Available {
		result.Reason = "未检测到任何可用的防火墙后端"
		result.Hint = "请安装以下任一防火墙：\n" +
			"  Debian/Ubuntu:  apt-get install ufw        （或 nftables）\n" +
			"  RHEL/CentOS:    dnf install firewalld      （或 nftables）\n" +
			"  Alpine:         apk add ufw                （或 nftables）\n" +
			"安装后无需重启面板，刷新本页即可。"
	}
	return result, nil
}

// probe 探测单个后端。
func (d *Detector) probe(ctx context.Context, backend string) (BackendInfo, error) {
	info := BackendInfo{Backend: backend, Label: BackendLabel(backend)}

	// ① 先看命令是否存在（不执行）。
	cmdName := commandNameOf(backend)
	path, err := d.exec.LookPath(cmdName)
	if err != nil {
		info.Reason = fmt.Sprintf("未找到 %s 命令", cmdName)
		info.Hint = installHintFor(backend)
		return info, nil
	}
	info.Installed = true
	_ = path

	// ② 执行只读探测命令。
	check, err := BuildBackendAvailableCheck(backend)
	if err != nil {
		return BackendInfo{}, err
	}
	res, err := d.exec.Run(ctx, check.Name, check.Args)
	if err != nil {
		// 执行失败：区分"权限不足"、"未启用"与"其它错误"。
		//
		// 这里**不把 err 直接当成"不可用"**：ufw 未启用时
		// `ufw status` 会成功返回 "Status: inactive"（退出码 0），
		// 走不到这个分支；能走到这里的失败通常是权限或环境问题。
		reason, hint, inactive := classifyFailure(backend, res, err)
		if inactive {
			// 存在但未启用：Available=true（命令能用，可以创建规则），
			// Active=false（规则不生效）。
			info.Available = true
			info.Active = false
			info.Reason = reason
			info.Hint = hint
			info.Version = d.probeVersion(ctx, backend)
			return info, nil
		}
		info.Reason = reason
		info.Hint = hint
		return info, nil
	}

	info.Available = true
	info.Version = d.probeVersion(ctx, backend)

	// ③ 判断是否已启用。
	switch backend {
	case BackendUFW:
		// `ufw status verbose` 的第一行是 "Status: active" 或 "Status: inactive"。
		st := ParseUFWStatus(res.Stdout)
		info.Active = st.Active
		if !st.Active {
			info.Reason = "ufw 已安装但未启用（Status: inactive），当前规则不会生效"
			info.Hint = "执行 `ufw enable` 启用（注意：启用前请确认 SSH 端口已放行，" +
				"否则会立刻断开当前连接）"
		}
	case BackendFirewalld:
		// `firewall-cmd --state` 输出 "running" 或 "not running"。
		info.Active = strings.Contains(strings.ToLower(res.Stdout), "running") &&
			!strings.Contains(strings.ToLower(res.Stdout), "not running")
		if !info.Active {
			info.Reason = "firewalld 已安装但未运行，规则不会生效"
			info.Hint = "执行 `systemctl enable --now firewalld` 启用"
		}
	case BackendNFTables, BackendIPTables:
		// nft 与 iptables 没有"启用/未启用"的概念：
		// 它们是内核框架的直接接口，**只要有规则就生效**。
		//
		// 这一点必须如实呈现：面板不能把 nft 显示成"未启用"，
		// 那会让用户以为规则没生效而反复操作。
		// 但也不等于"防护已到位"——默认策略可能是 ACCEPT
		// （什么都不拦），这是另一件事，由规则列表体现。
		info.Active = true
	}
	return info, nil
}

// probeVersion 尝试拿到后端版本（拿不到就返回空，不影响可用性判定）。
func (d *Detector) probeVersion(ctx context.Context, backend string) string {
	if v, ok := d.version[backend]; ok {
		return v
	}
	var cmd Command
	switch backend {
	case BackendUFW:
		cmd = Command{Name: "ufw", Args: []string{"--version"}}
	case BackendFirewalld:
		cmd = Command{Name: "firewall-cmd", Args: []string{"--version"}}
	case BackendNFTables:
		cmd = Command{Name: "nft", Args: []string{"--version"}}
	case BackendIPTables:
		cmd = Command{Name: "iptables", Args: []string{"--version"}}
	default:
		return ""
	}
	res, err := d.exec.Run(ctx, cmd.Name, cmd.Args)
	if err != nil {
		return ""
	}
	v := firstNonEmptyLine(res.Stdout)
	d.version[backend] = v
	return v
}

// commandNameOf 返回后端对应的可执行文件名。
func commandNameOf(backend string) string {
	switch backend {
	case BackendUFW:
		return "ufw"
	case BackendFirewalld:
		return "firewall-cmd"
	case BackendNFTables:
		return "nft"
	case BackendIPTables:
		return "iptables"
	default:
		return backend
	}
}

// installHintFor 返回某后端的安装指引。
func installHintFor(backend string) string {
	switch backend {
	case BackendUFW:
		return "Debian/Ubuntu: apt-get install ufw；Alpine: apk add ufw"
	case BackendFirewalld:
		return "RHEL/CentOS/Fedora: dnf install firewalld"
	case BackendNFTables:
		return "Debian/Ubuntu: apt-get install nftables；RHEL: dnf install nftables"
	case BackendIPTables:
		return "Debian/Ubuntu: apt-get install iptables；RHEL: dnf install iptables"
	default:
		return ""
	}
}

// classifyFailure 把一次失败的探测归类为可操作的原因。
//
// 返回 (reason, hint, inactive)。
//
// ########## 为什么必须区分这几类 ##########
//
// 全都归成"命令执行失败"会让用户完全不知道下一步做什么：
//
//	权限不足   -> 用户需要以 root 运行面板（可操作）
//	未启用     -> 用户需要执行 enable（可操作，但**有失联风险**）
//	命令不存在 -> 用户需要安装（可操作）
//	其它       -> 用户需要看原始输出排查（不可直接操作）
//
// 尤其"未启用"必须与其它失败区分开：它的提示里必须带上
// "启用前确认 SSH 端口已放行"，否则用户照做会立刻断线。
func classifyFailure(backend string, res ExecResult, err error) (reason, hint string, inactive bool) {
	output := strings.ToLower(res.Combined() + " " + err.Error())

	// 未启用（不同后端措辞不同，逐一匹配）。
	switch {
	case strings.Contains(output, "status: inactive"):
		return "ufw 已安装但未启用（Status: inactive），当前规则不会生效",
			"执行 `ufw enable` 启用。⚠️ 启用前请确认 SSH 端口已在允许列表中，" +
				"否则会立刻断开当前连接", true
	case strings.Contains(output, "not running"), strings.Contains(output, "firewalld is not running"):
		return "firewalld 已安装但未运行，规则不会生效",
			"执行 `systemctl enable --now firewalld` 启用", true
	}

	// 权限不足。
	//
	// 措辞在不同后端/内核版本下差异很大，因此匹配多个特征词：
	// ufw 会抛 Python 的 PermissionError / "ERROR: You need to be root"，
	// nft/iptables 会报 "Operation not permitted" / "Permission denied"。
	for _, marker := range []string{
		"permission denied", "operation not permitted", "you need to be root",
		"must be root", "are you root", "permissionerror", "access denied",
		"not permitted",
	} {
		if strings.Contains(output, marker) {
			return fmt.Sprintf("%s 命令存在，但当前权限不足，无法读写防火墙规则", BackendLabel(backend)),
				"防火墙操作需要 root 权限（以及 CAP_NET_ADMIN）。请以 root 身份运行面板，" +
					"或在容器中加上 --cap-add=NET_ADMIN", false
		}
	}

	// 内核模块/表缺失（容器里很常见）。
	for _, marker := range []string{
		"no such file or directory", "table does not exist", "not supported",
		"no such device", "cannot open",
	} {
		if strings.Contains(output, marker) {
			return fmt.Sprintf("%s 命令存在，但当前环境不支持（可能是容器缺少 NET_ADMIN 权限或内核模块）",
					BackendLabel(backend)),
				"若面板运行在容器中，请加上 --cap-add=NET_ADMIN 并确保宿主机内核提供 netfilter 支持", false
		}
	}

	msg := res.Combined()
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Sprintf("%s 探测失败: %s", BackendLabel(backend), truncateRunes(msg, 200)),
		"请手动执行该命令查看完整错误，" +
			"并用 -firewall-backend 指定可用的后端", false
}

// ParseUFWStatus 解析 `ufw status verbose` 的输出头部。
//
// ########## 为什么只解析头部 ##########
//
// 规则行由 parse.go 的 ParseUFWRules 处理（它需要编号、动作、协议、
// 来源、备注等更多信息）。本函数只回答"启用了没有 + 默认策略是什么"，
// 这两条信息只在输出头部，且是"防火墙状态"卡片最核心的内容。
type UFWStatus struct {
	// Active 表示 Status: active。
	Active bool
	// StatusLine 是原始的 Status 行（便于展示与排查）。
	StatusLine string
	// DefaultIncoming / DefaultOutgoing / DefaultRouted 是默认策略。
	//
	// ########## 为什么默认策略必须展示 ##########
	//
	// 它是"没有显式放行的端口会怎样"的答案。
	// Default: deny (incoming) 意味着除规则外一律拒绝；
	// Default: allow (incoming) 意味着防火墙**几乎不起作用**——
	// 用户看到一堆"允许"规则会以为自己被保护着，
	// 实际所有端口本来就都开着。
	// 若面板只显示规则列表而不显示默认策略，这个误解无法被发现。
	DefaultIncoming string
	DefaultOutgoing string
	DefaultRouted   string
	// Logging 是日志级别（如 "on (low)"）。
	Logging string
}

// IsDenyAllIncoming 表示默认拒绝所有入站（安全的默认策略）。
func (s UFWStatus) IsDenyAllIncoming() bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.DefaultIncoming)), "deny") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.DefaultIncoming)), "reject")
}

// ParseUFWStatus 从输出中提取状态头部。
func ParseUFWStatus(output string) UFWStatus {
	var st UFWStatus
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		switch {
		case strings.HasPrefix(lower, "status:"):
			st.StatusLine = trimmed
			// "Status: active" / "Status: inactive"
			st.Active = strings.Contains(lower, "active") && !strings.Contains(lower, "inactive")
		case strings.HasPrefix(lower, "default:"):
			// "Default: deny (incoming), allow (outgoing), disabled (routed)"
			st.DefaultIncoming, st.DefaultOutgoing, st.DefaultRouted = parseUFWDefaults(trimmed)
		case strings.HasPrefix(lower, "logging:"):
			st.Logging = strings.TrimSpace(trimmed[len("logging:"):])
		}
	}
	return st
}

// parseUFWDefaults 解析 Default 行的三个策略。
//
// 输出形如 "Default: deny (incoming), allow (outgoing), disabled (routed)"。
// 新版 ufw 可能省略 routed 段，因此每段都独立解析而不是按下标取。
func parseUFWDefaults(line string) (incoming, outgoing, routed string) {
	body := strings.TrimSpace(line[len("default:"):])
	for _, part := range strings.Split(body, ",") {
		p := strings.TrimSpace(part)
		// 形如 "deny (incoming)"
		lp := strings.ToLower(p)
		switch {
		case strings.Contains(lp, "(incoming)"):
			incoming = strings.TrimSpace(p[:strings.Index(lp, "(incoming)")])
		case strings.Contains(lp, "(outgoing)"):
			outgoing = strings.TrimSpace(p[:strings.Index(lp, "(outgoing)")])
		case strings.Contains(lp, "(routed)"):
			routed = strings.TrimSpace(p[:strings.Index(lp, "(routed)")])
		}
	}
	return incoming, outgoing, routed
}

// firstNonEmptyLine 返回第一个非空行。
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// truncateRunes 按字符截断字符串。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
