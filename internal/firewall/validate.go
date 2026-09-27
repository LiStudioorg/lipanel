package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================================
// 输入校验（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 本文件是本模块**唯一**接受用户输入的地方，因此它承担的安全责任最重。
// 与 4.3 网站管理的三层校验、4.5 软件商店的白名单查表同一思路：
//
//	用户输入只能用于**构造一条规则**，绝不能影响命令的形状。
//	所有命令都经 command.go 的纯函数以 argv 切片组装，
//	用户输入永远只是一个被插入的参数值，而不是命令文本的一部分。
//
// #################### 为什么规则是"白名单正则 + 数值范围"双判 ####################
//
// 直觉上"用 strconv.Atoi 转一下，转不动就是非法"已经够了。实测不够：
//
//	Atoi("０")    —— 全角数字，Atoi 其实会拒绝（好）
//	Atoi(" 22")   —— 前导空格，Atoi **接受**
//	Atoi("+22")   —— 带正号，Atoi **接受**
//	Atoi("0022")  —— 前导零，Atoi **接受** 且值为 22
//	Atoi("2_2")   —— Go 1.13+ 的下划线字面量语法，Atoi **接受** 且值为 22
//
// 后四种都不是攻击，但它们意味着**校验通过的内容与用户提交的内容不一致**。
// 4.3 已经为此踩过一次坑（TrimSpace 把 "site\n" 静默接受），
// 并确立了纪律：**校验函数只回答"这个字符串能不能用"，绝不悄悄改写它**。
//
// 因此这里先用 ^[0-9]{1,5}$ 把输入限定为"纯 ASCII 数字"，
// 再交给 Atoi 判范围。正则负责"形状"，Atoi 负责"数值"，
// 两者缺一不可：只有正则会让 "99999" 通过，只有 Atoi 会让 " 22" 通过。

// ============================================================================
// 端口
// ============================================================================

// 端口合法范围（IANA 定义）。
const (
	// MinPort 是最小可用端口号。
	MinPort = 1
	// MaxPort 是最大端口号（2^16 - 1）。
	MaxPort = 65535
)

// portRe 限定端口必须由 1~5 个**纯 ASCII 数字**组成，且**不允许前导零**。
//
// ########## 为什么必须显式禁止前导零 ##########
//
// 最初的写法是 ^[0-9]{1,5}$，看起来够了。但测试立刻抓出一个真实缺陷：
// "08080-08090" 被接受为端口范围 8080-8090。
// 原因是每段都满足 [0-9]{1,5}，而 Atoi("08080") = 8080。
//
// 这正是本文件开头所警告的那一类问题：**校验通过的内容与用户提交的
// 内容不一致**。危害不止于显示难看——用户在界面上看到自己填的
// 08080-08090，规则实际生效为 8080-8090；将来他手写 iptables 时
// 照样写前导零，某些工具会按八进制解释，得到完全不同的端口。
//
// (0|[1-9][0-9]{0,4}) 的含义：要么就是单个 "0"，要么以 1-9 开头。
// "0" 本身随后会被 MinPort 检查拦下（端口 0 在 iptables 里表示任意端口，
// 放行它等于静默放行全部端口），这里保留它只是为了错误信息更准确。
var portRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})$`)

// portRangeRe 限定端口范围形如 "8080-8090"。
//
// 两段复用与 portRe 相同的"无前导零"规则，否则范围会成为绕过
// 单端口校验的后门（这正是上面那个缺陷的形态）。
var portRangeRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})-(0|[1-9][0-9]{0,4})$`)

// PortSpec 是一条端口规则的目标：可能是单端口，也可能是一个闭区间范围。
//
// 单独建模而不是直接用字符串，是因为**下游需要区分这两种形态**：
// ufw 对单端口写 "8080/tcp"、对范围写 "8080:8090/tcp"（注意是冒号）；
// iptables 对单端口用 --dport、对范围必须用 -m multiport 或 : 语法。
// 若一路用字符串传递，这些差异就会散落在各个组装函数里，
// 每一处都是一次出错机会。
type PortSpec struct {
	// Start 是起始端口；单端口时等于 End。
	Start int
	// End 是结束端口；单端口时等于 Start。
	End int
}

// IsRange 表示这是一个端口范围（而非单端口）。
func (p PortSpec) IsRange() bool { return p.Start != p.End }

// String 返回规范化的展示形式（单端口 "8080"，范围 "8080-8090"）。
//
// 用短横线而不是冒号：短横线是用户输入的形态，也是前端展示的形态。
// 各后端的专有写法（ufw 的冒号、iptables 的多端口）在 command.go 里转换。
func (p PortSpec) String() string {
	if p.IsRange() {
		return strconv.Itoa(p.Start) + "-" + strconv.Itoa(p.End)
	}
	return strconv.Itoa(p.Start)
}

// ValidatePort 校验单个端口号。
//
// 返回规范化后的端口号；非法时返回错误。
// 错误信息直接面向用户，必须说清"哪里不对"，而不是只说"参数错误"。
func ValidatePort(raw string) (int, error) {
	s := raw
	if s == "" {
		return 0, fmt.Errorf("端口号不能为空")
	}
	// ########## 刻意不做 TrimSpace ##########
	//
	// 若先修整再校验，" 22" 会被接受并变成 22，
	// 用户提交的内容与最终生效的内容就不一致了（见文件头注释）。
	// 需要容错的地方由前端提示，而不是后端沉默修正。
	if !portRe.MatchString(s) {
		return 0, fmt.Errorf(
			"端口号必须是 %d-%d 之间的整数，实际收到 %q（不允许空格、正负号或非数字字符）",
			MinPort, MaxPort, raw)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		// 正则已限定为 1~5 位数字，理论上到不了这里；
		// 保留分支是为了不吞掉任何理论上的溢出（如 5 位数字在 16 位平台上）。
		return 0, fmt.Errorf("端口号 %q 无法解析: %w", raw, err)
	}
	if n < MinPort || n > MaxPort {
		return 0, fmt.Errorf("端口号必须位于 %d-%d 之间，实际为 %d", MinPort, MaxPort, n)
	}
	return n, nil
}

// ValidatePortSpec 校验端口或端口范围。
//
// 接受两种形态：
//
//	"8080"        单端口
//	"8080-8090"   闭区间范围（含首尾）
//
// ########## 范围顺序绝不自动交换 ##########
//
// "8090-8080" 是用户写反了。自动交换看起来"贴心"，但它有两个问题：
//
//	① 与"绝不悄悄改写用户输入"的纪律冲突；
//	② 用户在界面上看到 8090-8080 被接受，会以为自己填对了，
//	   下次在别的地方（比如手写 iptables）照样写反，得到完全不同的结果。
//
// 明确报错并说明方向，是唯一不会让用户形成错误认知的做法。
func ValidatePortSpec(raw string) (PortSpec, error) {
	s := raw
	if s == "" {
		return PortSpec{}, fmt.Errorf("端口不能为空")
	}

	m := portRangeRe.FindStringSubmatch(s)
	if m == nil {
		// 不是范围形态，按单端口处理。
		// 这里**不能再判断是否含 '-'**：像 "8080-" 或 "-8080" 这样的
		// 半截范围会落到单端口分支并被 portRe 拒绝，
		// 错误信息里会提到"范围格式"，对用户更有指导性。
		if strings.Contains(s, "-") {
			return PortSpec{}, fmt.Errorf(
				"端口范围格式必须是 起始-结束（如 8080-8090），实际收到 %q", raw)
		}
		p, err := ValidatePort(s)
		if err != nil {
			return PortSpec{}, err
		}
		return PortSpec{Start: p, End: p}, nil
	}

	start, err := ValidatePort(m[1])
	if err != nil {
		return PortSpec{}, fmt.Errorf("端口范围起点非法: %w", err)
	}
	end, err := ValidatePort(m[2])
	if err != nil {
		return PortSpec{}, fmt.Errorf("端口范围终点非法: %w", err)
	}
	if start > end {
		return PortSpec{}, fmt.Errorf(
			"端口范围的起始值不能大于结束值，实际收到 %d-%d（若想放行该区间请写成 %d-%d）",
			start, end, end, start)
	}
	return PortSpec{Start: start, End: end}, nil
}

// ============================================================================
// 协议
// ============================================================================

// 支持的协议标识。
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
	// ProtoAny 表示 tcp 与 udp 同时放行（各后端有不同表达方式）。
	ProtoAny = "any"
)

// ValidateProtocol 校验协议。
//
// 只接受 tcp / udp / any 三个值。**不接受 icmp/icmpv6**：
// 它们没有端口概念，而本模块的核心目标是"端口管理"。
// 若将来要支持 ICMP，应当是独立的一套规则模型，
// 而不是让端口规则里混进一个 protocol=icmp 的特例
// （那会让 command.go 里每个组装函数都要为它加分支）。
//
// 空字符串视为 tcp：TCP 是绝大多数场景的默认值，
// 但**只有显式允许这个默认**，参见调用方对"空"的语义说明。
func ValidateProtocol(raw string) (string, error) {
	switch strings.ToLower(raw) {
	case "":
		return ProtoTCP, nil
	case ProtoTCP:
		return ProtoTCP, nil
	case ProtoUDP:
		return ProtoUDP, nil
	case ProtoAny:
		return ProtoAny, nil
	default:
		return "", fmt.Errorf("协议只能是 tcp、udp 或 any，实际收到 %q", raw)
	}
}

// ============================================================================
// IP 地址与网段
// ============================================================================

// ValidateIP 校验 IP 地址或 CIDR 网段。
//
// ########## 为什么用 net/netip 而不是 net.ParseIP ##########
//
// 三个具体理由：
//
//	① ParseIP 接受 "1.2.3.4" 也接受 "::ffff:1.2.3.4"，
//	   返回的永远是 16 字节形式，调用方要自己判断它"本来"是 v4 还是 v6；
//	   netip.Addr 有明确的 Is4()/Is6()/Is4In6()，且是可比的值类型。
//
//	② ParseIP **接受前导零**，"010.1.1.1" 会被解析成 10.1.1.1
//	   （历史上不同实现对前导零有八进制解释，这是真实的解析歧义源）。
//	   netip.ParseAddr 明确拒绝前导零。
//
//	③ ParseIP 不接受带掩码的串，需要额外 ParseCIDR；
//	   netip 的 ParseAddr/ParsePrefix 语义边界更清晰。
//
// ########## 明确拒绝的形态 ##########
//
//   - "1.2.3.4/24"  → 这是网段，必须走 CIDR 语义（调用方用 AllowCIDR 区分）
//   - "1.2.3.4:22"  → 这是地址+端口，不是 IP（用户常犯的错，要明确提示）
//   - "any" / "*"   → 表示"所有来源"，应当由调用方传空字符串表达，
//     不要让一个特殊字符串混进 IP 字段
//   - 带方括号的 "[::1]"
func ValidateIP(raw string) (netip.Addr, error) {
	s := raw
	if s == "" {
		return netip.Addr{}, fmt.Errorf("IP 地址不能为空")
	}
	if strings.Contains(s, "/") {
		return netip.Addr{}, fmt.Errorf(
			"%q 是网段而不是单个 IP，请改用 CIDR 形式的网段校验或去掉掩码", raw)
	}
	if strings.Contains(s, ":") {
		// IPv6 本身含冒号，因此先尝试按 IPv6 解析；
		// 只有解析失败时才怀疑"地址+端口"这种形态并给出针对性提示。
		if addr, err := netip.ParseAddr(s); err == nil {
			return normalizeAddr(addr, raw)
		}
		if host, port, ok := splitHostPortLoose(s); ok {
			return netip.Addr{}, fmt.Errorf(
				"%q 看起来是「IP:端口」，IP 字段只接受地址本身（收到的主机部分是 %q，端口是 %q）",
				raw, host, port)
		}
		return netip.Addr{}, fmt.Errorf("%q 不是合法的 IPv6 地址", raw)
	}
	// 形如 "1.2.3.4:22" 的 v4+端口：netip 会直接拒绝，
	// 但错误信息不够具体，这里先识别出来给出更好的提示。
	if host, port, ok := splitHostPortLoose(s); ok {
		return netip.Addr{}, fmt.Errorf(
			"%q 看起来是「IP:端口」，IP 字段只接受地址本身（收到的主机部分是 %q，端口是 %q）",
			raw, host, port)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q 不是合法的 IP 地址: %w", raw, err)
	}
	return normalizeAddr(addr, raw)
}

// normalizeAddr 统一 IPv4 映射地址的处理。
//
// "::ffff:1.2.3.4" 在语义上就是 IPv4 地址，但它同时是合法的 IPv6 写法。
// 若不归一化，同一条规则在后端是 iptables（v4）还是 ip6tables（v6）上
// 会走向完全不同的分支，用户看到的行为难以预期。
// 这里统一 Unmap，让 v4 映射地址按 v4 处理。
func normalizeAddr(addr netip.Addr, raw string) (netip.Addr, error) {
	if addr.Is4In6() {
		return addr.Unmap(), nil
	}
	if addr.Zone() != "" {
		// 链路本地地址带 zone（fe80::1%eth0）在防火墙规则里无法表达，
		// 各后端都不接受这种写法。
		return netip.Addr{}, fmt.Errorf(
			"%q 带有网络接口后缀（%%），防火墙规则不支持链路本地地址的 zone 写法", raw)
	}
	return addr, nil
}

// splitHostPortLoose 尝试把一个串按 "host:port" 拆开。
//
// 只用于**生成更好的错误信息**，不参与任何"是否合法"的判定。
// 因此它刻意宽容：host 部分可以为空（":22"）、port 部分可以非数字
// ——只要能拆开，就说明用户很可能填错了字段。
func splitHostPortLoose(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	// 有多个冒号且不像 IPv6（未被上面的 ParseAddr 接受）时不猜，
	// 避免把 ":::" 这类畸形串说成"像是 IP:端口"。
	if strings.Count(s, ":") > 1 {
		return "", "", false
	}
	host = s[:i]
	port = s[i+1:]
	if port == "" {
		// "1.2.3.4:" —— 也算填错了字段的典型形态。
		return host, port, true
	}
	// 端口部分必须是数字才认为"用户是想写 IP:端口"，
	// 否则像 "a:b" 这样的串更可能是别的笔误。
	if !portRe.MatchString(port) {
		return "", "", false
	}
	return host, port, true
}

// IPRule 是一条 IP 规则的匹配目标。
type IPRule struct {
	// Addr 是单个地址；与 Prefix 互斥。
	Addr netip.Addr
	// Prefix 是 CIDR 网段；与 Addr 互斥。
	Prefix netip.Prefix
	// IsCIDR 表示本条用的是 Prefix。
	IsCIDR bool
}

// String 返回规范化展示形式。
func (r IPRule) String() string {
	if r.IsCIDR {
		return r.Prefix.String()
	}
	if !r.Addr.IsValid() {
		return ""
	}
	return r.Addr.String()
}

// IsV4 表示本条规则作用于 IPv4。
func (r IPRule) IsV4() bool {
	if r.IsCIDR {
		return r.Prefix.Addr().Is4()
	}
	return r.Addr.Is4()
}

// ValidateIPRule 校验 IP 或 CIDR，返回统一的规则模型。
//
// 自动区分两种形态：含 "/" 走网段，否则走单地址。
// 因此调用方不需要自己判断用户填的是哪一种。
func ValidateIPRule(raw string) (IPRule, error) {
	s := raw
	if s == "" {
		return IPRule{}, fmt.Errorf("IP 不能为空")
	}
	if !strings.Contains(s, "/") {
		addr, err := ValidateIP(s)
		if err != nil {
			return IPRule{}, err
		}
		return IPRule{Addr: addr}, nil
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return IPRule{}, fmt.Errorf("%q 不是合法的网段（应形如 192.168.1.0/24）: %w", raw, err)
	}
	// ########## 拒绝非规范网段（主机位非零）##########
	//
	// "192.168.1.5/24" 在语义上是"192.168.1.0/24"，
	// 但各后端对它的处理并不同：nft 会直接拒绝（"host bits set"），
	// iptables 会静默按 /24 处理。同一份输入在两个后端上一个报错、
	// 一个生效，是最难排查的一类问题。
	//
	// 与端口范围同理：**不自动修正**，而是明确告诉用户规范写法。
	// 这只影响展示与用户输入；Masked() 的归一化值我们在内部照常使用。
	if prefix.Addr() != prefix.Masked().Addr() {
		return IPRule{}, fmt.Errorf(
			"%q 的主机位不为零，请改写为规范网段 %s",
			raw, prefix.Masked().String())
	}
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if prefix.Addr().Zone() != "" {
		return IPRule{}, fmt.Errorf("%q 带有网络接口后缀（%%），防火墙规则不支持", raw)
	}
	return IPRule{Prefix: prefix, IsCIDR: true}, nil
}

// ============================================================================
// 备注
// ============================================================================

// MaxCommentLength 是备注的最大字符数。
//
// ufw 的 comment 会写进 /etc/ufw/user.rules 的注释里，
// 过长或含换行的内容会破坏该文件的格式（它是被 ufw 自己解析的）。
// 128 个字符足够表达用途，也远小于任何后端的限制。
const MaxCommentLength = 128

// ValidateComment 校验备注。
//
// ########## 为什么备注也要严格校验 ##########
//
// 备注看起来"只是显示用的"，但它在 ufw 后端里会**写进规则文件**：
//
//	### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in comment=我的备注
//
// 若备注里含换行，就会在 user.rules 里插入一行任意内容，
// 而那个文件是 ufw 自己解析的——用户可以借此写入伪造的规则条目。
// 因此这里的校验标准与其它字段一样严：**只允许可打印字符，拒绝控制字符**。
func ValidateComment(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	// 按 rune 计数而不是字节：中文备注按字节算会被过早截断。
	if len([]rune(raw)) > MaxCommentLength {
		return "", fmt.Errorf("备注不能超过 %d 个字符", MaxCommentLength)
	}
	for _, r := range raw {
		if r == '\n' || r == '\r' {
			return "", fmt.Errorf("备注不能包含换行符")
		}
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("备注不能包含控制字符（0x%02x）", r)
		}
	}
	return raw, nil
}

// ============================================================================
// 动作与方向
// ============================================================================

// 规则动作。
const (
	// ActionAllow 表示放行。
	ActionAllow = "allow"
	// ActionDeny 表示拒绝。
	ActionDeny = "deny"
)

// ValidateAction 校验动作（allow / deny）。
//
// 空值默认 allow：用户新建规则时最常见的意图是"放行端口"。
func ValidateAction(raw string) (string, error) {
	switch strings.ToLower(raw) {
	case "", ActionAllow:
		return ActionAllow, nil
	case ActionDeny:
		return ActionDeny, nil
	default:
		return "", fmt.Errorf("动作只能是 allow（放行）或 deny（拒绝），实际收到 %q", raw)
	}
}

// 黑白名单方向。
const (
	// DirectionAllow 是白名单：只允许这些来源访问。
	DirectionAllow = "allow"
	// DirectionDeny 是黑名单：拒绝这些来源访问。
	DirectionDeny = "deny"
)

// ValidateDirection 校验黑白名单方向。
//
// 与 ValidateAction 取值相同但**语义不同**，因此单独一个函数：
// action 描述"这条端口规则做什么"，direction 描述"这个 IP 列表是什么性质"。
// 合并成一个函数会让调用点无法表达意图，将来任一方扩展都会互相牵连。
func ValidateDirection(raw string) (string, error) {
	switch strings.ToLower(raw) {
	case "", DirectionDeny:
		// 默认 deny：用户填一个 IP 到"黑名单"区，意图几乎总是封禁。
		return DirectionDeny, nil
	case DirectionAllow:
		return DirectionAllow, nil
	default:
		return "", fmt.Errorf("IP 规则方向只能是 allow（白名单）或 deny（黑名单），实际收到 %q", raw)
	}
}

// ============================================================================
// 规则标识（删除时使用）
// ============================================================================

// RuleKey 是一条规则的稳定标识，用于"删除"操作定位目标。
//
// ########## 为什么删除不用"规则在列表里的下标" ##########
//
// 下标极不可靠：用户在页面上看到第 3 条并点了删除，
// 而在他点之前防火墙可能已经被别人（或另一个终端）改过，
// 此时第 3 条已经不是他看到的那条了——这会删错规则。
//
// 更危险的是下标与后端规则的对应关系依赖解析结果，
// 一旦解析行数变化（比如某行被跳过），下标就会整体偏移。
//
// 因此删除一律基于**规则的可比较内容**：端口 + 协议 + 来源 + 动作。
// 详见 portSpecFromRule 与 Manager.DeletePort 的匹配逻辑。
type RuleKey struct {
	// Port 是端口或范围。
	Port PortSpec
	// Protocol 是 tcp / udp。
	Protocol string
	// Source 是来源 IP/网段（空表示所有来源）。
	Source string
	// Action 是 allow / deny。
	Action string
}

// String 返回便于审计与日志的稳定描述。
func (k RuleKey) String() string {
	src := k.Source
	if src == "" {
		src = "any"
	}
	return fmt.Sprintf("%s/%s from %s (%s)", k.Port.String(), k.Protocol, src, k.Action)
}
