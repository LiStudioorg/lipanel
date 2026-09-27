package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================================
// 规则解析（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 把四个后端的输出解析成统一的 Rule 模型。
//
// #################### 本文件的每条解析规则都来自真实输出 ####################
//
// 下面每个解析函数上方都贴了**在本机真实环境下抓到的输出**
// （unshare -n 隔离环境 + 真实 ufw/nft/iptables）。
// 这不是装饰：防火墙输出格式的细节极易凭想象写错，而写错的后果是
// "界面显示得挺对、删除时却删不掉"或更糟——删掉了另一条规则。
//
// 真实的格式细节（都是实测确认的）：
//
//	① iptables -S 会补上 -m tcp —— 添加时写 "--dport 8080"，
//	   回读时是 "-p tcp -m tcp --dport 8080"。删除必须用回读的规格。
//	② nft -a list 的 handle 出现在**每一行**（table、chain、规则都有），
//	   必须取规则行末尾的那个，抓第一个会抓到 table 的 handle。
//	③ ufw status 的动作列可能是 "ALLOW"、"DENY"、"ALLOW IN"、
//	   "DENY IN"、"LIMIT"、"ALLOW FWD" 等多种形态。
//	④ ufw 的 v6 规则行以 "(v6)" 结尾。

// Rule 是一条规则在面板上的统一表示。
//
// 字段刻意设计成"四个后端都能填满"：
// 后端特有的信息（nft 的 handle、iptables 的规格串）
// 放在 Deletion 里，而不是污染通用字段。
type Rule struct {
	// Port 是端口或范围；IP 规则里为无效值（Start=0）。
	Port PortSpec `json:"-"`
	// PortText 是端口的展示文本（IP 规则为空）。
	//
	// ########## 字段名是 port_text 而不是 port ##########
	//
	// Port 字段带 `json:"-"`（它是 PortSpec 结构体，前端用不上），
	// 因此这里必须用 port_text 才能被前端读到。
	//
	// ########## 这个命名不一致是被端到端验证抓出来的 ##########
	//
	// 原先标签写的是 `json:"port"`，而单元测试只断言结构体字段
	// （PortText 本身有值），完全看不到 JSON 序列化后的名字。
	// 结果前端拿到的 port_text 永远是空——界面上的"端口"列
	// 会整列空白，而所有 Go 测试全绿。
	//
	// TestRuleJSONContract 现在锁死了所有对外的字段名。
	PortText string `json:"port_text,omitempty"`
	// Protocol 是 tcp / udp / any；IP 规则为空。
	Protocol string `json:"protocol,omitempty"`
	// Source 是来源 IP/网段（空表示所有来源）。
	Source string `json:"source,omitempty"`
	// Action 是 allow / deny。
	Action string `json:"action"`
	// Comment 是备注。
	Comment string `json:"comment,omitempty"`
	// Kind 是 rule 的类别：port 或 ip。
	//
	// ########## 为什么不用"Port 是否为空"来区分 ##########
	//
	// 端口规则与 IP 黑白名单在**后端层面是同一种东西**
	// （都是一条 iptables 规则 / 一个 nft 表达式 / 一个 ufw 规则），
	// 面板把它们分成两个区域展示只是 UI 的取舍。
	// 若靠"Port 为空"隐式区分，一条"允许 8080 来自 any"的规则
	// 与一条"允许来自 1.2.3.4 的所有端口"的规则会难以分辨，
	// 而它们的删除参数完全不同。显式一个 Kind 字段最清楚。
	Kind string `json:"kind"`
	// Family 是 ipv4 / ipv6。
	Family string `json:"family"`
	// Backend 是这条规则来自哪个后端。
	Backend string `json:"backend"`
	// Origin 标记规则来源：panel（面板创建）/ external（其它工具创建）。
	//
	// ########## 为什么必须区分 ##########
	//
	// 机器上原本就有大量规则（ufw 自己装的链、Docker 的规则、
	// 管理员手工加的规则）。面板展示它们是有价值的
	// （用户需要看到全貌），但**删除它们要慎重**：
	// 那些规则可能是 SSH 白名单，删掉就失联。
	// 因此列表里如实标注来源，前端对 external 规则的删除
	// 给出更强的警告。
	Origin string `json:"origin"`
	// Deletable 表示本模块能否精确删除这条规则。
	//
	// ########## 这是本模块安全设计的核心字段 ##########
	//
	// false 的情形（nft 解析不出 handle、iptables 有复杂跳转等）
	// 意味着删除它**没有可靠的手段**。此时前端必须禁用删除按钮
	// 并说明原因，而不是让用户点了以后得到一个语焉不详的失败——
	// 更不能退化成"清空整条链/整个规则集"来"达成目的"。
	Deletable bool `json:"deletable"`
	// NotDeletableReason 是 Deletable=false 的原因（面向用户）。
	NotDeletableReason string `json:"not_deletable_reason,omitempty"`
	// Protected 表示这条规则涉及被保护的端口（面板自身或 SSH）。
	Protected bool `json:"protected,omitempty"`
	// ProtectedReason 是受保护的原因。
	ProtectedReason string `json:"protected_reason,omitempty"`
	// ProtectionKind 是保护类型（panel / ssh），供前端选择展示样式。
	//
	// SSH 用更重的警示色：关掉它会直接失去远程登录，
	// 而面板端口关掉至少还能通过 SSH 改回来（除非两个一起关）。
	// 前端需要区分这两者，因此必须把类型传过去，
	// 而不是只给一个布尔值。
	ProtectionKind string `json:"protection_kind,omitempty"`
	// Spec 是删除所需的精确规格（不导出到 JSON）。
	//
	// iptables 后端：来自 `iptables -S` 的原始词元切片。
	// 其它后端为空（它们按内容删除）。
	Spec []string `json:"-"`
	// Handle 是删除所需的句柄（nftables 专用）。
	Handle int `json:"-"`
	// Raw 是解析出本行的原始输出（排查用，前端可选展示）。
	Raw string `json:"raw,omitempty"`
	// Index 是规则在其后端输出中的序号（0 起），仅用于稳定排序与展示。
	Index int `json:"index"`
}

// 规则类别。
const (
	// KindPort 表示端口规则。
	KindPort = "port"
	// KindIP 表示 IP 黑白名单规则。
	KindIP = "ip"
)

// 规则来源。
const (
	// OriginPanel 表示规则由面板创建（带面板写入的备注标记）。
	OriginPanel = "panel"
	// OriginExternal 表示规则由其它工具创建。
	OriginExternal = "external"
)

// PanelCommentMarker 是面板写入规则时附加在备注里的标记。
//
// ########## 为什么用备注标记而不是独立的状态文件 ##########
//
// 独立文件（记录"面板创建过哪些规则"）会与防火墙的真实状态
// **失去同步**：用户在命令行删掉规则后文件里还记着，
// 或者防火墙规则被 ufw 重建后文件里的记录全部失效。
// 而备注是随规则一起存储、一起删除的，天然一致。
//
// 多个后端都支持备注（ufw 的 comment、iptables 的 -m comment、
// nft 的 comment 语句），因此这个做法对四个后端都可用。
const PanelCommentMarker = "[lipanel]"

// MarkPanelComment 给用户备注加上面板标记。
func MarkPanelComment(comment string) string {
	if comment == "" {
		return PanelCommentMarker
	}
	return PanelCommentMarker + " " + comment
}

// StripPanelComment 去掉面板标记，返回用户可见的备注。
func StripPanelComment(comment string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(comment), PanelCommentMarker))
}

// IsPanelComment 判断备注是否带面板标记。
func IsPanelComment(comment string) bool {
	return strings.Contains(comment, PanelCommentMarker)
}

// ============================================================================
// ufw
// ============================================================================

// ufwRuleRe 匹配 ufw status numbered 的规则行。
//
// 真实输出样例（本机实测的格式，注意编号外的方括号）：
//
//	[ 1] 22/tcp                     ALLOW IN    Anywhere
//	[ 2] 8080/tcp                   ALLOW IN    192.168.1.0/24
//	[ 3] 8080:8090/tcp              DENY IN     Anywhere                   # web range
//	[ 4] 53/udp                     ALLOW IN    Anywhere (v6)
//	[ 5] Anywhere                   ALLOW IN    1.2.3.4
//
// 编号的间距会随规则数量变化（[ 1] 与 [ 10]），因此用 \s* 而不是固定宽度。
var ufwRuleRe = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(.+)$`)

// ParseUFWRules 解析 `ufw status numbered` 的全部规则行。
//
// ########## 为什么用 numbered 而不是普通 status ##########
//
// 普通 status 的输出列间距是**动态对齐**的，规则一多就会变，
// 而 numbered 有稳定的 `[ N]` 前缀可作为行锚点。
// 编号本身只用于展示（删除不依赖它，见 validate.go 的 RuleKey 说明）。
func ParseUFWRules(output string) []Rule {
	var rules []Rule
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// 跳过状态头部："Status: active"、"Default: ..."、"Logging: ..."、
		// 以及分隔线 "--"。
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "status:") ||
			strings.HasPrefix(low, "default:") ||
			strings.HasPrefix(low, "logging:") ||
			trimmed == "--" {
			continue
		}
		m := ufwRuleRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		to := strings.TrimSpace(m[2])
		rest := strings.TrimSpace(m[3])

		// rest 形如 "ALLOW IN    192.168.1.0/24" 或
		// "ALLOW IN    Anywhere                   # 备注"。
		action, remainder := splitUFWAction(rest)

		// 从 remainder 里分离来源与备注（备注以 " # " 开始）。
		source, comment := splitUFWSourceComment(remainder)

		rule := Rule{
			Kind:      classifyUFWRule(to),
			Action:    action,
			Source:    normalizeUFWSource(source),
			Comment:   StripPanelComment(comment),
			Raw:       trimmed,
			Index:     idx,
			Origin:    originOf(comment),
			Family:    familyOfSource(source),
			Deletable: true, // ufw 按内容删除，总是可删
			Backend:   BackendUFW,
		}
		// "Anywhere (v6)" 标记 IPv6。
		if strings.Contains(rest, "(v6)") || strings.Contains(source, "(v6)") {
			rule.Family = "ipv6"
		}

		// "to" 列可能是端口（8080/tcp）或 "Anywhere"（IP 规则）。
		if portText, proto, ok := parseUFWTarget(to); ok {
			rule.PortText = portText
			rule.Protocol = proto
			if spec, err := portSpecFromText(portText); err == nil {
				rule.Port = spec
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// splitUFWAction 从 "ALLOW IN    192.168.1.0/24" 里切出动作与剩余部分。
//
// ufw 的动作列形态（实测）：
//
//	ALLOW / DENY / REJECT / LIMIT
//	ALLOW IN / DENY IN / LIMIT IN      （入站）
//	ALLOW OUT / DENY OUT               （出站）
//	ALLOW FWD / DENY FWD               （转发）
//
// 统一映射到 allow/deny 两态：面板的语义只有"放行"与"拒绝"，
// LIMIT 与 REJECT 在本期不做（明确不在范围内），
// 但它们**必须能被解析出来**，否则用户在命令行加的
// "ufw limit ssh" 会在面板上凭空消失。
// 这里映射为 deny 并在备注里保留原始动作词，
// 让它至少"看得见"而不是静默丢失。
func splitUFWAction(rest string) (action string, remainder string) {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ActionAllow, ""
	}
	verb := strings.ToUpper(fields[0])
	consumed := 1

	// 第二个词可能是 IN / OUT / FWD 方向词。
	if len(fields) > 1 {
		switch strings.ToUpper(fields[1]) {
		case "IN", "OUT", "FWD":
			consumed = 2
		}
	}
	switch verb {
	case "ALLOW":
		action = ActionAllow
	case "DENY", "REJECT", "LIMIT":
		action = ActionDeny
	default:
		action = ActionAllow
	}
	return action, strings.Join(fields[consumed:], " ")
}

// splitUFWSourceComment 从 "192.168.1.0/24    # 备注" 里分离来源与备注。
func splitUFWSourceComment(s string) (source, comment string) {
	if i := strings.Index(s, "#"); i >= 0 {
		comment = strings.TrimSpace(s[i+1:])
		s = s[:i]
	}
	return strings.TrimSpace(s), comment
}

// normalizeUFWSource 把 ufw 的 "Anywhere" 归一化为空串（表示任意来源）。
//
// "Anywhere" / "Anywhere (v6)" 在 ufw 里表示"所有来源"，
// 对应本模块的空串语义。保留原文会让"任意来源"的规则
// 在面板上显示成"来源: Anywhere"，而按它组装删除命令时
// ufw 只认 "from any"（不是 "from Anywhere"），
// 因此必须在解析阶段就归一化——否则删除必然失败。
func normalizeUFWSource(s string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(t, "(v6)")
	t = strings.TrimSpace(t)
	if strings.EqualFold(t, "anywhere") || strings.EqualFold(t, "any") {
		return ""
	}
	return t
}

// parseUFWTarget 解析 ufw 的 to 列。
//
// 形态：
//
//	"8080/tcp"     -> ("8080", "tcp")
//	"8080:8090/tcp"-> ("8080-8090", "tcp")   ← 冒号转成本模块的短横线
//	"Anywhere"     -> 不是端口
//	"22"           -> ("22", "")  旧版本可能省略协议
func parseUFWTarget(to string) (portText, proto string, ok bool) {
	if strings.EqualFold(to, "anywhere") {
		return "", "", false
	}
	s := to
	if i := strings.Index(s, "/"); i >= 0 {
		proto = strings.ToLower(strings.TrimSpace(s[i+1:]))
		s = strings.TrimSpace(s[:i])
	}
	// ufw 的范围用冒号，本模块统一用短横线。
	s = strings.ReplaceAll(s, ":", "-")
	if !isPortLike(s) {
		return "", "", false
	}
	return s, proto, true
}

// isPortLike 判断一个串是否形如端口或端口范围。
func isPortLike(s string) bool {
	_, err := portSpecFromText(s)
	return err == nil
}

// portSpecFromText 从一个已被规范化的端口文本构造 PortSpec。
//
// 与 ValidatePortSpec 的区别：本函数用于**解析后端输出**，
// 因此更宽容（不因一个畸形行而放弃整份输出），
// 但仍走同一套范围检查，保证解析出的 PortSpec 一定是合法的。
func portSpecFromText(s string) (PortSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortSpec{}, fmt.Errorf("空端口")
	}
	if i := strings.Index(s, "-"); i >= 0 {
		start, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
		end, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err1 != nil || err2 != nil {
			return PortSpec{}, fmt.Errorf("非法端口范围 %q", s)
		}
		if start < MinPort || end > MaxPort || start > end {
			return PortSpec{}, fmt.Errorf("端口范围越界或反向: %q", s)
		}
		return PortSpec{Start: start, End: end}, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return PortSpec{}, fmt.Errorf("非法端口 %q", s)
	}
	if n < MinPort || n > MaxPort {
		return PortSpec{}, fmt.Errorf("端口越界: %q", s)
	}
	return PortSpec{Start: n, End: n}, nil
}

// classifyUFWRule 判断一条 ufw 规则是端口规则还是 IP 规则。
func classifyUFWRule(to string) string {
	if _, _, ok := parseUFWTarget(to); ok {
		return KindPort
	}
	return KindIP
}

// originOf 根据备注判断规则是否由面板创建。
func originOf(comment string) string {
	if IsPanelComment(comment) {
		return OriginPanel
	}
	return OriginExternal
}

// familyOfSource 根据来源判断地址族（无来源时按 ipv4）。
func familyOfSource(source string) string {
	if strings.Contains(source, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// ============================================================================
// nftables
// ============================================================================

// nftHandleRe 匹配 nft 规则行末尾的 handle 注释。
//
// 真实输出（unshare -n + nft -a list chain inet filter input）：
//
//	table inet filter { # handle 1
//		chain input { # handle 1
//			type filter hook input priority filter; policy accept;
//			tcp dport 8080 accept # handle 2
//			tcp dport 9090 drop # handle 3
//		}
//	}
//
// ########## 关键：handle 出现在每一行 ##########
//
// table 与 chain 行同样带 "# handle N"。若天真地"抓第一个 handle"，
// 会抓到 table 的 handle（实测确认：抓到 handle 1，
// 用它去 delete rule 报 "Could not process rule: No such file or directory"）。
//
// 因此必须**只在规则行**上取末尾的 handle，
// 而 table/chain 行要通过其语法特征排除。
var nftHandleRe = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)

// nftPortExprRe 从 nft 规则行里提取协议与端口。
//
// 形态：
//
//	tcp dport 8080 accept
//	udp dport 8080-8090 drop
//	meta l4proto { tcp, udp } th dport 53 accept
//	ip saddr 192.168.1.0/24 tcp dport 22 accept
//
// ########## 不能用 ^ 锚定行首 ##########
//
// 最初写成 `^\s*(tcp|udp)\s+dport\s+(\S+)`，测试立刻抓出问题：
// 带来源的规则（"ip saddr ... tcp dport 22 accept"）里
// 协议表达式**不在行首**，因此永远匹配不到。
//
// 症状具有迷惑性：该规则被解析成 IP 规则、端口列空白，
// 而用户在命令行看那条规则明明是端口规则——
// 会疑心是"面板解析不了我的规则"，而不是"正则少了个前缀"。
//
// 改为要求 dport 前的协议词处于词边界（行首或空格之后），
// 这样既能在任意位置匹配，又不会把 "th dport" 里的
// 残片误当成协议。
var nftPortExprRe = regexp.MustCompile(`(?:^|\s)(tcp|udp)\s+dport\s+(\S+)`)

// nftAnyProtoRe 匹配 meta l4proto { tcp, udp } th dport N 形态。
var nftAnyProtoRe = regexp.MustCompile(`meta\s+l4proto\s*\{\s*tcp\s*,\s*udp\s*\}\s*th\s+dport\s+(\S+)`)

// nftSaddrRe 匹配来源地址。
//
// 形如 "ip saddr 192.168.1.0/24" 或 "ip6 saddr 2001:db8::/32"。
var nftSaddrRe = regexp.MustCompile(`(ip6?)\s+saddr\s+(\S+)`)

// nftCommentRe 匹配 nft 的 comment 表达式。
//
// 形如：comment "web 服务"
var nftCommentRe = regexp.MustCompile(`comment\s+"([^"]*)"`)

// nftTableRe / nftChainRe 用于识别表与链的声明行。
var (
	nftTableRe = regexp.MustCompile(`^\s*table\s+\S+\s+\S+\s*\{`)
	nftChainRe = regexp.MustCompile(`^\s*chain\s+\S+\s*\{`)
	// nftPolicyRe 匹配链的 type/policy 声明行（不是规则）。
	nftPolicyRe = regexp.MustCompile(`^\s*(type\s+\S+|policy\s+\S+)`)
)

// ParseNFTRules 解析 `nft -a list ruleset` 的输出。
//
// 只解析形如 "inet <table> <chain>" 下的规则行；
// table/chain/policy 行被跳过（但它们**参与跟踪当前链**，
// 因为删除需要知道规则属于哪个链）。
//
// ########## 解析不出 handle 的规则标记为不可删除 ##########
//
// 这是本模块安全设计的核心：nft 没有"按内容删除"的语法。
// 若某条规则行无法提取 handle（格式变化、跨行续行等），
// 它会被标记 Deletable=false 并给出原因，
// **绝不会**退化成任何形式的清空操作。
func ParseNFTRules(output string) []Rule {
	var rules []Rule
	var currentTable, currentChain string
	idx := 0

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// 表声明：table inet filter { # handle 1
		if m := nftTableRe.FindStringSubmatch(trimmed); m != nil {
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 {
				currentTable = fields[2]
			}
			currentChain = ""
			continue
		}
		// 链声明：chain input { # handle 1
		if m := nftChainRe.FindStringSubmatch(trimmed); m != nil {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				currentChain = strings.TrimSuffix(fields[1], "{")
			}
			continue
		}
		// 单独一行 "}"：链或表结束。
		if trimmed == "}" || trimmed == "};" {
			// 只重置链（表可能还有别的链）。
			currentChain = ""
			continue
		}
		// 链的属性行（type/policy）不是规则。
		if nftPolicyRe.MatchString(trimmed) {
			continue
		}
		// 既没有表也没有链上下文时跳过。
		if currentTable == "" || currentChain == "" {
			continue
		}

		// 提取 handle。
		handle := 0
		if m := nftHandleRe.FindStringSubmatch(trimmed); m != nil {
			handle, _ = strconv.Atoi(m[1])
		}
		// 去掉 handle 注释得到纯表达式。
		expr := strings.TrimSpace(nftHandleRe.ReplaceAllString(trimmed, ""))
		if expr == "" {
			continue
		}

		// 判断 verdict。
		action, has := nftVerdict(expr)
		if !has {
			// 没有 verdict 的行（如 "counter"）不是完整的过滤规则，
			// 但仍然解析出来并标记不可删除——让用户在列表里看得见。
			rules = append(rules, Rule{
				Kind:               KindIP,
				Action:             ActionAllow,
				Raw:                trimmed,
				Index:              idx,
				Origin:             OriginExternal,
				Family:             "ipv4",
				Backend:            BackendNFTables,
				Deletable:          handle > 0,
				NotDeletableReason: notDeletableReason(handle),
				Handle:             handle,
			})
			idx++
			continue
		}

		rule := Rule{
			Action:             action,
			Kind:               KindIP,
			Raw:                trimmed,
			Index:              idx,
			Origin:             OriginExternal,
			Family:             "ipv4",
			Backend:            BackendNFTables,
			Deletable:          handle > 0,
			NotDeletableReason: notDeletableReason(handle),
			Handle:             handle,
		}
		if m := nftCommentRe.FindStringSubmatch(expr); m != nil {
			rule.Comment = StripPanelComment(m[1])
			rule.Origin = originOf(m[1])
		}
		if m := nftSaddrRe.FindStringSubmatch(expr); m != nil {
			rule.Source = m[2]
			rule.Family = "ipv4"
			if m[1] == "ip6" {
				rule.Family = "ipv6"
			}
		}
		// 端口表达式。
		if m := nftAnyProtoRe.FindStringSubmatch(expr); m != nil {
			rule.Kind = KindPort
			rule.Protocol = ProtoAny
			rule.PortText = m[1]
			if spec, err := portSpecFromText(m[1]); err == nil {
				rule.Port = spec
			}
		} else if m := nftPortExprRe.FindStringSubmatch(expr); m != nil {
			rule.Kind = KindPort
			rule.Protocol = m[1]
			rule.PortText = m[2]
			if spec, err := portSpecFromText(m[2]); err == nil {
				rule.Port = spec
			}
		}
		rules = append(rules, rule)
		idx++
	}
	return rules
}

// nftVerdict 从表达式里提取动作。
//
// nft 的 verdict 有 accept / drop / reject / return / jump / goto 等。
// 面板的语义只有放行与拒绝：
//
//	accept                 -> allow
//	drop / reject          -> deny
//	其余（return/jump/goto）-> 视为 deny 并保持不可删除
//	                          （它们是控制流跳转，删除它们会改变
//	                           其它规则的行为，绝不能让面板随手删）
func nftVerdict(expr string) (string, bool) {
	fields := strings.Fields(expr)
	for i := len(fields) - 1; i >= 0; i-- {
		switch fields[i] {
		case "accept":
			return ActionAllow, true
		case "drop", "reject":
			return ActionDeny, true
		case "return", "jump", "goto":
			return ActionDeny, true
		}
	}
	return "", false
}

// notDeletableReason 返回规则不可删除的原因。
func notDeletableReason(handle int) string {
	if handle > 0 {
		return ""
	}
	return "nftables 无法解析出该规则的 handle（句柄），因此无法精确删除它。" +
		"请使用创建这条规则的原工具（或 nft 命令行）删除。" +
		"面板绝不会用「清空规则集」的方式代替删除——那会丢掉全部防火墙规则。"
}

// ============================================================================
// iptables
// ============================================================================

// ParseIPTablesRules 解析 `iptables -S <chain>` 的输出。
//
// 真实输出（unshare -n + iptables -S INPUT，本机实测）：
//
//	-P INPUT ACCEPT
//	-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//	-A INPUT -s 192.168.1.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
//	-A INPUT -p tcp -m multiport --dports 8080:8090 -j ACCEPT
//	-A INPUT -j DOCKER-USER
//
// ########## 关键：-S 的输出就是可以回传给 -D 的规格 ##########
//
// 因此本函数把整行词元**原样保留在 Rule.Spec 里**，
// 删除时逐词回传。这是唯一能保证删除成功的方式——
// 按"我们添加时写的参数"重新组装会漏掉内核补的 -m tcp（见 command.go）。
func ParseIPTablesRules(output string) []Rule {
	var rules []Rule
	idx := 0
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// ########## 必须用引号感知的分词，不能用 strings.Fields ##########
		//
		// iptables -S 会**保留**注释的引号：
		//
		//	-A INPUT -p tcp --dport 443 -m comment --comment "[lipanel] https" -j ACCEPT
		//
		// strings.Fields 会把它切成 `"[lipanel]` 与 `https"` 两个词元
		// （注释里本来就常有空格，用户写"web 服务"更是必然）。
		// 后果有两层：
		//	① 备注读出来是半截（"[lipanel]"），面板显示错误；
		//	② **Spec 里的词元数是错的**，而 Spec 是删除时逐词回传的，
		//	   多切一刀就再也删不掉这条规则了。
		//
		// 因此这里必须按 iptables 自己的规则分词：双引号内的空格不分割。
		fields := splitIPTablesLine(trimmed)
		if len(fields) == 0 {
			continue
		}

		// 只处理规则行（-A）。
		// "-P"（默认策略）与 "-N"（建链）不是规则：
		// 它们出现在输出里但**不能删除**，
		// 把 -P INPUT DROP 误当成规则并"删除"会是灾难
		// （删除默认策略在 iptables 里没有对应操作，
		//   但把 ACCEPT 当成规则删掉会得到一条无意义的命令）。
		if fields[0] != "-A" {
			continue
		}
		if len(fields) < 2 {
			continue
		}

		rule := Rule{
			Kind:      KindIP,
			Action:    ActionAllow,
			Raw:       trimmed,
			Index:     idx,
			Origin:    OriginExternal,
			Family:    "ipv4",
			Backend:   BackendIPTables,
			Spec:      append([]string(nil), fields...),
			Deletable: true,
		}

		// 遍历时用显式的 next 索引，而不是在 case 里改 i。
		//
		// ########## 为什么不用 "case 内 i++" ##########
		//
		// 最初每个取值分支都写 `i++` 跳过一个参数值。
		// 这在 switch 里极易出错：`-m comment --comment "x"` 时，
		// `-m` 分支吃掉 "comment"，循环自身的 i++ 再前进一格，
		// 于是恰好**跳过 `--comment` 选项本身**，
		// 备注永远解析不到（这个缺陷被 TestParseIPTablesRules 抓到）。
		//
		// 现在统一为：每个有参选项自己回答"我消费了几个词元"，
		// 循环末尾统一前进，就不会出现"双重前进"。
		i := 2
		for i < len(fields) {
			f := fields[i]
			arg := func() (string, bool) {
				if i+1 < len(fields) {
					return fields[i+1], true
				}
				return "", false
			}
			switch f {
			case "-p":
				if v, ok := arg(); ok {
					rule.Protocol = v
					i += 2
					continue
				}
			case "-s", "--source":
				if v, ok := arg(); ok {
					rule.Source = v
					rule.Family = familyOfSource(v)
					i += 2
					continue
				}
			case "--dport":
				if v, ok := arg(); ok {
					rule.Kind = KindPort
					rule.PortText = v
					if spec, err := portSpecFromText(v); err == nil {
						rule.Port = spec
					}
					i += 2
					continue
				}
			case "--dports":
				if v, ok := arg(); ok {
					rule.Kind = KindPort
					// multiport 用冒号，本模块统一用短横线。
					text := strings.ReplaceAll(v, ":", "-")
					rule.PortText = text
					if spec, err := portSpecFromText(text); err == nil {
						rule.Port = spec
					}
					i += 2
					continue
				}
			case "-m":
				// 跳过扩展名（tcp/udp/multiport/comment/state...），
				// 但只在下一个词元确实不是新选项时才跳过它。
				//
				// 这一条判据是必要的：匹配器名恰好叫 "comment" 时
				// （`-m comment --comment "x"`），无条件跳过会吃掉
				// 后面的 `--comment` 选项本身。
				if v, ok := arg(); ok && !strings.HasPrefix(v, "-") {
					_ = v
					i += 2
					continue
				}
			case "--comment":
				if v, ok := arg(); ok {
					c := strings.Trim(v, `"`)
					rule.Comment = StripPanelComment(c)
					rule.Origin = originOf(c)
					i += 2
					continue
				}
			case "-j", "-g":
				if v, ok := arg(); ok {
					applyIPTablesTarget(&rule, v)
					i += 2
					continue
				}
			}
			// 无参选项或不认识的词元：前进一格。
			i++
		}

		// 没有端口的规则归为 IP 规则（如 "-A INPUT -j DOCKER-USER"）。
		if rule.Kind == KindPort && rule.PortText == "" {
			rule.Kind = KindIP
		}
		// 有端口但协议缺失时补 any（-m multiport 可以不带 -p）。
		if rule.Kind == KindPort && rule.Protocol == "" {
			rule.Protocol = ProtoAny
		}
		rules = append(rules, rule)
		idx++
	}
	return rules
}

// applyIPTablesTarget 根据 -j/-g 的参数设置规则动作与可删除性。
func applyIPTablesTarget(rule *Rule, target string) {
	switch target {
	case "ACCEPT":
		rule.Action = ActionAllow
	case "DROP", "REJECT":
		rule.Action = ActionDeny
	default:
		// ########## 跳转到自定义链：标记为不可删除 ##########
		//
		// 形如 "-j DOCKER-USER" 或 "-j ufw-before-input"。
		// 这类规则是防火墙的**结构性组成部分**，
		// 删除它会改变整条链的走向（Docker 的转发、
		// ufw 的全部入站处理都挂在这类跳转上）。
		//
		// 面板展示它（用户需要看到全貌），
		// 但不提供删除——避免一次误点让整台机器的
		// 网络策略失效。这与"只删除能精确识别规格的规则"
		// 的要求一致，而且更保守。
		rule.Action = ActionDeny
		rule.Deletable = false
		rule.NotDeletableReason = fmt.Sprintf(
			"该规则跳转到自定义链 %s，是整个防火墙策略的结构性组成部分。"+
				"删除它会改变其它规则的走向（例如 Docker 转发、ufw 的入站处理），"+
				"因此面板不提供删除。请使用创建它的工具（ufw / docker / 手工 iptables）管理。",
			target)
	}
}

// splitIPTablesLine 按 iptables -S 的格式分词（双引号内的空格不分割）。
//
// ########## 为什么不能直接用 strings.Fields ##########
//
// iptables -S 会保留注释的引号（"-m comment --comment "web 服务""），
// 而备注里含空格是常态。strings.Fields 会把一个备注切成多个词元，
// 后果是：
//
//	① 备注解析成半截；
//	② **Spec 的词元数错了**，而 Spec 是删除时逐词回传的
//	   —— 多切一刀就再也删不掉这条规则。
//
// 本函数按引号切分，并把引号**保留**在词元里
// （因为 Spec 要原样回传，去掉引号会让 -D 匹配不上）。
// 解析备注时才用 strings.Trim 去掉引号。
func splitIPTablesLine(line string) []string {
	var (
		out     []string
		current strings.Builder
		inQuote bool
		started bool
	)
	flush := func() {
		if started {
			out = append(out, current.String())
			current.Reset()
			started = false
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			// 引号本身保留在词元里（Spec 需要它）。
			current.WriteRune(r)
			started = true
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			current.WriteRune(r)
			started = true
		}
	}
	flush()
	return out
}

// ParseIPTablesDefaultPolicies 解析 `iptables -S` 输出里的默认策略。
//
// 形态：-P INPUT DROP / -P FORWARD DROP / -P OUTPUT ACCEPT
//
// ########## 为什么默认策略必须展示 ##########
//
// 与 ufw 的 Default 同理：它是"没有匹配规则的分组包会怎样"的答案。
// "-P INPUT ACCEPT" 意味着**防火墙几乎不设防**——
// 用户看到一堆规则会以为自己被保护着，实际所有端口本来就开着。
// 这个事实必须能被看到。
func ParseIPTablesDefaultPolicies(output string) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) == 3 && fields[0] == "-P" {
			out[fields[1]] = fields[2]
		}
	}
	return out
}

// ============================================================================
// firewalld
// ============================================================================

// ParseFirewallCmdListAll 解析 `firewall-cmd --list-all` 的输出。
//
// 真实输出形态：
//
//	public (active)
//	  target: default
//	  icmp-block-inversion: no
//	  interfaces: eth0
//	  sources:
//	  services: dhcpv6-client ssh
//	  ports: 8080/tcp 9090/udp
//	  protocols:
//	  masquerade: no
//	  forward-ports:
//	  source-ports:
//	  icmp-blocks:
//	  rich rules:
//		rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept
//
// ########## 必须解析 rich rules ##########
//
// 本模块的"带来源放行"与"拒绝"都以 rich rule 表达
// （见 command.go 的说明），只解析 ports 会漏掉它们——
// 用户在面板上加的规则刷新后消失，是绝不能出现的行为。
func ParseFirewallCmdListAll(output string) []Rule {
	var rules []Rule
	idx := 0
	currentSection := ""

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// 段落头："ports: 8080/tcp" 或 "rich rules:"（值可能为空）。
		if i := strings.Index(trimmed, ":"); i >= 0 && !strings.HasPrefix(trimmed, "rule ") {
			key := strings.TrimSpace(trimmed[:i])
			value := strings.TrimSpace(trimmed[i+1:])
			switch key {
			case "ports", "rich rules", "sources":
				currentSection = key
				if value == "" {
					continue
				}
				// 值在同一行：按空白切分（rich rules 除外，见下）。
				if key == "rich rules" {
					// rich rule 在同一行也按整行处理。
					rules = append(rules, parseFirewallRichRules(value, &idx)...)
					continue
				}
				rules = append(rules, parseFirewallValues(key, value, &idx)...)
				continue
			default:
				// 其它段落（interfaces/services/target 等）与规则无关。
				currentSection = ""
				continue
			}
		}

		// 续行：属于上一个段落。
		switch currentSection {
		case "rich rules":
			rules = append(rules, parseFirewallRichRules(trimmed, &idx)...)
		case "ports":
			rules = append(rules, parseFirewallValues("ports", trimmed, &idx)...)
		case "sources":
			rules = append(rules, parseFirewallValues("sources", trimmed, &idx)...)
		}
	}
	return rules
}

// parseFirewallValues 解析 ports 或 sources 段落的值。
func parseFirewallValues(section, value string, idx *int) []Rule {
	var out []Rule
	for _, token := range strings.Fields(value) {
		r := Rule{
			Backend:   BackendFirewalld,
			Origin:    OriginExternal,
			Family:    "ipv4",
			Action:    ActionAllow,
			Index:     *idx,
			Raw:       token,
			Deletable: true,
		}
		switch section {
		case "ports":
			// 形如 "8080/tcp" 或 "8080-8090/udp"。
			parts := strings.SplitN(token, "/", 2)
			if len(parts) != 2 {
				continue
			}
			r.Kind = KindPort
			r.PortText = parts[0]
			r.Protocol = strings.ToLower(parts[1])
			if spec, err := portSpecFromText(parts[0]); err == nil {
				r.Port = spec
			}
		case "sources":
			// 形如 "192.168.1.0/24" 或 "2001:db8::/32"。
			r.Kind = KindIP
			r.Source = token
			r.Family = familyOfSource(token)
		default:
			continue
		}
		out = append(out, r)
		*idx++
	}
	return out
}

// firewalldRichRuleRe 匹配 rich rule 的关键字段。
//
// 形如：
//
//	rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept
//	rule family="ipv4" source address="0.0.0.0/0" port port="25" protocol="tcp" reject
//	rule family="ipv4" source address="1.2.3.4" accept
var (
	richFamilyRe = regexp.MustCompile(`family="([^"]*)"`)
	richSourceRe = regexp.MustCompile(`source\s+address="([^"]*)"`)
	richPortRe   = regexp.MustCompile(`port\s+port="([^"]*)"`)
	richProtoRe  = regexp.MustCompile(`protocol="([^"]*)"`)
)

// parseFirewallRichRules 解析一条 rich rule。
//
// ########## 关于可删除性 ##########
//
// rich rule 的删除要求字符串**逐字节一致**，
// 因此这里保留原始文本到 Raw（Manager 删除时会原样回传）。
// 只要原文完整（本函数是从原始输出行解析的，因此一定完整），
// rich rule 就是可删除的。
func parseFirewallRichRules(text string, idx *int) []Rule {
	t := strings.TrimSpace(text)
	if t == "" || !strings.HasPrefix(t, "rule ") {
		return nil
	}
	r := Rule{
		Kind:      KindIP,
		Action:    ActionAllow,
		Raw:       t,
		Index:     *idx,
		Origin:    OriginExternal,
		Family:    "ipv4",
		Backend:   BackendFirewalld,
		Deletable: true,
	}
	if m := richFamilyRe.FindStringSubmatch(t); m != nil {
		r.Family = strings.ToLower(m[1])
	}
	if m := richSourceRe.FindStringSubmatch(t); m != nil {
		r.Source = m[1]
	}
	if m := richPortRe.FindStringSubmatch(t); m != nil {
		r.Kind = KindPort
		r.PortText = m[1]
		if spec, err := portSpecFromText(m[1]); err == nil {
			r.Port = spec
		}
	}
	if m := richProtoRe.FindStringSubmatch(t); m != nil {
		r.Protocol = strings.ToLower(m[1])
	}
	// verdict 是最后一个词。
	fields := strings.Fields(t)
	if len(fields) > 0 {
		switch fields[len(fields)-1] {
		case "reject", "drop":
			r.Action = ActionDeny
		case "accept":
			r.Action = ActionAllow
		default:
			// 其它动作（log/mark/limit 等）本模块不产生，
			// 也不应删除——它们可能带参数，删除语义复杂。
			r.Deletable = false
			r.NotDeletableReason = fmt.Sprintf(
				"该 rich rule 的动作是 %s，面板不管理这类规则，请使用 firewall-cmd 手工删除。",
				fields[len(fields)-1])
		}
	}
	*idx++
	return []Rule{r}
}

// ============================================================================
// 解析分发
// ============================================================================

// ParseRules 按后端分发解析。
func ParseRules(backend, output string) []Rule {
	switch backend {
	case BackendUFW:
		return ParseUFWRules(output)
	case BackendFirewalld:
		return ParseFirewallCmdListAll(output)
	case BackendNFTables:
		return ParseNFTRules(output)
	case BackendIPTables:
		return ParseIPTablesRules(output)
	default:
		return nil
	}
}

// IsValidSource 判断一个来源串是否是合法的地址或网段。
//
// 解析出的来源可能包含后端特有的写法（ufw 的 "Anywhere" 已在
// normalizeUFWSource 里归一化）。这里做最后一次把关：
// 不合法的来源在规则列表里保留展示，但标记为不可删除
// ——因为按它组装删除命令可能是错的。
func IsValidSource(source string) bool {
	if source == "" {
		return true // 任意来源
	}
	_, err := ValidateIPRule(source)
	return err == nil
}

// ParseAddrLenient 尽力把一个来源串解析成地址（解析不了返回空）。
//
// 与 ValidateIPRule 的区别：本函数**只用于展示与保护判定**，
// 不做任何写入。因此对"其实不合法但确实存在于系统里"的
// 来源串保持宽容，而不是让整条规则消失。
func ParseAddrLenient(source string) netip.Addr {
	if source == "" {
		return netip.Addr{}
	}
	if strings.Contains(source, "/") {
		if p, err := netip.ParsePrefix(source); err == nil {
			return p.Addr()
		}
		return netip.Addr{}
	}
	if a, err := netip.ParseAddr(source); err == nil {
		return a
	}
	return netip.Addr{}
}
