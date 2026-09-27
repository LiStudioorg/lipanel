package firewall

import (
	"fmt"
	"strings"
)

// ============================================================================
// 命令组装（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 本文件是**纯函数**集合：输入已校验的规则模型，输出 argv 切片。
// 没有任何 I/O、没有 Executor 依赖，因此可以被穷举单测。
//
// #################### 铁律：绝不拼 shell 字符串 ####################
//
// 全部函数返回 []string（argv 切片）而不是 string：
//
//	✅ []string{"ufw", "allow", "8080/tcp"}       -> exec.Command(name, args...)
//	❌ "ufw allow 8080/tcp"                       -> sh -c 里执行
//
// 这与 4.1 service、4.3 site、4.4 ssl、4.5 store 的纪律完全一致。
// 返回切片的额外好处是**测试可以逐元素断言**——
// 断言一个字符串里"包含 8080"远不如断言 args[2] == "8080/tcp" 精确，
// 后者能发现参数顺序错位、意外多出参数这类真实缺陷。
//
// #################### 为什么每个后端要单独一套组装函数 ####################
//
// 四个后端表达同一条"放行 8080/tcp"的语法差异很大，且**都有陷阱**：
//
//	ufw         allow 8080/tcp          范围用冒号 8080:8090/tcp（不是短横线！）
//	firewalld   --add-port=8080/tcp     范围用短横线 8080-8090/tcp
//	nftables    add rule inet filter input tcp dport 8080 accept
//	                                    范围用 8080-8090（同一条规则内）
//	iptables    -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//	                                    范围**必须**用 -m multiport --dports
//
// 试图写一个"通用组装器"注定要把这些差异塞进一堆 if，
// 结果是每个分支都难以独立测试。分开写、共用一个 RuleKey 输入模型，
// 是这里唯一能被测试锁死的结构。

// Command 是一条待执行的命令。
//
// 单独定义而不是直接返回 (string, []string) 二元组：
// 审计与 -firewall-dry-run 都需要把"将要执行的完整命令"记录下来，
// 有一个类型承载它比到处传两个值更不容易漏。
type Command struct {
	// Name 是可执行文件名（如 "ufw"、"iptables"）。
	Name string
	// Args 是参数切片，**绝不经过 shell**。
	Args []string
}

// String 返回仅供展示与日志的命令描述。
//
// ########## 它绝不能被执行 ##########
//
// 这个方法的唯一用途是写进审计与试运行日志，让人看清楚"到底跑了什么"。
// 执行路径必须是 exec.Command(cmd.Name, cmd.Args...)——
// 任何地方都不允许出现 sh -c cmd.String()。
// 为了减少误用，参数用引号包起来（含空格的参数在日志里不会被看错）。
func (c Command) String() string {
	if len(c.Args) == 0 {
		return c.Name
	}
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, c.Name)
	for _, a := range c.Args {
		if a == "" || strings.ContainsAny(a, " \t\"'\\$`;&|<>(){}[]*?!#~") {
			// 用 %q 而不是手工加引号：它会正确转义内部的反斜杠与引号，
			// 让人在日志里能准确还原原始参数值。
			parts = append(parts, fmt.Sprintf("%q", a))
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// ============================================================================
// 通用参数
// ============================================================================

// ufw 支持的协议后缀。
//
// ufw 的端口写法是 "8080/tcp"，协议是**端口的一部分**，
// 不能像 iptables 那样单独用 -p 指定。
func ufwPortArg(p PortSpec, proto string) (string, error) {
	switch proto {
	case ProtoTCP:
		return ufwPortString(p) + "/tcp", nil
	case ProtoUDP:
		return ufwPortString(p) + "/udp", nil
	case ProtoAny:
		// "any" 在 ufw 里没有单一后缀，调用方需展开成两条规则
		// （见 BuildUFWAddPort 的说明），因此这里返回错误。
		return "", fmt.Errorf("ufw 的端口后缀无法表达 any 协议，应由调用方展开为 tcp 与 udp 两条规则")
	default:
		return "", fmt.Errorf("不支持的协议 %q", proto)
	}
}

// ufwPortString 把 PortSpec 转成 ufw 的端口写法。
//
// ########## 范围分隔符是冒号，不是短横线 ##########
//
// ufw 的范围语法是 "8080:8090/tcp"。写短横线 ufw 会报
// "ERROR: Bad port"。这是最容易写错的一处（短横线是用户输入的形态、
// 也是 firewalld 的形态），因此单独一个函数并写明理由。
func ufwPortString(p PortSpec) string {
	if p.IsRange() {
		return fmt.Sprintf("%d:%d", p.Start, p.End)
	}
	return fmt.Sprintf("%d", p.Start)
}

// firewalldPortArg 把 PortSpec 转成 firewalld 的端口写法。
//
// firewalld 用短横线表达范围（"8080-8090/tcp"），
// 与 ufw 的冒号相反 —— 两者放一起看正是"不能写通用组装器"的例证。
func firewalldPortArg(p PortSpec, proto string) (string, error) {
	if proto == ProtoAny {
		return "", fmt.Errorf("firewalld 的 --add-port 需要明确协议，any 应由调用方展开为 tcp 与 udp")
	}
	if p.IsRange() {
		return fmt.Sprintf("%d-%d/%s", p.Start, p.End, proto), nil
	}
	return fmt.Sprintf("%d/%s", p.Start, proto), nil
}

// ============================================================================
// ufw
// ============================================================================

// BuildUFWAddPort 组装 ufw 的放行/拒绝端口命令。
//
// 命令形状：
//
//	ufw allow proto <tcp|udp> from <source> to any port <port> [comment <text>]
//	ufw deny  proto <tcp|udp> from <source> to any port <port> [comment <text>]
//
// ########## 为什么用长格式而不是 "ufw allow 8080/tcp" ##########
//
// 短格式（"ufw allow 8080/tcp"）无法表达来源限制，
// 而来源是本模块的功能要求之一。长格式能同时覆盖四种组合，
// 让"有没有来源"不成为两种不同的代码路径。
//
// ########## 范围与单端口在长格式下的写法一致 ##########
//
// 长格式下 ufw 同样用冒号表达范围（port 8080:8090）。
//
// ########## ProtoAny 必须由调用方展开 ##########
//
// ufw 的 proto 只能是一个具体协议。带来源限制的长格式下
// 无法用一个 proto 表达"tcp 和 udp 都要"，
// 因此返回错误而不是静默只放行 tcp——后者会让用户以为
// UDP 也开了，实际没有（DNS、WireGuard、游戏服务器都会受影响）。
func BuildUFWAddPort(key RuleKey, comment string) (Command, error) {
	proto := key.Protocol
	if proto == ProtoAny {
		return Command{}, fmt.Errorf("ufw 的一条规则无法同时覆盖 tcp 与 udp，请分别放行（调用方应展开为两条）")
	}
	// ufwPortArg 在这里的作用是**校验协议可表达性**：
	// any 协议与未知协议都必须被拒绝（见其实现）。
	// 返回值本身不直接使用——长格式下端口与协议是分开写的两段
	// （"proto tcp to any port 8080"），而不是短格式的 "8080/tcp"。
	if _, err := ufwPortArg(key.Port, proto); err != nil {
		return Command{}, err
	}

	verb := "allow"
	if key.Action == ActionDeny {
		verb = "deny"
	}

	args := []string{verb}
	if key.Source != "" {
		args = append(args, "from", key.Source)
	}
	// 长格式下必须显式写 proto 与 to any port。
	// 顺序固定为 ufw 文档规定的顺序，错了 ufw 会报语法错误。
	args = append(args, "proto", proto, "to", "any", "port", ufwPortString(key.Port))
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return Command{Name: "ufw", Args: args}, nil
}

// BuildUFWDeletePort 组装 ufw 的删除命令。
//
// ########## ufw 按规则**内容**删除，这是它相对 nft/iptables 的优势 ##########
//
// "ufw delete allow proto tcp from ... to any port 8080" 会找到
// 与内容完全匹配的规则并删除，不需要 handle 或精确规格。
// 因此 ufw 后端不存在 nft 那种"拿不到 handle 就删不掉"的问题。
//
// 注意 ufw delete 的参数必须与添加时**完全一致**（含 comment），
// 否则 ufw 报 "Could not delete non-existent rule"。
// 因此调用方必须把解析出的规则**原样**传回来，
// 而不是根据用户输入重新组装（见 Manager.DeletePort）。
func BuildUFWDeletePort(key RuleKey, comment string) (Command, error) {
	add, err := BuildUFWAddPort(key, comment)
	if err != nil {
		return Command{}, err
	}
	args := append([]string{"delete"}, add.Args...)
	return Command{Name: "ufw", Args: args}, nil
}

// BuildUFWStatus 组装查询状态的命令。
//
// 用 status verbose 而不是 status：verbose 会额外输出
//
//	Default: deny (incoming), allow (outgoing), disabled (routed)
//	Logging: on (low)
//
// 这些是用户在"防火墙状态"卡片里真正想看到的东西
// （默认策略尤其重要：它就是"没放行的端口会怎样"的答案）。
func BuildUFWStatus() Command {
	return Command{Name: "ufw", Args: []string{"status", "verbose"}}
}

// BuildUFWStatusNumbered 组装带编号的规则列表命令。
//
// ########## 为什么需要 numbered ##########
//
// 不带 numbered 的 status 输出**不包含规则编号**，
// 而编号是 ufw 自己维护的稳定标识，也是用户在其他地方
// （ufw status numbered + ufw delete <编号>）看到的形态。
// 面板展示编号能让用户把面板上的操作与命令行对上。
//
// 注意：本模块的删除**不依赖编号**（编号会随规则增删变化，
// 用它当删除目标有删错的风险），只用于展示。
func BuildUFWStatusNumbered() Command {
	return Command{Name: "ufw", Args: []string{"status", "numbered"}}
}

// ============================================================================
// firewalld
// ============================================================================

// BuildFirewallCmdAddPort 组装 firewalld 的放行端口命令。
func BuildFirewallCmdAddPort(key RuleKey, comment string) (Command, error) {
	portArg, err := firewalldPortArg(key.Port, key.Protocol)
	if err != nil {
		return Command{}, err
	}

	args := []string{"--permanent"}
	if key.Action == ActionDeny {
		// firewalld 没有"拒绝某端口"的永久规则语法：
		// rich rule 才是它的表达方式。
		args = append(args, "--add-rich-rule", firewalldDenyRichRule(key))
	} else if key.Source != "" {
		// 带来源的放行同样必须用 rich rule：
		// --add-port 只能表达"对所有来源开放"，无法限定来源。
		args = append(args, "--add-rich-rule", firewalldAllowRichRule(key, portArg))
	} else {
		args = append(args, "--add-port="+portArg)
	}
	return Command{Name: "firewall-cmd", Args: args}, nil
}

// firewalldAllowRichRule 生成限定来源的放行 rich rule。
func firewalldAllowRichRule(key RuleKey, portArg string) string {
	return fmt.Sprintf(
		`rule family="%s" source address="%s" port port="%s" protocol="%s" accept`,
		familyOf(key.Source), key.Source, key.Port.String(), key.Protocol)
}

// firewalldDenyRichRule 生成拒绝 rich rule。
func firewalldDenyRichRule(key RuleKey) string {
	src := key.Source
	if src == "" {
		// 没有来源时用 0.0.0.0/0 或 ::/0 表达"所有来源"：
		// rich rule 的 source 是必填项，不像 --add-port 可以省略。
		src = anySourceFor(familyOf(key.Source))
	}
	return fmt.Sprintf(
		`rule family="%s" source address="%s" port port="%s" protocol="%s" reject`,
		familyOf(src), src, key.Port.String(), key.Protocol)
}

// familyOf 判断某个来源串属于 ipv4 还是 ipv6 族。
//
// firewalld 的 rich rule **必须**声明 family，且必须与实际地址族一致，
// 否则 firewalld 报 "INVALID_ZONE" 或静默不生效。
// 空串（任意来源）默认 ipv4 —— IPv4 是绝大多数场景，
// 需要 v6 时用户显式填一个 v6 地址即可走到 ipv6 分支。
func familyOf(source string) string {
	if source == "" {
		return "ipv4"
	}
	if strings.Contains(source, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// anySourceFor 返回某地址族下"所有来源"的写法。
func anySourceFor(family string) string {
	if family == "ipv6" {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// BuildFirewallCmdRemovePort 组装 firewalld 的删除端口命令。
//
// 与添加同样需要区分形态（--remove-port 还是 rich rule），
// 因此调用方必须把解析出的规则原样传回。
// rich rule 的字符串必须**逐字节一致**，否则 firewalld
// 报 "NOT_ENABLED"（找不到要删的规则）。
func BuildFirewallCmdRemovePort(key RuleKey, comment string) (Command, error) {
	add, err := BuildFirewallCmdAddPort(key, comment)
	if err != nil {
		return Command{}, err
	}
	args := make([]string, 0, len(add.Args))
	for _, a := range add.Args {
		args = append(args, strings.Replace(a, "--add-", "--remove-", 1))
	}
	return Command{Name: "firewall-cmd", Args: args}, nil
}

// BuildFirewallCmdAddSource 组装 firewalld 的 IP 黑白名单命令。
//
// ########## 为什么黑白名单也用 rich rule ##########
//
// firewalld 的 --add-source 语义是"把这个来源划入某个 zone"，
// 而 zone 的行为（放行什么）取决于 zone 的配置——
// 同一个 --add-source 在 trusted zone 下是"完全放行"，
// 在 drop zone 下是"全部丢弃"。把这种依赖上下文的语义
// 暴露成"黑白名单"，用户无法预期结果。
//
// rich rule 的 accept/reject 是**明确无歧义**的，
// 与用户在面板上看到的"白名单/黑名单"一一对应。
func BuildFirewallCmdAddSource(key RuleKey, source string, comment string) Command {
	verb := "accept"
	if key.Action == ActionDeny {
		verb = "reject"
	}
	rule := fmt.Sprintf(`rule family="%s" source address="%s" %s`,
		familyOf(source), source, verb)
	return Command{Name: "firewall-cmd", Args: []string{"--permanent", "--add-rich-rule", rule}}
}

// BuildFirewallCmdRemoveSource 组装 firewalld 的删除 IP 规则命令。
func BuildFirewallCmdRemoveSource(key RuleKey, source string, comment string) Command {
	add := BuildFirewallCmdAddSource(key, source, comment)
	args := make([]string, 0, len(add.Args))
	for _, a := range add.Args {
		args = append(args, strings.Replace(a, "--add-", "--remove-", 1))
	}
	return Command{Name: "firewall-cmd", Args: args}
}

// BuildFirewallCmdListAll 组装查询 firewalld 全部规则的命令。
//
// 用 --list-all 而不是 --list-ports：前者同时给出 interfaces、
// sources、services、ports、rich rules，是"这个 zone 当前长什么样"
// 的完整快照。只列 ports 会漏掉 rich rule（而本模块的
// 带来源规则与拒绝规则恰好都以 rich rule 表达）。
func BuildFirewallCmdListAll() Command {
	return Command{Name: "firewall-cmd", Args: []string{"--list-all"}}
}

// BuildFirewallCmdState 组装查询 firewalld 运行状态的命令。
func BuildFirewallCmdState() Command {
	return Command{Name: "firewall-cmd", Args: []string{"--state"}}
}

// ============================================================================
// nftables
// ============================================================================

// BuildNFTAddPort 组装 nftables 的放行/拒绝端口命令。
//
// 命令形状：
//
//	nft add rule inet <table> <chain> tcp dport 8080 accept
//	nft add rule inet <table> <chain> tcp dport 8080-8090 accept
//	nft add rule inet <table> <chain> ip saddr 1.2.3.4 tcp dport 8080 accept
//
// ########## 范围用短横线 ##########
//
// nft 的端口范围是 "8080-8090"，写冒号会报语法错误。
// （ufw 是冒号、nft 与 firewalld 是短横线——三种写法。）
//
// ########## 来源用 ip saddr / ip6 saddr ##########
//
// nft 需要按地址族选择 ip 还是 ip6 关键字，
// 且 inet 表（同时承载 v4/v6）里两者可以并存。
func BuildNFTAddPort(table, chain string, key RuleKey, comment string) (Command, error) {
	if table == "" || chain == "" {
		return Command{}, fmt.Errorf("nftables 需要指定 table 与 chain")
	}
	expr, err := nftPortExpr(key)
	if err != nil {
		return Command{}, err
	}
	verdict := "accept"
	if key.Action == ActionDeny {
		verdict = "drop"
	}
	if comment != "" {
		expr = append(expr, "comment", fmt.Sprintf("%q", comment))
	}
	expr = append(expr, verdict)

	args := []string{"add", "rule", "inet", table, chain}
	args = append(args, expr...)
	return Command{Name: "nft", Args: args}, nil
}

// nftPortExpr 生成 nft 规则的匹配表达式。
func nftPortExpr(key RuleKey) ([]string, error) {
	var expr []string
	if key.Source != "" {
		// 按来源地址族选择 ip / ip6 关键字。
		family := "ip"
		if strings.Contains(key.Source, ":") {
			family = "ip6"
		}
		expr = append(expr, family, "saddr", key.Source)
	}

	portStr := key.Port.String() // nft 的范围写法与 PortSpec.String() 一致（短横线）
	if key.Protocol == ProtoAny {
		// nft 的一条规则若要同时覆盖 tcp/udp，需要用 meta l4proto
		// 配合匿名集合：meta l4proto { tcp, udp } th dport 8080
		expr = append(expr, "meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", portStr)
		return expr, nil
	}
	if key.Protocol != ProtoTCP && key.Protocol != ProtoUDP {
		return nil, fmt.Errorf("不支持的协议 %q", key.Protocol)
	}
	expr = append(expr, key.Protocol, "dport", portStr)
	return expr, nil
}

// BuildNFTDeletePort 组装 nftables 的删除命令（按 handle）。
//
// ########## 为什么 nft 只能按 handle 删 ##########
//
// nft 没有 "delete rule matching <内容>" 的语法。要删除一条规则，
// 必须给出它的 handle（一个由内核分配的数字）。
//
// ########## 为什么这里绝不能出现 flush ##########
//
// 一个"看起来能达成目的"的做法是 `nft flush ruleset`——
// 它会清空整个防火墙。用户在面板上点"删除 8080"，
// 结果是**这台机器上全部防火墙规则消失**（包括 SSH 白名单、
// 包括 ufw 装的那一整套链）。这是本模块唯一可能造成
// 灾难性后果的操作，因此在类型层面就杜绝：
//
//	本函数只接受 handle，且 handle <= 0 直接返回错误。
//	调用方（Manager.DeletePort）在拿不到 handle 时
//	**拒绝删除并说明原因**，而不是退化成任何形式的清空。
//
// 另有一条测试（TestNFTCommandsNeverFlush）断言本包**任何**
// 组装函数产出的 argv 里都不出现 "flush"。
func BuildNFTDeletePort(table, chain string, handle int) (Command, error) {
	if table == "" || chain == "" {
		return Command{}, fmt.Errorf("nftables 需要指定 table 与 chain")
	}
	if handle <= 0 {
		return Command{}, fmt.Errorf(
			"nftables 删除规则必须提供有效的 handle（收到 %d）。"+
				"拿不到 handle 时应拒绝删除，绝不能退化为清空规则集", handle)
	}
	return Command{
		Name: "nft",
		Args: []string{"delete", "rule", "inet", table, chain, "handle", fmt.Sprintf("%d", handle)},
	}, nil
}

// BuildNFTListRuleset 组装列出全部规则（含 handle）的命令。
//
// -a 是 --handle 的短选项，**必须有**：不带它输出里没有 handle，
// 于是所有删除操作都无法进行。
func BuildNFTListRuleset() Command {
	return Command{Name: "nft", Args: []string{"-a", "list", "ruleset"}}
}

// ============================================================================
// iptables
// ============================================================================

// BuildIPTablesAddPort 组装 iptables 的放行/拒绝端口命令。
//
// 命令形状（单端口）：
//
//	iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//
// 命令形状（范围）：
//
//	iptables -A INPUT -p tcp -m multiport --dports 8080:8090 -j ACCEPT
//
// ########## 范围的两种写法与为什么选 multiport ##########
//
// iptables 表达端口范围有两种方式：
//
//	① -p tcp --dport 8080:8090     （冒号，依赖 tcp 扩展的隐式加载）
//	② -p tcp -m multiport --dports 8080:8090
//
// 选 ② 的理由：① 的冒号语法在部分 iptables 版本/后端（nf_tables 后端
// 与 legacy 后端）里行为不一致，且当规则里还有别的匹配条件时
// 容易与 --dport 的单端口语义混淆。multiport 是明确表达
// "一组端口"的扩展，语义无歧义。
//
// 注意 multiport 的**分隔符也是冒号**（8080:8090），不是短横线——
// 这是本模块第四种范围写法。真实环境下 iptables 把
// "8080-8090" 解释成**两个独立端口**（8080 和 8090），
// 静默地给出与用户意图不符的规则，因此这一处必须精确。
func BuildIPTablesAddPort(key RuleKey, comment string) (Command, error) {
	proto := key.Protocol
	if proto == ProtoAny {
		return Command{}, fmt.Errorf("iptables 的一条规则需要明确的 -p 协议，any 应由调用方展开为两条")
	}
	if proto != ProtoTCP && proto != ProtoUDP {
		return Command{}, fmt.Errorf("不支持的协议 %q", proto)
	}

	args := []string{"-A", "INPUT"}
	if key.Source != "" {
		family := "-s"
		args = append(args, family, key.Source)
	}
	args = append(args, "-p", proto)

	if key.Port.IsRange() {
		// multiport 的端口分隔符是冒号。
		args = append(args, "-m", "multiport", "--dports",
			fmt.Sprintf("%d:%d", key.Port.Start, key.Port.End))
	} else {
		args = append(args, "-m", proto, "--dport", fmt.Sprintf("%d", key.Port.Start))
	}

	verdict := "ACCEPT"
	if key.Action == ActionDeny {
		verdict = "DROP"
	}
	args = append(args, "-j", verdict)

	if comment != "" {
		// 注释用双引号包裹：iptables 的 --comment 会把整个参数
		// 原样写进内核，含空格时不加引号在 iptables-save 输出里
		// 会变成一个没有引号的裸串，导致后续 -D 匹配不上。
		args = append(args, "-m", "comment", "--comment", fmt.Sprintf("%q", comment))
	}
	return Command{Name: "iptables", Args: args}, nil
}

// BuildIPTablesDeleteSpec 组装按精确规格删除 iptables 规则的命令。
//
// ########## 为什么删除必须用"解析出来的原始规格" ##########
//
// iptables 的 -D 要求参数与规则在**内核里的实际规格**一致。
// 真实环境实测（unshare -n + iptables）：
//
//	$ iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
//	$ iptables -S INPUT
//	-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//	                          ^^^^^^^ 我们没写，iptables 自己加的
//
// 若删除时按"我们添加时写的参数"重新组装（不含 -m tcp），
// iptables 报 "Bad rule (does a matching rule exist in that chain?)"。
// 因此删除**必须**用 iptables -S 解析出的规格串，
// 且必须逐词原样回传。
//
// ########## spec 的来源是可信的 ##########
//
// spec 来自我们自己执行的 `iptables -S` 输出，不是用户输入。
// 唯一需要防的是"解析出的规格被篡改"——因此调用方传进来的 spec
// 会被本函数做一次安全检查：拒绝含换行、拒绝不以 -A/-I 开头的串
// （保证它确实是一条规则规格而不是别的什么东西）。
func BuildIPTablesDeleteSpec(chain string, spec []string, comment string) (Command, error) {
	if chain == "" {
		return Command{}, fmt.Errorf("iptables 需要指定链名")
	}
	if len(spec) == 0 {
		return Command{}, fmt.Errorf("iptables 删除需要规则规格（来自 iptables -S 的解析结果）")
	}
	// 规格串必须以 -A 或 -I 开头（-S 的输出形态）。
	// 这能拦住"把整行别的文本当成规格"这类问题。
	if spec[0] != "-A" && spec[0] != "-I" {
		return Command{}, fmt.Errorf(
			"iptables 规则规格必须以 -A 或 -I 开头（收到 %q），拒绝执行", spec[0])
	}
	for _, tok := range spec {
		if strings.ContainsAny(tok, "\n\r\x00") {
			return Command{}, fmt.Errorf("iptables 规则规格含换行或空字节，拒绝执行")
		}
	}

	// -D <链> 后面接**去掉 -A <链> 前缀**的剩余部分。
	// 实测：-D 的参数格式是 "iptables -D INPUT -p tcp -m tcp --dport 8080 -j ACCEPT"，
	// 不能再带 -A INPUT（会报 "Bad rule"）。
	args := []string{"-D", chain}
	rest := spec[1:]
	// spec[1] 是链名（-S 输出形如 "-A INPUT -p tcp ..."），
	// 但个别情况下链名可能与传入的 chain 不一致，此时以规格里的为准并校验。
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		if rest[0] != chain {
			return Command{}, fmt.Errorf(
				"规则规格里的链名 %q 与期望的 %q 不一致，拒绝执行（避免删错链）", rest[0], chain)
		}
		rest = rest[1:]
	}
	args = append(args, rest...)
	return Command{Name: "iptables", Args: args}, nil
}

// BuildIPTablesListRules 组装列出某条链规则的命令。
//
// 用 -S <链> 而不是 -L -n -v：
//
//	① -S 的输出**就是可以直接回传给 -D 的规格**（本模块删除路径依赖这一点）；
//	② -L 的输出是给人看的表格，列宽对齐、端口被缩写成服务名
//	   （80 会显示成 "http"），解析它需要额外的反查，且不可靠。
//
// -n 让 -S 不做 DNS 反查（否则一个大网段的规则会让命令卡住几十秒）。
func BuildIPTablesListRules(chain string) (Command, error) {
	if chain == "" {
		return Command{}, fmt.Errorf("iptables 需要指定链名")
	}
	return Command{Name: "iptables", Args: []string{"-S", chain}}, nil
}

// ============================================================================
// 通用查询
// ============================================================================

// BuildBackendAvailableCheck 返回判断某后端命令是否存在/可用的探测命令。
//
// 探测一律用**只读且轻量**的子命令，绝不使用会修改系统状态的命令。
func BuildBackendAvailableCheck(backend string) (Command, error) {
	switch backend {
	case BackendUFW:
		return BuildUFWStatus(), nil
	case BackendFirewalld:
		return BuildFirewallCmdState(), nil
	case BackendNFTables:
		return Command{Name: "nft", Args: []string{"--version"}}, nil
	case BackendIPTables:
		return Command{Name: "iptables", Args: []string{"--version"}}, nil
	default:
		return Command{}, fmt.Errorf("未知的防火墙后端 %q", backend)
	}
}
