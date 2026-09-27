package firewall

import (
	"strings"
	"testing"
)

// ============================================================================
// 命令组装（阶段四 4.6）
// ============================================================================
//
// 本文件的断言一律**逐元素**比较 argv，而不是检查"字符串里包含什么"。
// 理由：包含式断言无法发现参数顺序错位（"allow tcp 8080" 与 "allow 8080 tcp"
// 都"包含 allow、tcp、8080"），而参数顺序对 ufw/nft/iptables 都是致命的。

// mustPort 是测试辅助：解析端口规格，失败即终止。
func mustPort(t *testing.T, raw string) PortSpec {
	t.Helper()
	p, err := ValidatePortSpec(raw)
	if err != nil {
		t.Fatalf("测试前置条件错误：ValidatePortSpec(%q) 失败: %v", raw, err)
	}
	return p
}

// eqArgs 逐元素比较 argv。
func eqArgs(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("argv 长度不符:\n  实际 %d: %#v\n  期望 %d: %#v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, 期望 %q\n  完整实际: %#v", i, got[i], want[i], got)
		}
	}
}

// ============================================================================
// ufw
// ============================================================================

func TestBuildUFWAddPortSimple(t *testing.T) {
	cmd, err := BuildUFWAddPort(RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if cmd.Name != "ufw" {
		t.Fatalf("命令名应为 ufw，实际 %q", cmd.Name)
	}
	// 长格式：allow proto tcp to any port 8080
	eqArgs(t, cmd.Args, "allow", "proto", "tcp", "to", "any", "port", "8080")
}

// TestBuildUFWRangeUsesColon 锁死"ufw 范围用冒号"。
//
// ufw 的范围语法是 8080:8090，写短横线会报 "ERROR: Bad port"。
// 短横线是用户输入的形态、也是 firewalld 与 nft 的形态，
// 因此这是最容易写错的一处。
func TestBuildUFWRangeUsesColon(t *testing.T) {
	cmd, err := BuildUFWAddPort(RuleKey{
		Port: mustPort(t, "8080-8090"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "allow", "proto", "tcp", "to", "any", "port", "8080:8090")
	// 断言绝不出现短横线形态。
	for _, a := range cmd.Args {
		if strings.Contains(a, "8080-8090") {
			t.Fatalf("ufw 的范围必须用冒号，实际出现短横线: %#v", cmd.Args)
		}
	}
}

func TestBuildUFWAddPortWithSource(t *testing.T) {
	cmd, err := BuildUFWAddPort(RuleKey{
		Port: mustPort(t, "22"), Protocol: ProtoTCP, Source: "192.168.1.0/24", Action: ActionAllow,
	}, "ssh 白名单")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args,
		"allow", "from", "192.168.1.0/24", "proto", "tcp", "to", "any", "port", "22",
		"comment", "ssh 白名单")
}

func TestBuildUFWAddPortDeny(t *testing.T) {
	cmd, err := BuildUFWAddPort(RuleKey{
		Port: mustPort(t, "25"), Protocol: ProtoTCP, Action: ActionDeny,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "deny", "proto", "tcp", "to", "any", "port", "25")
}

// TestBuildUFWAnyProtocolRejected 锁死"ufw 的 any 协议必须由调用方展开"。
//
// ufw 的 proto 只能是一个具体协议。若静默只放行 tcp，
// 用户会以为 UDP 也开了——DNS(53)、WireGuard(51820)、
// 游戏服务器这类场景会静默失效。
func TestBuildUFWAnyProtocolRejected(t *testing.T) {
	_, err := BuildUFWAddPort(RuleKey{
		Port: mustPort(t, "53"), Protocol: ProtoAny, Action: ActionAllow,
	}, "")
	if err == nil {
		t.Fatal("ufw 的 any 协议必须返回错误，由调用方展开为 tcp+udp 两条")
	}
	if !strings.Contains(err.Error(), "tcp") || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("错误信息应说明需分别放行 tcp 与 udp，实际: %v", err)
	}
}

// TestBuildUFWDeleteMatchesAdd 锁死"删除参数与添加参数完全一致（仅多 delete）"。
//
// ufw delete 要求参数与添加时逐字相同，否则报
// "Could not delete non-existent rule"。
func TestBuildUFWDeleteMatchesAdd(t *testing.T) {
	key := RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Source: "10.0.0.0/8",
		Action: ActionAllow,
	}
	add, err := BuildUFWAddPort(key, "备注")
	if err != nil {
		t.Fatalf("BuildUFWAddPort 失败: %v", err)
	}
	del, err := BuildUFWDeletePort(key, "备注")
	if err != nil {
		t.Fatalf("BuildUFWDeletePort 失败: %v", err)
	}
	if del.Name != "ufw" {
		t.Fatalf("命令名应为 ufw，实际 %q", del.Name)
	}
	if len(del.Args) != len(add.Args)+1 || del.Args[0] != "delete" {
		t.Fatalf("delete 命令应是在 add 参数前加 delete:\n  add %#v\n  del %#v", add.Args, del.Args)
	}
	eqArgs(t, del.Args[1:], add.Args...)
}

func TestBuildUFWStatusVerbose(t *testing.T) {
	cmd := BuildUFWStatus()
	eqArgs(t, cmd.Args, "status", "verbose")
}

func TestBuildUFWStatusNumbered(t *testing.T) {
	cmd := BuildUFWStatusNumbered()
	eqArgs(t, cmd.Args, "status", "numbered")
}

// ============================================================================
// firewalld
// ============================================================================

func TestBuildFirewallCmdAddPortSimple(t *testing.T) {
	cmd, err := BuildFirewallCmdAddPort(RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if cmd.Name != "firewall-cmd" {
		t.Fatalf("命令名应为 firewall-cmd，实际 %q", cmd.Name)
	}
	eqArgs(t, cmd.Args, "--permanent", "--add-port=8080/tcp")
}

// TestBuildFirewallCmdRangeUsesHyphen 锁死 firewalld 范围用短横线。
func TestBuildFirewallCmdRangeUsesHyphen(t *testing.T) {
	cmd, err := BuildFirewallCmdAddPort(RuleKey{
		Port: mustPort(t, "8080-8090"), Protocol: ProtoUDP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "--permanent", "--add-port=8080-8090/udp")
}

// TestBuildFirewallCmdSourceUsesRichRule 锁死"带来源的放行必须用 rich rule"。
//
// firewalld 的 --add-port 无法限定来源，只能表达"对所有来源开放"。
// 若忽略来源直接 --add-port，用户设置的"仅允许 192.168.1.0/24 访问 3306"
// 会变成"全互联网都能访问 MySQL"——这是静默的授权扩大。
func TestBuildFirewallCmdSourceUsesRichRule(t *testing.T) {
	cmd, err := BuildFirewallCmdAddPort(RuleKey{
		Port: mustPort(t, "3306"), Protocol: ProtoTCP,
		Source: "192.168.1.0/24", Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "--permanent", "--add-rich-rule",
		`rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept`)
	// 关键：绝不能出现 --add-port（那会变成对所有来源开放）。
	for _, a := range cmd.Args {
		if strings.HasPrefix(a, "--add-port") {
			t.Fatalf("带来源的规则绝不能退化为 --add-port，实际: %#v", cmd.Args)
		}
	}
}

// TestBuildFirewallCmdIPv6Family 校验 v6 来源的 family 判定。
//
// rich rule 的 family 必须与实际地址族一致，否则 firewalld 报错或静默不生效。
func TestBuildFirewallCmdIPv6Family(t *testing.T) {
	cmd, err := BuildFirewallCmdAddPort(RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP,
		Source: "2001:db8::/32", Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if !strings.Contains(cmd.Args[2], `family="ipv6"`) {
		t.Fatalf("IPv6 来源应使用 family=\"ipv6\"，实际: %#v", cmd.Args)
	}
}

// TestBuildFirewallCmdDenyUsesRichRule 锁死"拒绝规则用 rich rule"。
//
// firewalld 没有"拒绝某端口"的 --add 语法，
// rich rule 的 reject 才是其表达方式。
func TestBuildFirewallCmdDenyUsesRichRule(t *testing.T) {
	cmd, err := BuildFirewallCmdAddPort(RuleKey{
		Port: mustPort(t, "25"), Protocol: ProtoTCP, Action: ActionDeny,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "--add-rich-rule") || !strings.Contains(joined, "reject") {
		t.Fatalf("拒绝规则必须用 rich rule 的 reject，实际: %#v", cmd.Args)
	}
	// 无来源时用 0.0.0.0/0 表达所有来源（rich rule 的 source 是必填）。
	if !strings.Contains(joined, "0.0.0.0/0") {
		t.Fatalf("无来源的拒绝规则应使用 0.0.0.0/0，实际: %#v", cmd.Args)
	}
}

func TestBuildFirewallCmdRemovePort(t *testing.T) {
	cmd, err := BuildFirewallCmdRemovePort(RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "--permanent", "--remove-port=8080/tcp")
}

func TestBuildFirewallCmdAddSource(t *testing.T) {
	cmd := BuildFirewallCmdAddSource(
		RuleKey{Action: ActionAllow}, "1.2.3.4", "")
	eqArgs(t, cmd.Args, "--permanent", "--add-rich-rule",
		`rule family="ipv4" source address="1.2.3.4" accept`)

	cmd = BuildFirewallCmdAddSource(
		RuleKey{Action: ActionDeny}, "2001:db8::1", "")
	eqArgs(t, cmd.Args, "--permanent", "--add-rich-rule",
		`rule family="ipv6" source address="2001:db8::1" reject`)
}

func TestBuildFirewallCmdRemoveSource(t *testing.T) {
	cmd := BuildFirewallCmdRemoveSource(
		RuleKey{Action: ActionDeny}, "1.2.3.4", "")
	eqArgs(t, cmd.Args, "--permanent", "--remove-rich-rule",
		`rule family="ipv4" source address="1.2.3.4" reject`)
}

func TestBuildFirewallCmdListAll(t *testing.T) {
	cmd := BuildFirewallCmdListAll()
	eqArgs(t, cmd.Args, "--list-all")
}

// ============================================================================
// nftables
// ============================================================================

func TestBuildNFTAddPortSimple(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if cmd.Name != "nft" {
		t.Fatalf("命令名应为 nft，实际 %q", cmd.Name)
	}
	eqArgs(t, cmd.Args, "add", "rule", "inet", "filter", "input",
		"tcp", "dport", "8080", "accept")
}

// TestBuildNFTRangeUsesHyphen 锁死 nft 范围用短横线（不是 ufw 的冒号）。
func TestBuildNFTRangeUsesHyphen(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "8080-8090"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "add", "rule", "inet", "filter", "input",
		"tcp", "dport", "8080-8090", "accept")
}

func TestBuildNFTAddPortWithSourceV4(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "22"), Protocol: ProtoTCP,
		Source: "192.168.1.0/24", Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "add", "rule", "inet", "filter", "input",
		"ip", "saddr", "192.168.1.0/24", "tcp", "dport", "22", "accept")
}

// TestBuildNFTAddPortWithSourceV6 锁死 v6 来源用 ip6 关键字。
func TestBuildNFTAddPortWithSourceV6(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "22"), Protocol: ProtoTCP,
		Source: "2001:db8::/32", Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "add", "rule", "inet", "filter", "input",
		"ip6", "saddr", "2001:db8::/32", "tcp", "dport", "22", "accept")
}

func TestBuildNFTAddPortDenyUsesDrop(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "25"), Protocol: ProtoTCP, Action: ActionDeny,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if cmd.Args[len(cmd.Args)-1] != "drop" {
		t.Fatalf("拒绝规则应以 drop 结尾，实际: %#v", cmd.Args)
	}
}

// TestBuildNFTAddPortAnyProtocol 校验 any 协议用 meta l4proto 集合表达。
func TestBuildNFTAddPortAnyProtocol(t *testing.T) {
	cmd, err := BuildNFTAddPort("filter", "input", RuleKey{
		Port: mustPort(t, "53"), Protocol: ProtoAny, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	joined := strings.Join(cmd.Args, " ")
	for _, want := range []string{"meta", "l4proto", "tcp", "udp", "th", "dport", "53"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("nft 的 any 协议应使用 meta l4proto 集合，缺少 %q: %#v", want, cmd.Args)
		}
	}
}

// TestBuildNFTDeleteRequiresHandle 锁死"没有 handle 必须拒绝删除"。
//
// 这是本模块安全的最后一道闸门：拿不到 handle 时，
// 唯一"看起来可行"的替代是 flush ruleset（清空全部规则），
// 那会让用户在点"删除 8080"时丢掉整台机器的防火墙（含 SSH 白名单）。
func TestBuildNFTDeleteRequiresHandle(t *testing.T) {
	for _, handle := range []int{0, -1, -999} {
		_, err := BuildNFTDeletePort("filter", "input", handle)
		if err == nil {
			t.Fatalf("handle=%d 必须被拒绝，绝不能退化为清空规则集", handle)
		}
	}
	// 合法 handle 应当成功。
	cmd, err := BuildNFTDeletePort("filter", "input", 42)
	if err != nil {
		t.Fatalf("合法 handle 意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "delete", "rule", "inet", "filter", "input", "handle", "42")
}

// TestNFTCommandsNeverFlush 是本模块最重要的安全断言之一。
//
// 遍历本包全部 nft 组装函数，断言产出的 argv 里**绝不出现 flush**。
//
// 理由：`nft flush ruleset` 会清空整台机器的防火墙规则。
// 若有人为了"让删除功能可用"而引入它，用户在面板上点一下
// 「删除 8080」就会丢掉全部规则（包括 4.6 之前就存在的
// SSH 白名单、ufw 的整套链）。
// 这条断言把"绝不能出现 flush"从注释里的承诺变成测试锁死的事实。
func TestNFTCommandsNeverFlush(t *testing.T) {
	keys := []RuleKey{
		{Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow},
		{Port: mustPort(t, "8080-8090"), Protocol: ProtoUDP, Action: ActionDeny},
		{Port: mustPort(t, "22"), Protocol: ProtoTCP, Source: "1.2.3.4", Action: ActionAllow},
		{Port: mustPort(t, "53"), Protocol: ProtoAny, Action: ActionAllow},
	}

	var cmds []Command
	for _, k := range keys {
		if c, err := BuildNFTAddPort("filter", "input", k, "备注"); err == nil {
			cmds = append(cmds, c)
		}
	}
	if c, err := BuildNFTDeletePort("filter", "input", 7); err == nil {
		cmds = append(cmds, c)
	}
	cmds = append(cmds, BuildNFTListRuleset())

	if len(cmds) == 0 {
		t.Fatal("未收集到任何命令，测试本身失效")
	}
	for _, c := range cmds {
		if c.Name != "nft" {
			continue
		}
		for _, a := range c.Args {
			low := strings.ToLower(a)
			if strings.Contains(low, "flush") {
				t.Fatalf("nft 命令中出现了 flush，这会造成清空防火墙的灾难性后果: %s", c.String())
			}
		}
	}
}

// TestNoCommandUsesShell 锁死"绝不经过 shell"。
//
// 断言本包所有组装函数的输出中：
//
//	① 可执行文件名绝不是 sh/bash/dash/zsh；
//	② argv 里绝不出现 -c（sh -c 的特征）或 eval。
//
// 这是全模块的安全根基：用户输入只作为 argv 的一个元素传递，
// 永远不会被任何 shell 解释。
func TestNoCommandUsesShell(t *testing.T) {
	var cmds []Command

	add := func(c Command, err error) {
		if err == nil {
			cmds = append(cmds, c)
		}
	}

	keys := []RuleKey{
		{Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow},
		{Port: mustPort(t, "8080-8090"), Protocol: ProtoUDP, Action: ActionDeny},
		{Port: mustPort(t, "22"), Protocol: ProtoTCP, Source: "192.168.1.0/24", Action: ActionAllow},
		{Port: mustPort(t, "443"), Protocol: ProtoAny, Source: "2001:db8::/32", Action: ActionDeny},
	}
	for _, k := range keys {
		add(BuildUFWAddPort(k, "注释"))
		add(BuildUFWDeletePort(k, "注释"))
		add(BuildFirewallCmdAddPort(k, "注释"))
		add(BuildFirewallCmdRemovePort(k, "注释"))
		add(BuildNFTAddPort("filter", "input", k, "注释"))
		add(BuildIPTablesAddPort(k, "注释"))
	}
	cmds = append(cmds, BuildUFWStatus(), BuildUFWStatusNumbered(),
		BuildFirewallCmdListAll(), BuildFirewallCmdState(),
		BuildNFTListRuleset())
	cmds = append(cmds, BuildFirewallCmdAddSource(RuleKey{Action: ActionAllow}, "1.2.3.4", ""))
	cmds = append(cmds, BuildFirewallCmdRemoveSource(RuleKey{Action: ActionDeny}, "1.2.3.4", ""))
	add(BuildNFTDeletePort("filter", "input", 3))
	add(BuildIPTablesListRules("INPUT"))
	add(BuildIPTablesDeleteSpec("INPUT", []string{"-A", "INPUT", "-p", "tcp", "-j", "ACCEPT"}, ""))

	if len(cmds) < 20 {
		t.Fatalf("收集到的命令过少（%d），测试本身可能失效", len(cmds))
	}

	shells := map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true}
	for _, c := range cmds {
		if shells[strings.ToLower(c.Name)] {
			t.Fatalf("命令不能是 shell: %s", c.String())
		}
		for _, a := range c.Args {
			switch a {
			case "-c", "eval", "exec":
				t.Fatalf("命令中出现 shell 执行特征参数 %q: %s", a, c.String())
			}
		}
	}
}

// ============================================================================
// iptables
// ============================================================================

func TestBuildIPTablesAddPortSimple(t *testing.T) {
	cmd, err := BuildIPTablesAddPort(RuleKey{
		Port: mustPort(t, "8080"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	if cmd.Name != "iptables" {
		t.Fatalf("命令名应为 iptables，实际 %q", cmd.Name)
	}
	eqArgs(t, cmd.Args, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-j", "ACCEPT")
}

// TestBuildIPTablesRangeUsesMultiport 锁死"范围必须用 multiport + 冒号"。
//
// iptables 对 "8080-8090" 的解释是**两个独立端口**（8080 和 8090），
// 不是范围。用户填 8080-8090 期望放行整个区间，
// 若我们直接写 --dport 8080-8090，实际只放行两个端口——
// 这是静默的规则不符，中间 8081~8089 全部被拒。
// 因此范围必须走 -m multiport --dports 8080:8090（分隔符是冒号）。
func TestBuildIPTablesRangeUsesMultiport(t *testing.T) {
	cmd, err := BuildIPTablesAddPort(RuleKey{
		Port: mustPort(t, "8080-8090"), Protocol: ProtoTCP, Action: ActionAllow,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "-A", "INPUT", "-p", "tcp",
		"-m", "multiport", "--dports", "8080:8090", "-j", "ACCEPT")
	// 关键：绝不能出现 --dport（那是单端口语义）。
	for _, a := range cmd.Args {
		if a == "--dport" {
			t.Fatalf("范围规则绝不能使用 --dport，实际: %#v", cmd.Args)
		}
	}
}

func TestBuildIPTablesAddPortWithSource(t *testing.T) {
	cmd, err := BuildIPTablesAddPort(RuleKey{
		Port: mustPort(t, "22"), Protocol: ProtoTCP,
		Source: "192.168.1.0/24", Action: ActionAllow,
	}, "ssh")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "-A", "INPUT", "-s", "192.168.1.0/24", "-p", "tcp",
		"-m", "tcp", "--dport", "22", "-j", "ACCEPT",
		"-m", "comment", "--comment", `"ssh"`)
}

func TestBuildIPTablesAddPortDenyUsesDROPLowercaseIssue(t *testing.T) {
	cmd, err := BuildIPTablesAddPort(RuleKey{
		Port: mustPort(t, "25"), Protocol: ProtoTCP, Action: ActionDeny,
	}, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	// iptables 的 target 必须大写（DROP/ACCEPT）——它区分大小写。
	if cmd.Args[len(cmd.Args)-1] != "DROP" {
		t.Fatalf("拒绝规则的 target 必须是大写 DROP，实际: %#v", cmd.Args)
	}
}

// TestBuildIPTablesDeleteSpec 校验删除规格的原样回传。
//
// 真实环境实测（unshare -n + iptables）：
//
//	$ iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
//	$ iptables -S INPUT
//	-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//	                          ^^^^^^^ 内核自己补的
//
// 因此删除必须用 -S 的实际规格，且必须去掉 "-A <链>" 前缀。
func TestBuildIPTablesDeleteSpec(t *testing.T) {
	spec := strings.Fields("-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT")
	cmd, err := BuildIPTablesDeleteSpec("INPUT", spec, "")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "-D", "INPUT", "-p", "tcp", "-m", "tcp",
		"--dport", "8080", "-j", "ACCEPT")
}

// TestBuildIPTablesDeleteSpecRejectsMalformed 校验畸形规格被拒。
func TestBuildIPTablesDeleteSpecRejectsMalformed(t *testing.T) {
	bad := [][]string{
		{},                                // 空
		{"-P", "INPUT", "DROP"},           // 默认策略不是规则
		{"-N", "MYCHAIN"},                 // 建链
		{"-A", "INPUT", "-p", "tcp\nls"},  // 含换行
		{"-A", "INPUT", "-p", "tcp\x00x"}, // 含空字节
		{"random text"},                   // 完全无关
	}
	for _, spec := range bad {
		if got, err := BuildIPTablesDeleteSpec("INPUT", spec, ""); err == nil {
			t.Fatalf("畸形规格 %#v 必须被拒绝，实际生成: %s", spec, got.String())
		}
	}
}

// TestBuildIPTablesDeleteSpecChainMismatch 锁死"链名不一致必须拒绝"。
//
// 若规格来自 FORWARD 链而调用方以为是 INPUT，按 INPUT 删除会失败
// （报 Bad rule）或者更糟——删错链里的同名规则。
// 因此链名不一致时直接拒绝，而不是"以规格里的为准"。
func TestBuildIPTablesDeleteSpecChainMismatch(t *testing.T) {
	spec := strings.Fields("-A FORWARD -p tcp --dport 8080 -j ACCEPT")
	_, err := BuildIPTablesDeleteSpec("INPUT", spec, "")
	if err == nil {
		t.Fatal("规格里的链名与期望不一致时必须拒绝")
	}
	if !strings.Contains(err.Error(), "FORWARD") || !strings.Contains(err.Error(), "INPUT") {
		t.Fatalf("错误信息应同时指出两个链名，实际: %v", err)
	}
}

// TestBuildIPTablesListRulesUsesS 锁死用 -S 而不是 -L。
//
// -S 的输出可以直接回传给 -D；-L 的表格输出要把 80 显示成 "http"，
// 解析它需要反查服务名，不可靠。
func TestBuildIPTablesListRulesUsesS(t *testing.T) {
	cmd, err := BuildIPTablesListRules("INPUT")
	if err != nil {
		t.Fatalf("意外失败: %v", err)
	}
	eqArgs(t, cmd.Args, "-S", "INPUT")
}

// ============================================================================
// 其它
// ============================================================================

func TestBuildNFTListRulesetHasHandleFlag(t *testing.T) {
	cmd := BuildNFTListRuleset()
	// -a 必须有：不带它输出里没有 handle，所有删除都无法进行。
	found := false
	for _, a := range cmd.Args {
		if a == "-a" || a == "--handle" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nft 列规则必须带 -a/--handle，否则拿不到 handle 无法删除: %#v", cmd.Args)
	}
}

func TestBuildBackendAvailableCheck(t *testing.T) {
	for _, b := range []string{BackendUFW, BackendFirewalld, BackendNFTables, BackendIPTables} {
		cmd, err := BuildBackendAvailableCheck(b)
		if err != nil {
			t.Fatalf("后端 %s 的探测命令组装失败: %v", b, err)
		}
		if cmd.Name == "" {
			t.Fatalf("后端 %s 的探测命令名为空", b)
		}
		// 探测命令绝不能有写操作。
		joined := strings.Join(cmd.Args, " ")
		for _, forbidden := range []string{"add", "delete", "remove", "flush", "enable", "disable"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("后端 %s 的探测命令含写操作 %q: %s", b, forbidden, cmd.String())
			}
		}
	}
	if _, err := BuildBackendAvailableCheck("unknown"); err == nil {
		t.Fatal("未知后端应返回错误")
	}
}

// TestCommandStringQuotes 校验 Command.String 的可读性（仅用于日志）。
func TestCommandStringQuotes(t *testing.T) {
	c := Command{Name: "ufw", Args: []string{"allow", "proto", "tcp", "comment", "web 服务"}}
	got := c.String()
	if !strings.Contains(got, `"web 服务"`) {
		t.Fatalf("含空格的参数应被引号包裹，实际: %s", got)
	}
	if !strings.HasPrefix(got, "ufw allow proto tcp ") {
		t.Fatalf("无空格的参数不应加引号，实际: %s", got)
	}
	// 空参数必须显示出来，否则日志里看不出参数个数。
	c2 := Command{Name: "x", Args: []string{"a", "", "b"}}
	if !strings.Contains(c2.String(), `""`) {
		t.Fatalf("空参数应显示为引号对，实际: %s", c2.String())
	}
}
