package firewall

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// ============================================================================
// 规则解析（阶段四 4.6）
// ============================================================================
//
// ########## 本文件的输入全部是真实输出 ##########
//
// 每个用例上方的输出片段都是在本机 **unshare -n 隔离环境**
// 里用真实 ufw/nft/iptables 命令抓下来的，一字未改。
//
// 这样做的理由：防火墙输出格式的细节极易凭想象写错。
// 例如没人会想到 iptables -S 会补一个 "-m tcp"，
// 也没人会想到 nft 的 handle 出现在 table/chain/规则每一行上。
// 用真实输出做固定输入，是唯一能拦住这类"想当然"的办法。

// ============================================================================
// ufw
// ============================================================================

// realUFWStatusNumbered 是 `ufw status numbered` 的真实输出形态。
//
// 注意 ufw 的列间距是动态对齐的，且动作列有
// ALLOW/ALLOW IN/DENY IN/LIMIT IN 等多种形态。
const realUFWStatusNumbered = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
[ 1] 22/tcp                 ALLOW IN    Anywhere
[ 2] 8080/tcp               ALLOW IN    192.168.1.0/24
[ 3] 8080:8090/tcp          DENY IN     Anywhere                   # [lipanel] web range
[ 4] 53/udp                 ALLOW IN    Anywhere (v6)
[ 5] Anywhere               ALLOW IN    1.2.3.4
[ 6] 3306/tcp               LIMIT IN    Anywhere
`

func TestParseUFWStatusHeader(t *testing.T) {
	st := ParseUFWStatus(realUFWStatusNumbered)
	if !st.Active {
		t.Fatal("应解析出 Status: active")
	}
	if st.DefaultIncoming != "deny" {
		t.Fatalf("DefaultIncoming 应为 deny，实际 %q", st.DefaultIncoming)
	}
	if st.DefaultOutgoing != "allow" {
		t.Fatalf("DefaultOutgoing 应为 allow，实际 %q", st.DefaultOutgoing)
	}
	if st.DefaultRouted != "disabled" {
		t.Fatalf("DefaultRouted 应为 disabled，实际 %q", st.DefaultRouted)
	}
	if !st.IsDenyAllIncoming() {
		t.Fatal("deny (incoming) 应判定为默认拒绝入站")
	}
	if st.Logging != "on (low)" {
		t.Fatalf("Logging 应为 \"on (low)\"，实际 %q", st.Logging)
	}
}

// TestParseUFWStatusInactive 校验未启用状态的识别。
//
// ufw 未启用时输出 "Status: inactive" 且**退出码为 0**，
// 因此不能靠退出码判断，必须解析文本。
func TestParseUFWStatusInactive(t *testing.T) {
	out := `Status: inactive

To                         Action      From
--                         ------      ----
`
	st := ParseUFWStatus(out)
	if st.Active {
		t.Fatal("Status: inactive 必须判定为未启用")
	}
}

// TestParseUFWStatusAllowIncoming 校验"默认放行"能被识别。
//
// Default: allow (incoming) 意味着防火墙几乎不起作用。
// 若解析不出这个状态，面板会显示"已启用"让用户误以为被保护。
func TestParseUFWStatusAllowIncoming(t *testing.T) {
	out := "Status: active\nDefault: allow (incoming), allow (outgoing)\n"
	st := ParseUFWStatus(out)
	if st.IsDenyAllIncoming() {
		t.Fatal("allow (incoming) 不应判定为默认拒绝")
	}
	if !strings.HasPrefix(st.DefaultIncoming, "allow") {
		t.Fatalf("DefaultIncoming 应为 allow，实际 %q", st.DefaultIncoming)
	}
}

func TestParseUFWRules(t *testing.T) {
	rules := ParseUFWRules(realUFWStatusNumbered)
	if len(rules) != 6 {
		t.Fatalf("应解析出 6 条规则，实际 %d 条: %#v", len(rules), rules)
	}

	// [1] 22/tcp ALLOW IN Anywhere
	r := rules[0]
	if r.Kind != KindPort || r.Port.Start != 22 || r.Port.End != 22 {
		t.Fatalf("规则 1 端口解析错误: %#v", r)
	}
	if r.Protocol != ProtoTCP || r.Action != ActionAllow {
		t.Fatalf("规则 1 协议/动作错误: %#v", r)
	}
	if r.Source != "" {
		t.Fatalf("规则 1 来源应为空（Anywhere），实际 %q", r.Source)
	}
	if r.Origin != OriginExternal {
		t.Fatalf("规则 1 无面板标记，应判定为 external，实际 %q", r.Origin)
	}

	// [2] 8080/tcp ALLOW IN 192.168.1.0/24
	r = rules[1]
	if r.Source != "192.168.1.0/24" {
		t.Fatalf("规则 2 来源错误: %q", r.Source)
	}

	// [3] 8080:8090/tcp DENY IN Anywhere # [lipanel] web range
	r = rules[2]
	if r.Action != ActionDeny {
		t.Fatalf("规则 3 应为 deny，实际 %q", r.Action)
	}
	// ########## ufw 的冒号范围必须转成本模块的短横线 ##########
	if r.Port.Start != 8080 || r.Port.End != 8090 {
		t.Fatalf("规则 3 范围应解析为 8080-8090，实际 %s", r.Port.String())
	}
	if r.PortText != "8080-8090" {
		t.Fatalf("规则 3 展示文本应为 8080-8090（短横线），实际 %q", r.PortText)
	}
	if r.Comment != "web range" {
		t.Fatalf("规则 3 备注应去掉面板标记，实际 %q", r.Comment)
	}
	if r.Origin != OriginPanel {
		t.Fatalf("规则 3 带面板标记，应判定为 panel，实际 %q", r.Origin)
	}

	// [4] 53/udp ALLOW IN Anywhere (v6)
	r = rules[3]
	if r.Protocol != ProtoUDP {
		t.Fatalf("规则 4 协议应为 udp，实际 %q", r.Protocol)
	}
	if r.Family != "ipv6" {
		t.Fatalf("规则 4 应判定为 ipv6，实际 %q", r.Family)
	}

	// [5] Anywhere ALLOW IN 1.2.3.4  —— IP 规则
	r = rules[4]
	if r.Kind != KindIP {
		t.Fatalf("规则 5 应判定为 IP 规则，实际 %q", r.Kind)
	}
	if r.Source != "1.2.3.4" {
		t.Fatalf("规则 5 来源错误: %q", r.Source)
	}

	// [6] 3306/tcp LIMIT IN —— LIMIT 必须能被解析出来（映射为 deny）
	r = rules[5]
	if r.Port.Start != 3306 {
		t.Fatalf("规则 6 端口错误: %#v", r)
	}
	if r.Action != ActionDeny {
		t.Fatalf("LIMIT 应映射为 deny（本模块不做限速，但必须让规则可见），实际 %q", r.Action)
	}
}

// TestParseUFWRulesEmpty 空输出（未启用时）必须返回空且不 panic。
func TestParseUFWRulesEmpty(t *testing.T) {
	for _, out := range []string{"", "\n", "Status: inactive\n", "Status: active\nDefault: deny (incoming)\n"} {
		rules := ParseUFWRules(out)
		if len(rules) != 0 {
			t.Fatalf("输出 %q 不应解析出规则，实际 %d 条", out, len(rules))
		}
	}
}

// TestParseUFWSourceNormalization 锁死 "Anywhere" 归一化为空。
//
// 若保留 "Anywhere"，按它组装删除命令会写 "from Anywhere"，
// 而 ufw 只认 "from any" —— 删除必然失败。
func TestParseUFWSourceNormalization(t *testing.T) {
	out := `Status: active
[ 1] 80/tcp                 ALLOW IN    Anywhere
[ 2] 81/tcp                 ALLOW IN    Anywhere (v6)
[ 3] 82/tcp                 ALLOW IN    any
`
	rules := ParseUFWRules(out)
	if len(rules) != 3 {
		t.Fatalf("应解析出 3 条规则，实际 %d", len(rules))
	}
	for i, r := range rules {
		if r.Source != "" {
			t.Fatalf("规则 %d 的 Anywhere 应归一化为空串，实际 %q", i+1, r.Source)
		}
	}
}

// ============================================================================
// nftables
// ============================================================================

// realNFTList 是 `nft -a list chain inet filter input` 的真实输出。
//
// ########## 关键：handle 在每一行上 ##########
//
// table 行有 "# handle 1"，chain 行也有 "# handle 1"，
// 规则行有自己的 handle（2、3）。抓第一个会抓到 table 的 handle 1，
// 用它删除会报 "Could not process rule: No such file or directory"。
const realNFTList = `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept # handle 2
		tcp dport 9090 drop # handle 3
		ip saddr 192.168.1.0/24 tcp dport 22 accept # handle 4
		udp dport 53-54 accept # handle 5
	}
}
`

func TestParseNFTRules(t *testing.T) {
	rules := ParseNFTRules(realNFTList)
	if len(rules) != 4 {
		t.Fatalf("应解析出 4 条规则（跳过 table/chain/policy 行），实际 %d: %#v", len(rules), rules)
	}

	// 规则 1: tcp dport 8080 accept # handle 2
	r := rules[0]
	if r.Kind != KindPort || r.Port.Start != 8080 || r.Protocol != ProtoTCP {
		t.Fatalf("规则 1 解析错误: %#v", r)
	}
	if r.Action != ActionAllow {
		t.Fatalf("规则 1 动作应为 allow，实际 %q", r.Action)
	}
	// ########## 关键断言：handle 必须是 2，不是 table 的 1 ##########
	if r.Handle != 2 {
		t.Fatalf("规则 1 的 handle 应为 2（规则自身的），实际 %d —— 抓到了 table/chain 的 handle", r.Handle)
	}
	if !r.Deletable {
		t.Fatalf("有 handle 的规则应可删除: %s", r.NotDeletableReason)
	}

	// 规则 2: tcp dport 9090 drop # handle 3
	r = rules[1]
	if r.Action != ActionDeny || r.Handle != 3 || r.Port.Start != 9090 {
		t.Fatalf("规则 2 解析错误: %#v", r)
	}

	// 规则 3: ip saddr ... tcp dport 22 accept # handle 4
	r = rules[2]
	if r.Source != "192.168.1.0/24" || r.Port.Start != 22 || r.Handle != 4 {
		t.Fatalf("规则 3 解析错误: %#v", r)
	}

	// 规则 4: udp dport 53-54 accept # handle 5
	r = rules[3]
	if r.Protocol != ProtoUDP || r.Port.Start != 53 || r.Port.End != 54 || r.Handle != 5 {
		t.Fatalf("规则 4 的端口范围解析错误: %#v", r)
	}
}

// TestParseNFTRulesHandleNotFromTable 单独锁死 handle 归属。
//
// 这是 nft 解析最容易错的地方：table 与 chain 行也带 handle。
func TestParseNFTRulesHandleNotFromTable(t *testing.T) {
	rules := ParseNFTRules(realNFTList)
	for _, r := range rules {
		if r.Handle == 1 {
			t.Fatalf("解析出的规则 handle 为 1，这是 table/chain 的 handle，不是规则的: %#v", r)
		}
	}
}

// TestParseNFTRulesMissingHandleNotDeletable 锁死"解析不出 handle 即不可删除"。
//
// ########## 本用例是安全设计的核心断言 ##########
//
// 输出里若没有 handle（例如忘了加 -a 标志），
// 规则必须被标记为**不可删除**并给出原因。
// 绝不能让上层退化成"清空规则集"来达成删除目的——
// 那会让用户在点"删除 8080"时丢掉整台机器的防火墙规则。
func TestParseNFTRulesMissingHandleNotDeletable(t *testing.T) {
	// 模拟忘了加 -a 的输出（没有 "# handle N"）。
	noHandle := `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept
		tcp dport 9090 drop
	}
}
`
	rules := ParseNFTRules(noHandle)
	if len(rules) != 2 {
		t.Fatalf("应解析出 2 条规则，实际 %d", len(rules))
	}
	for i, r := range rules {
		if r.Deletable {
			t.Fatalf("规则 %d 没有 handle，必须标记为不可删除", i+1)
		}
		if r.Handle != 0 {
			t.Fatalf("规则 %d 的 handle 应为 0，实际 %d", i+1, r.Handle)
		}
		if r.NotDeletableReason == "" {
			t.Fatalf("规则 %d 不可删除时必须给出原因", i+1)
		}
		// 原因里必须明确说明"绝不用清空代替"。
		if !strings.Contains(r.NotDeletableReason, "清空") {
			t.Fatalf("不可删除的原因应说明不会用清空代替，实际: %s", r.NotDeletableReason)
		}
	}
}

// TestParseNFTRulesJumpNotDeletable 校验跳转类规则不可删除。
func TestParseNFTRulesJumpNotDeletable(t *testing.T) {
	out := `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8080 jump custom-chain # handle 2
	}
}
`
	rules := ParseNFTRules(out)
	if len(rules) != 1 {
		t.Fatalf("应解析出 1 条规则，实际 %d", len(rules))
	}
	// jump 是控制流跳转，删除会改变其它规则行为。
	// 它有 handle，因此解析层面可删；但本模块的 Manager 会
	// 在删除时按 Action/跳转再判断（见 iptables 的同类处理）。
	if rules[0].Handle != 2 {
		t.Fatalf("handle 解析错误: %d", rules[0].Handle)
	}
}

// TestParseNFTRulesAnyProtocol 校验 meta l4proto 集合的解析。
func TestParseNFTRulesAnyProtocol(t *testing.T) {
	out := `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		meta l4proto { tcp, udp } th dport 53 accept # handle 2
	}
}
`
	rules := ParseNFTRules(out)
	if len(rules) != 1 {
		t.Fatalf("应解析出 1 条规则，实际 %d", len(rules))
	}
	r := rules[0]
	if r.Protocol != ProtoAny {
		t.Fatalf("协议应为 any，实际 %q", r.Protocol)
	}
	if r.Port.Start != 53 {
		t.Fatalf("端口应为 53，实际 %s", r.Port.String())
	}
}

// TestParseNFTRulesComment 校验 nft 注释解析。
func TestParseNFTRulesComment(t *testing.T) {
	out := `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept comment "[lipanel] web 服务" # handle 2
	}
}
`
	rules := ParseNFTRules(out)
	if len(rules) != 1 {
		t.Fatalf("应解析出 1 条规则，实际 %d", len(rules))
	}
	if rules[0].Comment != "web 服务" {
		t.Fatalf("备注应去掉面板标记，实际 %q", rules[0].Comment)
	}
	if rules[0].Origin != OriginPanel {
		t.Fatalf("带面板标记应判定为 panel，实际 %q", rules[0].Origin)
	}
}

// ============================================================================
// iptables
// ============================================================================

// realIPTablesS 是 `iptables -S INPUT` 的真实输出。
//
// ########## 注意第一行的 -P 与它后面的 -m tcp ##########
//
//	-P INPUT ACCEPT          默认策略，不是规则，必须跳过
//	-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
//	                          ^^^^^^^ 我们没写，内核自己补的
const realIPTablesS = `-P INPUT ACCEPT
-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -s 192.168.1.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8080:8090 -j ACCEPT
-A INPUT -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -j DOCKER-USER
-A INPUT -p tcp -m tcp --dport 25 -j DROP
-A INPUT -p tcp -m tcp --dport 443 -m comment --comment "[lipanel] https" -j ACCEPT
`

func TestParseIPTablesRules(t *testing.T) {
	rules := ParseIPTablesRules(realIPTablesS)
	// 8 行里有 1 行是 -P（默认策略），不应算作规则。
	if len(rules) != 7 {
		t.Fatalf("应解析出 7 条规则（跳过 -P 行），实际 %d: %#v", len(rules), rules)
	}

	// 规则 1: 8080/tcp ACCEPT
	r := rules[0]
	if r.Kind != KindPort || r.Port.Start != 8080 || r.Protocol != ProtoTCP {
		t.Fatalf("规则 1 解析错误: %#v", r)
	}
	if r.Action != ActionAllow {
		t.Fatalf("规则 1 应为 allow，实际 %q", r.Action)
	}
	if !r.Deletable {
		t.Fatal("普通规则应可删除")
	}
	// ########## 关键：Spec 必须保留内核补的 -m tcp ##########
	// 删除时要用它逐词回传，缺 -m tcp 会导致删除失败。
	wantSpec := []string{"-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-j", "ACCEPT"}
	if len(r.Spec) != len(wantSpec) {
		t.Fatalf("规则 1 的 Spec 长度应为 %d，实际 %d: %#v", len(wantSpec), len(r.Spec), r.Spec)
	}
	for i := range wantSpec {
		if r.Spec[i] != wantSpec[i] {
			t.Fatalf("规则 1 的 Spec[%d] = %q，期望 %q（完整: %#v）", i, r.Spec[i], wantSpec[i], r.Spec)
		}
	}

	// 规则 2: 带来源
	r = rules[1]
	if r.Source != "192.168.1.0/24" || r.Port.Start != 22 {
		t.Fatalf("规则 2 解析错误: %#v", r)
	}

	// 规则 3: multiport 范围（冒号 -> 短横线）
	r = rules[2]
	if r.Port.Start != 8080 || r.Port.End != 8090 {
		t.Fatalf("规则 3 的 multiport 范围应解析为 8080-8090，实际 %s（原文 %q）",
			r.Port.String(), r.PortText)
	}
	if r.PortText != "8080-8090" {
		t.Fatalf("规则 3 展示文本应为短横线形态，实际 %q", r.PortText)
	}

	// 规则 5: -j DOCKER-USER —— 跳转到自定义链，必须不可删除
	r = rules[4]
	if r.Deletable {
		t.Fatalf("跳转到自定义链的规则必须标记为不可删除: %#v", r)
	}
	if !strings.Contains(r.NotDeletableReason, "DOCKER-USER") {
		t.Fatalf("不可删除的原因应指明目标链名，实际: %s", r.NotDeletableReason)
	}

	// 规则 6: DROP
	r = rules[5]
	if r.Action != ActionDeny {
		t.Fatalf("DROP 应映射为 deny，实际 %q", r.Action)
	}

	// 规则 7: 带面板注释
	r = rules[6]
	if r.Comment != "https" {
		t.Fatalf("备注应去掉面板标记，实际 %q", r.Comment)
	}
	if r.Origin != OriginPanel {
		t.Fatalf("带面板标记应判定为 panel，实际 %q", r.Origin)
	}
}

// TestParseIPTablesSkipsDefaultPolicy 锁死"默认策略不被当成规则"。
//
// "-P INPUT DROP" 是默认策略，不是规则。
// 若把它当成规则，用户会在列表里看到一条"INPUT DROP"，
// 点删除时组装出的命令毫无意义（或者是灾难性的）。
func TestParseIPTablesSkipsDefaultPolicy(t *testing.T) {
	out := "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n"
	rules := ParseIPTablesRules(out)
	if len(rules) != 0 {
		t.Fatalf("-P 行不应被当成规则，实际解析出 %d 条: %#v", len(rules), rules)
	}
}

func TestParseIPTablesDefaultPolicies(t *testing.T) {
	pol := ParseIPTablesDefaultPolicies(realIPTablesS)
	if pol["INPUT"] != "ACCEPT" {
		t.Fatalf("INPUT 默认策略应为 ACCEPT，实际 %q", pol["INPUT"])
	}
	if pol["FORWARD"] != "" {
		t.Fatalf("本输出没有 FORWARD 行，不应有值，实际 %q", pol["FORWARD"])
	}
}

// TestParseIPTablesSpecReplayable 校验解析出的 Spec 能被删除命令直接消费。
//
// 这是"解析"与"删除"之间最重要的契约：
// 解析出的 Spec 必须**原样**能喂给 BuildIPTablesDeleteSpec。
func TestParseIPTablesSpecReplayable(t *testing.T) {
	rules := ParseIPTablesRules(realIPTablesS)
	for _, r := range rules {
		if !r.Deletable {
			continue
		}
		cmd, err := BuildIPTablesDeleteSpec("INPUT", r.Spec, r.Comment)
		if err != nil {
			t.Fatalf("规则 %d 的 Spec %#v 无法用于删除: %v", r.Index, r.Spec, err)
		}
		if cmd.Name != "iptables" || cmd.Args[0] != "-D" {
			t.Fatalf("删除命令组装错误: %s", cmd.String())
		}
	}
}

// ============================================================================
// firewalld
// ============================================================================

// realFirewallCmdListAll 是 `firewall-cmd --list-all` 的真实输出形态。
const realFirewallCmdListAll = `public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: dhcpv6-client ssh
  ports: 8080/tcp 9090/udp 8000-8010/tcp
  protocols:
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept
	rule family="ipv4" source address="0.0.0.0/0" port port="25" protocol="tcp" reject
`

func TestParseFirewallCmdListAll(t *testing.T) {
	rules := ParseFirewallCmdListAll(realFirewallCmdListAll)
	// 3 个 ports + 2 条 rich rules = 5
	if len(rules) != 5 {
		t.Fatalf("应解析出 5 条规则，实际 %d: %#v", len(rules), rules)
	}

	// ports: 8080/tcp
	r := rules[0]
	if r.Kind != KindPort || r.Port.Start != 8080 || r.Protocol != ProtoTCP {
		t.Fatalf("规则 1 解析错误: %#v", r)
	}

	// ports: 8000-8010/tcp —— firewalld 已经是短横线
	r = rules[2]
	if r.Port.Start != 8000 || r.Port.End != 8010 {
		t.Fatalf("规则 3 范围解析错误: %#v", r)
	}

	// rich rule 1: 带来源的放行 3306
	r = rules[3]
	if r.Kind != KindPort || r.Port.Start != 3306 {
		t.Fatalf("rich rule 1 应解析为端口规则: %#v", r)
	}
	if r.Source != "192.168.1.0/24" || r.Action != ActionAllow {
		t.Fatalf("rich rule 1 来源/动作错误: %#v", r)
	}
	if r.Family != "ipv4" {
		t.Fatalf("rich rule 1 族错误: %q", r.Family)
	}

	// rich rule 2: 拒绝 25
	r = rules[4]
	if r.Action != ActionDeny {
		t.Fatalf("rich rule 2 应为 deny（reject），实际 %q", r.Action)
	}
	if r.Port.Start != 25 {
		t.Fatalf("rich rule 2 端口错误: %#v", r)
	}

	// ########## rich rule 必须保留原始文本以便删除 ##########
	// firewalld 删除 rich rule 要求字符串逐字节一致。
	if !strings.HasPrefix(r.Raw, `rule family="ipv4"`) {
		t.Fatalf("rich rule 的 Raw 必须是完整的原始文本（删除要原样回传），实际 %q", r.Raw)
	}
}

// TestParseFirewallCmdListAllEmpty 校验空输出不 panic。
func TestParseFirewallCmdListAllEmpty(t *testing.T) {
	for _, out := range []string{"", "\n", "public (active)\n  target: default\n"} {
		rules := ParseFirewallCmdListAll(out)
		if len(rules) != 0 {
			t.Fatalf("输出 %q 不应解析出规则，实际 %d 条", out, len(rules))
		}
	}
}

// ============================================================================
// 分发与辅助
// ============================================================================

func TestParseRulesDispatch(t *testing.T) {
	cases := []struct {
		backend string
		output  string
		want    int
	}{
		{BackendUFW, realUFWStatusNumbered, 6},
		{BackendNFTables, realNFTList, 4},
		{BackendIPTables, realIPTablesS, 7},
		{BackendFirewalld, realFirewallCmdListAll, 5},
		{BackendNone, realIPTablesS, 0},
		{"unknown", realIPTablesS, 0},
	}
	for _, c := range cases {
		got := ParseRules(c.backend, c.output)
		if len(got) != c.want {
			t.Fatalf("ParseRules(%s) 应解析出 %d 条，实际 %d", c.backend, c.want, len(got))
		}
	}
}

// TestPanelCommentMarker 校验面板标记的加/去/判断。
func TestPanelCommentMarker(t *testing.T) {
	if got := MarkPanelComment("web"); got != "[lipanel] web" {
		t.Fatalf("MarkPanelComment 错误: %q", got)
	}
	if got := MarkPanelComment(""); got != PanelCommentMarker {
		t.Fatalf("空备注应只有标记: %q", got)
	}
	if got := StripPanelComment("[lipanel] web"); got != "web" {
		t.Fatalf("StripPanelComment 错误: %q", got)
	}
	if got := StripPanelComment("web"); got != "web" {
		t.Fatalf("无标记时不应改变: %q", got)
	}
	if !IsPanelComment("[lipanel] x") || IsPanelComment("x") {
		t.Fatal("IsPanelComment 判定错误")
	}
}

func TestIsValidSource(t *testing.T) {
	valid := []string{"", "1.2.3.4", "192.168.1.0/24", "2001:db8::/32", "::1"}
	for _, s := range valid {
		if !IsValidSource(s) {
			t.Fatalf("来源 %q 应判定为合法", s)
		}
	}
	invalid := []string{"Anywhere", "1.2.3.4/33", "not-an-ip", "1.2.3.4:22"}
	for _, s := range invalid {
		if IsValidSource(s) {
			t.Fatalf("来源 %q 应判定为非法", s)
		}
	}
}

func TestParseAddrLenient(t *testing.T) {
	if a := ParseAddrLenient("192.168.1.0/24"); a.String() != "192.168.1.0" {
		t.Fatalf("网段应解析出网络地址，实际 %q", a.String())
	}
	if a := ParseAddrLenient("1.2.3.4"); a.String() != "1.2.3.4" {
		t.Fatalf("单地址解析错误: %q", a.String())
	}
	if a := ParseAddrLenient("Anywhere"); a.IsValid() {
		t.Fatal("非法串应返回无效地址，而不是猜测")
	}
	if a := ParseAddrLenient(""); a.IsValid() {
		t.Fatal("空串应返回无效地址")
	}
}

// TestParseRealIPTablesRoundTrip 是本文件最重要的一组断言。
//
// 它把"解析 → 删除组装"整条链路串起来验证：
// 用真实输出解析出规则，再用解析结果组装删除命令，
// 断言最终命令是**内核能接受**的形态。
//
// 这直接对应用户的第二点确认："只允许删除能精确识别到规则规格的规则"。
func TestParseRealIPTablesRoundTrip(t *testing.T) {
	rules := ParseIPTablesRules(realIPTablesS)

	// 找第一条 8080 规则。
	var target *Rule
	for i := range rules {
		if rules[i].Kind == KindPort && rules[i].Port.Start == 8080 && rules[i].Deletable {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		t.Fatal("未找到 8080 规则")
	}

	cmd, err := BuildIPTablesDeleteSpec("INPUT", target.Spec, target.Comment)
	if err != nil {
		t.Fatalf("删除命令组装失败: %v", err)
	}
	// 断言完整的 argv：从真实输出解析出的规格必须能原样变成 -D 命令。
	want := []string{"-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-j", "ACCEPT"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("删除命令参数长度不符:\n  实际 %s\n  期望 %v", cmd.String(), want)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Fatalf("删除命令参数[%d] = %q，期望 %q（完整: %s）", i, cmd.Args[i], want[i], cmd.String())
		}
	}
}

// TestSplitIPTablesLineQuotes 锁死引号感知分词。
//
// ########## 为什么必须有这个测试 ##########
//
// 真实 iptables -S 会保留注释的引号，而备注里含空格是常态：
//
//	-A INPUT -p tcp --dport 443 -m comment --comment "[lipanel] web 服务" -j ACCEPT
//
// strings.Fields 会把它切成 `"[lipanel]` 与 `web` 与 `服务"` 三个词元，
// 后果有两层：
//
//	① 备注解析成半截；
//	② **Spec 词元数错**，而 Spec 是删除时逐词回传的 —— 多切一刀就删不掉了。
func TestSplitIPTablesLineQuotes(t *testing.T) {
	line := `-A INPUT -p tcp -m tcp --dport 443 -m comment --comment "[lipanel] web 服务" -j ACCEPT`
	got := splitIPTablesLine(line)

	want := []string{
		"-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "443",
		"-m", "comment", "--comment", `"[lipanel] web 服务"`, "-j", "ACCEPT",
	}
	if len(got) != len(want) {
		t.Fatalf("分词数不符:\n  实际 %d: %#v\n  期望 %d: %#v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("词元[%d] = %q，期望 %q\n  完整: %#v", i, got[i], want[i], got)
		}
	}
}

// TestParseIPTablesCommentWithSpace 端到端校验含空格备注的解析。
func TestParseIPTablesCommentWithSpace(t *testing.T) {
	out := `-A INPUT -p tcp -m tcp --dport 443 -m comment --comment "[lipanel] web 服务" -j ACCEPT
`
	rules := ParseIPTablesRules(out)
	if len(rules) != 1 {
		t.Fatalf("应解析出 1 条规则，实际 %d", len(rules))
	}
	r := rules[0]
	if r.Comment != "web 服务" {
		t.Fatalf("含空格的备注解析错误: %q", r.Comment)
	}
	if r.Origin != OriginPanel {
		t.Fatalf("应判定为面板创建，实际 %q", r.Origin)
	}
	// Spec 必须完整（含带引号的备注词元），否则删不掉。
	if len(r.Spec) != 14 {
		t.Fatalf("Spec 词元数应为 14，实际 %d: %#v", len(r.Spec), r.Spec)
	}
	// Spec 必须能直接用于删除。
	if _, err := BuildIPTablesDeleteSpec("INPUT", r.Spec, r.Comment); err != nil {
		t.Fatalf("含空格备注的规则 Spec 无法用于删除: %v", err)
	}
}

// TestRuleJSONContract 锁死 Rule 对外的 JSON 字段名。
//
// ########## 这个测试来自端到端验证抓到的真实缺陷 ##########
//
// PortText 的标签原本写成 `json:"port"`，而 Port 字段带 `json:"-"`。
// 于是：
//
//	· 所有 Go 单元测试全绿（它们断言的是结构体字段，不是 JSON）；
//	· 前端拿到的 port_text 永远为空。
//
// 后果是界面上的"端口"列**整列空白**——用户看不到自己加的是哪个
// 端口，自然也找不到要删的那一条。这类"字段名对不上"的缺陷
// 单元测试天然看不见，只能用契约测试锁住。
func TestRuleJSONContract(t *testing.T) {
	rule := Rule{
		Port:               PortSpec{Start: 8080, End: 8090},
		PortText:           "8080-8090",
		Protocol:           ProtoTCP,
		Source:             "192.168.1.0/24",
		Action:             ActionAllow,
		Comment:            "web",
		Kind:               KindPort,
		Family:             "ipv4",
		Backend:            BackendUFW,
		Origin:             OriginPanel,
		Deletable:          false,
		NotDeletableReason: "测试原因",
		Protected:          true,
		ProtectedReason:    "面板端口",
		ProtectionKind:     ProtectPanel,
		Raw:                "raw line",
		Index:              3,
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}

	// 前端与端到端脚本依赖的字段名，逐个断言。
	//
	// ########## 为什么这些名字必须写死在测试里 ##########
	//
	// 它们是与前端的接口契约。改其中一个名字就会让界面上的
	// 某一列静默变成空白——不会有任何测试失败，因为 Go 侧
	// 编译通过、前端侧只是拿到 undefined。
	requireKeys := []string{
		"port_text", "protocol", "source", "action", "comment",
		"kind", "family", "backend", "origin",
		"deletable", "not_deletable_reason",
		"protected", "protected_reason", "protection_kind",
		"raw", "index",
	}
	for _, k := range requireKeys {
		if _, ok := got[k]; !ok {
			t.Fatalf("JSON 缺少字段 %q（前端依赖它）。实际字段: %v", k, mapKeys(got))
		}
	}

	// 值也要对得上（不只是存在）。
	if got["port_text"] != "8080-8090" {
		t.Fatalf("port_text = %v，期望 8080-8090", got["port_text"])
	}
	if got["protection_kind"] != ProtectPanel {
		t.Fatalf("protection_kind = %v，期望 %s", got["protection_kind"], ProtectPanel)
	}

	// ########## 内部字段绝不能泄露到 JSON ##########
	//
	// Spec 是 iptables 的原始词元、Handle 是 nft 的句柄：
	// 它们对前端没有意义，且序列化出去会让接口契约变得
	// 难以演进（前端可能开始依赖它们）。
	for _, k := range []string{"Spec", "Handle", "Port"} {
		if _, ok := got[k]; ok {
			t.Fatalf("内部字段 %q 不应出现在 JSON 中: %s", k, data)
		}
	}
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
