package firewall

import (
	"strings"
	"testing"
)

// ============================================================================
// 端口校验（阶段四 4.6）
// ============================================================================

// TestValidatePortInjectionPayloads 穷举注入载荷。
//
// 这是本模块最重要的一组用例：端口字段是用户输入进入命令的**第一条路径**，
// 任何一条载荷被接受，都意味着它会被拼进 ufw/nft/iptables 的参数里。
//
// 注意：本模块的命令组装全部用 argv 切片（绝不拼 shell），
// 因此这些载荷即便被接受也**不会**造成命令执行；
// 但"一个看起来像端口的字段接受了 `;reboot`"本身就是不可接受的，
// 它会污染审计、让规则语义不可预期，并为将来某次重构（比如有人
// 图省事改成拼字符串）埋下真实的可利用漏洞。
// 安全判定必须在输入边界完成，不能依赖下游的实现细节。
func TestValidatePortInjectionPayloads(t *testing.T) {
	payloads := []string{
		// shell 元字符
		"22;reboot", "22; reboot", "22&&reboot", "22||reboot", "22|reboot",
		"22`id`", "22$(id)", "22${IFS}id", "22>out", "22<in", "22&bg",
		// 引号与转义
		`22"`, `22'`, `22\`, "22\n",
		// 路径穿越与文件
		"../../etc/passwd", "22/../22", "/etc/passwd", "22/../../x",
		// 通配与选项注入
		"22*", "-22", "--22", "22-", "-", "--", "*",
		// 空白
		" 22", "22 ", "2 2", "22\t", "\t22", "22\n", "22\r\n",
		// 数字的变体（Atoi 会接受，因此必须由正则拦下）
		"+22", "0x16", "2_2", "0b10110", "0o26",
		// 全角 / 非 ASCII 数字
		"２２", "٢٢", "22２",
		// 空与超长
		"", " ", "0",
		// 越界
		"65536", "99999", "100000", "999999999999999999999",
		// 浮点与科学计数
		"22.0", "2e1", "22,0",
	}
	for _, p := range payloads {
		t.Run(p, func(t *testing.T) {
			got, err := ValidatePort(p)
			if err == nil {
				t.Fatalf("载荷 %q 被接受为端口 %d，必须拒绝", p, got)
			}
		})
	}
}

// TestValidatePortValid 校验合法端口被正确接受。
func TestValidatePortValid(t *testing.T) {
	cases := map[string]int{
		"1":     1,
		"22":    22,
		"80":    80,
		"443":   443,
		"8080":  8080,
		"65535": 65535,
	}
	for in, want := range cases {
		got, err := ValidatePort(in)
		if err != nil {
			t.Fatalf("ValidatePort(%q) 意外失败: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidatePort(%q) = %d, 期望 %d", in, got, want)
		}
	}
}

// TestValidatePortZero 边界：端口 0 必须拒绝。
//
// 0 在 iptables 里是合法语法（表示"任意端口"），
// 放行它会让"放行 0 端口"变成"放行全部端口"——静默的授权扩大。
func TestValidatePortZero(t *testing.T) {
	if _, err := ValidatePort("0"); err == nil {
		t.Fatal("端口 0 必须被拒绝（它在 iptables 里表示任意端口，会造成静默的授权扩大）")
	}
}

// TestValidatePortSpecRange 校验端口范围。
func TestValidatePortSpecRange(t *testing.T) {
	ok := []struct {
		in         string
		start, end int
	}{
		{"8080", 8080, 8080},
		{"8080-8090", 8080, 8090},
		{"1-65535", 1, 65535},
		{"22-22", 22, 22}, // 起止相同视为单端口范围
	}
	for _, c := range ok {
		got, err := ValidatePortSpec(c.in)
		if err != nil {
			t.Fatalf("ValidatePortSpec(%q) 意外失败: %v", c.in, err)
		}
		if got.Start != c.start || got.End != c.end {
			t.Fatalf("ValidatePortSpec(%q) = %d-%d, 期望 %d-%d",
				c.in, got.Start, got.End, c.start, c.end)
		}
	}
}

// TestValidatePortSpecReversedNotSwapped 锁死"范围写反不自动交换"。
//
// 自动交换看起来贴心，但它会让用户在界面上看到 8090-8080 被接受，
// 从而误以为自己填对了方向。这条纪律来自 4.3 的教训：
// **校验函数只回答"能不能用"，绝不悄悄改写用户输入。**
func TestValidatePortSpecReversedNotSwapped(t *testing.T) {
	_, err := ValidatePortSpec("8090-8080")
	if err == nil {
		t.Fatal("8090-8080 必须被拒绝，绝不自动交换")
	}
	// 错误信息里要给出正确写法，让用户知道该怎么办。
	if !strings.Contains(err.Error(), "8080-8090") {
		t.Fatalf("错误信息应提示正确写法 8080-8090，实际: %v", err)
	}
}

// TestValidatePortSpecVariants 范围的各种畸形写法。
func TestValidatePortSpecVariants(t *testing.T) {
	bad := []string{
		"8080-", "-8080", "8080--8090", "8080-8090-9000",
		"8080 - 8090", "8080 -8090", "8080- 8090",
		"08080-08090", // 前导零：由 ValidatePort 的正则拦下
		"0-100",       // 起点为 0
		"100-65536",   // 终点越界
		";-22",
		"22-;id",
		"A-B",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			if got, err := ValidatePortSpec(p); err == nil {
				t.Fatalf("畸形范围 %q 被接受为 %s", p, got.String())
			}
		})
	}
}

// ============================================================================
// 协议与动作
// ============================================================================

func TestValidateProtocol(t *testing.T) {
	ok := map[string]string{
		"":      ProtoTCP, // 空 => tcp（显式允许的默认）
		"tcp":   ProtoTCP,
		"TCP":   ProtoTCP,
		"udp":   ProtoUDP,
		"UDP":   ProtoUDP,
		"any":   ProtoAny,
		"Any":   ProtoAny,
		" tcp ": "",
	}
	// " tcp " 带空格必须拒绝（不接受带空白的输入，见 validate.go 的纪律）。
	for in, want := range ok {
		got, err := ValidateProtocol(in)
		if want == "" {
			if err == nil {
				t.Fatalf("ValidateProtocol(%q) 应被拒绝，实际返回 %q", in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ValidateProtocol(%q) 意外失败: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidateProtocol(%q) = %q, 期望 %q", in, got, want)
		}
	}

	bad := []string{"icmp", "icmpv6", "sctp", "tcp;udp", "tcp udp", "ALL", "ip", "gre", "esp"}
	for _, p := range bad {
		if got, err := ValidateProtocol(p); err == nil {
			t.Fatalf("协议 %q 必须被拒绝，实际返回 %q", p, got)
		}
	}
}

func TestValidateAction(t *testing.T) {
	ok := map[string]string{
		"":      ActionAllow,
		"allow": ActionAllow,
		"ALLOW": ActionAllow,
		"deny":  ActionDeny,
		"Deny":  ActionDeny,
	}
	for in, want := range ok {
		got, err := ValidateAction(in)
		if err != nil {
			t.Fatalf("ValidateAction(%q) 意外失败: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidateAction(%q) = %q, 期望 %q", in, got, want)
		}
	}
	// reject/drop 必须拒绝：它们语义上与 deny 相近但各后端映射不同
	// （ufw 的 reject 会回 ICMP，drop 不会），静默等价会让用户
	// 以为自己选了 reject 却得到 drop。
	for _, p := range []string{"reject", "drop", "ACCEPT", "DROP", "deny;allow", "allow deny"} {
		if got, err := ValidateAction(p); err == nil {
			t.Fatalf("动作 %q 必须被拒绝，实际返回 %q", p, got)
		}
	}
}

func TestValidateDirection(t *testing.T) {
	ok := map[string]string{
		"":      DirectionDeny, // 默认黑名单：填 IP 到黑名单区的意图
		"allow": DirectionAllow,
		"deny":  DirectionDeny,
		"ALLOW": DirectionAllow,
	}
	for in, want := range ok {
		got, err := ValidateDirection(in)
		if err != nil {
			t.Fatalf("ValidateDirection(%q) 意外失败: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidateDirection(%q) = %q, 期望 %q", in, got, want)
		}
	}
	for _, p := range []string{"blacklist", "whitelist", "block", "permit", "allow;deny"} {
		if got, err := ValidateDirection(p); err == nil {
			t.Fatalf("方向 %q 必须被拒绝，实际返回 %q", p, got)
		}
	}
}

// ============================================================================
// IP 校验
// ============================================================================

func TestValidateIPValidV4(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":         "1.2.3.4",
		"0.0.0.0":         "0.0.0.0",
		"255.255.255.255": "255.255.255.255",
		"192.168.1.1":     "192.168.1.1",
		"10.0.0.1":        "10.0.0.1",
	}
	for in, want := range cases {
		got, err := ValidateIP(in)
		if err != nil {
			t.Fatalf("ValidateIP(%q) 意外失败: %v", in, err)
		}
		if got.String() != want {
			t.Fatalf("ValidateIP(%q) = %q, 期望 %q", in, got.String(), want)
		}
		if !got.Is4() {
			t.Fatalf("ValidateIP(%q) 应判定为 IPv4", in)
		}
	}
}

func TestValidateIPValidV6(t *testing.T) {
	cases := map[string]bool{ // 值 => 是否应归一化为 v4
		"::1":         false,
		"2001:db8::1": false,
		"fe80::1":     false,
		"2001:0db8:0000:0000:0000:0000:0000:0001": false,
		// IPv4 映射地址按 v4 处理（normalizeAddr 的 Unmap）
		"::ffff:1.2.3.4": true,
	}
	for in, wantV4 := range cases {
		got, err := ValidateIP(in)
		if err != nil {
			t.Fatalf("ValidateIP(%q) 意外失败: %v", in, err)
		}
		if got.Is4() != wantV4 {
			t.Fatalf("ValidateIP(%q).Is4() = %v, 期望 %v", in, got.Is4(), wantV4)
		}
	}
}

// TestValidateIPRejected 穷举非法 IP 载荷。
func TestValidateIPRejected(t *testing.T) {
	bad := []string{
		// 空与空白
		"", " ", "  ",
		// 字段填错：地址+端口
		"1.2.3.4:22", "1.2.3.4:", "127.0.0.1:8080",
		// 网段误填到 IP 字段
		"192.168.1.0/24", "1.2.3.4/32", "::1/128",
		// 特殊字符串
		"any", "*", "all", "0/0", "::/0",
		// 前导零（netip 明确拒绝，避免八进制歧义）
		"010.1.1.1", "1.02.3.4", "1.2.3.004",
		// 越界与畸形
		"256.1.1.1", "1.2.3", "1.2.3.4.5", "1..2.3",
		":::", "::gggg", "2001:db8::1::2",
		// 注入载荷
		"1.2.3.4;id", "1.2.3.4$(id)", "1.2.3.4|reboot", "1.2.3.4`id`",
		"1.2.3.4\n", "1.2.3.4 ",
		// zone 后缀
		"fe80::1%eth0", "::1%lo",
		// 方括号
		"[::1]", "[1.2.3.4]",
		// 非数字
		"localhost", "example.com", "1.2.3.a",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			if got, err := ValidateIP(p); err == nil {
				t.Fatalf("非法 IP %q 被接受为 %q", p, got.String())
			}
		})
	}
}

// TestValidateIPHostPortMessage 锁死"IP:端口"的错误提示质量。
//
// 这是用户最常犯的字段填错。提示里同时给出主机部分与端口部分，
// 用户一眼就能看出自己把端口填进了 IP 字段。
func TestValidateIPHostPortMessage(t *testing.T) {
	_, err := ValidateIP("1.2.3.4:22")
	if err == nil {
		t.Fatal("1.2.3.4:22 必须被拒绝")
	}
	msg := err.Error()
	for _, want := range []string{"1.2.3.4", "22"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息应包含 %q，实际: %s", want, msg)
		}
	}
}

// TestValidateIPRuleCIDR 校验网段。
func TestValidateIPRuleCIDR(t *testing.T) {
	ok := []struct {
		in   string
		want string
		v4   bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"1.2.3.4/32", "1.2.3.4/32", true},
		{"0.0.0.0/0", "0.0.0.0/0", true},
		{"2001:db8::/32", "2001:db8::/32", false},
		{"::1/128", "::1/128", false},
		// 单地址走 Addr 分支
		{"1.2.3.4", "1.2.3.4", true},
		{"::1", "::1", false},
	}
	for _, c := range ok {
		got, err := ValidateIPRule(c.in)
		if err != nil {
			t.Fatalf("ValidateIPRule(%q) 意外失败: %v", c.in, err)
		}
		if got.String() != c.want {
			t.Fatalf("ValidateIPRule(%q) = %q, 期望 %q", c.in, got.String(), c.want)
		}
		if got.IsV4() != c.v4 {
			t.Fatalf("ValidateIPRule(%q).IsV4() = %v, 期望 %v", c.in, got.IsV4(), c.v4)
		}
	}
}

// TestValidateIPRuleHostBitsSet 锁死"主机位非零的网段必须拒绝"。
//
// "192.168.1.5/24" 在语义上是 192.168.1.0/24，但各后端处理不同：
// nft 直接拒绝（host bits set），iptables 静默按 /24 处理。
// 同一份输入在一个后端报错、在另一个后端生效，是最难排查的问题，
// 因此在输入边界就统一拒绝并给出规范写法。
func TestValidateIPRuleHostBitsSet(t *testing.T) {
	_, err := ValidateIPRule("192.168.1.5/24")
	if err == nil {
		t.Fatal("主机位非零的网段 192.168.1.5/24 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Fatalf("错误信息应给出规范写法，实际: %v", err)
	}

	// 各种主机位非零的形态
	for _, p := range []string{
		"10.1.2.3/8", "172.16.5.5/12", "2001:db8::1/32", "1.2.3.4/24",
	} {
		if got, err := ValidateIPRule(p); err == nil {
			t.Fatalf("主机位非零的网段 %q 必须被拒绝，实际 %q", p, got.String())
		}
	}
}

// TestValidateIPRuleRejected 非法网段载荷。
func TestValidateIPRuleRejected(t *testing.T) {
	bad := []string{
		"", " ",
		"192.168.1.0/33", "192.168.1.0/-1", "192.168.1.0/",
		"/24", "1.2.3.4/abc", "1.2.3.4/24/24",
		"::1/129",
		"1.2.3.4;id/24", "192.168.1.0/24;id",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			if got, err := ValidateIPRule(p); err == nil {
				t.Fatalf("非法网段 %q 被接受为 %q", p, got.String())
			}
		})
	}
}

// ============================================================================
// 备注
// ============================================================================

// TestValidateCommentNewlineRejected 锁死"备注不得含换行"。
//
// 这不是显示问题：备注在 ufw 后端会被写进 /etc/ufw/user.rules 的
// comment= 字段，而那个文件由 ufw 自己逐行解析。
// 一个换行就能在文件里插入一行任意内容，伪造出规则条目。
func TestValidateCommentNewlineRejected(t *testing.T) {
	for _, p := range []string{
		"正常备注\n### tuple ### allow tcp 1 2 3 4",
		"备注\r\n",
		"a\nb",
		"a\rb",
	} {
		if _, err := ValidateComment(p); err == nil {
			t.Fatalf("含换行的备注 %q 必须被拒绝", p)
		}
	}
}

func TestValidateCommentControlChars(t *testing.T) {
	for _, p := range []string{"a\x00b", "a\x1bb", "a\x7fb", "a\tb"} {
		if _, err := ValidateComment(p); err == nil {
			t.Fatalf("含控制字符的备注 %q 必须被拒绝", p)
		}
	}
}

func TestValidateCommentValid(t *testing.T) {
	ok := []string{
		"",
		"web 服务",
		"allow ssh for admin",
		"CI/CD 部署端口",
		"存在 空格 与 标点,;:!? 但不含换行",
		"emoji 🔒 也可以",
	}
	for _, c := range ok {
		got, err := ValidateComment(c)
		if err != nil {
			t.Fatalf("ValidateComment(%q) 意外失败: %v", c, err)
		}
		if got != c {
			t.Fatalf("ValidateComment(%q) = %q，不应改写输入", c, got)
		}
	}
}

// TestValidateCommentLength 校验长度上限按字符而非字节计算。
//
// 中文备注按字节算会在 42 个汉字时被误判超长（128/3），
// 用户看到"我明明只写了 42 个字"会非常困惑。
func TestValidateCommentLength(t *testing.T) {
	// 128 个汉字应当通过（按 rune 计数）。
	ok128 := strings.Repeat("中", MaxCommentLength)
	if _, err := ValidateComment(ok128); err != nil {
		t.Fatalf("%d 个汉字的备注应被接受（按字符计数）: %v", MaxCommentLength, err)
	}
	// 129 个必须拒绝。
	if _, err := ValidateComment(strings.Repeat("中", MaxCommentLength+1)); err == nil {
		t.Fatalf("超过 %d 个字符的备注必须被拒绝", MaxCommentLength)
	}
}

// ============================================================================
// RuleKey
// ============================================================================

func TestRuleKeyString(t *testing.T) {
	k := RuleKey{
		Port:     PortSpec{Start: 8080, End: 8090},
		Protocol: ProtoTCP,
		Source:   "192.168.1.0/24",
		Action:   ActionAllow,
	}
	got := k.String()
	for _, want := range []string{"8080-8090", "tcp", "192.168.1.0/24", "allow"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RuleKey.String() = %q，应包含 %q", got, want)
		}
	}
	// 空来源展示为 any，便于审计阅读。
	k.Source = ""
	if !strings.Contains(k.String(), "any") {
		t.Fatalf("空来源应展示为 any，实际: %s", k.String())
	}
}
