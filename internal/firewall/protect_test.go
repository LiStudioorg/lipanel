package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 端口保护（阶段四 4.6）
// ============================================================================

// writeFile 是测试辅助：在工作区临时目录写文件。
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	return path
}

// TestProtectorPanelPort 校验面板端口被保护。
func TestProtectorPanelPort(t *testing.T) {
	p := NewProtector(ProtectOptions{PanelPort: 8080})
	got := p.Evaluate(context.Background())

	if len(got.Ports) == 0 {
		t.Fatal("面板端口必须被保护")
	}
	found := false
	for _, pp := range got.Ports {
		if pp.Port == 8080 {
			found = true
			if pp.Kind != ProtectPanel {
				t.Fatalf("类别应为 panel，实际 %q", pp.Kind)
			}
			if !strings.Contains(pp.Reason, "面板") {
				t.Fatalf("保护原因应说明是面板端口，实际: %s", pp.Reason)
			}
			if pp.Source == "" {
				t.Fatal("必须给出探测来源")
			}
		}
	}
	if !found {
		t.Fatal("未在保护列表中找到面板端口 8080")
	}
}

// TestProtectorSSHFromConfig 校验从 sshd_config 读取 SSH 端口。
func TestProtectorSSHFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", `# 这是注释
Port 2222
#Port 9999
ListenAddress 0.0.0.0
PermitRootLogin no
`)
	p := NewProtector(ProtectOptions{
		PanelPort:      8080,
		SSHConfigPaths: []string{cfg},
	})
	got := p.Evaluate(context.Background())

	if !got.SSHDetected {
		t.Fatal("应从配置中探测到 SSH 端口")
	}
	var ports []int
	for _, pp := range got.Ports {
		if pp.Kind == ProtectSSH {
			ports = append(ports, pp.Port)
		}
	}
	if len(ports) != 1 || ports[0] != 2222 {
		t.Fatalf("应保护 SSH 端口 2222，实际 %v", ports)
	}
	// ########## 被注释掉的 9999 绝不能被保护 ##########
	for _, pp := range got.Ports {
		if pp.Port == 9999 {
			t.Fatal("被注释掉的 #Port 9999 绝不能被视为生效端口")
		}
	}
}

// TestProtectorSSHCommentedPortIgnored 单独锁死"注释掉的 Port 被忽略"。
//
// 若不忽略，面板会保护一个 sshd 实际不听的端口，
// 而真正的端口毫无保护——这是保护功能最危险的失效方式。
func TestProtectorSSHCommentedPortIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", `#Port 9999
Port 22
`)
	p := NewProtector(ProtectOptions{SSHConfigPaths: []string{cfg}})
	got := p.Evaluate(context.Background())

	for _, pp := range got.Ports {
		if pp.Port == 9999 {
			t.Fatal("#Port 9999 是注释，不能被保护")
		}
	}
	found := false
	for _, pp := range got.Ports {
		if pp.Port == 22 && pp.Kind == ProtectSSH {
			found = true
		}
	}
	if !found {
		t.Fatal("Port 22 应被保护")
	}
}

// TestProtectorSSHTrailingComment 校验行尾注释被剥离。
func TestProtectorSSHTrailingComment(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", "Port 2022 # main ssh port\n")
	p := NewProtector(ProtectOptions{SSHConfigPaths: []string{cfg}})
	got := p.Evaluate(context.Background())

	if !got.SSHDetected {
		t.Fatal("应探测到 SSH 端口")
	}
	for _, pp := range got.Ports {
		if pp.Kind == ProtectSSH && pp.Port != 2022 {
			t.Fatalf("行尾注释应被剥离，应得到 2022，实际 %d", pp.Port)
		}
	}
}

// TestProtectorSSHMultiplePorts 校验多个 Port 指令全部被保护。
func TestProtectorSSHMultiplePorts(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", "Port 22\nPort 2222\n")
	p := NewProtector(ProtectOptions{SSHConfigPaths: []string{cfg}})
	got := p.Evaluate(context.Background())

	ports := map[int]bool{}
	for _, pp := range got.Ports {
		if pp.Kind == ProtectSSH {
			ports[pp.Port] = true
		}
	}
	if !ports[22] || !ports[2222] {
		t.Fatalf("两个 SSH 端口都应被保护，实际 %v", ports)
	}
}

// TestProtectorSSHFromDirectory 校验 sshd_config.d 目录布局。
//
// Debian/Ubuntu 与 RHEL 都把配置拆到目录里，
// 只读主配置会漏掉真正的 Port 指令。
func TestProtectorSSHFromDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sshd_config.d")
	writeFile(t, sub, "10-port.conf", "Port 2200\n")
	writeFile(t, sub, "20-other.conf", "PermitRootLogin no\n")
	// 非 .conf 文件应被忽略。
	writeFile(t, sub, "README", "Port 9999\n")

	p := NewProtector(ProtectOptions{SSHConfigPaths: []string{sub}})
	got := p.Evaluate(context.Background())

	if !got.SSHDetected {
		t.Fatal("应从目录中探测到 SSH 端口")
	}
	for _, pp := range got.Ports {
		if pp.Kind != ProtectSSH {
			continue
		}
		if pp.Port == 9999 {
			t.Fatal("非 .conf 文件不应被解析")
		}
		if pp.Port == 2200 {
			return // 成功
		}
	}
	t.Fatalf("未保护目录中的 SSH 端口 2200，实际: %#v", got.Ports)
}

// TestProtectorSSHConnectionEnv 校验 SSH_CONNECTION 兜底。
func TestProtectorSSHConnectionEnv(t *testing.T) {
	// 格式：<客户端IP> <客户端端口> <服务端IP> <服务端端口>
	p := NewProtector(ProtectOptions{
		SSHConfigPaths:   []string{"/nonexistent/path"},
		SSHConnectionEnv: "203.0.113.5 51234 10.0.0.2 2222",
	})
	got := p.Evaluate(context.Background())

	if !got.SSHDetected {
		t.Fatal("应从 SSH_CONNECTION 探测到 SSH 端口")
	}
	for _, pp := range got.Ports {
		if pp.Kind != ProtectSSH {
			continue
		}
		// ########## 关键：必须是服务端端口（2222），不是客户端端口（51234）##########
		if pp.Port == 51234 {
			t.Fatal("取到了客户端端口 51234 —— 应取第 4 段（服务端端口）")
		}
		if pp.Port == 2222 {
			return
		}
	}
	t.Fatalf("未保护 SSH_CONNECTION 中的服务端端口 2222，实际: %#v", got.Ports)
}

// TestSSHPortFromConnectionEnv 单独校验该解析函数。
func TestSSHPortFromConnectionEnv(t *testing.T) {
	// 正常形态
	if p, ok := sshPortFromConnectionEnv("10.0.0.1 51234 10.0.0.2 22"); !ok || p != 22 {
		t.Fatalf("应解析出服务端端口 22，实际 %d ok=%v", p, ok)
	}
	// 字段数不足
	if _, ok := sshPortFromConnectionEnv("10.0.0.1 51234"); ok {
		t.Fatal("字段数不足时不应解析成功")
	}
	if _, ok := sshPortFromConnectionEnv(""); ok {
		t.Fatal("空串不应解析成功")
	}
	// 端口非法
	if _, ok := sshPortFromConnectionEnv("a b c notanumber"); ok {
		t.Fatal("非数字端口不应解析成功")
	}
	if _, ok := sshPortFromConnectionEnv("a b c 99999"); ok {
		t.Fatal("越界端口不应解析成功")
	}
	// ########## 必须取第 4 段而不是第 2 段 ##########
	// 两者都在合法范围内，只有这样明确的用例才能锁住。
	if p, _ := sshPortFromConnectionEnv("1.2.3.4 1111 5.6.7.8 2222"); p != 2222 {
		t.Fatalf("必须取第 4 段的 2222，实际 %d", p)
	}
}

// TestProtectorListenProbe 校验监听端口探测路径。
func TestProtectorListenProbe(t *testing.T) {
	p := NewProtector(ProtectOptions{
		SSHConfigPaths: []string{"/nonexistent"},
		SSHListenProbe: func(context.Context) []int { return []int{2222} },
	})
	got := p.Evaluate(context.Background())

	if !got.SSHDetected {
		t.Fatal("应从监听探测得到 SSH 端口")
	}
	for _, pp := range got.Ports {
		if pp.Kind == ProtectSSH && pp.Port == 2222 {
			if !strings.Contains(pp.Source, "监听") {
				t.Fatalf("来源应说明是监听端口探测，实际 %q", pp.Source)
			}
			return
		}
	}
	t.Fatalf("未保护监听端口 2222，实际: %#v", got.Ports)
}

// TestProtectorConfigTakesPrecedence 校验配置优先于监听探测。
//
// sshd_config 是 sshd 真正读取的配置，比"当前在听什么"更权威
// （sshd 可能刚改过配置还没重启，或者在听一个配置里没有的端口）。
func TestProtectorConfigTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", "Port 2022\n")
	probeCalled := false
	p := NewProtector(ProtectOptions{
		SSHConfigPaths: []string{cfg},
		SSHListenProbe: func(context.Context) []int {
			probeCalled = true
			return []int{9999}
		},
	})
	got := p.Evaluate(context.Background())

	if probeCalled {
		t.Fatal("配置命中时不应再去探测监听端口")
	}
	for _, pp := range got.Ports {
		if pp.Port == 9999 {
			t.Fatal("不应采用监听探测的结果")
		}
	}
	if !got.SSHDetected {
		t.Fatal("应探测到 SSH 端口")
	}
}

// TestProtectorNoSSHDetectedNeverGuesses 是本文件最重要的安全断言。
//
// ########## 探测不到时绝不能猜 ##########
//
// 若猜 SSH 是 22 而实际是 2222，会有两个后果：
//
//	· 真正的 2222 没被保护 —— 用户关掉它就失联（安全事故）
//	· 无关的 22 被"保护"   —— 用户被错误拦下（信任损失）
//
// 因此三条探测路径全失败时，必须返回**空集合** +
// 如实说明"未能确定 SSH 端口"，而不是填一个 22。
func TestProtectorNoSSHDetectedNeverGuesses(t *testing.T) {
	p := NewProtector(ProtectOptions{
		PanelPort:      8080,
		SSHConfigPaths: []string{"/nonexistent/sshd_config"},
		// 无监听探测、无 SSH_CONNECTION
	})
	got := p.Evaluate(context.Background())

	if got.SSHDetected {
		t.Fatal("三条路径都拿不到时，SSHDetected 必须为 false")
	}
	// ########## 绝不能凭空出现 22 ##########
	for _, pp := range got.Ports {
		if pp.Kind == ProtectSSH {
			t.Fatalf("探测不到 SSH 时绝不能猜测端口，实际保护了 %d（来源: %s）", pp.Port, pp.Source)
		}
		if pp.Port == 22 {
			t.Fatal("探测不到 SSH 时绝不能假定 22 是 SSH 端口")
		}
	}
	// 必须有如实说明的 note。
	foundNote := false
	for _, n := range got.Notes {
		if strings.Contains(n, "未能确定 SSH") {
			foundNote = true
		}
	}
	if !foundNote {
		t.Fatalf("必须如实说明未能确定 SSH 端口，实际 notes: %#v", got.Notes)
	}
	// 面板端口仍应被保护。
	if len(got.Ports) != 1 || got.Ports[0].Port != 8080 {
		t.Fatalf("应只保护面板端口 8080，实际 %#v", got.Ports)
	}
}

// TestProtectorExtraPorts 校验显式指定的受保护端口。
func TestProtectorExtraPorts(t *testing.T) {
	p := NewProtector(ProtectOptions{
		PanelPort:      8080,
		SSHConfigPaths: []string{"/nonexistent"},
		ExtraPorts:     []int{3306},
	})
	got := p.Evaluate(context.Background())

	found := false
	for _, pp := range got.Ports {
		if pp.Port == 3306 {
			found = true
			if !strings.Contains(pp.Source, "firewall-protected-ports") {
				t.Fatalf("来源应指明启动参数，实际 %q", pp.Source)
			}
		}
	}
	if !found {
		t.Fatal("显式指定的端口应被保护")
	}
}

// TestProtectionLookupSinglePort 校验单端口查询。
func TestProtectionLookupSinglePort(t *testing.T) {
	p := NewProtector(ProtectOptions{PanelPort: 8080})
	got := p.Evaluate(context.Background())
	lookup := got.Lookup()

	pp, ok := lookup.Find(PortSpec{Start: 8080, End: 8080})
	if !ok || pp.Port != 8080 {
		t.Fatalf("8080 应命中保护，实际 ok=%v %#v", ok, pp)
	}
	if _, ok := lookup.Find(PortSpec{Start: 9090, End: 9090}); ok {
		t.Fatal("9090 不应命中保护")
	}
	if !lookup.IsProtected(PortSpec{Start: 8080, End: 8080}) {
		t.Fatal("IsProtected(8080) 应为 true")
	}
}

// TestProtectionLookupRangeCoversProtected 锁死"范围覆盖受保护端口"的判定。
//
// ########## 这是一个真实的危险场景 ##########
//
// 用户想关闭一个端口范围 8000-9000，而面板端口 8080 落在其中。
// 若只做精确匹配，删掉这个范围会**静默地**关掉面板端口，
// 用户随即发现面板连不上了，却完全不知道是哪一步操作导致的
// （他删的是"8000-9000"，看起来跟 8080 无关）。
func TestProtectionLookupRangeCoversProtected(t *testing.T) {
	p := NewProtector(ProtectOptions{PanelPort: 8080})
	lookup := p.Evaluate(context.Background()).Lookup()

	// 范围覆盖 8080：必须命中保护。
	pp, ok := lookup.Find(PortSpec{Start: 8000, End: 9000})
	if !ok {
		t.Fatal("范围 8000-9000 覆盖面板端口 8080，必须命中保护")
	}
	if pp.Port != 8080 {
		t.Fatalf("应报告受保护的具体端口 8080，实际 %d", pp.Port)
	}

	// 范围不覆盖：不应命中。
	if _, ok := lookup.Find(PortSpec{Start: 9000, End: 9100}); ok {
		t.Fatal("范围 9000-9100 不覆盖 8080，不应命中保护")
	}
}

// TestProtectPortError 校验错误信息包含足够信息。
func TestProtectPortError(t *testing.T) {
	err := ProtectPortError(PortProtection{
		Port:   22,
		Reason: "这是 SSH 服务端口",
		Source: "读自 sshd 配置",
	})
	if !errors.Is(err, ErrProtectedPort) {
		t.Fatalf("应可用 errors.Is 判定为 ErrProtectedPort，实际: %v", err)
	}
	for _, want := range []string{"22", "SSH", "读自 sshd 配置"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息应包含 %q，实际: %s", want, err.Error())
		}
	}
}

// TestProtectionSorted 校验保护列表按端口升序。
func TestProtectionSorted(t *testing.T) {
	p := NewProtector(ProtectOptions{
		PanelPort:  9000,
		ExtraPorts: []int{3000, 100},
	})
	got := p.Evaluate(context.Background())
	for i := 1; i < len(got.Ports); i++ {
		if got.Ports[i-1].Port > got.Ports[i].Port {
			t.Fatalf("保护列表应按端口升序，实际: %#v", got.Ports)
		}
	}
}

// TestProtectorDuplicatePortNotRepeated 校验同一端口只出现一次。
func TestProtectorDuplicatePortNotRepeated(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", "Port 8080\n")
	p := NewProtector(ProtectOptions{
		PanelPort:      8080,
		SSHConfigPaths: []string{cfg},
	})
	got := p.Evaluate(context.Background())

	count := 0
	for _, pp := range got.Ports {
		if pp.Port == 8080 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("同一端口应只出现一次，实际出现 %d 次: %#v", count, got.Ports)
	}
	// 优先保留面板端口的原因（信息量更大）。
	for _, pp := range got.Ports {
		if pp.Port == 8080 && pp.Kind != ProtectPanel {
			t.Fatalf("面板端口与 SSH 端口重合时，应保留面板的原因，实际 %q", pp.Kind)
		}
	}
}

// TestProtectorUnreadableConfig 校验不可读配置不导致 panic。
func TestProtectorUnreadableConfig(t *testing.T) {
	// 指向一个目录但内容不可读的情况由 readSSHDPorts 处理；
	// 这里验证路径完全不存在时不 panic 且有合理结论。
	p := NewProtector(ProtectOptions{
		SSHConfigPaths: []string{"/proc/1/nonexistent-sshd-config"},
	})
	got := p.Evaluate(context.Background())
	if got.SSHDetected {
		t.Fatal("不存在的配置路径不应产生 SSH 探测结论")
	}
	_ = got.Lookup() // 不应 panic
}
