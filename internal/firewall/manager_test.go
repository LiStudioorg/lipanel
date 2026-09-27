package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// 权限判定（阶段四 4.6）
// ============================================================================

func TestRequiredPermission(t *testing.T) {
	reads := []string{ActionStatus, ActionListRules, ActionAudit, ActionCapabilities}
	for _, a := range reads {
		if got := RequiredPermission(a); got != PermRead {
			t.Fatalf("动作 %s 应需 %s，实际 %s", a, PermRead, got)
		}
	}
	writes := []string{ActionAddPort, ActionDeletePort, ActionAddIP, ActionDeleteIP, ActionEnable}
	for _, a := range writes {
		if got := RequiredPermission(a); got != PermWrite {
			t.Fatalf("动作 %s 应需 %s，实际 %s", a, PermWrite, got)
		}
	}
}

// TestEnableIsWritePermission 锁死"启用防火墙是写操作"。
//
// 启用防火墙会立刻让所有未放行的端口不可达。若 SSH 端口漏在规则外，
// 启用的一瞬间当前连接就断了。因此它是所有写操作里最危险的一个，
// 绝不能因为"只是打开一个开关"就被归为读操作。
func TestEnableIsWritePermission(t *testing.T) {
	if RequiredPermission(ActionEnable) != PermWrite {
		t.Fatal("启用防火墙必须是写操作（firewall.write）")
	}
	if !WritesSystem(ActionEnable) {
		t.Fatal("启用防火墙必须被标记为改变系统状态")
	}
}

func TestCheckFirewallPermission(t *testing.T) {
	// 管理员：全部放行。
	admin := AdminGrantee("root")
	for _, a := range []string{ActionStatus, ActionAddPort, ActionDeletePort, ActionEnable} {
		d := CheckFirewallPermission(admin, a)
		if !d.Allowed {
			t.Fatalf("管理员执行 %s 应被放行", a)
		}
		if d.Required != RequiredPermission(a) {
			t.Fatalf("动作 %s 的 Required 字段应为 %s，实际 %s", a, RequiredPermission(a), d.Required)
		}
	}

	// 只读用户：读放行，写拒绝。
	ro := ReadOnlyGrantee("viewer")
	for _, a := range []string{ActionStatus, ActionListRules, ActionAudit, ActionCapabilities} {
		if d := CheckFirewallPermission(ro, a); !d.Allowed {
			t.Fatalf("只读用户执行 %s 应被放行", a)
		}
	}
	for _, a := range []string{ActionAddPort, ActionDeletePort, ActionAddIP, ActionDeleteIP, ActionEnable} {
		d := CheckFirewallPermission(ro, a)
		if d.Allowed {
			t.Fatalf("只读用户执行 %s 必须被拒绝", a)
		}
		if d.Reason == "" || d.Hint == "" {
			t.Fatalf("拒绝时必须给出原因与提示（动作 %s）", a)
		}
		// 提示里要说明防火墙操作的风险。
		if !strings.Contains(d.Hint, "网络可达性") {
			t.Fatalf("动作 %s 的提示应说明防火墙操作的风险，实际: %s", a, d.Hint)
		}
	}
}

// TestDeletionAction 锁死"删除类动作集合"。
//
// 这个集合决定了哪些操作必须二次确认。漏掉一个就是失联风险，
// 因此用穷举断言把所有动作都覆盖到。
func TestDeletionAction(t *testing.T) {
	if !DeletionAction(ActionDeletePort) {
		t.Fatal("删除端口必须是删除类动作（需二次确认）")
	}
	if !DeletionAction(ActionDeleteIP) {
		t.Fatal("删除 IP 规则必须是删除类动作（需二次确认）")
	}
	// 添加类动作不需要确认（它们不会造成失联）。
	for _, a := range []string{ActionAddPort, ActionAddIP, ActionStatus, ActionListRules, ActionAudit, ActionCapabilities} {
		if DeletionAction(a) {
			t.Fatalf("动作 %s 不应被判定为删除类", a)
		}
	}
}

func TestWritesSystem(t *testing.T) {
	writes := map[string]bool{
		ActionAddPort: true, ActionDeletePort: true,
		ActionAddIP: true, ActionDeleteIP: true, ActionEnable: true,
		ActionStatus: false, ActionListRules: false,
		ActionAudit: false, ActionCapabilities: false,
	}
	for a, want := range writes {
		if got := WritesSystem(a); got != want {
			t.Fatalf("WritesSystem(%s) = %v, 期望 %v", a, got, want)
		}
	}
}

func TestGranteeHasCaseInsensitive(t *testing.T) {
	g := Grantee{User: "u", Granted: []string{"FIREWALL.READ", " firewall.write "}}
	if !g.Has(PermRead) || !g.Has(PermWrite) {
		t.Fatal("权限判定应对大小写与空白不敏感")
	}
	if g.Has("firewall.admin") {
		t.Fatal("未授予的权限不应通过")
	}
}

// ============================================================================
// 审计
// ============================================================================

func TestAuditorRecordAndQuery(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 10})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}
	defer a.Close()

	a.Record(AuditEvent{User: "root", Action: ActionAddPort, Target: "8080/tcp",
		Outcome: AuditAllowed, Status: 200, Backend: BackendUFW})
	a.Record(AuditEvent{User: "root", Action: ActionDeletePort, Target: "8080/tcp",
		Outcome: AuditDenied, Status: 403, Backend: BackendUFW, Reason: "权限不足"})
	a.Record(AuditEvent{User: "ops", Action: ActionListRules,
		Outcome: AuditAllowed, Status: 200})

	all := a.Query(AuditFilter{Limit: 100})
	if len(all) != 3 {
		t.Fatalf("应有 3 条记录，实际 %d", len(all))
	}
	// 最新的在前。
	if all[0].User != "ops" {
		t.Fatalf("查询应按时间倒序（最新在前），实际首条 user=%q", all[0].User)
	}

	// 过滤。
	if got := a.Query(AuditFilter{User: "root", Limit: 100}); len(got) != 2 {
		t.Fatalf("按 user 过滤应有 2 条，实际 %d", len(got))
	}
	if got := a.Query(AuditFilter{Outcome: AuditDenied, Limit: 100}); len(got) != 1 {
		t.Fatalf("按 outcome 过滤应有 1 条，实际 %d", len(got))
	}
	if got := a.Query(AuditFilter{Action: ActionListRules, Limit: 100}); len(got) != 1 {
		t.Fatalf("按 action 过滤应有 1 条，实际 %d", len(got))
	}
	if got := a.Query(AuditFilter{Backend: BackendUFW, Limit: 100}); len(got) != 2 {
		t.Fatalf("按 backend 过滤应有 2 条，实际 %d", len(got))
	}
}

// TestAuditorSystemChangeOnlyForNonDenied 锁死"被拒绝的请求不算改变系统"。
//
// 被拒绝的请求**没有执行任何命令**，防火墙状态分毫未动。
// 把它标成"改变了系统"会让审计失去可信度——
// 事后按 system_change 筛"到底动过什么"时会被噪音淹没。
func TestAuditorSystemChangeOnlyForNonDenied(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 10})
	defer a.Close()

	// 被拒绝的写操作。
	a.Record(AuditEvent{Action: ActionDeletePort, Outcome: AuditDenied, Status: 403})
	// 成功的写操作。
	a.Record(AuditEvent{Action: ActionDeletePort, Outcome: AuditAllowed, Status: 200})
	// 失败的写操作（命令可能已部分应用，算改变系统）。
	a.Record(AuditEvent{Action: ActionAddPort, Outcome: AuditFailed, Status: 500})
	// 读操作。
	a.Record(AuditEvent{Action: ActionListRules, Outcome: AuditAllowed, Status: 200})

	got := a.Query(AuditFilter{OnlySystemChange: true, Limit: 100})
	if len(got) != 2 {
		t.Fatalf("应只有 2 条真正改变系统的记录，实际 %d: %#v", len(got), got)
	}
	for _, ev := range got {
		if ev.Outcome == AuditDenied {
			t.Fatal("被拒绝的记录不应被标记为改变系统")
		}
		if ev.Action == ActionListRules {
			t.Fatal("读操作不应被标记为改变系统")
		}
	}
}

func TestAuditorRingEviction(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 3})
	defer a.Close()

	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Action: ActionListRules, Target: string(rune('a' + i))})
	}
	stats := a.Stats()
	if stats.Total != 5 {
		t.Fatalf("total 应为 5，实际 %d", stats.Total)
	}
	if stats.Retained != 3 {
		t.Fatalf("应保留 3 条，实际 %d", stats.Retained)
	}
	got := a.Query(AuditFilter{Limit: 100})
	if len(got) != 3 {
		t.Fatalf("查询应返回 3 条，实际 %d", len(got))
	}
}

func TestAuditorStats(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 20})
	defer a.Close()

	a.Record(AuditEvent{Action: ActionAddPort, Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Action: ActionAddIP, Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Action: ActionDeletePort, Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Action: ActionDeleteIP, Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Action: ActionDeletePort, Outcome: AuditDenied, Status: 403})
	a.Record(AuditEvent{Action: ActionAddPort, Outcome: AuditFailed, Status: 500})
	a.Record(AuditEvent{Action: ActionDeletePort, Outcome: AuditAllowed, Status: 200, Force: true, Protected: true})

	st := a.Stats()
	if st.Added != 2 {
		t.Fatalf("Added 应为 2，实际 %d", st.Added)
	}
	if st.Deleted != 3 {
		t.Fatalf("Deleted 应为 3，实际 %d", st.Deleted)
	}
	if st.Denied != 1 {
		t.Fatalf("Denied 应为 1，实际 %d", st.Denied)
	}
	if st.Failed != 1 {
		t.Fatalf("Failed 应为 1，实际 %d", st.Failed)
	}
	// ########## Forced 统计"强删受保护端口" ##########
	// 强删是"用户看到红色警告仍然继续"的行为，必须能被单独统计。
	if st.Forced != 1 {
		t.Fatalf("Forced 应为 1，实际 %d", st.Forced)
	}
}

func TestAuditorPersistJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}

	a.Record(AuditEvent{User: "root", Action: ActionAddPort, Target: "8080/tcp",
		Outcome: AuditAllowed, Status: 200, Backend: BackendNFTables,
		RuleSpec: "tcp dport 8080 accept", Command: "nft add rule ..."})
	a.Record(AuditEvent{User: "root", Action: ActionDeletePort, Target: "22/tcp",
		Outcome: AuditDenied, Status: 409, Protected: true, Force: true})
	if err := a.Close(); err != nil {
		t.Fatalf("关闭审计器失败: %v", err)
	}

	// 文件权限必须是 0600（审计里含系统操作细节）。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("审计文件不存在: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("审计文件权限应为 0600，实际 %o", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("应有 2 行 JSONL，实际 %d", len(lines))
	}

	// 每行都必须是合法 JSON，且字段完整。
	for i, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i+1, err)
		}
		if ev.Kind != KindFirewall {
			t.Fatalf("第 %d 行 kind 应为 %q，实际 %q", i+1, KindFirewall, ev.Kind)
		}
		if ev.Source != SourceCore {
			t.Fatalf("第 %d 行 source 应为 %q，实际 %q", i+1, SourceCore, ev.Source)
		}
		if ev.Time == "" || ev.Seq == 0 {
			t.Fatalf("第 %d 行缺少 time 或 seq: %#v", i+1, ev)
		}
	}

	// 第一条应含规则规格与命令（事后还原现场的关键字段）。
	var first AuditEvent
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.RuleSpec == "" || first.Command == "" {
		t.Fatalf("写操作审计必须记录 RuleSpec 与 Command（防火墙没有回收站，恢复只能靠它）: %#v", first)
	}
}

// TestAuditorPersistErrorIsFatal 锁死"落盘路径不可用即报错，不静默降级"。
//
// 用户显式配置了 -audit-log 却因为目录不可写而悄悄不记录，
// 是最糟的失败方式——尤其对防火墙模块（操作可能让人失联，
// 事后必须能查到是谁做的）。
func TestAuditorPersistErrorIsFatal(t *testing.T) {
	dir := t.TempDir()
	// 用一个"父路径是文件"的路径，必然打不开。
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("准备测试环境失败: %v", err)
	}
	_, err := NewAuditor(AuditOptions{Path: filepath.Join(blocker, "audit.jsonl")})
	if err == nil {
		t.Fatal("落盘路径不可用时必须构造失败，不能静默降级")
	}
}

func TestAuditorNilSafe(t *testing.T) {
	var a *Auditor
	// 所有方法都应能安全地在 nil 接收者上调用。
	a.Record(AuditEvent{})
	if got := a.Query(AuditFilter{}); len(got) != 0 {
		t.Fatal("nil 审计器查询应返回空")
	}
	if got := a.Stats(); got.Total != 0 {
		t.Fatal("nil 审计器统计应返回零值")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("nil 审计器 Close 应返回 nil: %v", err)
	}
}

func TestAuditorExportJSONL(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 5})
	defer a.Close()
	a.Record(AuditEvent{Action: ActionAddPort, Target: "1"})
	a.Record(AuditEvent{Action: ActionAddPort, Target: "2"})

	var buf bytes.Buffer
	if err := a.ExportAuditJSONL(&buf); err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("应导出 2 行，实际 %d", len(lines))
	}
	// 导出按 seq 正序。
	var first AuditEvent
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.Target != "1" {
		t.Fatalf("导出应按时间正序，首条 target 应为 1，实际 %q", first.Target)
	}
}

// TestAuditorConcurrent 校验并发写入不丢记录（-race 下运行）。
func TestAuditorConcurrent(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 500})
	defer a.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				a.Record(AuditEvent{Action: ActionListRules, Target: "x"})
			}
		}(i)
	}
	wg.Wait()

	if got := a.Stats().Total; got != 500 {
		t.Fatalf("并发写入应记录 500 条，实际 %d", got)
	}
	if got := len(a.Query(AuditFilter{Limit: MaxAuditQueryLimit})); got != 500 {
		t.Fatalf("应保留 500 条，实际 %d", got)
	}
}

// ============================================================================
// 管理器：删除语义与安全闸门
// ============================================================================

// newTestManager 构造一个使用假执行器与假探测器的管理器。
func newTestManager(t *testing.T, backend string, mock *MockExecutor, protect *Protector) *Manager {
	t.Helper()
	auditor, err := NewAuditor(AuditOptions{Capacity: 100})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}
	m, err := NewManager(Options{
		Executor:  mock,
		Auditor:   auditor,
		Detector:  NewDetector(DetectOptions{Executor: mock, ForceBackend: backend}),
		Protector: protect,
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}
	return m
}

// TestDeletePortRequiresConfirm 锁死"服务端强制二次确认"。
//
// ########## 这是计划里的明确要求 ##########
//
// "删除规则前必须二次确认，避免把 SSH 端口误关导致失联"。
// 前端弹窗只是体验；真正的边界在服务端——
// 不带 confirm 的请求一律 428，无论前端怎么做。
func TestDeletePortRequiresConfirm(t *testing.T) {
	mock := NewMockExecutor()
	m := newTestManager(t, BackendUFW, mock, nil)

	_, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow,
		Confirm: false, // 未确认
	})
	if err == nil {
		t.Fatal("不带 confirm 的删除请求必须被拒绝")
	}
	if !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("应返回 ErrConfirmRequired（映射为 428），实际: %v", err)
	}
	// ########## 关键：绝不能执行任何命令 ##########
	if calls := mock.Calls(); len(calls) != 0 {
		t.Fatalf("被拒绝的删除请求绝不能执行任何命令，实际执行了 %d 条: %#v", len(calls), calls)
	}
}

// TestDeleteIPRequiresConfirm 同上，IP 规则也要确认。
func TestDeleteIPRequiresConfirm(t *testing.T) {
	mock := NewMockExecutor()
	m := newTestManager(t, BackendUFW, mock, nil)

	_, err := m.DeleteIP(context.Background(), DeleteIPRequest{
		IP: "1.2.3.4", Direction: DirectionDeny, Confirm: false,
	})
	if !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("应返回 ErrConfirmRequired，实际: %v", err)
	}
	if calls := mock.Calls(); len(calls) != 0 {
		t.Fatalf("被拒绝的请求绝不应执行命令，实际 %d 条", len(calls))
	}
}

// TestDeleteProtectedPortRejected 锁死"受保护端口默认拒绝删除"。
func TestDeleteProtectedPortRejected(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing)\n"})
	mock.When("ufw", []string{"status", "numbered"},
		MockResponse{Stdout: "Status: active\n[ 1] 22/tcp  ALLOW IN  Anywhere\n"})

	// 用真实的 sshd 配置探测路径（工作区内的临时文件），
	// 而不是靠"猜 22 是 SSH"——本模块的核心纪律就是不猜。
	dir := t.TempDir()
	cfg := writeFile(t, dir, "sshd_config", "Port 22\n")
	protect := NewProtector(ProtectOptions{PanelPort: 8080, SSHConfigPaths: []string{cfg}})
	m := newTestManager(t, BackendUFW, mock, protect)

	// 删除 SSH 端口（被保护）——不带 force 必须拒绝。
	_, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "22", Protocol: ProtoTCP, Action: ActionAllow,
		Confirm: true, // 已确认，但仍被保护
	})
	if err == nil {
		t.Fatal("删除受保护端口必须被拒绝")
	}
	if !errors.Is(err, ErrProtectedPort) {
		t.Fatalf("应返回 ErrProtectedPort（映射为 409），实际: %v", err)
	}
	// 错误信息要说明保护原因，让用户能判断。
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("错误应说明是 SSH 端口，实际: %v", err)
	}

	// ########## 关键：绝不能执行删除命令 ##########
	mock.Reset()
	for _, c := range mock.Calls() {
		if len(c.Args) > 0 && c.Args[0] == "delete" {
			t.Fatalf("被保护的端口绝不能触发删除命令: %#v", c)
		}
	}
}

// TestDeleteProtectedPortForce 校验 force 可以强删（但要留痕）。
func TestDeleteProtectedPortForce(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing)\n"})
	mock.When("ufw", []string{"status", "numbered"},
		MockResponse{Stdout: "Status: active\n[ 1] 22/tcp  ALLOW IN  Anywhere\n"})
	mock.WhenPrefix("ufw", []string{"delete"}, MockResponse{Stdout: "Rule deleted\n"})

	protect := NewProtector(ProtectOptions{PanelPort: 8080})
	m := newTestManager(t, BackendUFW, mock, protect)

	result, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "22", Protocol: ProtoTCP, Action: ActionAllow,
		Confirm: true, Force: true,
	})
	if err != nil {
		t.Fatalf("带 force 时应允许删除，实际失败: %v", err)
	}
	if len(result.Commands) == 0 {
		t.Fatal("应记录执行的命令")
	}
}

// TestAddPortValidation 校验添加端口的输入校验。
func TestAddPortValidation(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	m := newTestManager(t, BackendUFW, mock, nil)

	bad := []PortRequest{
		{Port: "0"},                          // 端口 0
		{Port: "65536"},                      // 越界
		{Port: "8080;reboot"},                // 注入
		{Port: "8090-8080"},                  // 范围反向
		{Port: " 8080"},                      // 前导空格
		{Port: "8080", Protocol: "icmp"},     // 不支持的协议
		{Port: "8080", Action: "reject"},     // 不支持的动作
		{Port: "8080", Source: "1.2.3.4:22"}, // 字段填错
		{Port: "8080", Comment: "a\nb"},      // 换行备注
	}
	for _, req := range bad {
		mock.Reset()
		_, err := m.AddPort(context.Background(), req)
		if err == nil {
			t.Fatalf("非法请求 %#v 必须被拒绝", req)
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("请求 %#v 应返回 ErrInvalidRule（映射为 400），实际: %v", req, err)
		}
		// 校验失败绝不能执行命令。
		if calls := mock.Calls(); len(calls) != 0 {
			t.Fatalf("非法输入 %#v 绝不能执行命令，实际 %d 条: %#v", req, len(calls), calls)
		}
	}
}

// TestAddPortExpandsAnyProtocol 锁死"any 协议展开为两条"。
//
// ufw 与 iptables 的一条规则只能有一个协议。
// 若静默只放行 tcp，用户会以为 UDP 也开了——
// DNS(53)、WireGuard(51820)、游戏服务器都会静默失效。
func TestAddPortExpandsAnyProtocol(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	m := newTestManager(t, BackendUFW, mock, nil)

	result, err := m.AddPort(context.Background(), PortRequest{
		Port: "53", Protocol: ProtoAny, Action: ActionAllow,
	})
	if err != nil {
		t.Fatalf("添加失败: %v", err)
	}
	if len(result.Commands) != 2 {
		t.Fatalf("any 协议应展开为 2 条命令，实际 %d: %#v", len(result.Commands), result.Commands)
	}
	joined := strings.Join(result.Commands, " | ")
	if !strings.Contains(joined, "tcp") || !strings.Contains(joined, "udp") {
		t.Fatalf("展开的命令应同时覆盖 tcp 与 udp，实际: %s", joined)
	}
}

// TestAddPortAssemblesArgv 校验命令组装的正确性（逐元素）。
func TestAddPortAssemblesArgv(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	m := newTestManager(t, BackendUFW, mock, nil)

	_, err := m.AddPort(context.Background(), PortRequest{
		Port: "8080", Protocol: ProtoTCP, Source: "192.168.1.0/24",
		Action: ActionAllow, Comment: "web",
	})
	if err != nil {
		t.Fatalf("添加失败: %v", err)
	}

	want := []string{
		"allow", "from", "192.168.1.0/24", "proto", "tcp",
		"to", "any", "port", "8080", "comment", "[lipanel] web",
	}
	if !mock.ExactCallArgs("ufw", want) {
		t.Fatalf("未找到期望的命令调用:\n  期望 ufw %#v\n  实际调用: %#v", want, mock.Calls())
	}
}

// TestDeletePortRuleNotFound 校验规则不存在时的语义。
func TestDeletePortRuleNotFound(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	mock.When("ufw", []string{"status", "numbered"},
		MockResponse{Stdout: "Status: active\n"}) // 没有任何规则
	m := newTestManager(t, BackendUFW, mock, nil)

	_, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow, Confirm: true,
	})
	if !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("规则不存在时应返回 ErrRuleNotFound（映射为 404），实际: %v", err)
	}
}

// TestDeleteNFTWithoutHandleRefused 锁死"nft 拿不到 handle 就拒绝删除"。
//
// ########## 本用例是本模块最重要的安全断言之一 ##########
//
// nft 没有"按内容删除"的语法。若解析不出 handle，
// 唯一"看起来可行"的替代是 `nft flush ruleset`——
// 那会清空**整台机器**的防火墙规则（含 SSH 白名单、ufw 的整套链）。
//
// 因此拿不到 handle 时必须明确拒绝，且绝不能出现 flush。
func TestDeleteNFTWithoutHandleRefused(t *testing.T) {
	mock := NewMockExecutor()
	// 模拟忘加 -a 的输出：有规则但没有 handle。
	mock.When("nft", []string{"-a", "list", "ruleset"}, MockResponse{Stdout: `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept
	}
}
`})

	m := newTestManager(t, BackendNFTables, mock, nil)
	_, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow, Confirm: true,
	})
	if err == nil {
		t.Fatal("nft 规则没有 handle 时必须拒绝删除")
	}
	if !errors.Is(err, ErrNotDeletable) {
		t.Fatalf("应返回 ErrNotDeletable（映射为 409），实际: %v", err)
	}

	// ########## 断言：全程绝不出现 flush ##########
	if flushed := mock.CallsContaining("flush"); len(flushed) != 0 {
		t.Fatalf("绝不能执行任何含 flush 的命令（会清空整台机器的防火墙）: %#v", flushed)
	}
}

// TestDeleteNFTWithHandle 校验有 handle 时能正常删除。
func TestDeleteNFTWithHandle(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("nft", []string{"-a", "list", "ruleset"}, MockResponse{Stdout: `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept # handle 7
	}
}
`})
	mock.WhenPrefix("nft", []string{"delete"}, MockResponse{})

	m := newTestManager(t, BackendNFTables, mock, nil)
	result, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow, Confirm: true,
	})
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	// 必须用正确的 handle 7（不是 table 的 handle 1）。
	want := []string{"delete", "rule", "inet", "filter", "input", "handle", "7"}
	if !mock.ExactCallArgs("nft", want) {
		t.Fatalf("未按 handle 删除:\n  期望 nft %#v\n  实际: %#v", want, mock.Calls())
	}
	if len(result.Commands) == 0 {
		t.Fatal("应记录命令")
	}
}

// TestDeleteIPTablesUsesParsedSpec 锁死"iptables 用解析出的规格删除"。
//
// ########## 为什么必须用解析出的规格 ##########
//
// 真实环境实测：添加时写 "--dport 8080"，回读时是
// "-p tcp -m tcp --dport 8080"（内核补的 -m tcp）。
// 按用户输入重新组装会漏掉它，-D 报 "Bad rule"。
func TestDeleteIPTablesUsesParsedSpec(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("iptables", []string{"-S", "input"}, MockResponse{Stdout: `-P input ACCEPT
-A input -p tcp -m tcp --dport 8080 -j ACCEPT
`})
	mock.WhenPrefix("iptables", []string{"-D"}, MockResponse{})

	m := newTestManager(t, BackendIPTables, mock, nil)
	_, err := m.DeletePort(context.Background(), DeletePortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow, Confirm: true,
	})
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}

	// 必须包含内核补的 "-m tcp"。
	want := []string{"-D", "input", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-j", "ACCEPT"}
	if !mock.ExactCallArgs("iptables", want) {
		t.Fatalf("未按解析出的规格删除:\n  期望 iptables %#v\n  实际: %#v", want, mock.Calls())
	}
}

// TestDeleteIPTablesJumpRuleRefused 锁死"跳转规则不可删除"。
//
// 形如 "-A input -j DOCKER-USER" 的规则是防火墙的结构性组成部分，
// 删除它会改变其它规则的走向（Docker 转发、ufw 的入站处理都挂在上面）。
// 一次误点就能让整台机器的网络策略失效。
func TestDeleteIPTablesJumpRuleRefused(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("iptables", []string{"-S", "input"}, MockResponse{Stdout: `-P input ACCEPT
-A input -j DOCKER-USER
`})
	m := newTestManager(t, BackendIPTables, mock, nil)

	// 该规则没有端口，因此从端口删除路径找不到它；
	// 这里直接验证解析结果的可删除性。
	_, rules, err := m.fetchState(context.Background(), BackendIPTables)
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("应解析出 1 条规则，实际 %d", len(rules))
	}
	if rules[0].Deletable {
		t.Fatal("跳转到自定义链的规则必须不可删除")
	}
	if !strings.Contains(rules[0].NotDeletableReason, "DOCKER-USER") {
		t.Fatalf("原因应指明目标链，实际: %s", rules[0].NotDeletableReason)
	}
}

// TestAssertNoFlushPanics 校验运行时的 flush 最后防线。
func TestAssertNoFlushPanics(t *testing.T) {
	m := &Manager{}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("命令中出现 flush 时必须 panic（这是编程错误，必须被立刻发现）")
		}
	}()
	m.assertNoFlush(Command{Name: "nft", Args: []string{"flush", "ruleset"}})
}

// TestAssertNoFlushAllowsNormal 校验正常命令不触发防线。
func TestAssertNoFlushAllowsNormal(t *testing.T) {
	m := &Manager{}
	// 不应 panic。
	m.assertNoFlush(Command{Name: "ufw", Args: []string{"allow", "proto", "tcp", "to", "any", "port", "8080"}})
	m.assertNoFlush(Command{Name: "nft", Args: []string{"delete", "rule", "inet", "filter", "input", "handle", "7"}})
}

// TestDryRunExecutesNothing 锁死"试运行零真实执行"。
func TestDryRunExecutesNothing(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	mock.When("ufw", []string{"status", "numbered"}, MockResponse{Stdout: "Status: active\n"})

	auditor, _ := NewAuditor(AuditOptions{Capacity: 10})
	m, err := NewManager(Options{
		Executor: mock,
		Auditor:  auditor,
		Detector: NewDetector(DetectOptions{Executor: mock, ForceBackend: BackendUFW}),
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	result, err := m.AddPort(context.Background(), PortRequest{
		Port: "8080", Protocol: ProtoTCP, Action: ActionAllow,
	})
	if err != nil {
		t.Fatalf("试运行不应失败: %v", err)
	}
	if !result.Simulated {
		t.Fatal("试运行结果的 Simulated 应为 true")
	}
	// ########## 关键：写命令绝不能真的执行 ##########
	for _, c := range mock.Calls() {
		if c.Name == "ufw" && len(c.Args) > 0 &&
			(c.Args[0] == "allow" || c.Args[0] == "deny" || c.Args[0] == "delete") {
			t.Fatalf("试运行绝不能执行写命令，实际执行了: %#v", c)
		}
	}
}

// TestStatusDegradesGracefully 锁死"无防火墙时优雅降级"。
func TestStatusDegradesGracefully(t *testing.T) {
	mock := NewMockExecutor()
	// 四个后端都不存在。
	for _, name := range []string{"ufw", "firewall-cmd", "nft", "iptables"} {
		mock.Missing(name)
	}
	m := newTestManager(t, "", mock, nil)

	result, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("无防火墙时 Status 不应返回错误（应降级）: %v", err)
	}
	if result.Detection.Available {
		t.Fatal("无防火墙时 Available 应为 false")
	}
	if result.Detection.Reason == "" {
		t.Fatal("应给出不可用原因")
	}
	// 必须给出安装指引。
	if !strings.Contains(result.Detection.Hint, "apt-get install ufw") {
		t.Fatalf("应给出安装指引，实际: %s", result.Detection.Hint)
	}
}

// TestListRulesIncludesProtection 校验规则列表带保护标记。
func TestListRulesIncludesProtection(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing)\n"})
	mock.When("ufw", []string{"status", "numbered"}, MockResponse{Stdout: `Status: active
[ 1] 22/tcp                 ALLOW IN    Anywhere
[ 2] 8081/tcp               ALLOW IN    Anywhere
`})

	protect := NewProtector(ProtectOptions{PanelPort: 22})
	m := newTestManager(t, BackendUFW, mock, protect)

	result, err := m.ListRules(context.Background())
	if err != nil {
		t.Fatalf("列规则失败: %v", err)
	}
	if len(result.Ports) != 2 {
		t.Fatalf("应有 2 条端口规则，实际 %d", len(result.Ports))
	}
	if !result.Ports[0].Protected {
		t.Fatal("22 是面板端口，应被标记为受保护")
	}
	if result.Ports[0].ProtectedReason == "" {
		t.Fatal("受保护的规则必须给出原因")
	}
	if result.Ports[1].Protected {
		t.Fatal("8081 不应被标记为受保护")
	}
	if result.Counts.Protected != 1 {
		t.Fatalf("受保护计数应为 1，实际 %d", result.Counts.Protected)
	}
}

// TestListRulesUnavailable 校验无防火墙时列规则优雅降级。
func TestListRulesUnavailable(t *testing.T) {
	mock := NewMockExecutor()
	for _, name := range []string{"ufw", "firewall-cmd", "nft", "iptables"} {
		mock.Missing(name)
	}
	m := newTestManager(t, "", mock, nil)

	result, err := m.ListRules(context.Background())
	if err != nil {
		t.Fatalf("无防火墙时列规则不应报错: %v", err)
	}
	if result.Available {
		t.Fatal("Available 应为 false")
	}
	if result.UnavailableReason == "" {
		t.Fatal("应给出不可用原因")
	}
	if len(result.Rules) != 0 {
		t.Fatal("不可用时应返回空列表而不是 nil/panic")
	}
}

// TestCommandTimeout 校验超时配置生效。
func TestCommandTimeout(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Err: context.DeadlineExceeded})
	mock.When("ufw", []string{"status", "numbered"},
		MockResponse{Err: context.DeadlineExceeded})

	auditor, _ := NewAuditor(AuditOptions{Capacity: 10})
	m, err := NewManager(Options{
		Executor:       mock,
		Auditor:        auditor,
		Detector:       NewDetector(DetectOptions{Executor: mock, ForceBackend: BackendUFW}),
		CommandTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if m.CommandTimeout() != 50*time.Millisecond {
		t.Fatalf("超时配置未生效: %v", m.CommandTimeout())
	}
}

func TestCapabilities(t *testing.T) {
	m := &Manager{}
	caps := m.Capabilities()
	if len(caps) != 4 {
		t.Fatalf("应有 4 个后端的能力说明，实际 %d", len(caps))
	}
	for _, c := range caps {
		if c.Deletion == "" {
			t.Fatalf("后端 %s 必须说明删除方式", c.Backend)
		}
	}
	// nftables 的说明必须点明"拿不到句柄不可删除"与"绝不清空"。
	for _, c := range caps {
		if c.Backend == BackendNFTables {
			if !strings.Contains(c.Deletion, "句柄") {
				t.Fatalf("nftables 的删除说明应提到句柄，实际: %s", c.Deletion)
			}
			if !strings.Contains(c.Deletion, "清空") {
				t.Fatalf("nftables 的删除说明应声明绝不用清空代替，实际: %s", c.Deletion)
			}
		}
	}
}

// TestDeleteUFWIPRule 锁死"ufw 的 IP 规则删除命令形态"。
//
// ########## 这个用例来自端到端验证抓到的真实缺陷 ##########
//
// 原先所有 ufw 删除都走 BuildUFWDeletePort，而它会校验协议。
// IP 规则没有协议（Protocol 为空），于是删除黑名单条目会返回
// 500「不支持的协议 ""」——用户在界面上点删除，只看到一个
// 无法理解的内部错误。
//
// 单元测试没抓到它，是因为测试都构造了完整的**端口**规则；
// 只有端到端走完"添加 IP → 列出 → 删除"才暴露出来。
// 这个用例把那条路径固定下来。
func TestDeleteUFWIPRule(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing)\n"})
	mock.When("ufw", []string{"status", "numbered"}, MockResponse{Stdout: `Status: active
     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   DENY IN     203.0.113.5  # [lipanel]
`})
	mock.WhenPrefix("ufw", []string{"delete"}, MockResponse{Stdout: "Rule deleted\n"})

	m := newTestManager(t, BackendUFW, mock, nil)
	result, err := m.DeleteIP(context.Background(), DeleteIPRequest{
		IP: "203.0.113.5", Direction: DirectionDeny, Confirm: true,
	})
	if err != nil {
		t.Fatalf("删除 IP 规则失败（曾经因协议为空而返回 500）: %v", err)
	}

	// 命令形态必须是 `ufw delete deny from <ip>`，
	// 而不是端口规则那种 `delete allow proto ... to any port ...`。
	want := []string{"delete", "deny", "from", "203.0.113.5", "comment", "[lipanel]"}
	if !mock.ExactCallArgs("ufw", want) {
		t.Fatalf("IP 规则删除命令不正确:\n  期望 ufw %#v\n  实际: %#v", want, mock.Calls())
	}
	if len(result.Commands) == 0 {
		t.Fatal("应记录执行的命令")
	}
}

// TestDeleteUFWIPRuleAllow 校验白名单条目用的是 allow。
func TestDeleteUFWIPRuleAllow(t *testing.T) {
	mock := NewMockExecutor()
	mock.When("ufw", []string{"status", "verbose"},
		MockResponse{Stdout: "Status: active\nDefault: deny (incoming)\n"})
	mock.When("ufw", []string{"status", "numbered"}, MockResponse{Stdout: `Status: active
[ 1] Anywhere                   ALLOW IN    10.0.0.0/8  # [lipanel]
`})
	mock.WhenPrefix("ufw", []string{"delete"}, MockResponse{})

	m := newTestManager(t, BackendUFW, mock, nil)
	_, err := m.DeleteIP(context.Background(), DeleteIPRequest{
		IP: "10.0.0.0/8", Direction: DirectionAllow, Confirm: true,
	})
	if err != nil {
		t.Fatalf("删除白名单条目失败: %v", err)
	}
	want := []string{"delete", "allow", "from", "10.0.0.0/8", "comment", "[lipanel]"}
	if !mock.ExactCallArgs("ufw", want) {
		t.Fatalf("白名单删除命令不正确:\n  期望 ufw %#v\n  实际: %#v", want, mock.Calls())
	}
}
