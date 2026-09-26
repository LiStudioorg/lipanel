package ssl

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 权限判定测试（阶段四 4.4）
// ============================================================================

// TestRequiredPermissionMapping 验证动作到权限的映射。
func TestRequiredPermissionMapping(t *testing.T) {
	readActions := []string{ActionList, ActionView, ActionCapabilities, ActionAudit}
	for _, a := range readActions {
		if got := RequiredPermission(a); got != PermRead {
			t.Errorf("RequiredPermission(%q) = %q，期望 %q", a, got, PermRead)
		}
	}

	writeActions := []string{ActionIssue, ActionRenew, ActionAutoRenew}
	for _, a := range writeActions {
		if got := RequiredPermission(a); got != PermWrite {
			t.Errorf("RequiredPermission(%q) = %q，期望 %q", a, got, PermWrite)
		}
	}

	// 未知动作必须落到**写**权限（默认拒绝的安全侧）。
	// 若未知动作被当成读，将来新增一个写动作而忘了登记，
	// 它就会在没有任何权限检查的情况下被执行。
	if got := RequiredPermission("some-unknown-action"); got != PermWrite {
		t.Errorf("未知动作应当要求 %q（默认拒绝），实际 %q", PermWrite, got)
	}
}

// TestCheckSSLPermissionAllows 验证有权限时放行。
func TestCheckSSLPermissionAllows(t *testing.T) {
	g := AdminGrantee("admin")
	for _, a := range []string{ActionList, ActionView, ActionIssue, ActionRenew, ActionAutoRenew} {
		d := CheckSSLPermission(g, a)
		if !d.Allowed {
			t.Errorf("管理员执行 %q 应当被放行，实际被拒: %s", a, d.Reason)
		}
		if d.Required == "" {
			t.Errorf("%q 的判定应当带上 required 字段", a)
		}
	}
}

// TestCheckSSLPermissionDeniesReadOnly 验证只读用户被拒。
//
// 只读用户可以看（list/view/capabilities），
// 但**不能**申请或续期（那会消耗 CA 配额并改写 nginx 配置）。
func TestCheckSSLPermissionDeniesReadOnly(t *testing.T) {
	g := Grantee{User: "viewer", Granted: []string{PermRead}}

	// 读操作放行
	for _, a := range []string{ActionList, ActionView, ActionCapabilities, ActionAudit} {
		if d := CheckSSLPermission(g, a); !d.Allowed {
			t.Errorf("只读用户执行 %q 应当被放行", a)
		}
	}

	// 写操作拒绝
	for _, a := range []string{ActionIssue, ActionRenew, ActionAutoRenew} {
		d := CheckSSLPermission(g, a)
		if d.Allowed {
			t.Errorf("只读用户执行 %q 竟然被放行", a)
		}
		if d.Reason == "" {
			t.Errorf("%q 被拒时应当给出原因", a)
		}
		if !strings.Contains(d.Reason, "viewer") {
			t.Errorf("拒绝原因应当包含用户名，实际: %s", d.Reason)
		}
		if d.Hint == "" {
			t.Errorf("%q 被拒时应当给出 hint", a)
		}
	}
}

// TestCheckSSLPermissionDeniesEmpty 验证无任何权限时全部被拒。
//
// 这是「默认拒绝」的底线：空授权集合不能放行任何操作。
func TestCheckSSLPermissionDeniesEmpty(t *testing.T) {
	g := Grantee{User: "nobody"}
	for _, a := range []string{ActionList, ActionIssue, ActionRenew} {
		if d := CheckSSLPermission(g, a); d.Allowed {
			t.Errorf("空授权集合执行 %q 竟然被放行", a)
		}
	}
}

// TestGranteeHasIsCaseInsensitive 验证权限匹配大小写不敏感。
func TestGranteeHasIsCaseInsensitive(t *testing.T) {
	g := Grantee{Granted: []string{"SSL.Write", "  ssl.read  "}}
	if !g.Has(PermWrite) {
		t.Error("权限匹配应当大小写不敏感")
	}
	if !g.Has(PermRead) {
		t.Error("权限匹配应当忽略首尾空白")
	}
	if g.Has("ssl.delete") {
		t.Error("未授予的权限不该匹配")
	}
}

// TestAutomationGrantee 验证自动续期的系统身份。
//
// ########## 为什么定时任务也要走权限判定 ##########
//
// 自动续期同样会消耗 CA 配额、改写 nginx 配置。
// 若给它开一条"内部调用免检"的后门，那么
// "权限判定是唯一强制点"这句话就不成立了——
// 将来收窄策略（例如"只允许为特定域名续期"）时，
// 定时任务会成为一个静默绕过它的通道。
func TestAutomationGrantee(t *testing.T) {
	g := AutomationGrantee()

	if g.User != AutomationUser {
		t.Errorf("User = %q，期望 %q", g.User, AutomationUser)
	}
	// 审计时能一眼区分"这是定时任务续的"与"有人手工续的"
	if !strings.HasPrefix(g.User, "system:") {
		t.Errorf("系统身份应当带 system: 前缀，实际 %q", g.User)
	}
	for _, a := range []string{ActionAutoRenew, ActionRenew, ActionList} {
		if d := CheckSSLPermission(g, a); !d.Allowed {
			t.Errorf("自动续期身份执行 %q 应当被放行", a)
		}
	}
}

// ============================================================================
// 审计测试（阶段四 4.4）
// ============================================================================

// TestAuditorRecordsMemory 验证内存记录。
func TestAuditorRecordsMemory(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 10})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}

	a.Record(AuditEvent{
		User:    "admin",
		Action:  ActionIssue,
		Target:  "example.com",
		Domain:  "example.com",
		Outcome: AuditAllowed,
		Status:  200,
		Issued:  true,
		Applied: true,
	})

	events := a.Query(AuditFilter{})
	if len(events) != 1 {
		t.Fatalf("期望 1 条记录，实际 %d 条", len(events))
	}
	ev := events[0]
	if ev.Kind != KindSSL {
		t.Errorf("Kind = %q，期望 %q", ev.Kind, KindSSL)
	}
	if ev.Source != SourceCore {
		t.Errorf("Source = %q，期望 %q（核心自带不伪造插件 ID）", ev.Source, SourceCore)
	}
	if ev.Seq == 0 {
		t.Error("Seq 应当被自动赋值")
	}
	if ev.Time == "" {
		t.Error("Time 应当被自动填充")
	}
}

// TestAuditorRingBufferEvicts 验证环形缓冲淘汰。
func TestAuditorRingBufferEvicts(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 3})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for i := 0; i < 10; i++ {
		a.Record(AuditEvent{Action: ActionIssue, Target: "s", Outcome: AuditAllowed})
	}

	st := a.Stats()
	if st.Total != 10 {
		t.Errorf("Total = %d，期望 10（总数不该被淘汰影响）", st.Total)
	}
	if st.Retained != 3 {
		t.Errorf("Retained = %d，期望 3", st.Retained)
	}
	if got := len(a.Query(AuditFilter{})); got != 3 {
		t.Errorf("查询返回 %d 条，期望 3", got)
	}
}

// TestAuditorQueryFilters 验证各维度过滤。
func TestAuditorQueryFilters(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 100})

	a.Record(AuditEvent{User: "admin", Action: ActionIssue, Target: "a.com", Outcome: AuditAllowed})
	a.Record(AuditEvent{User: "admin", Action: ActionRenew, Target: "b.com", Outcome: AuditFailed})
	a.Record(AuditEvent{User: "bob", Action: ActionIssue, Target: "a.com", Outcome: AuditDenied})
	a.Record(AuditEvent{User: AutomationUser, Action: ActionAutoRenew, Target: "a.com", Outcome: AuditAllowed})

	tests := []struct {
		name   string
		filter AuditFilter
		want   int
	}{
		{"按目标", AuditFilter{Target: "a.com"}, 3},
		{"按用户", AuditFilter{User: "admin"}, 2},
		{"按动作", AuditFilter{Action: ActionIssue}, 2},
		{"按结果", AuditFilter{Outcome: AuditAllowed}, 2},
		{"自动续期用户", AuditFilter{User: AutomationUser}, 1},
		{"组合", AuditFilter{User: "admin", Target: "a.com"}, 1},
		{"匹配不到", AuditFilter{Target: "nope.com"}, 0},
		{"无过滤", AuditFilter{}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(a.Query(tt.filter)); got != tt.want {
				t.Errorf("查询返回 %d 条，期望 %d 条", got, tt.want)
			}
		})
	}
}

// TestAuditorQueryOrdersNewestFirst 验证查询按时间倒序。
func TestAuditorQueryOrdersNewestFirst(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 10})
	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Action: ActionIssue, Target: string(rune('a' + i))})
	}
	events := a.Query(AuditFilter{})
	if len(events) != 5 {
		t.Fatalf("期望 5 条，实际 %d", len(events))
	}
	// 最新在前
	if events[0].Target != "e" {
		t.Errorf("最新记录应当排在最前，实际首条 Target = %q", events[0].Target)
	}
	if events[4].Target != "a" {
		t.Errorf("最旧记录应当排在最后，实际末条 Target = %q", events[4].Target)
	}
}

// TestAuditorQueryLimit 验证条数上限。
func TestAuditorQueryLimit(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 50})
	for i := 0; i < 30; i++ {
		a.Record(AuditEvent{Action: ActionIssue, Target: "s"})
	}
	if got := len(a.Query(AuditFilter{Limit: 5})); got != 5 {
		t.Errorf("Limit=5 应返回 5 条，实际 %d", got)
	}
	// 超过硬上限时被 clamp
	if got := len(a.Query(AuditFilter{Limit: 99999})); got != 30 {
		t.Errorf("上限不该超过已有条数，实际 %d", got)
	}
}

// TestAuditorPersistsJSONL 验证落盘。
func TestAuditorPersistsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{User: "admin", Action: ActionIssue, Target: "x.com", Issued: true, Applied: true})
	a.Record(AuditEvent{User: "admin", Action: ActionRenew, Target: "y.com", Renewed: true})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计日志失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("期望 2 行，实际 %d 行", len(lines))
	}

	// 每一行都必须是合法 JSON，且 kind / source 正确
	for i, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i, err)
		}
		if ev.Kind != KindSSL {
			t.Errorf("第 %d 行 Kind = %q", i, ev.Kind)
		}
		if ev.Source != SourceCore {
			t.Errorf("第 %d 行 Source = %q", i, ev.Source)
		}
	}

	// 关键布尔字段必须落盘（审计的价值就在于事后可检索）
	var first AuditEvent
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if !first.Issued || !first.Applied {
		t.Error("Issued / Applied 必须落盘（用于筛出「配额花了但没生效」的记录）")
	}
}

// TestAuditorFilePermissions 验证落盘文件权限。
//
// 审计日志含操作者与域名信息，不该被同机其他用户读到。
func TestAuditorFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer func() { _ = a.Close() }()
	a.Record(AuditEvent{Action: ActionIssue, Target: "x"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("审计日志权限 = %o，期望 600", perm)
	}
	// 目录也应当收紧
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat 目录失败: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("审计目录权限 = %o，期望 700", perm)
	}
}

// TestAuditorAppendsNotOverwrites 验证追加写而不是覆盖。
//
// 审计日志绝不能覆盖历史记录——那样"事后复盘"就无从谈起。
func TestAuditorAppendsNotOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	a1, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	a1.Record(AuditEvent{Action: ActionIssue, Target: "first"})
	_ = a1.Close()

	// 模拟面板重启后再写
	a2, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("第二次构造失败: %v", err)
	}
	a2.Record(AuditEvent{Action: ActionIssue, Target: "second"})
	_ = a2.Close()

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "first") {
		t.Error("重启后第一次写入的记录被覆盖了")
	}
	if !strings.Contains(content, "second") {
		t.Error("第二次写入的记录缺失")
	}
	if lines := strings.Split(strings.TrimSpace(content), "\n"); len(lines) != 2 {
		t.Errorf("期望 2 行（追加），实际 %d 行", len(lines))
	}
}

// TestAuditorBadPathReturnsError 验证落盘路径不可用时构造即报错。
//
// 用户显式配置了 -audit-log 却因为目录不可写而悄悄不记录，
// 是最糟的失败方式：他以为有审计，实际上没有。
func TestAuditorBadPathReturnsError(t *testing.T) {
	// 用一个文件充当目录 → MkdirAll 必然失败
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备测试文件失败: %v", err)
	}
	_, err := NewAuditor(AuditOptions{Path: filepath.Join(filePath, "audit.jsonl")})
	if err == nil {
		t.Fatal("路径不可用时应当构造失败，而不是静默降级")
	}
}

// TestAuditorStats 验证统计。
func TestAuditorStats(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 100})

	a.Record(AuditEvent{Action: ActionIssue, Target: "a", Outcome: AuditAllowed, Issued: true, Applied: true})
	a.Record(AuditEvent{Action: ActionIssue, Target: "b", Outcome: AuditDenied})
	a.Record(AuditEvent{Action: ActionRenew, Target: "c", Outcome: AuditFailed})
	a.Record(AuditEvent{Action: ActionRenew, Target: "d", Outcome: AuditPending, Issued: true})
	// 这个组合是"配额花了但 HTTPS 没起来"，最需要被计数
	a.Record(AuditEvent{Action: ActionIssue, Target: "e", Outcome: AuditFailed, Issued: true, Applied: false})

	st := a.Stats()
	if st.Total != 5 {
		t.Errorf("Total = %d，期望 5", st.Total)
	}
	if st.Denied != 1 {
		t.Errorf("Denied = %d，期望 1", st.Denied)
	}
	if st.Failed != 2 {
		t.Errorf("Failed = %d，期望 2", st.Failed)
	}
	if st.Pending != 1 {
		t.Errorf("Pending = %d，期望 1", st.Pending)
	}
	if st.Issued != 3 {
		t.Errorf("Issued = %d，期望 3（配额消耗次数）", st.Issued)
	}
	if st.IssuedNotApplied != 2 {
		t.Errorf("IssuedNotApplied = %d，期望 2（配额花了但没生效）", st.IssuedNotApplied)
	}
}

// TestAuditorNilSafety 验证 nil 审计器不 panic。
//
// 各方法都应当能安全地在 nil 上调用：调用方（server 层）
// 不必到处判空。
func TestAuditorNilSafety(t *testing.T) {
	var a *Auditor
	a.Record(AuditEvent{Action: ActionIssue}) // 不该 panic
	if got := a.Query(AuditFilter{}); len(got) != 0 {
		t.Errorf("nil 审计器查询应返回空，实际 %d 条", len(got))
	}
	if st := a.Stats(); st.Total != 0 {
		t.Errorf("nil 审计器统计应为零值")
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil 审计器 Close 应返回 nil，实际: %v", err)
	}
	var buf bytes.Buffer
	if err := a.ExportAuditJSONL(&buf); err != nil {
		t.Errorf("nil 审计器导出应返回 nil，实际: %v", err)
	}
}

// TestAuditorConcurrent 验证并发写入安全（配合 -race）。
func TestAuditorConcurrent(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 100})
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				a.Record(AuditEvent{Action: ActionIssue, Target: "s"})
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if st := a.Stats(); st.Total != 1000 {
		t.Errorf("Total = %d，期望 1000", st.Total)
	}
}

// TestAuditorCloseIsIdempotent 验证 Close 幂等。
func TestAuditorCloseIsIdempotent(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: filepath.Join(t.TempDir(), "a.jsonl")})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("第一次 Close 失败: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("重复 Close 应当返回 nil，实际: %v", err)
	}
}

// ============================================================================
// 续期调度器测试（阶段四 4.4）
// ============================================================================

// TestSchedulerRunsAndStops 验证调度器能启动、执行并停止。
func TestSchedulerRunsAndStops(t *testing.T) {
	now := time.Now()
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			return "Certificate not yet due for renewal; no action taken.", "", nil
		case strings.Contains(joined, "certificates"):
			return certbotOutputFor("example.com", "example.com", 5, now), "", nil
		}
		return "", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	s := NewRenewScheduler(RenewSchedulerOptions{
		Manager:      m,
		Interval:     50 * time.Millisecond,
		InitialDelay: 0, InitialDelaySet: true, // 立刻执行第一次
	})
	s.Start(context.Background())
	defer func() { _ = s.Close() }()

	// 等待至少一轮执行完成
	deadline := time.After(2 * time.Second)
	for {
		if s.Stats().Runs > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("调度器未在预期时间内执行")
		case <-time.After(10 * time.Millisecond):
		}
	}

	st := s.Stats()
	if !st.Running {
		t.Error("Running 应当为 true")
	}
	if st.Interval == "" {
		t.Error("Interval 应当有值")
	}
}

// TestSchedulerCloseIsIdempotent 验证重复 Close 安全。
func TestSchedulerCloseIsIdempotent(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	s := NewRenewScheduler(RenewSchedulerOptions{
		Manager:      m,
		Interval:     time.Hour, // 不会触发第二轮
		InitialDelay: 0, InitialDelaySet: true,
	})
	s.Start(context.Background())

	if err := s.Close(); err != nil {
		t.Errorf("第一次 Close 失败: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("重复 Close 应当返回 nil，实际: %v", err)
	}
}

// TestSchedulerCloseWithoutStart 验证未启动就 Close 不 panic。
func TestSchedulerCloseWithoutStart(t *testing.T) {
	s := NewRenewScheduler(RenewSchedulerOptions{Manager: &Manager{}})
	if err := s.Close(); err != nil {
		t.Errorf("未启动时 Close 应当返回 nil，实际: %v", err)
	}
}

// TestSchedulerStartIsIdempotent 验证重复 Start 只启动一个 goroutine。
//
// 调用方（main.go）不该需要自己判重，重复启动也不该
// 变成两个并发的续期循环（那会破坏 Manager.mu 的串行化假设）。
func TestSchedulerStartIsIdempotent(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	s := NewRenewScheduler(RenewSchedulerOptions{
		Manager:      m,
		Interval:     time.Hour,
		InitialDelay: 0, InitialDelaySet: true,
	})
	for i := 0; i < 5; i++ {
		s.Start(context.Background())
	}
	defer func() { _ = s.Close() }()

	// 等待第一次执行
	deadline := time.After(2 * time.Second)
	for s.Stats().Runs == 0 {
		select {
		case <-deadline:
			t.Fatal("调度器未执行")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// 重复 Start 不该让 Runs 变成多次
	time.Sleep(100 * time.Millisecond)
	if runs := s.Stats().Runs; runs > 1 {
		t.Errorf("重复 Start 导致了 %d 轮执行，应当只有 1 轮", runs)
	}
}

// TestSchedulerContinuesAfterError 验证失败不会停止调度。
//
// 一次网络抖动不该让自动续期永久失效——
// 那样用户会在 30 天后收到一个"证书已过期"的意外。
func TestSchedulerContinuesAfterError(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--version") {
			return "certbot 1.21.0", "", nil
		}
		// certificates 查询总是失败
		return "", "boom", context.DeadlineExceeded
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	s := NewRenewScheduler(RenewSchedulerOptions{
		Manager:      m,
		Interval:     40 * time.Millisecond,
		InitialDelay: 0, InitialDelaySet: true,
	})
	s.Start(context.Background())
	defer func() { _ = s.Close() }()

	// 等到跑满至少 3 轮
	deadline := time.After(3 * time.Second)
	for s.Stats().Runs < 3 {
		select {
		case <-deadline:
			t.Fatalf("调度器在失败后停止了：只跑了 %d 轮", s.Stats().Runs)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestSchedulerStatsNilSafety 验证 nil 调度器不 panic。
func TestSchedulerStatsNilSafety(t *testing.T) {
	var s *RenewScheduler
	if st := s.Stats(); st.Running {
		t.Error("nil 调度器 Running 应为 false")
	}
	s.Start(context.Background()) // 不该 panic
	if err := s.Close(); err != nil {
		t.Errorf("nil 调度器 Close 应返回 nil，实际: %v", err)
	}
}
