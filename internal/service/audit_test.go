package service

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// discardLogger 返回一个丢弃全部输出的 logger，避免测试输出被日志淹没。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ============================================================================
// 审计（阶段四 4.1）
// ============================================================================

func TestAuditorRecordAndQuery(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}

	a.Record(AuditEvent{User: "admin", Action: "start", Target: "nginx.service", Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{User: "admin", Action: "stop", Target: "cron.service", Outcome: AuditFailed, Status: 500, Reason: "boom"})
	a.Record(AuditEvent{User: "bob", Action: "restart", Target: "nginx.service", Outcome: AuditDenied, Status: 403})

	// 默认按时间倒序（最新在前）。
	all := a.Query(AuditFilter{})
	if len(all) != 3 {
		t.Fatalf("Query 返回 %d 条，期望 3 条", len(all))
	}
	if all[0].User != "bob" {
		t.Errorf("第一条 = %q，期望最新记录 bob", all[0].User)
	}
	if all[0].Kind != "service" {
		t.Errorf("Kind = %q，期望默认填充为 service", all[0].Kind)
	}
	if all[0].Time == "" {
		t.Error("Time 应被自动填充")
	}

	// 按服务过滤。
	nginx := a.Query(AuditFilter{Target: "nginx.service"})
	if len(nginx) != 2 {
		t.Errorf("按服务过滤返回 %d 条，期望 2 条", len(nginx))
	}

	// 按用户过滤。
	bob := a.Query(AuditFilter{User: "bob"})
	if len(bob) != 1 || bob[0].User != "bob" {
		t.Errorf("按用户过滤返回 %+v，期望 1 条 bob 的记录", bob)
	}

	// 按结果过滤。
	denied := a.Query(AuditFilter{Outcome: AuditDenied})
	if len(denied) != 1 || denied[0].Outcome != AuditDenied {
		t.Errorf("按结果过滤返回 %+v，期望 1 条 denied", denied)
	}

	// 组合过滤。
	combined := a.Query(AuditFilter{Target: "nginx.service", Outcome: AuditAllowed})
	if len(combined) != 1 || combined[0].Action != "start" {
		t.Errorf("组合过滤返回 %+v，期望 1 条 start", combined)
	}
}

func TestAuditorRingBufferEviction(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Logger: discardLogger(), Capacity: 3})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}

	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Target: "svc.service", Action: "start", Reason: string(rune('a' + i))})
	}

	st := a.Stats()
	if st.Total != 5 {
		t.Errorf("Total = %d，期望 5（累计值不受容量影响）", st.Total)
	}
	if st.Retained != 3 {
		t.Errorf("Retained = %d，期望 3（容量上限）", st.Retained)
	}

	// 保留的应是最新的三条（c/d/e）。
	got := a.Query(AuditFilter{})
	if len(got) != 3 {
		t.Fatalf("Query 返回 %d 条，期望 3 条", len(got))
	}
	reasons := got[0].Reason + got[1].Reason + got[2].Reason
	if strings.Contains(reasons, "a") || strings.Contains(reasons, "b") {
		t.Errorf("最旧的记录应被淘汰，got=%q", reasons)
	}
}

func TestAuditorStatsCountsDeniedAndFailed(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Logger: discardLogger()})
	a.Record(AuditEvent{Outcome: AuditAllowed})
	a.Record(AuditEvent{Outcome: AuditAllowed})
	a.Record(AuditEvent{Outcome: AuditDenied})
	a.Record(AuditEvent{Outcome: AuditFailed})
	a.Record(AuditEvent{Outcome: AuditFailed})

	st := a.Stats()
	if st.Denied != 1 {
		t.Errorf("Denied = %d，期望 1", st.Denied)
	}
	if st.Failed != 2 {
		t.Errorf("Failed = %d，期望 2", st.Failed)
	}
}

func TestAuditorPersistsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	a, err := NewAuditor(AuditOptions{Logger: discardLogger(), Path: path})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{User: "admin", Action: "restart", Target: "nginx.service", Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{User: "admin", Action: "stop", Target: "cron.service", Outcome: AuditDenied, Status: 403})

	// 文件权限必须是 0600（审计含操作者信息）。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("审计文件不存在: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("审计文件权限 = %o，期望 600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("审计文件有 %d 行，期望 2 行", len(lines))
	}

	// 每行都是合法 JSON，且含关键字段。
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("第一行不是合法 JSON: %v", err)
	}
	if ev.User != "admin" || ev.Target != "nginx.service" || ev.Action != "restart" {
		t.Errorf("落盘内容 = %+v，关键字段不符", ev)
	}
	if ev.Kind != "service" {
		t.Errorf("Kind = %q，期望 service（便于与插件事件区分）", ev.Kind)
	}
}

func TestAuditorAppendsNotOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	a1, _ := NewAuditor(AuditOptions{Logger: discardLogger(), Path: path})
	a1.Record(AuditEvent{Target: "first.service"})
	_ = a1.Close()

	// 模拟进程重启后再次打开同一文件。
	a2, _ := NewAuditor(AuditOptions{Logger: discardLogger(), Path: path})
	a2.Record(AuditEvent{Target: "second.service"})
	_ = a2.Close()

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "first.service") {
		t.Error("历史记录被覆盖：first.service 丢失")
	}
	if !strings.Contains(content, "second.service") {
		t.Error("新记录未写入：second.service 缺失")
	}
}

func TestAuditorBadPathFailsFast(t *testing.T) {
	// 用一个不可能创建的位置：文件被当作目录的父路径。
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "notadir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备测试文件失败: %v", err)
	}

	_, err := NewAuditor(AuditOptions{
		Logger: discardLogger(),
		Path:   filepath.Join(fileAsDir, "audit.jsonl"),
	})
	if err == nil {
		t.Fatal("期望在不可写路径上构造失败，但返回 nil —— 会导致「以为有审计其实没有」")
	}
}

// TestAuditorRecordNeverPanicsOnNil 断言 nil 审计器是安全的：
// 这让调用方不需要到处判空。
func TestAuditorRecordNeverPanicsOnNil(t *testing.T) {
	var a *Auditor
	a.Record(AuditEvent{Target: "x.service"})
	if got := a.Query(AuditFilter{}); len(got) != 0 {
		t.Errorf("nil 审计器 Query 返回 %d 条，期望 0 条", len(got))
	}
	if st := a.Stats(); st.Total != 0 {
		t.Errorf("nil 审计器 Stats = %+v，期望零值", st)
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil 审计器 Close = %v，期望 nil", err)
	}
}

func TestAuditorConcurrentRecord(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Logger: discardLogger(), Capacity: 100})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.Record(AuditEvent{Action: "start", Target: "svc.service"})
		}(i)
	}
	wg.Wait()

	if st := a.Stats(); st.Total != 50 {
		t.Errorf("并发写入后 Total = %d，期望 50", st.Total)
	}
}

func TestAuditorExportJSONL(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Logger: discardLogger()})
	a.Record(AuditEvent{Target: "a.service"})
	a.Record(AuditEvent{Target: "b.service"})

	var buf bytes.Buffer
	if err := a.ExportAuditJSONL(&buf); err != nil {
		t.Fatalf("ExportAuditJSONL 失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("导出 %d 行，期望 2 行", len(lines))
	}
	// 导出应为正序（与落盘文件一致）。
	var first AuditEvent
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.Target != "a.service" {
		t.Errorf("导出顺序错误，首条 = %q，期望 a.service", first.Target)
	}
}

func TestAuditorQueryLimitClamped(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Logger: discardLogger(), Capacity: 10})
	for i := 0; i < 10; i++ {
		a.Record(AuditEvent{Target: "svc.service"})
	}

	if got := a.Query(AuditFilter{Limit: 3}); len(got) != 3 {
		t.Errorf("Limit=3 返回 %d 条，期望 3 条", len(got))
	}
	if got := a.Query(AuditFilter{Limit: 999999}); len(got) != 10 {
		t.Errorf("超大 Limit 返回 %d 条，期望被 clamp 到 10 条", len(got))
	}
	if got := a.Query(AuditFilter{Limit: -5}); len(got) != DefaultAuditQueryLimit && len(got) != 10 {
		t.Errorf("负数 Limit 返回 %d 条，期望回落到默认值", len(got))
	}
}

// ============================================================================
// 权限判定（阶段四 4.1）
// ============================================================================

func TestRequiredPermission(t *testing.T) {
	cases := map[Action]string{
		ActionStart:   PermWrite,
		ActionStop:    PermWrite,
		ActionRestart: PermWrite,
	}
	for action, want := range cases {
		if got := RequiredPermission(action); got != want {
			t.Errorf("RequiredPermission(%q) = %q，期望 %q", action, got, want)
		}
	}
}

func TestCheckServicePermissionAdminAllowed(t *testing.T) {
	g := AdminGrantee("admin")
	for _, action := range []Action{ActionStart, ActionStop, ActionRestart} {
		d := CheckServicePermission(g, action)
		if !d.Allowed {
			t.Errorf("管理员执行 %q 被拒绝: %s", action, d.Reason)
		}
		if d.Required != PermWrite {
			t.Errorf("Required = %q，期望 %q", d.Required, PermWrite)
		}
	}
}

// TestCheckServicePermissionDeniedIsFailClosed 断言权限不足时**默认拒绝**，
// 这是权限模型最重要的性质。
func TestCheckServicePermissionDeniedIsFailClosed(t *testing.T) {
	readOnly := Grantee{User: "viewer", Granted: []string{PermRead}}

	for _, action := range []Action{ActionStart, ActionStop, ActionRestart} {
		d := CheckServicePermission(readOnly, action)
		if d.Allowed {
			t.Errorf("只读用户执行 %q 被放行，期望拒绝（fail-closed）", action)
		}
		if d.Required != PermWrite {
			t.Errorf("Required = %q，期望 %q", d.Required, PermWrite)
		}
		if d.Reason == "" || d.Hint == "" {
			t.Errorf("拒绝时必须给出原因与提示，got=%+v", d)
		}
	}
}

// TestCheckServicePermissionEmptyGranteeDenied 断言零值 Grantee 一律拒绝。
func TestCheckServicePermissionEmptyGranteeDenied(t *testing.T) {
	var g Grantee
	for _, action := range []Action{ActionStart, ActionStop, ActionRestart} {
		if d := CheckServicePermission(g, action); d.Allowed {
			t.Errorf("空权限集合执行 %q 被放行，期望拒绝", action)
		}
	}
}

func TestGranteeHas(t *testing.T) {
	g := Grantee{Granted: []string{"service.read", "service.write"}}
	if !g.Has(PermRead) || !g.Has(PermWrite) {
		t.Error("Has 应命中已授予权限")
	}
	if g.Has("file.read") {
		t.Error("Has 不应命中未授予权限")
	}
	// 大小写不敏感：配置里写 Service.Write 不该导致静默失效。
	if !(Grantee{Granted: []string{"SERVICE.WRITE"}}).Has(PermWrite) {
		t.Error("Has 应当大小写不敏感")
	}
	if !(Grantee{Granted: []string{" service.write "}}).Has("service.write") {
		t.Error("Has 应当忽略空白")
	}
}

// TestDecisionDoesNotAliasGranteeSlice 断言返回的 Granted 是副本，
// 调用方修改它不会影响原 Grantee（避免共享切片被意外改写）。
func TestDecisionDoesNotAliasGranteeSlice(t *testing.T) {
	g := AdminGrantee("admin")
	d := CheckServicePermission(g, ActionStart)
	if len(d.Granted) == 0 {
		t.Fatal("Granted 不应为空")
	}
	d.Granted[0] = "mutated"
	if g.Granted[0] == "mutated" {
		t.Error("Decision.Granted 与原 Grantee 共享底层数组，存在被意外改写的风险")
	}
}
