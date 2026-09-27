package store

import (
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 权限判定测试
// ============================================================================

// TestRequiredPermission 穷举动作到权限的映射。
//
// 映射表是安全策略的一部分：如果哪天有人把 install 的必需权限
// 改成 store.read，这里必须立刻红。
func TestRequiredPermission(t *testing.T) {
	readActions := []string{ActionList, ActionView, ActionCapabilities, ActionAudit, ActionTask}
	for _, a := range readActions {
		if got := RequiredPermission(a); got != PermRead {
			t.Errorf("RequiredPermission(%q) = %q，应为 %q", a, got, PermRead)
		}
	}
	for _, a := range []string{ActionInstall, ActionUninstall} {
		if got := RequiredPermission(a); got != PermWrite {
			t.Errorf("RequiredPermission(%q) = %q，应为 %q", a, got, PermWrite)
		}
	}
	// 未知动作必须按**写**处理（fail-closed）。
	//
	// 这一条比看上去重要：将来新增动作时若忘了登记，
	// 默认放行意味着"新动作自动对所有只读用户开放"。
	for _, a := range []string{"", "delete", "exec", "unknown-action"} {
		if got := RequiredPermission(a); got != PermWrite {
			t.Errorf("未知动作 %q 应要求 %q（fail-closed），实际 %q", a, PermWrite, got)
		}
	}
}

// TestWritesSystem 验证"会改系统"的标记。
func TestWritesSystem(t *testing.T) {
	for _, a := range []string{ActionInstall, ActionUninstall} {
		if !WritesSystem(a) {
			t.Errorf("WritesSystem(%q) 应为 true", a)
		}
	}
	// 查看类动作绝不能标记为改系统。
	for _, a := range []string{ActionList, ActionView, ActionCapabilities, ActionAudit, ActionTask, ""} {
		if WritesSystem(a) {
			t.Errorf("WritesSystem(%q) 应为 false", a)
		}
	}
}

// TestCheckStorePermissionAllowed 验证有权限时放行且回显授予集合。
func TestCheckStorePermissionAllowed(t *testing.T) {
	g := AdminGrantee("admin")
	for _, a := range []string{ActionList, ActionInstall, ActionUninstall} {
		d := CheckStorePermission(g, a)
		if !d.Allowed {
			t.Errorf("%q 应被放行: %+v", a, d)
		}
		if d.Required != RequiredPermission(a) {
			t.Errorf("%q 的 Required = %q", a, d.Required)
		}
		if len(d.Granted) != 2 {
			t.Errorf("%q 的 Granted = %v", a, d.Granted)
		}
	}
	if AdminGrantee("admin").User != "admin" {
		t.Error("AdminGrantee 应记录用户名")
	}
}

// TestCheckStorePermissionDenied 验证缺权限时拒绝，并给出可读原因。
func TestCheckStorePermissionDenied(t *testing.T) {
	// 只读用户点"安装"。
	readonly := Grantee{User: "viewer", Granted: []string{PermRead}}
	d := CheckStorePermission(readonly, ActionInstall)
	if d.Allowed {
		t.Fatal("只读用户不应被允许安装")
	}
	if d.Required != PermWrite {
		t.Errorf("Required = %q", d.Required)
	}
	if !strings.Contains(d.Reason, "viewer") || !strings.Contains(d.Reason, PermWrite) {
		t.Errorf("Reason 应说明谁缺什么权限: %q", d.Reason)
	}
	if !strings.Contains(d.Hint, PermWrite) {
		t.Errorf("Hint 应告诉用户需要什么权限: %q", d.Hint)
	}

	// 完全没授予权限。
	none := Grantee{User: "nobody"}
	if CheckStorePermission(none, ActionList).Allowed {
		t.Error("无任何权限时连查看都不应放行")
	}
	// 只有写权限时，查看也应被拒（权限不是"写包含读"）。
	writeOnly := Grantee{User: "op", Granted: []string{PermWrite}}
	if CheckStorePermission(writeOnly, ActionList).Allowed {
		t.Error("只有 store.write 时不应放行 store.read 动作")
	}
	// 用户名为空时也要给出可读的原因。
	anon := CheckStorePermission(Grantee{}, ActionInstall)
	if anon.Allowed || anon.Reason == "" {
		t.Errorf("匿名用户应被拒绝且给出原因: %+v", anon)
	}
}

// TestGranteeHas 验证权限集合判定（大小写与空白容错）。
func TestGranteeHas(t *testing.T) {
	g := Grantee{User: "u", Granted: []string{" Store.Read ", "STORE.WRITE"}}
	if !g.Has(PermRead) || !g.Has(PermWrite) {
		t.Errorf("应容忍大小写与空白: %+v", g.Granted)
	}
	if g.Has("store.exec") {
		t.Error("未授予的权限不应通过")
	}
	// 必须是精确匹配，不能前缀匹配。
	if g.Has("store") || g.Has("store.r") {
		t.Error("权限判定必须是精确匹配，不能前缀匹配")
	}
}

// TestCheckStorePermissionDoesNotMutateGranted 验证返回值不共享底层数组。
//
// 否则调用方 A 改了 Decision.Granted，调用方 B 看到的也变了。
func TestCheckStorePermissionDoesNotMutateGranted(t *testing.T) {
	g := AdminGrantee("admin")
	d := CheckStorePermission(g, ActionList)
	d.Granted[0] = "tampered"
	if g.Granted[0] == "tampered" {
		t.Fatal("Decision.Granted 与入参共享底层数组")
	}
	// 拒绝分支同样不能共享。
	ro := Grantee{User: "v", Granted: []string{PermRead}}
	denied := CheckStorePermission(ro, ActionInstall)
	if len(denied.Granted) > 0 {
		denied.Granted[0] = "tampered"
		if ro.Granted[0] == "tampered" {
			t.Error("拒绝分支的 Granted 与入参共享底层数组")
		}
	}
}

// ============================================================================
// 审计测试
// ============================================================================

// TestAuditorRecordsAndQueries 验证写入与按条件查询。
func TestAuditorRecordsAndQueries(t *testing.T) {
	a, err := NewAuditor(AuditOptions{})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{
		Action: ActionInstall, Target: "nginx", Version: "1.26",
		User: "admin", ClientIP: "10.0.0.1", Outcome: AuditAllowed,
		Strategy: StrategySystem, TaskID: "t1",
	})
	a.Record(AuditEvent{
		Action: ActionUninstall, Target: "nginx", Version: "1.24",
		User: "admin", Outcome: AuditFailed, Reason: "包仍存在", TaskID: "t2",
	})
	a.Record(AuditEvent{
		Action: ActionList, User: "viewer", Outcome: AuditAllowed,
	})

	all := a.Query(AuditFilter{Limit: 10})
	if len(all) != 3 {
		t.Fatalf("应返回 3 条，实际 %d", len(all))
	}
	// 最新在前。
	if all[0].Action != ActionList {
		t.Errorf("应按时间倒序返回，首条 = %q", all[0].Action)
	}
	if got := a.Query(AuditFilter{Action: ActionInstall, Limit: 10}); len(got) != 1 {
		t.Errorf("按动作过滤失败: %d", len(got))
	}
	if got := a.Query(AuditFilter{Outcome: AuditFailed, Limit: 10}); len(got) != 1 {
		t.Errorf("按结果过滤失败: %d", len(got))
	}
	if got := a.Query(AuditFilter{Target: "nginx", Limit: 10}); len(got) != 2 {
		t.Errorf("按目标过滤失败: %d", len(got))
	}
	if got := a.Query(AuditFilter{User: "viewer", Limit: 10}); len(got) != 1 {
		t.Errorf("按用户过滤失败: %d", len(got))
	}
	if got := a.Query(AuditFilter{Version: "1.24", Limit: 10}); len(got) != 1 {
		t.Errorf("按版本过滤失败: %d", len(got))
	}
	if got := a.Query(AuditFilter{Target: "nginx", Action: ActionUninstall, Limit: 10}); len(got) != 1 {
		t.Errorf("组合过滤失败: %d", len(got))
	}
}

// TestAuditorDefaultsOutcomeAndSystemChange 验证默认值补齐。
func TestAuditorDefaultsOutcomeAndSystemChange(t *testing.T) {
	a, err := NewAuditor(AuditOptions{})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	// 未显式给 Outcome 的写入型动作：默认 allowed，且必须标记为系统变更。
	a.Record(AuditEvent{Action: ActionInstall, Target: "nginx"})
	got := a.Query(AuditFilter{Limit: 10})
	if len(got) != 1 {
		t.Fatalf("应写入一条")
	}
	if got[0].Outcome != AuditAllowed {
		t.Errorf("Outcome 默认值应为 allowed，实际 %q", got[0].Outcome)
	}
	if !got[0].SystemChange {
		t.Error("安装动作应自动标记为系统变更")
	}
	if got[0].Source != SourceCore {
		t.Errorf("默认来源应为 core，实际 %q（核心能力不得伪装成插件）", got[0].Source)
	}
	if got[0].Time == "" {
		t.Error("应自动补时间戳")
	}
	// 时间戳必须是可被外部工具直接解析的 RFC3339。
	if _, err := time.Parse(time.RFC3339Nano, got[0].Time); err != nil {
		t.Errorf("时间戳格式应为 RFC3339Nano，实际 %q: %v", got[0].Time, err)
	}
	if got[0].Kind != KindStore {
		t.Errorf("Kind 应为 %q，实际 %q", KindStore, got[0].Kind)
	}
	if got[0].Seq == 0 {
		t.Error("应分配自增序号")
	}

	// 被拒绝的写动作不能标记为"已改系统"——它什么都没做。
	a.Record(AuditEvent{Action: ActionInstall, Target: "nginx", Outcome: AuditDenied})
	got = a.Query(AuditFilter{Outcome: AuditDenied, Limit: 10})
	if len(got) != 1 {
		t.Fatalf("应有拒绝记录")
	}
	if got[0].SystemChange {
		t.Error("被拒绝的请求不应标记为系统变更")
	}
}

// TestAuditorPendingVsAllowed 验证异步任务的"进行中"语义。
//
// 安装是异步的：API 返回 202 时命令还没跑完。若这时就记成 allowed，
// 事后按 allowed 筛"装成功过什么"会把失败的任务也算进去。
func TestAuditorPendingVsAllowed(t *testing.T) {
	a, err := NewAuditor(AuditOptions{})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{
		Action: ActionInstall, Target: "php", Version: "8.3",
		Outcome: AuditPending, TaskID: "task-1", User: "admin",
	})
	pending := a.Query(AuditFilter{Outcome: AuditPending, Limit: 10})
	if len(pending) != 1 {
		t.Fatalf("应有 pending 记录")
	}
	// pending 不算"已改系统"。
	if pending[0].SystemChange {
		t.Error("pending 不应标记为系统变更")
	}
	// 终态由任务结束时补记，两者通过 TaskID 关联。
	a.Record(AuditEvent{
		Action: ActionInstall, Target: "php", Version: "8.3",
		Outcome: AuditAllowed, TaskID: "task-1", Strategy: StrategyOfficial,
	})
	byTask := 0
	for _, ev := range a.Query(AuditFilter{Target: "php", Limit: 10}) {
		if ev.TaskID == "task-1" {
			byTask++
		}
	}
	if byTask != 2 {
		t.Errorf("同一任务应有发起与终态两条记录，实际 %d", byTask)
	}
}

// TestAuditorQueryLimit 验证条数上限与默认值。
func TestAuditorQueryLimit(t *testing.T) {
	a, err := NewAuditor(AuditOptions{})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	for i := 0; i < MaxAuditQueryLimit+50; i++ {
		a.Record(AuditEvent{Action: ActionList, Target: "nginx"})
	}
	if got := a.Query(AuditFilter{Target: "nginx"}); len(got) != DefaultAuditQueryLimit {
		t.Errorf("未指定 Limit 时应返回默认上限 %d，实际 %d", DefaultAuditQueryLimit, len(got))
	}
	// Limit 超过硬上限时也必须被夹住，避免一次拉爆内存。
	if got := a.Query(AuditFilter{Target: "nginx", Limit: 1 << 20}); len(got) > MaxAuditQueryLimit {
		t.Errorf("Limit 应被夹到 %d，实际 %d", MaxAuditQueryLimit, len(got))
	}
	if got := a.Query(AuditFilter{Target: "nginx", Limit: 5}); len(got) != 5 {
		t.Errorf("Limit=5 应返回 5 条，实际 %d", len(got))
	}
}

// TestAuditorRingCapacity 验证环形缓冲不会无限增长。
func TestAuditorRingCapacity(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 16})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	for i := 0; i < 100; i++ {
		a.Record(AuditEvent{Action: ActionList, Target: "nginx"})
	}
	got := a.Query(AuditFilter{Target: "nginx", Limit: MaxAuditQueryLimit})
	if len(got) != 16 {
		t.Errorf("容量 16 时应只保留 16 条，实际 %d", len(got))
	}
}

// TestAuditorStats 验证统计。
func TestAuditorStats(t *testing.T) {
	a, err := NewAuditor(AuditOptions{})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{Action: ActionInstall, Target: "nginx", Outcome: AuditAllowed})
	a.Record(AuditEvent{Action: ActionInstall, Target: "php", Outcome: AuditFailed, Reason: "x"})
	a.Record(AuditEvent{Action: ActionUninstall, Target: "nginx", Outcome: AuditAllowed})
	a.Record(AuditEvent{Action: ActionInstall, Target: "redis", Outcome: AuditDenied})
	a.Record(AuditEvent{Action: ActionInstall, Target: "mysql", Outcome: AuditPending})

	st := a.Stats()
	if st.Total != 5 {
		t.Errorf("Total = %d", st.Total)
	}
	if st.Failed != 1 || st.Denied != 1 || st.Pending != 1 {
		t.Errorf("分类统计错误: %+v", st)
	}
	// Installed 只统计**成功**的安装：pending 与 failed 都不能计入，
	// 否则"装成功过什么"的问题会被失败任务污染。
	if st.Installed != 1 {
		t.Errorf("Installed = %d，应只统计成功的安装", st.Installed)
	}
	if st.Uninstalled != 1 {
		t.Errorf("Uninstalled = %d", st.Uninstalled)
	}
	if st.Retained != 5 {
		t.Errorf("Retained = %d", st.Retained)
	}
	if st.Capacity != DefaultAuditCapacity {
		t.Errorf("Capacity = %d", st.Capacity)
	}
}
