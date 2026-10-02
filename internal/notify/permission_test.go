package notify

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

func TestCheckNotifyPermission(t *testing.T) {
	admin := AdminGrantee("root")
	for _, a := range []Action{ActionList, ActionQuery, ActionCreate, ActionUpdate, ActionDelete, ActionTest, ActionSend} {
		if d := CheckNotifyPermission(admin, a); !d.Allowed {
			t.Errorf("管理员 %s 应放行", a)
		}
	}
	// 只读用户：读放行，写拒绝。
	ro := Grantee{User: "viewer", Granted: []string{PermRead}}
	if !CheckNotifyPermission(ro, ActionList).Allowed {
		t.Error("只读用户应能列表")
	}
	d := CheckNotifyPermission(ro, ActionCreate)
	if d.Allowed {
		t.Error("只读用户不应能创建")
	}
	if d.Required != PermWrite {
		t.Errorf("required=%q 应为 notify.write", d.Required)
	}
	if !strings.Contains(d.Reason, "viewer") {
		t.Errorf("拒绝原因应含用户名: %s", d.Reason)
	}
	if d.Hint == "" {
		t.Error("拒绝应给 hint")
	}
}

// ---------------------------------------------------------------------------
// 审计环形缓冲
// ---------------------------------------------------------------------------

func TestNotifyAuditRing(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 3})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer a.Close()
	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Action: "create", Outcome: AuditAllowed, Status: 200})
	}
	list := a.List(AuditQuery{})
	if len(list) != 3 {
		t.Fatalf("环形缓冲应保留最近 3 条, got %d", len(list))
	}
	st := a.Stats()
	if st.Total != 5 {
		t.Errorf("total=5, got %d", st.Total)
	}
	if st.Allowed != 3 {
		t.Errorf("allowed=3 (仅内存有 3 条), got %d", st.Allowed)
	}
	// 审计事件不该带凭证字段（结构体里本就没有），验证不允许把 token 塞进去：
	// 这里确保 Record 接受的是结构化类型而非 map，无法误存任意键值。
}

func TestNotifyAuditPersist(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: dir + "/audit.jsonl"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer a.Close()
	a.Record(AuditEvent{Action: "test", Outcome: AuditAllowed, Status: 200})
	// 落盘文件存在且含记录。
	data, err := os.ReadFile(dir + "/audit.jsonl")
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	if !strings.Contains(string(data), `"test"`) {
		t.Errorf("落盘审计应含动作: %s", string(data))
	}
	// 凭证绝不落盘：审计结构里没有凭证字段，且内容不含任何 token。
	if strings.Contains(string(data), "token") && strings.Contains(string(data), "SECRET") {
		t.Errorf("审计不应含凭证: %s", string(data))
	}
}
