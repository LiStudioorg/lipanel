package file

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ============================================================================
// 审计测试（阶段四 4.2）
// ============================================================================

func TestAuditorRecordsEvent(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 10})
	if err != nil {
		t.Fatal(err)
	}
	a.Record(AuditEvent{
		User:   "admin",
		Action: ActionDelete,
		Path:   "/tmp/x.txt",
		Status: 200,
	})

	events := a.Query(AuditFilter{})
	if len(events) != 1 {
		t.Fatalf("应有 1 条记录，实际 %d", len(events))
	}
	ev := events[0]
	if ev.Kind != KindFile {
		t.Errorf("Kind 应为 file，实际 %q", ev.Kind)
	}
	if ev.Source != SourceCore {
		t.Errorf("Source 应为 core（核心自带，不能伪造成插件），实际 %q", ev.Source)
	}
	if ev.Outcome != AuditAllowed {
		t.Errorf("未指定 outcome 时应默认为 allowed，实际 %q", ev.Outcome)
	}
	if ev.Seq == 0 || ev.Time == "" {
		t.Errorf("Seq/Time 应被自动填充，实际 seq=%d time=%q", ev.Seq, ev.Time)
	}
}

func TestAuditorRingBufferEvictsOldest(t *testing.T) {
	a, err := NewAuditor(AuditOptions{Capacity: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Action: ActionWrite, Path: "/p" + string(rune('0'+i))})
	}
	events := a.Query(AuditFilter{})
	if len(events) != 3 {
		t.Fatalf("环形缓冲应保留 3 条，实际 %d", len(events))
	}
	// 查询按时间倒序：最新的是 p4，最旧的 p2 已被淘汰。
	if events[0].Path != "/p4" || events[2].Path != "/p2" {
		t.Fatalf("淘汰顺序不正确: %v", []string{events[0].Path, events[1].Path, events[2].Path})
	}
	if st := a.Stats(); st.Total != 5 || st.Retained != 3 {
		t.Fatalf("统计应为 total=5 retained=3，实际 %+v", st)
	}
}

func TestAuditorOutcomeCounters(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 10})
	a.Record(AuditEvent{Action: ActionDelete, Outcome: AuditAllowed})
	a.Record(AuditEvent{Action: ActionDelete, Outcome: AuditDenied})
	a.Record(AuditEvent{Action: ActionDelete, Outcome: AuditFailed})
	a.Record(AuditEvent{Action: ActionDelete, Outcome: AuditDenied})

	st := a.Stats()
	if st.Denied != 2 || st.Failed != 1 {
		t.Fatalf("denied/failed 计数不符: %+v", st)
	}
}

func TestAuditorFilter(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 50})
	a.Record(AuditEvent{User: "admin", Action: ActionWrite, Path: "/a.txt", Outcome: AuditAllowed})
	a.Record(AuditEvent{User: "bob", Action: ActionDelete, Path: "/b.txt", Outcome: AuditDenied})
	a.Record(AuditEvent{User: "admin", Action: ActionDelete, Path: "/c.txt", Outcome: AuditAllowed})

	cases := []struct {
		name   string
		filter AuditFilter
		want   int
	}{
		{"无过滤", AuditFilter{}, 3},
		{"按用户", AuditFilter{User: "admin"}, 2},
		{"按动作", AuditFilter{Action: ActionDelete}, 2},
		{"按结果", AuditFilter{Outcome: AuditDenied}, 1},
		{"按路径子串", AuditFilter{Path: "b.txt"}, 1},
		{"组合", AuditFilter{User: "admin", Action: ActionDelete}, 1},
		{"无匹配", AuditFilter{User: "nobody"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(a.Query(tc.filter)); got != tc.want {
				t.Fatalf("应返回 %d 条，实际 %d", tc.want, got)
			}
		})
	}
}

func TestAuditorQueryLimitClamp(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 2000})
	for i := 0; i < 1500; i++ {
		a.Record(AuditEvent{Action: ActionWrite})
	}
	if got := len(a.Query(AuditFilter{Limit: 10})); got != 10 {
		t.Fatalf("Limit=10 应返回 10 条，实际 %d", got)
	}
	if got := len(a.Query(AuditFilter{Limit: 999999})); got != MaxAuditQueryLimit {
		t.Fatalf("超大的 Limit 应被夹到 %d，实际 %d", MaxAuditQueryLimit, got)
	}
	if got := len(a.Query(AuditFilter{Limit: -1})); got != DefaultAuditQueryLimit {
		t.Fatalf("非法 Limit 应用默认值 %d，实际 %d", DefaultAuditQueryLimit, got)
	}
}

func TestAuditorPersistsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.jsonl")
	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Record(AuditEvent{User: "admin", Action: ActionUpload, Path: "/x.txt", Status: 200, Bytes: 42})
	a.Record(AuditEvent{User: "admin", Action: ActionDelete, Path: "/y.txt", Status: 200})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("应有 2 行 JSONL，实际 %d: %s", len(lines), data)
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("第一行不是合法 JSON: %v", err)
	}
	if ev.Action != ActionUpload || ev.Bytes != 42 || ev.Kind != KindFile {
		t.Fatalf("落盘字段不完整: %+v", ev)
	}

	// 文件权限必须是 0600：审计里含操作者与真实路径。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("审计文件权限应为 0600，实际 %04o", info.Mode().Perm())
	}
}

func TestAuditorAppendsNeverTruncates(t *testing.T) {
	// 与插件/服务审计共用同一个 -audit-log 文件：
	// 打开时必须是追加写，绝不能覆盖别人的历史记录。
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"kind":"plugin","plugin":"sysinfo"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	a.Record(AuditEvent{Action: ActionWrite, Path: "/x"})
	_ = a.Close()

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"kind":"plugin"`) {
		t.Fatal("打开审计文件时覆盖了已有内容（必须是追加写）")
	}
	if !strings.Contains(string(data), `"kind":"file"`) {
		t.Fatal("新记录未写入")
	}
}

func TestNewAuditorFailsOnBadPath(t *testing.T) {
	// 用户显式配了 -audit-log 却因目录不可写而悄悄不记录，是最糟的失败方式：
	// 构造阶段必须直接报错，而不是静默降级。
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditor(AuditOptions{Path: filepath.Join(blocker, "audit.jsonl")}); err == nil {
		t.Fatal("路径不可用时应构造失败")
	}
}

func TestAuditorConcurrentRecord(t *testing.T) {
	// 并发安全由 -race 验证；这里同时检查计数不丢。
	a, err := NewAuditor(AuditOptions{Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				a.Record(AuditEvent{Action: ActionWrite, Path: "/p"})
			}
		}(i)
	}
	wg.Wait()

	if st := a.Stats(); st.Total != 500 {
		t.Fatalf("应记录 500 条，实际 %d", st.Total)
	}
}

func TestAuditorExportJSONL(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 10})
	a.Record(AuditEvent{Action: ActionWrite, Path: "/1"})
	a.Record(AuditEvent{Action: ActionWrite, Path: "/2"})

	var buf bytes.Buffer
	if err := a.ExportAuditJSONL(&buf); err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("应导出 2 行，实际 %d", len(lines))
	}
	// 导出按 Seq 正序（阅读顺序），与 Query 的倒序不同——这是刻意的。
	var first AuditEvent
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.Path != "/1" {
		t.Fatalf("导出应为正序，首条是 %q", first.Path)
	}
}

func TestAuditorNilSafety(t *testing.T) {
	// Manager 允许不注入审计器（测试便利）。此时所有方法都必须是安全的空操作。
	var a *Auditor
	a.Record(AuditEvent{Action: ActionWrite}) // 不应 panic
	if got := a.Query(AuditFilter{}); len(got) != 0 {
		t.Fatalf("nil 审计器应返回空切片，实际 %v", got)
	}
	if st := a.Stats(); st.Total != 0 {
		t.Fatalf("nil 审计器统计应全为 0，实际 %+v", st)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("nil 审计器 Close 应返回 nil，实际 %v", err)
	}
}

func TestManagerAuditsNothingByDefault(t *testing.T) {
	// Manager 未注入审计器时，操作照常可用（审计是旁路能力，
	// 它的缺失不该让文件管理不可用）。
	root := t.TempDir()
	m, err := NewManager(ManagerOptions{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Mkdir(filepath.Join(root, "d"), false); err != nil {
		t.Fatalf("未注入审计器时操作应正常: %v", err)
	}
	if m.Auditor() != nil {
		t.Fatal("未注入时 Auditor() 应为 nil")
	}
}
