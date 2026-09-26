// 操作审计（阶段三 3.3）的单元测试。
//
// 覆盖三件事：
//  1. 环形缓冲的淘汰语义（满了丢最旧、统计仍准确）；
//  2. JSONL 落盘的内容与追加语义（这是事后取证的唯一凭据）；
//  3. 失败路径不影响调用方（审计是旁路能力，写不进去也不能影响请求）。
package plugin

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// newTestAuditor 构造一个纯内存审计器。
func newTestAuditor(t *testing.T, capacity int) *Auditor {
	t.Helper()
	a, err := NewAuditor(AuditOptions{
		Capacity: capacity,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestAuditorRingBuffer 验证环形缓冲的容量与淘汰顺序。
func TestAuditorRingBuffer(t *testing.T) {
	const capacity = 5
	a := newTestAuditor(t, capacity)

	// 写入 8 条，容量只有 5：应当只保留最后 5 条（seq 4..8）。
	for i := 0; i < 8; i++ {
		a.Record(AuditEvent{
			Plugin:  "demo",
			Method:  "GET",
			Path:    "/info",
			Outcome: AuditAllowed,
			Status:  200,
		})
	}

	st := a.Stats()
	if st.Total != 8 {
		t.Errorf("Total = %d, 期望 8（累计条数不因淘汰而减少）", st.Total)
	}
	if st.Retained != capacity {
		t.Errorf("Retained = %d, 期望 %d", st.Retained, capacity)
	}
	if st.Capacity != capacity {
		t.Errorf("Capacity = %d, 期望 %d", st.Capacity, capacity)
	}

	events := a.Query(AuditFilter{})
	if len(events) != capacity {
		t.Fatalf("Query 返回 %d 条, 期望 %d", len(events), capacity)
	}
	// 最新在前，且必须是最后写入的那 5 条（seq 8,7,6,5,4）。
	for i, ev := range events {
		wantSeq := uint64(8 - i)
		if ev.Seq != wantSeq {
			t.Errorf("events[%d].Seq = %d, 期望 %d（最新在前，旧的被淘汰）", i, ev.Seq, wantSeq)
		}
	}
}

// TestAuditorCountsByOutcome 验证允许/拒绝/失败三类统计。
func TestAuditorCountsByOutcome(t *testing.T) {
	a := newTestAuditor(t, 100)

	a.Record(AuditEvent{Plugin: "p1", Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Plugin: "p1", Outcome: AuditAllowed, Status: 200})
	a.Record(AuditEvent{Plugin: "p1", Outcome: AuditDenied, Status: 403, Required: "file.read"})
	a.Record(AuditEvent{Plugin: "p2", Outcome: AuditFailed, Status: 503})
	a.Record(AuditEvent{Plugin: "p2", Outcome: AuditDenied, Status: 403, Required: "process.exec"})

	st := a.Stats()
	if st.Denied != 2 {
		t.Errorf("Denied = %d, 期望 2", st.Denied)
	}
	if st.Failed != 1 {
		t.Errorf("Failed = %d, 期望 1", st.Failed)
	}

	byPlugin := a.CountByPlugin()
	if byPlugin["p1"].Total != 3 || byPlugin["p1"].Denied != 1 {
		t.Errorf("p1 统计 = %+v, 期望 Total=3 Denied=1", byPlugin["p1"])
	}
	if byPlugin["p2"].Total != 2 || byPlugin["p2"].Denied != 1 || byPlugin["p2"].Failed != 1 {
		t.Errorf("p2 统计 = %+v, 期望 Total=2 Denied=1 Failed=1", byPlugin["p2"])
	}
}

// TestAuditorQueryFilter 验证过滤与 limit。
func TestAuditorQueryFilter(t *testing.T) {
	a := newTestAuditor(t, 100)

	for i := 0; i < 10; i++ {
		a.Record(AuditEvent{Plugin: "alpha", Outcome: AuditAllowed, Status: 200})
	}
	for i := 0; i < 3; i++ {
		a.Record(AuditEvent{Plugin: "beta", Outcome: AuditDenied, Status: 403, Required: "system.read"})
	}

	if got := a.Query(AuditFilter{Plugin: "alpha"}); len(got) != 10 {
		t.Errorf("按插件过滤 alpha 得到 %d 条, 期望 10", len(got))
	}
	if got := a.Query(AuditFilter{Plugin: "beta"}); len(got) != 3 {
		t.Errorf("按插件过滤 beta 得到 %d 条, 期望 3", len(got))
	}
	if got := a.Query(AuditFilter{Outcome: AuditDenied}); len(got) != 3 {
		t.Errorf("按结果过滤 denied 得到 %d 条, 期望 3", len(got))
	}
	if got := a.Query(AuditFilter{Plugin: "beta", Outcome: AuditAllowed}); len(got) != 0 {
		t.Errorf("beta + allowed 应为空, 实际 %d 条", len(got))
	}
	if got := a.Query(AuditFilter{Limit: 2}); len(got) != 2 {
		t.Errorf("limit=2 得到 %d 条", len(got))
	}
	// limit 超上限必须被 clamp，否则一次请求就能把整个缓冲拉走。
	if got := a.Query(AuditFilter{Limit: 999999}); len(got) != 13 {
		t.Errorf("超大 limit 应当被 clamp 到实际条数 13, 实际 %d", len(got))
	}
}

// TestAuditorPersistJSONL 验证落盘内容。
//
// 这是审计最关键的用例：文件里的每一行都必须是一条完整、可解析的 JSON，
// 且字段齐全——审计记录一旦写坏，事后取证就等于没有。
func TestAuditorPersistJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	a, err := NewAuditor(AuditOptions{
		Capacity: 10,
		Path:     path,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}

	a.Record(AuditEvent{
		Plugin:   "sysinfo",
		Method:   "GET",
		Path:     "/info",
		Required: "system.read",
		Granted:  []string{"system.read", "process.read"},
		Outcome:  AuditAllowed,
		Status:   200,
		ClientIP: "127.0.0.1",
	})
	a.Record(AuditEvent{
		Plugin:   "sysinfo",
		Method:   "GET",
		Path:     "/files",
		Required: "file.read",
		Granted:  []string{"system.read", "process.read"},
		Outcome:  AuditDenied,
		Status:   403,
		ClientIP: "127.0.0.1",
		Reason:   "插件 sysinfo 未声明权限 file.read",
	})
	if err := a.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	// 文件权限必须是 0600：审计日志含路径与插件 ID，不该被其他用户读到。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("审计文件不存在: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("审计文件权限 = %04o, 期望 0600", perm)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开审计文件失败: %v", err)
	}
	defer func() { _ = f.Close() }()

	var lines []AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("审计行不是合法 JSON: %q, err=%v", line, err)
		}
		lines = append(lines, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}

	if len(lines) != 2 {
		t.Fatalf("审计文件有 %d 行, 期望 2", len(lines))
	}

	// 放行记录。
	if lines[0].Outcome != AuditAllowed || lines[0].Status != 200 {
		t.Errorf("第 1 行 = %+v, 期望 allowed/200", lines[0])
	}
	if lines[0].Time == "" {
		t.Error("审计记录必须带时间戳")
	}
	if lines[0].Seq != 1 || lines[1].Seq != 2 {
		t.Errorf("seq 应为 1,2，实际 %d,%d", lines[0].Seq, lines[1].Seq)
	}
	if len(lines[0].Granted) != 2 {
		t.Errorf("放行记录应带上已声明权限清单，实际 %v", lines[0].Granted)
	}

	// 拒绝记录：必须能一眼看出「缺哪个权限」。
	if lines[1].Outcome != AuditDenied || lines[1].Status != 403 {
		t.Errorf("第 2 行 = %+v, 期望 denied/403", lines[1])
	}
	if lines[1].Required != "file.read" {
		t.Errorf("拒绝记录的 required = %q, 期望 file.read", lines[1].Required)
	}
	if lines[1].Reason == "" {
		t.Error("拒绝记录必须带原因")
	}
}

// TestAuditorAppendAcrossRestart 验证重复打开同一路径是追加而非覆盖。
//
// 审计日志绝不能覆盖历史记录：那等于把最有价值的证据抹掉。
func TestAuditorAppendAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	for i := 0; i < 3; i++ {
		a, err := NewAuditor(AuditOptions{Capacity: 10, Path: path, Logger: quiet})
		if err != nil {
			t.Fatalf("第 %d 次 NewAuditor 失败: %v", i, err)
		}
		a.Record(AuditEvent{Plugin: "demo", Outcome: AuditAllowed, Status: 200})
		if err := a.Close(); err != nil {
			t.Fatalf("Close 失败: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}
	n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1
	if n != 3 {
		t.Errorf("重启三次后应有 3 行（追加写入），实际 %d 行:\n%s", n, data)
	}
}

// TestAuditorBadPathFailsFast 验证落盘路径不可用时构造失败。
//
// 显式配置了 -audit-log 却因为目录不可写而静默不记录，是最糟的失败方式：
// 用户以为有审计，实际什么都没有。必须在启动阶段就报错。
func TestAuditorBadPathFailsFast(t *testing.T) {
	// 用一个「已存在的普通文件」当作目录：MkdirAll 必定失败。
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备阻塞文件失败: %v", err)
	}

	_, err := NewAuditor(AuditOptions{
		Path:   filepath.Join(blocker, "audit.jsonl"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Error("审计路径不可用时应返回错误，而不是静默降级")
	}
}

// TestAuditorConcurrentRecords 验证并发写入不丢记录、不产生 data race。
//
// 审计写入处在请求路径上，天然会被并发调用；这条用例配合 -race 使用。
func TestAuditorConcurrentRecords(t *testing.T) {
	const (
		goroutines = 8
		perRoutine = 50
	)
	a := newTestAuditor(t, goroutines*perRoutine)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perRoutine; i++ {
				a.Record(AuditEvent{Plugin: "demo", Outcome: AuditAllowed, Status: 200})
				_ = a.Query(AuditFilter{Limit: 5})
				_ = a.Stats()
			}
		}()
	}
	wg.Wait()

	st := a.Stats()
	if st.Total != goroutines*perRoutine {
		t.Errorf("Total = %d, 期望 %d（并发写入不应丢记录）", st.Total, goroutines*perRoutine)
	}
	if st.Retained != goroutines*perRoutine {
		t.Errorf("Retained = %d, 期望 %d", st.Retained, goroutines*perRoutine)
	}
}

// TestNilAuditorSafe 验证 nil 审计器的容忍度。
//
// Manager.Permissions 等方法可能返回零值 Auditor 指针，所有方法都必须
// 能安全地在 nil 上调用——否则一个"没配审计"的部署会在请求路径上 panic。
func TestNilAuditorSafe(t *testing.T) {
	var a *Auditor

	// 这些调用都不该 panic。
	a.Record(AuditEvent{Plugin: "x"})
	if got := a.Query(AuditFilter{}); got == nil {
		t.Error("nil Auditor 的 Query 应返回空切片而非 nil")
	}
	if st := a.Stats(); st.Total != 0 {
		t.Errorf("nil Auditor 的 Stats 应为零值，实际 %+v", st)
	}
	if got := a.CountByPlugin(); got == nil {
		t.Error("nil Auditor 的 CountByPlugin 应返回空 map")
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil Auditor 的 Close 应返回 nil，实际 %v", err)
	}
}

// TestExportAuditJSONL 验证导出按 seq 正序输出。
func TestExportAuditJSONL(t *testing.T) {
	a := newTestAuditor(t, 10)
	for i := 0; i < 3; i++ {
		a.Record(AuditEvent{Plugin: "demo", Outcome: AuditAllowed, Status: 200})
	}

	var sb strings.Builder
	if err := a.ExportAuditJSONL(&sb); err != nil {
		t.Fatalf("导出失败: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(sb.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("导出 %d 行, 期望 3", len(lines))
	}
	for i, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i, err)
		}
		if ev.Seq != uint64(i+1) {
			t.Errorf("第 %d 行 seq = %d, 期望 %d（导出应按 seq 正序）", i, ev.Seq, i+1)
		}
	}
}
