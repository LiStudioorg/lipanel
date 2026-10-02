package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkLogFile 在临时目录写一个日志文件并返回路径。
func mkLogFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写测试日志失败: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// 文件日志读取与过滤
// ---------------------------------------------------------------------------

func TestReadFileBasic(t *testing.T) {
	dir := t.TempDir()
	p := mkLogFile(t, dir, "access.log", strings.Join([]string{
		"GET / 200",
		"GET /health 200",
		"[error] db down",
		"POST /login 302",
		"[error] cache miss",
	}, "\n")+"\n")

	res := readFile(context.Background(), p, 100, "", "")
	if len(res.Entries) != 5 {
		t.Fatalf("应读到 5 行, got %d", len(res.Entries))
	}
	if res.Scanned != 5 {
		t.Errorf("scanned=%d 应为 5", res.Scanned)
	}

	// 关键词过滤。
	res = readFile(context.Background(), p, 100, "error", "")
	if len(res.Entries) != 2 {
		t.Fatalf("关键词 error 应命中 2 行, got %d", len(res.Entries))
	}
	for _, e := range res.Entries {
		if !strings.Contains(e.Line, "error") {
			t.Errorf("命中行不包含关键词: %q", e.Line)
		}
	}

	// 行数截断（保留最近 lines 行后再过滤）。
	res = readFile(context.Background(), p, 2, "", "")
	if len(res.Entries) != 2 || res.Entries[0].Line != "POST /login 302" {
		t.Fatalf("截断后应剩最近2行, got %v", res.Entries)
	}
	if !res.Truncated {
		t.Error("应标记 truncated")
	}
}

func TestReadFileLevelFilter(t *testing.T) {
	dir := t.TempDir()
	p := mkLogFile(t, dir, "syslog", strings.Join([]string{
		"[info] boot ok",
		"[error] crash",
		"[debug] detail",
		"GET /health 200", // 无法识别级别
	}, "\n")+"\n")

	// 级别过滤 + KeepUnknown=true：保留 error 与无关行。
	res := readFile(context.Background(), p, 100, "", "error")
	if len(res.Entries) != 2 {
		t.Fatalf("error 级过滤应得 2 行([error]+无关行), got %d: %v", len(res.Entries), res.Entries)
	}
}

func TestReadFileNonexistent(t *testing.T) {
	res := readFile(context.Background(), filepath.Join(t.TempDir(), "nope.log"), 100, "", "")
	if res.Entries == nil {
		t.Error("读不存在文件应返回空（而非 nil 触发 panic）")
	}
}

// ---------------------------------------------------------------------------
// 源探测与白名单
// ---------------------------------------------------------------------------

func TestProbeFileWhitelist(t *testing.T) {
	dir := t.TempDir()
	p := mkLogFile(t, dir, "access.log", "x\n")

	// 合法：父目录正是允许目录。
	r := probeFile(p, "access.log", dir)
	if !r.available {
		t.Fatalf("合法文件应可用: %+v", r)
	}

	// 父目录不匹配（白名单拒绝）。
	r2 := probeFile(filepath.Join(dir, "sub", "access.log"), "x", dir)
	if r2.available {
		t.Error("父目录不符应被拒")
	}

	// 不存在。
	r3 := probeFile(filepath.Join(dir, "missing.log"), "x", dir)
	if r3.available {
		t.Error("不存在文件应不可用")
	}
	if r3.reason == "" {
		t.Error("不可用时应给原因")
	}
}

func TestSourcesRegistered(t *testing.T) {
	m, err := New(ManagerOptions{NginxLogsDir: t.TempDir()})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	sources := m.Sources()
	ids := map[string]bool{}
	for _, s := range sources {
		ids[s.ID] = true
		if s.ID == "" {
			t.Error("日志源 ID 不能为空")
		}
	}
	for _, want := range []string{SourceIDSystem, SourceIDNginxAcc, SourceIDNginxErr} {
		if !ids[want] {
			t.Errorf("缺少日志源 %s", want)
		}
	}
}

func TestNginxSourcesAvailableWithLogsDir(t *testing.T) {
	dir := t.TempDir()
	mkLogFile(t, dir, "access.log", "GET / 200\n")
	mkLogFile(t, dir, "error.log", "[error] bad\n")

	m, err := New(ManagerOptions{NginxLogsDir: dir})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for _, sid := range []string{SourceIDNginxAcc, SourceIDNginxErr} {
		if !m.SourceAvailable(sid) {
			t.Errorf("%s 应有日志目录而可用", sid)
		}
	}

	// 查询 nginx-access 走 / 过滤。
	res, err := m.Query(context.Background(), Query{SourceID: SourceIDNginxAcc, Lines: 10})
	if err != nil {
		t.Fatalf("查询 nginx-access 失败: %v", err)
	}
	if len(res.Entries) != 1 || !strings.Contains(res.Entries[0].Line, "GET") {
		t.Errorf("nginx-access 查询结果不符: %v", res.Entries)
	}
}

func TestNginxSourcesUnavailableNoLogsDir(t *testing.T) {
	// 不配置 nginx 目录 → nginx 源不可用，但接口/Manager 仍正常。
	m, err := New(ManagerOptions{})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for _, sid := range []string{SourceIDNginxAcc, SourceIDNginxErr} {
		if m.SourceAvailable(sid) {
			t.Errorf("%s 无目录时应不可用", sid)
		}
	}
	if m.SourceAvailable(SourceIDSystem) == false {
		// 本机有 journalctl 就可用；无则不可用。不强行断言。
	}
}

func TestQueryUnknownSource(t *testing.T) {
	m, _ := New(ManagerOptions{})
	_, err := m.Query(context.Background(), Query{SourceID: "totally-bogus"})
	if err == nil {
		t.Fatal("未知日志源应报错")
	}
	if !strings.Contains(err.Error(), "不存在") {
		t.Errorf("错误应说明不存在: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 审计环形缓冲与落盘
// ---------------------------------------------------------------------------

func TestAuditorRingAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAuditor(AuditOptions{Capacity: 5, Path: path})
	if err != nil {
		t.Fatalf("构造审计失败: %v", err)
	}
	defer a.Close()

	// 写入 8 条，环形缓冲容量 5。
	for i := 0; i < 8; i++ {
		a.Record(AuditEvent{Action: "query", Outcome: AuditAllowed, Status: 200, Returned: i})
	}

	list := a.List(AuditQuery{})
	if len(list) != 5 {
		t.Fatalf("环形缓冲应保留最近 5 条, got %d", len(list))
	}
	// 新的在前：第一条应为第 7 次（Returned=7）。
	if list[0].Returned != 7 {
		t.Errorf("第一条应为最新（Returned=7）, got %d", list[0].Returned)
	}

	st := a.Stats()
	if st.Total != 8 {
		t.Errorf("total=8, got %d", st.Total)
	}

	// outcome 过滤。
	denied := a.List(AuditQuery{Outcome: AuditDenied})
	if len(denied) != 0 {
		t.Errorf("全 allowed 时 denied 应为 0, got %d", len(denied))
	}

	// 落盘验证。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	if lines := strings.Count(string(data), "\n"); lines != 8 {
		t.Errorf("落盘应 8 行, got %d", lines)
	}
}

func TestAuditStatsCounts(t *testing.T) {
	a, _ := NewAuditor(AuditOptions{Capacity: 10})
	defer a.Close()
	a.Record(AuditEvent{Outcome: AuditAllowed})
	a.Record(AuditEvent{Outcome: AuditDenied})
	a.Record(AuditEvent{Outcome: AuditFailed})
	st := a.Stats()
	if st.Allowed != 1 || st.Denied != 1 || st.Failed != 1 {
		t.Errorf("统计不符: %+v", st)
	}
}

// ---------------------------------------------------------------------------
// Manager 查询收敛与 unavailable
// ---------------------------------------------------------------------------

func TestQueryLinesClamped(t *testing.T) {
	dir := t.TempDir()
	// 20 行。
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = "line " + string(rune('a'+i))
	}
	mkLogFile(t, dir, "access.log", strings.Join(lines, "\n"))

	m, err := New(ManagerOptions{NginxLogsDir: dir})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	res, err := m.Query(context.Background(), Query{SourceID: SourceIDNginxAcc, Lines: -5})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	// lines<=0 回落到默认 100，20 行全部返回。
	if len(res.Entries) != 20 {
		t.Errorf("应返回 20 行（clamp 后 100 上限内）, got %d", len(res.Entries))
	}
}
