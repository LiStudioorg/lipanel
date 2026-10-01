package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lipanel/internal/backup"
	"lipanel/internal/cron"
)

// ============================================================================
// 备份接口层测试（阶段五 5.3）
// ============================================================================
//
// 这一层要验证的不是「打包对不对」（那是 internal/backup 的事），
// 而是七件接口契约：
//
//	① 路由注册顺序：固定段不能被 `{id}` 通配吃掉；
//	② 全部接口都要登录；
//	③ **恢复必须二次确认，且确认文字逐字匹配任务名，否则 428**；
//	④ 未注册路径返回 JSON 404（而不是 SPA 的 200 + HTML）；
//	⑤ **存储凭证一个字都不出现在任何响应里**；
//	⑥ 语义错误 → 正确的状态码（404/409/413/428/503 不能混）；
//	⑦ 审计如实记下"谁在什么时候把什么送到了哪里"。
//
// ########## 全程只碰隔离目录 ##########
//
// 数据目录、源白名单、恢复白名单、本地存储目录全部指向 t.TempDir()；
// cron 一律用隔离文件模式。宿主机上任何真实目录、crontab、
// 系统文件都不会被读写——这是计划里的安全红线。

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type backupTestEnv struct {
	server  *Server
	manager *backup.Manager
	dir     string
	srcDir  string
	// storeDir 是本地存储的目标目录。
	storeDir string
	// cronFile 是隔离的 crontab 文件（绝不碰系统 crontab）。
	cronFile string
}

func newBackupTestServer(t *testing.T, mut func(*backup.Options)) *backupTestEnv {
	t.Helper()
	dir := t.TempDir()

	// cron 管理器：隔离文件模式，数据目录也在临时目录里。
	cronFile := filepath.Join(dir, "crontab")
	cronMgr, err := cron.NewManager(cron.Options{
		FilePath: cronFile,
		DataDir:  filepath.Join(dir, "cron-data"),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造 cron.Manager 失败: %v", err)
	}

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "app.conf"), []byte("listen 8080;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(srcDir, "conf.d")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "extra.conf"), []byte("extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restoreRoot := filepath.Join(dir, "restore")

	opts := backup.Options{
		DataDir:      filepath.Join(dir, "backup-data"),
		SourceRoots:  []string{srcDir},
		RestoreRoots: []string{restoreRoot},
		Cron:         cronMgr,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		// 固定时钟：否则「下次执行时间」与「归档名」的断言会漂移。
		Now: func() time.Time { return time.Date(2026, 3, 5, 10, 0, 0, 0, time.Local) },
	}
	if mut != nil {
		mut(&opts)
	}
	mgr, err := backup.NewManager(opts)
	if err != nil {
		t.Fatalf("构造 backup.Manager 失败: %v", err)
	}

	base := newAuthedTestServer(t)
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     base.auth,
		WebFS:    testFS(),
		WebBuilt: true,
		Cron:     cronMgr,
		Backup:   mgr,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return &backupTestEnv{
		server: s, manager: mgr, dir: dir,
		srcDir: srcDir, storeDir: storeDir, cronFile: cronFile,
	}
}

// mustCreateStorage 建一个本地存储配置并返回其 id。
func (e *backupTestEnv) mustCreateStorage(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	rec := doJSON(t, e.server, http.MethodPost, "/api/backup/storages", map[string]any{
		"name": "本地测试", "type": "local", "path": e.storeDir,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("建存储应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	st, _ := out["storage"].(map[string]any)
	id, _ := st["id"].(string)
	if id == "" {
		t.Fatalf("响应缺少 storage.id：%v", out)
	}
	return id
}

// mustCreateTask 建一条备份任务并返回其 id 与任务名。
func (e *backupTestEnv) mustCreateTask(t *testing.T, cookie *http.Cookie, storageID string) (string, string) {
	t.Helper()
	name := "nginx 配置备份"
	rec := doJSON(t, e.server, http.MethodPost, "/api/backup/tasks", map[string]any{
		"name": name, "type": "full", "source_type": "dir",
		"source_path": e.srcDir, "storage_id": storageID,
		"expr": "0 3 * * *", "keep_policy": "count", "keep_count": 3,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("建任务应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	task, _ := out["task"].(map[string]any)
	id, _ := task["id"].(string)
	if id == "" {
		t.Fatalf("响应缺少 task.id：%v", out)
	}
	return id, name
}

// mustRun 执行一次备份并返回归档对象名。
func (e *backupTestEnv) mustRun(t *testing.T, cookie *http.Cookie, taskID string) string {
	t.Helper()
	rec := doJSON(t, e.server, http.MethodPost, "/api/backup/tasks/"+taskID+"/run", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("立即执行应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析执行响应失败: %v", err)
	}
	result, _ := out["result"].(map[string]any)
	entry, _ := result["entry"].(map[string]any)
	if entry == nil {
		t.Fatalf("执行响应缺少 entry：%v", out)
	}
	if entry["status"] != "ok" {
		t.Fatalf("执行状态 = %v, 错误 = %v", entry["status"], entry["error"])
	}
	key, _ := entry["archive_key"].(string)
	if key == "" {
		t.Fatalf("执行响应缺少 archive_key：%v", entry)
	}
	return key
}

// firstStorageIDOf 从存储列表里取出第一个 id。
func (e *backupTestEnv) firstStorageIDOf(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	rec := doJSON(t, e.server, http.MethodGet, "/api/backup/storages", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("列存储应 200，实际 %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	items, _ := out["storages"].([]any)
	if len(items) == 0 {
		t.Fatalf("存储列表为空")
	}
	first, _ := items[0].(map[string]any)
	st, _ := first["storage"].(map[string]any)
	id, _ := st["id"].(string)
	return id
}

// ---------------------------------------------------------------------------
// ① 鉴权：全部接口都要登录
// ---------------------------------------------------------------------------

func TestBackupRoutesRequireAuth(t *testing.T) {
	env := newBackupTestServer(t, nil)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/backup"},
		{http.MethodGet, "/api/backup/tasks"},
		{http.MethodPost, "/api/backup/tasks"},
		{http.MethodPut, "/api/backup/tasks/abcdef123456"},
		{http.MethodDelete, "/api/backup/tasks/abcdef123456"},
		{http.MethodPost, "/api/backup/tasks/abcdef123456/run"},
		{http.MethodGet, "/api/backup/tasks/abcdef123456/history"},
		{http.MethodGet, "/api/backup/files"},
		{http.MethodGet, "/api/backup/files/download"},
		{http.MethodDelete, "/api/backup/files"},
		{http.MethodPost, "/api/backup/restore/preview"},
		{http.MethodPost, "/api/backup/restore"},
		{http.MethodGet, "/api/backup/storages"},
		{http.MethodPost, "/api/backup/storages"},
		{http.MethodPost, "/api/backup/storages/test"},
		{http.MethodPut, "/api/backup/storages/abcdef123456"},
		{http.MethodDelete, "/api/backup/storages/abcdef123456"},
		{http.MethodGet, "/api/backup/audit"},
	}
	for _, rt := range routes {
		rec := doJSON(t, env.server, rt.method, rt.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未登录时状态码 = %d, 期望 401", rt.method, rt.path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ② 路由注册顺序：固定段不能被通配吃掉
// ---------------------------------------------------------------------------

// 固定段与通配路径并存时，固定段必须先注册。
//
// 这一条连续踩过八次（4.1~4.6、5.1、5.2），因此这里**用测试锁死**：
// 若哪天有人把 `PUT /api/backup/tasks/{id}` 挪到 `POST /api/backup/tasks` 之前，
// 或漏掉 `.../storages/test` 的固定段注册，这条用例会立刻变红。
func TestBackupFixedSegmentRoutesNotShadowed(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)

	// /api/backup/tasks 是**集合**接口，绝不能被 {id} 通配吃掉。
	rec := doJSON(t, env.server, http.MethodGet, "/api/backup/tasks", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/backup/tasks = %d, 期望 200（被 {id} 通配吃掉了？）", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["tasks"]; !ok {
		t.Fatalf("集合接口响应里没有 tasks 字段：%v", out)
	}

	// /api/backup/storages/test 必须先于 /api/backup/storages/{id}。
	stID := env.mustCreateStorage(t, cookie)
	rec = doJSON(t, env.server, http.MethodPost,
		"/api/backup/storages/test?id="+stID, map[string]any{}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/backup/storages/test = %d, 期望 200（被 {id} 通配吃掉了？）：%s",
			rec.Code, rec.Body.String())
	}

	// /api/backup/files/download 是固定段。
	rec = doJSON(t, env.server, http.MethodGet,
		"/api/backup/files/download?storage_id="+stID+"&key=nope/x.tar.gz", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/backup/files/download = %d, 期望 404（被通配吃掉了？）", rec.Code)
	}

	// /api/backup/restore/preview 是固定段。
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/restore/preview",
		map[string]any{"storage_id": stID, "key": "nope/x.tar.gz", "target_dir": env.dir}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /api/backup/restore/preview = %d, 期望 404（被通配吃掉了？）：%s",
			rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ③ 未注册路径返回 JSON 404，而不是 SPA 的 HTML
// ---------------------------------------------------------------------------

func TestBackupUnknownSubpathReturnsJSON404(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)

	rec := doJSON(t, env.server, http.MethodGet, "/api/backup/nope/whatever", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, 期望 404", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, 期望 JSON（落到 SPA 兜底了？）", ct)
	}
	if strings.Contains(rec.Body.String(), "<!DOCTYPE") {
		t.Fatalf("返回了 HTML（前端 SPA 兜底），接口层应返回 JSON 404")
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if out["available"] == nil {
		t.Fatalf("404 响应应列出可用接口，实际 %v", out)
	}
}

// 未注入管理器时返回 503（而不是 panic）。
func TestBackupUnavailableWithoutManager(t *testing.T) {
	s := newAuthedTestServer(t)
	cookie := login(t, s)

	// newAuthedTestServer 没有注入 Backup。
	for _, path := range []string{"/api/backup", "/api/backup/tasks"} {
		rec := doJSON(t, s, http.MethodGet, path, nil, cookie)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s 未注入管理器时 = %d, 期望 503", path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ④ 恢复：服务端强制的二次确认
// ---------------------------------------------------------------------------

// ########## 本模块最关键的一条用例 ##########
//
// 恢复会**覆盖**目标目录里的同名文件且不可撤销。
// 三种情况必须分别被拒：
//   · 没有 confirm
//   · confirm=true 但确认文字不对
//   · 确认文字与任务名只差一点（大小写、空格）
//
// 且拒绝时**必须什么都没发生**（目标目录里不能多出任何东西）。
func TestBackupRestoreRequiresDoubleConfirmation(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)
	taskID, taskName := env.mustCreateTask(t, cookie, stID)
	key := env.mustRun(t, cookie, taskID)

	target := filepath.Join(env.dir, "restore", "case1")

	cases := []struct {
		name        string
		body        map[string]any
		wantCode    int
		wantConfirm bool
	}{
		{
			name: "没有 confirm",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm_text": taskName},
			wantCode: http.StatusPreconditionRequired, wantConfirm: true,
		},
		{
			name: "confirm 为 false",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm": false, "confirm_text": taskName},
			wantCode: http.StatusPreconditionRequired, wantConfirm: true,
		},
		{
			name: "确认文字是别的任务名",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm": true, "confirm_text": "另一个任务"},
			wantCode: http.StatusPreconditionRequired, wantConfirm: false,
		},
		{
			name: "确认文字大小写不对",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm": true, "confirm_text": strings.ToUpper(taskName)},
			wantCode: http.StatusPreconditionRequired, wantConfirm: false,
		},
		{
			name: "确认文字带多余空格",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm": true, "confirm_text": " " + taskName + " "},
			wantCode: http.StatusPreconditionRequired, wantConfirm: false,
		},
		{
			name: "确认文字为空",
			body: map[string]any{"storage_id": stID, "key": key,
				"target_dir": target, "confirm": true, "confirm_text": ""},
			wantCode: http.StatusPreconditionRequired, wantConfirm: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, env.server, http.MethodPost, "/api/backup/restore", tc.body, cookie)
			if rec.Code != tc.wantCode {
				t.Fatalf("状态码 = %d, 期望 %d：%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantConfirm {
				if rec.Header().Get("X-Lipanel-Confirm-Required") != "true" {
					t.Fatalf("缺少 X-Lipanel-Confirm-Required 响应头")
				}
			}
			// 被拒绝的请求不能留下任何痕迹。
			if _, err := os.Stat(filepath.Join(target, "app.conf")); err == nil {
				t.Fatalf("被拒绝的恢复竟然写入了文件")
			}
		})
	}

	// 正确的确认文字必须成功。
	rec := doJSON(t, env.server, http.MethodPost, "/api/backup/restore", map[string]any{
		"storage_id": stID, "key": key, "target_dir": target,
		"confirm": true, "confirm_text": taskName,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确的确认应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(target, "app.conf"))
	if err != nil {
		t.Fatalf("恢复后的文件不存在: %v", err)
	}
	if string(got) != "listen 8080;\n" {
		t.Fatalf("恢复内容不对: %q", got)
	}
}

// 删除任务同样必须带 confirm（避免"点错一下就再也没有备份了"）。
func TestBackupDeleteTaskRequiresConfirm(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)
	taskID, _ := env.mustCreateTask(t, cookie, stID)

	rec := doJSON(t, env.server, http.MethodDelete, "/api/backup/tasks/"+taskID, nil, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("无确认删除 = %d, 期望 428：%s", rec.Code, rec.Body.String())
	}
	// 任务必须还在。
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/tasks", nil, cookie)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	tasks, _ := out["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("被拒绝的删除竟然生效了（剩 %d 条）", len(tasks))
	}

	// 带确认则成功。
	rec = doJSON(t, env.server, http.MethodDelete,
		"/api/backup/tasks/"+taskID+"?confirm=true", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("带确认删除 = %d, 期望 200：%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ⑤ 凭证绝不回显
// ---------------------------------------------------------------------------

// ########## 存储凭证是本模块最敏感的数据 ##########
//
// S3 的 SecretKey、WebDAV 的密码一旦通过接口回显，任何一次
// 浏览器缓存、日志、截图都可能泄露它。这里逐条断言：
// 列表、创建、更新、测试四个接口的响应里都不能出现密钥原文。
func TestBackupStorageNeverEchoesCredentials(t *testing.T) {
	const (
		secretKey = "wJalrXUtnFEMI-super-secret-key"
		password  = "webdav-super-secret-password"
	)
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)

	// --- 创建 S3 ---
	rec := doJSON(t, env.server, http.MethodPost, "/api/backup/storages", map[string]any{
		"name": "s3 存储", "type": "s3", "endpoint": "http://127.0.0.1:9000",
		"bucket": "backups", "region": "us-east-1",
		"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": secretKey,
		"path_style": true,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("建 S3 存储 = %d：%s", rec.Code, rec.Body.String())
	}
	assertNoSecret(t, rec.Body.String(), secretKey, "创建 S3 存储的响应")
	s3ID := extractStorageID(t, rec.Body.Bytes())

	// --- 列表 ---
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/storages", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("列存储 = %d", rec.Code)
	}
	assertNoSecret(t, rec.Body.String(), secretKey, "存储列表的响应")
	// 但要能告诉用户"密钥已经设过了"。
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Fatalf("列表应报告 has_secret=true，实际 %s", rec.Body.String())
	}
	// 尾 4 位用于人工核对。
	if !strings.Contains(rec.Body.String(), `"secret_tail":"-key"`) {
		t.Fatalf("列表应给出密钥尾 4 位，实际 %s", rec.Body.String())
	}

	// --- 更新（改名字，不带密钥）---
	rec = doJSON(t, env.server, http.MethodPut, "/api/backup/storages/"+s3ID, map[string]any{
		"name": "改名后的 s3", "type": "s3", "endpoint": "http://127.0.0.1:9000",
		"bucket": "backups", "region": "us-east-1",
		"access_key": "AKIAIOSFODNN7EXAMPLE", "path_style": true,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("改存储 = %d：%s", rec.Code, rec.Body.String())
	}
	assertNoSecret(t, rec.Body.String(), secretKey, "更新存储的响应")

	// 且改名后密钥必须还在（省略 = 不改动）。
	raw, err := env.manager.FindStorageRaw(s3ID)
	if err != nil {
		t.Fatal(err)
	}
	if raw.SecretKey != secretKey {
		t.Fatalf("改个名字把密钥改没了（%q）", raw.SecretKey)
	}

	// --- WebDAV ---
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/storages", map[string]any{
		"name": "dav", "type": "webdav", "endpoint": "http://127.0.0.1:8080/dav",
		"username": "alice", "password": password,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("建 WebDAV 存储 = %d：%s", rec.Code, rec.Body.String())
	}
	assertNoSecret(t, rec.Body.String(), password, "创建 WebDAV 存储的响应")

	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/storages", nil, cookie)
	assertNoSecret(t, rec.Body.String(), password, "存储列表的响应")
	assertNoSecret(t, rec.Body.String(), secretKey, "存储列表的响应")

	// --- 状态接口 ---
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup", nil, cookie)
	assertNoSecret(t, rec.Body.String(), secretKey, "状态接口的响应")
	assertNoSecret(t, rec.Body.String(), password, "状态接口的响应")

	// --- 审计接口 ---
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/audit?limit=200", nil, cookie)
	assertNoSecret(t, rec.Body.String(), secretKey, "审计接口的响应")
	assertNoSecret(t, rec.Body.String(), password, "审计接口的响应")
}

// assertNoSecret 断言响应体里不含凭证原文。
func assertNoSecret(t *testing.T, body, secret, where string) {
	t.Helper()
	if strings.Contains(body, secret) {
		t.Fatalf("%s 里泄露了凭证原文：%s", where, body)
	}
	// 也别泄露成 base64（Basic 认证那一份）。
	if strings.Contains(body, "Basic ") {
		t.Fatalf("%s 里出现了 Basic 认证头", where)
	}
}

func extractStorageID(t *testing.T, body []byte) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	st, _ := out["storage"].(map[string]any)
	id, _ := st["id"].(string)
	if id == "" {
		t.Fatalf("响应缺少 storage.id：%s", body)
	}
	return id
}

// ---------------------------------------------------------------------------
// ⑥ 状态码语义
// ---------------------------------------------------------------------------

func TestBackupErrorStatusCodes(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)
	taskID, _ := env.mustCreateTask(t, cookie, stID)

	t.Run("任务不存在_404", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodGet,
			"/api/backup/tasks/000000000000/history", nil, cookie)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("= %d, 期望 404：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("存储不存在_404", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodGet,
			"/api/backup/files/download?storage_id=000000000000&key=a/b.tar.gz", nil, cookie)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("= %d, 期望 404：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("存储被引用_409", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodDelete,
			"/api/backup/storages/"+stID+"?confirm=true", nil, cookie)
		if rec.Code != http.StatusConflict {
			t.Fatalf("= %d, 期望 409：%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		// 必须报出是哪些任务在用，否则用户还得自己去列表里找。
		usedBy, _ := out["used_by"].([]any)
		if len(usedBy) == 0 {
			t.Fatalf("409 响应应列出引用它的任务：%v", out)
		}
	})

	t.Run("非法表达式_400", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodPost, "/api/backup/tasks", map[string]any{
			"name": "坏表达式", "source_type": "dir", "source_path": env.srcDir,
			"storage_id": stID, "expr": "这不是 cron",
		}, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, 期望 400：%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out["field"] != "expr" {
			t.Fatalf("应指出字段是 expr，实际 %v", out["field"])
		}
	})

	t.Run("源路径在白名单外_400", func(t *testing.T) {
		outside := t.TempDir()
		rec := doJSON(t, env.server, http.MethodPost, "/api/backup/tasks", map[string]any{
			"name": "越界源", "source_type": "dir", "source_path": outside,
			"storage_id": stID, "expr": "0 3 * * *",
		}, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, 期望 400（源路径越界）：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("并发冲突_409", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodPut, "/api/backup/tasks/"+taskID, map[string]any{
			"name": "改名", "source_type": "dir", "source_path": env.srcDir,
			"storage_id": stID, "expr": "0 4 * * *",
			"expected_ids": []string{taskID, "999999999999"},
		}, cookie)
		if rec.Code != http.StatusConflict {
			t.Fatalf("= %d, 期望 409：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("恢复目标在白名单外_400", func(t *testing.T) {
		key := env.mustRun(t, cookie, taskID)
		outside := t.TempDir()
		rec := doJSON(t, env.server, http.MethodPost, "/api/backup/restore", map[string]any{
			"storage_id": stID, "key": key, "target_dir": outside,
			"confirm": true, "confirm_text": "nginx 配置备份",
		}, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, 期望 400（恢复目标越界）：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("非法分页参数_400", func(t *testing.T) {
		rec := doJSON(t, env.server, http.MethodGet,
			"/api/backup/tasks/"+taskID+"/history?limit=abc", nil, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("= %d, 期望 400：%s", rec.Code, rec.Body.String())
		}
	})
}

// 下载与删除只接受"能反查回任务"的对象名。
//
// ########## 这是一条越权防线 ##########
//
// 若接口直接拿一个对象名去存储上取，它就是一个
// 「登录即可读取桶内任意对象」的入口。这里用一个**真实存在
// 但不属于任何任务**的文件来验证：它必须被拒绝。
func TestBackupDownloadRejectsUnregisteredKey(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)

	// 在存储根目录里手工放一个"别人的文件"。
	stranger := filepath.Join(env.storeDir, "stranger-secret.tar.gz")
	if err := os.WriteFile(stranger, []byte("TOP SECRET DATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := doJSON(t, env.server, http.MethodGet,
		"/api/backup/files/download?storage_id="+stID+"&key=stranger-secret.tar.gz", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("下载不属于任何任务的对象 = %d, 期望 404：%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "TOP SECRET") {
		t.Fatalf("陌生人文件的内容被读出来了")
	}

	// 删除同理。
	rec = doJSON(t, env.server, http.MethodDelete,
		"/api/backup/files?storage_id="+stID+"&key=stranger-secret.tar.gz&confirm=true", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("删除不属于任何任务的对象 = %d, 期望 404", rec.Code)
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Fatalf("陌生人的文件被删掉了: %v", err)
	}

	// 越界的对象名必须被形态校验挡下。
	rec = doJSON(t, env.server, http.MethodGet,
		"/api/backup/files/download?storage_id="+stID+"&key=../escape.tar.gz", nil, cookie)
	if rec.Code == http.StatusOK {
		t.Fatalf("含 ../ 的对象名竟然被接受了")
	}
}

// ---------------------------------------------------------------------------
// ⑦ 正常流程：创建 → 执行 → 历史 → 清单 → 恢复
// ---------------------------------------------------------------------------

func TestBackupFullLifecycleOverHTTP(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)

	// --- 状态 ---
	rec := doJSON(t, env.server, http.MethodGet, "/api/backup", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态接口 = %d", rec.Code)
	}
	var statusOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &statusOut)
	if statusOut["status"] == nil {
		t.Fatalf("状态响应缺少 status 字段")
	}
	// 存储类型与保留策略清单由**后端**给出（前端不写死）。
	if statusOut["storage_types"] == nil || statusOut["keep_policies"] == nil {
		t.Fatalf("状态响应应列出存储类型与保留策略：%v", statusOut)
	}

	// --- 建存储 ---
	stID := env.mustCreateStorage(t, cookie)

	// --- 建任务 ---
	taskID, taskName := env.mustCreateTask(t, cookie, stID)

	// 任务视图必须带派生字段（界面靠它们显示"下次执行时间"）。
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/tasks", nil, cookie)
	var listOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &listOut)
	tasks, _ := listOut["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("任务列表 = %d 条，期望 1", len(tasks))
	}
	task0, _ := tasks[0].(map[string]any)
	if task0["valid"] != true {
		t.Fatalf("合法表达式应标记 valid=true：%v", task0["invalid_reason"])
	}
	if task0["source_exists"] != true {
		t.Fatalf("源目录存在应标记 source_exists=true")
	}
	if task0["next_run"] == nil || task0["next_run"] == "" {
		t.Fatalf("应给出下次执行时间")
	}
	if task0["human"] == nil || task0["human"] == "" {
		t.Fatalf("应给出表达式的自然语言描述")
	}

	// --- 立即执行 ---
	key := env.mustRun(t, cookie, taskID)

	// --- 历史 ---
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/tasks/"+taskID+"/history", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("历史接口 = %d：%s", rec.Code, rec.Body.String())
	}
	var histOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &histOut)
	entries, _ := histOut["entries"].([]any)
	if len(entries) == 0 {
		t.Fatalf("历史为空")
	}
	first, _ := entries[0].(map[string]any)
	if first["status"] != "ok" {
		t.Fatalf("最新历史状态 = %v", first["status"])
	}
	if first["archive_bytes"] == nil {
		t.Fatalf("历史应记录归档体积")
	}

	// --- 清单 ---
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/files", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("清单接口 = %d：%s", rec.Code, rec.Body.String())
	}
	var filesOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &filesOut)
	files, _ := filesOut["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("清单 = %d 项，期望 1", len(files))
	}
	file0, _ := files[0].(map[string]any)
	if file0["key"] != key {
		t.Fatalf("清单里的 key = %v, 期望 %s", file0["key"], key)
	}
	if file0["task_name"] != taskName {
		t.Fatalf("清单应带任务名（界面上要显示它属于哪条任务）")
	}

	// --- 下载 ---
	req := httptest.NewRequest(http.MethodGet,
		"/api/backup/files/download?storage_id="+stID+"&key="+key, nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("下载 = %d：%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Fatalf("下载内容为空")
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("下载应带 attachment 头，实际 %q", rec.Header().Get("Content-Disposition"))
	}
	body := rec.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("下载的不是 gzip 数据（魔术字节不对）")
	}

	// --- 恢复预览（只读，不落盘）---
	target := filepath.Join(env.dir, "restore", "lifecycle")
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/restore/preview", map[string]any{
		"storage_id": stID, "key": key, "target_dir": target,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("预览 = %d：%s", rec.Code, rec.Body.String())
	}
	var prevOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &prevOut)
	prev, _ := prevOut["preview"].(map[string]any)
	if prev == nil {
		t.Fatalf("预览响应缺少 preview：%v", prevOut)
	}
	if prev["confirm_text"] != taskName {
		t.Fatalf("预览应告诉前端要输入什么确认文字，实际 %v", prev["confirm_text"])
	}
	if prev["danger"] == nil || prev["danger"] == "" {
		t.Fatalf("预览必须带危险说明（前端红色警示的正文）")
	}
	if prev["total"] == nil {
		t.Fatalf("预览应给出条目数")
	}
	// 预览绝不能落盘。
	if _, err := os.Stat(filepath.Join(target, "app.conf")); err == nil {
		t.Fatalf("预览落盘了文件")
	}

	// --- 恢复 ---
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/restore", map[string]any{
		"storage_id": stID, "key": key, "target_dir": target,
		"confirm": true, "confirm_text": taskName,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("恢复 = %d：%s", rec.Code, rec.Body.String())
	}
	var resOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resOut)
	result, _ := resOut["result"].(map[string]any)
	if result["restored"] == nil {
		t.Fatalf("恢复响应应给出已恢复条目数：%v", resOut)
	}
	got, err := os.ReadFile(filepath.Join(target, "app.conf"))
	if err != nil {
		t.Fatalf("恢复后的文件不存在: %v", err)
	}
	if string(got) != "listen 8080;\n" {
		t.Fatalf("恢复内容不对: %q", got)
	}
	// 嵌套子目录也要恢复出来。
	if _, err := os.Stat(filepath.Join(target, "conf.d", "extra.conf")); err != nil {
		t.Fatalf("嵌套目录没有恢复出来: %v", err)
	}
}

// 删除单个备份文件：必须带 confirm，且不影响任务本身。
func TestBackupDeleteFileRequiresConfirmAndKeepsTask(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)
	taskID, _ := env.mustCreateTask(t, cookie, stID)
	key := env.mustRun(t, cookie, taskID)

	// 无确认。
	rec := doJSON(t, env.server, http.MethodDelete,
		"/api/backup/files?storage_id="+stID+"&key="+key, nil, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("无确认删除备份 = %d, 期望 428", rec.Code)
	}

	// 带确认。
	rec = doJSON(t, env.server, http.MethodDelete,
		"/api/backup/files?storage_id="+stID+"&key="+key+"&confirm=true", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("带确认删除备份 = %d：%s", rec.Code, rec.Body.String())
	}
	// 存储上看不到了。
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/files", nil, cookie)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	files, _ := out["files"].([]any)
	if len(files) != 0 {
		t.Fatalf("删除后清单仍有 %d 项", len(files))
	}
	// 但**任务还在**、历史也还在（删一份旧备份不该让任务消失）。
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/tasks", nil, cookie)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	tasks, _ := out["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("删掉一份备份后任务也消失了（剩 %d 条）", len(tasks))
	}
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/tasks/"+taskID+"/history", nil, cookie)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	entries, _ := out["entries"].([]any)
	if len(entries) == 0 {
		t.Fatalf("删掉一份备份后历史也没了（用户会以为它从没跑过）")
	}
}

// ---------------------------------------------------------------------------
// ⑧ 审计
// ---------------------------------------------------------------------------

// 审计必须如实记下"谁、在什么时候、对哪个任务、把什么送到了哪里"。
//
// 这是安全底线的**唯一可见证据**：出了事只有它能回答
// "是谁把数据送走的"。
func TestBackupAuditRecordsOperations(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)
	stID := env.mustCreateStorage(t, cookie)
	taskID, taskName := env.mustCreateTask(t, cookie, stID)
	key := env.mustRun(t, cookie, taskID)
	// 显式做一次列表查询，好断言"读取操作同样留痕"。
	doJSON(t, env.server, http.MethodGet, "/api/backup/tasks", nil, cookie)

	rec := doJSON(t, env.server, http.MethodGet, "/api/backup/audit?limit=200", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("审计接口 = %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	events, _ := out["events"].([]any)
	if len(events) == 0 {
		t.Fatalf("审计为空")
	}

	// 收口成可查询的形式。
	byAction := map[string]map[string]any{}
	for _, e := range events {
		ev, _ := e.(map[string]any)
		if a, ok := ev["action"].(string); ok {
			byAction[a] = ev
		}
	}
	for _, want := range []string{"create", "run", "storage_create", "list"} {
		if _, ok := byAction[want]; !ok {
			t.Fatalf("审计里缺少 %q 操作，实际有 %v", want, keysOfAny(byAction))
		}
	}

	// 执行那条必须记下归档对象名与体积（"送到了哪里"）。
	run := byAction["run"]
	if run["archive_key"] != key {
		t.Fatalf("执行审计的 archive_key = %v, 期望 %s", run["archive_key"], key)
	}
	if run["task_name"] != taskName {
		t.Fatalf("执行审计的 task_name = %v", run["task_name"])
	}
	if run["user"] != testUser {
		t.Fatalf("审计应记录操作用户，实际 %v", run["user"])
	}
	if run["client_ip"] == nil || run["client_ip"] == "" {
		t.Fatalf("审计应记录来源 IP")
	}
	if run["outcome"] != "allowed" {
		t.Fatalf("成功的执行 outcome 应为 allowed，实际 %v", run["outcome"])
	}
	if run["duration_ms"] == nil {
		t.Fatalf("审计应记录耗时")
	}

	// 被拒绝的恢复尝试也必须留痕（那是真实的信号）。
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/restore", map[string]any{
		"storage_id": stID, "key": key, "target_dir": filepath.Join(env.dir, "restore", "denied"),
		"confirm": true, "confirm_text": "错误的任务名",
	}, cookie)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("前置条件：该请求应被拒（428）")
	}

	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/audit?outcome=denied&limit=100", nil, cookie)
	var deniedOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &deniedOut)
	denied, _ := deniedOut["events"].([]any)
	if len(denied) == 0 {
		t.Fatalf("被拒绝的恢复尝试没有进审计")
	}
	found := false
	for _, e := range denied {
		ev, _ := e.(map[string]any)
		if ev["action"] == "restore" {
			found = true
			// 确认文字对不对，是一个有意义的信号。
			if ev["confirm_text_ok"] != false {
				t.Fatalf("审计应记下确认文字不匹配，实际 %v", ev["confirm_text_ok"])
			}
		}
	}
	if !found {
		t.Fatalf("审计里没有那条被拒的恢复记录")
	}

	// 审计过滤器必须真的生效。
	rec = doJSON(t, env.server, http.MethodGet, "/api/backup/audit?action=run&limit=100", nil, cookie)
	var runOut map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &runOut)
	runEvents, _ := runOut["events"].([]any)
	for _, e := range runEvents {
		ev, _ := e.(map[string]any)
		if ev["action"] != "run" {
			t.Fatalf("action=run 过滤器返回了 %v", ev["action"])
		}
	}
}

// 存储连通性测试接口：传一个尚未保存的配置也应该能测。
//
// 这是用户真正需要的顺序："先试试连得上，再决定要不要存"。
func TestBackupStorageTestWithUnsavedConfig(t *testing.T) {
	env := newBackupTestServer(t, nil)
	cookie := login(t, env.server)

	// 本地目录可以真连上。
	rec := doJSON(t, env.server, http.MethodPost, "/api/backup/storages/test", map[string]any{
		"name": "试试", "type": "local", "path": env.storeDir,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("测试未保存的本地配置 = %d：%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["ok"] != true {
		t.Fatalf("应报告 ok=true：%v", out)
	}

	// 测试必须**自己清理**留下的探测对象（不能污染目标目录）。
	entries, err := os.ReadDir(env.storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("连通性测试留下了残留文件：%v", entries)
	}

	// 连不上的地址必须如实报错（而且不能是 500）。
	rec = doJSON(t, env.server, http.MethodPost, "/api/backup/storages/test", map[string]any{
		"name": "连不上", "type": "webdav",
		"endpoint": "http://127.0.0.1:1/dav", "username": "u",
		"password": "probe-password-must-not-leak",
	}, cookie)
	if rec.Code == http.StatusOK {
		t.Fatalf("连不上的地址竟然报告成功")
	}
	if rec.Code >= 500 && rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusBadGateway {
		t.Fatalf("连通性失败的状态码 = %d（应为 502/503 这类可解释的码）", rec.Code)
	}
	// 响应里一个凭证字符都不该出现（这里用的密码很独特，
	// 因此子串误判不会发生）。
	assertNoSecret(t, rec.Body.String(), "probe-password-must-not-leak", "连通性测试失败的响应")
}

func keysOfAny(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

