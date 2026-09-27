package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lipanel/internal/plugin"
)

// ============================================================================
// 插件安装接口与外部插件资源路由测试
// ============================================================================
//
// 本文件锁定四类接口契约（都是**只有这一层才能验证**的）：
//
//	① 路由注册顺序：/api/plugins/install 不能被 {id} 通配吃掉
//	② 鉴权：安装接口必须登录；未登录不得写入任何字节
//	③ 二次确认：不带 confirm 返回 428，且**不安装**
//	④ **外部插件资源路由必须在 SPA 兜底之前**
//	   （否则浏览器拿到 HTML 并按 ESM 解析 → P0 同款白屏）

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

type installTestEnv struct {
	server    *Server
	manager   *plugin.Manager
	pluginDir string
}

// newInstallTestServer 构造一个带外部插件目录的测试 Server。
func newInstallTestServer(t *testing.T) *installTestEnv {
	t.Helper()

	pluginDir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("创建插件目录失败: %v", err)
	}

	mgr, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		DisableWatcher: true,
		PluginDir:      pluginDir,
	})
	if err != nil {
		t.Fatalf("构造插件管理器失败: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	s := newAuthedTestServer(t)
	s.plugins = mgr
	rebuildTestRoutes(s)

	return &installTestEnv{server: s, manager: mgr, pluginDir: pluginDir}
}

// uploadPlugin 以 multipart 上传一个插件包。
//
// confirm/overwrite 决定是否带上相应的表单字段。
func (e *installTestEnv) upload(t *testing.T, filename string, content []byte,
	confirm, overwrite bool, cookie *http.Cookie) *httptest.ResponseRecorder {

	t.Helper()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("创建表单文件失败: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("写入表单失败: %v", err)
	}
	if confirm {
		_ = mw.WriteField("confirm", "true")
	}
	if overwrite {
		_ = mw.WriteField("overwrite", "true")
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("关闭 multipart 失败: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/install", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, req)
	return rec
}

// makePluginZip 构造一个最小的合法插件包。
func makePluginZip(t *testing.T, id string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, _ := zw.Create(plugin.DescriptorFileName)
	_, _ = w.Write([]byte(`{
	  "apiVersion": "1",
	  "id": "` + id + `",
	  "name": "测试插件",
	  "version": "1.0.0",
	  "permissions": ["system.read"],
	  "frontend": {
	    "entry": "/plugin-assets/` + id + `/plugin.js",
	    "nav_title": "测试"
	  }
	}`))

	w, _ = zw.Create("assets/plugin.js")
	_, _ = w.Write([]byte("export default { component: { setup() { return () => null } } }"))

	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// ① 路由注册顺序
// ---------------------------------------------------------------------------

// ########## /api/plugins/install 不能被 {id} 通配吃掉 ##########
//
// 若晚于 "/api/plugins/{id}/" 注册，安装请求会被当成
// "插件 ID = install 的子路径请求"转发出去，用户看到的是
// 404「插件不存在」——一个与真实原因毫无关系的错误。
func TestPluginInstallRouteNotShadowedByWildcard(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "x.zip", makePluginZip(t, "aaaa"), true, false, cookie)

	// 绝不能是"插件不存在"（那说明被转发走了）。
	if rec.Code == http.StatusNotFound {
		var payload map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &payload)
		if msg, _ := payload["error"].(string); strings.Contains(msg, "插件") &&
			strings.Contains(msg, "不存在") {
			t.Fatalf("install 被 {id} 通配路由吃掉了: %s", rec.Body.String())
		}
	}
	// 应正常安装。
	if rec.Code != http.StatusCreated {
		t.Fatalf("状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// 安装接口不能被当成插件子路径转发到插件进程。
func TestPluginInstallNotProxied(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "x.zip", makePluginZip(t, "bbbb"), true, false, cookie)

	// 代理转发成功时会带 X-Lipanel-Plugin-Proxy 之类的痕迹，
	// 且一定是 503（插件未运行）或 404（插件不存在）。
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("install 被转发到插件代理了: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ② 鉴权
// ---------------------------------------------------------------------------

func TestPluginInstallRequiresAuth(t *testing.T) {
	env := newInstallTestServer(t)

	rec := env.upload(t, "x.zip", makePluginZip(t, "cccc"), true, false, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录安装应返回 401，实际 %d", rec.Code)
	}

	// ########## 未授权的请求不得写入任何字节 ##########
	//
	// 权限检查必须在读取请求体之前完成。若先落盘再判权限，
	// 一个未登录的请求就能在服务器上留下文件。
	assertPluginDirEmpty(t, env.pluginDir)

	// 也不应有插件被注册。
	if len(env.manager.List()) != 0 {
		t.Error("未授权的请求产生了注册项")
	}
}

// ---------------------------------------------------------------------------
// ③ 二次确认
// ---------------------------------------------------------------------------

// ########## 不带 confirm 必须 428，且不能真的安装 ##########
//
// 安装会往服务器写将被执行的代码。前端弹窗只是体验，
// 服务端必须自己拦得住。
func TestPluginInstallRequiresConfirm(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "x.zip", makePluginZip(t, "dddd"), false, false, cookie)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("缺少 confirm 应返回 428，实际 %d, body = %s", rec.Code, rec.Body.String())
	}
	// 响应头让前端能程序化识别"需要确认"。
	if rec.Header().Get("X-Lipanel-Confirm-Required") != "true" {
		t.Error("缺少 X-Lipanel-Confirm-Required 响应头")
	}

	// ########## 关键：目录必须是空的 ##########
	assertPluginDirEmpty(t, env.pluginDir)
	if len(env.manager.List()) != 0 {
		t.Error("未确认的请求产生了注册项")
	}
}

// 通过查询参数传 confirm=true 也应被接受（便于 curl 调试）。
func TestPluginInstallConfirmViaQuery(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "q.zip")
	_, _ = fw.Write(makePluginZip(t, "query-confirm"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/install?confirm=true", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("查询参数 confirm=true 应被接受，实际 %d, body = %s",
			rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 安装的各种失败场景
// ---------------------------------------------------------------------------

func TestPluginInstallMissingFile(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("confirm", "true") // 有 confirm，但没有文件
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/install", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少文件应返回 400，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "file") {
		t.Errorf("错误应说明字段名: %s", rec.Body.String())
	}
}

func TestPluginInstallUnsupportedFormat(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "plugin.rar", []byte("junk"), true, false, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不支持的格式应返回 400，实际 %d, body = %s", rec.Code, rec.Body.String())
	}
	assertPluginDirEmpty(t, env.pluginDir)
}

// ########## ID 与内置插件冲突必须返回 409 ##########
func TestPluginInstallRejectsBuiltinConflict(t *testing.T) {
	env := newInstallTestServer(t)

	// 注册一个内置插件占住 ID。
	const builtinID = "builtinconf"
	if err := env.manager.Register(plugin.Descriptor{
		ID: builtinID, Name: "内置", Version: "1.0.0",
		Builtin: true, Mode: plugin.ModeManaged,
		Permissions: []string{"system.read"},
	}); err != nil {
		t.Fatal(err)
	}

	cookie := login(t, env.server)

	// 即便带 overwrite=true 也必须拒绝。
	rec := env.upload(t, "evil.zip", makePluginZip(t, builtinID), true, true, cookie)

	if rec.Code != http.StatusConflict {
		t.Fatalf("与内置插件冲突应返回 409，实际 %d, body = %s",
			rec.Code, rec.Body.String())
	}

	var payload map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	hint, _ := payload["hint"].(string)
	if hint == "" {
		t.Error("409 应给出可行动的 hint")
	}

	// ########## 内置插件必须完好无损 ##########
	st, err := env.manager.Get(builtinID)
	if err != nil {
		t.Fatalf("内置插件消失了: %v", err)
	}
	if !st.Builtin || st.External {
		t.Error("内置插件被外部插件覆盖了")
	}
	if st.Name != "内置" {
		t.Errorf("内置插件的名字被改成了 %q", st.Name)
	}
}

// zip slip 的包通过接口上传必须返回 400。
func TestPluginInstallRejectsZipSlip(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(plugin.DescriptorFileName)
	_, _ = w.Write([]byte(`{"apiVersion":"1","id":"evil","name":"x","version":"1.0.0"}`))
	w, _ = zw.Create("../../../pwned.txt")
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()

	rec := env.upload(t, "evil.zip", buf.Bytes(), true, false, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("zip slip 应返回 400，实际 %d, body = %s", rec.Code, rec.Body.String())
	}

	// 越界文件绝不能存在。
	outside := filepath.Join(filepath.Dir(env.pluginDir), "pwned.txt")
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("越界文件被写出了 —— zip slip 防护失效")
	}
	assertPluginDirEmpty(t, env.pluginDir)
}

// apiVersion 不兼容应返回 422（包本身的问题，不是请求语法问题）。
func TestPluginInstallIncompatibleAPIVersion(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(plugin.DescriptorFileName)
	_, _ = w.Write([]byte(`{"apiVersion":"99","id":"oldver","name":"x","version":"1.0.0"}`))
	_ = zw.Close()

	rec := env.upload(t, "old.zip", buf.Bytes(), true, false, cookie)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("apiVersion 不兼容应返回 422，实际 %d, body = %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "hint") {
		t.Errorf("应给出 hint: %s", rec.Body.String())
	}
}

// 正常安装后：注册成功、资源可访问、状态为 stopped。
func TestPluginInstallSuccessResponse(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "ok.zip", makePluginZip(t, "okplugin"), true, false, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Installed   bool   `json:"installed"`
		ID          string `json:"id"`
		Mode        string `json:"mode"`
		AutoStarted bool   `json:"auto_started"`
		Hint        string `json:"hint"`
		DirName     string `json:"dir_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}

	if !payload.Installed || payload.ID != "okplugin" {
		t.Errorf("响应不符: %+v", payload)
	}
	// ########## auto_started 必须显式为 false ##########
	//
	// 前端据此告诉用户"装好了但没启动"，而不是让他以为能用了。
	if payload.AutoStarted {
		t.Error("auto_started 必须为 false（不允许自动执行上传的二进制）")
	}
	if payload.Hint == "" {
		t.Error("应给出下一步提示")
	}
	// 不能泄露服务器绝对路径。
	if strings.Contains(rec.Body.String(), env.pluginDir) {
		t.Errorf("响应泄露了服务器路径: %s", rec.Body.String())
	}

	// 插件已注册但未启动。
	st, err := env.manager.Get("okplugin")
	if err != nil {
		t.Fatalf("插件未注册: %v", err)
	}
	if st.State != plugin.StateStopped {
		t.Errorf("State = %q，期望 %q", st.State, plugin.StateStopped)
	}
}

// ---------------------------------------------------------------------------
// ④ 外部插件资源路由（P0 同类问题的防线）
// ---------------------------------------------------------------------------

// ########## 外部插件资源必须返回 JS，而不是 HTML ##########
//
// 这是本文件最重要的一条测试，因为它对应一次**真实发生过的 P0 白屏**：
//
//	v0.2.0 发布后页面白屏，报错是
//	"Failed to load module script: Expected a JavaScript-or-Wasm
//	 module script but the server responded with a MIME type of text/html"
//	（见 开发计划.md 坑位 64）
//
// 同一个故障模式在这里会原样复现：外部插件的 /plugin-assets/<id>/plugin.js
// 若没有被专门处理，请求会落到 SPA 兜底，返回 index.html ——
// 浏览器拿到 HTML 却按 ESM 模块解析，直接拒绝执行。
//
// 因此必须有这条测试：它断言的是 **Content-Type**，而不只是状态码。
// 状态码 200 但内容是 HTML，正是这个 bug 的表现形式。
func TestExternalPluginAssetServedAsJSNotHTML(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	// 装一个外部插件。
	rec := env.upload(t, "asset.zip", makePluginZip(t, "assetplug"), true, false, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("安装失败: %d %s", rec.Code, rec.Body.String())
	}

	// 请求它的前端资源（**不带登录**：静态资源由 iframe 直接加载，
	// iframe 是 opaque origin，不会携带也不应需要会话 Cookie）。
	req := httptest.NewRequest(http.MethodGet, "/plugin-assets/assetplug/plugin.js", nil)
	assetRec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(assetRec, req)

	if assetRec.Code != http.StatusOK {
		t.Fatalf("资源状态码 = %d，期望 200", assetRec.Code)
	}

	ct := assetRec.Header().Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		t.Fatalf("########## 资源被 SPA 兜底吃掉了 ##########\n"+
			"Content-Type = %q（期望 JavaScript）。\n"+
			"浏览器会报：Failed to load module script: Expected a JavaScript-or-Wasm "+
			"module script but the server responded with a MIME type of %q —— "+
			"这正是 v0.2.0 那次 P0 白屏的同一个故障模式（坑位 64）。\n"+
			"修复方式：确保 serveExternalPluginAsset 被调用在 "+
			"spaHandler 的 index.html 兜底**之前**。", ct, ct)
	}
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q，期望包含 javascript", ct)
	}

	// 内容必须是真实的 JS，而不是 index.html。
	body := assetRec.Body.String()
	if strings.Contains(body, "<!doctype html") || strings.Contains(body, "<div id=\"app\"") {
		t.Fatal("返回的是 index.html 的内容")
	}
	if !strings.Contains(body, "export default") {
		t.Errorf("资源内容不符: %s", body)
	}
}

// 已注册但**没有** assets/ 目录的外部插件：应落到 SPA 兜底（保持原行为）。
func TestExternalAssetWithoutDirFallsThrough(t *testing.T) {
	env := newInstallTestServer(t)

	// 手动注册一个没有 assets 的外部插件（模拟手工放进目录的情况）。
	dir := filepath.Join(env.pluginDir, "noassets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, plugin.DescriptorFileName),
		[]byte(`{"apiVersion":"1","id":"noassets","name":"x","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := env.manager.LoadExternal(env.pluginDir); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/plugin-assets/noassets/plugin.js", nil)
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	// 没有资源时不做特殊处理，交回原有逻辑（SPA 兜底）。
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Error("无资源时应落到 SPA 兜底（HTML）")
	}
}

// 未注册的插件 ID：不改变既有行为（落到 SPA 兜底）。
func TestExternalAssetUnknownPluginFallsThrough(t *testing.T) {
	env := newInstallTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/plugin-assets/nosuchplugin/plugin.js", nil)
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	// 未注册的 ID 不做特殊处理。
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Error("未注册插件应落到 SPA 兜底")
	}
}

// 资源路径含 .. 必须被拒绝（不能穿越到插件目录之外）。
func TestExternalAssetRejectsTraversal(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	rec := env.upload(t, "t.zip", makePluginZip(t, "travplug"), true, false, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("安装失败: %d %s", rec.Code, rec.Body.String())
	}

	// 在插件目录里放一个"敏感文件"（位于 assets 之外）。
	secret := filepath.Join(env.pluginDir, "travplug", "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 尝试用 .. 跳出 assets 目录读到它。
	req := httptest.NewRequest(http.MethodGet, "/plugin-assets/travplug/../secret.txt", nil)
	rec2 := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec2, req)

	if strings.Contains(rec2.Body.String(), "SECRET") {
		t.Fatal("通过 .. 读到了 assets 之外的文件 —— 目录穿越")
	}
}

// 非法 ID 的资源请求不应被特殊处理。
func TestExternalAssetRejectsBadID(t *testing.T) {
	env := newInstallTestServer(t)

	// 大写、含点等非法 ID。
	for _, id := range []string{"Bad", "a.b", "1abc"} {
		req := httptest.NewRequest(http.MethodGet, "/plugin-assets/"+id+"/plugin.js", nil)
		rec := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rec, req)

		// 不应因为非法 ID 而产生 500 或特殊响应。
		if rec.Code == http.StatusInternalServerError {
			t.Errorf("非法 ID %q 导致了 500", id)
		}
	}
}

// 非 GET 方法不应被资源路由处理。
func TestExternalAssetOnlyGET(t *testing.T) {
	env := newInstallTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/plugin-assets/whatever/plugin.js", nil)
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("POST 不应被当作资源请求处理，状态码 = %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 与插件列表接口的联动
// ---------------------------------------------------------------------------

// 安装后 /api/plugins 应能看到该插件，且标记为 external。
func TestInstalledPluginAppearsInList(t *testing.T) {
	env := newInstallTestServer(t)
	cookie := login(t, env.server)

	if rec := env.upload(t, "l.zip", makePluginZip(t, "listplug"), true, false, cookie); rec.Code != http.StatusCreated {
		t.Fatalf("安装失败: %s", rec.Body.String())
	}

	rec := doJSON(t, env.server, http.MethodGet, "/api/plugins", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("列表接口状态码 = %d", rec.Code)
	}

	var payload struct {
		Plugins []struct {
			ID       string `json:"id"`
			Builtin  bool   `json:"builtin"`
			External bool   `json:"external"`
			State    string `json:"state"`
			Dir      string `json:"dir"`
		} `json:"plugins"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}

	var found bool
	for _, p := range payload.Plugins {
		if p.ID == "listplug" {
			found = true
			if p.Builtin {
				t.Error("外部插件不应标记为 builtin")
			}
			if !p.External {
				t.Error("应标记为 external")
			}
			if p.State != plugin.StateStopped {
				t.Errorf("State = %q，期望 stopped", p.State)
			}
			// ########## 不能泄露服务器路径 ##########
			if p.Dir != "" {
				t.Errorf("响应里出现了目录路径: %q", p.Dir)
			}
		}
	}
	if !found {
		t.Fatal("安装的插件未出现在列表里")
	}
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// assertPluginDirEmpty 断言插件目录为空（没有残留文件或目录）。
func assertPluginDirEmpty(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取插件目录失败: %v", err)
	}
	if len(entries) == 0 {
		return
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	t.Fatalf("插件目录应为空，实际有: %v", names)
}

