package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lipanel/internal/plugin"
	// 匿名导入内置插件，用于校验前端入口前缀约定。
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

// newPluginTestServer 构造一个注入了插件管理器的测试 Server。
//
// 这里不启动真实插件进程（那是 internal/plugin 的 live_test.go 的职责），
// 本文件专注验证「路由层」的行为：鉴权、状态码映射、路径裁剪与穿越拦截。
func newPluginTestServer(t *testing.T) *Server {
	t.Helper()

	mgr, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		DisableWatcher: true,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	// 注册一个外部模式插件：不会真的拉起进程，
	// 但可以把它置为 running 以验证转发路径的可用性。
	//
	// Permissions 必须显式声明（阶段三 3.3 起）：权限校验发生在
	// 「运行状态检查」之前，未声明的插件会先撞上 403，
	// 那就测不到本文件真正关心的 503 / 转发语义了。
	ext := plugin.Descriptor{
		ID:      "extplug",
		Name:    "外部插件",
		Version: "1.0.0",
		Mode:    plugin.ModeExternal,
		// 覆盖测试会用到的路径：/info 验证转发链路，
		// /files 留作权限用例的对照（见 TestPluginPermissionDenied）。
		Permissions: []string{"system.read", "file.read"},
		Frontend: plugin.Frontend{
			Entry:    "/plugin-assets/extplug/plugin.js",
			Assets:   "/plugin-assets/extplug/",
			NavTitle: "外部插件",
		},
	}
	if err := mgr.Register(ext); err != nil {
		t.Fatalf("注册插件失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.plugins = mgr
	s.pluginProxy = plugin.NewProxy(mgr)
	// 重新组装路由，让新增的插件路由生效。
	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)
	s.registerPluginRoutes(mux)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html>"))
	}))
	s.handler = s.withRecovery(s.withRequestLog(mux))
	return s
}

// loginCookie 复用 auth_api_test.go 中的 login 助手，
// 这里只做一层语义化包装，避免两处维护同一段登录逻辑。
func loginCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	return login(t, s)
}

// 插件接口必须全部要求登录：转发接口尤其重要，
// 否则任何人都能通过面板代理调用插件能力。
func TestPluginEndpointsRequireAuth(t *testing.T) {
	s := newPluginTestServer(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/plugins"},
		{http.MethodGet, "/api/plugins/extplug"},
		{http.MethodPost, "/api/plugins/extplug/start"},
		{http.MethodPost, "/api/plugins/extplug/stop"},
		{http.MethodPost, "/api/plugins/extplug/restart"},
		{http.MethodPost, "/api/plugins/extplug/health"},
		{http.MethodGet, "/api/plugins/extplug/anything"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := doJSON(t, s, tc.method, tc.path, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("未登录状态码 = %d, 期望 401, body=%s", rec.Code, rec.Body.String())
			}
			assertJSONContentType(t, rec)
		})
	}
}

// 插件列表必须返回完整的描述符与前端插槽元数据。
func TestPluginListResponse(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}

	var got pluginListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got.Total != 1 {
		t.Errorf("total = %d, 期望 1", got.Total)
	}
	if got.Running != 0 {
		t.Errorf("running = %d, 期望 0", got.Running)
	}
	if len(got.Plugins) != 1 {
		t.Fatalf("plugins 长度 = %d, 期望 1", len(got.Plugins))
	}
	// 前端菜单插槽依赖这两个字段，缺一不可。
	if got.Plugins[0].Frontend.Entry == "" || got.Plugins[0].Frontend.NavTitle == "" {
		t.Errorf("前端插槽元数据缺失: %+v", got.Plugins[0].Frontend)
	}
	if got.SocketDir == "" {
		t.Error("socket_dir 不应为空（便于排查部署问题）")
	}
}

// 查询单个插件：存在返回 200，不存在返回 404（且是 JSON，不是前端页面）。
func TestPluginGet(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins/extplug", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, s, http.MethodGet, "/api/plugins/ghost", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在插件状态码 = %d, 期望 404", rec.Code)
	}
	assertJSONContentType(t, rec)

	// 关键：/api/plugins/ghost 不能被前端 HTML 兜底吞掉。
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Error("404 响应落到了前端 HTML 兜底，应返回 JSON")
	}
}

// 非法插件 ID 必须被拦截在路由层，不能进入转发逻辑。
func TestPluginGetRejectsInvalidID(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	cases := []string{
		"/api/plugins/SYSINFO",
		"/api/plugins/sys_info",
		"/api/plugins/a",
	}
	for _, path := range cases {
		rec := doJSON(t, s, http.MethodGet, path, nil, cookie)
		if rec.Code == http.StatusOK {
			t.Errorf("%s 状态码 = 200, 期望被拒绝", path)
		}
		assertJSONContentType(t, rec)
	}
}

// 转发接口在插件未运行时必须返回 503（而不是 502/超时）。
// 这是前端给出「请先启动插件」提示的依据。
func TestPluginProxyReturns503WhenStopped(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins/extplug/info", nil, cookie)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, 期望 503, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Lipanel-Plugin-State"); got != plugin.StateStopped {
		t.Errorf("X-Lipanel-Plugin-State = %q, 期望 %q", got, plugin.StateStopped)
	}
	if !strings.Contains(rec.Body.String(), "未运行") {
		t.Errorf("响应应说明未运行，实际: %s", rec.Body.String())
	}
	assertJSONContentType(t, rec)
}

// 不存在的插件转发应返回 404。
func TestPluginProxyUnknownPlugin(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins/ghost/info", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, 期望 404, body=%s", rec.Code, rec.Body.String())
	}
	assertJSONContentType(t, rec)
}

// 启动/停止/健康探测的状态码映射。
//
// external 模式的价值在这里体现：它能被置为 running 而不需要真实进程，
// 因此可以完整验证「已运行时」的分支（重复启动 → 409、健康探测 → 无 socket 失败）。
func TestPluginLifecycleStatusCodes(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	// 启动 external 插件：成功（核心不拉起进程）。
	rec := doJSON(t, s, http.MethodPost, "/api/plugins/extplug/start", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("启动状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}
	var st plugin.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if st.State != plugin.StateRunning {
		t.Errorf("启动后状态 = %q, 期望 %q", st.State, plugin.StateRunning)
	}

	// 重复启动 → 409。
	rec = doJSON(t, s, http.MethodPost, "/api/plugins/extplug/start", nil, cookie)
	if rec.Code != http.StatusConflict {
		t.Errorf("重复启动状态码 = %d, 期望 409, body=%s", rec.Code, rec.Body.String())
	}

	// 健康探测：external 插件没有真实 socket，因此必然失败 → 503，
	// 但响应体里要带状态，前端才能把该行标红。
	rec = doJSON(t, s, http.MethodPost, "/api/plugins/extplug/health", nil, cookie)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("健康探测状态码 = %d, 期望 503, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "plugin") {
		t.Errorf("健康探测失败时应返回插件状态，实际: %s", rec.Body.String())
	}

	// 停止 external 插件 → 409 + 说明 + 新状态。
	rec = doJSON(t, s, http.MethodPost, "/api/plugins/extplug/stop", nil, cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("停止 external 插件状态码 = %d, 期望 409, body=%s", rec.Code, rec.Body.String())
	}
	var stopBody struct {
		Error  string        `json:"error"`
		Plugin plugin.Status `json:"plugin"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stopBody); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !strings.Contains(stopBody.Error, "外部") {
		t.Errorf("错误信息应说明进程由外部托管，实际: %q", stopBody.Error)
	}
	if stopBody.Plugin.State != plugin.StateStopped {
		t.Errorf("返回的状态 = %q, 期望 %q（核心已停止转发）", stopBody.Plugin.State, plugin.StateStopped)
	}
}

// 未注入插件管理器时，插件接口返回 503 而不是 panic 或落到 HTML。
func TestPluginEndpointsWithoutManager(t *testing.T) {
	s := newAuthedTestServer(t) // 这个 Server 没有 plugins
	cookie := loginCookie(t, s)

	for _, path := range []string{"/api/plugins", "/api/plugins/sysinfo", "/api/plugins/sysinfo/info"} {
		rec := doJSON(t, s, http.MethodGet, path, nil, cookie)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s 状态码 = %d, 期望 503", path, rec.Code)
		}
		assertJSONContentType(t, rec)
	}
}

// pluginSubPath 是路径穿越的第一道防线，必须逐条覆盖。
func TestPluginSubPath(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
		id       string
		want     string
		wantOK   bool
	}{
		{"普通子路径", "/api/plugins/sysinfo/info", "sysinfo", "/info", true},
		{"多级子路径", "/api/plugins/sysinfo/api/v1/info", "sysinfo", "/api/v1/info", true},
		{"尾部斜杠", "/api/plugins/sysinfo/", "sysinfo", "/", true},
		{"无子路径", "/api/plugins/sysinfo", "sysinfo", "", false},
		{"前缀不匹配", "/api/plugins/other/info", "sysinfo", "", false},
		{"含上跳段", "/api/plugins/sysinfo/../secret", "sysinfo", "", false},
		{"含点段", "/api/plugins/sysinfo/./info", "sysinfo", "", false},
		{"空字符串", "", "sysinfo", "", false},
		{"ID 前缀劫持", "/api/plugins/sysinfo2/info", "sysinfo", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pluginSubPath(tt.fullPath, tt.id)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, 期望 %v (path=%q id=%q)", ok, tt.wantOK, tt.fullPath, tt.id)
			}
			if ok && got != tt.want {
				t.Errorf("subPath = %q, 期望 %q", got, tt.want)
			}
		})
	}
}

// assertJSONContentType 断言响应是 JSON。
// 关键场景：任何 /api/plugins/* 的错误都不能落到前端 HTML 兜底，
// 否则前端会拿到一张网页并报「后端返回了非 JSON 内容」。
func assertJSONContentType(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, 期望包含 application/json", ct)
	}
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Errorf("响应体是前端 HTML，说明落到了 SPA 兜底: %s", rec.Body.String())
	}
}

// ---------- 阶段三 3.2：插件前端资源的转发路径 ----------
//
// 前端加载插件前端时的实际链路是：
//
//	import "/plugin-assets/sysinfo/plugin.js"      （前端写死的约定前缀）
//	  → fetch "/api/plugins/sysinfo/assets/plugin.js"（经核心）
//	  → 转发到插件进程的 GET /assets/plugin.js
//
// 这里锁定路由层：请求必须走「转发兜底」路由并落到插件上，
// 不能被 /api/plugins/{id} 之类的精确路由吞掉（那样会拿到元数据 JSON
// 而不是插件代码，表现为插件页白屏，且日志里什么都看不到）。

// 插件未运行时请求前端资源：必须是 503（可操作的提示），
// 而不是 404——404 会让前端以为"插件没有前端"。
func TestPluginAssetsReturns503WhenStopped(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins/extplug/assets/plugin.js", nil, cookie)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, 期望 503, body=%s", rec.Code, rec.Body.String())
	}
	assertJSONContentType(t, rec)
}

// 前端资源路径必须走完整鉴权：未登录一律 401。
//
// 插件前端代码本身不是机密，但它揭示插件的内部实现，
// 且该前缀经核心转发，绝不能成为绕过鉴权的口子。
func TestPluginAssetsRequiresAuth(t *testing.T) {
	s := newPluginTestServer(t)

	for _, path := range []string{
		"/api/plugins/extplug/assets/plugin.js",
		"/api/plugins/extplug/assets/",
	} {
		rec := doJSON(t, s, http.MethodGet, path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s 未登录状态码 = %d, 期望 401", path, rec.Code)
		}
		assertJSONContentType(t, rec)
	}
}

// 子路径裁剪必须把 assets 前缀完整交给插件。
//
// 插件侧注册的是 "GET /assets/"，若核心把路径裁成 "/plugin.js"
// 或 "/assetsplugin.js"，插件就会 404，而核心侧看不出任何异常。
func TestPluginAssetsSubPathTrimming(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
		id       string
		want     string
	}{
		{"插件前端入口", "/api/plugins/sysinfo/assets/plugin.js", "sysinfo", "/assets/plugin.js"},
		{"嵌套资源", "/api/plugins/sysinfo/assets/img/logo.png", "sysinfo", "/assets/img/logo.png"},
		{"基址本身", "/api/plugins/sysinfo/assets/", "sysinfo", "/assets/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pluginSubPath(tt.fullPath, tt.id)
			if !ok {
				t.Fatalf("pluginSubPath(%q, %q) 未识别为子路径", tt.fullPath, tt.id)
			}
			if got != tt.want {
				t.Errorf("subPath = %q, 期望 %q", got, tt.want)
			}
		})
	}
}

// 插件声明的前端入口地址必须与核心的转发前缀对得上。
//
// 这是动态挂载里最容易"各自都对、合起来不通"的地方：
// 插件写 /plugin-assets/<id>/plugin.js，核心转发 /api/plugins/<id>/assets/*，
// 两者靠 frontend.assets 的位置约定关联。此断言把该约定钉死。
func TestPluginFrontendAssetsPrefixContract(t *testing.T) {
	const (
		wantPrefix = "/plugin-assets/"
		wantSuffix = "plugin.js"
	)

	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)
	rec := doJSON(t, s, http.MethodGet, "/api/plugins", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}

	// 测试 Server 里的 extplug 是外部插件，未声明 assets；
	// 这里只需确认字段被完整透传（空值也是有效信息）。
	var got pluginListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(got.Plugins) == 0 {
		t.Fatal("插件列表为空")
	}

	// 反向校验：真正声明了前端的内置插件（sysinfo）必须符合前缀约定。
	// 通过 plugin 包的内置注册表读取，避免测试里硬编码插件实现。
	for _, id := range plugin.BuiltinIDs() {
		h, err := plugin.Build(id, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatalf("构造内置插件 %s 失败: %v", id, err)
		}
		fe := h.Descriptor().Frontend
		if !fe.Valid() {
			continue // 没有前端的插件不参与本约定
		}
		if !strings.HasPrefix(fe.Entry, wantPrefix+id+"/") {
			t.Errorf("插件 %s 的 Entry = %q, 期望以 %q 开头", id, fe.Entry, wantPrefix+id+"/")
		}
		if !strings.HasSuffix(fe.Entry, wantSuffix) {
			t.Errorf("插件 %s 的 Entry = %q, 期望以 %q 结尾", id, fe.Entry, wantSuffix)
		}
		if fe.Assets != wantPrefix+id+"/" {
			t.Errorf("插件 %s 的 Assets = %q, 期望 %q", id, fe.Assets, wantPrefix+id+"/")
		}
	}
}

// ============================================================================
// 阶段三 3.3：权限与审计的接口层验证
// ============================================================================

// TestPluginPermissionDeniedReturns403 验证越权转发返回结构化 403。
//
// 与 internal/plugin 的 proxy 测试的区别：这里验证的是**完整路由链路**——
// 经过 RequireAuth、ServeMux 匹配、子路径裁剪之后，403 依然能被正确产出，
// 且不会被 "/api/plugins/{id}/" 通配路由或前端 HTML 兜底吃掉。
func TestPluginPermissionDeniedReturns403(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	// DELETE /files 需要 file.write，extplug 只声明了 file.read。
	rec := doJSON(t, s, http.MethodDelete, "/api/plugins/extplug/files/a.txt", nil, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d, 期望 403, body=%s", rec.Code, rec.Body.String())
	}
	assertJSONContentType(t, rec)

	var payload struct {
		Code     string   `json:"code"`
		Plugin   string   `json:"plugin"`
		Required string   `json:"required"`
		Granted  []string `json:"granted"`
		Hint     string   `json:"hint"`
		Scope    string   `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("403 响应解析失败: %v", err)
	}
	if payload.Code != "plugin_permission_denied" {
		t.Errorf("code = %q, 期望 plugin_permission_denied", payload.Code)
	}
	if payload.Required != "file.write" {
		t.Errorf("required = %q, 期望 file.write", payload.Required)
	}
	if payload.Hint == "" {
		t.Error("403 必须带 hint")
	}
	if !strings.Contains(payload.Scope, "不是内核级沙箱") {
		t.Errorf("scope 应说明能力边界，实际 %q", payload.Scope)
	}

	// 而已声明的 GET /files（file.read）不该被权限拒绝。
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/extplug/files", nil, cookie)
	if rec.Code == http.StatusForbidden {
		t.Errorf("GET /files 已声明 file.read，不该 403: %s", rec.Body.String())
	}
}

// TestPluginPermissionDeniedRequiresAuth 验证权限接口不绕过鉴权。
//
// 顺序必须是「先鉴权、再鉴权权限」：未登录时应当 401 而不是 403，
// 否则一个未登录的访客就能靠 403/401 的差异探测出哪些插件存在。
func TestPluginPermissionDeniedRequiresAuth(t *testing.T) {
	s := newPluginTestServer(t)

	// 直接构造不带 Cookie 的请求：doJSON 助手要求 cookie 非 nil
	// （它无条件 AddCookie），因此这里不能复用它。
	paths := []string{
		"/api/plugins/extplug/info",
		"/api/plugins/extplug/permissions",
		"/api/plugins/extplug/audit",
		"/api/plugins/audit",
	}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("未登录取 %s 状态码 = %d, 期望 401, body=%s",
				path, rec.Code, rec.Body.String())
		}
	}
}

// TestPluginPermissionsEndpoint 验证权限清单查询接口。
func TestPluginPermissionsEndpoint(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins/extplug/permissions", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}
	assertJSONContentType(t, rec)

	var payload struct {
		Plugin      string   `json:"plugin"`
		Permissions []string `json:"permissions"`
		ScopeNote   string   `json:"scope_note"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if payload.Plugin != "extplug" {
		t.Errorf("plugin = %q, 期望 extplug", payload.Plugin)
	}
	if len(payload.Permissions) != 2 {
		t.Errorf("permissions = %v, 期望 2 条", payload.Permissions)
	}
	// scope_note 是要给用户看的说明，必须存在且写明边界。
	if !strings.Contains(payload.ScopeNote, "不是内核级沙箱") {
		t.Errorf("scope_note 应说明能力边界，实际 %q", payload.ScopeNote)
	}

	// 不存在的插件必须 404，而不是返回空权限列表
	// （否则用户会以为「这个插件什么都没声明」）。
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/ghost/permissions", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Errorf("不存在的插件状态码 = %d, 期望 404", rec.Code)
	}
}

// TestPluginAuditEndpoint 验证审计查询接口。
func TestPluginAuditEndpoint(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	// 先制造一条拒绝记录。
	rec := doJSON(t, s, http.MethodDelete, "/api/plugins/extplug/files/a.txt", nil, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("准备拒绝记录失败，状态码 = %d", rec.Code)
	}

	// --- 全局审计 ---
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/audit", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("全局审计状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}
	assertJSONContentType(t, rec)

	var payload struct {
		Events []struct {
			Plugin   string `json:"plugin"`
			Method   string `json:"method"`
			Path     string `json:"path"`
			Required string `json:"required"`
			Outcome  string `json:"outcome"`
			Status   int    `json:"status"`
			Time     string `json:"time"`
		} `json:"events"`
		Stats struct {
			Total    uint64 `json:"total"`
			Retained int    `json:"retained"`
			Denied   int    `json:"denied"`
		} `json:"stats"`
		ByPlugin map[string]struct {
			Total  uint64 `json:"total"`
			Denied int    `json:"denied"`
		} `json:"by_plugin"`
		Filter struct {
			Limit int `json:"limit"`
		} `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("审计响应解析失败: %v\n%s", err, rec.Body.String())
	}
	if len(payload.Events) == 0 {
		t.Fatal("审计事件不应为空")
	}
	if payload.Stats.Total == 0 {
		t.Error("审计统计 total 应大于 0")
	}
	if payload.Stats.Denied == 0 {
		t.Error("审计统计 denied 应大于 0（刚制造了一条拒绝）")
	}
	if payload.Filter.Limit <= 0 {
		t.Error("响应应回显生效的 limit")
	}

	// 最新在前：第一条应当是刚刚那条 DELETE。
	first := payload.Events[0]
	if first.Method != http.MethodDelete || first.Outcome != "denied" {
		t.Errorf("最新记录 = %+v, 期望 DELETE/denied", first)
	}
	if first.Time == "" {
		t.Error("审计记录必须带时间")
	}

	// 分插件统计必须包含 extplug。
	if _, ok := payload.ByPlugin["extplug"]; !ok {
		t.Errorf("by_plugin 应包含 extplug，实际 %v", payload.ByPlugin)
	}

	// --- 单插件审计 ---
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/extplug/audit", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("单插件审计状态码 = %d, 期望 200", rec.Code)
	}
	var single struct {
		Events []struct {
			Plugin string `json:"plugin"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &single); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, ev := range single.Events {
		if ev.Plugin != "extplug" {
			t.Errorf("单插件审计返回了其它插件的记录: %q", ev.Plugin)
		}
	}

	// --- 过滤 ---
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/audit?outcome=denied&limit=1", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("带过滤的审计查询状态码 = %d", rec.Code)
	}
	var filtered struct {
		Events []struct {
			Outcome string `json:"outcome"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &filtered); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(filtered.Events) != 1 {
		t.Errorf("limit=1 应返回 1 条，实际 %d", len(filtered.Events))
	}
	for _, ev := range filtered.Events {
		if ev.Outcome != "denied" {
			t.Errorf("outcome 过滤失效，返回了 %q", ev.Outcome)
		}
	}

	// 非法 limit 不该让接口失败（审计页是排查工具，不该因为参数写错就打不开）。
	rec = doJSON(t, s, http.MethodGet, "/api/plugins/audit?limit=abc", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Errorf("非法 limit 应回落到默认值并返回 200，实际 %d", rec.Code)
	}
}

// TestPluginAuditRequiresAuth 验证审计接口需要登录。
//
// 审计记录包含路径、插件 ID 与来源 IP，属于敏感信息，
// 绝不能因为「只是日志」就免鉴权。
func TestPluginAuditRequiresAuth(t *testing.T) {
	s := newPluginTestServer(t)

	for _, path := range []string{"/api/plugins/audit", "/api/plugins/extplug/audit", "/api/plugins/extplug/permissions"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("未登录取 %s 状态码 = %d, 期望 401", path, rec.Code)
		}
	}
}

// TestPluginListIncludesAuditStats 验证插件列表携带审计统计。
func TestPluginListIncludesAuditStats(t *testing.T) {
	s := newPluginTestServer(t)
	cookie := loginCookie(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/plugins", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}

	var payload struct {
		Plugins []plugin.Status `json:"plugins"`
		Audit   struct {
			Total    uint64 `json:"total"`
			Capacity int    `json:"capacity"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if payload.Audit.Capacity <= 0 {
		t.Errorf("插件列表应带上审计容量信息，实际 %+v", payload.Audit)
	}
	// 注册本身就会留下审计记录，因此 total 必然 > 0。
	if payload.Audit.Total == 0 {
		t.Error("注册插件应当留下审计记录，total 应大于 0")
	}

	// 列表里的插件必须带上权限清单，供前端展示。
	var found bool
	for _, p := range payload.Plugins {
		if p.ID == "extplug" {
			found = true
			if len(p.Permissions) != 2 {
				t.Errorf("extplug 的 permissions = %v, 期望 2 条", p.Permissions)
			}
		}
	}
	if !found {
		t.Error("插件列表中未找到 extplug")
	}
}
