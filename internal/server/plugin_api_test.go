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
	ext := plugin.Descriptor{
		ID:      "extplug",
		Name:    "外部插件",
		Version: "1.0.0",
		Mode:    plugin.ModeExternal,
		Frontend: plugin.Frontend{
			Entry:    "extplug",
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
