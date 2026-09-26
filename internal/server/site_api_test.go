package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"lipanel/internal/site"
)

// ============================================================================
// 站点管理接口测试（阶段四 4.3）
// ============================================================================
//
// 这里测的是**真实的 HTTP 链路**：路由挂载 → 鉴权 → 权限判定 → 输入校验
// → 配置写入 → nginx -t → 响应翻译 → 审计。
//
// 不 mock site.Manager：本阶段最需要验证的性质（路由遮蔽、权限与状态码
// 翻译、注入被拦在入口、失败不触碰磁盘）全都发生在**真实调用链**上，
// mock 掉中间层等于把要验证的东西假设掉了。

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

// siteTestEnv 是一次接口测试的环境。
type siteTestEnv struct {
	server  *Server
	manager *site.Manager
	adapter *site.SystemAdapter
	// executor 让我们可以控制 nginx -t 的成败。
	executor *siteStubExecutor
	// root 是静态站根目录。
	root string
}

// siteStubExecutor 是可编程的 nginx 执行器。
type siteStubExecutor struct {
	mu         sync.Mutex
	failTest   bool
	failReload bool
	testOutput string
	calls      int
}

func (s *siteStubExecutor) Run(_ context.Context, _ string, args []string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-t") {
		if s.failTest {
			out := s.testOutput
			if out == "" {
				out = `nginx: [emerg] unknown directive "bogus"`
			}
			return "", out, errors.New("exit status 1")
		}
		return "nginx: configuration file test is successful", "", nil
	}
	if strings.Contains(joined, "reload") && s.failReload {
		return "", "nginx: [error] invalid PID number", errors.New("exit status 1")
	}
	return "", "", nil
}

func (s *siteStubExecutor) setFailTest(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failTest = v
}

func (s *siteStubExecutor) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// newSiteTestServer 构造一个注入了站点管理器的测试 Server。
func newSiteTestServer(t *testing.T) *siteTestEnv {
	t.Helper()

	base := t.TempDir()
	prefix := filepath.Join(base, "nginx")
	for _, sub := range []string{"sites-available", "sites-enabled", "logs"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建测试目录失败: %v", err)
		}
	}
	// 用**相对** include 写法，与真实生产配置一致（也覆盖适配器的相对路径解析）。
	conf := "events {}\nhttp {\n    include sites-enabled/*.conf;\n}\n"
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}

	root := filepath.Join(base, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根失败: %v", err)
	}

	adapter := site.NewSystemAdapter(site.AdapterOptions{Prefix: prefix})
	if !adapter.Available() {
		t.Fatalf("适配器应可用: %s", adapter.UnavailableReason())
	}

	executor := &siteStubExecutor{}
	auditor, err := site.NewAuditor(site.AuditOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}
	mgr, err := site.NewManager(site.ManagerOptions{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Adapter:  adapter,
		Auditor:  auditor,
		Executor: executor,
		RootChecker: func(p string) error {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s 不是目录", p)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.siteMgr = mgr
	rebuildTestRoutes(s)

	return &siteTestEnv{server: s, manager: mgr, adapter: adapter, executor: executor, root: root}
}

// doSite 发起一次已登录的 JSON 请求。
func (e *siteTestEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body, login(t, e.server))
}

// doAnon 发起一次未登录请求。
func (e *siteTestEnv) doAnon(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body)
}

// staticBody 返回一个合法的静态站请求体。
func (e *siteTestEnv) staticBody(name, domain string, enabled bool) map[string]any {
	return map[string]any{
		"name": name, "domain": domain, "type": "static",
		"root": e.root, "enabled": enabled,
	}
}

// decodeSite 解析响应体，并断言 Content-Type 是 JSON。
//
// 为什么必须断言 Content-Type：未注册的 /api 路径会落到 SPA 兜底返回
// **200 + text/html**（坑位 47）。只看状态码会把"接口没注册"误判为成功。
func decodeSite(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("响应 Content-Type 应为 JSON，实际 %q（body 前 200 字: %s）",
			ct, truncate(rec.Body.String(), 200))
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v\nbody: %s", err, rec.Body.String())
	}
}

// decodeSiteMap 解析响应为一个 map。
func decodeSiteMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	decodeSite(t, rec, &m)
	return m
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// 路由注册顺序（4.2 踩过的坑，这里必须锁死）
// ---------------------------------------------------------------------------

// TestSiteAuditRouteNotShadowedByWildcard 锁定 "/api/sites/audit" 不被
// "/api/sites/{name}" 通配吃掉。
//
// #################### 这条测试为什么必须有 ####################
//
// 4.1 与 4.2 都真实踩过同一个坑：固定段路由注册在通配段之后时，
// ServiceMux 会优先匹配**先注册**的模式，于是 "audit" 被当成站点名，
// 查询审计变成"查看名为 audit 的站点"，返回 404。
//
// 更糟的是这种失败**看起来像功能没实现**（一个 404），
// 而不是像配置错误，排查方向很容易跑偏。
//
// 因此这里不仅断言状态码，还断言响应体里**确实是审计结构**
// （含 events/stats 字段），而不是一个站点对象或错误信息。
func TestSiteAuditRouteNotShadowedByWildcard(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/sites/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/sites/audit 状态码 = %d，期望 200（被 {name} 通配吃掉了？）body=%s",
			rec.Code, rec.Body.String())
	}

	body := decodeSiteMap(t, rec)
	// 必须是审计结构。
	if _, ok := body["events"]; !ok {
		t.Errorf("响应缺少 events 字段，说明命中的不是审计接口: %v", keysOf(body))
	}
	if _, ok := body["stats"]; !ok {
		t.Errorf("响应缺少 stats 字段，说明命中的不是审计接口: %v", keysOf(body))
	}
	if _, ok := body["scope_note"]; !ok {
		t.Errorf("响应缺少 scope_note 字段: %v", keysOf(body))
	}
	// 绝不能是"站点不存在"这类错误。
	if _, ok := body["error"]; ok {
		t.Errorf("审计接口不应返回错误: %v", body)
	}
}

// TestSiteCapabilitiesRouteNotShadowedByWildcard 锁定 capabilities 不被通配吃掉。
func TestSiteCapabilitiesRouteNotShadowedByWildcard(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/sites/capabilities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/sites/capabilities 状态码 = %d，期望 200，body=%s",
			rec.Code, rec.Body.String())
	}
	body := decodeSiteMap(t, rec)
	if _, ok := body["limits"]; !ok {
		t.Errorf("响应缺少 limits 字段，说明命中的不是能力接口: %v", keysOf(body))
	}
	if _, ok := body["available_dir"]; !ok {
		t.Errorf("响应缺少 available_dir 字段: %v", keysOf(body))
	}
}

// TestSiteAuditWorksAfterCreatingSiteNamedAuditAttempt 验证"想建叫 audit 的站点"不会破坏路由。
//
// 站点名 "audit" 是保留名（会被 400 拒绝），因此审计路由
// 永远不会与真实站点冲突——这条测试把该结论固化下来。
func TestSiteAuditWorksAfterCreatingSiteNamedAuditAttempt(t *testing.T) {
	env := newSiteTestServer(t)

	// 尝试创建名为 audit 的站点：必须被拒绝（保留名）。
	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("audit", "a.example.com", true))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("创建名为 audit 的站点应被拒绝（400），实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 审计路由仍然正常。
	rec = env.do(t, http.MethodGet, "/api/sites/audit", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("审计接口应仍然可用，状态码 = %d", rec.Code)
	}
}

// TestUnregisteredSiteAPIPathReturnsJSON 验证未注册路径返回 JSON 404。
//
// 而不是落到前端 SPA 兜底（200 + text/html）。
func TestUnregisteredSiteAPIPathReturnsJSON(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/sites/does-not-exist/nested/path", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("未注册路径应为 404，实际 %d: %s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("未注册的站点路径应返回 JSON 404，实际 Content-Type=%q（落到了 HTML 兜底？）", ct)
	}
	body := decodeSiteMap(t, rec)
	if _, ok := body["available"]; !ok {
		t.Errorf("JSON 404 应列出可用接口，实际: %v", body)
	}
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

// TestSiteRoutesRequireAuth 验证全部站点接口都要求登录。
//
// 站点管理会改 nginx 配置，未登录能访问等于把整台机器的 Web 服务入口交出去。
func TestSiteRoutesRequireAuth(t *testing.T) {
	env := newSiteTestServer(t)

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/sites", nil},
		{http.MethodGet, "/api/sites/audit", nil},
		{http.MethodGet, "/api/sites/capabilities", nil},
		{http.MethodPost, "/api/sites", map[string]any{"name": "x"}},
		{http.MethodGet, "/api/sites/x", nil},
		{http.MethodPut, "/api/sites/x", map[string]any{"name": "x"}},
		{http.MethodDelete, "/api/sites/x", nil},
		{http.MethodPost, "/api/sites/x/enable", nil},
		{http.MethodPost, "/api/sites/x/disable", nil},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := env.doAnon(t, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("未登录访问 %s %s 应返回 401，实际 %d: %s",
					tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSitesUnavailableWhenManagerMissing 验证未注入管理器时的降级。
func TestSitesUnavailableWhenManagerMissing(t *testing.T) {
	s := newAuthedTestServer(t)
	rebuildTestRoutes(s)

	rec := doJSON(t, s, http.MethodGet, "/api/sites", nil, login(t, s))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("未注入管理器时应返回 503，实际 %d: %s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("降级响应应为 JSON，实际 %q", ct)
	}
}

// ---------------------------------------------------------------------------
// 完整生命周期（HTTP 层）
// ---------------------------------------------------------------------------

// TestSiteFullLifecycleOverHTTP 跑通创建 → 列表 → 编辑 → 禁用 → 启用 → 删除。
func TestSiteFullLifecycleOverHTTP(t *testing.T) {
	env := newSiteTestServer(t)

	// ---------- 创建静态站 ----------
	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("web", "web.example.com", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建静态站失败: %d %s", rec.Code, rec.Body.String())
	}
	var created site.Site
	decodeSite(t, rec, &created)
	if created.Name != "web" || created.Domain != "web.example.com" || !created.Enabled {
		t.Errorf("创建结果不符: %+v", created)
	}

	// ---------- 创建反代站 ----------
	rec = env.do(t, http.MethodPost, "/api/sites", map[string]any{
		"name": "api", "domain": "api.example.com", "type": "proxy",
		"upstream": "127.0.0.1:3000", "enabled": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("创建反代站失败: %d %s", rec.Code, rec.Body.String())
	}
	var proxy site.Site
	decodeSite(t, rec, &proxy)
	if proxy.Upstream != "http://127.0.0.1:3000" {
		t.Errorf("反代目标应归一化，实际 %q", proxy.Upstream)
	}

	// ---------- 列表 ----------
	rec = env.do(t, http.MethodGet, "/api/sites", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("列表失败: %d %s", rec.Code, rec.Body.String())
	}
	var listing struct {
		Sites       []site.Site `json:"sites"`
		Total       int         `json:"total"`
		Enabled     int         `json:"enabled"`
		Available   bool        `json:"available"`
		Mode        string      `json:"mode"`
		Permissions []string    `json:"permissions"`
	}
	decodeSite(t, rec, &listing)
	if listing.Total != 2 {
		t.Errorf("应有 2 个站点，实际 %d", listing.Total)
	}
	if listing.Enabled != 2 {
		t.Errorf("应有 2 个启用站点，实际 %d", listing.Enabled)
	}
	if !listing.Available {
		t.Error("available 应为 true")
	}
	if listing.Mode != site.ModeSites {
		t.Errorf("mode 应为 %q，实际 %q", site.ModeSites, listing.Mode)
	}

	// ---------- 查看单个 ----------
	rec = env.do(t, http.MethodGet, "/api/sites/web", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("查看站点失败: %d %s", rec.Code, rec.Body.String())
	}

	// ---------- 编辑 ----------
	body := env.staticBody("web", "www.example.com", true)
	rec = env.do(t, http.MethodPut, "/api/sites/web", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("编辑失败: %d %s", rec.Code, rec.Body.String())
	}
	var updated site.Site
	decodeSite(t, rec, &updated)
	if updated.Domain != "www.example.com" {
		t.Errorf("域名未更新: %q", updated.Domain)
	}

	// ---------- 禁用 ----------
	rec = env.do(t, http.MethodPost, "/api/sites/api/disable", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("禁用失败: %d %s", rec.Code, rec.Body.String())
	}
	var disabled site.Site
	decodeSite(t, rec, &disabled)
	if disabled.Enabled {
		t.Error("禁用后 Enabled 应为 false")
	}
	// 禁用后配置内容仍在（可逆）。
	if _, err := os.Stat(env.adapter.SiteFilePath("api")); err != nil {
		t.Errorf("禁用不应删除配置: %v", err)
	}

	// ---------- 启用 ----------
	rec = env.do(t, http.MethodPost, "/api/sites/api/enable", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("启用失败: %d %s", rec.Code, rec.Body.String())
	}
	var enabled site.Site
	decodeSite(t, rec, &enabled)
	if !enabled.Enabled {
		t.Error("启用后 Enabled 应为 true")
	}

	// ---------- 删除 ----------
	rec = env.do(t, http.MethodDelete, "/api/sites/api", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("删除失败: %d %s", rec.Code, rec.Body.String())
	}
	var deleted struct {
		Deleted bool   `json:"deleted"`
		Name    string `json:"name"`
	}
	decodeSite(t, rec, &deleted)
	if !deleted.Deleted || deleted.Name != "api" {
		t.Errorf("删除响应不符: %+v", deleted)
	}

	// 删除后再查应 404。
	rec = env.do(t, http.MethodGet, "/api/sites/api", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("删除后查询应为 404，实际 %d", rec.Code)
	}

	// ---------- 审计应完整留痕 ----------
	rec = env.do(t, http.MethodGet, "/api/sites/audit", nil)
	var audit struct {
		Events []site.AuditEvent `json:"events"`
		Stats  site.AuditStats   `json:"stats"`
	}
	decodeSite(t, rec, &audit)
	// 本条链路共 7 次请求，其中 1 次是查询审计本身（不记审计）
	// → 应恰好 6 条：2 创建 + 1 编辑 + 1 禁用 + 1 启用 + 1 删除。
	//
	// 用"恰好等于"而不是"至少"：多了说明有接口重复记审计，
	// 少了说明有接口漏记——两个方向都是缺陷，都该被发现。
	// （权限判定拒绝的请求由 TestSitePermissionDeniedLeavesAudit 单独覆盖。）
	if audit.Stats.Total != 6 {
		t.Errorf("审计应恰好记录 6 条（2 创建 + 编辑 + 禁用 + 启用 + 删除），实际 %d: %+v",
			audit.Stats.Total, audit.Events)
	}
	// 每个事件都要有 user/action/target/outcome。
	for _, ev := range audit.Events {
		if ev.User == "" {
			t.Errorf("审计事件缺少 user 字段: %+v", ev)
		}
		if ev.Action == "" || ev.Target == "" || ev.Outcome == "" {
			t.Errorf("审计事件字段不完整: %+v", ev)
		}
		if ev.Kind != site.KindSite {
			t.Errorf("Kind 应为 %q，实际 %q", site.KindSite, ev.Kind)
		}
		if ev.Source != site.SourceCore {
			t.Errorf("Source 应为 %q，实际 %q", site.SourceCore, ev.Source)
		}
	}
}

// ---------------------------------------------------------------------------
// 负向用例：注入与非法输入
// ---------------------------------------------------------------------------

// TestSiteCreateRejectsInjection 验证三种注入载荷经 HTTP 链路被拒绝。
//
// 这是 4.3 的安全命脉在**接口层**的验证：即使绕过了前端校验，
// 后端也必须独立拒绝。
func TestSiteCreateRejectsInjection(t *testing.T) {
	env := newSiteTestServer(t)

	payloads := []string{
		"a;b", "a{b", "a}b", "a$b", "a`b", "a'b", `a"b`, "a#b",
		"a\nb", "a\rb", "a\tb", "a b", "a\\b", "a/b", "a..b", "../etc",
		"..", "/etc/passwd", "a|b", "a&b", "a<b", "a>b",
	}

	for _, p := range payloads {
		t.Run("name", func(t *testing.T) {
			body := env.staticBody("site"+p, "x.example.com", true)
			rec := env.do(t, http.MethodPost, "/api/sites", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("站点名 %q 应返回 400，实际 %d: %s", "site"+p, rec.Code, truncate(rec.Body.String(), 200))
			}
		})
		t.Run("domain", func(t *testing.T) {
			body := env.staticBody("injectdomain", "x.example.com"+p, true)
			rec := env.do(t, http.MethodPost, "/api/sites", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("域名 %q 应返回 400，实际 %d: %s", "x.example.com"+p, rec.Code, truncate(rec.Body.String(), 200))
			}
		})
		t.Run("root", func(t *testing.T) {
			body := env.staticBody("injectroot", "x.example.com", true)
			body["root"] = "/var/www;" + p
			rec := env.do(t, http.MethodPost, "/api/sites", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("根目录 %q 应返回 400，实际 %d: %s", "/var/www;"+p, rec.Code, truncate(rec.Body.String(), 200))
			}
		})
		t.Run("upstream", func(t *testing.T) {
			body := map[string]any{
				"name": "injectup", "domain": "x.example.com", "type": "proxy",
				"upstream": "http://127.0.0.1:3000;" + p, "enabled": true,
			}
			rec := env.do(t, http.MethodPost, "/api/sites", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("反代目标 %q 应返回 400，实际 %d: %s",
					"http://127.0.0.1:3000;"+p, rec.Code, truncate(rec.Body.String(), 200))
			}
		})
	}

	// 全程不应产生任何配置文件，也不应调用 nginx。
	entries, err := os.ReadDir(env.adapter.AvailableDir())
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("注入尝试不应产生任何文件，实际: %v", entries)
	}
	if n := env.executor.callCount(); n != 0 {
		t.Errorf("注入尝试不应触发 nginx 调用，实际 %d 次", n)
	}
}

// TestSiteCreateRejectsMissingFields 验证缺字段的请求被拒绝。
func TestSiteCreateRejectsMissingFields(t *testing.T) {
	env := newSiteTestServer(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺站点名", map[string]any{"domain": "x.com", "type": "static", "root": env.root}},
		{"缺域名", map[string]any{"name": "a", "type": "static", "root": env.root}},
		{"缺类型", map[string]any{"name": "a", "domain": "x.com", "root": env.root}},
		{"静态站缺根目录", map[string]any{"name": "a", "domain": "x.com", "type": "static"}},
		{"反代站缺目标", map[string]any{"name": "a", "domain": "x.com", "type": "proxy"}},
		{"类型非法", map[string]any{"name": "a", "domain": "x.com", "type": "php", "root": env.root}},
		{"静态站带 upstream", map[string]any{"name": "a", "domain": "x.com", "type": "static", "root": env.root, "upstream": "http://127.0.0.1:3000"}},
		{"反代站带 root", map[string]any{"name": "a", "domain": "x.com", "type": "proxy", "upstream": "http://127.0.0.1:3000", "root": env.root}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, http.MethodPost, "/api/sites", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s 应返回 400，实际 %d: %s", tc.name, rec.Code, truncate(rec.Body.String(), 200))
			}
			// 错误响应必须带可操作的提示。
			body := decodeSiteMap(t, rec)
			if _, ok := body["error"]; !ok {
				t.Errorf("错误响应应含 error 字段: %v", body)
			}
			if _, ok := body["hint"]; !ok {
				t.Errorf("错误响应应含 hint 字段（告诉用户怎么办）: %v", body)
			}
		})
	}
}

// TestSiteCreateRejectsBadJSON 验证畸形请求体。
func TestSiteCreateRejectsBadJSON(t *testing.T) {
	env := newSiteTestServer(t)
	cookie := login(t, env.server)

	req := httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("畸形 JSON 应返回 400，实际 %d", rec.Code)
	}
}

// TestSiteCreateDuplicateReturnsConflict 验证重复创建返回 409。
func TestSiteCreateDuplicateReturnsConflict(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("dup", "dup.example.com", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("首次创建应成功: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do(t, http.MethodPost, "/api/sites", env.staticBody("dup", "other.example.com", true))
	if rec.Code != http.StatusConflict {
		t.Errorf("重复创建应返回 409，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 200))
	}
}

// TestSiteGetNotFound 验证查询不存在的站点返回 404。
func TestSiteGetNotFound(t *testing.T) {
	env := newSiteTestServer(t)
	rec := env.do(t, http.MethodGet, "/api/sites/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("查询不存在的站点应返回 404，实际 %d", rec.Code)
	}
}

// TestSiteUpdateRejectsExternalConfig 验证编辑外部配置返回 409。
func TestSiteUpdateRejectsExternalConfig(t *testing.T) {
	env := newSiteTestServer(t)

	external := "server {\n    listen 80;\n    server_name manual.example.com;\n    root /srv/manual;\n}\n"
	if err := os.WriteFile(env.adapter.SiteFilePath("manual"), []byte(external), 0o644); err != nil {
		t.Fatalf("写入外部配置失败: %v", err)
	}

	rec := env.do(t, http.MethodPut, "/api/sites/manual", env.staticBody("manual", "new.example.com", true))
	if rec.Code != http.StatusConflict {
		t.Errorf("编辑外部配置应返回 409，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	// 文件必须一字未改。
	after, _ := os.ReadFile(env.adapter.SiteFilePath("manual"))
	if string(after) != external {
		t.Error("被拒绝的编辑不应改动文件")
	}
}

// TestSiteDeleteRejectsExternalConfig 验证删除外部配置返回 409。
func TestSiteDeleteRejectsExternalConfig(t *testing.T) {
	env := newSiteTestServer(t)

	external := "server {\n    listen 80;\n    server_name manual.example.com;\n}\n"
	if err := os.WriteFile(env.adapter.SiteFilePath("manual"), []byte(external), 0o644); err != nil {
		t.Fatalf("写入外部配置失败: %v", err)
	}
	rec := env.do(t, http.MethodDelete, "/api/sites/manual", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("删除外部配置应返回 409，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	if _, err := os.Stat(env.adapter.SiteFilePath("manual")); err != nil {
		t.Error("被拒绝的删除不应移除文件")
	}
}

// ---------------------------------------------------------------------------
// 回滚：经 HTTP 链路验证（422 + rolled_back 标记 + 配置真的回来了）
// ---------------------------------------------------------------------------

// TestSiteUpdateRollbackOverHTTP 验证 nginx -t 失败时接口返回 422 并已回滚。
func TestSiteUpdateRollbackOverHTTP(t *testing.T) {
	env := newSiteTestServer(t)

	// 建一个正常站点。
	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("rb", "rb.example.com", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建失败: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := os.ReadFile(env.adapter.SiteFilePath("rb"))

	// 让 nginx -t 失败。
	env.executor.setFailTest(true)
	env.executor.mu.Lock()
	env.executor.testOutput = `nginx: [emerg] unknown directive "bogus" in /etc/nginx/sites-enabled/rb.conf:5`
	env.executor.mu.Unlock()

	rec = env.do(t, http.MethodPut, "/api/sites/rb", env.staticBody("rb", "changed.example.com", true))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("nginx -t 失败应返回 422，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}

	body := decodeSiteMap(t, rec)
	if v, ok := body["rolled_back"].(bool); !ok || !v {
		t.Errorf("响应应标记 rolled_back=true: %v", body)
	}
	errText, _ := body["error"].(string)
	if !strings.Contains(errText, "unknown directive") {
		t.Errorf("错误信息应包含 nginx 的原始报错，实际: %q", errText)
	}
	if hint, _ := body["hint"].(string); !strings.Contains(hint, "回滚") {
		t.Errorf("提示应说明已回滚，实际: %q", hint)
	}

	// 核心断言：磁盘上的配置回到原样。
	after, err := os.ReadFile(env.adapter.SiteFilePath("rb"))
	if err != nil {
		t.Fatalf("回滚后应能读取配置: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("配置未回滚。\n修改前:\n%s\n回滚后:\n%s", before, after)
	}

	// 关掉故障注入后，站点应仍可用（再次编辑成功）。
	env.executor.setFailTest(false)
	rec = env.do(t, http.MethodPut, "/api/sites/rb", env.staticBody("rb", "changed.example.com", true))
	if rec.Code != http.StatusOK {
		t.Errorf("回滚后再次编辑应成功，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}

	// 审计里应有被标记为 rolled_back 的记录。
	rec = env.do(t, http.MethodGet, "/api/sites/audit?outcome=failed", nil)
	var audit struct {
		Events []site.AuditEvent `json:"events"`
		Stats  site.AuditStats   `json:"stats"`
	}
	decodeSite(t, rec, &audit)
	if audit.Stats.RolledBack == 0 {
		t.Error("审计 stats 应记录到回滚次数（供运维发现'配置曾写坏又恢复'）")
	}
}

// TestSiteReloadFailureReturnsBadGateway 验证 reload 失败返回 502。
func TestSiteReloadFailureReturnsBadGateway(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("rl", "rl.example.com", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建失败: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := os.ReadFile(env.adapter.SiteFilePath("rl"))

	env.executor.mu.Lock()
	env.executor.failReload = true
	env.executor.mu.Unlock()

	rec = env.do(t, http.MethodPut, "/api/sites/rl", env.staticBody("rl", "changed.example.com", true))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("reload 失败应返回 502，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	after, _ := os.ReadFile(env.adapter.SiteFilePath("rl"))
	if string(after) != string(before) {
		t.Error("reload 失败后配置应回滚")
	}
}

// TestSiteCreateRollbackLeavesNoFile 验证创建失败不留文件。
func TestSiteCreateRollbackLeavesNoFile(t *testing.T) {
	env := newSiteTestServer(t)
	env.executor.setFailTest(true)

	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("newone", "new.example.com", true))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("创建失败应返回 422，实际 %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	if _, err := os.Stat(env.adapter.SiteFilePath("newone")); !errors.Is(err, os.ErrNotExist) {
		t.Error("创建失败回滚后不应留下配置文件")
	}

	// 列表应为空。
	rec = env.do(t, http.MethodGet, "/api/sites", nil)
	var listing struct {
		Total int `json:"total"`
	}
	decodeSite(t, rec, &listing)
	if listing.Total != 0 {
		t.Errorf("回滚后列表应为空，实际 %d 个", listing.Total)
	}
}

// ---------------------------------------------------------------------------
// 审计查询
// ---------------------------------------------------------------------------

// TestSiteAuditFilters 验证审计过滤参数。
func TestSiteAuditFilters(t *testing.T) {
	env := newSiteTestServer(t)

	if rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("one", "one.example.com", true)); rec.Code != http.StatusOK {
		t.Fatalf("创建失败: %s", rec.Body.String())
	}
	if rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("two", "two.example.com", true)); rec.Code != http.StatusOK {
		t.Fatalf("创建失败: %s", rec.Body.String())
	}

	rec := env.do(t, http.MethodGet, "/api/sites/audit?target=one", nil)
	var byTarget struct {
		Events []site.AuditEvent `json:"events"`
	}
	decodeSite(t, rec, &byTarget)
	if len(byTarget.Events) == 0 {
		t.Fatal("按 target 过滤应有结果")
	}
	for _, ev := range byTarget.Events {
		if ev.Target != "one" {
			t.Errorf("按 target=one 过滤出现了 target=%q 的记录", ev.Target)
		}
	}

	rec = env.do(t, http.MethodGet, "/api/sites/audit?action=create", nil)
	var byAction struct {
		Events []site.AuditEvent `json:"events"`
	}
	decodeSite(t, rec, &byAction)
	if len(byAction.Events) != 2 {
		t.Errorf("按 action=create 过滤应有 2 条，实际 %d", len(byAction.Events))
	}

	// limit 应生效。
	rec = env.do(t, http.MethodGet, "/api/sites/audit?limit=1", nil)
	var limited struct {
		Events []site.AuditEvent `json:"events"`
	}
	decodeSite(t, rec, &limited)
	if len(limited.Events) != 1 {
		t.Errorf("limit=1 应只返回 1 条，实际 %d", len(limited.Events))
	}
}

// TestSiteAuditRecordsDenied 验证被拒绝的注入尝试也留痕。
//
// 这是安全审计的关键：有人在探测配置注入，运维必须能事后看到。
func TestSiteAuditRecordsDenied(t *testing.T) {
	env := newSiteTestServer(t)

	// 用 HTTP 方法路由之外的非法站点名（会走 handleSiteNotFound 或校验拒绝）。
	// 这里用创建接口提交非法域名。
	rec := env.do(t, http.MethodPost, "/api/sites", env.staticBody("probe", "evil.com; root /etc;", true))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("注入尝试应被拒绝，实际 %d", rec.Code)
	}

	rec = env.do(t, http.MethodGet, "/api/sites/audit?outcome=failed", nil)
	var audit struct {
		Events []site.AuditEvent `json:"events"`
	}
	decodeSite(t, rec, &audit)
	if len(audit.Events) == 0 {
		t.Fatal("被拒绝的注入尝试必须留痕（安全审计的核心）")
	}
	found := false
	for _, ev := range audit.Events {
		if ev.Target == "probe" && ev.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("应能找到针对 probe 的失败记录，实际: %+v", audit.Events)
	}
}

// ---------------------------------------------------------------------------
// 能力探测
// ---------------------------------------------------------------------------

// TestSiteCapabilitiesContent 验证能力接口返回前端需要的信息。
func TestSiteCapabilitiesContent(t *testing.T) {
	env := newSiteTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/sites/capabilities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	body := decodeSiteMap(t, rec)

	if body["available"] != true {
		t.Error("available 应为 true")
	}
	if body["mode"] != site.ModeSites {
		t.Errorf("mode 应为 %q，实际 %v", site.ModeSites, body["mode"])
	}
	// 用户需要知道面板会动哪些目录。
	if body["available_dir"] == "" || body["available_dir"] == nil {
		t.Error("应返回 available_dir（用户有权知道面板在动哪些文件）")
	}
	limits, ok := body["limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits 应为对象: %v", body["limits"])
	}
	if limits["max_name_len"] == nil || limits["max_domain_len"] == nil {
		t.Errorf("limits 应包含表单校验所需的限制: %v", limits)
	}
	if _, ok := body["scope_note"]; !ok {
		t.Error("应返回 scope_note 说明面板的能力边界")
	}
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// TestSitePermissionDeniedDoesNotTouchDisk 验证权限不足时不触碰磁盘。
//
// 通过注入一个只读 grantee 来模拟"账号权限被收窄"。
// 由于 AdminGrantee 目前总是返回全部权限，这里直接测 site 包层
// 的判定函数（接口层的强制点调用的是同一个函数）。
func TestSitePermissionDeniedDoesNotTouchDisk(t *testing.T) {
	env := newSiteTestServer(t)

	viewer := site.Grantee{User: "viewer", Granted: []string{site.PermRead}}
	for _, action := range []string{site.ActionCreate, site.ActionUpdate, site.ActionDelete, site.ActionEnable, site.ActionDisable} {
		d := site.CheckSitePermission(viewer, action)
		if d.Allowed {
			t.Errorf("只读用户不应被允许执行 %s", action)
		}
		if d.Required != site.PermWrite {
			t.Errorf("%s 的所需权限应为 %s，实际 %s", action, site.PermWrite, d.Required)
		}
		if d.Hint == "" {
			t.Errorf("%s 被拒时应给出提示", action)
		}
	}

	// 目录应仍然是空的（本测试只做判定，不应有副作用）。
	entries, _ := os.ReadDir(env.adapter.AvailableDir())
	if len(entries) != 0 {
		t.Errorf("权限判定不应产生文件: %v", entries)
	}
}

// keysOf 返回 map 的键（用于错误信息）。
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
