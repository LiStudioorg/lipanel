package server

import (
	"context"
	"encoding/json"
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
	"time"

	"lipanel/internal/ssl"
)

// ============================================================================
// SSL 接口层测试（阶段四 4.4）
// ============================================================================

// sslStubExecutor 是一个可编程的假 certbot。
type sslStubExecutor struct {
	mu      sync.Mutex
	calls   [][]string
	handler func(args []string) (string, string, error)
}

func (e *sslStubExecutor) Run(_ context.Context, name string, args []string) (string, string, error) {
	e.mu.Lock()
	e.calls = append(e.calls, append([]string{name}, args...))
	h := e.handler
	e.mu.Unlock()
	if h == nil {
		return "", "", nil
	}
	return h(args)
}

func (e *sslStubExecutor) called(substr string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.calls {
		if strings.Contains(strings.Join(c, " "), substr) {
			return true
		}
	}
	return false
}

// sslTestEnv 是 SSL 接口测试环境。
type sslTestEnv struct {
	server  *Server
	manager *ssl.Manager
	exec    *sslStubExecutor
	root    string
}

// newSSLTestServer 构造一个注入了 SSL 管理器的测试 Server。
func newSSLTestServer(t *testing.T) *sslTestEnv {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根失败: %v", err)
	}

	// 造一个"存在且可执行"的假 certbot：探测器会 os.Stat 它。
	certbot := filepath.Join(base, "fake-certbot")
	if err := os.WriteFile(certbot, []byte("#!/bin/sh\necho certbot 1.21.0\n"), 0o755); err != nil {
		t.Fatalf("写假 certbot 失败: %v", err)
	}

	exec := &sslStubExecutor{handler: func(args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		default:
			return noCertsStubOutput, "", nil
		}
	}}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 站点提供器：直接用 ssl 包自己的接口实现一个内存版本。
	sites := newSSLStubSites(ssl.SiteRef{
		Name:    "demo",
		Domain:  "demo.example.com",
		Root:    root,
		Type:    "static",
		Enabled: true,
	})

	auditor, err := ssl.NewAuditor(ssl.AuditOptions{Logger: logger})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}

	mgr, err := ssl.NewManager(ssl.ManagerOptions{
		Logger: logger,
		Detector: ssl.NewDetector(ssl.DetectorOptions{
			CertbotPath: certbot,
			Executor:    exec,
			Logger:      logger,
		}),
		Sites:    sites,
		Executor: exec,
		Auditor:  auditor,
		Email:    "admin@example.com",
	})
	if err != nil {
		t.Fatalf("构造 SSL 管理器失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.sslMgr = mgr
	rebuildTestRoutes(s)

	return &sslTestEnv{server: s, manager: mgr, exec: exec, root: root}
}

// noCertsStubOutput 是 certbot 无证书时的输出（与真实输出一致）。
const noCertsStubOutput = `Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
No certificates found.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`

// sslStubSites 是内存站点表。
type sslStubSites struct {
	sites map[string]ssl.SiteRef
}

func newSSLStubSites(refs ...ssl.SiteRef) *sslStubSites {
	m := make(map[string]ssl.SiteRef, len(refs))
	for _, r := range refs {
		m[r.Name] = r
	}
	return &sslStubSites{sites: m}
}

func (s *sslStubSites) GetSite(name string) (ssl.SiteRef, error) {
	r, ok := s.sites[name]
	if !ok {
		return ssl.SiteRef{}, fmt.Errorf("站点 %s 不存在", name)
	}
	return r, nil
}

func (s *sslStubSites) ListSites() ([]ssl.SiteRef, error) {
	out := make([]ssl.SiteRef, 0, len(s.sites))
	for _, r := range s.sites {
		out = append(out, r)
	}
	return out, nil
}

// do 发起一次已登录的 JSON 请求。
func (e *sslTestEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body, login(t, e.server))
}

// doAnon 发起一次未登录请求。
func (e *sslTestEnv) doAnon(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body)
}

// decodeSSLMap 解析响应体并断言 Content-Type 是 JSON。
//
// 断言 Content-Type 是必需的：未注册的 /api 路径会落到 SPA 兜底返回
// **200 + text/html**（坑位 47）。只看状态码会把"接口没注册"误判为成功。
func decodeSSLMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("响应 Content-Type 应为 JSON，实际 %q（body 前 200 字: %s）",
			ct, truncate(rec.Body.String(), 200))
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("解析响应失败: %v（body: %s）", err, rec.Body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// 路由顺序（4.1/4.2/4.3 连续踩过三次的坑）
// ---------------------------------------------------------------------------

// TestSSLAuditRouteNotShadowedByWildcard 锁定 /api/ssl/audit 不被通配吃掉。
//
// ########## 为什么这条测试必须存在 ##########
//
// "/api/ssl/audit" 与 "/api/ssl/{name}/..." 形态相近。若注册顺序反了，
// 查询审计会变成"查看名为 audit 的站点的证书"，
// 返回一个 404 或错误的站点对象——而前端只会说一句
// "加载失败"，排查方向完全错。
//
// 4.1（/api/plugins/audit）、4.2（/api/files/audit）、
// 4.3（/api/sites/audit）**连续踩过三次**同一个坑，
// 因此本次从一开始就用测试锁死。
func TestSSLAuditRouteNotShadowedByWildcard(t *testing.T) {
	env := newSSLTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/ssl/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/ssl/audit 状态码 = %d，期望 200（被 {name} 通配吃掉了？）body=%s",
			rec.Code, rec.Body.String())
	}

	body := decodeSSLMap(t, rec)
	// 必须是审计结构。
	if _, ok := body["events"]; !ok {
		t.Errorf("响应缺少 events 字段，说明命中的不是审计接口: %v", keysOfSSL(body))
	}
	if _, ok := body["stats"]; !ok {
		t.Errorf("响应缺少 stats 字段，说明命中的不是审计接口: %v", keysOfSSL(body))
	}
	// 绝不能是"站点不存在"这类错误。
	if _, ok := body["error"]; ok {
		t.Errorf("审计接口不应返回错误: %v", body)
	}
}

// TestSSLCapabilitiesRouteNotShadowedByWildcard 锁定 capabilities 不被通配吃掉。
func TestSSLCapabilitiesRouteNotShadowedByWildcard(t *testing.T) {
	env := newSSLTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/ssl/capabilities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/ssl/capabilities 状态码 = %d，期望 200。body=%s",
			rec.Code, rec.Body.String())
	}

	body := decodeSSLMap(t, rec)
	if _, ok := body["challenge_type"]; !ok {
		t.Errorf("响应缺少 challenge_type 字段，说明命中的不是能力接口: %v", keysOfSSL(body))
	}
	if _, ok := body["scope_note"]; !ok {
		t.Errorf("响应缺少 scope_note 字段: %v", keysOfSSL(body))
	}
	if _, ok := body["error"]; ok {
		t.Errorf("能力接口不应返回错误: %v", body)
	}
}

// keysOfSSL 返回 map 的键（用于错误信息）。
func keysOfSSL(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

// TestSSLRoutesRequireAuth 验证所有 SSL 接口都要求登录。
//
// 这是最重要的一条边界：SSL 接口会消耗外部配额、改写 HTTPS 配置，
// 未登录绝对不能触达。
func TestSSLRoutesRequireAuth(t *testing.T) {
	env := newSSLTestServer(t)

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/ssl"},
		{http.MethodGet, "/api/ssl/capabilities"},
		{http.MethodGet, "/api/ssl/audit"},
		{http.MethodPost, "/api/ssl/demo/issue"},
		{http.MethodPost, "/api/ssl/demo/renew"},
		{http.MethodGet, "/api/ssl/does-not-exist"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec := env.doAnon(t, c.method, c.path, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("未登录访问 %s %s 状态码 = %d，期望 401。body=%s",
					c.method, c.path, rec.Code, rec.Body.String())
			}
			// 关键：未登录时**不能执行任何 certbot 命令**
			if env.exec.called("certonly") || env.exec.called("renew") {
				t.Error("未登录的请求竟然触发了 certbot 命令")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GET /api/ssl
// ---------------------------------------------------------------------------

// TestSSLStatusRoute 验证状态接口。
func TestSSLStatusRoute(t *testing.T) {
	env := newSSLTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/ssl", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200。body=%s", rec.Code, rec.Body.String())
	}

	body := decodeSSLMap(t, rec)

	// 站点列表必须存在且包含我们的站点。
	sites, ok := body["sites"].([]any)
	if !ok {
		t.Fatalf("sites 字段类型错误: %T", body["sites"])
	}
	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d 个", len(sites))
	}
	first, _ := sites[0].(map[string]any)
	if first["site"] != "demo" {
		t.Errorf("站点名 = %v，期望 demo", first["site"])
	}
	if first["status"] != ssl.StatusNone {
		t.Errorf("未申请证书时状态 = %v，期望 %q", first["status"], ssl.StatusNone)
	}

	// 能力字段
	if body["available"] != true {
		t.Errorf("available = %v，期望 true（假 certbot 可用）", body["available"])
	}
	if body["renew_days"] == nil {
		t.Error("缺少 renew_days 字段")
	}
	// 权限清单（前端据此禁用按钮）
	if _, ok := body["permissions"]; !ok {
		t.Error("缺少 permissions 字段")
	}
	// 审计状态
	if _, ok := body["audit"]; !ok {
		t.Error("缺少 audit 字段")
	}
}

// TestSSLStatusWithoutClient 验证无 certbot 时接口仍返回 200。
//
// 降级策略与 4.1/4.3 一致：环境不具备能力时返回 200 + available=false，
// 让前端能渲染出带原因的说明，而不是一个红色错误框。
func TestSSLStatusWithoutClient(t *testing.T) {
	env := newSSLTestServer(t)
	// 换一个指向不存在路径的管理器
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := ssl.NewManager(ssl.ManagerOptions{
		Logger: logger,
		Detector: ssl.NewDetector(ssl.DetectorOptions{
			CertbotPath: "/nonexistent/certbot",
			Logger:      logger,
		}),
		Sites: newSSLStubSites(ssl.SiteRef{
			Name: "demo", Domain: "demo.example.com", Root: env.root, Type: "static",
		}),
		Email: "a@b.com",
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	env.server.sslMgr = mgr
	rebuildTestRoutes(env.server)

	rec := env.do(t, http.MethodGet, "/api/ssl", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("无 certbot 时状态码 = %d，期望 200。body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSSLMap(t, rec)
	if body["available"] != false {
		t.Errorf("available = %v，期望 false", body["available"])
	}
	if body["unavailable_reason"] == nil || body["unavailable_reason"] == "" {
		t.Error("应当给出不可用原因")
	}
	// 站点列表仍然要返回，否则用户连"我有几个站点"都看不到
	if sites, ok := body["sites"].([]any); !ok || len(sites) != 1 {
		t.Errorf("站点列表仍应返回，实际 %v", body["sites"])
	}
}

// ---------------------------------------------------------------------------
// GET /api/ssl/capabilities
// ---------------------------------------------------------------------------

// TestSSLCapabilitiesRoute 验证能力接口内容。
func TestSSLCapabilitiesRoute(t *testing.T) {
	env := newSSLTestServer(t)

	rec := env.do(t, http.MethodGet, "/api/ssl/capabilities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", rec.Code)
	}
	body := decodeSSLMap(t, rec)

	if body["available"] != true {
		t.Errorf("available = %v，期望 true", body["available"])
	}
	// 本期固定 HTTP-01
	if body["challenge_type"] != "http-01" {
		t.Errorf("challenge_type = %v，期望 http-01", body["challenge_type"])
	}
	if body["webroot_required"] != true {
		t.Error("HTTP-01 需要 webroot")
	}
	if body["email_configured"] != true {
		t.Error("配置了邮箱，email_configured 应为 true")
	}
	// scope_note 必须说明面板会调用外部程序
	scope, _ := body["scope_note"].(string)
	if !strings.Contains(scope, "certbot") {
		t.Errorf("scope_note 应当说明会调用 certbot，实际: %s", scope)
	}
}

// ---------------------------------------------------------------------------
// POST /api/ssl/{name}/issue
// ---------------------------------------------------------------------------

// TestSSLIssueRouteSucceeds 验证申请成功路径。
func TestSSLIssueRouteSucceeds(t *testing.T) {
	env := newSSLTestServer(t)

	// 让 certbot 先"签发成功"，之后 certificates 返回证书
	now := time.Now()
	var issued bool
	env.exec.handler = func(args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "certonly"):
			issued = true
			return "Successfully received certificate.", "", nil
		case strings.Contains(joined, "certificates"):
			if issued {
				return sslStubCertOutput("demo", "demo.example.com", 90, now), "", nil
			}
			return noCertsStubOutput, "", nil
		}
		return "", "", nil
	}

	rec := env.do(t, http.MethodPost, "/api/ssl/demo/issue", map[string]any{"force": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200。body=%s", rec.Code, rec.Body.String())
	}

	body := decodeSSLMap(t, rec)
	if body["issued"] != true {
		t.Errorf("issued = %v，期望 true", body["issued"])
	}
	if body["domain"] != "demo.example.com" {
		t.Errorf("domain = %v", body["domain"])
	}
	// 命令形状
	cmd, _ := body["command"].(string)
	if !strings.Contains(cmd, "certonly") || !strings.Contains(cmd, "--webroot") {
		t.Errorf("command 应当使用 certonly + webroot，实际: %s", cmd)
	}
}

// TestSSLIssueRouteWildcardRejected 验证通配符域名被拒绝为 400。
//
// 这条用例覆盖了"输入校验 → HTTP 状态码 → 未触发外部命令"的完整链路。
func TestSSLIssueRouteWildcardRejected(t *testing.T) {
	env := newSSLTestServer(t)
	env.server.sslMgr = mustSSLManagerWithSite(t, env, ssl.SiteRef{
		Name: "wild", Domain: "*.example.com", Root: env.root, Type: "static",
	})
	rebuildTestRoutes(env.server)

	rec := env.do(t, http.MethodPost, "/api/ssl/wild/issue", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("通配符域名状态码 = %d，期望 400。body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSSLMap(t, rec)
	// hint 必须说明"通配符需要 DNS 验证"
	hint, _ := body["hint"].(string)
	if !strings.Contains(hint, "DNS") {
		t.Errorf("hint 应当说明通配符需要 DNS 验证，实际: %s", hint)
	}
	// 关键：被拒绝时**不能触发 certbot**
	if env.exec.called("certonly") {
		t.Error("被拒绝的申请竟然执行了 certbot（会浪费 CA 配额）")
	}
}

// TestSSLIssueRouteSiteNotFound 验证站点不存在返回 404。
func TestSSLIssueRouteSiteNotFound(t *testing.T) {
	env := newSSLTestServer(t)

	rec := env.do(t, http.MethodPost, "/api/ssl/nonexistent/issue", map[string]any{})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404。body=%s", rec.Code, rec.Body.String())
	}
	if env.exec.called("certonly") {
		t.Error("站点不存在时不该执行 certbot")
	}
}

// TestSSLIssueRouteProxySiteRejected 验证反代站（无 webroot）被拒绝。
func TestSSLIssueRouteProxySiteRejected(t *testing.T) {
	env := newSSLTestServer(t)
	env.server.sslMgr = mustSSLManagerWithSite(t, env, ssl.SiteRef{
		Name: "app", Domain: "app.example.com", Type: "proxy",
		Upstream: "http://127.0.0.1:3000",
	})
	rebuildTestRoutes(env.server)

	rec := env.do(t, http.MethodPost, "/api/ssl/app/issue", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("反代站状态码 = %d，期望 400。body=%s", rec.Code, rec.Body.String())
	}
	if env.exec.called("certonly") {
		t.Error("反代站被拒绝时不该执行 certbot")
	}
}

// TestSSLIssueRouteWithoutClientReturns503 验证无 certbot 时返回 503。
//
// 503（而非 4xx）的语义是"环境不具备该能力"，
// 而不是"请求写错了"——这样用户能正确理解要去装 certbot。
func TestSSLIssueRouteWithoutClientReturns503(t *testing.T) {
	env := newSSLTestServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := ssl.NewManager(ssl.ManagerOptions{
		Logger: logger,
		Detector: ssl.NewDetector(ssl.DetectorOptions{
			CertbotPath: "/nonexistent/certbot",
			Logger:      logger,
		}),
		Sites: newSSLStubSites(ssl.SiteRef{
			Name: "demo", Domain: "demo.example.com", Root: env.root, Type: "static",
		}),
		Email: "a@b.com",
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	env.server.sslMgr = mgr
	rebuildTestRoutes(env.server)

	rec := env.do(t, http.MethodPost, "/api/ssl/demo/issue", map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("无客户端状态码 = %d，期望 503。body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSSLMap(t, rec)
	hint, _ := body["hint"].(string)
	if !strings.Contains(hint, "certbot") {
		t.Errorf("hint 应当告诉用户装 certbot，实际: %s", hint)
	}
}

// TestSSLIssueRouteBadJSON 验证请求体畸形返回 400。
func TestSSLIssueRouteBadJSON(t *testing.T) {
	env := newSSLTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/ssl/demo/issue",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(login(t, env.server))

	rec := httptest.NewRecorder()
	env.server.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d，期望 400。body=%s", rec.Code, rec.Body.String())
	}
	if env.exec.called("certonly") {
		t.Error("请求体畸形时不该执行 certbot")
	}
}

// TestSSLIssueRouteNoBodyAllowed 验证不带请求体也能申请。
//
// 前端「一键申请」按钮不带 body 是最自然的用法，
// 若接口强制要求 JSON body，用户会得到一个莫名其妙的 400。
func TestSSLIssueRouteNoBodyAllowed(t *testing.T) {
	env := newSSLTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/ssl/demo/issue", nil)
	req.AddCookie(login(t, env.server))

	rec := httptest.NewRecorder()
	env.server.handler.ServeHTTP(rec, req)

	// 不带 body 会正常走到申请逻辑（此处 certbot 返回"无证书"，
	// 因此最终是一个业务错误而不是 400 参数错误）
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("不带请求体不该被当成参数错误。body=%s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// POST /api/ssl/{name}/renew
// ---------------------------------------------------------------------------

// TestSSLRenewRouteSkipped 验证"未到续期窗口"被如实报告。
//
// ########## 这条测试锁的是一个真实的误导风险 ##########
//
// `certbot renew` 对未进入续期窗口的证书输出
// "not yet due for renewal" 并以 exit 0 退出。
// 若接口把它当成"续期成功"，前端会显示"续期成功"，
// 而到期时间毫无变化——用户会怀疑功能是假的。
//
// 因此响应里必须有 skipped=true、renewed=false。
func TestSSLRenewRouteSkipped(t *testing.T) {
	env := newSSLTestServer(t)
	now := time.Now()
	env.exec.handler = func(args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			return "Certificate not yet due for renewal; no action taken.", "", nil
		case strings.Contains(joined, "certificates"):
			return sslStubCertOutput("demo", "demo.example.com", 80, now), "", nil
		}
		return "", "", nil
	}

	rec := env.do(t, http.MethodPost, "/api/ssl/demo/renew", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200。body=%s", rec.Code, rec.Body.String())
	}

	body := decodeSSLMap(t, rec)
	if body["renewed"] != false {
		t.Errorf("renewed = %v，期望 false（未到续期窗口）", body["renewed"])
	}
	if body["skipped"] != true {
		t.Errorf("skipped = %v，期望 true", body["skipped"])
	}
}

// TestSSLRenewRouteFailure 验证续期失败返回 502。
func TestSSLRenewRouteFailure(t *testing.T) {
	env := newSSLTestServer(t)
	env.exec.handler = func(args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--version") {
			return "certbot 1.21.0", "", nil
		}
		if strings.Contains(joined, "renew") {
			return "", "Failed to renew certificate demo.example.com", fmt.Errorf("exit status 1")
		}
		return noCertsStubOutput, "", nil
	}

	rec := env.do(t, http.MethodPost, "/api/ssl/demo/renew", map[string]any{})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("状态码 = %d，期望 502。body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSSLMap(t, rec)
	// 错误里必须带 certbot 的原始输出，否则用户无从判断原因
	errMsg, _ := body["error"].(string)
	if !strings.Contains(errMsg, "Failed to renew") {
		t.Errorf("错误信息应包含 certbot 的原始输出，实际: %s", errMsg)
	}
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

// TestSSLIssueWritesAudit 验证申请会写审计。
//
// 这是本模块**唯一会消耗外部配额**的操作，
// "谁在什么时候申请了什么"必须有据可查。
func TestSSLIssueWritesAudit(t *testing.T) {
	env := newSSLTestServer(t)
	now := time.Now()
	var issued bool
	env.exec.handler = func(args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "certonly"):
			issued = true
			return "Successfully received certificate.", "", nil
		case strings.Contains(joined, "certificates"):
			if issued {
				return sslStubCertOutput("demo", "demo.example.com", 90, now), "", nil
			}
			return noCertsStubOutput, "", nil
		}
		return "", "", nil
	}

	rec := env.do(t, http.MethodPost, "/api/ssl/demo/issue", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("申请失败: %d %s", rec.Code, rec.Body.String())
	}

	// 查询审计接口
	auditRec := env.do(t, http.MethodGet, "/api/ssl/audit", nil)
	auditBody := decodeSSLMap(t, auditRec)
	events, _ := auditBody["events"].([]any)
	if len(events) == 0 {
		t.Fatal("申请操作没有留下审计记录")
	}

	ev, _ := events[0].(map[string]any)
	if ev["action"] != ssl.ActionIssue {
		t.Errorf("action = %v，期望 %q", ev["action"], ssl.ActionIssue)
	}
	if ev["target"] != "demo" {
		t.Errorf("target = %v，期望 demo", ev["target"])
	}
	if ev["kind"] != ssl.KindSSL {
		t.Errorf("kind = %v，期望 %q", ev["kind"], ssl.KindSSL)
	}
	if ev["source"] != ssl.SourceCore {
		t.Errorf("source = %v，期望 %q（核心自带，不伪造插件 ID）", ev["source"], ssl.SourceCore)
	}
	// 这两个字段是 SSL 审计的核心价值
	if ev["issued"] != true {
		t.Errorf("issued = %v，期望 true（配额已消耗）", ev["issued"])
	}
	if ev["applied"] != true {
		t.Errorf("applied = %v，期望 true", ev["applied"])
	}
	// 必须记录发起人
	if user, _ := ev["user"].(string); user == "" {
		t.Error("审计必须记录操作者")
	}
}

// TestSSLDeniedInputWritesAudit 验证被输入校验拒绝的申请会记为 denied。
//
// 这让我们能区分"有人在探测注入载荷"与"申请真的失败了"：
// denied 的含义是"请求没有到达任何外部命令"。
func TestSSLDeniedInputWritesAudit(t *testing.T) {
	env := newSSLTestServer(t)
	env.server.sslMgr = mustSSLManagerWithSite(t, env, ssl.SiteRef{
		Name: "wild", Domain: "*.example.com", Root: env.root, Type: "static",
	})
	rebuildTestRoutes(env.server)

	rec := env.do(t, http.MethodPost, "/api/ssl/wild/issue", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d，期望 400", rec.Code)
	}

	auditRec := env.do(t, http.MethodGet, "/api/ssl/audit", nil)
	auditBody := decodeSSLMap(t, auditRec)
	events, _ := auditBody["events"].([]any)
	if len(events) == 0 {
		t.Fatal("被拒绝的申请没有留下审计记录")
	}
	ev, _ := events[0].(map[string]any)
	if ev["outcome"] != ssl.AuditDenied {
		t.Errorf("outcome = %v，期望 %q（输入校验失败 = 未到达外部命令）",
			ev["outcome"], ssl.AuditDenied)
	}
}

// TestSSLAuditFilters 验证审计过滤参数。
func TestSSLAuditFilters(t *testing.T) {
	env := newSSLTestServer(t)

	// 造两条不同动作的记录
	env.manager.Auditor().Record(ssl.AuditEvent{
		User: "admin", Action: ssl.ActionIssue, Target: "a", Outcome: ssl.AuditAllowed,
	})
	env.manager.Auditor().Record(ssl.AuditEvent{
		User: "admin", Action: ssl.ActionRenew, Target: "b", Outcome: ssl.AuditFailed,
	})

	tests := []struct {
		query string
		want  int
	}{
		{"", 2},
		{"?action=issue", 1},
		{"?target=b", 1},
		{"?outcome=failed", 1},
		{"?limit=1", 1},
		{"?action=nonexistent", 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			rec := env.do(t, http.MethodGet, "/api/ssl/audit"+tt.query, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，期望 200", rec.Code)
			}
			body := decodeSSLMap(t, rec)
			events, _ := body["events"].([]any)
			if len(events) != tt.want {
				t.Errorf("查询 %q 返回 %d 条，期望 %d 条", tt.query, len(events), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 未注册路径
// ---------------------------------------------------------------------------

// TestSSLUnknownPathReturnsJSON404 验证未注册路径返回 JSON 404。
//
// ########## 为什么这条很重要 ##########
//
// 4.2 实测发现的真实缺陷：未注册的 /api/files/* 路径落到了
// 前端 SPA 兜底，返回 **200 + <!doctype html>**。
// 前端只会报一句"后端返回了非 JSON 内容"，无从判断原因。
//
// 这里从一开始就补上前缀兜底，并用测试锁死。
func TestSSLUnknownPathReturnsJSON404(t *testing.T) {
	env := newSSLTestServer(t)

	paths := []string{
		"/api/ssl/does-not-exist",
		"/api/ssl/demo/unknown-action",
		"/api/ssl/demo/issue/extra",
		"/api/ssl/nested/deep/path",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			rec := env.do(t, http.MethodGet, p, nil)
			if rec.Code != http.StatusNotFound {
				t.Errorf("状态码 = %d，期望 404。body=%s", rec.Code, rec.Body.String())
			}
			// 必须是 JSON，不能是 HTML 兜底
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q，期望 JSON（落到了 SPA 兜底？）", ct)
			}
			if strings.Contains(rec.Body.String(), "<!doctype html") {
				t.Error("返回了 HTML 兜底页面，而不是 JSON 404")
			}
		})
	}
}

// TestSSLUnavailableWithoutManager 验证未注入管理器时返回 JSON 503。
func TestSSLUnavailableWithoutManager(t *testing.T) {
	s := newAuthedTestServer(t)
	// sslMgr 保持 nil
	rebuildTestRoutes(s)

	for _, p := range []string{"/api/ssl", "/api/ssl/capabilities", "/api/ssl/audit"} {
		t.Run(p, func(t *testing.T) {
			rec := doJSON(t, s, http.MethodGet, p, nil, login(t, s))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s 状态码 = %d，期望 503", p, rec.Code)
			}
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q，期望 JSON", ct)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// mustSSLManagerWithSite 构造一个只含单个指定站点的 SSL 管理器。
func mustSSLManagerWithSite(t *testing.T, env *sslTestEnv, ref ssl.SiteRef) *ssl.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := ssl.NewManager(ssl.ManagerOptions{
		Logger: logger,
		Detector: ssl.NewDetector(ssl.DetectorOptions{
			CertbotPath: findFakeCertbot(t),
			Executor:    env.exec,
			Logger:      logger,
		}),
		Sites:    newSSLStubSites(ref),
		Executor: env.exec,
		Email:    "admin@example.com",
	})
	if err != nil {
		t.Fatalf("构造 SSL 管理器失败: %v", err)
	}
	return mgr
}

// findFakeCertbot 造一个存在的假 certbot 文件。
func findFakeCertbot(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-certbot")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho certbot 1.21.0\n"), 0o755); err != nil {
		t.Fatalf("写假 certbot 失败: %v", err)
	}
	return path
}

// sslStubCertOutput 生成一份 certbot certificates 的假输出。
func sslStubCertOutput(name, domain string, days int, now time.Time) string {
	expiry := now.AddDate(0, 0, days)
	return fmt.Sprintf(`Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Found the following certs:
  Certificate Name: %s
    Serial Number: deadbeef
    Key Type: RSA
    Domains: %s
    Expiry Date: %s (VALID: %d days)
    Certificate Path: /etc/letsencrypt/live/%s/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/%s/privkey.pem
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`, name, domain, expiry.UTC().Format("2006-01-02 15:04:05-07:00"), days, name, name)
}
