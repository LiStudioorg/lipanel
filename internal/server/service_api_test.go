package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lipanel/internal/service"
)

// ============================================================================
// 服务接口测试（阶段四 4.1）
// ============================================================================

// stubExecutor 让服务层的 systemctl 调用可控，从而能测试真实的 HTTP 行为。
//
// 说明：这里刻意复用 service 包对外暴露的 Executor 接口，
// 而不是在 server 层再造一套 mock —— 保证测的是**真实代码路径**
// （service.Manager.Do → 权限判定 → 审计 → HTTP 响应）。
type stubExecutor struct {
	mu    sync.Mutex
	calls [][]string
	// failWith 非空时，操作类命令（start/stop/restart）返回该 stderr 与错误。
	failWith string
	// loadState 是 show 查询返回的 LoadState（用于模拟服务不存在）。
	loadState string
}

func (s *stubExecutor) Run(_ context.Context, name string, args []string) (string, string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, append([]string{name}, args...))
	failWith := s.failWith
	loadState := s.loadState
	s.mu.Unlock()

	if loadState == "" {
		loadState = "loaded"
	}

	// 判断是 show 查询还是操作命令。
	isShow := false
	for _, a := range args {
		if a == "show" {
			isShow = true
			break
		}
	}

	if isShow {
		if loadState == "not-found" {
			return "LoadState=not-found\nActiveState=inactive\nSubState=dead\n", "", nil
		}
		return "LoadState=loaded\nActiveState=active\nSubState=running\n" +
			"Description=Test Service\nUnitFileState=enabled\n", "", nil
	}

	if failWith != "" {
		return "", failWith, errors.New("exit status 1")
	}
	return "", "", nil
}

func (s *stubExecutor) invocationText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sb strings.Builder
	for _, c := range s.calls {
		sb.WriteString(strings.Join(c, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (s *stubExecutor) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// newServiceTestServer 构造一个注入了 stub 执行器的测试 Server。
//
// 与 newPluginTestServer 同样的做法：先构造带鉴权的 Server，
// 再注入依赖并**重新组装路由**（注册函数在 New 里才跑一次，
// 事后再设字段不会自动生效）。
func newServiceTestServer(t *testing.T, ex service.Executor) (*Server, *service.Manager) {
	t.Helper()

	auditor, err := service.NewAuditor(service.AuditOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}

	mgr, err := service.NewManager(service.Options{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Executor: ex,
		Auditor:  auditor,
		LookPath: func(string) (string, error) { return "/usr/bin/systemctl", nil },
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.serviceMgr = mgr
	rebuildTestRoutes(s)
	return s, mgr
}

// newNoSystemdTestServer 构造一个「系统没有 systemd」的测试服务器。
func newNoSystemdTestServer(t *testing.T) *Server {
	t.Helper()
	mgr, err := service.NewManager(service.Options{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	s := newAuthedTestServer(t)
	s.serviceMgr = mgr
	rebuildTestRoutes(s)
	return s
}

// newServiceTestServerWithManager 用于「未注入服务管理器」的降级测试。
func newServiceTestServerWithoutManager(t *testing.T) *Server {
	t.Helper()
	return newAuthedTestServer(t)
}

// rebuildTestRoutes 重新组装路由，让测试中后注入的依赖生效。
//
// 按**生产环境的真实组装顺序**注册：API 路由在前，SPA 兜底在后。
// 兜底 handler 必须存在：否则"未注册的 /api 路径不能落到 HTML 兜底"
// 这类用例验证不出任何东西（那条路径根本不存在，见 4.2 的一次实测教训）。
func rebuildTestRoutes(s *Server) {
	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)
	s.registerPluginRoutes(mux)
	s.handler = s.withRecovery(s.withRequestLog(s.withSPAFallback(mux)))
}

// withSPAFallback 给测试路由装上前端兜底。
//
// 语义与生产的 static.go 保持一致，尤其是**顺序**：
//
//	① 未注册的 /api* 路径 → JSON 404（先判，绝不能落到 HTML）；
//	② 其余未命中路径      → HTML 兜底页面。
//
// ⚠️ 两个坑都在 4.2 实现时真的踩过：
//   - 让 mux 自己的 "/" 兜底先跑：未注册的 /api 路径会先被渲染成
//     HTML（200），既拿不到 JSON，也让"不落到兜底"的用例失去意义；
//   - 反过来无条件先判 /api 前缀：会把已注册的 /api/login 一起吞掉，
//     症状是**所有依赖登录的测试同时失败**。
//
// 因此这里让 mux 只承载**已注册**路由，未命中由本函数按 /api 前缀分流，
// 与 static.go 里的分支判断逐条对应。
func (s *Server) withSPAFallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)

		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			// /api 前缀：未注册（含 mux 自身给出的 404 文本）统一改写为 JSON，
			// 与 static.go 的行为一致。
			if rec.Code == http.StatusNotFound &&
				strings.Contains(rec.Body.String(), "page not found") {
				writeJSON(w, s.logger, http.StatusNotFound, map[string]string{
					"error": "接口不存在: " + r.URL.Path,
				})
				return
			}
			copyResponse(w, rec)
			return
		}

		if rec.Code != http.StatusNotFound {
			copyResponse(w, rec)
			return
		}
		// 非 /api 的未命中路径：返回前端页面。
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html>"))
	})
}

// copyResponse 把缓冲的响应原样写回。
//
// 为什么要缓冲：ServeMux 对"未注册的 /api 路径"给出的是自带的
// 404 文本，而我们希望像 static.go 那样改成 JSON——
// 只能在写出之前判断并改写，因此必须先把响应接住。
func copyResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

// loginAndDo 登录后发起请求，返回响应记录器。
func loginAndDo(t *testing.T, srv *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	cookie := login(t, srv)
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// ============================================================================
// 鉴权：所有服务接口都必须要求登录
// ============================================================================

func TestServiceEndpointsRequireAuth(t *testing.T) {
	ex := &stubExecutor{}
	srv, _ := newServiceTestServer(t, ex)

	paths := []struct{ method, path string }{
		{"GET", "/api/services"},
		{"GET", "/api/services/audit"},
		{"POST", "/api/services/nginx.service/start"},
		{"POST", "/api/services/nginx.service/stop"},
		{"POST", "/api/services/nginx.service/restart"},
	}

	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未登录状态码 = %d，期望 401", tc.method, tc.path, rec.Code)
		}
	}

	// 关键：未登录不得触发任何命令执行。
	if got := ex.invocationText(); got != "" {
		t.Errorf("未登录请求触发了命令执行:\n%s", got)
	}
}

// ============================================================================
// 列表接口
// ============================================================================

func TestServiceListEndpoint(t *testing.T) {
	ex := &stubExecutor{}
	// 列表走 list-units，需要单独控制返回。
	listEx := &listExecutor{stubExecutor: ex}
	srv, _ := newServiceTestServer(t, listEx)

	rec := loginAndDo(t, srv, "GET", "/api/services")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}

	var resp serviceListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if !resp.Available {
		t.Error("Available = false，期望 true")
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d，期望 2（内部服务应被过滤）", resp.Total)
	}
	if resp.Running != 1 {
		t.Errorf("Running = %d，期望 1", resp.Running)
	}
	// 权限清单必须下发，前端据此禁用按钮。
	if len(resp.Permissions) == 0 {
		t.Error("Permissions 不应为空")
	}
}

// TestServiceListUnavailableSystemd 断言无 systemd 时**返回 200 而非错误**，
// 并带上可展示的原因（计划要求：优雅降级并提示）。
func TestServiceListUnavailableSystemd(t *testing.T) {
	srv := newNoSystemdTestServer(t)

	rec := loginAndDo(t, srv, "GET", "/api/services")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200（降级而非报错）；body=%s", rec.Code, rec.Body.String())
	}

	var resp serviceListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Available {
		t.Error("Available = true，期望 false")
	}
	if resp.UnavailableReason == "" {
		t.Error("UnavailableReason 为空，前端将无法解释为什么不可用")
	}
	if resp.Services == nil {
		t.Error("Services 应为空数组而非 null（前端表格需要可迭代值）")
	}
}

// ============================================================================
// 写操作：成功路径
// ============================================================================

func TestServiceActionsSucceed(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart"} {
		t.Run(action, func(t *testing.T) {
			ex := &stubExecutor{}
			srv, mgr := newServiceTestServer(t, ex)

			rec := loginAndDo(t, srv, "POST", "/api/services/nginx.service/"+action)
			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
			}

			var svc service.Service
			if err := json.Unmarshal(rec.Body.Bytes(), &svc); err != nil {
				t.Fatalf("解析响应失败: %v", err)
			}
			if svc.Name != "nginx.service" {
				t.Errorf("Name = %q，期望 nginx.service", svc.Name)
			}

			// 命令必须真的以正确形式执行。
			txt := ex.invocationText()
			if !strings.Contains(txt, action+" -- nginx.service") {
				t.Errorf("未执行预期的 %s 命令:\n%s", action, txt)
			}

			// 审计必须记录一条 allowed。
			events := mgr.Auditor().Query(service.AuditFilter{})
			if len(events) != 1 {
				t.Fatalf("审计记录 %d 条，期望 1 条", len(events))
			}
			ev := events[0]
			if ev.Outcome != service.AuditAllowed {
				t.Errorf("Outcome = %q，期望 %q", ev.Outcome, service.AuditAllowed)
			}
			if ev.Action != action || ev.Target != "nginx.service" {
				t.Errorf("审计内容 = %+v，action/target 不符", ev)
			}
			// 「记录谁在何时做了什么」——User 是审计的核心字段。
			if ev.User == "" {
				t.Error("审计缺少 User 字段（无法回答「谁干的」）")
			}
			if ev.Status != 200 {
				t.Errorf("审计 Status = %d，期望 200", ev.Status)
			}
		})
	}
}

// ============================================================================
// 写操作：服务不存在 → 404
// ============================================================================

func TestServiceActionNotFound(t *testing.T) {
	ex := &stubExecutor{loadState: "not-found"}
	srv, mgr := newServiceTestServer(t, ex)

	rec := loginAndDo(t, srv, "POST", "/api/services/nonexistent.service/start")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404；body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] == nil {
		t.Error("应返回明确的 error 字段")
	}
	if body["hint"] == nil {
		t.Error("404 应给出 hint 帮助用户定位问题")
	}
	if !strings.Contains(body["error"].(string), "不存在") {
		t.Errorf("错误信息 = %q，期望说明服务不存在", body["error"])
	}

	// 服务不存在时绝不能执行 start 命令。
	if txt := ex.invocationText(); strings.Contains(txt, "start --") {
		t.Errorf("服务不存在却执行了 start:\n%s", txt)
	}
	// 但审计必须留下记录（失败也要留痕）。
	events := mgr.Auditor().Query(service.AuditFilter{Outcome: service.AuditFailed})
	if len(events) != 1 {
		t.Errorf("失败审计记录 %d 条，期望 1 条", len(events))
	}
}

// ============================================================================
// 写操作：权限不足 → 403
// ============================================================================

func TestServiceActionPermissionDenied(t *testing.T) {
	ex := &stubExecutor{
		failWith: "Failed to start nginx.service: Interactive authentication required.",
	}
	srv, mgr := newServiceTestServer(t, ex)

	rec := loginAndDo(t, srv, "POST", "/api/services/nginx.service/start")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403；body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	hint, _ := body["hint"].(string)
	// 提示必须告诉用户「怎么解决」，而不是复述 systemd 原文。
	if !strings.Contains(hint, "root") {
		t.Errorf("hint = %q，期望提示需要 root 权限", hint)
	}

	events := mgr.Auditor().Query(service.AuditFilter{Outcome: service.AuditFailed})
	if len(events) != 1 {
		t.Fatalf("审计记录 %d 条，期望 1 条", len(events))
	}
	if events[0].Status != http.StatusForbidden {
		t.Errorf("审计 Status = %d，期望 403（必须与真实响应一致）", events[0].Status)
	}
}

// ============================================================================
// 写操作：非法服务名 → 400，且不执行任何命令
// ============================================================================

func TestServiceActionInvalidName(t *testing.T) {
	// 这些名字在 URL 里都是合法的路径段，但都不是合法服务名。
	names := []string{
		"..%2f..%2fetc%2fpasswd",
		"foo%3Breboot.service",
		"foo%20bar.service",
		"-now.service",
		"a$(id).service",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ex := &stubExecutor{}
			srv, mgr := newServiceTestServer(t, ex)

			rec := loginAndDo(t, srv, "POST", "/api/services/"+name+"/start")

			// 关键断言：必须是 400 或 404，绝不能是 200。
			if rec.Code == http.StatusOK {
				t.Fatalf("非法服务名 %q 被接受了；body=%s", name, rec.Body.String())
			}
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
				t.Errorf("状态码 = %d，期望 400 或 404；body=%s", rec.Code, rec.Body.String())
			}

			// 最关键的断言：一次 systemctl 都不该执行。
			if txt := ex.invocationText(); txt != "" {
				t.Errorf("非法服务名触发了命令执行:\n%s", txt)
			}
			// 非法输入同样要留痕（可能在探测）。
			if events := mgr.Auditor().Query(service.AuditFilter{}); len(events) == 0 {
				t.Error("非法服务名的请求未被审计")
			}
		})
	}
}

// ============================================================================
// 审计接口
// ============================================================================

func TestServiceAuditEndpoint(t *testing.T) {
	ex := &stubExecutor{}
	srv, _ := newServiceTestServer(t, ex)

	// 先做两次操作，产生审计记录。
	loginAndDo(t, srv, "POST", "/api/services/nginx.service/start")
	loginAndDo(t, srv, "POST", "/api/services/cron.service/stop")

	rec := loginAndDo(t, srv, "GET", "/api/services/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Events []service.AuditEvent `json:"events"`
		Stats  service.AuditStats   `json:"stats"`
		Filter map[string]any       `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("审计事件 %d 条，期望 2 条", len(resp.Events))
	}
	if resp.Stats.Total != 2 {
		t.Errorf("Stats.Total = %d，期望 2", resp.Stats.Total)
	}

	// 按服务过滤。
	rec = loginAndDo(t, srv, "GET", "/api/services/audit?target=nginx.service")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Events) != 1 || resp.Events[0].Target != "nginx.service" {
		t.Errorf("按 target 过滤失败: %+v", resp.Events)
	}

	// 按结果过滤。
	rec = loginAndDo(t, srv, "GET", "/api/services/audit?outcome=allowed")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Events) != 2 {
		t.Errorf("按 outcome=allowed 过滤返回 %d 条，期望 2 条", len(resp.Events))
	}
	rec = loginAndDo(t, srv, "GET", "/api/services/audit?outcome=denied")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Events) != 0 {
		t.Errorf("按 outcome=denied 过滤返回 %d 条，期望 0 条", len(resp.Events))
	}
}

// TestServiceAuditMarksSourceAsCore 断言审计事件的来源被如实标注为 core。
//
// 设计要点：服务管理是**核心自带**能力，不经过插件转发通道，
// 因此来源记为 core，而**不是**伪造一个插件 ID（如 "core:systemd"）。
// 伪造插件 ID 会让插件审计页冒出一个根本不存在的"插件"、统计失真。
func TestServiceAuditMarksSourceAsCore(t *testing.T) {
	ex := &stubExecutor{}
	srv, mgr := newServiceTestServer(t, ex)

	loginAndDo(t, srv, "POST", "/api/services/nginx.service/start")

	events := mgr.Auditor().Query(service.AuditFilter{})
	if len(events) != 1 {
		t.Fatalf("审计记录 %d 条，期望 1 条", len(events))
	}
	if events[0].Source != service.SourceCore {
		t.Errorf("Source = %q，期望 %q（核心自带能力应标记为 core）",
			events[0].Source, service.SourceCore)
	}
	if events[0].Kind != "service" {
		t.Errorf("Kind = %q，期望 service", events[0].Kind)
	}
}

// TestServiceAuditRouteNotShadowedByWildcard 断言 /api/services/audit
// 不会被 /api/services/{name}/... 的通配路由吃掉。
//
// 这是阶段三在 /api/plugins/audit 上踩过的坑的回归测试：
// 若注册顺序写错，"audit" 会被当成服务名，
// 查询审计会返回「服务 audit 不存在」而不是审计列表。
func TestServiceAuditRouteNotShadowedByWildcard(t *testing.T) {
	ex := &stubExecutor{loadState: "not-found"}
	srv, _ := newServiceTestServer(t, ex)

	rec := loginAndDo(t, srv, "GET", "/api/services/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200（审计路由被通配路由遮蔽了）；body=%s",
			rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	// 审计接口的响应必须含 events 字段（而不是服务的错误结构）。
	if _, ok := resp["events"]; !ok {
		t.Errorf("响应缺少 events 字段，说明命中的不是审计接口: %s", rec.Body.String())
	}
}

// ============================================================================
// 未注入管理器时的降级
// ============================================================================

func TestServiceEndpointsUnavailableWhenNotInjected(t *testing.T) {
	// 不注入服务管理器：模拟未启用服务管理的部署。
	srv := newServiceTestServerWithoutManager(t)

	for _, path := range []string{"/api/services", "/api/services/audit"} {
		rec := loginAndDo(t, srv, "GET", path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s 状态码 = %d，期望 503", path, rec.Code)
		}
		// 必须是 JSON，不能落到前端 HTML 兜底。
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("GET %s Content-Type = %q，期望 JSON", path, ct)
		}
	}
}

// ============================================================================
// 审计隔离：服务审计不得污染插件审计
// ============================================================================

// TestServiceAuditIsolatedFromPluginAudit 是本设计的关键性质：
// 两者「统一落盘、分别查询」——各自查询只应看到自己的事件。
func TestServiceAuditIsolatedFromPluginAudit(t *testing.T) {
	ex := &stubExecutor{}
	srv, mgr := newServiceTestServer(t, ex)

	loginAndDo(t, srv, "POST", "/api/services/nginx.service/start")

	// 服务审计有 1 条。
	if got := len(mgr.Auditor().Query(service.AuditFilter{})); got != 1 {
		t.Errorf("服务审计 %d 条，期望 1 条", got)
	}

	// 这份 Server 没有插件管理器，因此插件审计接口应返回 503，
	// 且服务事件不会出现在插件审计里。
	rec := loginAndDo(t, srv, "GET", "/api/plugins/audit")
	if rec.Code == http.StatusOK {
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if events, ok := resp["events"].([]any); ok && len(events) > 0 {
			t.Errorf("插件审计中出现了 %d 条记录，服务事件不应污染插件审计", len(events))
		}
	}
}

// listExecutor 让 list-units / list-unit-files 返回可控内容。
type listExecutor struct {
	*stubExecutor
}

func (l *listExecutor) Run(ctx context.Context, name string, args []string) (string, string, error) {
	for _, a := range args {
		if a == "list-unit-files" {
			// 全集：nginx（运行中）、cron（已停止）、两个内部单元。
			return `  nginx.service        enabled
  cron.service         enabled
  systemd-journald.service static
  user@1000.service    enabled
`, "", nil
		}
		if a == "list-units" {
			return `  nginx.service        loaded active running Web server
  cron.service         loaded inactive dead   Cron
  systemd-journald.service loaded active running Journal
  user@1000.service    loaded active running User manager
`, "", nil
		}
	}
	return l.stubExecutor.Run(ctx, name, args)
}
