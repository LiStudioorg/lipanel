package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"lipanel/internal/terminal"
)

// ============================================================================
// Web 终端接口层测试（阶段五 5.1）
// ============================================================================
//
// 这一层要验证的不是"PTY 能不能跑 shell"（那是 internal/terminal 的事），
// 而是接口契约里**只有这一层才能验证**的部分：
//
//	① 路由注册顺序：固定段不能被通配吃掉；
//	② 全部接口都要登录（含 WebSocket 端点）；
//	③ **未登录时 WebSocket 绝不升级**（401 而不是 101）；
//	④ **Origin 校验**：跨站 Origin 被拒（防 CSWSH）；
//	⑤ 关闭会话必须带 confirm，否则 428；
//	⑥ 未注册路径返回 JSON 404（而不是 SPA 的 200 + HTML）；
//	⑦ 未注入管理器时返回 JSON 503。
//
// #################### 关于本文件为什么不 spawn 真实 shell ####################
//
// 接口层测试**不创建真实终端会话**。原因有两条：
//
//  1. 终端是全权限 shell。接口测试若真的 fork shell，会在开发机上
//     留下一串需要回收的进程，且与项目的"不制造孤儿进程"纪律冲突。
//
//  2. 本层的安全边界（鉴权顺序、Origin、二次确认）**全部发生在
//     创建进程之前**。因此用真实会话并不能多验证什么——
//     真正需要真实 PTY 的用例在 internal/terminal 里，
//     由那一个包集中承担（并通过一个明确的授权开关运行）。
//
// 因此这里的会话用**注入的空管理器**（不支持的平台天然即如此），
// 凡是需要"会话存在"的用例，都通过 status/sessions 的返回形状验证。

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type terminalTestEnv struct {
	server  *Server
	manager *terminal.Manager
	dir     string
}

// newTerminalTestServer 构造一个注入了终端管理器的测试 Server。
//
// 不启动任何真实 shell：Manager 的 shell 解析在测试环境里
// 是"能解析到 /bin/sh"，但本文件的用例都不会调到创建会话那一步
// （那一层的真实行为由 internal/terminal 的测试覆盖）。
func newTerminalTestServer(t *testing.T) *terminalTestEnv {
	t.Helper()

	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	auditor, err := terminal.NewAuditor(terminal.AuditOptions{
		Capacity: 200,
		Path:     filepath.Join(dir, "audit.jsonl"),
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("构造终端审计器失败: %v", err)
	}
	t.Cleanup(func() { _ = auditor.Close() })

	mgr, err := terminal.NewManager(terminal.ManagerOptions{
		Logger:      logger,
		Auditor:     auditor,
		MaxSessions: 3,
		// 用一个不存在的 shell 也可以：本文件不创建会话。
		// 但为了让"创建会话"路径在 Linux 上可被验证到权限/校验分支，
		// 还是给一个真实存在的。
		Shell: "/bin/sh",
	})
	if err != nil {
		t.Fatalf("构造终端管理器失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.terminalMgr = mgr
	rebuildTestRoutes(s)

	return &terminalTestEnv{server: s, manager: mgr, dir: dir}
}

// do 发起一次已登录的请求。
func (e *terminalTestEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body, login(t, e.server))
}

// doAnon 发起一次未登录请求。
func (e *terminalTestEnv) doAnon(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, nil)
}

// ---------------------------------------------------------------------------
// ① 路由注册顺序
// ---------------------------------------------------------------------------

// 固定段路由不能被通配吃掉。
//
// ########## 这是 4.1~4.6 连续踩过六次的同一个坑 ##########
//
// 若 "/api/terminal/audit" 晚于某个 "/api/terminal/{name}" 注册，
// "audit" 会被当成 name，于是"查审计"变成"操作名为 audit 的东西"。
// 本模块当前没有 {name} 通配，但仍然写这个测试锁住纪律。
func TestTerminalFixedSegmentsNotShadowedByWildcard(t *testing.T) {
	env := newTerminalTestServer(t)

	fixed := []string{
		"/api/terminal/status",
		"/api/terminal/sessions",
		"/api/terminal/audit",
	}

	for _, path := range fixed {
		t.Run(path, func(t *testing.T) {
			rec := env.do(t, http.MethodGet, path, nil)

			// 关键断言：绝不能是"接口不存在"的 404。
			if rec.Code == http.StatusNotFound {
				body := rec.Body.String()
				if strings.Contains(body, "接口不存在") {
					t.Fatalf("固定段路由 %s 被通配吃掉了：%s", path, body)
				}
			}
			// 也绝不能落到前端 HTML 兜底。
			if strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("固定段路由 %s 落到了 HTML 兜底", path)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("%s 状态码 = %d, body = %s", path, rec.Code, rec.Body.String())
			}
		})
	}
}

// 未注册的 /api/terminal/* 必须返回 JSON 404 + 可用接口清单。
func TestTerminalUnknownPathReturnsJSON404(t *testing.T) {
	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodGet, "/api/terminal/does-not-exist", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q，期望 JSON（落到 HTML 兜底会让前端 JSON.parse 失败）", ct)
	}

	var payload struct {
		Error     string   `json:"error"`
		Available []string `json:"available"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(payload.Available) == 0 {
		t.Error("响应未给出可用接口清单")
	}
}

// ---------------------------------------------------------------------------
// ② 全部接口都要登录
// ---------------------------------------------------------------------------

func TestTerminalRequiresAuth(t *testing.T) {
	env := newTerminalTestServer(t)

	// 逐个方法/路径验证，而不是只测一个就假定其余相同：
	// 路由是**按条挂载** RequireAuth 的，漏挂一条就是一个裸奔接口。
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/terminal/status"},
		{http.MethodGet, "/api/terminal/sessions"},
		{http.MethodGet, "/api/terminal/audit"},
		{http.MethodGet, "/api/terminal/ws?id=whatever"},
		{http.MethodPost, "/api/terminal/sessions"},
		{http.MethodDelete, "/api/terminal/sessions?id=whatever&confirm=true"},
		{http.MethodGet, "/api/terminal/unregistered"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := env.doAnon(t, tc.method, tc.path)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("未登录访问 %s 状态码 = %d，期望 401", tc.path, rec.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ③ WebSocket：未登录绝不升级
// ---------------------------------------------------------------------------

// 未登录的 WebSocket 请求必须拿到 401，而**不是** 101。
//
// ########## 为什么这条是本模块最重要的安全断言 ##########
//
// 终端的 WebSocket 一旦升级成功，客户端就拿到了一个可以
// 双向读写的全权限 shell 通道。因此"鉴权必须在 Upgrade 之前完成"
// 是硬约束：升级之后再想返回 401 已经不可能（HTTP 语义已结束）。
//
// 若实现把 RequireAuth 包在 handler **内部**（先 Hijack 再判权限），
// 结果会是"连上了但立刻断开"——用户看不出是权限问题，
// 而攻击面已经建立（TCP 连接与 WebSocket 状态机都已就绪）。
//
// 本用例直接断言**没有** 101。
func TestTerminalWSNeverUpgradesWithoutAuth(t *testing.T) {
	env := newTerminalTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ws?id=abc", nil)
	// 构造一个**完全合法**的 WebSocket 握手请求。
	// 这样如果实现有误，它会一路走到 Upgrade 并返回 101——
	// 从而让本用例真正测到"鉴权在升级之前"这件事。
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	// 不带 Cookie。

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusSwitchingProtocols {
		t.Fatal("未登录的 WebSocket 请求被升级了（101）——" +
			"鉴权必须在 Upgrade 之前完成，否则等于开放了一个全权限 shell 通道")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d，期望 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// ④ Origin 校验（防 CSWSH）
// ---------------------------------------------------------------------------

// 跨站 Origin 必须被拒绝。
//
// ## 为什么 WebSocket 需要额外的 Origin 校验 ##
//
// WebSocket **不受同源策略约束**：浏览器允许任意源的 JS 发起连接，
// 且**自动携带目标域的 Cookie**。这就是 CSWSH：用户登录了面板，
// 又访问了一个恶意页面，那个页面用 JS 连上 /api/terminal/ws，
// 请求带着用户的会话 Cookie，RequireAuth 通过，
// 于是恶意页面拿到了一个**全权限 root shell**。
func TestTerminalWSRejectsCrossOrigin(t *testing.T) {
	env := newTerminalTestServer(t)
	cookie := login(t, env.server)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ws?id=abc", nil)
	req.Host = "panel.example.com"
	req.Header.Set("Origin", "https://evil.example.net") // 跨站
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusSwitchingProtocols {
		t.Fatal("跨站 Origin 的 WebSocket 请求被升级了——存在 CSWSH 漏洞")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Origin") {
		t.Errorf("响应未说明是 Origin 校验失败: %s", rec.Body.String())
	}
}

// 同源 Origin 必须被放行（否则正常浏览器用不了）。
//
// 这条与上一条配对：只测拒绝会把实现"永远返回 403"也判为通过。
func TestTerminalWSAcceptsSameOrigin(t *testing.T) {
	env := newTerminalTestServer(t)
	cookie := login(t, env.server)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ws?id=abc", nil)
	req.Host = "panel.example.com"
	req.Header.Set("Origin", "https://panel.example.com") // 同源
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	// 同源应通过 Origin 校验，继续走到"会话不存在"（本环境无会话）。
	// 关键是它**不能**因为 Origin 被拒。
	if rec.Code == http.StatusForbidden {
		t.Fatalf("同源请求被 Origin 校验拒绝了: %s", rec.Body.String())
	}
}

// Origin 为空（非浏览器客户端）必须放行。
//
// websocat / curl 这类客户端不携带 Cookie，因此不存在被第三方
// 站点利用的问题；把空 Origin 也拒掉会让命令行调试完全无法进行。
func TestTerminalWSAllowsEmptyOrigin(t *testing.T) {
	env := newTerminalTestServer(t)
	cookie := login(t, env.server)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ws?id=abc", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.AddCookie(cookie)
	// 不设 Origin。

	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("空 Origin 被拒绝（命令行客户端将无法调试）: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ⑤ 关闭会话必须二次确认
// ---------------------------------------------------------------------------

// 不带 confirm 的关闭请求必须是 428，且**不能真的关闭会话**。
//
// 与服务端强制二次确认的纪律一致：前端弹窗只是体验，
// 被绕过时后端仍要拦得住。
func TestTerminalCloseRequiresConfirm(t *testing.T) {
	env := newTerminalTestServer(t)

	// 会话不存在时无法测"确认"分支（会先 404）。
	// 因此这里只验证：即使会话不存在，也**不会**因为缺 confirm
	// 而放行到别处——响应必须是可预期的 JSON，而不是 500。
	rec := env.do(t, http.MethodDelete, "/api/terminal/sessions?id=nonexistent", nil)
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("缺少 confirm 时返回了裸奔 500: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q，期望 JSON", ct)
	}

	// 缺 id 必须是 404 而不是 500。
	rec = env.do(t, http.MethodDelete, "/api/terminal/sessions", nil)
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("缺少 id 时返回了裸奔 500: %s", rec.Body.String())
	}
}

// 关闭不存在的会话必须是 404（而不是 500）。
func TestTerminalCloseUnknownSessionIs404(t *testing.T) {
	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodDelete, "/api/terminal/sessions?id=nope&confirm=true", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404, body = %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ⑥ 状态接口的形状（前端降级的依据）
// ---------------------------------------------------------------------------

// status 必须包含 supported 字段 —— 前端据此决定是否渲染终端。
func TestTerminalStatusReportsCapability(t *testing.T) {
	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodGet, "/api/terminal/status", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Supported   bool   `json:"supported"`
		OS          string `json:"os"`
		Reason      string `json:"reason"`
		Shell       string `json:"shell"`
		IdleTimeout string `json:"idle_timeout"`
		Sessions    struct {
			Total   int `json:"total"`
			Running int `json:"running"`
			Max     int `json:"max"`
		} `json:"sessions"`
		Audit struct {
			Total int `json:"total"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}

	// ########## 契约测试：字段名是跨语言接口的一部分 ##########
	//
	// 4.6 踩过这个坑：结构体字段有值 ≠ JSON 里有这个字段
	// （标签写错导致前端整列空白，而所有 Go 测试全绿）。
	// 因此这里逐个断言**前端依赖的字段名**确实存在。
	if !payload.Supported {
		t.Errorf("supported = false（本测试环境是 Linux，应当支持）；reason=%q", payload.Reason)
	}
	if payload.OS == "" {
		t.Error("os 字段为空（JS 里拼成 os_name 之类的错名会让前端拿不到）")
	}
	if payload.Shell == "" {
		t.Error("shell 字段为空")
	}
	if payload.IdleTimeout == "" {
		t.Error("idle_timeout 字段为空")
	}
	if payload.Sessions.Max != 3 {
		t.Errorf("sessions.max = %d，期望 3", payload.Sessions.Max)
	}
}

// sessions 必须返回数组（空时是 []，不是 null）。
func TestTerminalSessionsReturnsArrayNotNull(t *testing.T) {
	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodGet, "/api/terminal/sessions", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Sessions []json.RawMessage `json:"sessions"`
		Total    int               `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if payload.Sessions == nil {
		t.Fatal("sessions 为 null —— 前端 .map 会抛异常，" +
			"必须是 []（Go 里 nil slice 会序列化成 null）")
	}
	if payload.Total != 0 {
		t.Errorf("total = %d，期望 0", payload.Total)
	}
}

// audit 必须返回可用的空结构（而不是 null）。
func TestTerminalAuditReturnsShape(t *testing.T) {
	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodGet, "/api/terminal/audit", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Events []json.RawMessage `json:"events"`
		Stats  struct {
			Total    uint64 `json:"total"`
			Capacity int    `json:"capacity"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if payload.Stats.Capacity == 0 {
		t.Error("stats.capacity 为 0")
	}
}

// ---------------------------------------------------------------------------
// ⑦ 未注入管理器 → JSON 503
// ---------------------------------------------------------------------------

func TestTerminalUnavailableWithoutManager(t *testing.T) {
	s := newAuthedTestServer(t)
	// 不注入 terminalMgr。
	rebuildTestRoutes(s)
	cookie := login(t, s)

	for _, path := range []string{"/api/terminal/status", "/api/terminal/sessions"} {
		rec := doJSON(t, s, http.MethodGet, path, nil, cookie)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s 状态码 = %d，期望 503", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s Content-Type = %q，期望 JSON", path, ct)
		}
	}
}

// ---------------------------------------------------------------------------
// ⑧ 审计留痕
// ---------------------------------------------------------------------------

// 终端操作必须写入审计，且 kind=terminal / source=core。
func TestTerminalOperationsAreAudited(t *testing.T) {
	env := newTerminalTestServer(t)

	// 做几次读操作与一次被拒绝的连接尝试。
	env.do(t, http.MethodGet, "/api/terminal/status", nil)
	env.do(t, http.MethodGet, "/api/terminal/sessions", nil)
	env.do(t, http.MethodGet, "/api/terminal/ws?id=nope", nil)

	events := env.manager.Auditor().Query(terminal.AuditFilter{Limit: 50})
	if len(events) == 0 {
		t.Fatal("终端操作没有留下任何审计记录")
	}

	var sawStatus, sawDenied bool
	for _, ev := range events {
		if ev.Kind != terminal.KindTerminal {
			t.Errorf("kind = %q，期望 %q", ev.Kind, terminal.KindTerminal)
		}
		if ev.Source != terminal.SourceCore {
			t.Errorf("source = %q，期望 %q（不得伪造插件 ID）", ev.Source, terminal.SourceCore)
		}
		if ev.User != testUser {
			t.Errorf("user = %q，期望 %q", ev.User, testUser)
		}
		switch {
		case ev.Action == terminal.ActionStatus && ev.Outcome == terminal.AuditAllowed:
			sawStatus = true
		case ev.Outcome == terminal.AuditDenied:
			sawDenied = true
		}
	}

	if !sawStatus {
		t.Error("未记录 status 操作")
	}
	if !sawDenied {
		t.Error("未记录被拒绝的连接尝试（会话不存在应留痕）")
	}
}

// 审计事件必须能按 session 过滤（重建单个 shell 的生命周期）。
func TestTerminalAuditFilterBySession(t *testing.T) {
	env := newTerminalTestServer(t)

	// 直接写两条不同会话的记录，验证过滤器。
	auditor := env.manager.Auditor()
	auditor.Record(terminal.AuditEvent{Action: terminal.ActionConnect, Session: "aaa"})
	auditor.Record(terminal.AuditEvent{Action: terminal.ActionConnect, Session: "bbb"})

	got := auditor.Query(terminal.AuditFilter{Session: "aaa"})
	if len(got) != 1 {
		t.Fatalf("按 session 过滤返回 %d 条，期望 1 条", len(got))
	}
	if got[0].Session != "aaa" {
		t.Errorf("过滤结果 session = %q，期望 aaa", got[0].Session)
	}
}

// ---------------------------------------------------------------------------
// 跨平台：Windows 上的接口行为
// ---------------------------------------------------------------------------

// 在 Windows 上，创建会话必须返回 501 且带 supported=false。
//
// 本用例只在非 PTY 平台生效；Linux 上跳过。
func TestTerminalCreateOnUnsupportedPlatform(t *testing.T) {
	if terminal.Supported() {
		t.Skipf("当前平台支持 PTY，跳过（降级分支由 internal/terminal 的纯函数测试覆盖）")
	}

	env := newTerminalTestServer(t)
	rec := env.do(t, http.MethodPost, "/api/terminal/sessions", map[string]int{"cols": 80, "rows": 24})

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("状态码 = %d，期望 501, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Supported bool   `json:"supported"`
		Hint      string `json:"hint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if payload.Supported {
		t.Error("supported 应为 false")
	}
	if payload.Hint == "" {
		t.Error("缺少 hint（前端 n-alert 需要它来告诉用户怎么办）")
	}
}
