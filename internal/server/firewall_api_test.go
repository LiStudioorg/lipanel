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

	"lipanel/internal/firewall"
)

// ============================================================================
// 防火墙接口层测试（阶段四 4.6）
// ============================================================================
//
// 这一层要验证的不是"规则组装对不对"（那是 internal/firewall 的事），
// 而是五件接口契约：
//
//	① 路由注册顺序：固定段不能被通配吃掉；
//	② 全部接口都要登录；
//	③ **删除必须带 confirm，否则 428**（服务端强制二次确认）；
//	④ **受保护端口返回 409**，且被拒绝时零副作用；
//	⑤ 未注册路径返回 JSON 404（而不是 SPA 的 200 + HTML）。
//
// ③ 与 ④ 是本模块特有的、也是计划明确要求的。

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type firewallTestEnv struct {
	server  *Server
	manager *firewall.Manager
	mock    *firewall.MockExecutor
	dir     string
}

// ufwActive 是假执行器返回的"ufw 已启用"响应。
const ufwActiveStatus = "Status: active\n" +
	"Logging: on (low)\n" +
	"Default: deny (incoming), allow (outgoing), disabled (routed)\n"

// newFirewallTestServer 构造一个注入了防火墙管理器的测试 Server。
//
// ########## 全程使用假执行器 ##########
//
// 本模块的写操作会真实修改系统防火墙，而一条错误的规则
// 可以让开发机**失去 SSH 与面板的访问**（只能去控制台救）。
// 因此接口层测试一律注入 firewall.MockExecutor，
// 绝不执行任何真实的 ufw / firewall-cmd / nft / iptables 命令。
func newFirewallTestServer(t *testing.T, mut func(*firewall.Options)) *firewallTestEnv {
	t.Helper()
	dir := t.TempDir()
	mock := firewall.NewMockExecutor()

	// 默认：ufw 可用且已启用。
	mock.When("ufw", []string{"status", "verbose"}, firewall.MockResponse{Stdout: ufwActiveStatus})
	mock.When("ufw", []string{"status", "numbered"}, firewall.MockResponse{Stdout: ufwActiveStatus})
	mock.WhenPrefix("ufw", []string{"allow"}, firewall.MockResponse{})
	mock.WhenPrefix("ufw", []string{"deny"}, firewall.MockResponse{})
	mock.WhenPrefix("ufw", []string{"delete"}, firewall.MockResponse{})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 用真实的 sshd 配置路径探测（工作区临时文件），
	// 而不是靠"猜 22 是 SSH"——本模块的核心纪律就是不猜。
	sshCfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(sshCfg, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatalf("写测试 sshd 配置失败: %v", err)
	}

	auditor, err := firewall.NewAuditor(firewall.AuditOptions{
		Capacity: 200,
		Path:     filepath.Join(dir, "audit.jsonl"),
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("构造防火墙审计器失败: %v", err)
	}

	opts := firewall.Options{
		Logger:   logger,
		Executor: mock,
		Auditor:  auditor,
		Detector: firewall.NewDetector(firewall.DetectOptions{Executor: mock, ForceBackend: firewall.BackendUFW}),
		Protector: firewall.NewProtector(firewall.ProtectOptions{
			PanelPort:      8080,
			SSHConfigPaths: []string{sshCfg},
		}),
	}
	if mut != nil {
		mut(&opts)
	}
	mgr, err := firewall.NewManager(opts)
	if err != nil {
		t.Fatalf("构造防火墙管理器失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.firewallMgr = mgr
	rebuildTestRoutes(s)

	return &firewallTestEnv{server: s, manager: mgr, mock: mock, dir: dir}
}

// do 发起一次已登录的 JSON 请求。
func (e *firewallTestEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body, login(t, e.server))
}

// doAnon 发起一次未登录请求。
func (e *firewallTestEnv) doAnon(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, nil)
}

// ---------------------------------------------------------------------------
// ① 路由注册顺序
// ---------------------------------------------------------------------------

// TestFirewallFixedSegmentsNotShadowedByWildcard 锁死固定段路由的注册顺序。
//
// ########## 这是 4.1~4.5 连续踩过五次的同一个坑 ##########
//
// 若 "/api/firewall/audit" 晚于某个 "/api/firewall/{name}" 注册，
// "audit" 会被当成 name，于是"查审计"变成"操作名为 audit 的东西"。
//
// 本模块当前没有 {name} 通配，但仍然写这个测试：
// ① 它锁住"固定段注册在前面"这个纪律，将来加通配时不会踩坑；
// ② 它同时验证这些路径返回的是**各自的结构**（而不是被兜底吃掉）。
func TestFirewallFixedSegmentsNotShadowedByWildcard(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	cases := []struct {
		path string
		// wantKey 是响应里必须存在的字段（用于确认返回的是正确的结构）。
		wantKey string
	}{
		{"/api/firewall/rules", "rules"},
		{"/api/firewall/audit", "events"},
		{"/api/firewall/capabilities", "backends"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := env.do(t, http.MethodGet, c.path, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s 状态码 = %d，期望 200，body=%s", c.path, rec.Code, rec.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("%s 响应不是合法 JSON: %v", c.path, err)
			}
			if _, ok := got[c.wantKey]; !ok {
				t.Fatalf("%s 的响应缺少字段 %q（说明被别的路由吃掉了）: %s",
					c.path, c.wantKey, rec.Body.String())
			}
		})
	}
}

// TestFirewallUnknownSubpathReturnsJSON404 锁死未注册子路径返回 JSON 404。
//
// ########## 为什么必须是 JSON 404 ##########
//
// 若不注册前缀兜底，请求会落到前端 SPA 兜底路由，
// 返回 **200 + text/html**。于是 curl 看起来"成功"了，
// 客户端拿到的却是一整页 HTML，JSON 解析失败后报出
// 完全无关的错误（"unexpected token <"）。
// 这个坑在 4.1~4.5 都记录过。
func TestFirewallUnknownSubpathReturnsJSON404(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodGet, "/api/firewall/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q，期望 JSON（不能落到 HTML 兜底）", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v, body=%s", err, rec.Body.String())
	}
	// 响应里要列出可用接口，方便排错。
	if _, ok := got["available"]; !ok {
		t.Fatalf("404 响应应列出可用接口: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ② 鉴权
// ---------------------------------------------------------------------------

// TestFirewallRequiresAuth 锁死全部接口都要登录。
func TestFirewallRequiresAuth(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	reqs := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/firewall"},
		{http.MethodGet, "/api/firewall/rules"},
		{http.MethodGet, "/api/firewall/audit"},
		{http.MethodGet, "/api/firewall/capabilities"},
		{http.MethodPost, "/api/firewall/ports"},
		{http.MethodDelete, "/api/firewall/ports"},
		{http.MethodPost, "/api/firewall/ips"},
		{http.MethodDelete, "/api/firewall/ips"},
		{http.MethodGet, "/api/firewall/whatever"},
	}
	for _, r := range reqs {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rec := env.doAnon(t, r.method, r.path)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("未登录访问 %s %s 状态码 = %d，期望 401",
					r.method, r.path, rec.Code)
			}
		})
	}
}

// TestFirewallUnavailableWithoutManager 校验未注入管理器时返回 JSON 503。
func TestFirewallUnavailableWithoutManager(t *testing.T) {
	s := newAuthedTestServer(t)
	rebuildTestRoutes(s)

	rec := doJSON(t, s, http.MethodGet, "/api/firewall", nil, login(t, s))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("未注入管理器时状态码 = %d，期望 503", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q，期望 JSON", ct)
	}
}

// ---------------------------------------------------------------------------
// ③ 状态与规则查询
// ---------------------------------------------------------------------------

func TestFirewallStatusEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodGet, "/api/firewall", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}

	var got firewallStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !got.Available {
		t.Fatalf("ufw 可用时 Available 应为 true: %s", rec.Body.String())
	}
	if got.Detection.Backend != firewall.BackendUFW {
		t.Fatalf("后端应为 ufw，实际 %q", got.Detection.Backend)
	}
	// 默认策略要能解析出来（"deny (incoming)"）。
	if got.Detail.DefaultIncoming != "deny" {
		t.Fatalf("DefaultIncoming 应为 deny，实际 %q", got.Detail.DefaultIncoming)
	}
	if got.Detail.AllowAllIncoming {
		t.Fatal("deny (incoming) 不应判定为全放行")
	}
	// ########## 保护端口必须包含面板端口与 SSH 端口 ##########
	ports := map[int]string{}
	for _, p := range got.Protection.Ports {
		ports[p.Port] = p.Kind
	}
	if ports[8080] != firewall.ProtectPanel {
		t.Fatalf("面板端口 8080 应受保护，实际保护列表: %#v", got.Protection.Ports)
	}
	if ports[22] != firewall.ProtectSSH {
		t.Fatalf("SSH 端口 22 应受保护，实际保护列表: %#v", got.Protection.Ports)
	}
	if !got.Protection.SSHDetected {
		t.Fatal("应从 sshd 配置探测到 SSH 端口")
	}
	// 权限列表要返回。
	if len(got.Permissions) == 0 {
		t.Fatal("应返回当前用户的权限列表")
	}
}

func TestFirewallRulesEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)
	env.mock.When("ufw", []string{"status", "numbered"}, firewall.MockResponse{Stdout: `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
[ 1] 22/tcp                 ALLOW IN    Anywhere
[ 2] 8081/tcp               ALLOW IN    Anywhere
[ 3] 3306/tcp               DENY IN     192.168.1.0/24
[ 4] Anywhere               DENY IN     203.0.113.5
`})

	rec := env.do(t, http.MethodGet, "/api/firewall/rules", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}

	var got firewall.RulesResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if len(got.Ports) != 3 {
		t.Fatalf("应有 3 条端口规则，实际 %d: %#v", len(got.Ports), got.Ports)
	}
	if len(got.IPRules) != 1 {
		t.Fatalf("应有 1 条 IP 规则，实际 %d: %#v", len(got.IPRules), got.IPRules)
	}
	// 22 是 SSH 端口，必须被标记为受保护。
	if !got.Ports[0].Protected {
		t.Fatal("22/tcp 应被标记为受保护（SSH 端口）")
	}
	if got.Ports[0].ProtectedReason == "" {
		t.Fatal("受保护的规则必须给出原因")
	}
	// 8081 不受保护。
	if got.Ports[1].Protected {
		t.Fatal("8081 不应被标记为受保护")
	}
	if got.Counts.Protected != 1 {
		t.Fatalf("受保护计数应为 1，实际 %d", got.Counts.Protected)
	}
}

// ---------------------------------------------------------------------------
// ④ 添加端口
// ---------------------------------------------------------------------------

func TestFirewallAddPortEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodPost, "/api/firewall/ports", firewall.PortRequest{
		Port: "9090", Protocol: "tcp", Action: "allow", Comment: "测试",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}

	var got firewallOpResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !got.OK {
		t.Fatal("ok 应为 true")
	}
	// 命令要返回给用户（可复现、可审计）。
	if len(got.Commands) == 0 {
		t.Fatal("应返回执行的命令")
	}
	// 断言真实执行的 argv。
	want := []string{"allow", "proto", "tcp", "to", "any", "port", "9090", "comment", "[lipanel] 测试"}
	if !env.mock.ExactCallArgs("ufw", want) {
		t.Fatalf("未找到期望的命令调用:\n  期望 ufw %#v\n  实际: %#v", want, env.mock.Calls())
	}
}

// TestFirewallAddPortInvalidInput 锁死非法输入返回 400 且零副作用。
func TestFirewallAddPortInvalidInput(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	bad := []map[string]any{
		{"port": "0", "protocol": "tcp"},
		{"port": "65536", "protocol": "tcp"},
		{"port": "8080;reboot", "protocol": "tcp"},
		{"port": "8090-8080", "protocol": "tcp"},
		{"port": "8080", "protocol": "icmp"},
		{"port": "8080", "source": "1.2.3.4:22"},
		{"port": "8080", "comment": "a\nb"},
	}
	for _, body := range bad {
		env.mock.Reset()
		rec := env.do(t, http.MethodPost, "/api/firewall/ports", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("非法请求 %#v 状态码 = %d，期望 400，body=%s",
				body, rec.Code, rec.Body.String())
		}
		// ########## 关键：非法输入绝不能执行任何命令 ##########
		if calls := env.mock.Calls(); len(calls) != 0 {
			t.Fatalf("非法输入 %#v 绝不能执行命令，实际 %d 条: %#v", body, len(calls), calls)
		}
	}
}

// TestFirewallAddPortRejectsUnknownFields 锁死未知字段被拒绝。
//
// 拼错的字段名若被静默忽略，用户会以为参数生效了。
// 例如把 protocol 写成 protocal，就会静默用默认的 tcp ——
// 用户以为放行了 UDP，实际只开了 TCP。
func TestFirewallAddPortRejectsUnknownFields(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodPost, "/api/firewall/ports", map[string]any{
		"port": "8080", "protocal": "udp", // 故意拼错
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知字段应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if calls := env.mock.Calls(); len(calls) != 0 {
		t.Fatalf("解析失败时绝不能执行命令，实际 %d 条", len(calls))
	}
}

// ---------------------------------------------------------------------------
// ⑤ 删除端口：二次确认（本模块最重要的接口契约）
// ---------------------------------------------------------------------------

// TestFirewallDeletePortRequiresConfirm 锁死"服务端强制二次确认"。
//
// ########## 这是计划里的明确要求 ##########
//
// "删除规则前必须二次确认，避免把 SSH 端口误关导致失联"。
// 前端弹窗只是体验；真正的边界在这里——
// 不带 confirm 的请求一律 **428 Precondition Required**，
// 无论请求来自什么客户端（包括被绕过前端直接调接口的情况）。
func TestFirewallDeletePortRequiresConfirm(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	// 不带 confirm 的 DELETE。
	rec := env.do(t, http.MethodDelete, "/api/firewall/ports",
		map[string]any{"port": "9090", "protocol": "tcp"})

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("不带 confirm 的删除应返回 428，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	// 响应头要让客户端知道"补上确认再重试"。
	if rec.Header().Get("X-Lipanel-Confirm-Required") != "true" {
		t.Fatal("428 响应应带 X-Lipanel-Confirm-Required 头")
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got["hint"] == nil {
		t.Fatal("428 响应应给出 hint（说明为什么要确认）")
	}

	// ########## 关键：绝不能执行任何命令 ##########
	if calls := env.mock.Calls(); len(calls) != 0 {
		t.Fatalf("未确认的删除绝不能执行命令，实际 %d 条: %#v", len(calls), calls)
	}
}

// TestFirewallDeletePortConfirmViaQuery 校验查询串形式也能确认（便于 curl）。
func TestFirewallDeletePortConfirmViaQuery(t *testing.T) {
	env := newFirewallTestServer(t, nil)
	env.mock.When("ufw", []string{"status", "numbered"}, firewall.MockResponse{Stdout: `Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 9090/tcp               ALLOW IN    Anywhere
`})

	rec := env.do(t, http.MethodDelete,
		"/api/firewall/ports?port=9090&protocol=tcp&confirm=true", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("带 confirm=true 的删除应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	// 断言真的执行了删除命令。
	if !env.mock.ExactCallArgs("ufw", []string{"delete", "allow", "proto", "tcp", "to", "any", "port", "9090"}) {
		t.Fatalf("未执行期望的删除命令，实际: %#v", env.mock.Calls())
	}
}

// ---------------------------------------------------------------------------
// ⑥ 受保护端口：409
// ---------------------------------------------------------------------------

// TestFirewallDeleteProtectedPortReturns409 锁死"受保护端口返回 409"。
//
// SSH 端口是 22（来自真实的 sshd 配置探测），删除它必须被拒绝。
func TestFirewallDeleteProtectedPortReturns409(t *testing.T) {
	env := newFirewallTestServer(t, nil)
	env.mock.When("ufw", []string{"status", "numbered"}, firewall.MockResponse{Stdout: `Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 22/tcp                 ALLOW IN    Anywhere
`})

	rec := env.do(t, http.MethodDelete, "/api/firewall/ports",
		map[string]any{"port": "22", "protocol": "tcp", "confirm": true})

	if rec.Code != http.StatusConflict {
		t.Fatalf("删除受保护的 SSH 端口应返回 409，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	// 错误信息要说明是哪个端口、为什么受保护。
	errMsg, _ := got["error"].(string)
	if !strings.Contains(errMsg, "22") {
		t.Fatalf("错误信息应指明端口号，实际: %s", errMsg)
	}
	if !strings.Contains(errMsg, "SSH") {
		t.Fatalf("错误信息应说明是 SSH 端口，实际: %s", errMsg)
	}
	// hint 要告诉用户"如果确实要删，可以用 force"。
	hint, _ := got["hint"].(string)
	if !strings.Contains(hint, "force") {
		t.Fatalf("hint 应说明可用 force 强制删除，实际: %s", hint)
	}

	// ########## 关键：绝不能执行删除命令 ##########
	for _, c := range env.mock.Calls() {
		if c.Name == "ufw" && len(c.Args) > 0 && c.Args[0] == "delete" {
			t.Fatalf("受保护的端口绝不能触发删除命令: %#v", c)
		}
	}
}

// TestFirewallDeleteProtectedPortForce 校验 force 可强删且留痕。
func TestFirewallDeleteProtectedPortForce(t *testing.T) {
	env := newFirewallTestServer(t, nil)
	env.mock.When("ufw", []string{"status", "numbered"}, firewall.MockResponse{Stdout: `Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 22/tcp                 ALLOW IN    Anywhere
`})

	rec := env.do(t, http.MethodDelete, "/api/firewall/ports",
		map[string]any{"port": "22", "protocol": "tcp", "confirm": true, "force": true})

	if rec.Code != http.StatusOK {
		t.Fatalf("带 force 时应允许删除，实际 %d，body=%s", rec.Code, rec.Body.String())
	}

	// ########## 强删必须在审计里留痕 ##########
	stats := env.manager.Auditor().Stats()
	if stats.Forced == 0 {
		t.Fatal("强删受保护端口必须记入审计（Forced 计数）")
	}
	// 事件里要标出 Protected + Force。
	events := env.manager.Auditor().Query(firewall.AuditFilter{
		Action: firewall.ActionDeletePort, Limit: 10,
	})
	found := false
	for _, ev := range events {
		if ev.Force && ev.Protected {
			found = true
			if !strings.Contains(ev.Reason+ev.Target, "22") {
				t.Fatalf("强删事件应记录端口号: %#v", ev)
			}
		}
	}
	if !found {
		t.Fatalf("审计里应有一条 Protected+Force 的记录: %#v", events)
	}
}

// ---------------------------------------------------------------------------
// ⑦ IP 黑白名单
// ---------------------------------------------------------------------------

func TestFirewallAddIPEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodPost, "/api/firewall/ips", firewall.IPRequest{
		IP: "203.0.113.5", Direction: "deny", Comment: "恶意扫描",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}
	// 断言命令形态。
	if !env.mock.ExactCallArgs("ufw", []string{"deny", "from", "203.0.113.5", "comment", "[lipanel] 恶意扫描"}) {
		t.Fatalf("未执行期望的命令，实际: %#v", env.mock.Calls())
	}
}

func TestFirewallAddIPInvalidInput(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	bad := []map[string]any{
		{"ip": "1.2.3.4:22"},
		{"ip": "192.168.1.5/24"}, // 主机位非零
		{"ip": "not-an-ip"},
		{"ip": "010.1.1.1"},
		{"ip": "1.2.3.4", "direction": "blacklist"},
	}
	for _, body := range bad {
		env.mock.Reset()
		rec := env.do(t, http.MethodPost, "/api/firewall/ips", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("非法请求 %#v 状态码 = %d，期望 400，body=%s",
				body, rec.Code, rec.Body.String())
		}
		if calls := env.mock.Calls(); len(calls) != 0 {
			t.Fatalf("非法输入 %#v 绝不能执行命令，实际 %d 条", body, len(calls))
		}
	}
}

func TestFirewallDeleteIPRequiresConfirm(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodDelete, "/api/firewall/ips",
		map[string]any{"ip": "203.0.113.5", "direction": "deny"})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("不带 confirm 的 IP 删除应返回 428，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if calls := env.mock.Calls(); len(calls) != 0 {
		t.Fatalf("未确认的删除绝不能执行命令，实际 %d 条", len(calls))
	}
}

// ---------------------------------------------------------------------------
// ⑧ 审计接口
// ---------------------------------------------------------------------------

func TestFirewallAuditEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	// 先做一次添加，产生审计。
	rec := env.do(t, http.MethodPost, "/api/firewall/ports", firewall.PortRequest{
		Port: "9090", Protocol: "tcp", Action: "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("添加失败: %s", rec.Body.String())
	}

	rec = env.do(t, http.MethodGet, "/api/firewall/audit?limit=50", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}
	var got firewallAuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if len(got.Events) == 0 {
		t.Fatal("应至少有一条审计记录")
	}
	// 找出添加端口那条，验证关键字段被填全。
	found := false
	for _, ev := range got.Events {
		if ev.Action == firewall.ActionAddPort {
			found = true
			if ev.Backend != firewall.BackendUFW {
				t.Fatalf("审计应记录后端，实际 %q", ev.Backend)
			}
			if ev.Port != "9090" {
				t.Fatalf("审计应记录端口，实际 %q", ev.Port)
			}
			if ev.Command == "" {
				t.Fatal("写操作审计必须记录实际执行的命令")
			}
			if ev.RuleSpec == "" {
				t.Fatal("写操作审计必须记录规则规格（防火墙没有回收站，恢复只能靠它）")
			}
			if !ev.SystemChange {
				t.Fatal("成功的写操作应标记为改变了系统")
			}
			if ev.ClientIP == "" {
				t.Fatal("审计应记录客户端 IP")
			}
		}
	}
	if !found {
		t.Fatalf("未找到添加端口的审计记录: %#v", got.Events)
	}
}

func TestFirewallAuditFilter(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	// 一次成功 + 一次被拒绝。
	env.do(t, http.MethodPost, "/api/firewall/ports", firewall.PortRequest{
		Port: "9090", Protocol: "tcp", Action: "allow",
	})
	env.do(t, http.MethodDelete, "/api/firewall/ports", map[string]any{"port": "9090"}) // 无 confirm -> 428

	rec := env.do(t, http.MethodGet, "/api/firewall/audit?outcome=denied&limit=50", nil)
	var got firewallAuditResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Events) == 0 {
		t.Fatal("按 outcome=denied 过滤应至少有一条")
	}
	for _, ev := range got.Events {
		if ev.Outcome != firewall.AuditDenied {
			t.Fatalf("过滤结果含非 denied 记录: %#v", ev)
		}
	}
	// filter 要回显。
	if got.Filter["outcome"] != "denied" {
		t.Fatalf("filter 应回显查询条件，实际: %#v", got.Filter)
	}
}

func TestFirewallAuditInvalidLimit(t *testing.T) {
	env := newFirewallTestServer(t, nil)
	rec := env.do(t, http.MethodGet, "/api/firewall/audit?limit=abc", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 limit 应返回 400，实际 %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// ⑨ 能力探测
// ---------------------------------------------------------------------------

func TestFirewallCapabilitiesEndpoint(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	rec := env.do(t, http.MethodGet, "/api/firewall/capabilities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，body=%s", rec.Code, rec.Body.String())
	}
	var got firewallCapabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if len(got.Backends) != 4 {
		t.Fatalf("应返回 4 个后端的能力说明，实际 %d", len(got.Backends))
	}
	// 当前后端（ufw）的删除语义要能查到。
	if got.DeletionSemantics == "" {
		t.Fatal("应给出当前后端的删除语义")
	}
	// ########## 接口要自描述"删除需要确认" ##########
	// 让第三方脚本不必"试一次拿到 428"才知道。
	if !got.ConfirmRequired {
		t.Fatal("capabilities 必须声明 confirm_required=true")
	}
	if !got.ForceSupported {
		t.Fatal("capabilities 必须声明 force_supported=true")
	}
}

// ---------------------------------------------------------------------------
// ⑩ 降级与试运行
// ---------------------------------------------------------------------------

// TestFirewallDegradesWithoutBackend 锁死"无防火墙时优雅降级"。
//
// 接口返回 200 + available=false + 安装指引，
// 让前端渲染说明页而不是红色错误框（与 4.1 无 systemd、
// 4.4 无 certbot 完全一致的降级策略）。
func TestFirewallDegradesWithoutBackend(t *testing.T) {
	env := newFirewallTestServer(t, func(o *firewall.Options) {
		// 四个后端都不存在。
		for _, name := range []string{"ufw", "firewall-cmd", "nft", "iptables"} {
			o.Executor.(*firewall.MockExecutor).Missing(name)
		}
		o.Detector = firewall.NewDetector(firewall.DetectOptions{
			Executor: o.Executor,
		})
	})

	rec := env.do(t, http.MethodGet, "/api/firewall", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("无防火墙时状态码 = %d，期望 200（降级而非报错），body=%s",
			rec.Code, rec.Body.String())
	}
	var got firewallStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if got.Available {
		t.Fatal("无防火墙时 available 应为 false")
	}
	if got.UnavailableReason == "" {
		t.Fatal("应给出不可用原因")
	}
	if !strings.Contains(got.InstallHint, "apt-get install ufw") {
		t.Fatalf("应给出安装指引，实际: %s", got.InstallHint)
	}
}

// TestFirewallDryRunNeverExecutesWrites 锁死"试运行时零真实写命令"。
func TestFirewallDryRunNeverExecutesWrites(t *testing.T) {
	env := newFirewallTestServer(t, func(o *firewall.Options) {
		o.DryRun = true
	})

	rec := env.do(t, http.MethodPost, "/api/firewall/ports", firewall.PortRequest{
		Port: "9090", Protocol: "tcp", Action: "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("试运行不应失败: %d, body=%s", rec.Code, rec.Body.String())
	}
	var got firewallOpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if !got.Simulated {
		t.Fatal("试运行结果的 simulated 应为 true")
	}

	// ########## 关键：写命令绝不能真的执行 ##########
	for _, c := range env.mock.Calls() {
		if c.Name != "ufw" || len(c.Args) == 0 {
			continue
		}
		switch c.Args[0] {
		case "allow", "deny", "delete":
			t.Fatalf("试运行绝不能执行写命令，实际执行了: %#v", c)
		}
	}
}

// TestFirewallAddPortReturns400OnBadJSON 校验畸形 JSON 的处理。
func TestFirewallAddPortReturns400OnBadJSON(t *testing.T) {
	env := newFirewallTestServer(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/firewall/ports",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(login(t, env.server))
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("畸形 JSON 应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if calls := env.mock.Calls(); len(calls) != 0 {
		t.Fatalf("解析失败时绝不能执行命令，实际 %d 条", len(calls))
	}
}
