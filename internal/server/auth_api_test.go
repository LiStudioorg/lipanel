package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lipanel/internal/auth"
)

// testCredentials 是测试用账号，与线上默认口令无关。
const (
	testUser = "admin"
	testPass = "test-password-123"
)

// newAuthedTestServer 构造一个带真实鉴权组件的测试 Server。
func newAuthedTestServer(t *testing.T) *Server {
	t.Helper()

	hash, err := auth.HashPassword(testPass)
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	store, err := auth.NewMemoryUserStore(testUser, hash)
	if err != nil {
		t.Fatalf("NewMemoryUserStore 失败: %v", err)
	}
	authenticator, err := auth.New(auth.Options{
		Store:  store,
		Secret: []byte("test-secret-at-least-16-bytes-long"),
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("auth.New 失败: %v", err)
	}

	s, err := New(Options{
		Addr:    "127.0.0.1:0",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "test",
		Auth:    authenticator,
		// 前端资源由 main 注入（根包已是 package main，无法被 import），
		// 测试里用内存 FS 顶替，见 server_test.go 的 testFS。
		WebFS:    testFS(),
		WebBuilt: true,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return s
}

// doJSON 发起一次 JSON 请求，body 为 nil 时不带请求体。
func doJSON(t *testing.T, s *Server, method, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求体失败: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// login 执行一次成功登录并返回会话 Cookie。
func login(t *testing.T, s *Server) *http.Cookie {
	t.Helper()

	rec := doJSON(t, s, http.MethodPost, "/api/login", loginRequest{Username: testUser, Password: testPass})
	if rec.Code != http.StatusOK {
		t.Fatalf("登录失败，状态码 = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	t.Fatal("登录响应未下发会话 Cookie")
	return nil
}

// ---------- 登录接口 ----------

func TestLoginSuccess(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodPost, "/api/login", loginRequest{Username: testUser, Password: testPass})

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Username != testUser {
		t.Errorf("username = %q, 期望 %q", resp.Username, testUser)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at 为空")
	}
	if resp.Redirect != "/" {
		t.Errorf("默认 redirect = %q, 期望 /", resp.Redirect)
	}

	// token 只能通过 HttpOnly Cookie 下发，绝不能出现在响应体里。
	if strings.Contains(rec.Body.String(), auth.CookieName) {
		t.Error("响应体中不应包含 Cookie 名")
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Error("响应未下发 Cookie")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodPost, "/api/login", loginRequest{Username: testUser, Password: "wrong-password"})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
	}
	// 失败时绝不能下发 Cookie。
	if len(rec.Result().Cookies()) != 0 {
		t.Error("登录失败不应下发 Cookie")
	}
}

// 用户不存在与密码错误必须返回完全一致的提示，防止账号枚举。
func TestLoginUnknownUserSameMessage(t *testing.T) {
	s := newAuthedTestServer(t)

	wrongPass := doJSON(t, s, http.MethodPost, "/api/login", loginRequest{Username: testUser, Password: "wrong-password"})
	noUser := doJSON(t, s, http.MethodPost, "/api/login", loginRequest{Username: "nobody", Password: testPass})

	if wrongPass.Code != noUser.Code {
		t.Errorf("状态码不一致: 密码错误=%d, 用户不存在=%d", wrongPass.Code, noUser.Code)
	}
	if wrongPass.Body.String() != noUser.Body.String() {
		t.Errorf("响应体不一致，可能泄露账号是否存在:\n密码错误: %s\n用户不存在: %s",
			wrongPass.Body.String(), noUser.Body.String())
	}
}

func TestLoginValidation(t *testing.T) {
	s := newAuthedTestServer(t)

	cases := []struct {
		name string
		body any
	}{
		{"缺少密码", map[string]string{"username": testUser}},
		{"缺少用户名", map[string]string{"password": testPass}},
		{"全空", loginRequest{}},
		{"用户名仅空格", loginRequest{Username: "   ", Password: testPass}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, s, http.MethodPost, "/api/login", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("状态码 = %d, 期望 %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

// 非 JSON 请求体必须被拒绝，且不能让服务 panic。
func TestLoginMalformedBody(t *testing.T) {
	s := newAuthedTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("状态码 = %d, 期望 %d", rec.Code, http.StatusBadRequest)
	}
}

// 超大请求体必须被限制，防止内存被打满。
func TestLoginOversizedBody(t *testing.T) {
	s := newAuthedTestServer(t)

	huge := `{"username":"admin","password":"` + strings.Repeat("x", maxLoginBodySize*2) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("超大请求体不应被接受")
	}
}

// redirect 参数必须被清洗，阻止开放重定向。
func TestLoginSanitizesRedirect(t *testing.T) {
	s := newAuthedTestServer(t)

	for _, evil := range []string{"//evil.com", "https://evil.com", "javascript:alert(1)"} {
		rec := doJSON(t, s, http.MethodPost, "/api/login?redirect="+evil,
			loginRequest{Username: testUser, Password: testPass})
		if rec.Code != http.StatusOK {
			t.Fatalf("登录失败: %d", rec.Code)
		}
		var resp loginResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		if resp.Redirect != "/" {
			t.Errorf("redirect=%q 未被清洗，返回 %q", evil, resp.Redirect)
		}
	}

	// 合法站内路径应被保留。
	rec := doJSON(t, s, http.MethodPost, "/api/login?redirect=/services",
		loginRequest{Username: testUser, Password: testPass})
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Redirect != "/services" {
		t.Errorf("redirect = %q, 期望 /services", resp.Redirect)
	}
}

// ---------- 受保护接口 ----------

// 未登录访问受保护接口必须返回 401 JSON。
func TestSystemInfoRequiresAuth(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodGet, "/api/system/info", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, 期望 JSON", ct)
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("401 响应不是合法 JSON: %v", err)
	}
	if payload["error"] == "" {
		t.Error("401 响应缺少 error 字段")
	}
}

func TestAuthMeRequiresAuth(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodGet, "/api/auth/me", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
	}
}

// 伪造的 Cookie 必须被拒绝。
func TestForgedCookieRejected(t *testing.T) {
	s := newAuthedTestServer(t)
	fake := &http.Cookie{Name: auth.CookieName, Value: "eyJhbGciOiJub25lIn0.e30."}

	for _, path := range []string{"/api/system/info", "/api/auth/me"} {
		rec := doJSON(t, s, http.MethodGet, path, nil, fake)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 状态码 = %d, 期望 %d", path, rec.Code, http.StatusUnauthorized)
		}
	}
}

// 登录后必须能拿到真实的系统信息。
func TestSystemInfoAfterLogin(t *testing.T) {
	s := newAuthedTestServer(t)
	cookie := login(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/system/info", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Hostname      string `json:"hostname"`
		OS            string `json:"os"`
		Kernel        string `json:"kernel"`
		Arch          string `json:"arch"`
		UptimeSeconds uint64 `json:"uptime_seconds"`
		CPU           struct {
			Model        string  `json:"model"`
			Cores        int     `json:"cores"`
			UsagePercent float64 `json:"usage_percent"`
		} `json:"cpu"`
		Memory struct {
			TotalBytes   uint64  `json:"total_bytes"`
			UsedBytes    uint64  `json:"used_bytes"`
			UsagePercent float64 `json:"usage_percent"`
		} `json:"memory"`
		Disk struct {
			Path         string  `json:"path"`
			TotalBytes   uint64  `json:"total_bytes"`
			UsagePercent float64 `json:"usage_percent"`
		} `json:"disk"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}

	// 这些字段来自 uname 与 /proc，任何 Linux 上都应非空/非零。
	if resp.Kernel == "" || resp.Arch == "" {
		t.Errorf("内核/架构为空: kernel=%q arch=%q", resp.Kernel, resp.Arch)
	}
	if resp.CPU.Cores <= 0 {
		t.Errorf("CPU 核心数 = %d, 期望 > 0", resp.CPU.Cores)
	}
	if resp.CPU.UsagePercent < 0 || resp.CPU.UsagePercent > 100 {
		t.Errorf("CPU 使用率 = %v, 应在 0~100 之间", resp.CPU.UsagePercent)
	}
	if resp.Memory.TotalBytes == 0 {
		t.Error("内存总量为 0")
	}
	if resp.Memory.UsedBytes > resp.Memory.TotalBytes {
		t.Error("已用内存超过总量")
	}
	if resp.Disk.TotalBytes == 0 {
		t.Error("磁盘总量为 0")
	}
	if resp.Disk.Path != "/" {
		t.Errorf("磁盘路径 = %q, 期望 /", resp.Disk.Path)
	}
}

func TestAuthMeAfterLogin(t *testing.T) {
	s := newAuthedTestServer(t)
	cookie := login(t, s)

	rec := doJSON(t, s, http.MethodGet, "/api/auth/me", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}

	var resp meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Username != testUser {
		t.Errorf("username = %q, 期望 %q", resp.Username, testUser)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at 为空")
	}
}

// ---------- 登出 ----------

// 登出必须让旧 Cookie 失效：模拟浏览器覆盖 Cookie 后再次访问应被拒绝。
func TestLogoutInvalidatesSession(t *testing.T) {
	s := newAuthedTestServer(t)
	cookie := login(t, s)

	rec := doJSON(t, s, http.MethodPost, "/api/logout", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("登出状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("登出未下发清除 Cookie 的指令")
	}
	if cleared.Value != "" {
		t.Errorf("登出后 Cookie 值应为空，实际 %q", cleared.Value)
	}

	// 浏览器收到清除指令后，后续请求不再携带该 Cookie。
	after := doJSON(t, s, http.MethodGet, "/api/system/info", nil)
	if after.Code != http.StatusUnauthorized {
		t.Errorf("登出后访问受保护接口状态码 = %d, 期望 %d", after.Code, http.StatusUnauthorized)
	}
}

// 未登录时调用登出也应成功返回，便于前端无条件清理本地状态。
func TestLogoutWithoutSession(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodPost, "/api/logout", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}
}

// ---------- 公开接口与鉴权边界 ----------

// health 必须保持公开：探活接口不该被登录挡住。
func TestHealthStaysPublic(t *testing.T) {
	s := newAuthedTestServer(t)
	rec := doJSON(t, s, http.MethodGet, "/api/health", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}

	var resp healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, 期望 ok", resp.Status)
	}
	if resp.TokenTTLSeconds != 3600 {
		t.Errorf("token_ttl_seconds = %d, 期望 3600", resp.TokenTTLSeconds)
	}
	if !resp.HasFixedSecret {
		t.Error("测试使用固定密钥，has_fixed_secret 应为 true")
	}
}

// 所有未注册的 /api 路径都应是 JSON 404，包括受保护前缀下的路径。
func TestUnknownAPIPathsReturnJSON404(t *testing.T) {
	s := newAuthedTestServer(t)

	for _, path := range []string{"/api/not-exist", "/api/system/unknown", "/api/auth/nope"} {
		rec := doJSON(t, s, http.MethodGet, path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s 状态码 = %d, 期望 %d", path, rec.Code, http.StatusNotFound)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s Content-Type = %q, 期望 JSON", path, ct)
		}
	}
}

// 方法不匹配时不应误击中业务 handler，也不应被当作前端路由返回 HTML 页面。
//
// 说明：Go 1.22+ 的 ServeMux 在「路径存在但方法不匹配」且没有裸路径模式时
// 返回 404（而非 405），因此这里不锁死具体状态码，只断言「非 200 且是 JSON 错误」。
func TestWrongMethodRejected(t *testing.T) {
	s := newAuthedTestServer(t)

	// 登录接口只接受 POST。
	rec := doJSON(t, s, http.MethodGet, "/api/login", nil)
	if rec.Code == http.StatusOK {
		t.Error("GET /api/login 不应返回 200")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("GET /api/login Content-Type = %q, 期望 JSON（不应返回前端 HTML）", ct)
	}

	// 受保护接口用 POST 访问同样应被拒绝（且不应因绕过鉴权而放行）。
	rec = doJSON(t, s, http.MethodPost, "/api/system/info", nil)
	if rec.Code == http.StatusOK {
		t.Error("POST /api/system/info 不应返回 200")
	}
}

// 未配置 Auth 时，Server 应回退到开发默认账号并可正常登录（保证 go run 开箱可用）。
func TestDefaultAuthFallback(t *testing.T) {
	s := newTestServer(t)

	if rec := doJSON(t, s, http.MethodPost, "/api/login",
		loginRequest{Username: "admin", Password: "admin123"}); rec.Code != http.StatusOK {
		t.Fatalf("默认账号登录失败: %d, body = %s", rec.Code, rec.Body.String())
	}

	// 默认账号也不应放行错误密码。
	if rec := doJSON(t, s, http.MethodPost, "/api/login",
		loginRequest{Username: "admin", Password: "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("错误密码状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
	}
}
