package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testSecret 是测试用的固定签名密钥，长度满足 New 的最小要求。
var testSecret = []byte("test-secret-at-least-16-bytes-long")

// newTestAuth 构造一个使用固定密钥的 Authenticator（避免测试间随机密钥导致不可复现）。
func newTestAuth(t *testing.T, ttl time.Duration) *Authenticator {
	t.Helper()

	hash, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	store, err := NewMemoryUserStore("admin", hash)
	if err != nil {
		t.Fatalf("NewMemoryUserStore 失败: %v", err)
	}
	a, err := New(Options{
		Store:  store,
		Secret: testSecret,
		TTL:    ttl,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return a
}

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	if !IsBcryptHash(hash) {
		t.Fatalf("生成的哈希不是 bcrypt 格式: %q", hash)
	}
	// 明文绝不能出现在哈希里。
	if hash == "s3cret-pw" {
		t.Fatal("哈希与明文相同，密码未被加密")
	}
	if err := VerifyPassword(hash, "s3cret-pw"); err != nil {
		t.Errorf("正确密码校验失败: %v", err)
	}
	if err := VerifyPassword(hash, "wrong-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("错误密码应返回 ErrInvalidCredentials，实际: %v", err)
	}
}

// 同一个密码两次哈希必须不同（bcrypt 自带随机 salt）。
func TestHashPasswordIsSalted(t *testing.T) {
	h1, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	h2, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	if h1 == h2 {
		t.Error("两次哈希结果相同，说明没有使用随机 salt")
	}
}

func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("空密码应当返回错误")
	}
}

func TestNewMemoryUserStoreRejectsBadHash(t *testing.T) {
	if _, err := NewMemoryUserStore("admin", "plain-text"); err == nil {
		t.Fatal("非 bcrypt 哈希应当被拒绝")
	}
	if _, err := NewMemoryUserStore("", mustHash(t)); err == nil {
		t.Fatal("空用户名应当被拒绝")
	}
}

func TestAuthenticate(t *testing.T) {
	a := newTestAuth(t, time.Hour)

	name, _, err := a.Login(httptest.NewRecorder(), "admin", "s3cret-pw")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if name != "admin" {
		t.Errorf("用户名 = %q, 期望 %q", name, "admin")
	}

	if _, _, err := a.Login(httptest.NewRecorder(), "admin", "bad-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("错误密码应返回 ErrInvalidCredentials，实际: %v", err)
	}
	// 用户不存在与密码错误必须返回同一个错误，避免枚举账号。
	if _, _, err := a.Login(httptest.NewRecorder(), "root", "s3cret-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("不存在的用户应返回 ErrInvalidCredentials，实际: %v", err)
	}
}

// 登录成功后必须写入 HttpOnly 会话 Cookie。
func TestLoginSetsHttpOnlyCookie(t *testing.T) {
	a := newTestAuth(t, time.Hour)
	rec := httptest.NewRecorder()

	if _, _, err := a.Login(rec, "admin", "s3cret-pw"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()

	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("响应未设置 %s Cookie", CookieName)
	}
	if !found.HttpOnly {
		t.Error("会话 Cookie 必须是 HttpOnly（防 XSS 窃取）")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, 期望 Lax", found.SameSite)
	}
	if found.Path != "/" {
		t.Errorf("Path = %q, 期望 /", found.Path)
	}
	if found.Value == "" {
		t.Error("Cookie 值为空，token 未写入")
	}
}

// 会话 Cookie 必须能被同一 Authenticator 解析回用户名（中间件与登录共用校验逻辑）。
func TestCookieRoundTrip(t *testing.T) {
	a := newTestAuth(t, time.Hour)
	rec := httptest.NewRecorder()
	if _, _, err := a.Login(rec, "admin", "s3cret-pw"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
	req.AddCookie(rec.Result().Cookies()[0])

	name, err := a.Username(req)
	if err != nil {
		t.Fatalf("解析 Cookie 失败: %v", err)
	}
	if name != "admin" {
		t.Errorf("用户名 = %q, 期望 %q", name, "admin")
	}
}

// 过期的 token 必须被拒绝。
func TestExpiredTokenRejected(t *testing.T) {
	a := newTestAuth(t, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: newExpiredToken(t, "admin")})

	if _, err := a.Username(req); err == nil {
		t.Fatal("过期 token 应当被拒绝")
	}
}

// 过期后 ExpiresAt 应返回零值，避免前端误判会话仍有效。
func TestExpiresAtZeroWhenInvalid(t *testing.T) {
	a := newTestAuth(t, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: newExpiredToken(t, "admin")})

	if got := a.ExpiresAt(req); !got.IsZero() {
		t.Errorf("过期 token 的 ExpiresAt = %v, 期望零值", got)
	}

	loginRec := httptest.NewRecorder()
	if _, expiresAt, err := a.Login(loginRec, "admin", "s3cret-pw"); err != nil {
		t.Fatalf("登录失败: %v", err)
	} else if expiresAt.IsZero() {
		t.Error("登录返回的过期时间为零值")
	}
}

// 使用其他密钥签发的 token 必须被拒绝（防伪造）。
func TestTokenSignedWithOtherSecretRejected(t *testing.T) {
	a := newTestAuth(t, time.Hour)
	other := newTestAuth(t, time.Hour)
	// 让 other 使用不同密钥。
	other.secret = []byte("another-secret-at-least-16-bytes")

	rec := httptest.NewRecorder()
	if _, _, err := other.Login(rec, "admin", "s3cret-pw"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
	req.AddCookie(rec.Result().Cookies()[0])

	if _, err := a.Username(req); err == nil {
		t.Fatal("其他密钥签发的 token 应当被拒绝")
	}
}

func TestRequireAuth(t *testing.T) {
	a := newTestAuth(t, time.Hour)

	protected := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := UsernameFrom(r.Context())
		if !ok {
			t.Error("受保护 handler 中应当能取到用户名")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(name))
	}))

	t.Run("未登录返回 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/system/info", nil))

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q, 期望 JSON", ct)
		}
	})

	t.Run("伪造 token 返回 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: "not-a-jwt"})
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("已登录放行并注入用户名", func(t *testing.T) {
		loginRec := httptest.NewRecorder()
		if _, _, err := a.Login(loginRec, "admin", "s3cret-pw"); err != nil {
			t.Fatalf("登录失败: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
		req.AddCookie(loginRec.Result().Cookies()[0])
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
		}
		if rec.Body.String() != "admin" {
			t.Errorf("handler 取到用户名 = %q, 期望 %q", rec.Body.String(), "admin")
		}
	})
}

// 登出必须让 Cookie 立即失效。
func TestLogoutClearsCookie(t *testing.T) {
	a := newTestAuth(t, time.Hour)
	rec := httptest.NewRecorder()
	a.Logout(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("登出未设置任何 Cookie")
	}
	c := cookies[0]
	if c.Value != "" {
		t.Errorf("登出后 Cookie 值应为空，实际 %q", c.Value)
	}
	if c.MaxAge >= 0 {
		t.Errorf("登出后 MaxAge 应为负数（立即过期），实际 %d", c.MaxAge)
	}
}

func TestGenerateSecret(t *testing.T) {
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret 失败: %v", err)
	}
	s2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret 失败: %v", err)
	}
	if s1 == s2 {
		t.Error("两次生成的密钥相同，随机性不足")
	}
	if len(s1) < 32 {
		t.Errorf("密钥长度 = %d, 期望 >= 32", len(s1))
	}
}

// 签名密钥过短必须启动失败，而不是静默降级。
func TestNewRejectsShortSecret(t *testing.T) {
	hash := mustHash(t)
	store, err := NewMemoryUserStore("admin", hash)
	if err != nil {
		t.Fatalf("NewMemoryUserStore 失败: %v", err)
	}
	if _, err := New(Options{Store: store, Secret: []byte("short")}); err == nil {
		t.Fatal("过短的密钥应当被拒绝")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("缺少 UserStore 应当被拒绝")
	}
}

// 未配置密钥时应自动生成，并标记为自动生成。
func TestNewGeneratesSecretWhenEmpty(t *testing.T) {
	store, err := NewMemoryUserStore("admin", mustHash(t))
	if err != nil {
		t.Fatalf("NewMemoryUserStore 失败: %v", err)
	}
	a, err := New(Options{Store: store})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if !a.SecretGenerated() {
		t.Error("未配置密钥时应标记为自动生成")
	}
	if a.TTL() != DefaultTokenTTL {
		t.Errorf("TTL = %v, 期望默认值 %v", a.TTL(), DefaultTokenTTL)
	}
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"/":                   "/",
		"/services":           "/services",
		"":                    "/",
		"//evil.com":          "/",
		"https://evil.com":    "/",
		"javascript:alert(1)": "/",
	}
	for in, want := range cases {
		if got := SanitizeNext(in); got != want {
			t.Errorf("SanitizeNext(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// mustHash 是测试辅助函数：哈希失败直接 panic（仅用于测试常量）。
func mustHash(t *testing.T) string {
	t.Helper()
	h, err := HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	return h
}

// newExpiredToken 用测试密钥签发一个已过期的 token，用于验证过期拒绝逻辑。
func newExpiredToken(t *testing.T, subject string) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(testSecret)
	if err != nil {
		t.Fatalf("签发过期 token 失败: %v", err)
	}
	return s
}
