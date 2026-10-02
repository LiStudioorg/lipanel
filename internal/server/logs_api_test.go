package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/logs"
)

// ============================================================================
// 日志查看接口测试（阶段五 5.4.1）
// ============================================================================

// buildTestAuthenticator 构造一个含测试账号的鉴权组件（可在登录测试里复用的标准配方）。
func buildTestAuthenticator(t *testing.T) *auth.Authenticator {
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
	return authenticator
}

// newLogsServer 构造一个注入了日志管理器的 Server，并配好测试账号（可登录）。
// Logs 为 nil 时等价于「日志模块未开启」。所有日志文件都用临时目录，绝不碰宿主真实日志。
func newLogsServer(t *testing.T, nginxLogsDir string) *Server {
	t.Helper()
	mgr, err := logs.New(logs.ManagerOptions{NginxLogsDir: nginxLogsDir})
	if err != nil {
		t.Fatalf("构造日志管理器失败: %v", err)
	}

	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     buildTestAuthenticator(t),
		WebFS:    testFS(),
		WebBuilt: true,
		Logs:     mgr,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return s
}

// newAuthedServerNoLogs 构造一个已登录可用的、但**未注入日志管理器**的 Server，
// 用于验证「模块未开 → 503」降级路径。
func newAuthedServerNoLogs(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     buildTestAuthenticator(t),
		WebFS:    testFS(),
		WebBuilt: true,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return s
}

func writeTestLog(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("写测试日志失败: %v", err)
	}
}

func TestLogsEndpointsRequireAuth(t *testing.T) {
	s := newLogsServer(t, t.TempDir())
	for _, path := range []string{"/api/logs", "/api/logs/sources", "/api/logs/query?source=system", "/api/logs/audit"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 未登录状态码 = %d，期望 401", path, rec.Code)
		}
	}
}

func TestLogsUnavailableWhenNoManager(t *testing.T) {
	// 未注入管理器 → 503，绝不 panic。
	s := newAuthedServerNoLogs(t)
	rec := loginAndDo(t, s, "GET", "/api/logs")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("未注入日志管理器状态码 = %d，期望 503", rec.Code)
	}
}

func TestLogSourcesEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "access.log", "GET / 200\n")
	writeTestLog(t, dir, "error.log", "[error] boom\n")
	s := newLogsServer(t, dir)

	rec := loginAndDo(t, s, "GET", "/api/logs/sources")
	if rec.Code != http.StatusOK {
		t.Fatalf("sources 状态码 = %d，期望 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// 三个源全部出现。
	for _, id := range []string{"system", "nginx-access", "nginx-error"} {
		if !strings.Contains(body, `"id":"`+id+`"`) && !strings.Contains(body, id) {
			t.Errorf("sources 响应缺少源 %s", id)
		}
	}
	// 有测试文件，nginx 源应可用。
	if !strings.Contains(body, `"available":true`) {
		t.Errorf("有 access/error.log 时 nginx 源应可用: %s", body)
	}
}

func TestLogQueryOnNginxAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "access.log", strings.Join([]string{
		"[error] crashed",
		"GET /health 200",
		"POST /login 200",
	}, "\n")+"\n")
	writeTestLog(t, dir, "error.log", "[error] boom\n")
	s := newLogsServer(t, dir)

	// 查询 nginx-access。
	rec := loginAndDo(t, s, "GET", "/api/logs/query?source=nginx-access&lines=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("query 状态码 = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Count(rec.Body.String(), `"line"`) != 3 {
		t.Errorf("应返回 3 条 log line: %s", rec.Body.String())
	}

	// 关键词过滤。
	rec = loginAndDo(t, s, "GET", "/api/logs/query?source=nginx-access&filter=GET")
	if !strings.Contains(rec.Body.String(), "GET /health") ||
		strings.Contains(rec.Body.String(), "crashed") {
		t.Errorf("filter=GET 应只含 GET 行: %s", rec.Body.String())
	}
}

func TestLogQueryRejectsUnknownSource(t *testing.T) {
	dir := t.TempDir()
	s := newLogsServer(t, dir)
	rec := loginAndDo(t, s, "GET", "/api/logs/query?source=evil")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("未知源应 400，got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogQueryRejectsBadLevel(t *testing.T) {
	dir := t.TempDir()
	s := newLogsServer(t, dir)
	rec := loginAndDo(t, s, "GET", "/api/logs/query?source=system&level=super-evil")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 level 应 400，got %d", rec.Code)
	}
}

func TestLogQueryMissingSource(t *testing.T) {
	dir := t.TempDir()
	s := newLogsServer(t, dir)
	rec := loginAndDo(t, s, "GET", "/api/logs/query")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("缺 source 应 400，got %d", rec.Code)
	}
}

func TestLogAuditEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "access.log", "GET / 200\n")
	s := newLogsServer(t, dir)

	// 先做一次查询产生审计，再查审计。
	loginAndDo(t, s, "GET", "/api/logs/query?source=nginx-access&lines=5")
	rec := loginAndDo(t, s, "GET", "/api/logs/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit 状态码 = %d，期望 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "query") {
		t.Errorf("审计应包含 query 动作: %s", rec.Body.String())
	}
}
