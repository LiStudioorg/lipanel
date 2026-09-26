package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"lipanel"
)

// newTestServer 构造一个用于测试的 Server，日志丢弃以免污染测试输出。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{
		Addr:    "127.0.0.1:0",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "test",
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return s
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}

	var got healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v, body=%q", err, rec.Body.String())
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, 期望 %q", got.Status, "ok")
	}
	if got.Version != "test" {
		t.Errorf("version = %q, 期望 %q", got.Version, "test")
	}
	if got.Time == "" {
		t.Error("time 字段为空")
	}
}

// 未注册的 /api 路径必须返回 JSON 404，而不是前端 HTML，避免前端把 404 当成页面解析。
func TestUnknownAPIReturnsJSON404(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/not-exist", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusNotFound)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, 期望 JSON", ct)
	}
}

// 前端未构建时访问页面应返回 503，并给出可操作的错误提示。
// 若已执行过前端构建（embed 中有 index.html），该分支不适用，跳过。
func TestRootWithoutFrontendReturns503(t *testing.T) {
	if lipanel.WebBuilt() {
		t.Skip("检测到已构建的前端产物，跳过「未构建」分支")
	}
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, 期望 %d（前端未构建）", rec.Code, http.StatusServiceUnavailable)
	}
}

// 使用 -static-dir 指定磁盘目录时，SPA 兜底应返回该目录下的 index.html。
func TestStaticDirServesIndexForUnknownRoute(t *testing.T) {
	dir := t.TempDir()
	const page = "<!doctype html><title>lipanel</title>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(page), 0o644); err != nil {
		t.Fatalf("写入测试 index.html 失败: %v", err)
	}

	s, err := New(Options{
		Addr:      "127.0.0.1:0",
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		StaticDir: dir,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != page {
		t.Errorf("响应体 = %q, 期望 %q", rec.Body.String(), page)
	}
}

// Addr 缺失时必须报错，而不是默默监听随机端口。
func TestNewRejectsEmptyAddr(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("Addr 为空时应当返回错误")
	}
}
