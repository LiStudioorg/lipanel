package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// testFS 是大多数测试共用的最小前端资源：存在 index.html 表示"已构建"。
func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>lipanel</title>")},
	}
}

// newTestServer 构造一个用于测试的 Server，日志丢弃以免污染测试输出。
// 注入一个最小前端资源，使构造必定成功（不注入会被视为配置错误）。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithFS(t, testFS())
}

// newTestServerWithFS 用指定前端资源构造 Server。
func newTestServerWithFS(t *testing.T, fsys fs.FS) *Server {
	t.Helper()
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		WebFS:    fsys,
		WebBuilt: fsys != nil,
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

// 前端未注入时访问页面应返回 503，并给出可操作的错误提示。
//
// 注意：前端资源现在由 main 通过 Options.WebFS 注入（入口迁到根目录后，
// 根包是 package main，internal/server 不能再 import 它）。
// 因此这里用 fstest.MapFS 构造内存文件系统，测试不再依赖"构建产物是否存在"，
// 也就不会因为跑过一次 npm run build 而变成 skip。
func TestRootWithoutFrontendReturns503(t *testing.T) {
	// 模拟「只有 .gitkeep 占位、没有 index.html」的未构建状态。
	s := newTestServerWithFS(t, fstest.MapFS{
		".gitkeep": &fstest.MapFile{Data: []byte("# 占位文件\n")},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, 期望 %d（前端未构建）", rec.Code, http.StatusServiceUnavailable)
	}
}

// 注入的内嵌资源可用时，未知路由应回退到 index.html（SPA 兜底）。
func TestEmbeddedFSServesIndexForUnknownRoute(t *testing.T) {
	const indexHTML = "<!doctype html><title>lipanel-test</title>"
	s := newTestServerWithFS(t, fstest.MapFS{
		"index.html":           &fstest.MapFile{Data: []byte(indexHTML)},
		"assets/app-abc123.js": &fstest.MapFile{Data: []byte("console.log(1)")},
	})

	// SPA 兜底：未命中的前端路由返回 index.html。
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plugins/sysinfo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("未知前端路由状态码 = %d, 期望 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "lipanel-test") {
		t.Errorf("响应体不是注入的 index.html: %s", rec.Body.String())
	}

	// 命中真实文件时直接返回该文件。
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("静态资源状态码 = %d, 期望 200", rec.Code)
	}
	if rec.Body.String() != "console.log(1)" {
		t.Errorf("静态资源内容 = %q", rec.Body.String())
	}
}

// 未注入任何前端资源（既没有 -static-dir 也没有 WebFS）时应明确报错，
// 而不是静默返回空白页。
func TestNoFrontendSourceFailsFast(t *testing.T) {
	_, err := New(Options{
		Addr:    "127.0.0.1:0",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "test",
	})
	if err == nil {
		t.Fatal("既无 StaticDir 又无 WebFS 时应当返回错误")
	}
	if !strings.Contains(err.Error(), "WebFS") {
		t.Errorf("错误信息应指出缺少 WebFS，实际: %v", err)
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
