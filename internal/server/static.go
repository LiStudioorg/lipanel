package server

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
)

// staticHandler 返回处理前端页面的 handler。
//
// 优先级：
//  1. Options.StaticDir 非空 → 使用磁盘目录（开发调试用，改完刷新即可生效）。
//  2. 否则 → 使用 Options.WebFS 注入的内嵌资源（单二进制运行方式）。
//
// SPA 兜底：未命中静态文件且不是 /api 前缀的路径，一律返回 index.html，
// 交给前端路由处理。
func (s *Server) staticHandler() (http.Handler, error) {
	if s.opts.StaticDir != "" {
		info, err := os.Stat(s.opts.StaticDir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, &os.PathError{Op: "stat", Path: s.opts.StaticDir, Err: os.ErrInvalid}
		}
		s.logger.Info("使用磁盘静态资源目录", "dir", s.opts.StaticDir)
		return s.spaHandler(os.DirFS(s.opts.StaticDir)), nil
	}

	// WebFS 由 main 注入（见 main.go 的 go:embed）。
	//
	// 为什么不在这里直接 import 根包：入口 main.go 迁到根目录后，根目录是
	// package main，而 Go 不允许 import 一个 main 包。由调用方注入 fs.FS
	// 反而更干净——internal/server 不再依赖"前端产物放在哪"这种部署细节，
	// 测试里也能塞一个内存 FS。
	if s.opts.WebFS == nil {
		return nil, errors.New(
			"server: 未注入前端资源（Options.WebFS 为空）；" +
				"请用 -static-dir 指定目录，或由 main 注入 go:embed 的文件系统")
	}
	s.logger.Info("使用内置 embed 静态资源", "built", s.opts.WebBuilt)
	return s.spaHandler(s.opts.WebFS), nil
}

// spaHandler 基于 fs.FS 提供静态文件服务，并实现 SPA 兜底与 API 404 语义。
func (s *Server) spaHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")

		// /api 前缀的未注册路由返回 JSON 404，而不是前端页面。
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, s.logger, http.StatusNotFound, map[string]string{
				"error": "接口不存在: " + r.URL.Path,
			})
			return
		}

		// index.html 不缓存，避免发版后前端仍引用旧资源。
		w.Header().Set("Cache-Control", "no-cache")

		// 命中真实文件则直接交给 FileServer（如 /assets/index-xxx.js）。
		if info, err := fs.Stat(fsys, clean); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		// 未命中：回退到 index.html，交给前端路由处理。
		data, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			// 前端尚未构建（仅有 web/dist/.gitkeep）时给出可操作的提示。
			writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
				"error": "前端资源未构建，请先执行 ./build.sh 或 cd web && pnpm build",
			})
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			s.logger.Error("写出 index.html 失败", "err", err)
		}
	})
}
