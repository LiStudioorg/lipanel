package server

import (
	"io/fs"
	"net/http"
	"os"
	"strings"

	"lipanel"
)

// staticHandler 返回处理前端页面的 handler。
//
// 优先级：
//  1. Options.StaticDir 非空 → 使用磁盘目录（开发调试用，改完刷新即可生效）。
//  2. 否则 → 使用 go:embed 打包进二进制的 web/dist（单二进制运行方式）。
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

	fsys, err := lipanel.WebFS()
	if err != nil {
		return nil, err
	}
	s.logger.Info("使用内置 embed 静态资源", "built", lipanel.WebBuilt())
	return s.spaHandler(fsys), nil
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
