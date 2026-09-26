package server

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusRecorder 记录实际写出的状态码，供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	// 处理未显式调用 WriteHeader 的隐式 200。
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// withRequestLog 记录每个请求的方法、路径、状态码与耗时。
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		s.logger.LogAttrs(r.Context(), slog.LevelInfo, "http 请求",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("cost", time.Since(start)),
		)
	})
}

// withRecovery 捕获 panic，避免单个请求导致整个进程退出。
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("请求处理 panic",
					"err", rec,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				writeJSON(w, s.logger, http.StatusInternalServerError, map[string]string{
					"error": "服务器内部错误",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
