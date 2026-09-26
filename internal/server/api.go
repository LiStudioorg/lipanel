package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// registerAPIRoutes 注册所有 /api 下的接口。
// 新增接口时统一在此登记，保证路由集中可查。
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", s.handleHealth)
}

// healthResponse 是 /api/health 的响应体，字段使用 snake_case 以便前端直接消费。
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

// handleHealth 返回服务健康状态，供前端首屏探活与联调使用。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: s.opts.Version,
		Time:    time.Now().Format(time.RFC3339),
	})
}

// writeJSON 以统一格式写出 JSON 响应。
// 序列化失败属于编程错误，此时响应头可能已写出，只能记录日志。
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("写出 JSON 响应失败", "err", err)
	}
}
