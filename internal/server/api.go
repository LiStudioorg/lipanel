package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// registerAPIRoutes 注册所有 /api 下的接口。
// 新增接口时统一在此登记，保证路由集中可查。
//
// 鉴权采用「按路由显式挂载」的白名单方式：只有包了 s.auth.RequireAuth 的接口才需要登录。
// 相比全局拦截 /api/*，这里多写一行，但新增接口不会因为白名单漏配而意外裸奔，
// 公开接口（health/login）也无需额外的豁免名单。
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	// ---------- 公开接口 ----------
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// ---------- 需要登录的接口 ----------
	mux.Handle("GET /api/auth/me", s.auth.RequireAuth(http.HandlerFunc(s.handleAuthMe)))
	mux.Handle("GET /api/system/info", s.auth.RequireAuth(http.HandlerFunc(s.handleSystemInfo)))

	// ---------- 服务管理（阶段四 4.1，核心自带）----------
	//
	// 这里是核心功能的统一登记处，因此服务路由的**注册入口**放在本函数；
	// 具体 handler 与实现细节在 service_api.go / internal/service 包。
	// 之所以不在本文件里逐个写 mux.Handle：服务有多条路由且要处理
	// "审计路径必须先于 {name} 通配注册"的顺序问题，
	// 集中在一个注册函数里比散落在两处更不容易写错。
	s.registerServiceRoutes(mux)

	// ---------- 文件管理（阶段四 4.2，核心自带）----------
	//
	// 同样是核心自带能力（不做成插件）：新增 file_api.go 承载 handler，
	// internal/file 承载路径安全、权限与审计。这里只负责"登记"。
	s.registerFileRoutes(mux)

	// ---------- 网站管理（阶段四 4.3，核心自带）----------
	//
	// 与 4.1/4.2 同一套架构：site_api.go 承载 handler，
	// internal/site 承载配置生成、nginx -t 校验与自动回滚、权限与审计。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（/api/sites/audit 与
	// /api/sites/capabilities 必须先于 /api/sites/{name} 注册），
	// 已由 registerSiteRoutes 集中处理，详见其注释与
	// site_api_test.go 中锁死该行为的测试。
	s.registerSiteRoutes(mux)
}

// healthResponse 是 /api/health 的响应体，字段使用 snake_case 以便前端直接消费。
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
	// TokenTTLSeconds 告诉前端会话时长，便于提示「登录已过期」。
	TokenTTLSeconds int `json:"token_ttl_seconds"`
	// HasFixedSecret 为 false 表示签名密钥是每次启动随机生成的（重启需重新登录）。
	HasFixedSecret bool `json:"has_fixed_secret"`
}

// handleHealth 返回服务健康状态，供前端首屏探活与联调使用。
//
// 该接口保持公开且极轻量：它可能被监控系统高频轮询，
// 因此不读 /proc、不查 Cookie，只返回内存中的常量信息。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusOK, healthResponse{
		Status:          "ok",
		Version:         s.opts.Version,
		Time:            time.Now().Format(time.RFC3339),
		TokenTTLSeconds: int(s.auth.TTL().Seconds()),
		HasFixedSecret:  !s.auth.SecretGenerated(),
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
