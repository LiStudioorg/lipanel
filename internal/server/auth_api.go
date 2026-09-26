package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
)

// loginRequest 是 POST /api/login 的请求体。
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginResponse 是登录成功的响应体。
// 注意：token 不放在响应体里，只通过 HttpOnly Cookie 下发，前端 JS 无法读取。
type loginResponse struct {
	Username  string `json:"username"`
	ExpiresAt string `json:"expires_at"`
	// Redirect 是经校验的跳转地址，前端可直接使用，避免开放重定向。
	Redirect string `json:"redirect"`
}

// maxLoginBodySize 限制登录请求体大小，防止超大 body 打满内存。
const maxLoginBodySize = 4 << 10 // 4 KiB

// handleLogin 校验账号密码，成功后通过 HttpOnly Cookie 下发 JWT。
//
// 安全约定：
//   - 无论「用户不存在」还是「密码错误」，对外都是同一个 401 文案，防止账号枚举。
//   - 失败日志只记录用户名，绝不记录密码。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBodySize))
	// 不启用 DisallowUnknownFields：前端后续可能附加字段（如 remember），
	// 让未知字段宽进不影响安全，却可避免无谓的 400。
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "请求体格式错误，应为 JSON: {\"username\":\"...\",\"password\":\"...\"}",
		})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "用户名和密码不能为空",
		})
		return
	}

	name, expiresAt, err := s.auth.Login(w, username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.logger.Warn("登录失败", "username", username, "remote", clientIP(r))
			writeJSON(w, s.logger, http.StatusUnauthorized, map[string]string{
				"error": "用户名或密码错误",
			})
			return
		}
		// 非凭证类错误（如签名失败）属于服务端问题，不应暴露细节。
		s.logger.Error("登录处理异常", "err", err, "username", username)
		writeJSON(w, s.logger, http.StatusInternalServerError, map[string]string{
			"error": "登录失败，请稍后重试",
		})
		return
	}

	s.logger.Info("登录成功", "username", name, "remote", clientIP(r))
	writeJSON(w, s.logger, http.StatusOK, loginResponse{
		Username:  name,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Redirect:  auth.SanitizeNext(r.URL.Query().Get("redirect")),
	})
}

// handleLogout 清除会话 Cookie。
//
// 设计说明：无状态 JWT 无法在服务端吊销单个 token，登出只清客户端 Cookie。
// 该接口保持公开（未登录时调用也应成功返回），使前端可以无条件执行登出清理。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w)
	if name, ok := s.currentUser(r); ok {
		s.logger.Info("登出", "username", name, "remote", clientIP(r))
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]string{"status": "ok"})
}

// meResponse 是 GET /api/auth/me 的响应体。
//
// 为什么需要这个接口：前端刷新页面后内存状态丢失，路由守卫需要一个
// 「轻量、只验证登录态」的接口来恢复会话，而不能依赖较重的 /api/system/info
// （后者每次都会读 /proc 并做 CPU 采样）。
type meResponse struct {
	Username  string `json:"username"`
	ExpiresAt string `json:"expires_at"`
}

// handleAuthMe 返回当前登录用户，供前端路由守卫恢复登录态。
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	name, ok := s.currentUser(r)
	if !ok {
		// 正常流程下 RequireAuth 已挡在前面，这里是防御性分支。
		writeJSON(w, s.logger, http.StatusUnauthorized, map[string]string{
			"error": "未登录或登录已过期，请重新登录",
		})
		return
	}

	resp := meResponse{Username: name}
	if exp := s.auth.ExpiresAt(r); !exp.IsZero() {
		resp.ExpiresAt = exp.Format(time.RFC3339)
	}
	writeJSON(w, s.logger, http.StatusOK, resp)
}

// handleSystemInfo 返回当前机器的基础信息（CPU/内存/磁盘/系统版本）。
//
// 采集过程中任何子项失败都只降级为 warnings，接口本身仍返回 200，
// 保证前端至少能看到部分信息，而不是整页报错。
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := s.sysinfo.Collect()

	if len(info.Warnings) > 0 {
		s.logger.Warn("系统信息部分采集失败", "warnings", info.Warnings)
	}
	writeJSON(w, s.logger, http.StatusOK, info)
}

// currentUser 从请求中解析当前登录用户名（RequireAuth 已校验过 token）。
func (s *Server) currentUser(r *http.Request) (string, bool) {
	if name, ok := auth.UsernameFrom(r.Context()); ok {
		return name, true
	}
	// 兜底：重新解析一次 Cookie，保证 handler 可被独立测试。
	name, err := s.auth.Username(r)
	if err != nil {
		return "", false
	}
	return name, true
}

// buildAuth 构造默认的鉴权组件，仅在未通过 Options 注入时使用。
//
// 这里使用的默认口令 admin/admin123 只适用于本地开发，必须打印醒目告警。
func buildAuth(logger *slog.Logger) (*auth.Authenticator, error) {
	const (
		defaultUser = "admin"
		defaultPass = "admin123"
	)

	hash, err := auth.HashPassword(defaultPass)
	if err != nil {
		return nil, fmt.Errorf("server: 生成默认密码哈希失败: %w", err)
	}
	store, err := auth.NewMemoryUserStore(defaultUser, hash)
	if err != nil {
		return nil, fmt.Errorf("server: 构造默认账号失败: %w", err)
	}

	logger.Warn("未配置管理员账号，正在使用开发默认口令",
		"username", defaultUser, "password", defaultPass,
		"hint", "生产环境请使用 -admin-password 或 -admin-password-hash 指定",
	)

	a, err := auth.New(auth.Options{Store: store})
	if err != nil {
		return nil, fmt.Errorf("server: 初始化鉴权组件失败: %w", err)
	}
	return a, nil
}

// clientIP 提取客户端 IP 用于日志。
// 面板通常部署在反向代理之后，因此优先取 X-Forwarded-For 的第一段。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}
