package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/notify"
)

// ============================================================================
// 通知渠道接口（阶段五 5.4.2，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/notify              渠道列表（脱敏视图）+ 加密可用性 + 审计统计
//	POST   /api/notify              新建渠道
//	GET    /api/notify/capabilities 各渠道支持字段与示例
//	GET    /api/notify/audit        操作审计
//	POST   /api/notify/test         测试发送（?channel=xxx 或全部启用）
//	GET    /api/notify/{id}         单个渠道（脱敏）
//	PUT    /api/notify/{id}         编辑渠道
//	DELETE /api/notify/{id}         删除渠道
//
// ⚠️ 注册顺序：/api/notify/capabilities、/api/notify/audit、/api/notify/test
// 这些**固定段**路由必须先于 /api/notify/{id} 通配注册（4.1~5.3 连续踩过的坑）。
//
// #################### 本模块接口最要紧的一件事 ####################
//
// **凭证既不回显也不进审计。** 列表只返回脱敏视图（has_secret 布尔），
// 编辑时请求里的密文字段为空串表示「不改动」。任何响应、任何审计记录、
// 任何错误信息里都不能出现 webhook 地址的真正 token、SMTP 密码、
// Telegram token。

func (s *Server) registerNotifyRoutes(mux *http.ServeMux) {
	if s.notifyMgr == nil {
		mux.Handle("/api/notify/", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyUnavailable)))
		mux.Handle("/api/notify", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyUnavailable)))
		return
	}

	// 固定段路由先于通配注册。
	mux.Handle("GET /api/notify/capabilities", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyCapabilities)))
	mux.Handle("GET /api/notify/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyAudit)))
	mux.Handle("POST /api/notify/test", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyTest)))
	mux.Handle("GET /api/notify", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyList)))
	mux.Handle("POST /api/notify", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyCreate)))
	mux.Handle("GET /api/notify/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyGet)))
	mux.Handle("PUT /api/notify/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyUpdate)))
	mux.Handle("DELETE /api/notify/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleNotifyDelete)))
}

func (s *Server) handleNotifyUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]any{
		"error": "通知渠道模块未启用",
		"hint":  "通知管理器未注入，无法提供服务。",
	})
}

// ---- 审计脚手架 ----

type notifyAudit struct {
	srv     *Server
	user    string
	ip      string
	started time.Time
	channel string
	chType  notify.ChannelType
	chName  string
}

func (s *Server) beginNotifyAudit(r *http.Request, channel, name string, chType notify.ChannelType) *notifyAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &notifyAudit{
		srv: s, user: user, ip: clientIPOf(r), started: time.Now(),
		channel: channel, chName: name, chType: chType,
	}
}

func (a *notifyAudit) record(ev notify.AuditEvent) {
	ev.User = a.user
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.ChannelID == "" {
		ev.ChannelID = a.channel
	}
	if ev.ChannelType == "" {
		ev.ChannelType = string(a.chType)
	}
	if ev.ChannelName == "" {
		ev.ChannelName = a.chName
	}
	a.srv.notifyMgr.Auditor().Record(ev)
}

func (s *Server) requireNotifyPermission(w http.ResponseWriter, a *notifyAudit, action notify.Action) bool {
	decision := notify.CheckNotifyPermission(notify.AdminGrantee(a.user), action)
	if decision.Allowed {
		return true
	}
	a.record(notify.AuditEvent{
		Action:   string(action),
		Outcome:  notify.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("通知操作被权限校验拒绝",
		"user", a.user, "action", action, "required", decision.Required)
	writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
		"error":    decision.Reason,
		"hint":     decision.Hint,
		"required": decision.Required,
		"granted":  decision.Granted,
	})
	return false
}

// ---- JSON 编解码 ----

type notifyChannelRequest struct {
	Name           string             `json:"name"`
	Type           notify.ChannelType `json:"type"`
	Enabled        bool               `json:"enabled"`
	SMTPHost       string             `json:"smtp_host"`
	SMTPPort       int                `json:"smtp_port"`
	SMTPUser       string             `json:"smtp_user"`
	SMTPFrom       string             `json:"smtp_from"`
	Receivers      string             `json:"receivers"`
	SMTPUseTLS     bool               `json:"smtp_use_tls"`
	TelegramChatID string             `json:"telegram_chat_id"`
	SMTPPassword   string             `json:"smtp_password"`
	WebhookURL     string             `json:"webhook_url"`
	TelegramToken  string             `json:"telegram_token"`
}

func (req notifyChannelRequest) toInput() notify.ChannelInput {
	return notify.ChannelInput{
		Name:           strings.TrimSpace(req.Name),
		Type:           req.Type,
		Enabled:        req.Enabled,
		SMTPHost:       strings.TrimSpace(req.SMTPHost),
		SMTPPort:       req.SMTPPort,
		SMTPUser:       strings.TrimSpace(req.SMTPUser),
		SMTPFrom:       strings.TrimSpace(req.SMTPFrom),
		Receivers:      strings.TrimSpace(req.Receivers),
		SMTPUseTLS:     req.SMTPUseTLS,
		TelegramChatID: strings.TrimSpace(req.TelegramChatID),
		SMTPPassword:   req.SMTPPassword,
		WebhookURL:     strings.TrimSpace(req.WebhookURL),
		TelegramToken:  strings.TrimSpace(req.TelegramToken),
	}
}

func decodeNotifyChannel(w http.ResponseWriter, r *http.Request) (notifyChannelRequest, error) {
	var req notifyChannelRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		return req, fmt.Errorf("请求体不是合法 JSON: %w", err)
	}
	return req, nil
}

// ---- Handlers ----

func (s *Server) handleNotifyList(w http.ResponseWriter, r *http.Request) {
	a := s.beginNotifyAudit(r, "", "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionList) {
		return
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"channels":           s.notifyMgr.List(),
		"encryption_enabled": s.notifyMgr.EncryptionEnabled(),
		"store_path":         s.notifyMgr.StorePath(),
		"audit":              s.notifyMgr.Auditor().Stats(),
	})
}

func (s *Server) handleNotifyCapabilities(w http.ResponseWriter, r *http.Request) {
	// 只读能力声明，无需写权限。
	a := s.beginNotifyAudit(r, "", "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionQuery) {
		return
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"encryption_enabled": s.notifyMgr.EncryptionEnabled(),
		"channels": []map[string]any{
			{"type": string(notify.TypeSMTP), "label": "邮件 (SMTP)", "fields": []string{"name", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "receivers"}},
			{"type": string(notify.TypeDingTalk), "label": "钉钉机器人", "fields": []string{"name", "webhook_url"}},
			{"type": string(notify.TypeWeCom), "label": "企业微信机器人", "fields": []string{"name", "webhook_url"}},
			{"type": string(notify.TypeTelegram), "label": "Telegram Bot", "fields": []string{"name", "telegram_token", "telegram_chat_id"}},
		},
	})
}

func (s *Server) handleNotifyCreate(w http.ResponseWriter, r *http.Request) {
	a := s.beginNotifyAudit(r, "", "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionCreate) {
		return
	}
	req, err := decodeNotifyChannel(w, r)
	if err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	in := req.toInput()
	ch, err := s.notifyMgr.Create(in)
	if err != nil {
		s.writeNotifyError(w, a, notify.ActionCreate, err)
		return
	}
	a.channel = ch.ID
	a.chName = ch.Name
	a.chType = ch.Type
	a.record(notify.AuditEvent{Action: "create", Outcome: notify.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"channel": notify.PublicChannelOf(ch),
	})
}

func (s *Server) handleNotifyGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a := s.beginNotifyAudit(r, id, "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionQuery) {
		return
	}
	ch, err := s.notifyMgr.Get(id)
	if err != nil {
		s.writeNotifyError(w, a, notify.ActionQuery, err)
		return
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"channel": ch})
}

func (s *Server) handleNotifyUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a := s.beginNotifyAudit(r, id, "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionUpdate) {
		return
	}
	req, err := decodeNotifyChannel(w, r)
	if err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ch, err := s.notifyMgr.Update(id, req.toInput())
	if err != nil {
		s.writeNotifyError(w, a, notify.ActionUpdate, err)
		return
	}
	a.chName = ch.Name
	a.chType = ch.Type
	a.record(notify.AuditEvent{Action: "update", Outcome: notify.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"channel": notify.PublicChannelOf(ch)})
}

func (s *Server) handleNotifyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a := s.beginNotifyAudit(r, id, "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionDelete) {
		return
	}
	err := s.notifyMgr.Delete(id)
	if err != nil {
		s.writeNotifyError(w, a, notify.ActionDelete, err)
		return
	}
	a.record(notify.AuditEvent{Action: "delete", Outcome: notify.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	channelID := r.URL.Query().Get("channel")
	a := s.beginNotifyAudit(r, channelID, "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionTest) {
		return
	}
	res := s.notifyMgr.Test(r.Context(), channelID)
	status := http.StatusOK
	evOutcome := notify.AuditAllowed
	reason := ""
	if res.Sent == 0 {
		status = http.StatusBadGateway
		evOutcome = notify.AuditFailed
		// 只取第一个错误的脱敏文本（already 无凭证）。
		for _, e := range res.Errors {
			reason = e
			break
		}
	}
	a.record(notify.AuditEvent{
		Action: "test", Outcome: evOutcome, Status: status,
		Sent: res.Sent, Failed: res.Failed, Reason: reason,
	})
	writeJSON(w, s.logger, status, map[string]any{"sent": res.Sent, "failed": res.Failed})
}

func (s *Server) handleNotifyAudit(w http.ResponseWriter, r *http.Request) {
	a := s.beginNotifyAudit(r, "", "", "")
	if !s.requireNotifyPermission(w, a, notify.ActionQuery) {
		return
	}
	limit := parseInt(q(r, "limit"))
	events := s.notifyMgr.Auditor().List(notify.AuditQuery{Limit: limit, Outcome: q(r, "outcome")})
	a.record(notify.AuditEvent{Action: "audit", Outcome: notify.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"audit": events})
}

// writeNotifyError 统一映射 notify 错误到 HTTP 状态码并记审计。
func (s *Server) writeNotifyError(w http.ResponseWriter, a *notifyAudit, action notify.Action, err error) {
	status := http.StatusBadRequest
	hint := "请检查字段是否符合所选渠道的要求。"
	switch {
	case errors.Is(err, notify.ErrChannelNotFound):
		status = http.StatusNotFound
	case errors.Is(err, notify.ErrInvalidChannel):
		status = http.StatusBadRequest
	case errors.Is(err, notify.ErrNoCipher):
		// 凭证加密不可用（未配置主密钥/jwt_secret）。此时不允许创建带凭证
		// 的渠道 —— 绝不静默明文落盘。给可操作的提示而非 500。
		status = http.StatusServiceUnavailable
		hint = "面板未配置主密钥（配置文件里的 jwt_secret），通知凭证加密不可用。" +
			"请通过 -config 指定配置文件（含 jwt_secret）后再创建带凭证的渠道。"
	}
	a.record(notify.AuditEvent{
		Action: string(action), Outcome: notify.AuditDenied,
		Status: status, Reason: err.Error(),
		Required: notify.RequiredPermission(action),
	})
	writeJSON(w, s.logger, status, map[string]any{
		"error": err.Error(),
		"hint":  hint,
	})
}

func q(r *http.Request, k string) string { return r.URL.Query().Get(k) }
func parseInt(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}
