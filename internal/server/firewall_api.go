package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/firewall"
)

// ============================================================================
// 防火墙与端口管理接口（阶段四 4.6，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/firewall                状态 + 后端 + 保护端口 + 审计状态
//	GET    /api/firewall/rules          规则列表（端口规则 + IP 黑白名单）
//	GET    /api/firewall/audit          操作审计
//	GET    /api/firewall/capabilities   能力探测（各后端可用性、删除方式）
//	POST   /api/firewall/ports          放行/拒绝端口
//	DELETE /api/firewall/ports          删除端口规则（必须 confirm）
//	POST   /api/firewall/ips            添加 IP 黑白名单
//	DELETE /api/firewall/ips            删除 IP 规则（必须 confirm）
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/firewall/rules"、"/api/firewall/audit"、"/api/firewall/capabilities"
// 这些**固定段**路由必须在任何通配路由**之前**注册。
//
// ########## 这是 4.1~4.5 连续踩过五次的同一个坑 ##########
//
// 本模块的删除走 DELETE 方法上的 /ports 与 /ips 固定路径，
// 因此当前不存在 {name} 通配——但**仍然按同样纪律注册**：
// 将来若要加 "/api/firewall/rules/{id}"，固定段就已经在正确的位置上，
// 不需要回头调整顺序（那时候调整极容易漏掉）。
// 另有测试（firewall_api_test.go）锁死固定段路由不会被通配吃掉。
//
// 与其它核心模块一致：
//   - 全部接口挂 RequireAuth（按路由显式挂载）；
//   - 写操作顺序固定：**校验 → 保护判定 → 二次确认 → 权限 → 执行 → 审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
//
// ########## 本模块接口的两个特有设计 ##########
//
// ① **删除必须带 confirm**（428 Precondition Required）
//
//	计划明确要求"删除规则前必须二次确认，避免把 SSH 端口误关导致失联"。
//	前端弹窗只是体验，服务端强制才是边界。不带 confirm 的 DELETE
//	一律 428，无论请求来自什么客户端。
//
// ② **受保护端口默认拒绝**（409）、需要 force
//
//	面板自身端口与 SSH 端口受保护。删除它们需要显式 force=true，
//	且审计里会单独记录（Force 字段 + Forced 计数），
//	让"谁在什么时候强行删了 SSH 端口"事后可查。
func (s *Server) registerFirewallRoutes(mux *http.ServeMux) {
	if s.firewallMgr == nil {
		// 未注入管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/firewall/", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallUnavailable)))
		mux.Handle("/api/firewall", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallUnavailable)))
		return
	}

	mux.Handle("GET /api/firewall", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallStatus)))

	// ⚠️ 固定段路由必须先于任何通配注册（见上方说明）。
	mux.Handle("GET /api/firewall/rules", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallRules)))
	mux.Handle("GET /api/firewall/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallAudit)))
	mux.Handle("GET /api/firewall/capabilities", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallCapabilities)))

	// 写操作。
	mux.Handle("POST /api/firewall/ports", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallAddPort)))
	mux.Handle("DELETE /api/firewall/ports", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallDeletePort)))
	mux.Handle("POST /api/firewall/ips", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallAddIP)))
	mux.Handle("DELETE /api/firewall/ips", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallDeleteIP)))

	// 前缀兜底：未注册的 /api/firewall/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html）。
	mux.Handle("/api/firewall/", s.auth.RequireAuth(http.HandlerFunc(s.handleFirewallNotFound)))
}

// handleFirewallUnavailable 在防火墙管理器未注入时给出明确提示。
func (s *Server) handleFirewallUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "防火墙管理未启用（服务启动时未注入管理器）",
	})
}

// handleFirewallNotFound 处理 /api/firewall/* 下未注册的子路径。
//
// 返回 JSON 404 并**列出可用接口**——这类 404 多半是路径写错了，
// 把正确的接口清单摆在响应里，比让人去翻源码快得多。
func (s *Server) handleFirewallNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "防火墙接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET    /api/firewall",
			"GET    /api/firewall/rules",
			"GET    /api/firewall/audit?limit=100&action=&outcome=",
			"GET    /api/firewall/capabilities",
			"POST   /api/firewall/ports",
			"DELETE /api/firewall/ports?confirm=true",
			"POST   /api/firewall/ips",
			"DELETE /api/firewall/ips?confirm=true",
		},
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// firewallAudit 收口一次防火墙操作的审计写入。
//
// 与 4.2 的 fileAudit、4.3 的 siteAudit、4.4 的 sslAudit、4.5 的 storeAudit
// 同构：每个接口都要填 user/action/target/client_ip 这几个固定字段，
// 散落各处必然出现"某个接口忘了填 client_ip"这种不一致。
type firewallAudit struct {
	srv     *Server
	user    string
	action  string
	target  string
	ip      string
	started time.Time
	// 规则上下文（在请求解析后填充）。
	backend    string
	port       string
	protocol   string
	sourceIP   string
	ruleAction string
	ruleSpec   string
	command    string
	protected  bool
	force      bool
	confirmed  bool
}

// beginFirewallAudit 构造一次操作的审计上下文。
func (s *Server) beginFirewallAudit(r *http.Request, action, target string) *firewallAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &firewallAudit{
		srv:     s,
		user:    user,
		action:  action,
		target:  target,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计。
func (a *firewallAudit) record(ev firewall.AuditEvent) {
	ev.User = a.user
	ev.Action = a.action
	ev.Target = a.target
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.Required == "" {
		ev.Required = firewall.RequiredPermission(a.action)
	}
	// 请求解析后的上下文（谁填什么、命中了哪条规则）。
	if ev.Backend == "" {
		ev.Backend = a.backend
	}
	if ev.Port == "" {
		ev.Port = a.port
	}
	if ev.Protocol == "" {
		ev.Protocol = a.protocol
	}
	if ev.SourceIP == "" {
		ev.SourceIP = a.sourceIP
	}
	if ev.RuleAction == "" {
		ev.RuleAction = a.ruleAction
	}
	if ev.RuleSpec == "" {
		ev.RuleSpec = a.ruleSpec
	}
	if ev.Command == "" {
		ev.Command = a.command
	}
	if !ev.Protected {
		ev.Protected = a.protected
	}
	if !ev.Force {
		ev.Force = a.force
	}
	if !ev.Confirmed {
		ev.Confirmed = a.confirmed
	}
	a.srv.firewallMgr.Auditor().Record(ev)
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireFirewallPermission 判定当前用户能否执行某防火墙动作。
//
// 顺序与其它核心模块一致且不可调换：**先判权限，再碰外部命令**。
// 被拒绝的请求绝不能产生任何副作用——对本模块而言，
// 副作用就是"改变了这台机器的网络可达性"，
// 一条错误的规则可以让 SSH 与面板同时失联。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireFirewallPermission(w http.ResponseWriter, a *firewallAudit) bool {
	grantee := firewall.AdminGrantee(a.user)
	decision := firewall.CheckFirewallPermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(firewall.AuditEvent{
		Outcome:  firewall.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	// 响应头与其它模块的权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("防火墙操作被权限校验拒绝",
		"user", a.user, "action", a.action, "target", a.target, "required", decision.Required)
	writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
		"error":    decision.Reason,
		"hint":     decision.Hint,
		"required": decision.Required,
		"granted":  decision.Granted,
	})
	return false
}

// ---------------------------------------------------------------------------
// 错误映射
// ---------------------------------------------------------------------------

// firewallErrorStatus 把 firewall 包的语义错误映射为 HTTP 状态码。
//
// ########## 状态码的语义必须准确 ##########
//
//	400 输入非法（端口越界、IP 格式错）—— 用户的输入问题
//	404 规则不存在                   —— 可能已被其它工具删除
//	409 规则不可精确删除 / 端口受保护 —— **不是用户的输入问题，
//	                                     而是当前状态不允许此操作**
//	428 缺少二次确认                 —— 请求合法但需要显式确认
//	503 后端不可用                   —— 系统没装防火墙
//	502 命令执行失败                 —— 防火墙自己报错
//
// 428 是本模块特有的：它让"删除需要确认"这件事在协议层可见，
// 而不是靠前端自觉（前端被绕过时后端仍然拦得住）。
func firewallErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, firewall.ErrConfirmRequired):
		return http.StatusPreconditionRequired, "缺少二次确认"
	case errors.Is(err, firewall.ErrProtectedPort):
		return http.StatusConflict, "端口受保护"
	case errors.Is(err, firewall.ErrNotDeletable):
		return http.StatusConflict, "规则无法精确删除"
	case errors.Is(err, firewall.ErrInvalidRule):
		return http.StatusBadRequest, "输入非法"
	case errors.Is(err, firewall.ErrRuleNotFound):
		return http.StatusNotFound, "规则不存在"
	case errors.Is(err, firewall.ErrUnavailable):
		return http.StatusServiceUnavailable, "防火墙不可用"
	case errors.Is(err, firewall.ErrBackendInactive):
		return http.StatusConflict, "防火墙未启用"
	case errors.Is(err, firewall.ErrPermission):
		return http.StatusForbidden, "权限不足"
	case errors.Is(err, firewall.ErrTimeout):
		return http.StatusGatewayTimeout, "操作超时"
	case errors.Is(err, firewall.ErrCommandFailed):
		return http.StatusBadGateway, "命令执行失败"
	default:
		return http.StatusInternalServerError, "内部错误"
	}
}

// writeFirewallError 统一写出防火墙操作错误。
func (s *Server) writeFirewallError(w http.ResponseWriter, a *firewallAudit, err error) {
	status, kind := firewallErrorStatus(err)

	// 428 需要按 RFC 6585 给出提示，让客户端知道"补上确认再重试"。
	if status == http.StatusPreconditionRequired {
		w.Header().Set("X-Lipanel-Confirm-Required", "true")
	}

	a.record(firewall.AuditEvent{
		Outcome:  firewall.AuditDenied,
		Status:   status,
		Reason:   err.Error(),
		Required: firewall.RequiredPermission(a.action),
	})

	payload := map[string]any{
		"error": err.Error(),
		"kind":  kind,
		// 把状态码语义重复一遍：前端可以直接展示，
		// 不必自己维护一份"哪个错对应哪个码"的表。
		"status": status,
	}
	switch status {
	case http.StatusPreconditionRequired:
		payload["hint"] = "删除防火墙规则可能让你失去与服务器的连接，" +
			"因此必须在请求中显式带上 confirm=true 才会执行。" +
			"前端会弹出确认框；如果你在用命令行，请手动加上该参数。"
	case http.StatusConflict:
		if errors.Is(err, firewall.ErrProtectedPort) {
			payload["hint"] = "该端口是面板自身端口或 SSH 端口，删除后你将无法再访问面板或服务器。" +
				"如果你确实确定要删除，请在请求中额外带上 force=true —— " +
				"该操作会被记入审计。"
		}
	case http.StatusNotFound:
		payload["hint"] = "规则可能已被其它工具（ufw / firewall-cmd / iptables / nft）删除。" +
			"请刷新规则列表后重试。"
	case http.StatusServiceUnavailable:
		payload["hint"] = "当前系统没有可用的防火墙后端。请查看 GET /api/firewall 的安装指引。"
	}
	writeJSON(w, s.logger, status, payload)
}

// ---------------------------------------------------------------------------
// GET /api/firewall —— 状态
// ---------------------------------------------------------------------------

// firewallStatusResponse 是 GET /api/firewall 的响应体。
type firewallStatusResponse struct {
	// Detection 是后端探测结论。
	Detection firewall.Detection `json:"detection"`
	// Protection 是端口保护判定。
	Protection firewall.Protection `json:"protection"`
	// Detail 是后端详细状态。
	Detail firewall.StatusDetail `json:"detail"`
	// RuleCount 是规则条数。
	RuleCount int `json:"rule_count"`
	// Available 表示后端可用。
	//
	// ########## 为 false 时不是错误 ##########
	//
	// "没装防火墙"与"接口坏了"是两件事。这里返回 200 + available=false
	// + 安装指引，让前端渲染说明页而不是红色错误框
	// （与 4.1 无 systemd、4.4 无 certbot 完全一致的降级策略）。
	Available bool `json:"available"`
	// UnavailableReason 是不可用原因。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// InstallHint 是安装指引（不可用时给出）。
	InstallHint string `json:"install_hint,omitempty"`
	ScannedAt   string `json:"scanned_at"`
	DryRun      bool   `json:"dry_run"`
	// CommandTimeoutSeconds 是命令超时配置。
	CommandTimeoutSeconds float64 `json:"command_timeout_seconds"`
	// Audit 是审计器状态。
	Audit firewall.AuditStats `json:"audit"`
	// Permissions 是当前用户被授予的防火墙权限。
	//
	// 注意：这只是**体验优化**。真正的强制点始终在后端
	// （见 requireFirewallPermission），前端拿到的标记被篡改也没用。
	Permissions []string `json:"permissions"`
}

// handleFirewallStatus 返回防火墙状态。
func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	audit := s.beginFirewallAudit(r, firewall.ActionStatus, "")

	result, err := s.firewallMgr.Status(r.Context())
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}
	audit.backend = result.Detection.Backend
	audit.target = result.Detection.Backend
	audit.record(firewall.AuditEvent{
		Outcome: firewall.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, firewallStatusResponse{
		Detection:             result.Detection,
		Protection:            result.Protection,
		Detail:                result.Detail,
		RuleCount:             result.RuleCount,
		Available:             result.Detection.Available,
		UnavailableReason:     result.Detection.Reason,
		InstallHint:           result.Detection.Hint,
		ScannedAt:             result.ScannedAt,
		DryRun:                result.DryRun,
		CommandTimeoutSeconds: result.CommandTimeoutSeconds,
		Audit:                 s.firewallMgr.Auditor().Stats(),
		Permissions:           firewall.AdminGrantee(user).Granted,
	})
}

// ---------------------------------------------------------------------------
// GET /api/firewall/rules —— 规则列表
// ---------------------------------------------------------------------------

// handleFirewallRules 返回规则列表。
func (s *Server) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	audit := s.beginFirewallAudit(r, firewall.ActionListRules, "")

	result, err := s.firewallMgr.ListRules(r.Context())
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}
	audit.backend = result.Backend
	audit.target = result.Backend
	audit.record(firewall.AuditEvent{
		Outcome: firewall.AuditAllowed,
		Status:  http.StatusOK,
	})
	writeJSON(w, s.logger, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// GET /api/firewall/capabilities —— 能力探测
// ---------------------------------------------------------------------------

// firewallCapabilitiesResponse 是 GET /api/firewall/capabilities 的响应体。
//
// 这个接口回答的是"为什么某些操作在不同后端表现不同"，
// 是用户理解面板行为的第一入口（例如"为什么这条 nft 规则删不掉"）。
type firewallCapabilitiesResponse struct {
	// Backends 是各后端的能力说明。
	Backends []firewall.CapabilityInfo `json:"backends"`
	// Detection 是当前探测结论。
	Detection firewall.Detection `json:"detection"`
	// DeletionSemantics 是当前生效后端的删除语义（前端在删除按钮旁展示）。
	DeletionSemantics string `json:"deletion_semantics,omitempty"`
	// Protection 是保护判定（前端据此说明"哪些端口受保护"）。
	Protection firewall.Protection `json:"protection"`
	// ConfirmRequired 恒为 true：声明本面板的删除必须二次确认。
	//
	// ########## 为什么把它放进响应里 ##########
	//
	// 让客户端（包括第三方脚本）能**从接口自描述**得知
	// "删除需要 confirm"，而不是试一次拿到 428 才知道。
	ConfirmRequired bool `json:"confirm_required"`
	// ForceSupported 恒为 true：声明受保护端口可用 force 强删。
	ForceSupported bool `json:"force_supported"`
	DryRun         bool `json:"dry_run"`
}

// handleFirewallCapabilities 返回能力探测结果。
func (s *Server) handleFirewallCapabilities(w http.ResponseWriter, r *http.Request) {
	audit := s.beginFirewallAudit(r, firewall.ActionCapabilities, "")

	detection, err := s.firewallMgr.Detect(r.Context(), false)
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}
	protection := s.firewallMgr.Protection(r.Context())

	backends := s.firewallMgr.Capabilities()
	var semantics string
	for _, b := range backends {
		if b.Backend == detection.Backend {
			semantics = b.Deletion
		}
	}

	audit.backend = detection.Backend
	audit.target = detection.Backend
	audit.record(firewall.AuditEvent{
		Outcome: firewall.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, firewallCapabilitiesResponse{
		Backends:          backends,
		Detection:         detection,
		DeletionSemantics: semantics,
		Protection:        protection,
		ConfirmRequired:   true,
		ForceSupported:    true,
		DryRun:            s.firewallMgr.DryRun(),
	})
}

// ---------------------------------------------------------------------------
// GET /api/firewall/audit —— 审计
// ---------------------------------------------------------------------------

// firewallAuditResponse 是 GET /api/firewall/audit 的响应体。
type firewallAuditResponse struct {
	Events []firewall.AuditEvent `json:"events"`
	Stats  firewall.AuditStats   `json:"stats"`
	// Total 是本次返回的条数。
	Total int `json:"total"`
	// Filter 回显本次的过滤条件（便于前端展示"当前筛选"）。
	Filter map[string]string `json:"filter,omitempty"`
}

// handleFirewallAudit 返回防火墙操作审计。
func (s *Server) handleFirewallAudit(w http.ResponseWriter, r *http.Request) {
	audit := s.beginFirewallAudit(r, firewall.ActionAudit, "")

	limit := firewall.DefaultAuditQueryLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			// 必须包装成 ErrInvalidRule，否则会被错误映射表
			// 归到 default 分支返回 500 —— 而"limit 写错了"
			// 明明是用户的输入问题，应当 400。
			s.writeFirewallError(w, audit, fmt.Errorf(
				"%w: limit 必须是正整数，实际收到 %q", firewall.ErrInvalidRule, v))
			return
		}
		limit = n
	}
	filter := firewall.AuditFilter{
		User:             strings.TrimSpace(r.URL.Query().Get("user")),
		Action:           strings.TrimSpace(r.URL.Query().Get("action")),
		Outcome:          strings.TrimSpace(r.URL.Query().Get("outcome")),
		Backend:          strings.TrimSpace(r.URL.Query().Get("backend")),
		OnlySystemChange: r.URL.Query().Get("system_change") == "true",
		Limit:            limit,
	}

	events := s.firewallMgr.Auditor().Query(filter)

	audit.record(firewall.AuditEvent{
		Outcome: firewall.AuditAllowed,
		Status:  http.StatusOK,
	})

	echo := map[string]string{}
	if filter.User != "" {
		echo["user"] = filter.User
	}
	if filter.Action != "" {
		echo["action"] = filter.Action
	}
	if filter.Outcome != "" {
		echo["outcome"] = filter.Outcome
	}
	if filter.Backend != "" {
		echo["backend"] = filter.Backend
	}
	if filter.OnlySystemChange {
		echo["system_change"] = "true"
	}

	writeJSON(w, s.logger, http.StatusOK, firewallAuditResponse{
		Events: events,
		Stats:  s.firewallMgr.Auditor().Stats(),
		Total:  len(events),
		Filter: echo,
	})
}

// ---------------------------------------------------------------------------
// POST /api/firewall/ports —— 放行/拒绝端口
// ---------------------------------------------------------------------------

// handleFirewallAddPort 处理端口规则的添加。
func (s *Server) handleFirewallAddPort(w http.ResponseWriter, r *http.Request) {
	var req firewall.PortRequest
	if !s.decodeFirewallBody(w, r, &req) {
		return
	}

	audit := s.beginFirewallAudit(r, firewall.ActionAddPort, firewallTargetOf(req.Port, req.Protocol))
	audit.port = req.Port
	audit.protocol = req.Protocol
	audit.sourceIP = req.Source
	audit.ruleAction = req.Action

	if !s.requireFirewallPermission(w, audit) {
		return
	}

	result, err := s.firewallMgr.AddPort(r.Context(), req)
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}

	audit.backend = result.Backend
	audit.command = strings.Join(result.Commands, " && ")
	audit.record(firewall.AuditEvent{
		Outcome:  firewall.AuditAllowed,
		Status:   http.StatusOK,
		Command:  audit.command,
		RuleSpec: firewallSpecOf(req.Port, req.Protocol, req.Source, req.Action),
		Reason: func() string {
			if result.Simulated {
				return "试运行：命令未真正执行"
			}
			return ""
		}(),
	})

	writeJSON(w, s.logger, http.StatusOK, firewallOpResponse{
		OK:        true,
		Backend:   result.Backend,
		Commands:  result.Commands,
		Simulated: result.Simulated,
		Message:   firewallAddedMessage(req, result),
	})
}

// handleFirewallDeletePort 处理端口规则的删除。
//
// ########## 三道闸门 ##########
//
//	① confirm —— 二次确认（428）
//	② protect —— 受保护端口（409），除非 force
//	③ deletable —— 无法精确删除的规则（409）
//
// 顺序：确认在前（"是否继续"与"输入是否合法"无关），
// 权限在确认之后（避免用"需要确认"掩盖权限问题——
// 那样用户会以为有权限只是没确认，实际是没权限）。
func (s *Server) handleFirewallDeletePort(w http.ResponseWriter, r *http.Request) {
	// 支持两种传参：JSON body 与查询参数。
	//
	// ########## 为什么 DELETE 也支持 body ##########
	//
	// 计划的删除语义是"端口 + 协议 + 来源 + 动作"四项定位一条规则，
	// 而查询串表达多字段既不直观也容易漏。
	// 但 curl 手工测试时查询串更方便，因此两者都支持。
	req, ok := s.parseDeletePortRequest(r)
	if !ok {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "无法解析删除请求（请提供 port，可选 protocol/source/action/confirm/force）",
			"hint": "可用的形式：JSON body {\"port\":\"8080\",\"protocol\":\"tcp\",\"confirm\":true} " +
				"或查询串 ?port=8080&protocol=tcp&confirm=true",
		})
		return
	}

	audit := s.beginFirewallAudit(r, firewall.ActionDeletePort, firewallTargetOf(req.Port, req.Protocol))
	audit.port = req.Port
	audit.protocol = req.Protocol
	audit.sourceIP = req.Source
	audit.ruleAction = req.Action
	audit.force = req.Force
	audit.confirmed = req.Confirm

	// 保护判定提前做一次，仅为了**审计留痕**能标出"涉及受保护端口"。
	// 真正的强制点在 Manager 里（那里会在执行前再判一次）。
	if protection := s.firewallMgr.Protection(r.Context()); len(protection.Ports) > 0 {
		if port, err := firewall.ValidatePortSpec(req.Port); err == nil {
			if _, hit := protection.Lookup().Find(port); hit {
				audit.protected = true
			}
		}
	}

	if !s.requireFirewallPermission(w, audit) {
		return
	}

	result, err := s.firewallMgr.DeletePort(r.Context(), req)
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}

	audit.backend = result.Backend
	audit.command = strings.Join(result.Commands, " && ")
	audit.record(firewall.AuditEvent{
		Outcome:  firewall.AuditAllowed,
		Status:   http.StatusOK,
		Command:  audit.command,
		RuleSpec: firewallSpecOf(req.Port, req.Protocol, req.Source, req.Action),
	})

	msg := "已删除规则 " + firewallTargetOf(req.Port, req.Protocol)
	if audit.force && audit.protected {
		msg += "。⚠️ 这是一条受保护端口的规则，你使用了强制删除 —— 该操作已记入审计。"
	}
	writeJSON(w, s.logger, http.StatusOK, firewallOpResponse{
		OK:        true,
		Backend:   result.Backend,
		Commands:  result.Commands,
		Simulated: result.Simulated,
		Message:   msg,
	})
}

// parseDeletePortRequest 解析删除端口的请求（支持 JSON body 与查询串）。
func (s *Server) parseDeletePortRequest(r *http.Request) (firewall.DeletePortRequest, bool) {
	var req firewall.DeletePortRequest

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFirewallBodyBytes))
	if err == nil && len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return req, false
		}
	}

	// 查询串补充/覆盖（便于 curl 手工调用）。
	q := r.URL.Query()
	if v := q.Get("port"); v != "" {
		req.Port = v
	}
	if v := q.Get("protocol"); v != "" {
		req.Protocol = v
	}
	if v := q.Get("source"); v != "" {
		req.Source = v
	}
	if v := q.Get("action"); v != "" {
		req.Action = v
	}
	if v := q.Get("confirm"); v != "" {
		req.Confirm = parseBoolLoose(v)
	}
	if v := q.Get("force"); v != "" {
		req.Force = parseBoolLoose(v)
	}
	if req.Port == "" {
		return req, false
	}
	if req.Action == "" {
		req.Action = firewall.ActionAllow
	}
	return req, true
}

// ---------------------------------------------------------------------------
// POST / DELETE /api/firewall/ips —— IP 黑白名单
// ---------------------------------------------------------------------------

// handleFirewallAddIP 处理 IP 黑白名单的添加。
func (s *Server) handleFirewallAddIP(w http.ResponseWriter, r *http.Request) {
	var req firewall.IPRequest
	if !s.decodeFirewallBody(w, r, &req) {
		return
	}

	audit := s.beginFirewallAudit(r, firewall.ActionAddIP, req.IP)
	audit.sourceIP = req.IP
	audit.ruleAction = req.Direction

	if !s.requireFirewallPermission(w, audit) {
		return
	}

	result, err := s.firewallMgr.AddIP(r.Context(), req)
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}

	audit.backend = result.Backend
	audit.command = strings.Join(result.Commands, " && ")
	audit.record(firewall.AuditEvent{
		Outcome:  firewall.AuditAllowed,
		Status:   http.StatusOK,
		Command:  audit.command,
		RuleSpec: "source=" + req.IP + " " + req.Direction,
	})

	label := "黑名单"
	if strings.EqualFold(req.Direction, firewall.DirectionAllow) {
		label = "白名单"
	}
	writeJSON(w, s.logger, http.StatusOK, firewallOpResponse{
		OK:        true,
		Backend:   result.Backend,
		Commands:  result.Commands,
		Simulated: result.Simulated,
		Message:   "已将 " + req.IP + " 加入" + label,
	})
}

// handleFirewallDeleteIP 处理 IP 黑白名单的删除。
func (s *Server) handleFirewallDeleteIP(w http.ResponseWriter, r *http.Request) {
	req, ok := s.parseDeleteIPRequest(r)
	if !ok {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "无法解析删除请求（请提供 ip，可选 direction/confirm）",
			"hint": "可用的形式：JSON body {\"ip\":\"1.2.3.4\",\"direction\":\"deny\",\"confirm\":true} " +
				"或查询串 ?ip=1.2.3.4&direction=deny&confirm=true",
		})
		return
	}

	audit := s.beginFirewallAudit(r, firewall.ActionDeleteIP, req.IP)
	audit.sourceIP = req.IP
	audit.ruleAction = req.Direction
	audit.confirmed = req.Confirm

	if !s.requireFirewallPermission(w, audit) {
		return
	}

	result, err := s.firewallMgr.DeleteIP(r.Context(), req)
	if err != nil {
		s.writeFirewallError(w, audit, err)
		return
	}

	audit.backend = result.Backend
	audit.command = strings.Join(result.Commands, " && ")
	audit.record(firewall.AuditEvent{
		Outcome:  firewall.AuditAllowed,
		Status:   http.StatusOK,
		Command:  audit.command,
		RuleSpec: "source=" + req.IP + " " + req.Direction,
	})

	writeJSON(w, s.logger, http.StatusOK, firewallOpResponse{
		OK:        true,
		Backend:   result.Backend,
		Commands:  result.Commands,
		Simulated: result.Simulated,
		Message:   "已删除 IP 规则 " + req.IP,
	})
}

// parseDeleteIPRequest 解析删除 IP 规则的请求。
func (s *Server) parseDeleteIPRequest(r *http.Request) (firewall.DeleteIPRequest, bool) {
	var req firewall.DeleteIPRequest

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFirewallBodyBytes))
	if err == nil && len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return req, false
		}
	}

	q := r.URL.Query()
	if v := q.Get("ip"); v != "" {
		req.IP = v
	}
	if v := q.Get("direction"); v != "" {
		req.Direction = v
	}
	if v := q.Get("confirm"); v != "" {
		req.Confirm = parseBoolLoose(v)
	}
	if req.IP == "" {
		return req, false
	}
	return req, true
}

// ---------------------------------------------------------------------------
// 响应与解析辅助
// ---------------------------------------------------------------------------

// firewallOpResponse 是写操作的成功响应体。
type firewallOpResponse struct {
	OK bool `json:"ok"`
	// Backend 是执行时使用的后端。
	Backend string `json:"backend"`
	// Commands 是实际执行（或将要执行）的命令。
	//
	// ########## 为什么把命令返回给前端 ##########
	//
	// 用户改完防火墙后可能想在其他机器上做同样操作，
	// 或者想确认"面板到底做了什么"。把命令如实列出，
	// 让面板的行为完全可审计、可复现，而不是一个黑盒。
	Commands []string `json:"commands"`
	// Simulated 表示这是试运行（命令未真正执行）。
	Simulated bool `json:"simulated"`
	// Message 是给用户看的结果说明。
	Message string `json:"message,omitempty"`
}

// maxFirewallBodyBytes 是请求体的最大字节数。
//
// 防火墙请求体非常小（几个字段），64 KiB 已经极其宽松；
// 设上限是为了避免一个畸形的大请求把内存打满。
const maxFirewallBodyBytes = 64 * 1024

// decodeFirewallBody 解析 JSON 请求体。
//
// 与其它模块一致：解析失败返回 400 且**不执行任何操作**，
// 并且拒绝未知字段（DisallowUnknownFields）——
// 拼错的字段名会让用户以为参数生效了，实际被静默忽略。
// 例如把 "protocol" 写成 "protocal"，若静默忽略就会用默认的 tcp，
// 用户以为放行了 UDP 却实际只开了 TCP。
func (s *Server) decodeFirewallBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxFirewallBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "请求体解析失败: " + err.Error(),
			"hint": "请检查 JSON 格式与字段名。注意字段名拼写错误不会被忽略" +
				"（例如 protocol 写成 protocal 会报错，而不是静默使用默认值）。",
		})
		return false
	}
	return true
}

// parseBoolLoose 宽松解析布尔值（接受 true/1/yes/on）。
//
// 手工用 curl 测试时 ?confirm=1 比 ?confirm=true 顺手，
// 而这两种写法在用户心里是等价的。
func parseBoolLoose(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// firewallTargetOf 生成审计用的目标描述。
func firewallTargetOf(port, protocol string) string {
	if port == "" {
		return ""
	}
	if protocol == "" {
		return port
	}
	return port + "/" + protocol
}

// firewallSpecOf 生成审计用的规则规格。
//
// ########## 为什么审计要存完整的规则规格 ##########
//
// 防火墙没有回收站：恢复一条被删的规则只能靠人重新输入。
// 把"端口+协议+来源+动作"完整记下来，事后就能直接照着重加。
func firewallSpecOf(port, protocol, source, action string) string {
	if port == "" {
		return ""
	}
	p := protocol
	if p == "" {
		p = firewall.ProtoTCP
	}
	a := action
	if a == "" {
		a = firewall.ActionAllow
	}
	s := source
	if s == "" {
		s = "any"
	}
	return port + "/" + p + " from " + s + " " + a
}

// firewallAddedMessage 生成添加端口的结果说明。
func firewallAddedMessage(req firewall.PortRequest, result firewall.OpResult) string {
	action := "已放行"
	if strings.EqualFold(req.Action, firewall.ActionDeny) {
		action = "已拒绝"
	}
	msg := action + "端口 " + req.Port
	if req.Source != "" {
		msg += "（来源 " + req.Source + "）"
	}
	if strings.EqualFold(req.Protocol, firewall.ProtoAny) {
		msg += "，协议 tcp + udp"
	}
	if result.Simulated {
		msg += "（试运行：命令未真正执行）"
	}
	return msg
}
