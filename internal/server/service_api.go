package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/service"
)

// registerServiceRoutes 注册 systemd 服务管理接口（阶段四 4.1）。
//
// 路由设计：
//
//	GET  /api/services                服务列表（已过滤内部服务）
//	GET  /api/services/audit          服务操作审计记录
//	POST /api/services/{name}/start   启动服务
//	POST /api/services/{name}/stop    停止服务
//	POST /api/services/{name}/restart 重启服务
//
// 注册顺序说明（有实际后果，不是风格问题）：
// "/api/services/audit" 必须在 "/api/services/{name}/..." 之前注册。
// 否则 "audit" 会被 {name} 通配吃掉，查询审计会变成
// 「对名为 audit 的服务执行操作」——与阶段三 3.3 里
// "/api/plugins/audit" 踩过的坑完全同源。
//
// 鉴权：全部接口都要求登录（显式挂 RequireAuth，与 api.go 的白名单式风格一致）。
// 登录只解决「有没有身份」，写操作的「有没有权限」由 requireServicePermission 判定。
func (s *Server) registerServiceRoutes(mux *http.ServeMux) {
	if s.serviceMgr == nil {
		// 未注入服务管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/services/", s.auth.RequireAuth(http.HandlerFunc(s.handleServicesUnavailable)))
		mux.Handle("/api/services", s.auth.RequireAuth(http.HandlerFunc(s.handleServicesUnavailable)))
		return
	}

	mux.Handle("GET /api/services", s.auth.RequireAuth(http.HandlerFunc(s.handleServiceList)))

	// 审计接口必须在 {name} 通配之前注册（见上方说明）。
	mux.Handle("GET /api/services/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleServiceAudit)))

	mux.Handle("POST /api/services/{name}/start", s.auth.RequireAuth(http.HandlerFunc(s.handleServiceStart)))
	mux.Handle("POST /api/services/{name}/stop", s.auth.RequireAuth(http.HandlerFunc(s.handleServiceStop)))
	mux.Handle("POST /api/services/{name}/restart", s.auth.RequireAuth(http.HandlerFunc(s.handleServiceRestart)))
}

// handleServicesUnavailable 在服务管理器未注入时给出明确提示。
func (s *Server) handleServicesUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "服务管理未启用（服务启动时未注入服务管理器）",
	})
}

// serviceListResponse 是 GET /api/services 的响应体。
type serviceListResponse struct {
	Services []service.Service `json:"services"`
	// Total / Running 便于前端直接展示统计，不必自己遍历。
	Total   int `json:"total"`
	Running int `json:"running"`
	// Available 为 false 表示系统没有 systemd，前端据此禁用按钮并提示。
	Available bool `json:"available"`
	// UnavailableReason 是 systemd 不可用时的原因说明。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Audit 是审计器状态，供页面展示「操作是否在留痕」。
	Audit service.AuditStats `json:"audit"`
	// Permissions 是当前用户被授予的服务权限，前端据此禁用无权操作的按钮。
	//
	// 注意：这只是**体验优化**。真正的强制点始终在后端
	// （见 requireServicePermission），前端拿到的标记被篡改也没用。
	Permissions []string `json:"permissions"`
}

// handleServiceList 返回服务列表。
//
// 即使 systemd 不可用也返回 200：这样前端能拿到 available=false 与原因，
// 从而渲染出「为什么不可用」的说明页，而不是一个红色错误框。
func (s *Server) handleServiceList(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := service.AdminGrantee(user)

	resp := serviceListResponse{
		Available:   s.serviceMgr.Available(),
		Audit:       s.serviceMgr.Auditor().Stats(),
		Permissions: grantee.Granted,
		Services:    []service.Service{},
	}

	if !s.serviceMgr.Available() {
		resp.UnavailableReason = s.serviceMgr.UnavailableReason()
		writeJSON(w, s.logger, http.StatusOK, resp)
		return
	}

	list, err := s.serviceMgr.List(r.Context())
	if err != nil {
		s.writeServiceError(w, err, "", "")
		return
	}
	resp.Services = list
	resp.Total = len(list)
	resp.Running = service.RunningCount(list)
	writeJSON(w, s.logger, http.StatusOK, resp)
}

// handleServiceStart 启动服务。
func (s *Server) handleServiceStart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceAction(w, r, service.ActionStart)
}

// handleServiceStop 停止服务。
func (s *Server) handleServiceStop(w http.ResponseWriter, r *http.Request) {
	s.handleServiceAction(w, r, service.ActionStop)
}

// handleServiceRestart 重启服务。
func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceAction(w, r, service.ActionRestart)
}

// handleServiceAction 是三个写操作的统一实现。
//
// 执行顺序（顺序本身就是安全设计，不能调换）：
//
//  1. 校验服务名形态 → 非法直接 400，**不执行任何命令**；
//  2. 权限判定       → 无权直接 403，**不执行任何命令**；
//  3. 执行操作；
//  4. 无论成功、失败还是被拒绝，**都写一条审计**。
//
// 为什么权限判定放在执行之前：被拒绝的操作绝不能产生任何副作用，
// 这既是安全要求，也让审计里 denied 记录的含义是确定的
// （「请求没到达 systemctl」，而非「跑了但被拦下」）。
func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request, action service.Action) {
	name := r.PathValue("name")
	user, _ := auth.UsernameFrom(r.Context())
	grantee := service.AdminGrantee(user)
	clientIP := clientIPOf(r)
	started := time.Now()

	// 审计闭包：三个出口（拒绝 / 失败 / 成功）都要留痕，
	// 用闭包收口避免漏记——漏记的审计等于没有审计。
	record := func(outcome string, status int, reason, stateAfter string) {
		s.serviceMgr.Auditor().Record(service.AuditEvent{
			User:       user,
			Action:     string(action),
			Target:     name,
			Required:   service.RequiredPermission(action),
			Outcome:    outcome,
			Status:     status,
			DurationMS: time.Since(started).Milliseconds(),
			ClientIP:   clientIP,
			Reason:     reason,
			StateAfter: stateAfter,
		})
	}

	// ---------- 1. 服务名形态校验 ----------
	// 放在最前面：非法输入不该进入权限判定，更不该产生副作用。
	// 注意这里也要记审计：有人在探测非法服务名，本身就是值得留痕的信号。
	if !service.ValidUnitName(name) {
		msg := "非法的服务名: " + name
		record(service.AuditFailed, http.StatusBadRequest, msg, "")
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": msg,
			"hint": "服务名只允许字母、数字与 : _ . @ - \\ 字符，长度不超过 128。" +
				"请检查是否误传了路径或 shell 元字符。",
			"required": service.RequiredPermission(action),
		})
		return
	}

	// ---------- 2. 权限判定 ----------
	decision := service.CheckServicePermission(grantee, action)
	if !decision.Allowed {
		record(service.AuditDenied, http.StatusForbidden, decision.Reason, "")
		// 响应头与插件权限拦截保持一致，便于统一排查与告警规则复用。
		w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
		s.logger.Warn("服务操作被权限校验拒绝",
			"user", user, "action", action, "target", name,
			"required", decision.Required, "client_ip", clientIP)
		writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
			"error":    decision.Reason,
			"hint":     decision.Hint,
			"required": decision.Required,
			"granted":  decision.Granted,
		})
		return
	}

	// ---------- 3. 执行 ----------
	svc, err := s.serviceMgr.Do(r.Context(), action, name)
	if err != nil {
		status := s.writeServiceError(w, err, name, string(action))
		record(service.AuditFailed, status, err.Error(), "")
		return
	}

	// ---------- 4. 成功 ----------
	record(service.AuditAllowed, http.StatusOK, "", svc.State)
	s.logger.Info("服务操作成功",
		"user", user, "action", action, "target", name,
		"state", svc.State, "client_ip", clientIP)
	writeJSON(w, s.logger, http.StatusOK, svc)
}

// handleServiceAudit 返回服务操作审计记录。
//
// 支持 ?target= / ?user= / ?outcome= / ?limit= 过滤。
func (s *Server) handleServiceAudit(w http.ResponseWriter, r *http.Request) {
	if s.serviceMgr == nil {
		s.handleServicesUnavailable(w, r)
		return
	}

	query := r.URL.Query()
	filter := service.AuditFilter{
		Target:  strings.TrimSpace(query.Get("target")),
		User:    strings.TrimSpace(query.Get("user")),
		Outcome: strings.TrimSpace(query.Get("outcome")),
		Limit:   parseAuditLimit(query.Get("limit")),
	}
	auditor := s.serviceMgr.Auditor()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": auditor.Query(filter),
		"stats":  auditor.Stats(),
		"filter": map[string]any{
			"target":  filter.Target,
			"user":    filter.User,
			"outcome": filter.Outcome,
			"limit":   effectiveAuditLimit(filter.Limit),
		},
		// scope_note 把「这份审计覆盖什么」写进响应，
		// 避免用户误以为它记录了系统里所有人的操作。
		"scope_note": "本审计记录的是**经本面板发起**的服务操作（含被权限拒绝的请求）。" +
			"在面板之外直接执行的 systemctl 命令不会被记录。",
	})
}

// writeServiceError 把 service 包的错误翻译成合适的 HTTP 状态码并写出响应。
//
// 这是计划里「不能裸奔报 500」的落点。状态码语义：
//
//	400 服务名非法（形态校验未通过）
//	403 权限不足（需要 root / polkit 认证）
//	404 服务不存在
//	503 systemd 不可用（未安装 systemctl / 非 systemd 环境）
//	504 操作超时
//	500 其它错误（透传 systemctl 的真实 stderr）
//
// 返回值是实际写出的状态码，供调用方写入审计记录
// （避免审计里的 status 与真实响应不一致）。
func (s *Server) writeServiceError(w http.ResponseWriter, err error, name, action string) int {
	write := func(status int, payload map[string]any) int {
		writeJSON(w, s.logger, status, payload)
		return status
	}

	switch {
	case errors.Is(err, service.ErrInvalidName):
		return write(http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "服务名只允许字母、数字与 : _ . @ - \\ 字符，且不能以 - 开头。",
		})

	case errors.Is(err, service.ErrPermission):
		// 权限不足是最需要「说清楚怎么办」的一类错误：
		// 用户看到的应当是「用 root 运行」，而不是一句 systemd 原文。
		return write(http.StatusForbidden, map[string]any{
			"error": "权限不足：" + err.Error(),
			"hint": "管理 systemd 服务需要 root 权限。" +
				"请以 root 身份运行 lipanel（例如 sudo ./lipanel ...），" +
				"或为该进程配置 polkit 授权。",
			"target": name,
			"action": action,
		})

	case errors.Is(err, service.ErrNotFound):
		return write(http.StatusNotFound, map[string]any{
			"error":  "服务不存在：" + name,
			"hint":   "请确认服务名是否正确（可用 GET /api/services 查看系统中已有的服务）。",
			"target": name,
		})

	case errors.Is(err, service.ErrSystemdUnavailable):
		return write(http.StatusServiceUnavailable, map[string]any{
			"error": err.Error(),
			"hint": "服务管理需要 systemd 环境；" +
				"容器镜像、Alpine、WSL1 等通常不提供 systemd。面板其它功能不受影响。",
		})

	case errors.Is(err, service.ErrTimeout):
		return write(http.StatusGatewayTimeout, map[string]any{
			"error":  err.Error(),
			"hint":   "systemctl 未在超时时间内返回，服务可能正在长时间启动。请稍后重试并检查该服务状态。",
			"target": name,
			"action": action,
		})

	case errors.Is(err, service.ErrUnsupportedAction):
		return write(http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "仅支持 start / stop / restart 三种操作。",
		})

	default:
		s.logger.Error("服务操作失败", "target", name, "action", action, "err", err)
		return write(http.StatusInternalServerError, map[string]any{
			"error":  err.Error(),
			"target": name,
			"action": action,
		})
	}
}

// clientIPOf 提取发起请求的客户端 IP（用于审计）。
//
// 只取 RemoteAddr，**不信任 X-Forwarded-For**：
// 该头可被客户端随意伪造，把它写进审计会制造「看起来精确其实不可信」的记录。
// 若面板部署在反向代理后且确实需要真实 IP，
// 应显式配置受信任的代理来源后再解析（不在 4.1 范围内）。
func clientIPOf(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return r.RemoteAddr
	}
	return host
}
