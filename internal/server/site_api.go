package server

import (
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/site"
)

// ============================================================================
// 站点管理接口（阶段四 4.3，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/sites                站点列表
//	GET    /api/sites/capabilities   能力探测（nginx 可用性、目录、白名单）
//	GET    /api/sites/audit          站点操作审计
//	POST   /api/sites                创建站点
//	GET    /api/sites/{name}         查看单个站点
//	PUT    /api/sites/{name}         编辑站点
//	DELETE /api/sites/{name}         删除站点
//	POST   /api/sites/{name}/enable  启用
//	POST   /api/sites/{name}/disable 禁用
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/sites/audit" 与 "/api/sites/capabilities" 必须在
// "/api/sites/{name}" **之前**注册。否则它们会被 {name} 通配吃掉——
// 查询审计会变成"查看名为 audit 的站点"，返回 404 或一个错误的站点。
//
// 这正是 4.1（/api/plugins/audit 与 /api/services/audit）与 4.2
// 反复踩过的同一个坑，因此本次在 site_api_test.go 里用测试锁死
// （TestSiteAuditRouteNotShadowedByWildcard）。
//
// 与前三个核心模块的接口一致性：
//   - 全部接口挂 RequireAuth（按路由显式挂载，与 api.go 的白名单式风格一致）；
//   - 写操作顺序固定：**校验 → 权限判定 → 执行 → 无论成败都审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
func (s *Server) registerSiteRoutes(mux *http.ServeMux) {
	if s.siteMgr == nil {
		// 未注入站点管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/sites/", s.auth.RequireAuth(http.HandlerFunc(s.handleSitesUnavailable)))
		mux.Handle("/api/sites", s.auth.RequireAuth(http.HandlerFunc(s.handleSitesUnavailable)))
		return
	}

	mux.Handle("GET /api/sites", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteList)))
	mux.Handle("POST /api/sites", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteCreate)))

	// ⚠️ 这两个**固定段**路由必须先于 {name} 通配注册（见上方说明）。
	mux.Handle("GET /api/sites/capabilities", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteCapabilities)))
	mux.Handle("GET /api/sites/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteAudit)))

	// {name} 通配路由。
	mux.Handle("GET /api/sites/{name}", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteGet)))
	mux.Handle("PUT /api/sites/{name}", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteUpdate)))
	mux.Handle("DELETE /api/sites/{name}", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteDelete)))
	mux.Handle("POST /api/sites/{name}/enable", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteEnable)))
	mux.Handle("POST /api/sites/{name}/disable", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteDisable)))

	// 前缀兜底：未注册的 /api/sites/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html，
	// 前端只会报一句"后端返回了非 JSON 内容"，无从判断原因）。
	// 这是 4.2 实测发现的真实缺陷，这里从一开始就补上。
	mux.Handle("/api/sites/", s.auth.RequireAuth(http.HandlerFunc(s.handleSiteNotFound)))
}

// handleSitesUnavailable 在站点管理器未注入时给出明确提示。
func (s *Server) handleSitesUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "站点管理未启用（服务启动时未注入站点管理器）",
	})
}

// handleSiteNotFound 处理 /api/sites/* 下未注册的子路径。
//
// 返回 JSON 404 并**列出可用接口**——这类 404 多半是调用方路径写错了，
// 把正确的接口清单摆在响应里，比让人去翻源码快得多。
func (s *Server) handleSiteNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "站点接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET    /api/sites",
			"POST   /api/sites",
			"GET    /api/sites/capabilities",
			"GET    /api/sites/audit",
			"GET    /api/sites/{name}",
			"PUT    /api/sites/{name}",
			"DELETE /api/sites/{name}",
			"POST   /api/sites/{name}/enable",
			"POST   /api/sites/{name}/disable",
		},
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// siteAudit 收口一次站点操作的审计写入。
//
// 与 4.2 的 fileAudit 同构：每个接口都要填 user/action/target/client_ip
// 这几个固定字段，散落八处必然出现"某个接口忘了填 client_ip"这种不一致。
type siteAudit struct {
	srv     *Server
	user    string
	action  string
	target  string
	domain  string
	siteTyp string
	ip      string
	started time.Time
}

// beginSiteAudit 构造一次操作的审计上下文。
func (s *Server) beginSiteAudit(r *http.Request, action, target string) *siteAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &siteAudit{
		srv:     s,
		user:    user,
		action:  action,
		target:  target,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计（outcome 见 site.AuditAllowed/Denied/Failed）。
func (a *siteAudit) record(outcome string, status int, reason string, rolledBack bool, enabledAfter *bool) {
	a.srv.siteMgr.Auditor().Record(site.AuditEvent{
		User:         a.user,
		Action:       a.action,
		Target:       a.target,
		Domain:       a.domain,
		SiteType:     a.siteTyp,
		Required:     site.RequiredPermission(a.action),
		Outcome:      outcome,
		Status:       status,
		DurationMS:   time.Since(a.started).Milliseconds(),
		ClientIP:     a.ip,
		Reason:       reason,
		RolledBack:   rolledBack,
		EnabledAfter: enabledAfter,
	})
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireSitePermission 判定当前用户能否执行某站点动作。
//
// 顺序与 4.1/4.2 一致且不可调换：**先判权限，再碰文件系统**。
// 被拒绝的请求绝不能产生任何副作用，这样审计里 denied 的含义
// 才是确定的（"请求没到达磁盘"），而不是"写了但被拦下"。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireSitePermission(w http.ResponseWriter, a *siteAudit) bool {
	grantee := site.AdminGrantee(a.user)
	decision := site.CheckSitePermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(site.AuditDenied, http.StatusForbidden, decision.Reason, false, nil)
	// 响应头与插件/服务/文件权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("站点操作被权限校验拒绝",
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
// GET /api/sites —— 列表
// ---------------------------------------------------------------------------

// siteListResponse 是 GET /api/sites 的响应体。
type siteListResponse struct {
	Sites []site.Site `json:"sites"`
	// Total / Enabled 便于前端直接展示统计，不必自己遍历。
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
	// Available 为 false 表示系统没有可用的 nginx，前端据此禁用按钮并提示。
	Available bool `json:"available"`
	// UnavailableReason 是 nginx 不可用时的原因说明。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Mode 是探测到的目录布局（sites / conf.d / unavailable）。
	Mode string `json:"mode,omitempty"`
	// Audit 是审计器状态，供页面展示"操作是否在留痕"。
	Audit site.AuditStats `json:"audit"`
	// Permissions 是当前用户被授予的站点权限，前端据此禁用无权操作的按钮。
	//
	// 注意：这只是**体验优化**。真正的强制点始终在后端
	// （见 requireSitePermission），前端拿到的标记被篡改也没用。
	Permissions []string `json:"permissions"`
}

// handleSiteList 返回站点列表。
//
// 即使 nginx 不可用也返回 200：这样前端能拿到 available=false 与原因，
// 从而渲染出"为什么不可用"的说明页，而不是一个红色错误框
// （与 4.1 的服务列表同样的降级策略）。
func (s *Server) handleSiteList(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := site.AdminGrantee(user)

	resp := siteListResponse{
		Available:   s.siteMgr.Available(),
		Mode:        s.siteMgr.Adapter().Mode(),
		Audit:       s.siteMgr.Auditor().Stats(),
		Permissions: grantee.Granted,
		Sites:       []site.Site{},
	}

	if !s.siteMgr.Available() {
		resp.UnavailableReason = s.siteMgr.UnavailableReason()
		writeJSON(w, s.logger, http.StatusOK, resp)
		return
	}

	list, err := s.siteMgr.List()
	if err != nil {
		s.writeSiteError(w, err, "", site.ActionList)
		return
	}
	resp.Sites = list
	resp.Total = len(list)
	for _, item := range list {
		if item.Enabled {
			resp.Enabled++
		}
	}
	writeJSON(w, s.logger, http.StatusOK, resp)
}

// handleSiteCapabilities 返回站点管理的能力探测结果。
//
// 前端据此：
//   - 在 nginx 不可用时展示原因并禁用全部操作；
//   - 展示"配置会写到哪个目录"（用户需要知道面板在动哪些文件）；
//   - 用 min/max 等限制做表单的前置校验（**只是体验**，
//     后端独立校验且是唯一强制点）。
func (s *Server) handleSiteCapabilities(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := site.AdminGrantee(user)
	adapter := s.siteMgr.Adapter()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"available":          s.siteMgr.Available(),
		"unavailable_reason": s.siteMgr.UnavailableReason(),
		"mode":               adapter.Mode(),
		"prefix":             adapter.Prefix(),
		"executable":         adapter.Executable(),
		"available_dir":      adapter.AvailableDir(),
		"enabled_dir":        adapter.EnabledDir(),
		"permissions":        grantee.Granted,
		"limits": map[string]any{
			"max_name_len":   site.MaxSiteNameLen,
			"min_name_len":   site.MinSiteNameLen,
			"max_domain_len": site.MaxDomainLen,
		},
		"types": []map[string]string{
			{"value": site.TypeStatic, "label": "静态站"},
			{"value": site.TypeProxy, "label": "反向代理"},
		},
		"audit": s.siteMgr.Auditor().Stats(),
		// scope_note 说明面板能碰到什么、不能碰到什么。
		// 站点管理会写系统目录，用户有权知道确切范围。
		"scope_note": "面板只管理 " + adapter.AvailableDir() +
			" 下的 .conf 文件。不是由面板创建的配置会以「只读」标记展示，" +
			"面板不会修改它们。",
	})
}

// ---------------------------------------------------------------------------
// POST /api/sites —— 创建
// ---------------------------------------------------------------------------

// handleSiteCreate 创建站点。
//
// 执行顺序（顺序本身就是安全设计，不能调换）：
//
//  1. 解析请求体 → 失败直接 400，**不触碰文件系统**；
//  2. 权限判定   → 无权直接 403，**不触碰文件系统**；
//  3. 校验 + 执行（含 nginx -t 与回滚）；
//  4. 无论成功、失败还是被拒绝，**都写一条审计**。
func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	var req site.SiteInput
	if err := decodeJSONBody(w, r, 16*1024, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "请求体必须是 JSON，字段见 GET /api/sites/capabilities。",
		})
		return
	}

	audit := s.beginSiteAudit(r, site.ActionCreate, strings.TrimSpace(req.Name))
	audit.domain = strings.TrimSpace(req.Domain)
	audit.siteTyp = req.Type

	if !s.requireSitePermission(w, audit) {
		return
	}

	created, err := s.siteMgr.Create(r.Context(), req)
	if err != nil {
		status := s.writeSiteError(w, err, audit.target, site.ActionCreate)
		audit.record(site.AuditFailed, status, err.Error(), isRolledBack(err), nil)
		return
	}

	enabled := created.Enabled
	audit.record(site.AuditAllowed, http.StatusOK, "", false, &enabled)
	s.logger.Info("站点已创建",
		"user", audit.user, "name", created.Name, "domain", created.Domain,
		"type", created.Type, "enabled", created.Enabled, "client_ip", audit.ip)
	writeJSON(w, s.logger, http.StatusOK, created)
}

// ---------------------------------------------------------------------------
// GET/PUT/DELETE /api/sites/{name}
// ---------------------------------------------------------------------------

// handleSiteGet 返回单个站点。
func (s *Server) handleSiteGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	audit := s.beginSiteAudit(r, site.ActionView, name)

	item, err := s.siteMgr.Get(name)
	if err != nil {
		// 站点名非法属于"探测"，值得留痕；单纯的"不存在"只记 Debug。
		if isNameViolation(err) {
			status := s.writeSiteError(w, err, name, site.ActionView)
			audit.record(site.AuditDenied, status, err.Error(), false, nil)
			return
		}
		s.writeSiteError(w, err, name, site.ActionView)
		return
	}
	writeJSON(w, s.logger, http.StatusOK, item)
}

// handleSiteUpdate 编辑站点。
func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req site.SiteInput
	if err := decodeJSONBody(w, r, 16*1024, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "请求体必须是 JSON。",
		})
		return
	}

	audit := s.beginSiteAudit(r, site.ActionUpdate, name)
	audit.domain = strings.TrimSpace(req.Domain)
	audit.siteTyp = req.Type

	if !s.requireSitePermission(w, audit) {
		return
	}

	updated, err := s.siteMgr.Update(r.Context(), name, req)
	if err != nil {
		status := s.writeSiteError(w, err, name, site.ActionUpdate)
		audit.record(site.AuditFailed, status, err.Error(), isRolledBack(err), nil)
		return
	}

	enabled := updated.Enabled
	audit.record(site.AuditAllowed, http.StatusOK, "", false, &enabled)
	s.logger.Info("站点已更新",
		"user", audit.user, "name", updated.Name, "domain", updated.Domain,
		"enabled", updated.Enabled, "client_ip", audit.ip)
	writeJSON(w, s.logger, http.StatusOK, updated)
}

// siteDeleteResponse 是删除成功的响应。
//
// 删除没有"结果对象"可返回，因此显式回一个 deleted 标记：
// 前端据此给出确定的成功提示，而不是靠"没报错"猜测。
type siteDeleteResponse struct {
	Deleted bool   `json:"deleted"`
	Name    string `json:"name"`
}

// handleSiteDelete 删除站点。
func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	audit := s.beginSiteAudit(r, site.ActionDelete, name)

	// 删除前先取一次域名，让审计记录里带上它——
	// 删除之后就无法再从配置里读出来了，而"谁删了哪个域名的站点"
	// 恰恰是事后最需要还原的信息。
	if existing, err := s.siteMgr.Get(name); err == nil {
		audit.domain = existing.Domain
		audit.siteTyp = existing.Type
	}

	if !s.requireSitePermission(w, audit) {
		return
	}

	if err := s.siteMgr.Delete(r.Context(), name); err != nil {
		status := s.writeSiteError(w, err, name, site.ActionDelete)
		audit.record(site.AuditFailed, status, err.Error(), isRolledBack(err), nil)
		return
	}

	audit.record(site.AuditAllowed, http.StatusOK, "", false, nil)
	// 删除是最需要留痕的操作：用 Warn 级别打日志，便于在系统日志里直接看到。
	s.logger.Warn("站点已删除",
		"user", audit.user, "name", name, "domain", audit.domain, "client_ip", audit.ip)
	writeJSON(w, s.logger, http.StatusOK, siteDeleteResponse{Deleted: true, Name: name})
}

// ---------------------------------------------------------------------------
// POST /api/sites/{name}/enable | disable
// ---------------------------------------------------------------------------

// handleSiteEnable 启用站点。
func (s *Server) handleSiteEnable(w http.ResponseWriter, r *http.Request) {
	s.handleSiteSetEnabled(w, r, true)
}

// handleSiteDisable 禁用站点。
func (s *Server) handleSiteDisable(w http.ResponseWriter, r *http.Request) {
	s.handleSiteSetEnabled(w, r, false)
}

// handleSiteSetEnabled 是启用/禁用的统一实现。
//
// 抽成一个函数而不是写两份：两者的行为、审计、错误处理完全一致，
// 写两份只会让"将来改一处忘了另一处"这类问题出现。
func (s *Server) handleSiteSetEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	name := r.PathValue("name")
	action := site.ActionDisable
	if enabled {
		action = site.ActionEnable
	}
	audit := s.beginSiteAudit(r, action, name)

	if existing, err := s.siteMgr.Get(name); err == nil {
		audit.domain = existing.Domain
		audit.siteTyp = existing.Type
	}

	if !s.requireSitePermission(w, audit) {
		return
	}

	updated, err := s.siteMgr.SetEnabled(r.Context(), name, enabled)
	if err != nil {
		status := s.writeSiteError(w, err, name, action)
		audit.record(site.AuditFailed, status, err.Error(), isRolledBack(err), nil)
		return
	}

	now := updated.Enabled
	audit.record(site.AuditAllowed, http.StatusOK, "", false, &now)
	s.logger.Info("站点启用状态已变更",
		"user", audit.user, "name", name, "enabled", enabled, "client_ip", audit.ip)
	writeJSON(w, s.logger, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// GET /api/sites/audit —— 审计查询
// ---------------------------------------------------------------------------

// handleSiteAudit 返回站点操作审计记录。
//
// 支持 ?target= / ?user= / ?action= / ?outcome= / ?limit= 过滤。
func (s *Server) handleSiteAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := site.AuditFilter{
		Target:  strings.TrimSpace(query.Get("target")),
		User:    strings.TrimSpace(query.Get("user")),
		Action:  strings.TrimSpace(query.Get("action")),
		Outcome: strings.TrimSpace(query.Get("outcome")),
		Limit:   parseAuditLimit(query.Get("limit")),
	}
	auditor := s.siteMgr.Auditor()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": auditor.Query(filter),
		"stats":  auditor.Stats(),
		"filter": map[string]any{
			"target":  filter.Target,
			"user":    filter.User,
			"action":  filter.Action,
			"outcome": filter.Outcome,
			"limit":   effectiveAuditLimit(filter.Limit),
		},
		// scope_note 把"这份审计覆盖什么"写进响应，
		// 避免用户误以为它记录了系统里所有人的 nginx 操作。
		"scope_note": "本审计只记录**经本面板发起**的站点操作（含被权限或校验拒绝的请求，" +
			"以及触发自动回滚的失败）。在服务器上直接编辑 nginx 配置文件不会被记录。",
	})
}

// ---------------------------------------------------------------------------
// 错误翻译
// ---------------------------------------------------------------------------

// isRolledBack 判断错误是否表示"已自动回滚"。
//
// 单独抽出来是因为它要同时喂给两处：审计的 RolledBack 字段，
// 以及日志。用 errors.Is 而不是字符串匹配——字符串匹配会在
// 文案改动时静默失效。
func isRolledBack(err error) bool {
	return errors.Is(err, site.ErrRolledBack) ||
		errors.Is(err, site.ErrNginxTestFailed) ||
		errors.Is(err, site.ErrReloadFailed)
}

// isNameViolation 判断错误是否属于"站点名非法"。
//
// 这类错误在站点模块里是**安全信号**（有人在探测配置注入），
// 即使发生在只读操作上也要留痕。
func isNameViolation(err error) bool {
	return errors.Is(err, site.ErrInvalidName) || errors.Is(err, site.ErrReservedName)
}

// writeSiteError 把 site 包的错误翻译成合适的 HTTP 状态码并写出响应。
//
// 这是"不能裸奔报 500"的落点。状态码语义：
//
//	400 输入非法（站点名/域名/根目录/后端地址/类型）
//	403 权限不足（文件系统层面或 nginx 配置目录不可写）
//	404 站点不存在
//	409 站点已存在 / 站点不是面板创建的（只读）
//	422 nginx -t 校验失败（**已回滚**）
//	502 nginx reload 失败（**已回滚**）
//	503 nginx 不可用
//	504 操作超时
//	500 其它错误（透传底层原因）
//
// 返回值是实际写出的状态码，供调用方写入审计记录
// （避免审计里的 status 与真实响应不一致——4.1/4.2 的同一做法）。
func (s *Server) writeSiteError(w http.ResponseWriter, err error, name, action string) int {
	write := func(status int, payload map[string]any) int {
		writeJSON(w, s.logger, status, payload)
		return status
	}
	errText := err.Error()

	switch {
	// ---------- 输入校验类（400） ----------
	//
	// 顺序说明：这些必须**先于**底层错误判定。它们的错误信息里
	// 也包着 os 的错误链（例如 "以 / 开头" 之类），若不先判就会被
	// 翻译成 404/403，把"这是一次注入探测"这个关键信息丢掉。
	case errors.Is(err, site.ErrInvalidName), errors.Is(err, site.ErrReservedName):
		// 站点名非法是安全信号：日志用 Warn，便于运维直接看到有人在探测。
		s.logger.Warn("站点名校验拒绝",
			"action", action, "name", name, "reason", errText)
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "站点名会同时作为配置文件名与接口路径，只允许字母、数字、点、" +
				"下划线与短横线，且必须以字母或数字开头结尾（不允许 / \\ .. 空格 ; { } $ ` ' \" # 等）。",
			"name": name,
		})

	case errors.Is(err, site.ErrInvalidDomain):
		s.logger.Warn("站点域名校验拒绝",
			"action", action, "name", name, "reason", errText)
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "域名只允许字母、数字、点、短横线与下划线，通配需写成 *.example.com，" +
				"匹配任意主机名请填 \"_\"。分号、花括号、引号、换行等字符会导致 nginx 配置注入，一律拒绝。",
			"name": name,
		})

	case errors.Is(err, site.ErrInvalidRoot):
		s.logger.Warn("站点根目录校验拒绝",
			"action", action, "name", name, "reason", errText)
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "静态站根目录必须是存在的绝对路径，且落在启动参数 -file-root " +
				"允许的范围内；路径中不能含空格或 nginx 元字符。",
			"name": name,
		})

	case errors.Is(err, site.ErrInvalidUpstream):
		s.logger.Warn("反代目标校验拒绝",
			"action", action, "name", name, "reason", errText)
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "后端地址形如 http://127.0.0.1:3000，只支持 http/https，" +
				"不接受 unix socket、查询串与内嵌凭据。",
			"name": name,
		})

	case errors.Is(err, site.ErrInvalidType):
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint":  "站点类型只支持 static（静态站）与 proxy（反向代理）。",
			"name":  name,
		})

	// ---------- nginx 校验 / 重载失败（已回滚） ----------
	//
	// 这两类必须**先于**通用的 ErrNotFound 等判定，且状态码要能
	// 让前端一眼看出"这不是用户输入错了，是 nginx 拒绝了配置"。
	case errors.Is(err, site.ErrNginxTestFailed), errors.Is(err, site.ErrRolledBack):
		s.logger.Error("站点操作失败并已回滚",
			"action", action, "name", name, "err", err)
		return write(http.StatusUnprocessableEntity, map[string]any{
			"error": errText,
			"hint": "nginx 拒绝了这个配置，面板已**自动回滚**到修改前的状态，" +
				"并通过 nginx -t 复验，现有站点未受影响。请根据上方 nginx 报错调整后重试。",
			"name":        name,
			"rolled_back": true,
		})

	case errors.Is(err, site.ErrReloadFailed):
		s.logger.Error("nginx 重载失败并已回滚",
			"action", action, "name", name, "err", err)
		return write(http.StatusBadGateway, map[string]any{
			"error": errText,
			"hint": "nginx 无法重新加载配置，面板已**自动回滚**。请检查 nginx 进程状态" +
				"（systemctl status nginx）与错误日志后重试。",
			"name":        name,
			"rolled_back": true,
		})

	// ---------- 状态类 ----------
	case errors.Is(err, site.ErrExists):
		return write(http.StatusConflict, map[string]any{
			"error": errText,
			"hint":  "已存在同名站点。请换一个站点名，或在列表中编辑已有站点。",
			"name":  name,
		})

	case errors.Is(err, site.ErrExternal):
		return write(http.StatusConflict, map[string]any{
			"error": errText,
			"hint": "该配置文件不是由面板创建（缺少生成标记），面板不会修改它，" +
				"以免覆盖你手写的配置。如需用面板管理，请先备份并删除该文件后重新创建。",
			"name": name,
		})

	case errors.Is(err, site.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return write(http.StatusNotFound, map[string]any{
			"error": "站点不存在：" + name,
			"hint":  "请刷新列表确认该站点是否已被删除。",
			"name":  name,
		})

	case errors.Is(err, site.ErrAdapterUnavailable), errors.Is(err, site.ErrNginxUnavailable):
		return write(http.StatusServiceUnavailable, map[string]any{
			"error": errText,
			"hint": "站点管理需要 nginx 环境；若 nginx 装在非标准位置，" +
				"可用启动参数 -nginx-prefix 指定其 prefix 目录。面板其它功能不受影响。",
		})

	case errors.Is(err, site.ErrTimeout):
		return write(http.StatusGatewayTimeout, map[string]any{
			"error":  errText,
			"hint":   "nginx 未在超时时间内返回，请稍后重试并检查 nginx 状态。",
			"name":   name,
			"action": action,
		})

	case errors.Is(err, fs.ErrPermission):
		return write(http.StatusForbidden, map[string]any{
			"error": "权限不足：" + errText,
			"hint": "写入 nginx 配置目录需要 root 权限。请以 root 身份运行 lipanel" +
				"（例如 sudo ./lipanel ...）。",
			"name": name,
		})

	default:
		s.logger.Error("站点操作失败", "action", action, "name", name, "err", err)
		return write(http.StatusInternalServerError, map[string]any{
			"error":  errText,
			"name":   name,
			"action": action,
		})
	}
}
