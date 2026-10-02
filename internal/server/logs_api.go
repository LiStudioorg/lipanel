package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/logs"
)

// ============================================================================
// 日志查看接口（阶段五 5.4.1，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录 + log.read）：
//
//	GET /api/logs/sources   日志源列表（含可用性）
//	GET /api/logs/query     查询日志（source/lines/filter/level）
//	GET /api/logs/audit     操作审计
//	GET /api/logs           状态（可用性摘要 + 审计统计）
//
// ⚠️ 注册顺序：/api/logs/sources、/api/logs/audit 这些固定段路由
// 必须先于任何通配注册。本模块没有 {source} 通配（日志源是白名单，
// 不接受任意字符串），因此不存在通配坑，但仍按纪律集中注册。
//
// #################### 本模块接口最要紧的一件事 ####################
//
// **查询绝不接受任意路径。** 日志源必须是白名单内的 ID（system /
// nginx-access / nginx-error）；文件路径由启动时的源探测决定，
// 运行时不接受任何 path 类参数。否则 ?path= 就是一个
// 「登录即可读这台机器任意文件」的入口（与 5.2 cron 的日志接口同纪律）。

// (s *Server) registerLogRoutes 在 api.go 的 registerAPIRoutes 里调用。
func (s *Server) registerLogRoutes(mux *http.ServeMux) {
	if s.logsMgr == nil {
		mux.Handle("/api/logs/", s.auth.RequireAuth(http.HandlerFunc(s.handleLogsUnavailable)))
		mux.Handle("/api/logs", s.auth.RequireAuth(http.HandlerFunc(s.handleLogsUnavailable)))
		return
	}

	// 固定段路由先于一切注册。
	mux.Handle("GET /api/logs/sources", s.auth.RequireAuth(http.HandlerFunc(s.handleLogSources)))
	mux.Handle("GET /api/logs/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleLogAudit)))
	mux.Handle("GET /api/logs", s.auth.RequireAuth(http.HandlerFunc(s.handleLogStatus)))
	mux.Handle("GET /api/logs/query", s.auth.RequireAuth(http.HandlerFunc(s.handleLogQuery)))
}

func (s *Server) handleLogsUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]any{
		"error": "日志查看模块未启用",
		"hint":  "日志管理器未注入，无法提供服务。",
	})
}

// ---- 审计脚手架 ----

type logAudit struct {
	srv     *Server
	user    string
	ip      string
	started time.Time
}

func (s *Server) beginLogAudit(r *http.Request) *logAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &logAudit{srv: s, user: user, ip: clientIPOf(r), started: time.Now()}
}

func (a *logAudit) record(ev logs.AuditEvent) {
	ev.User = a.user
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	a.srv.logsMgr.Auditor().Record(ev)
}

// ---- 权限判定 ----

func (s *Server) requireLogPermission(w http.ResponseWriter, a *logAudit, action logs.Action) bool {
	decision := logs.CheckLogPermission(logs.AdminGrantee(a.user), action)
	if decision.Allowed {
		return true
	}
	a.record(logs.AuditEvent{
		Action:   string(action),
		Outcome:  logs.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("日志查看被权限校验拒绝",
		"user", a.user, "action", action, "required", decision.Required)
	writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
		"error":    decision.Reason,
		"hint":     decision.Hint,
		"required": decision.Required,
		"granted":  decision.Granted,
	})
	return false
}

// ---- Handlers ----

func (s *Server) handleLogStatus(w http.ResponseWriter, r *http.Request) {
	a := s.beginLogAudit(r)
	if !s.requireLogPermission(w, a, logs.ActionList) {
		return
	}
	sources := s.logsMgr.Sources()
	available := 0
	for _, src := range sources {
		if src.Available {
			available++
		}
	}
	res := map[string]any{
		"available":         available > 0,
		"source_count":      len(sources),
		"available_sources": available,
		"query_timeout":     float64(s.logsMgr.Options().QueryTimeout.Seconds()),
		"nginx_logs_dir":    s.logsMgr.Options().NginxLogsDir,
		"audit":             s.logsMgr.Auditor().Stats(),
	}
	writeJSON(w, s.logger, http.StatusOK, res)
}

func (s *Server) handleLogSources(w http.ResponseWriter, r *http.Request) {
	a := s.beginLogAudit(r)
	if !s.requireLogPermission(w, a, logs.ActionList) {
		return
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"sources": s.logsMgr.Sources(),
	})
}

func (s *Server) handleLogAudit(w http.ResponseWriter, r *http.Request) {
	a := s.beginLogAudit(r)
	if !s.requireLogPermission(w, a, logs.ActionList) {
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	outcome := r.URL.Query().Get("outcome")
	events := s.logsMgr.Auditor().List(logs.AuditQuery{Limit: limit, Outcome: outcome})

	a.record(logs.AuditEvent{Action: "audit", Outcome: logs.AuditAllowed,
		Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"audit": events})
}

func (s *Server) handleLogQuery(w http.ResponseWriter, r *http.Request) {
	a := s.beginLogAudit(r)
	if !s.requireLogPermission(w, a, logs.ActionQuery) {
		return
	}

	// 解析并校验参数（顺序：白名单 source + 参数合法性 → 查询 → 审计）。
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		s.logQueryError(w, a, http.StatusBadRequest,
			"缺少日志源参数", "请指定 ?source=system 或某个可用日志源。")
		return
	}
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	filter := r.URL.Query().Get("filter")
	level := r.URL.Query().Get("level")

	if err := validateLogQuery(source, lines, level); err != nil {
		s.logQueryError(w, a, http.StatusBadRequest, err.Error(),
			"确认 source 是列表中的 ID，lines 在 [1,2000] 内，level 为 error/warn/info/debug。")
		return
	}

	res, err := s.logsMgr.Query(r.Context(), logs.Query{
		SourceID: source,
		Lines:    lines,
		Filter:   filter,
		Level:    level,
	})
	if err != nil {
		switch {
		case errors.Is(err, logs.ErrSourceNotFound):
			s.logQueryError(w, a, http.StatusBadRequest,
				"日志源不存在", "请从 /api/logs/sources 中选择一个 ID。")
		case errors.Is(err, logs.ErrSourceUnavailable):
			s.logQueryError(w, a, http.StatusServiceUnavailable,
				"日志源当前不可用", "请查看 sources 接口的 unavailable_reason。")
		default:
			s.logQueryError(w, a, http.StatusBadGateway,
				"读取日志失败: "+err.Error(), "后端读取日志时出错。")
		}
		return
	}

	// 成功：记录审计（含返回行数，便于观测频繁查询）。
	a.record(logs.AuditEvent{
		Action:   "query",
		SourceID: source,
		Query:    summarizeQuery(lines, filter, level),
		Outcome:  logs.AuditAllowed,
		Status:   http.StatusOK,
		Returned: len(res.Entries),
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// validateLogQuery 校验查询参数（不访问文件系统，纯判定）。
func validateLogQuery(source string, lines int, level string) error {
	if lines < 0 || lines > logs.MaxLines {
		return errors.New("lines 超出范围 [0," + strconv.Itoa(logs.MaxLines) + "]")
	}
	if level != "" && !logs.ValidLevel(level) {
		return errors.New("不支持的 level: " + level)
	}
	return nil
}

// summarizeQuery 生成查询参数的脱敏摘要，用于审计（不含凭据类敏感内容）。
func summarizeQuery(lines int, filter, level string) string {
	b := strings.Builder{}
	if lines > 0 {
		b.WriteString("lines=" + strconv.Itoa(lines))
	}
	if filter != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString("filter=\"" + filter + "\"")
	}
	if level != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString("level=" + level)
	}
	return b.String()
}

func (s *Server) logQueryError(w http.ResponseWriter, a *logAudit, status int, msg, hint string) {
	a.record(logs.AuditEvent{
		Action:  "query",
		Outcome: logs.AuditDenied,
		Status:  status,
		Reason:  msg,
	})
	writeJSON(w, s.logger, status, map[string]any{"error": msg, "hint": hint})
}
