package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/terminal"
)

// ============================================================================
// Web 终端接口（阶段五 5.1，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/terminal/status            平台能力 + 会话统计 + 审计状态
//	GET    /api/terminal/sessions          当前会话列表
//	GET    /api/terminal/audit             操作审计
//	POST   /api/terminal/sessions          创建会话
//	DELETE /api/terminal/sessions          关闭会话（必须 confirm）
//	GET    /api/terminal/ws                建立 WebSocket 终端连接
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/terminal/status"、"/api/terminal/sessions"、".../audit" 这些
// **固定段**路由必须先于任何通配注册。这是 4.1~4.6 连续踩过六次的
// 同一个坑（见 开发计划.md「已知坑位」），因此这里从一开始就按纪律来，
// 并有测试锁死。
//
// 与其它核心模块一致：
//   - 全部接口挂 RequireAuth（按路由显式挂载）；
//   - 写操作顺序固定：**校验 → 二次确认 → 权限 → 执行 → 审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
//
// #################### 本模块接口的两个特有设计 ####################
//
// ① **WebSocket 端点必须额外校验 Origin**
//
//	WebSocket 不受同源策略约束：浏览器允许任意源的 JS 发起 WS 连接，
//	并且**自动携带目标域的 Cookie**。这就是 CSWSH
//	（Cross-Site WebSocket Hijacking）——用户登录了面板，
//	又访问了一个恶意页面，那个页面用 JS 连上
//	/api/terminal/ws，请求带着用户的会话 Cookie，RequireAuth 通过，
//	于是恶意页面拿到一个**全权限 root shell**。
//
//	普通 XHR 不会被这样利用（同源策略拦住读取响应），
//	但 WebSocket 没有这道防线。因此 Origin 校验不是可选项。
//
// ② **不支持的平台返回 501（Not Implemented），而不是 500**
//
//	Windows 没有 POSIX 伪终端，终端功能在该平台必然不可用。
//	501 的语义正是"服务器不支持该功能所必需的能力"，
//	让前端能据此渲染一个**说明性提示**而不是一个红色错误框
//	（详见 5.1 的优雅降级）。
func (s *Server) registerTerminalRoutes(mux *http.ServeMux) {
	if s.terminalMgr == nil {
		// 未注入管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/terminal/", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalUnavailable)))
		mux.Handle("/api/terminal", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalUnavailable)))
		return
	}

	mux.Handle("GET /api/terminal/status", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalStatus)))

	// ⚠️ 固定段路由必须先于通配注册（见上方说明）。
	mux.Handle("GET /api/terminal/sessions", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalListSessions)))
	mux.Handle("GET /api/terminal/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalAudit)))
	// WebSocket 升级端点：**同样挂 RequireAuth**。
	//
	// ########## 顺序至关重要：鉴权必须在 Upgrade 之前 ##########
	//
	// 一旦写出 101 Switching Protocols，HTTP 语义就结束了——
	// 之后再想返回 401 已经不可能（浏览器已经把它当 WS 连接）。
	// 因此 RequireAuth 必须包在最外层，未登录的请求
	// **在握手之前**就被 401 挡掉，绝不建立未认证的 WS 连接。
	mux.Handle("GET /api/terminal/ws", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalWS)))

	// 写操作。
	mux.Handle("POST /api/terminal/sessions", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalCreateSession)))
	mux.Handle("DELETE /api/terminal/sessions", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalCloseSession)))

	// 前缀兜底：未注册的 /api/terminal/* 返回 JSON 404 + 可用接口清单，
	// 而不是落到前端 HTML 兜底（那会让前端 JSON.parse 失败，
	// 报出一个与真实原因无关的解析错误）。
	mux.Handle("/api/terminal/", s.auth.RequireAuth(http.HandlerFunc(s.handleTerminalNotFound)))
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

// terminalAudit 承载一次终端操作审计所需的上下文。
//
// 与 4.1~4.6 的 *Audit 辅助结构同构：把"每个 handler 都要写"
// 的字段（用户、客户端 IP、耗时）集中起来，handler 只填自己特有的部分。
type terminalAudit struct {
	srv    *Server
	r      *http.Request
	user   string
	action string
	// session 是会话 ID（创建/连接/关闭时必填）。
	session string
	// owner 是会话创建者（跨用户 attach 被拒时用于留痕）。
	owner string
	// shell / pid / cols / rows 描述被操作的终端。
	shell string
	pid   int
	cols  int
	rows  int
	// reason 是会话结束原因（稳定常量，可聚合）。
	reason string
	// detail 是自由文本的错误/说明（与 reason 分开，避免污染聚合）。
	detail string
	start  time.Time
}

// newTerminalAudit 构造审计上下文。
func (s *Server) newTerminalAudit(r *http.Request, action string) *terminalAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &terminalAudit{
		srv:    s,
		r:      r,
		user:   user,
		action: action,
		start:  time.Now(),
	}
}

// record 写入一条审计记录。
func (a *terminalAudit) record(ev terminal.AuditEvent) {
	if a == nil || a.srv == nil || a.srv.terminalMgr == nil {
		return
	}
	auditor := a.srv.terminalMgr.Auditor()
	if auditor == nil {
		return
	}

	if ev.User == "" {
		ev.User = a.user
	}
	if ev.Action == "" {
		ev.Action = a.action
	}
	if ev.Session == "" {
		ev.Session = a.session
	}
	if ev.Owner == "" {
		ev.Owner = a.owner
	}
	if ev.Shell == "" {
		ev.Shell = a.shell
	}
	if ev.PID == 0 {
		ev.PID = a.pid
	}
	if ev.Cols == 0 {
		ev.Cols = a.cols
	}
	if ev.Rows == 0 {
		ev.Rows = a.rows
	}
	if ev.Reason == "" {
		ev.Reason = a.reason
	}
	if ev.Detail == "" {
		ev.Detail = a.detail
	}
	if ev.ClientIP == "" {
		ev.ClientIP = clientIP(a.r)
	}
	if ev.Required == "" {
		ev.Required = terminal.RequiredPermission(ev.Action)
	}
	ev.DurationMS = time.Since(a.start).Milliseconds()
	auditor.Record(ev)
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireTerminalPermission 判定当前用户能否执行某终端动作。
//
// 顺序与其它核心模块一致且不可调换：**先判权限，再创建进程**。
// 被拒绝的请求绝不能产生任何副作用——对本模块而言，
// 副作用就是"服务器上多了一个全权限 shell 进程"。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireTerminalPermission(w http.ResponseWriter, a *terminalAudit) bool {
	grantee := terminal.AdminGrantee(a.user)
	decision := terminal.CheckTerminalPermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(terminal.AuditEvent{
		Outcome:  terminal.AuditDenied,
		Status:   http.StatusForbidden,
		Detail:   decision.Reason,
		Required: decision.Required,
	})
	// 响应头与其它模块的权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("终端操作被权限校验拒绝",
		"user", a.user, "action", a.action, "required", decision.Required)
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

// terminalErrorStatus 把 terminal 包的语义错误映射为 HTTP 状态码。
//
// ########## 状态码的语义必须准确 ##########
//
//	400 输入非法（cols/rows 越界）—— 用户的输入问题
//	403 权限不足                   —— 未被授予 terminal.write
//	404 会话不存在                 —— 已结束，或 ID 写错
//	409 会话被占用 / 数达上限      —— **不是输入问题，而是当前状态不允许**
//	428 缺少二次确认               —— 请求合法但需要显式确认
//	501 平台不支持                 —— Windows 等无 PTY 平台
//	503 管理器不可用 / 已关停      —— 面板正在关闭
//
// ########## 为什么 409 与 428 要分开 ##########
//
// 两者都让前端"重试前先做点什么"，但要做的事完全不同：
//
//	409（会话被占用）—— 重试无用，必须**换一个会话**或先断开旧的；
//	409（数达上限）  —— 重试无用，必须**先关掉不用的终端**；
//	428（缺确认）    —— **补上 confirm 后重试就会成功**。
//
// 若把它们混成一个码，前端只能给出一句"操作失败"，
// 用户会反复点击同一个按钮。
func terminalErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, terminal.ErrUnsupported):
		return http.StatusNotImplemented, "当前平台不支持 Web 终端"
	case errors.Is(err, terminal.ErrConfirmRequired):
		return http.StatusPreconditionRequired, "缺少二次确认"
	case errors.Is(err, terminal.ErrSessionBusy):
		return http.StatusConflict, "会话已被占用"
	case errors.Is(err, terminal.ErrTooManySessions):
		return http.StatusConflict, "会话数已达上限"
	case errors.Is(err, terminal.ErrSessionNotFound):
		return http.StatusNotFound, "会话不存在"
	case errors.Is(err, terminal.ErrSessionClosed):
		return http.StatusGone, "会话已结束"
	case errors.Is(err, terminal.ErrManagerClosed):
		return http.StatusServiceUnavailable, "终端服务正在关闭"
	case errors.Is(err, terminal.ErrPermission):
		return http.StatusForbidden, "权限不足"
	case errors.Is(err, terminal.ErrUnavailable):
		return http.StatusServiceUnavailable, "终端不可用"
	default:
		return http.StatusInternalServerError, "内部错误"
	}
}

// writeTerminalError 统一写出终端操作错误。
//
// 对 ErrUnsupported 额外带 supported=false 与 hint：
// 前端据此渲染 n-alert 说明，而不是把一句技术错误直接甩给用户。
func (s *Server) writeTerminalError(w http.ResponseWriter, a *terminalAudit, err error) {
	status, kind := terminalErrorStatus(err)

	if status == http.StatusPreconditionRequired {
		// 让客户端知道"补上 confirm 再重试"。
		w.Header().Set("X-Lipanel-Confirm-Required", "true")
	}

	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditFailed,
		Status:  status,
		Detail:  err.Error(),
	})

	payload := map[string]any{
		"error": err.Error(),
		"kind":  kind,
	}
	// 平台不支持是"环境限制"而非"操作失败"，需要额外字段让前端
	// 渲染说明性提示（而不是红色报错）。
	if errors.Is(err, terminal.ErrUnsupported) {
		cap := terminal.CurrentCapability()
		payload["supported"] = false
		payload["os"] = cap.OS
		payload["hint"] = cap.Hint
	}

	s.logger.Warn("终端操作失败",
		"user", a.user, "action", a.action, "session", a.session,
		"status", status, "err", err)
	writeJSON(w, s.logger, status, payload)
}

// ---------------------------------------------------------------------------
// Handler: 状态
// ---------------------------------------------------------------------------

// handleTerminalStatus 返回平台能力、会话统计与审计状态。
//
// ########## 这个接口是前端"优雅降级"的唯一入口 ##########
//
// 前端在渲染终端页之前先调它：supported=false 时直接展示
// n-alert 说明并隐藏"新建终端"按钮，**绝不去尝试建立 WebSocket**
// （那会让用户看到一个连接失败的红框，而真正的原因
// ——平台不支持——反而被埋起来）。
func (s *Server) handleTerminalStatus(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionStatus)
	if !s.requireTerminalPermission(w, a) {
		return
	}

	cap := s.terminalMgr.Capability()
	stats := s.terminalMgr.Auditor().Stats()

	// 会话统计。
	sessions := s.terminalMgr.List()
	running := 0
	for _, s := range sessions {
		if s.Status == terminal.StatusRunning {
			running++
		}
	}

	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		// supported 放在最前面：它是前端分支的依据。
		"supported":    cap.Supported,
		"os":           cap.OS,
		"reason":       cap.Reason,
		"hint":         cap.Hint,
		"shell":        s.terminalMgr.Shell(),
		"idle_timeout": s.terminalMgr.IdleTimeout().String(),
		"sessions": map[string]any{
			"total":   len(sessions),
			"running": running,
			"max":     s.terminalMgr.MaxSessions(),
		},
		"audit": map[string]any{
			"total":    stats.Total,
			"retained": stats.Retained,
			"capacity": stats.Capacity,
			"denied":   stats.Denied,
			"failed":   stats.Failed,
		},
	})
}

// handleTerminalListSessions 返回当前会话列表。
func (s *Server) handleTerminalListSessions(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionListSessions)
	if !s.requireTerminalPermission(w, a) {
		return
	}

	sessions := s.terminalMgr.List()

	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditAllowed,
		Status:  http.StatusOK,
	})

	// 列表始终是数组（空时是 []），而不是 null——
	// 前端可以无条件 .map，不需要先判空。
	if sessions == nil {
		sessions = []terminal.SessionInfo{}
	}
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"supported": s.terminalMgr.Supported(),
		"sessions":  sessions,
		"total":     len(sessions),
	})
}

// handleTerminalAudit 返回终端操作审计。
func (s *Server) handleTerminalAudit(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionAudit)
	if !s.requireTerminalPermission(w, a) {
		return
	}

	q := r.URL.Query()
	limit := parseTerminalInt(q.Get("limit"), terminal.DefaultAuditQueryLimit)

	auditor := s.terminalMgr.Auditor()
	events := auditor.Query(terminal.AuditFilter{
		User:             strings.TrimSpace(q.Get("user")),
		Action:           strings.TrimSpace(q.Get("action")),
		Outcome:          strings.TrimSpace(q.Get("outcome")),
		Session:          strings.TrimSpace(q.Get("session")),
		Reason:           strings.TrimSpace(q.Get("reason")),
		OnlySystemChange: q.Get("only_system_change") == "true",
		Limit:            limit,
	})

	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditAllowed,
		Status:  http.StatusOK,
	})

	stats := auditor.Stats()
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": events,
		"total":  len(events),
		"stats": map[string]any{
			"total":        stats.Total,
			"retained":     stats.Retained,
			"capacity":     stats.Capacity,
			"denied":       stats.Denied,
			"failed":       stats.Failed,
			"created":      stats.Created,
			"closed":       stats.Closed,
			"idle_closed":  stats.IdleClosed,
			"exit_closed":  stats.ExitClosed,
			"write_errors": stats.WriteErrors,
			"persist_path": stats.PersistPath,
		},
	})
}

// ---------------------------------------------------------------------------
// Handler: 创建 / 关闭会话
// ---------------------------------------------------------------------------

// handleTerminalCreateSession 创建一个终端会话。
//
// 请求体（都可选）：
//
//	{"cols": 80, "rows": 24, "confirm": true}
//
// ########## 为什么这个接口没有强制 confirm ##########
//
// 与防火墙的删除不同，创建一个终端（在已有权限的前提下）
// 不破坏任何东西——它只是打开一个 shell。真正危险的是
// **attach 之后敲的命令**，而那无法用一次确认来兜住。
//
// 因此这里不设 428，而是靠三层防线：
//  1. terminal.write 权限（能登录 ≠ 能开终端）；
//  2. 会话数上限（防资源耗尽）；
//  3. 全部创建与连接行为留痕（谁在什么时候拿了一个 shell）。
//
// 前端仍会弹一次二次确认（写明"这是一个全权限 shell"），
// 但那是**体验层面**的提示，不是安全边界——安全边界在上面三层。
func (s *Server) handleTerminalCreateSession(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionCreate)
	if !s.requireTerminalPermission(w, a) {
		return
	}

	var req struct {
		Cols int `json:"cols"`
		Rows int `json:"rows"`
	}
	if r.Body != nil {
		// 空 body 是合法的（用默认尺寸）。
		// 解码失败则说明前端发的东西不是 JSON，需要明确报错而不是静默用默认值。
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil &&
			!errors.Is(err, http.ErrBodyReadAfterClose) && err.Error() != "EOF" {
			a.detail = "请求体不是合法 JSON: " + err.Error()
			s.writeTerminalError(w, a, fmt.Errorf("%w: %v", terminal.ErrInvalidSize, err))
			return
		}
	}

	sess, err := s.terminalMgr.Create(a.user, req.Cols, req.Rows)
	if err != nil {
		s.writeTerminalError(w, a, err)
		return
	}

	info := sess.Snapshot()
	a.session = info.ID
	a.shell = s.terminalMgr.Shell()
	a.pid = info.PID
	a.cols = info.Cols
	a.rows = info.Rows

	// 创建成功是**本面板最高危的事件之一**：服务器上从此多了一个
	// 以面板身份运行的 shell。因此这条审计必须记全（ID/pid/shell/尺寸/IP）。
	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditAllowed,
		Status:  http.StatusCreated,
	})

	writeJSON(w, s.logger, http.StatusCreated, map[string]any{
		"session": info,
		"shell":   s.terminalMgr.Shell(),
		// ws_path 由后端给出，避免前端拼 URL（拼错只会得到一个
		// 难懂的 404，而路径规则将来可能变）。
		"ws_path": "/api/terminal/ws?id=" + info.ID,
	})
}

// handleTerminalCloseSession 关闭一个终端会话。
//
// 必须带 ?confirm=true：这是**用户主动终止自己 shell** 的破坏性动作，
// 会话里可能正跑着长任务（apt install、rsync）。
// 与服务端强制二次确认的纪律一致（见 4.6），
// 不依赖前端自觉。
func (s *Server) handleTerminalCloseSession(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionClose)

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		a.detail = "缺少 id 参数"
		s.writeTerminalError(w, a, fmt.Errorf("%w: 缺少 id 参数", terminal.ErrSessionNotFound))
		return
	}
	a.session = id

	// 先取会话，用于 attach 授权判定与审计留痕。
	sess, ok := s.terminalMgr.Get(id)
	if !ok {
		s.writeTerminalError(w, a, terminal.ErrSessionNotFound)
		return
	}
	info := sess.Snapshot()
	a.owner = info.Owner
	a.shell = s.terminalMgr.Shell()
	a.pid = info.PID
	a.reason = terminal.CloseReasonUser

	if !s.requireTerminalPermission(w, a) {
		return
	}

	// 授权判定：只有会话所有者能关闭它。
	if err := terminal.CanAttach(terminal.AdminGrantee(a.user), info.Owner); err != nil {
		s.writeTerminalError(w, a, fmt.Errorf("%w: %v", terminal.ErrPermission, err))
		return
	}

	// 服务端强制二次确认（428）。
	if r.URL.Query().Get("confirm") != "true" {
		s.writeTerminalError(w, a, terminal.ErrConfirmRequired)
		return
	}

	if err := s.terminalMgr.CloseSession(id, terminal.CloseReasonUser); err != nil {
		s.writeTerminalError(w, a, err)
		return
	}

	// 关闭后补一次快照：拿到真实的存活时长与空闲秒数。
	after := sess.Snapshot()
	a.record(terminal.AuditEvent{
		Outcome:         terminal.AuditAllowed,
		Status:          http.StatusOK,
		IdleSeconds:     after.IdleSeconds,
		DurationSeconds: durationSeconds(info.CreatedAt, after.Closed),
	})

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"closed":  true,
		"session": after,
	})
}

// ---------------------------------------------------------------------------
// Handler: WebSocket
// ---------------------------------------------------------------------------

// handleTerminalWS 把请求升级为 WebSocket 并桥接到 PTY。
//
// ########## 执行顺序是本模块最重要的安全约束 ##########
//
// 顺序固定为：
//
//	① 权限判定（terminal.write）
//	② Origin 校验（防 CSWSH）
//	③ 会话归属判定（只有 owner 能 attach）
//	④ 升级（写 101）
//	⑤ Attach（服务端保证只 attach 一次）
//	⑥ 读循环
//
// ①②③ 必须在 ④ **之前**完成。一旦写出 101，
// HTTP 语义就结束了，之后再想返回 401/403/404 已经不可能
// ——浏览器已经把它当 WS 连接，只能通过 close 帧表达失败，
// 而前端拿到的是一个"连上了但立刻断开"的神秘现象。
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	a := s.newTerminalAudit(r, terminal.ActionConnect)

	// ① 权限。
	if !s.requireTerminalPermission(w, a) {
		return
	}

	// ② Origin 校验（防 CSWSH）。
	if err := s.checkTerminalOrigin(r); err != nil {
		a.detail = err.Error()
		s.recordTerminalWSDenied(a, http.StatusForbidden, err)
		writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
			"error": err.Error(),
			"hint": "WebSocket 不受同源策略保护，浏览器会自动携带 Cookie，" +
				"因此必须校验 Origin。若你是通过反向代理访问，" +
				"请确认代理正确转发了 Host 与 Origin 头。",
		})
		return
	}

	// 会话必须存在。
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		a.detail = "缺少 id 参数"
		s.recordTerminalWSDenied(a, http.StatusBadRequest,
			fmt.Errorf("%w: 缺少 id 参数", terminal.ErrSessionNotFound))
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "缺少 id 参数",
		})
		return
	}
	a.session = id

	sess, ok := s.terminalMgr.Get(id)
	if !ok {
		s.recordTerminalWSDenied(a, http.StatusNotFound, terminal.ErrSessionNotFound)
		writeJSON(w, s.logger, http.StatusNotFound, map[string]string{
			"error": terminal.ErrSessionNotFound.Error(),
		})
		return
	}

	info := sess.Snapshot()
	a.owner = info.Owner
	a.shell = s.terminalMgr.Shell()
	a.pid = info.PID
	a.cols = info.Cols
	a.rows = info.Rows

	// ③ 会话归属：只有创建者能 attach。
	if err := terminal.CanAttach(terminal.AdminGrantee(a.user), info.Owner); err != nil {
		a.detail = err.Error()
		s.recordTerminalWSDenied(a, http.StatusForbidden,
			fmt.Errorf("%w: %v", terminal.ErrPermission, err))
		writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
			"error": err.Error(),
			"hint": "终端会话不能被共享：同一个 shell 上的两个输入源" +
				"会交错成无法理解的命令，且审计无法归因。",
		})
		return
	}

	// ④ 升级。
	conn, err := terminal.Upgrade(w, r)
	if err != nil {
		// 升级失败时响应头**尚未**写出（Upgrade 失败会在此之前返回），
		// 因此这里仍可以正常返回 HTTP 错误。
		a.detail = err.Error()
		s.recordTerminalWSDenied(a, http.StatusBadRequest, err)
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}
	defer conn.Close()

	// ⑤ Attach。服务端在此强制"一个会话只能被连接一次"。
	if err := sess.Attach(conn); err != nil {
		status, kind := terminalErrorStatus(err)
		_ = conn.WriteClose(uint16(closeCodeForStatus(status)), reasonForStatus(status))
		s.recordTerminalWSDenied(a, status, err)
		// 已经在 WS 上了，无法再返回 HTTP 状态码；错误通过 close 帧表达。
		s.logger.Warn("终端 attach 失败",
			"user", a.user, "session", id, "kind", kind, "err", err)
		return
	}

	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditAllowed,
		Status:  http.StatusSwitchingProtocols,
	})

	// ⑥ 读循环：本 goroutine 独占读方向（见 ws.go 的并发约定）。
	s.runTerminalReadLoop(a, sess, conn)

	// 循环结束 = 客户端断开或会话结束。
	reason := terminal.CloseReasonClientGone
	if sess.Snapshot().Closed {
		reason = sess.Snapshot().CloseReason
	}
	after := sess.Snapshot()
	a2 := s.newTerminalAudit(r, terminal.ActionDisconnect)
	a2.session = id
	a2.owner = info.Owner
	a2.shell = a.shell
	a2.pid = info.PID
	a2.reason = reason
	a2.record(terminal.AuditEvent{
		Outcome:         terminal.AuditAllowed,
		Status:          http.StatusOK,
		IdleSeconds:     after.IdleSeconds,
		DurationSeconds: durationSeconds(info.CreatedAt, true),
	})
}

// runTerminalReadLoop 是 WS → PTY 的读循环。
//
// 每次收到消息就交给会话处理（输入写入 PTY、resize 调用 Setsize、
// ping 刷新空闲计时器）。协议错误只回一条提示而不关闭连接：
// 单条坏消息不足以断定客户端有问题，而关闭连接会让用户
// 丢失整个会话。
func (s *Server) runTerminalReadLoop(a *terminalAudit, sess *terminal.Session, conn *terminal.Conn) {
	for {
		opcode, payload, err := conn.ReadMessage()
		if err != nil {
			// 客户端断开是最常见的结束方式（关标签页/网络中断），
			// 记为 debug 而不是 warn，避免刷屏。
			s.logger.Debug("终端连接读取结束", "session", sess.ID(), "err", err)
			return
		}

		// 客户端主动关闭。
		if opcode == terminal.OpClose {
			return
		}

		if err := sess.HandleMessage(payload); err != nil {
			// 协议错误要告诉用户，否则他敲了键却没反应会以为卡死。
			s.logger.Debug("终端消息处理失败", "session", sess.ID(), "err", err)
			_ = conn.WriteText([]byte("\r\n\x1b[31m[面板] " + err.Error() + "\x1b[0m\r\n"))
		}
	}
}

// checkTerminalOrigin 校验 WebSocket 请求的 Origin。
//
// ########## 为什么这个检查不能省 ##########
//
// WebSocket **不受同源策略约束**：任意源的 JS 都能发起 WS 连接，
// 且浏览器会**自动携带目标域的 Cookie**。若只靠 RequireAuth，
// 那么"用户登录了面板 + 访问了一个恶意页面"就等于
// "恶意页面拿到了一个全权限 root shell"（CSWSH）。
//
// 校验规则：
//   - Origin 为空 → 放行（非浏览器客户端，如 websocat/curl，
//     它们不携带 Cookie，因此不存在被第三方站点利用的问题）；
//   - Origin 与请求 Host 同源 → 放行；
//   - 其余 → 拒绝。
//
// ########## 为什么用 Host 而不是硬编码地址 ##########
//
// 面板可能部署在任意域名/端口，也可能在 nginx 反代之后
// （此时 Host 是域名，而面板监听 127.0.0.1）。
// 用 r.Host 做比较天然适配这两种情况；硬编码一个地址
// 会让反代部署全部连不上。
func (s *Server) checkTerminalOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}

	// Origin 形如 "scheme://host[:port]"。取出 host 部分比较。
	host := origin
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// 去掉可能存在的路径部分（某些客户端会带）。
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}

	if strings.EqualFold(host, r.Host) {
		return nil
	}

	// 显式允许的来源（部署在独立域名时的逃生舱）。
	for _, allowed := range s.terminalMgr.AllowedOrigins() {
		if strings.EqualFold(strings.TrimSpace(allowed), origin) {
			return nil
		}
	}

	return fmt.Errorf("terminal: Origin %q 与请求 Host %q 不同源，已拒绝", origin, r.Host)
}

// recordTerminalWSDenied 记录一次被拒绝的 WS 连接尝试。
func (s *Server) recordTerminalWSDenied(a *terminalAudit, status int, err error) {
	a.record(terminal.AuditEvent{
		Outcome: terminal.AuditDenied,
		Status:  status,
		Detail:  err.Error(),
	})
	s.logger.Warn("终端连接被拒绝",
		"user", a.user, "session", a.session, "status", status, "err", err)
}

// closeCodeForStatus 把 HTTP 语义映射为 WebSocket 关闭码。
//
// WebSocket 有自己的一套关闭码（RFC 6455 §7.4.1），
// 不能直接把 HTTP 状态码塞进去（1000~4999 才是合法区间）。
func closeCodeForStatus(status int) int {
	switch status {
	case http.StatusConflict:
		// 会话被占用（不能共享）—— 属于策略违规。
		return 1008
	case http.StatusNotFound, http.StatusGone:
		// 会话不存在/已结束 —— 正常关闭即可，不是错误。
		return 1000
	case http.StatusServiceUnavailable:
		// 面板正在关闭 —— 告知对面"服务即将消失"。
		return 1001
	default:
		return 1011
	}
}

// reasonForStatus 给出关闭原因（会出现在浏览器的 close 事件里）。
func reasonForStatus(status int) string {
	switch status {
	case http.StatusConflict:
		return "session_busy"
	case http.StatusNotFound, http.StatusGone:
		return "session_gone"
	case http.StatusServiceUnavailable:
		return "server_shutdown"
	default:
		return "internal_error"
	}
}

// durationSeconds 计算会话存活秒数。
func durationSeconds(createdAt string, ended bool) int {
	if !ended {
		return 0
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return 0
	}
	d := int(time.Since(t).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

// parseTerminalInt 解析整型查询参数，失败时返回默认值。
//
// 与 4.6 的同类函数一致：查询参数非法不是需要 400 的错误，
// 回退到默认值对用户更友好（他只是手改了一下 URL）。
func parseTerminalInt(raw string, def int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return def
		}
	}
	if n <= 0 {
		return def
	}
	return n
}

// ---------------------------------------------------------------------------
// 降级 handler
// ---------------------------------------------------------------------------

// handleTerminalUnavailable 在未注入管理器时返回 JSON 503。
func (s *Server) handleTerminalUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]any{
		"error": "终端功能不可用",
		"hint":  "面板未启用 Web 终端（未注入终端管理器）。",
	})
}

// handleTerminalNotFound 是 /api/terminal/ 前缀的兜底。
//
// 返回 JSON 404 + 可用接口清单：未注册的路径若落到前端 HTML 兜底，
// 前端会尝试 JSON.parse 一段 HTML 并报出与真实原因无关的解析错误。
func (s *Server) handleTerminalNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "接口不存在: " + r.URL.Path,
		"available": []string{
			"GET /api/terminal/status",
			"GET /api/terminal/sessions",
			"GET /api/terminal/audit",
			"POST /api/terminal/sessions",
			"DELETE /api/terminal/sessions?id=<id>&confirm=true",
			"GET /api/terminal/ws?id=<id>  (WebSocket)",
		},
	})
}
