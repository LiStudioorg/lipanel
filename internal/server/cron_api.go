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
	"lipanel/internal/cron"
)

// ============================================================================
// 计划任务接口（阶段五 5.2，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/cron                  状态（面板在改谁的 crontab、是否可用、备份、审计）
//	GET    /api/cron/jobs             任务列表 + crontab 里的全局设置行
//	POST   /api/cron/jobs             新增任务
//	PUT    /api/cron/jobs/{id}        编辑任务（非面板行编辑即「收编」）
//	DELETE /api/cron/jobs/{id}        删除任务（必须 confirm）
//	GET    /api/cron/jobs/{id}/logs   该任务的执行日志
//	POST   /api/cron/validate         表达式校验 + 中文描述 + 未来若干次执行时间
//	GET    /api/cron/audit            操作审计
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/cron/jobs"、"/api/cron/audit"、"/api/cron/validate" 这些**固定段**
// 路由必须先于任何通配注册。这是 4.1~4.6 与 5.1 连续踩过七次的同一个坑
// （见 开发计划.md「已知坑位」），这里从一开始就按纪律来，并有测试锁死。
//
// 与其它核心模块一致：
//   - 全部接口挂 RequireAuth（按路由显式挂载）；
//   - 写操作顺序固定：**解析 → 权限判定 → 执行 → 审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
//
// #################### 本模块接口最要紧的四件事 ####################
//
// ① **删除必须带 confirm（428 Precondition Required）**
//
//	一条正在跑的生产定时任务（数据库备份、证书续期、日志轮转）被误删，
//	后果往往要在几天后才被发现，而那时备份早就没了。
//	前端弹窗只是体验，服务端强制才是边界。
//
// ② **审计必须记命令原文**
//
//	计划任务是以面板身份（生产上通常是 root）在**无人值守的时刻**
//	执行任意 shell 命令。「谁在什么时候让这台机器以后每天凌晨跑什么」
//	必须完整留痕，包括被拒绝的越权尝试。
//	因此 create/update/delete 的审计里 Expression 与 Command 一律是原文，
//	不做截断、不做脱敏（脱敏后就没法事后审计）。
//
// ③ **「没装 cron」是状态，不是错误**
//
//	GET /api/cron 返回 200 + available=false + 原因 + 指引，
//	让前端渲染说明页而不是一个与真实原因无关的红色错误框
//	（与 4.1 无 systemd、4.4 无 certbot、5.1 无 PTY 完全一致的降级策略）。
//	而具体操作接口拿不到 crontab 时才返回 503。
//
// ④ **日志路径不接受外部输入**
//
//	/logs 只接受任务 id，路径由 id + 当前 crontab 内容反推。
//	若开一个 ?path= 参数，就是「登录即可读 root 的任意文件」。
func (s *Server) registerCronRoutes(mux *http.ServeMux) {
	if s.cronMgr == nil {
		mux.Handle("/api/cron/", s.auth.RequireAuth(http.HandlerFunc(s.handleCronUnavailable)))
		mux.Handle("/api/cron", s.auth.RequireAuth(http.HandlerFunc(s.handleCronUnavailable)))
		return
	}

	mux.Handle("GET /api/cron", s.auth.RequireAuth(http.HandlerFunc(s.handleCronStatus)))

	// ⚠️ 固定段路由必须先于通配注册（见上方说明）。
	mux.Handle("GET /api/cron/jobs", s.auth.RequireAuth(http.HandlerFunc(s.handleCronList)))
	mux.Handle("POST /api/cron/jobs", s.auth.RequireAuth(http.HandlerFunc(s.handleCronCreate)))
	mux.Handle("PUT /api/cron/jobs/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleCronUpdate)))
	mux.Handle("DELETE /api/cron/jobs/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleCronDelete)))
	mux.Handle("GET /api/cron/jobs/{id}/logs", s.auth.RequireAuth(http.HandlerFunc(s.handleCronLogs)))
	mux.Handle("POST /api/cron/validate", s.auth.RequireAuth(http.HandlerFunc(s.handleCronValidate)))
	mux.Handle("GET /api/cron/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleCronAudit)))

	// 前缀兜底：未注册的 /api/cron/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html）。
	mux.Handle("/api/cron/", s.auth.RequireAuth(http.HandlerFunc(s.handleCronNotFound)))
}

// handleCronUnavailable 在计划任务管理器未注入时给出明确提示。
func (s *Server) handleCronUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "计划任务管理未启用（服务启动时未注入管理器）",
	})
}

// handleCronNotFound 处理 /api/cron/* 下未注册的子路径。
//
// 返回 JSON 404 并把可用接口列在响应里——这类 404 多半是路径写错了。
func (s *Server) handleCronNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "计划任务接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET    /api/cron",
			"GET    /api/cron/jobs",
			"POST   /api/cron/jobs",
			"PUT    /api/cron/jobs/{id}",
			"DELETE /api/cron/jobs/{id}?confirm=true",
			"GET    /api/cron/jobs/{id}/logs?lines=200",
			"POST   /api/cron/validate",
			"GET    /api/cron/audit?limit=100&job_id=&user=&outcome=",
		},
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// cronAudit 收口一次计划任务操作的审计写入。
//
// 与 4.2 的 fileAudit、4.6 的 firewallAudit 同构：每个接口都要填
// user/action/target/client_ip 这几个固定字段，散落各处必然出现
// 「某个接口忘了填 client_ip」这种不一致。
type cronAudit struct {
	srv     *Server
	user    string
	action  cron.Action
	target  string
	ip      string
	started time.Time
	// 任务上下文（请求解析后填充）。
	jobID      string
	expression string
	command    string
	comment    string
	confirmed  bool
}

// beginCronAudit 构造一次操作的审计上下文。
func (s *Server) beginCronAudit(r *http.Request, action cron.Action, target string) *cronAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &cronAudit{
		srv:     s,
		user:    user,
		action:  action,
		target:  target,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计。
//
// Manager 自己不写审计（它只暴露 Auditor()）：只有接口层知道
// 「谁、从哪个 IP、以什么身份」发起的请求。
func (a *cronAudit) record(ev cron.AuditEvent) {
	ev.User = a.user
	ev.Action = string(a.action)
	if ev.Target == "" {
		ev.Target = a.target
	}
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.Required == "" {
		ev.Required = cron.RequiredPermission(a.action)
	}
	if ev.JobID == "" {
		ev.JobID = a.jobID
	}
	if ev.Expression == "" {
		ev.Expression = a.expression
	}
	if ev.Command == "" {
		ev.Command = a.command
	}
	if ev.Comment == "" {
		ev.Comment = a.comment
	}
	if !ev.Confirmed {
		ev.Confirmed = a.confirmed
	}
	a.srv.cronMgr.Auditor().Record(ev)
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireCronPermission 判定当前用户能否执行某计划任务动作。
//
// 顺序与其它核心模块一致且不可调换：**先判权限，再碰 crontab**。
// 被拒绝的请求绝不能产生任何副作用——对本模块而言，副作用是
// 「这台机器未来的执行计划被改掉了」。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireCronPermission(w http.ResponseWriter, a *cronAudit) bool {
	grantee := cron.AdminGrantee(a.user)
	decision := cron.CheckCronPermission(grantee, a.action)
	if decision.Allowed {
		return true
	}
	a.record(cron.AuditEvent{
		Outcome:  cron.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("计划任务操作被权限校验拒绝",
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

// cronErrorStatus 把 cron 包的语义错误映射为 HTTP 状态码。
//
// ########## 状态码的语义必须准确 ##########
//
//	400 输入非法（表达式、命令、备注、id 形态）—— 用户的输入问题
//	404 任务不存在                              —— 可能已被 crontab -e 删掉
//	409 并发冲突 / 表达式不被面板支持           —— 当前状态不允许此操作
//	428 缺少二次确认                            —— 请求合法但需要显式确认
//	503 crontab 不可用                          —— 环境没这个能力（不是 bug）
//	502 crontab 命令执行失败                     —— 系统自己报的错
//
// 428 与 409 是本模块最需要说清楚的两位：前者让用户去点确认框，
// 后者的两种含义（并发冲突 vs 表达式不支持）给出的下一步动作完全不同，
// 因此响应里额外带 kind 与 hint。
//
// ########## 为什么用 errors.As 而不是 errors.Is ##########
//
// ErrEditConflict 与 ErrJobInvalid 是**带字段的 struct 错误**
// （要携带 id 与原因），每次都是新实例，errors.Is 按值比较永远不相等。
// 用 errors.As 按类型判定才能命中；写成 errors.Is 的话这两类错误
// 会统统掉进 default 分支变成 502——把「刷新一下就好」的 409
// 报成「面板坏了」，用户会反复重试并最终覆盖掉别人的改动。
func cronErrorStatus(err error) (int, string) {
	var conflict *cron.ErrEditConflict
	var invalidJob *cron.ErrJobInvalid
	var fieldErr *cron.ValidationError
	switch {
	// ErrJobNotFound 是**被 %w 包装**的哨兵错误，必须排在最前：
	// 它携带 id，若先撞上上面的 As 分支判定顺序发生变化，
	// 「任务不存在」就可能被误判成别的类别。
	case errors.Is(err, cron.ErrJobNotFound):
		return http.StatusNotFound, "任务不存在"
	case errors.Is(err, cron.ErrConfirmRequired):
		return http.StatusPreconditionRequired, "缺少二次确认"
	case errors.As(err, &conflict):
		return http.StatusConflict, "任务已被外部修改"
	case errors.As(err, &invalidJob):
		return http.StatusConflict, "任务不可由面板接管"
	case errors.Is(err, cron.ErrStoreUnavailable):
		return http.StatusServiceUnavailable, "crontab 不可用"
	case errors.As(err, &fieldErr):
		return http.StatusBadRequest, "输入非法"
	default:
		// 保存失败（Manager 已回滚）与 crontab 命令自身的失败都归 502：
		// 用户输入没问题，是系统那侧出了状况。
		return http.StatusBadGateway, "crontab 操作失败"
	}
}

// writeCronError 统一写出计划任务操作错误。
func (s *Server) writeCronError(w http.ResponseWriter, a *cronAudit, err error, res *cron.WriteResult) {
	status, kind := cronErrorStatus(err)

	if status == http.StatusPreconditionRequired {
		// 按 RFC 6585 给出提示，让客户端知道「补上确认再重试」。
		w.Header().Set("X-Lipanel-Confirm-Required", "true")
	}

	ev := cron.AuditEvent{
		Outcome:  cron.AuditDenied,
		Status:   status,
		Reason:   err.Error(),
		Required: cron.RequiredPermission(a.action),
	}
	if res != nil {
		// 写失败但已回滚：这不是「什么都没发生」，而是
		// 「尝试改动 → 失败 → 恢复原状」，回滚结果必须进审计。
		ev.RollbackOK = res.RolledBack && res.RollbackErr == ""
		ev.RollbackErr = res.RollbackErr
		ev.BackupPath = res.BackupPath
		ev.BeforeJobs = res.BeforeCount
		ev.AfterJobs = res.AfterCount
	}
	a.record(ev)

	payload := map[string]any{
		"error":  err.Error(),
		"kind":   kind,
		"status": status,
	}
	// 字段名：让前端能直接把错误挂到对应表单项上。
	var ve *cron.ValidationError
	if errors.As(err, &ve) {
		payload["field"] = ve.Field
	}
	switch status {
	case http.StatusPreconditionRequired:
		payload["hint"] = "删除定时任务是不可逆的：一条正在跑的备份或证书续期任务" +
			"被删掉后，往往要过几天才会发现。因此必须在请求里显式带上 confirm=true。"
	case http.StatusConflict:
		var conflict *cron.ErrEditConflict
		if errors.As(err, &conflict) {
			payload["hint"] = "crontab 在你编辑期间被别处改过（crontab -e、其它面板、ansible）。" +
				"请**刷新列表后重新编辑**，不要直接重试提交——重试会覆盖别人的改动。"
		} else {
			payload["hint"] = "该任务的表达式不是面板支持的 5 段式或 @ 别名。" +
				"面板不会替你改写它，请在系统里用 crontab -e 处理。"
		}
	case http.StatusNotFound:
		payload["hint"] = "任务可能已被 crontab -e 或其它工具删除，请刷新列表后重试。"
	case http.StatusServiceUnavailable:
		payload["hint"] = "这台机器现在无法管理 crontab：通常是没装 cron，" +
			"或面板运行身份没有权限。可先用 GET /api/cron 看清原因；" +
			"验证与开发环境可用 -cron-file 指向一个隔离文件。"
	}
	if res != nil {
		// 回滚信息如实给到用户：回滚失败时那行备份路径是救命稻草。
		if res.RolledBack {
			payload["rolled_back"] = true
			payload["restored_from"] = res.RestoredFrom
		}
		if res.RollbackErr != "" {
			payload["rollback_error"] = res.RollbackErr
			payload["backup_path"] = res.BackupPath
			payload["restore_hint"] = "**自动回滚也失败了**：请手工执行 `crontab " +
				res.BackupPath + "` 恢复改动前的内容。"
		}
	}
	writeJSON(w, s.logger, status, payload)
}

// ---------------------------------------------------------------------------
// GET /api/cron —— 状态
// ---------------------------------------------------------------------------

// handleCronStatus 返回模块状态。
//
// available=false **不是错误**：返回 200 让前端渲染说明页
// （见文件头 ③）。
func (s *Server) handleCronStatus(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	audit := s.beginCronAudit(r, cron.ActionList, "status")

	st := s.cronMgr.Status(r.Context())
	audit.target = st.Target
	audit.record(cron.AuditEvent{
		Outcome:    cron.AuditAllowed,
		Status:     http.StatusOK,
		Mode:       st.Mode,
		BackupPath: strings.Join(st.Backups, ","),
	})

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"status":                  st,
		"available":               st.Available,
		"reason":                  st.Reason,
		"permissions":             cron.AdminGrantee(user).Granted,
		"confirm_required":        true,
		"max_command_bytes":       cron.MaxCommandLen,
		"max_comment_bytes":       cron.MaxCommentLen,
		"default_log_tail_lines":  cron.DefaultLogTailLines,
		"max_log_tail_lines":      cron.MaxLogTailLines,
		"install_hint":            cronInstallHint(st),
		"log_max_bytes":           s.cronMgr.LogMaxBytes(),
		"command_timeout_seconds": s.cronMgr.CommandTimeout().Seconds(),
		"audit":                   s.cronMgr.Auditor().Stats(),
	})
}

// cronInstallHint 在不可用时给出可操作的指引。
//
// 措辞刻意区分两种成因：没装 cron（要装包）与 -cron-file 隔离模式
// （验证环境故意指向文件）。把它们混成一句会让人装完 cron 还是看不懂。
func cronInstallHint(st cron.Status) string {
	if st.Available {
		return ""
	}
	if st.Mode == cron.ModeFile {
		return "当前是隔离文件模式（-cron-file），它不接系统 cron，仅用于验证与开发。"
	}
	return "安装 cron：Debian/Ubuntu `apt-get install -y cron && systemctl enable --now cron`；" +
		"RHEL/Rocky `dnf install -y cronie && systemctl enable --now crond`。" +
		"若只想验证面板功能，可用 -cron-file 指向一个隔离文件。"
}

// ---------------------------------------------------------------------------
// GET /api/cron/jobs —— 列表
// ---------------------------------------------------------------------------

// handleCronList 返回任务列表。
func (s *Server) handleCronList(w http.ResponseWriter, r *http.Request) {
	audit := s.beginCronAudit(r, cron.ActionList, "jobs")

	res, err := s.cronMgr.List(r.Context())
	if err != nil {
		s.writeCronError(w, audit, err, nil)
		return
	}
	audit.target = res.Target
	audit.record(cron.AuditEvent{
		Outcome:   cron.AuditAllowed,
		Status:    http.StatusOK,
		Mode:      res.Mode,
		AfterJobs: len(res.Jobs),
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// 写操作请求体
// ---------------------------------------------------------------------------

// maxCronBodyBytes 是写请求体的上限。
//
// 命令上限 900 字节、备注 200 字节，加上 expected_ids（每个 12 字节）
// 与 JSON 开销，16 KiB 已给出十几倍余量。给无限的好处是零，
// 代价是任何人可以用一个 1 GB 的 body 打满面板内存。
const maxCronBodyBytes = 16 * 1024

// cronJobRequest 是新增/编辑的请求体。
type cronJobRequest struct {
	Expression  string   `json:"expression"`
	Command     string   `json:"command"`
	Comment     string   `json:"comment"`
	ExpectedIDs []string `json:"expected_ids"`
	Confirm     bool     `json:"confirm"`
}

// toInput 转成 Manager 的输入。
func (q cronJobRequest) toInput() cron.JobInput {
	return cron.JobInput{
		Expression:     q.Expression,
		Command:        q.Command,
		Comment:        q.Comment,
		ExpectedJobIDs: q.ExpectedIDs,
	}
}

// decodeCronBody 解析 JSON 请求体（带大小上限）。
//
// 允许空 body：DELETE 走 query 参数确认时 body 就是空的。
// `Decode` 在空 body 上返回 io.EOF，那不是错误而是「什么都没写」，
// 必须与「写了但不是 JSON」区分开——后者要 400 并留痕，
// 前者交给后续的字段校验给出准确报错。
func (s *Server) decodeCronBody(w http.ResponseWriter, r *http.Request, dst *cronJobRequest) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCronBodyBytes))
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		audit := s.beginCronAudit(r, cron.ActionCreate, "body")
		audit.record(cron.AuditEvent{
			Outcome: cron.AuditDenied, Status: http.StatusBadRequest,
			Reason: err.Error(),
		})
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error":  "请求体不是合法 JSON：" + err.Error(),
			"kind":   "输入非法",
			"status": http.StatusBadRequest,
			"hint":   fmt.Sprintf("请求体上限 %d 字节；写操作请带 Content-Type: application/json。", maxCronBodyBytes),
		})
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// POST /api/cron/jobs —— 新增
// ---------------------------------------------------------------------------

func (s *Server) handleCronCreate(w http.ResponseWriter, r *http.Request) {
	var req cronJobRequest
	if !s.decodeCronBody(w, r, &req) {
		return
	}
	audit := s.beginCronAudit(r, cron.ActionCreate, "jobs")
	audit.expression = strings.TrimSpace(req.Expression)
	audit.command = strings.TrimSpace(req.Command)
	audit.comment = strings.TrimSpace(req.Comment)
	audit.target = audit.expression

	if !s.requireCronPermission(w, audit) {
		return
	}

	res, err := s.cronMgr.Create(r.Context(), req.toInput())
	if err != nil {
		s.writeCronError(w, audit, err, res)
		return
	}
	if res.Job != nil {
		audit.jobID = res.Job.ID
		audit.expression = res.Job.Expression
		audit.comment = res.Job.Comment
	}
	audit.record(cron.AuditEvent{
		Outcome:      cron.AuditAllowed,
		Status:       http.StatusOK,
		Mode:         s.cronMgr.Mode(),
		JobID:        audit.jobID,
		BackupPath:   res.BackupPath,
		BeforeJobs:   res.BeforeCount,
		AfterJobs:    res.AfterCount,
		SystemChange: true,
		Reason:       res.Warning,
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// PUT /api/cron/jobs/{id} —— 编辑（非面板行 = 收编）
// ---------------------------------------------------------------------------

func (s *Server) handleCronUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req cronJobRequest
	if !s.decodeCronBody(w, r, &req) {
		return
	}
	audit := s.beginCronAudit(r, cron.ActionUpdate, id)
	audit.jobID = id
	audit.expression = strings.TrimSpace(req.Expression)
	audit.command = strings.TrimSpace(req.Command)
	audit.comment = strings.TrimSpace(req.Comment)

	if !s.requireCronPermission(w, audit) {
		return
	}

	res, err := s.cronMgr.Update(r.Context(), id, req.toInput())
	if err != nil {
		s.writeCronError(w, audit, err, res)
		return
	}
	if res.Job != nil {
		audit.jobID = res.Job.ID
		audit.expression = res.Job.Expression
		audit.comment = res.Job.Comment
	}
	audit.record(cron.AuditEvent{
		Outcome:      cron.AuditAllowed,
		Status:       http.StatusOK,
		Mode:         s.cronMgr.Mode(),
		JobID:        audit.jobID,
		BackupPath:   res.BackupPath,
		BeforeJobs:   res.BeforeCount,
		AfterJobs:    res.AfterCount,
		SystemChange: true,
		Reason:       res.Warning,
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// DELETE /api/cron/jobs/{id} —— 删除（强制二次确认）
// ---------------------------------------------------------------------------

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req cronJobRequest
	if !s.decodeCronBody(w, r, &req) {
		return
	}
	// confirm 走 query 或 body 都接受：curl 手敲更省事，前端走 body。
	// 两者取「或」，绝不取「与」——否则出现「传了 body 却忘了 query」
	// 这种无意义的失败。
	confirmed := req.Confirm ||
		r.URL.Query().Get("confirm") == "true" ||
		r.URL.Query().Get("confirm") == "1"

	audit := s.beginCronAudit(r, cron.ActionDelete, id)
	audit.jobID = id
	audit.confirmed = confirmed

	if !s.requireCronPermission(w, audit) {
		return
	}

	res, err := s.cronMgr.Delete(r.Context(), id, confirmed, req.ExpectedIDs)
	if err != nil {
		s.writeCronError(w, audit, err, res)
		return
	}
	audit.record(cron.AuditEvent{
		Outcome:      cron.AuditAllowed,
		Status:       http.StatusOK,
		Mode:         s.cronMgr.Mode(),
		JobID:        id,
		Expression:   exprOfResult(res),
		BackupPath:   res.BackupPath,
		BeforeJobs:   res.BeforeCount,
		AfterJobs:    res.AfterCount,
		SystemChange: true,
		Reason:       res.Warning,
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// exprOfResult 取结果里的表达式（结果可能为 nil 分支已在上游拦掉）。
func exprOfResult(res *cron.WriteResult) string {
	if res == nil || res.Job == nil {
		return ""
	}
	return res.Job.Expression
}

// ---------------------------------------------------------------------------
// GET /api/cron/jobs/{id}/logs —— 执行日志
// ---------------------------------------------------------------------------

func (s *Server) handleCronLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	lines := cron.DefaultLogTailLines
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			audit := s.beginCronAudit(r, cron.ActionLogs, id)
			// 必须包装成校验错误，否则被默认分支归到 502——
			// 而「lines 写错了」明明是输入问题。
			s.writeCronError(w, audit, &cron.ValidationError{
				Field: "lines", Reason: fmt.Sprintf("必须是正整数，实际收到 %q", v),
			}, nil)
			return
		}
		lines = n
	}

	audit := s.beginCronAudit(r, cron.ActionLogs, id)
	audit.jobID = id
	if !s.requireCronPermission(w, audit) {
		return
	}

	res, err := s.cronMgr.Logs(r.Context(), id, lines)
	if err != nil {
		s.writeCronError(w, audit, err, nil)
		return
	}
	audit.record(cron.AuditEvent{
		Outcome: cron.AuditAllowed,
		Status:  http.StatusOK,
		JobID:   id,
		Reason:  res.Reason,
	})
	writeJSON(w, s.logger, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// POST /api/cron/validate —— 表达式预校验与执行时间预览
// ---------------------------------------------------------------------------

// handleCronValidate 校验表达式并给出中文描述与未来若干次执行时间。
//
// 这个接口存在的意义是「让用户在保存之前就看到真实后果」。
// 它必须与列表用的是**同一份**解析器与时钟（见 Manager.PreviewExpr），
// 否则会出现「校验放行、列表显示的下次执行时间却是另一个」。
func (s *Server) handleCronValidate(w http.ResponseWriter, r *http.Request) {
	var req cronJobRequest
	if !s.decodeCronBody(w, r, &req) {
		return
	}
	audit := s.beginCronAudit(r, cron.ActionList, "validate")
	audit.expression = strings.TrimSpace(req.Expression)

	count := 5
	res, err := s.cronMgr.PreviewExpr(req.Expression, count)
	if err != nil {
		// 表达式非法是输入问题，不是服务错误：返回 200 + valid=false
		// 而不是 400，因为调用方是**表单实时校验**，
		// 用户边打字边调用，每敲一个字符就 400 一次会让前端
		// 的「请求失败」提示刷屏，反而看不到真正有用的错误文案。
		audit.record(cron.AuditEvent{
			Outcome: cron.AuditAllowed, Status: http.StatusOK,
			Expression: audit.expression, Reason: err.Error(),
		})
		writeJSON(w, s.logger, http.StatusOK, map[string]any{
			"valid":      false,
			"expression": strings.TrimSpace(req.Expression),
			"error":      strings.TrimPrefix(err.Error(), "cron: "),
		})
		return
	}
	audit.record(cron.AuditEvent{
		Outcome:    cron.AuditAllowed,
		Status:     http.StatusOK,
		Expression: res.Expression,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"valid":   true,
		"preview": res,
	})
}

// ---------------------------------------------------------------------------
// GET /api/cron/audit —— 操作审计
// ---------------------------------------------------------------------------

func (s *Server) handleCronAudit(w http.ResponseWriter, r *http.Request) {
	audit := s.beginCronAudit(r, cron.ActionList, "audit")

	limit := cron.DefaultAuditQueryLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.writeCronError(w, audit, &cron.ValidationError{
				Field: "limit", Reason: fmt.Sprintf("必须是正整数，实际收到 %q", v),
			}, nil)
			return
		}
		limit = n
	}
	filter := cron.AuditFilter{
		JobID:   r.URL.Query().Get("job_id"),
		User:    r.URL.Query().Get("user"),
		Outcome: r.URL.Query().Get("outcome"),
		Limit:   limit,
	}
	events := s.cronMgr.Auditor().Query(filter)
	audit.record(cron.AuditEvent{
		Outcome: cron.AuditAllowed, Status: http.StatusOK,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": events,
		"stats":  s.cronMgr.Auditor().Stats(),
		"total":  len(events),
		"filter": map[string]string{
			"job_id":  filter.JobID,
			"user":    filter.User,
			"outcome": filter.Outcome,
		},
	})
}
