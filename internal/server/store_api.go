package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/store"
)

// ============================================================================
// 软件商店接口（阶段四 4.5，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET  /api/store                       软件清单与安装状态
//	GET  /api/store/capabilities          环境能力探测（包管理器/发行版/官方源）
//	GET  /api/store/audit                 软件商店操作审计
//	GET  /api/store/tasks                 最近任务列表
//	GET  /api/store/tasks/{id}            单个任务的进度与日志（轮询用）
//	POST /api/store/{name}/install        安装（202 + 任务 ID）
//	POST /api/store/{name}/uninstall      卸载（202 + 任务 ID）
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/store/capabilities"、"/api/store/audit"、"/api/store/tasks" 这些
// **固定段**路由必须在 "/api/store/{name}/install" 之类的通配**之前**注册。
// 否则它们会被通配吃掉——查审计会变成"安装名为 audit 的软件"。
//
// 这是 4.1/4.2/4.3/4.4 **连续踩过四次**的同一个坑，
// 因此本次从一开始就写测试锁死（见 store_api_test.go）。
//
// 与其它核心模块一致：
//   - 全部接口挂 RequireAuth（按路由显式挂载）；
//   - 写操作顺序固定：**校验 → 权限判定 → 发起任务 → 审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
//
// ########## 本模块与其它四个模块的接口差异 ##########
//
// 4.1~4.4 的写操作是**同步**的（改一行配置、跑一次 certbot），请求返回时
// 结果已经确定。安装软件不行：装 MySQL 要几十秒到几分钟，
// 同步等待必然被反向代理掐断，而机器上 dpkg 还在跑。
//
// 因此这里的写接口一律返回 **202 + 任务 ID**，真正的结果由
// GET /api/store/tasks/{id} 轮询获得。这意味着：
//   - 202 响应里的 status 不是"成功"，只是"任务已受理"；
//   - 审计在发起时记 pending，任务结束时由 Manager 补记终态；
//   - 前端必须展示进度，而不是拿 202 当"装好了"。
func (s *Server) registerStoreRoutes(mux *http.ServeMux) {
	if s.storeMgr == nil {
		// 未注入软件商店管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/store/", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreUnavailable)))
		mux.Handle("/api/store", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreUnavailable)))
		return
	}

	mux.Handle("GET /api/store", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreList)))

	// ⚠️ 固定段路由必须先于 /{name}/... 通配注册（见上方说明）。
	mux.Handle("GET /api/store/capabilities", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreCapabilities)))
	mux.Handle("GET /api/store/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreAudit)))
	mux.Handle("GET /api/store/tasks", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreTasks)))
	mux.Handle("GET /api/store/tasks/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreTask)))

	// 软件维度的写操作（异步）。
	mux.Handle("POST /api/store/{name}/install", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreInstall)))
	mux.Handle("POST /api/store/{name}/uninstall", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreUninstall)))

	// 前缀兜底：未注册的 /api/store/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html）。
	mux.Handle("/api/store/", s.auth.RequireAuth(http.HandlerFunc(s.handleStoreNotFound)))
}

// handleStoreUnavailable 在软件商店管理器未注入时给出明确提示。
func (s *Server) handleStoreUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "软件商店未启用（服务启动时未注入管理器）",
	})
}

// handleStoreNotFound 处理 /api/store/* 下未注册的子路径。
//
// 返回 JSON 404 并**列出可用接口**——这类 404 多半是路径写错了，
// 把正确的接口清单摆在响应里，比让人去翻源码快得多。
func (s *Server) handleStoreNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "软件商店接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET  /api/store",
			"GET  /api/store/capabilities",
			"GET  /api/store/audit",
			"GET  /api/store/tasks",
			"GET  /api/store/tasks/{id}?since=N",
			"POST /api/store/{name}/install",
			"POST /api/store/{name}/uninstall",
		},
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// storeAudit 收口一次软件商店操作的审计写入。
//
// 与 4.2 的 fileAudit、4.3 的 siteAudit、4.4 的 sslAudit 同构：
// 每个接口都要填 user/action/target/client_ip 这几个固定字段，
// 散落各处必然出现"某个接口忘了填 client_ip"这种不一致。
type storeAudit struct {
	srv     *Server
	user    string
	action  string
	target  string
	version string
	ip      string
	started time.Time
}

// beginStoreAudit 构造一次操作的审计上下文。
func (s *Server) beginStoreAudit(r *http.Request, action, target string) *storeAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &storeAudit{
		srv:     s,
		user:    user,
		action:  action,
		target:  target,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计（outcome 见 store.AuditAllowed/Denied/Failed/Pending）。
func (a *storeAudit) record(ev store.AuditEvent) {
	ev.User = a.user
	ev.Action = a.action
	ev.Target = a.target
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.Version == "" {
		ev.Version = a.version
	}
	if ev.Required == "" {
		ev.Required = store.RequiredPermission(a.action)
	}
	a.srv.storeMgr.Auditor().Record(ev)
}

// recordTask 记录一次"任务已受理"（pending）。
//
// 安装/卸载是异步的，请求返回时命令还没跑完。因此这里只能记 pending；
// 真正的终态由 Manager 在任务结束时补记（两条记录通过 TaskID 关联）。
// 若这里就记成 allowed，事后按 allowed 筛"装成功过什么"
// 会把失败的任务也算进去。
func (a *storeAudit) recordTask(task store.Task, status int) {
	a.record(store.AuditEvent{
		Outcome:  store.AuditPending,
		Status:   status,
		TaskID:   task.ID,
		Version:  task.Version,
		Packages: task.Packages,
		Reason:   "任务已受理，执行进度见 GET /api/store/tasks/" + task.ID,
	})
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireStorePermission 判定当前用户能否执行某软件商店动作。
//
// 顺序与其它核心模块一致且不可调换：**先判权限，再碰外部命令**。
// 被拒绝的请求绝不能产生任何副作用——对本模块而言，
// 副作用就是"以 root 身份跑了发行版的安装脚本"，代价极高。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireStorePermission(w http.ResponseWriter, a *storeAudit) bool {
	grantee := store.AdminGrantee(a.user)
	decision := store.CheckStorePermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(store.AuditEvent{
		Outcome:  store.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	// 响应头与其它模块的权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("软件商店操作被权限校验拒绝",
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
// GET /api/store —— 软件清单与安装状态
// ---------------------------------------------------------------------------

// storeListResponse 是 GET /api/store 的响应体。
type storeListResponse struct {
	// Software 是全部软件的清单与安装状态。
	Software []store.SoftwareStatus `json:"software"`
	// Counts 是汇总统计，前端直接展示不必自己遍历。
	Counts store.StatusCounts `json:"counts"`
	// Available 为 false 表示无法安装（未探测到包管理器）。
	//
	// 注意：这与"软件清单不可用"不同——即使不能安装，
	// 清单与状态**仍会正常返回**。前端据此禁用按钮并展示原因，
	// 而不是整页报错（与 4.1/4.3/4.4 同样的降级策略）。
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Running 是当前正在执行的任务（无则为 null）。
	//
	// 放进列表响应是有意的：用户刷新页面后必须能立刻看到
	// "上一次的安装还在跑"，否则会再点一次（然后被 409 拒绝，
	// 或者更糟——如果锁失效就会有两个 apt 抢 dpkg 锁）。
	Running *store.Task `json:"running,omitempty"`
	// DryRun 表示是否处于试运行模式（前端要显著提示）。
	DryRun bool `json:"dry_run"`
	// Environment 是环境摘要（发行版、包管理器、架构）。
	Environment storeEnvironment `json:"environment"`
	// ScannedAt 是本次扫描时间。
	ScannedAt string `json:"scanned_at"`
	// Audit 是审计器状态，供页面展示"操作是否在留痕"。
	Audit store.AuditStats `json:"audit"`
	// Permissions 是当前用户被授予的软件商店权限。
	//
	// 注意：这只是**体验优化**。真正的强制点始终在后端
	// （见 requireStorePermission），前端拿到的标记被篡改也没用。
	Permissions []string `json:"permissions"`
}

// storeEnvironment 是环境摘要（前端在页头展示一行"当前环境"）。
type storeEnvironment struct {
	// Distro 是发行版展示名。
	Distro string `json:"distro,omitempty"`
	// Family 是 debian / rhel / unknown。
	Family string `json:"family,omitempty"`
	// PackageManager 是 apt / dnf / yum。
	PackageManager string `json:"package_manager,omitempty"`
	// Codename / Arch 决定官方源与预编译包能否使用。
	Codename string `json:"codename,omitempty"`
	Arch     string `json:"arch,omitempty"`
	// OfficialSources 表示是否支持追加官方源。
	OfficialSources bool `json:"official_sources"`
	// Notes 是探测过程中的告警（如"未识别发行版"）。
	Notes []string `json:"notes,omitempty"`
}

// handleStoreList 返回软件清单与安装状态。
func (s *Server) handleStoreList(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	audit := s.beginStoreAudit(r, store.ActionList, "")

	result, err := s.storeMgr.Status(r.Context())
	if err != nil {
		audit.record(store.AuditEvent{
			Outcome: store.AuditFailed,
			Status:  http.StatusInternalServerError,
			Reason:  err.Error(),
		})
		writeJSON(w, s.logger, http.StatusInternalServerError, map[string]any{
			"error": "读取软件商店状态失败: " + err.Error(),
		})
		return
	}

	audit.record(store.AuditEvent{
		Outcome: store.AuditAllowed,
		Status:  http.StatusOK,
	})

	vars := s.storeMgr.Vars()
	writeJSON(w, s.logger, http.StatusOK, storeListResponse{
		Software:          result.Software,
		Counts:            result.Counts,
		Available:         result.Available,
		UnavailableReason: result.UnavailableReason,
		Running:           result.Running,
		DryRun:            result.DryRun,
		ScannedAt:         result.ScannedAt,
		Audit:             s.storeMgr.Auditor().Stats(),
		Permissions:       store.AdminGrantee(user).Granted,
		Environment: storeEnvironment{
			Distro:          vars.DistroName,
			Family:          vars.Family,
			PackageManager:  vars.Manager,
			Codename:        vars.Codename,
			Arch:            vars.Arch,
			OfficialSources: vars.SupportsOfficialSource(),
			Notes:           vars.ProbeNotes,
		},
	})
}

// ---------------------------------------------------------------------------
// GET /api/store/capabilities —— 环境能力探测
// ---------------------------------------------------------------------------

// storeCapabilitiesResponse 是 GET /api/store/capabilities 的响应体。
//
// 这个接口回答的是"这台机器上能装什么、靠什么装"。
// 单独做成接口而不是塞进列表响应，是因为它是排查问题的第一入口：
// 用户问"为什么装不上"时，看的就是这里的 manager / official_source。
type storeCapabilitiesResponse struct {
	// Environment 是环境摘要。
	Environment storeEnvironment `json:"environment"`
	// Available 表示能否安装软件。
	Available bool `json:"available"`
	// UnavailableReason 是不可用原因（可用时为空）。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Tools 是探测到的外部命令（前端展示"依赖哪些工具"）。
	Tools map[string]string `json:"tools"`
	// Software 是每个软件的能力摘要。
	Software []store.CapabilityInfo `json:"software"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
	// StepTimeoutSeconds / TaskTimeoutSeconds 是超时配置。
	//
	// 展示出来是因为"超时了怎么办"是本模块最常见的疑问，
	// 用户需要知道面板等了多久才放弃。
	StepTimeoutSeconds int `json:"step_timeout_seconds"`
	TaskTimeoutSeconds int `json:"task_timeout_seconds"`
	// ProbedAt 是探测时间。
	ProbedAt string `json:"probed_at"`
}

// handleStoreCapabilities 返回环境能力探测结果。
//
// 即使不可用也返回 200：这样前端能拿到 available=false 与原因，
// 从而渲染出"为什么不可用"的说明，而不是一个红色错误框。
func (s *Server) handleStoreCapabilities(w http.ResponseWriter, r *http.Request) {
	audit := s.beginStoreAudit(r, store.ActionCapabilities, "")

	vars := s.storeMgr.Vars()
	tools := map[string]string{}
	for name, path := range map[string]string{
		"apt-get": vars.Tools.AptGet, "apt-cache": vars.Tools.AptCache,
		"dpkg-query": vars.Tools.DpkgQuery, "rpm": vars.Tools.RPM,
		"curl": vars.Tools.Curl, "tar": vars.Tools.Tar,
	} {
		if path != "" {
			tools[name] = path
		}
	}

	audit.record(store.AuditEvent{
		Outcome: store.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, storeCapabilitiesResponse{
		Environment: storeEnvironment{
			Distro:          vars.DistroName,
			Family:          vars.Family,
			PackageManager:  vars.Manager,
			Codename:        vars.Codename,
			Arch:            vars.Arch,
			OfficialSources: vars.SupportsOfficialSource(),
			Notes:           vars.ProbeNotes,
		},
		Available:          s.storeMgr.Available(),
		UnavailableReason:  s.storeMgr.UnavailableReason(),
		Tools:              tools,
		Software:           s.storeMgr.Capabilities(),
		DryRun:             s.storeMgr.DryRun(),
		StepTimeoutSeconds: int(s.storeMgr.StepTimeout().Seconds()),
		TaskTimeoutSeconds: int(s.storeMgr.TaskTimeout().Seconds()),
		ProbedAt:           time.Now().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// GET /api/store/audit —— 审计
// ---------------------------------------------------------------------------

// storeAuditResponse 是 GET /api/store/audit 的响应体。
type storeAuditResponse struct {
	Events []store.AuditEvent `json:"events"`
	Stats  store.AuditStats   `json:"stats"`
	Count  int                `json:"count"`
	// Limit 是本次生效的条数上限（便于前端提示"还有更多"）。
	Limit int `json:"limit"`
}

// handleStoreAudit 返回软件商店操作审计（最新在前）。
func (s *Server) handleStoreAudit(w http.ResponseWriter, r *http.Request) {
	audit := s.beginStoreAudit(r, store.ActionAudit, r.URL.Query().Get("target"))

	limit := parseIntDefault(r.URL.Query().Get("limit"), store.DefaultAuditQueryLimit)
	filter := store.AuditFilter{
		Target:  strings.TrimSpace(r.URL.Query().Get("target")),
		Version: strings.TrimSpace(r.URL.Query().Get("version")),
		User:    strings.TrimSpace(r.URL.Query().Get("user")),
		Action:  strings.TrimSpace(r.URL.Query().Get("action")),
		Outcome: strings.TrimSpace(r.URL.Query().Get("outcome")),
		Limit:   limit,
	}
	events := s.storeMgr.Auditor().Query(filter)

	audit.record(store.AuditEvent{
		Outcome: store.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, storeAuditResponse{
		Events: events,
		Stats:  s.storeMgr.Auditor().Stats(),
		Count:  len(events),
		Limit:  limit,
	})
}

// ---------------------------------------------------------------------------
// GET /api/store/tasks —— 任务列表
// ---------------------------------------------------------------------------

// storeTasksResponse 是 GET /api/store/tasks 的响应体。
type storeTasksResponse struct {
	Tasks []store.Task `json:"tasks"`
	Count int          `json:"count"`
	Limit int          `json:"limit"`
	// Running 是当前运行中的任务（无则为 null）。
	Running *store.Task `json:"running,omitempty"`
}

// handleStoreTasks 返回最近的任务列表。
//
// 前端在"安装中"状态下用它恢复界面：刷新页面后若不知道
// 有任务在跑，用户会再点一次安装。
func (s *Server) handleStoreTasks(w http.ResponseWriter, r *http.Request) {
	audit := s.beginStoreAudit(r, store.ActionTask, "")

	limit := parseIntDefault(r.URL.Query().Get("limit"), 20)
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	tasks := s.storeMgr.Tasks(limit)
	running := s.storeMgr.RunningTask()

	audit.record(store.AuditEvent{
		Outcome: store.AuditAllowed,
		Status:  http.StatusOK,
	})

	writeJSON(w, s.logger, http.StatusOK, storeTasksResponse{
		Tasks:   tasks,
		Count:   len(tasks),
		Limit:   limit,
		Running: running,
	})
}

// ---------------------------------------------------------------------------
// GET /api/store/tasks/{id} —— 任务进度与日志（轮询）
// ---------------------------------------------------------------------------

// storeTaskResponse 是 GET /api/store/tasks/{id} 的响应体。
type storeTaskResponse struct {
	// Task 是任务快照。
	Task store.Task `json:"task"`
	// Logs 是**增量**日志（由 since 游标决定）。
	Logs []store.LogLine `json:"logs"`
	// Since 是本次请求使用的游标。
	Since int `json:"since"`
	// NextSince 是下次轮询应传的游标。
	//
	// 由服务端计算而不是让前端自己取"最后一条的 seq"：
	// 日志为空时前端无从得知该传什么，容易写成 since=0
	// 从而每轮都全量拉取（日志上千行时这是可观的浪费）。
	NextSince int `json:"next_since"`
	// Done 表示任务已进入终态（前端据此停止轮询）。
	Done bool `json:"done"`
}

// handleStoreTask 返回单个任务的快照与增量日志。
func (s *Server) handleStoreTask(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	audit := s.beginStoreAudit(r, store.ActionTask, id)

	// 任务 ID 也要过白名单：它会被用于日志与响应回显，
	// 不做校验就是把用户输入原样反射回去。
	if err := store.ValidTaskID(id); err != nil {
		audit.record(store.AuditEvent{
			Outcome: store.AuditDenied,
			Status:  http.StatusBadRequest,
			Reason:  err.Error(),
		})
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "任务 ID 形如 t1、t2，可从安装/卸载接口的响应中获得。",
		})
		return
	}

	task, ok := s.storeMgr.Task(id)
	if !ok {
		audit.record(store.AuditEvent{
			Outcome: store.AuditFailed,
			Status:  http.StatusNotFound,
			Reason:  "任务不存在或已被清理",
		})
		writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
			"error": "任务不存在: " + id,
			"hint": "任务状态保存在内存中（只保留最近若干条），" +
				"面板重启后旧任务的进度不可查；历史留痕请看 /api/store/audit。",
		})
		return
	}

	since := parseIntDefault(r.URL.Query().Get("since"), 0)
	if since < 0 {
		since = 0
	}
	logs, _ := s.storeMgr.TaskLogs(id, since)

	// 下一次的游标：本次最后一条日志的序号；没有新日志时保持原游标。
	next := since
	if len(logs) > 0 {
		next = logs[len(logs)-1].Seq
	}

	done := task.Status == store.TaskSucceeded || task.Status == store.TaskFailed
	audit.record(store.AuditEvent{
		Outcome: store.AuditAllowed,
		Status:  http.StatusOK,
		TaskID:  id,
	})

	writeJSON(w, s.logger, http.StatusOK, storeTaskResponse{
		Task:      task,
		Logs:      logs,
		Since:     since,
		NextSince: next,
		Done:      done,
	})
}

// ---------------------------------------------------------------------------
// POST /api/store/{name}/install —— 安装
// ---------------------------------------------------------------------------

// storeActionRequest 是安装/卸载请求体。
type storeActionRequest struct {
	// Version 是版本 ID；省略时使用清单里的默认版本。
	Version string `json:"version"`
	// SkipDependencies 为 true 时不自动安装依赖。
	SkipDependencies bool `json:"skip_dependencies"`
}

// handleStoreInstall 发起安装任务（返回 202 + 任务 ID）。
func (s *Server) handleStoreInstall(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	audit := s.beginStoreAudit(r, store.ActionInstall, name)

	// 顺序固定：校验 → 权限 → 执行 → 审计。
	// 权限判定放在**解析请求体之前**有一个额外好处：
	// 被拒绝的请求连 JSON 解析都不会触发（拒绝路径没有任何副作用），
	// 这正是审计里 denied 的含义。
	if !s.requireStorePermission(w, audit) {
		return
	}

	if err := store.ValidSoftwareID(name); err != nil {
		audit.record(store.AuditEvent{
			Outcome: store.AuditDenied,
			Status:  http.StatusBadRequest,
			Reason:  err.Error(),
		})
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "软件 ID 只能是小写字母、数字、点、下划线与短横线。",
		})
		return
	}

	var req storeActionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, 1<<16, &req); err != nil {
			audit.record(store.AuditEvent{
				Outcome: store.AuditDenied,
				Status:  http.StatusBadRequest,
				Reason:  "请求体解析失败: " + err.Error(),
			})
			return
		}
	}
	audit.version = strings.TrimSpace(req.Version)

	task, err := s.storeMgr.StartInstall(r.Context(), store.InstallRequest{
		Software:         name,
		Version:          audit.version,
		User:             audit.user,
		ClientIP:         audit.ip,
		SkipDependencies: req.SkipDependencies,
	})
	if err != nil {
		s.writeStoreActionError(w, audit, err)
		return
	}

	audit.recordTask(task, http.StatusAccepted)
	writeJSON(w, s.logger, http.StatusAccepted, map[string]any{
		"task": task,
		"hint": "安装已在后台开始。请轮询 GET /api/store/tasks/" + task.ID +
			"?since=N 获取进度与日志；状态为 succeeded / failed 时结束。",
	})
}

// ---------------------------------------------------------------------------
// POST /api/store/{name}/uninstall —— 卸载
// ---------------------------------------------------------------------------

// handleStoreUninstall 发起卸载任务（返回 202 + 任务 ID）。
func (s *Server) handleStoreUninstall(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	audit := s.beginStoreAudit(r, store.ActionUninstall, name)

	if !s.requireStorePermission(w, audit) {
		return
	}

	if err := store.ValidSoftwareID(name); err != nil {
		audit.record(store.AuditEvent{
			Outcome: store.AuditDenied,
			Status:  http.StatusBadRequest,
			Reason:  err.Error(),
		})
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "软件 ID 只能是小写字母、数字、点、下划线与短横线。",
		})
		return
	}

	var req storeActionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, 1<<16, &req); err != nil {
			audit.record(store.AuditEvent{
				Outcome: store.AuditDenied,
				Status:  http.StatusBadRequest,
				Reason:  "请求体解析失败: " + err.Error(),
			})
			return
		}
	}
	audit.version = strings.TrimSpace(req.Version)

	task, err := s.storeMgr.StartUninstall(r.Context(), store.InstallRequest{
		Software: name,
		Version:  audit.version,
		User:     audit.user,
		ClientIP: audit.ip,
	})
	if err != nil {
		s.writeStoreActionError(w, audit, err)
		return
	}

	audit.recordTask(task, http.StatusAccepted)
	writeJSON(w, s.logger, http.StatusAccepted, map[string]any{
		"task": task,
		"hint": "卸载已在后台开始。请轮询 GET /api/store/tasks/" + task.ID +
			"?since=N 获取进度与日志。",
	})
}

// ---------------------------------------------------------------------------
// 错误映射
// ---------------------------------------------------------------------------

// writeStoreActionError 把 Manager 的错误映射成 HTTP 状态码 + 可读响应。
//
// ########## 为什么必须逐类映射，而不是一律 500 ##########
//
// 前端要根据状态码决定"要不要让用户改输入再试"：
//
//	400 参数不合法 / 404 软件不存在 → 用户改一下就能成功
//	409 已有任务在跑 / 版本冲突     → 用户**不要**重试，先处理冲突
//	503 环境没有包管理器            → 重试多少次都没用
//	500 其它                        → 可以重试
//
// 一律 500 会把"改个版本号就好"和"这台机器根本装不了"混成同一类，
// 用户只能反复点。
func (s *Server) writeStoreActionError(w http.ResponseWriter, a *storeAudit, err error) {
	status := http.StatusInternalServerError
	hint := ""

	switch {
	case errors.Is(err, store.ErrInvalidInput):
		status = http.StatusBadRequest
		hint = "请检查软件名与版本号；可用值见 GET /api/store 的 versions 列表。"
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
		hint = "该软件或版本不在商店清单里，请刷新页面获取最新列表。"
	case errors.Is(err, store.ErrConflict):
		status = http.StatusConflict
		hint = "同一软件只允许安装一个版本：请先卸载已安装的版本，再安装目标版本。" +
			"面板不会自动卸载——那会在你不知情时拆掉现有环境。"
	case errors.Is(err, store.ErrBusy):
		status = http.StatusConflict
		hint = "同一时刻只允许一个安装/卸载任务（apt/dpkg 与 rpm 都有全局锁）。" +
			"请等待当前任务结束，进度见 GET /api/store/tasks。"
	case errors.Is(err, store.ErrUnavailable):
		status = http.StatusServiceUnavailable
		hint = "本机未探测到可用的包管理器（apt-get / dnf / yum），无法安装软件。" +
			"面板的其它功能不受影响。"
	case errors.Is(err, store.ErrTimeout):
		status = http.StatusGatewayTimeout
		hint = "操作超时。包管理器可能仍在运行，请先用 ps 确认，" +
			"不要立即重试（会与它抢同一把全局锁）。"
	case errors.Is(err, store.ErrCommandFailed):
		status = http.StatusBadGateway
		hint = "外部命令执行失败，具体报错见响应中的 error 字段。"
	}

	a.record(store.AuditEvent{
		Outcome: store.AuditFailed,
		Status:  status,
		Reason:  err.Error(),
	})

	body := map[string]any{"error": err.Error()}
	if hint != "" {
		body["hint"] = hint
	}
	s.logger.Warn("软件商店操作失败",
		"user", a.user, "action", a.action, "target", a.target, "status", status, "err", err)
	writeJSON(w, s.logger, status, body)
}

// parseIntDefault 在 server 层已存在（4.1 引入），此处不重复定义。
