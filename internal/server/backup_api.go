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
	"lipanel/internal/backup"
)

// ============================================================================
// 备份恢复接口（阶段五 5.3，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/backup                          状态
//	GET    /api/backup/tasks                    任务列表
//	POST   /api/backup/tasks                    新增任务
//	PUT    /api/backup/tasks/{id}               编辑任务
//	DELETE /api/backup/tasks/{id}               删除任务（必须 confirm）
//	POST   /api/backup/tasks/{id}/run           立即执行
//	GET    /api/backup/tasks/{id}/history       该任务的执行历史
//	GET    /api/backup/files                    备份清单（?task_id=）
//	GET    /api/backup/files/download           下载（?storage_id=&key=）
//	DELETE /api/backup/files                    删除单个备份（必须 confirm）
//	POST   /api/backup/restore/preview          恢复预览（只读）
//	POST   /api/backup/restore                  执行恢复（**强制二次确认**）
//	GET    /api/backup/storages                 存储配置列表（凭证脱敏）
//	POST   /api/backup/storages                 新增存储配置
//	PUT    /api/backup/storages/{id}            编辑存储配置
//	DELETE /api/backup/storages/{id}            删除存储配置（必须 confirm）
//	POST   /api/backup/storages/test            连通性测试
//	GET    /api/backup/audit                    操作审计
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/backup/tasks"、"/api/backup/files"、"…/files/download"、
// "/api/backup/storages"、"…/storages/test" 这些**固定段**路由必须先于
// 任何通配注册。这是 4.1~4.6、5.1、5.2 连续踩过八次的同一个坑
// （见 开发计划.md「已知坑位」），这里从一开始就按纪律来，并有测试锁死。
//
// #################### 本模块接口最要紧的三件事 ####################
//
// ① **恢复必须二次确认（428 Precondition Required），且确认文字逐字匹配**
//
//	恢复会覆盖目标目录里的同名文件，是本模块唯一不可逆的动作。
//	服务端要求 confirm=true **且** confirm_text 等于任务名——
//	前端弹窗只是体验。
//
// ② **下载与删除只接受"能反查回任务"的对象名**
//
//	若接口直接拿一个对象名去存储上取，它就是一个「登录即可读取桶内
//	任意对象」的入口。因此 key 必须能反查到真实任务且落在其前缀之下
//	（backup.Manager.ResolveKey）。
//
// ③ **凭证一个字都不回显**
//
//	存储列表返回的已经是脱敏副本（Manager.ListStorages 内部调用
//	Redacted），handler 里没有任何"记得脱敏"的负担。
//	编辑时的密钥字段为 nil 表示"不改动"——不是清空。
func (s *Server) registerBackupRoutes(mux *http.ServeMux) {
	if s.backupMgr == nil {
		mux.Handle("/api/backup/", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupUnavailable)))
		mux.Handle("/api/backup", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupUnavailable)))
		return
	}

	mux.Handle("GET /api/backup", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStatus)))

	// ⚠️ 固定段路由必须先于通配注册（见文件头说明）。
	mux.Handle("GET /api/backup/tasks", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupTaskList)))
	mux.Handle("POST /api/backup/tasks", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupTaskCreate)))
	mux.Handle("PUT /api/backup/tasks/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupTaskUpdate)))
	mux.Handle("DELETE /api/backup/tasks/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupTaskDelete)))
	mux.Handle("POST /api/backup/tasks/{id}/run", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupRun)))
	mux.Handle("GET /api/backup/tasks/{id}/history", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupHistory)))

	mux.Handle("GET /api/backup/files", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupFiles)))
	mux.Handle("GET /api/backup/files/download", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupDownload)))
	mux.Handle("DELETE /api/backup/files", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupFileDelete)))

	mux.Handle("POST /api/backup/restore/preview", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupRestorePreview)))
	mux.Handle("POST /api/backup/restore", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupRestore)))

	mux.Handle("GET /api/backup/storages", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStorageList)))
	mux.Handle("POST /api/backup/storages", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStorageCreate)))
	mux.Handle("POST /api/backup/storages/test", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStorageTest)))
	mux.Handle("PUT /api/backup/storages/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStorageUpdate)))
	mux.Handle("DELETE /api/backup/storages/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupStorageDelete)))

	mux.Handle("GET /api/backup/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupAudit)))

	// 前缀兜底：未注册的 /api/backup/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html）。
	mux.Handle("/api/backup/", s.auth.RequireAuth(http.HandlerFunc(s.handleBackupNotFound)))
}

// handleBackupUnavailable 在备份管理器未注入时给出明确提示。
func (s *Server) handleBackupUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "备份恢复功能未启用（服务启动时未注入管理器）",
	})
}

// handleBackupNotFound 处理 /api/backup/* 下未注册的子路径。
func (s *Server) handleBackupNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "备份接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET    /api/backup",
			"GET    /api/backup/tasks",
			"POST   /api/backup/tasks",
			"PUT    /api/backup/tasks/{id}",
			"DELETE /api/backup/tasks/{id}?confirm=true",
			"POST   /api/backup/tasks/{id}/run",
			"GET    /api/backup/tasks/{id}/history?limit=50",
			"GET    /api/backup/files?task_id=",
			"GET    /api/backup/files/download?storage_id=&key=",
			"DELETE /api/backup/files?storage_id=&key=&confirm=true",
			"POST   /api/backup/restore/preview",
			"POST   /api/backup/restore",
			"GET    /api/backup/storages",
			"POST   /api/backup/storages",
			"PUT    /api/backup/storages/{id}",
			"DELETE /api/backup/storages/{id}?confirm=true",
			"POST   /api/backup/storages/test",
			"GET    /api/backup/audit?limit=100",
		},
	})
}

// backupLongTimeout 是备份执行与下载这两个接口的写超时。
//
// server.go 的全局 WriteTimeout 是 60s，对"打一个 30 GB 的包传给云存储"
// 是致命的（请求进行到一半连接被掐，而后面还在跑）。这里用
// ResponseController **只对本请求**放宽，而不是把全局超时调大——
// 后者会让慢速攻击也获得同样的宽容（与 4.2 的大文件下载同一手法）。
//
// 它必须**长于** backup 包的 ExecTimeout（默认 30 分钟）：
// 后端先超时并返回错误，前端才知道"到底发生了什么"；
// 反过来只会让前端报一个与真实原因无关的网络错误。
const backupLongTimeout = 35 * time.Minute

// extendWriteDeadline 只对当前请求放宽写超时。
func (s *Server) extendWriteDeadline(w http.ResponseWriter, what string) {
	ctl := http.NewResponseController(w)
	if ctl == nil {
		return
	}
	if err := ctl.SetWriteDeadline(time.Now().Add(backupLongTimeout)); err != nil {
		// 不支持 SetWriteDeadline 的环境（少见）只记录，不阻断操作：
		// 被掐断总好过直接拒绝执行一次用户明确要求的备份。
		s.logger.Debug("无法延长写超时", "op", what, "err", err)
	}
}

// ---------------------------------------------------------------------------
// 审计脚手架（与 4.2/4.6/5.2 同构）
// ---------------------------------------------------------------------------

// backupAudit 收口一次备份操作的审计写入。
type backupAudit struct {
	srv     *Server
	user    string
	action  backup.Action
	target  string
	ip      string
	started time.Time

	// 操作上下文（请求解析后填充）。
	taskID        string
	taskName      string
	sourcePath    string
	storageID     string
	storageType   string
	archiveKey    string
	archiveBytes  int64
	trigger       string
	confirmed     bool
	confirmTextOK bool
	restoreTarget string
	restored      int
	overwritten   int
	cronJobID     string
}

// beginBackupAudit 构造一次操作的审计上下文。
func (s *Server) beginBackupAudit(r *http.Request, action backup.Action, target string) *backupAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &backupAudit{
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
func (a *backupAudit) record(ev backup.AuditEvent) {
	ev.User = a.user
	ev.Action = string(a.action)
	if ev.Target == "" {
		ev.Target = a.target
	}
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.Required == "" {
		ev.Required = backup.RequiredPermission(a.action)
	}
	if ev.TaskID == "" {
		ev.TaskID = a.taskID
	}
	if ev.TaskName == "" {
		ev.TaskName = a.taskName
	}
	if ev.SourcePath == "" {
		ev.SourcePath = a.sourcePath
	}
	if ev.StorageID == "" {
		ev.StorageID = a.storageID
	}
	if ev.StorageType == "" {
		ev.StorageType = a.storageType
	}
	if ev.ArchiveKey == "" {
		ev.ArchiveKey = a.archiveKey
	}
	if ev.Trigger == "" {
		ev.Trigger = a.trigger
	}
	if !ev.Confirmed {
		ev.Confirmed = a.confirmed
	}
	if !ev.ConfirmTextOK {
		ev.ConfirmTextOK = a.confirmTextOK
	}
	if ev.RestoreTarget == "" {
		ev.RestoreTarget = a.restoreTarget
	}
	if ev.CronJobID == "" {
		ev.CronJobID = a.cronJobID
	}
	a.srv.backupMgr.Auditor().Record(ev)
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireBackupPermission 判定当前用户能否执行某备份动作。
//
// 顺序与其它核心模块一致且不可调换：**先判权限，再碰任何东西**。
// 被拒绝的请求绝不能产生任何副作用——对本模块而言，副作用是
// 「文件被打包送到了远端」或「目标目录被覆盖」。
func (s *Server) requireBackupPermission(w http.ResponseWriter, a *backupAudit) bool {
	grantee := backup.AdminGrantee(a.user)
	decision := backup.CheckBackupPermission(grantee, a.action)
	if decision.Allowed {
		return true
	}
	a.record(backup.AuditEvent{
		Outcome:  backup.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("备份操作被权限校验拒绝",
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

// backupErrorStatus 把 backup 包的语义错误映射为 HTTP 状态码。
//
// ########## 状态码的语义必须准确 ##########
//
//	400 输入非法（字段级校验）              —— 用户的输入问题
//	404 任务/存储/备份文件不存在            —— 可能已被别处删除
//	409 并发冲突 / 存储被引用 / 已有执行在跑 —— 当前状态不允许此操作
//	413 归档超出体积或条目数上限            —— 数据太大
//	428 缺少二次确认 / 确认文字不匹配        —— 请求合法但需要显式确认
//	503 crontab 或存储后端不可用             —— 环境没这个能力（不是 bug）
//	502 存储/打包/解压失败                   —— 系统那侧出了状况
func backupErrorStatus(err error) (int, string) {
	var fieldErr *backup.ValidationError
	switch {
	// 带 id 的哨兵错误必须排在最前：它们被 %w 包装，
	// 若先撞上别的分支判定，"不存在"就可能被误判成别的类别。
	case errors.Is(err, backup.ErrTaskNotFound),
		errors.Is(err, backup.ErrStorageNotFound),
		errors.Is(err, backup.ErrObjectNotFound):
		return http.StatusNotFound, "对象不存在"
	case errors.Is(err, backup.ErrConfirmRequired),
		errors.Is(err, backup.ErrConfirmTextMismatch):
		return http.StatusPreconditionRequired, "缺少二次确认"
	case errors.Is(err, backup.ErrEditConflict):
		return http.StatusConflict, "配置已被外部修改"
	case errors.Is(err, backup.ErrStorageInUse):
		return http.StatusConflict, "存储配置仍被引用"
	case errors.Is(err, backup.ErrRunning):
		return http.StatusConflict, "已有执行在进行"
	case errors.Is(err, backup.ErrCronUnavailable):
		return http.StatusServiceUnavailable, "计划任务不可用"
	case errors.Is(err, backup.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "超出体积或条目数上限"
	case errors.Is(err, backup.ErrArchiveUnsafe):
		return http.StatusBadRequest, "备份归档不安全"
	case errors.Is(err, backup.ErrSourceUnavailable):
		return http.StatusBadRequest, "备份源不可用"
	case errors.As(err, &fieldErr):
		return http.StatusBadRequest, "输入非法"
	default:
		return http.StatusBadGateway, "备份操作失败"
	}
}

// writeBackupError 统一写出备份操作错误。
func (s *Server) writeBackupError(w http.ResponseWriter, a *backupAudit, err error) {
	status, kind := backupErrorStatus(err)

	if status == http.StatusPreconditionRequired {
		// 按 RFC 6585 给出提示，让客户端知道「补上确认再重试」。
		w.Header().Set("X-Lipanel-Confirm-Required", "true")
	}

	ev := backup.AuditEvent{
		Outcome:       backup.AuditDenied,
		Status:        status,
		Reason:        err.Error(),
		Required:      backup.RequiredPermission(a.action),
		Confirmed:     a.confirmed,
		ConfirmTextOK: a.confirmTextOK,
	}
	a.record(ev)

	payload := map[string]any{
		"error":  err.Error(),
		"kind":   kind,
		"status": status,
	}
	// 字段名：让前端能直接把错误挂到对应表单项上。
	var ve *backup.ValidationError
	if errors.As(err, &ve) {
		payload["field"] = ve.Field
	}
	switch status {
	case http.StatusPreconditionRequired:
		if errors.Is(err, backup.ErrConfirmTextMismatch) {
			payload["hint"] = "恢复会覆盖目标目录里的同名文件，且无法撤销。" +
				"请在确认框里**逐字输入任务名**后再提交。"
		} else {
			payload["hint"] = "该操作会删除或覆盖数据，必须在请求里显式带上 confirm=true。"
		}
	case http.StatusConflict:
		switch {
		case errors.Is(err, backup.ErrStorageInUse):
			payload["hint"] = "请先修改或删除引用了该存储的备份任务，再删除这个存储配置。" +
				"直接删掉会让那些任务在下一次执行时才失败。"
		case errors.Is(err, backup.ErrRunning):
			payload["hint"] = "该任务已有一次备份正在执行。等它结束后再试——" +
				"并发执行会互相覆盖同一份备份。"
		default:
			payload["hint"] = "配置在你编辑期间被别处改过。请**刷新列表后重新编辑**，" +
				"不要直接重试提交——重试会覆盖别人的改动。"
		}
	case http.StatusNotFound:
		payload["hint"] = "对象可能已被删除，请刷新列表后重试。"
	case http.StatusServiceUnavailable:
		payload["hint"] = "这台机器现在无法管理 crontab：通常是没装 cron，" +
			"或面板运行身份没有权限。备份任务仍可保存并手动执行；" +
			"验证与开发环境可用 -cron-file 指向一个隔离文件。"
	case http.StatusRequestEntityTooLarge:
		payload["hint"] = "请收窄源路径，或用启动参数提高 -backup-max-bytes / -backup-max-entries 上限。"
	}
	writeJSON(w, s.logger, status, payload)
}

// ---------------------------------------------------------------------------
// GET /api/backup —— 状态
// ---------------------------------------------------------------------------

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	audit := s.beginBackupAudit(r, backup.ActionList, "status")

	st := s.backupMgr.Status(r.Context())
	audit.record(backup.AuditEvent{
		Outcome: backup.AuditAllowed,
		Status:  http.StatusOK,
		Mode:    st.CronMode,
	})

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"status":            st,
		"permissions":       backup.AdminGrantee(user).Granted,
		"confirm_required":  true,
		"storage_types":     backup.StorageTypes(),
		"keep_policies":     backup.KeepPolicies(),
		"cron_install_hint": backupCronInstallHint(st),
		"restore_hint": "恢复是不可撤销的：面板会**覆盖**目标目录里与归档同名的文件，" +
			"且需要逐字输入任务名才能继续。",
	})
}

// backupCronInstallHint 在 crontab 不可用时给出可操作的指引。
func backupCronInstallHint(st backup.Status) string {
	if st.CronAvailable {
		return ""
	}
	if st.CronMode == "file" {
		return "当前计划任务处于隔离文件模式（-cron-file），它不接系统 cron，" +
			"仅用于验证与开发。备份任务仍可手动执行。"
	}
	return "安装 cron：Debian/Ubuntu `apt-get install -y cron && systemctl enable --now cron`；" +
		"RHEL/Rocky `dnf install -y cronie && systemctl enable --now crond`。" +
		"没有 cron 时备份任务仍可保存并手动执行。"
}

// ---------------------------------------------------------------------------
// 任务
// ---------------------------------------------------------------------------

func (s *Server) handleBackupTaskList(w http.ResponseWriter, r *http.Request) {
	audit := s.beginBackupAudit(r, backup.ActionList, "tasks")

	tasks, err := s.backupMgr.ListTasks(r.Context())
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	if tasks == nil {
		tasks = []*backup.TaskView{}
	}
	audit.record(backup.AuditEvent{
		Outcome: backup.AuditAllowed, Status: http.StatusOK,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"tasks": tasks,
		"total": len(tasks),
	})
}

// maxBackupBodyBytes 是写请求体的上限。
//
// 任务字段都很短（最长的源路径 500 字节），存储配置里最长的
// 是凭证（500 字节）。64 KiB 已给出几十倍余量；给无限的好处是零，
// 代价是任何人可以用一个 1 GB 的 body 打满面板内存。
const maxBackupBodyBytes = 64 * 1024

// backupTaskRequest 是新增/编辑任务的请求体。
type backupTaskRequest struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	SourceType  string   `json:"source_type"`
	SourcePath  string   `json:"source_path"`
	StorageID   string   `json:"storage_id"`
	Prefix      string   `json:"prefix"`
	Expr        string   `json:"expr"`
	Comment     string   `json:"comment"`
	KeepPolicy  string   `json:"keep_policy"`
	KeepCount   int      `json:"keep_count"`
	KeepDays    int      `json:"keep_days"`
	Enabled     *bool    `json:"enabled"`
	ExpectedIDs []string `json:"expected_ids"`
	Confirm     bool     `json:"confirm"`
}

// toInput 转成 Manager 的输入。
//
// Enabled 用 *bool：省略该字段时默认**启用**（新建任务默认就该跑），
// 而显式传 false 表示停用。用 bool 的话零值 false 会让"没传"
// 变成"停用"——用户建完任务发现它从来不动，却看不出哪里错了。
func (q backupTaskRequest) toInput() backup.TaskInput {
	enabled := true
	if q.Enabled != nil {
		enabled = *q.Enabled
	}
	return backup.TaskInput{
		// 只有请求里**显式**带了 enabled=false 才算停用；
		// 省字段 = 启用（见 backup.TaskInput.Enabled 的说明）。
		DisableExplicit: q.Enabled != nil && !*q.Enabled,
		Name:        q.Name,
		Type:        q.Type,
		SourceType:  q.SourceType,
		SourcePath:  q.SourcePath,
		StorageID:   q.StorageID,
		Prefix:      q.Prefix,
		Expr:        q.Expr,
		Comment:     q.Comment,
		KeepPolicy:  q.KeepPolicy,
		KeepCount:   q.KeepCount,
		KeepDays:    q.KeepDays,
		Enabled:     enabled,
		ExpectedIDs: q.ExpectedIDs,
	}
}

// decodeBackupBody 解析 JSON 请求体（带大小上限）。
//
// 允许空 body：DELETE 走 query 参数确认时 body 就是空的。
func (s *Server) decodeBackupBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBackupBodyBytes))
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error":  "请求体不是合法 JSON：" + err.Error(),
			"kind":   "输入非法",
			"status": http.StatusBadRequest,
			"hint": fmt.Sprintf("请求体上限 %d 字节；写操作请带 Content-Type: application/json。",
				maxBackupBodyBytes),
		})
		return false
	}
	return true
}

func (s *Server) handleBackupTaskCreate(w http.ResponseWriter, r *http.Request) {
	var req backupTaskRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionCreate, "tasks")
	audit.taskName = strings.TrimSpace(req.Name)
	audit.sourcePath = strings.TrimSpace(req.SourcePath)
	audit.storageID = strings.TrimSpace(req.StorageID)
	audit.target = audit.taskName

	if !s.requireBackupPermission(w, audit) {
		return
	}

	view, err := s.backupMgr.CreateTask(r.Context(), req.toInput())
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.taskID = view.ID
	audit.cronJobID = view.CronJobID
	audit.storageType = view.StorageType
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
		Reason:       view.CronReason,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"task": view})
}

func (s *Server) handleBackupTaskUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req backupTaskRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionUpdate, id)
	audit.taskID = id
	audit.taskName = strings.TrimSpace(req.Name)
	audit.sourcePath = strings.TrimSpace(req.SourcePath)
	audit.storageID = strings.TrimSpace(req.StorageID)

	if !s.requireBackupPermission(w, audit) {
		return
	}

	view, err := s.backupMgr.UpdateTask(r.Context(), id, req.toInput())
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.cronJobID = view.CronJobID
	audit.storageType = view.StorageType
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
		Reason:       view.CronReason,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"task": view})
}

func (s *Server) handleBackupTaskDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req backupTaskRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	// confirm 走 query 或 body 都接受：curl 手敲更省事，前端走 body。
	// 两者取「或」，绝不取「与」——否则出现「传了 body 却忘了 query」
	// 这种无意义的失败。
	confirmed := req.Confirm ||
		r.URL.Query().Get("confirm") == "true" ||
		r.URL.Query().Get("confirm") == "1"

	audit := s.beginBackupAudit(r, backup.ActionDelete, id)
	audit.taskID = id
	audit.confirmed = confirmed

	if !s.requireBackupPermission(w, audit) {
		return
	}

	task, err := s.backupMgr.DeleteTask(r.Context(), id, confirmed, req.ExpectedIDs)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.taskName = task.Name
	audit.sourcePath = task.SourcePath
	audit.storageID = task.StorageID
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"deleted": true, "task": task})
}

// handleBackupRun 立即执行一次备份（同步等待）。
//
// ########## 为什么同步等待而不是"丢后台返回 202" ##########
//
// 备份的产物是**用户此刻就要确认的东西**：「上次执行」列要立刻
// 显示成功与大小，而不是"刷新几次看看"。同步返回还把失败原因
// 完整地交给了调用方（网络错误、权限、体积超限），
// 异步则需要前端再开一个轮询接口并自己拼装状态。
//
// 代价是请求可能持续几十分钟，因此超时预算在两边都单独放宽
// （后端 ExecTimeout、前端 30 分钟），且后端保证**长于**前端。
func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	audit := s.beginBackupAudit(r, backup.ActionRun, id)
	audit.taskID = id
	audit.trigger = backup.TriggerManual

	if !s.requireBackupPermission(w, audit) {
		return
	}

	// 备份可能跑几十分钟（打包 + 上传），必须放宽本请求的写超时。
	s.extendWriteDeadline(w, "backup_run")

	user, _ := auth.UsernameFrom(r.Context())
	res, err := s.backupMgr.RunNow(r.Context(), id, user)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	entry := res.Entry
	if entry != nil {
		audit.taskName = entry.TaskName
		audit.storageID = entry.StorageID
		audit.storageType = entry.StorageType
		audit.archiveKey = entry.ArchiveKey
		audit.archiveBytes = entry.ArchiveBytes
	}
	outcome := backup.AuditAllowed
	status := http.StatusOK
	reason := ""
	if entry != nil && entry.Status == backup.StatusFailed {
		// 备份"执行了但失败"不是接口层的错误（请求本身是成功的），
		// 但审计必须记成 failed——否则审计里全是 allowed，
		// 事后完全看不出"那次备份其实是失败的"。
		outcome = backup.AuditFailed
		reason = entry.Error
	}
	audit.record(backup.AuditEvent{
		Outcome:      outcome,
		Status:       status,
		SystemChange: entry != nil && entry.Status == backup.StatusOK,
		Reason:       reason,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"result":  res,
		"skipped": res.Skipped,
	})
}

func (s *Server) handleBackupHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			audit := s.beginBackupAudit(r, backup.ActionHistory, id)
			s.writeBackupError(w, audit, &backup.ValidationError{
				Field: "limit", Reason: fmt.Sprintf("必须是正整数，实际收到 %q", v),
			})
			return
		}
		limit = n
	}

	audit := s.beginBackupAudit(r, backup.ActionHistory, id)
	audit.taskID = id
	if !s.requireBackupPermission(w, audit) {
		return
	}

	entries, err := s.backupMgr.ReadHistory(id, limit)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	if entries == nil {
		entries = []*backup.HistoryEntry{}
	}
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   len(entries),
	})
}

// ---------------------------------------------------------------------------
// 备份清单 / 下载 / 删除
// ---------------------------------------------------------------------------

func (s *Server) handleBackupFiles(w http.ResponseWriter, r *http.Request) {
	audit := s.beginBackupAudit(r, backup.ActionList, "files")
	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))
	audit.taskID = taskID

	if !s.requireBackupPermission(w, audit) {
		return
	}

	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.writeBackupError(w, audit, &backup.ValidationError{
				Field: "limit", Reason: fmt.Sprintf("必须是正整数，实际收到 %q", v),
			})
			return
		}
		limit = n
	}

	files, err := s.backupMgr.ListFiles(r.Context(), taskID, limit)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	if files == nil {
		files = []backup.FileEntry{}
	}
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"files": files,
		"total": len(files),
	})
}

// handleBackupDownload 下载一个备份文件。
//
// ########## 这里没有任何"路径"参数 ##########
//
// 只接受 storage_id + key，且 key 必须能反查回一个真实任务
// 并落在它的前缀之下（Manager.ResolveKey）。若开一个 ?path=，
// 那就是「登录即可读取任意文件」——而本模块还能直接读本地存储目录。
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	storageID := strings.TrimSpace(r.URL.Query().Get("storage_id"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))

	audit := s.beginBackupAudit(r, backup.ActionDownload, key)
	audit.storageID = storageID
	audit.archiveKey = key

	if !s.requireBackupPermission(w, audit) {
		return
	}

	s.extendWriteDeadline(w, "backup_download")

	rc, size, name, err := s.backupMgr.OpenFile(r.Context(), storageID, key)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	defer func() { _ = rc.Close() }()

	// 文件名用**面板生成的对象名**（key 的末段），绝不回显用户输入。
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", sanitizeFilename(name)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	// 流式写出：备份可能很大，绝不整份读进内存。
	n, cerr := io.Copy(w, rc)
	if cerr != nil {
		// 响应头已发出，无法再改状态码；只能记录。
		s.logger.Warn("下载备份中断", "key", key, "written", n, "err", cerr)
	}
	s.backupMgr.Auditor().Record(backup.AuditEvent{
		Seq: 0, Kind: "backup", Source: backup.SourceCore,
		User: audit.user, Action: string(backup.ActionDownload), Target: key,
		ClientIP: audit.ip, Outcome: backup.AuditAllowed, Status: http.StatusOK,
		DurationMS: time.Since(audit.started).Milliseconds(),
		Required:   backup.RequiredPermission(backup.ActionDownload),
		StorageID:  storageID, ArchiveKey: key, ArchiveBytes: n,
		TaskID: audit.taskID,
	})
}

// sanitizeFilename 把文件名里可能干扰响应头的字符去掉。
//
// 对象名由面板生成（12 位 hex + 时间戳 + .tar.gz），本不该出现
// 引号或换行；但下载头是少数几个"内容直接进 HTTP 头"的地方，
// 这里再收一道防线（\r\n 注入可以伪造响应头）。
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("\r", "", "\n", "", "\"", "", "\\", "")
	out := replacer.Replace(strings.TrimSpace(name))
	if out == "" {
		return "backup.tar.gz"
	}
	return out
}

// handleBackupFileDelete 删除一个备份文件。
//
// 只删存储上的对象，**不删任务、也不动历史**：
// 用户删掉一个旧备份不该让"这个任务曾经成功备份过"这件事从界面上消失。
func (s *Server) handleBackupFileDelete(w http.ResponseWriter, r *http.Request) {
	storageID := strings.TrimSpace(r.URL.Query().Get("storage_id"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	confirmed := r.URL.Query().Get("confirm") == "true" ||
		r.URL.Query().Get("confirm") == "1"

	audit := s.beginBackupAudit(r, backup.ActionDeleteFile, key)
	audit.storageID = storageID
	audit.archiveKey = key
	audit.confirmed = confirmed

	if !s.requireBackupPermission(w, audit) {
		return
	}

	if err := s.backupMgr.DeleteFile(r.Context(), storageID, key, confirmed); err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.record(backup.AuditEvent{
		Outcome: backup.AuditAllowed, Status: http.StatusOK, SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"deleted": true, "key": key})
}

// ---------------------------------------------------------------------------
// 恢复
// ---------------------------------------------------------------------------

// backupRestoreRequest 是恢复预览/执行的请求体。
type backupRestoreRequest struct {
	StorageID string `json:"storage_id"`
	Key       string `json:"key"`
	TargetDir string `json:"target_dir"`
	// Confirm / ConfirmText 是二次确认（执行恢复时强制）。
	Confirm     bool   `json:"confirm"`
	ConfirmText string `json:"confirm_text"`
}

func (s *Server) handleBackupRestorePreview(w http.ResponseWriter, r *http.Request) {
	var req backupRestoreRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionPreview, req.Key)
	audit.storageID = req.StorageID
	audit.archiveKey = req.Key
	audit.restoreTarget = req.TargetDir

	if !s.requireBackupPermission(w, audit) {
		return
	}

	prev, err := s.backupMgr.PreviewRestoreFile(r.Context(), req.StorageID, req.Key, req.TargetDir)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.taskID = ""
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"preview": prev})
}

// handleBackupRestore 执行恢复。
//
// ########## 本接口是全模块唯一不可逆的入口 ##########
//
// 双重强制都在服务端：confirm=true **且** confirm_text 逐字等于任务名。
// 前端那个红色警示框与输入框只是体验；即便前端被绕过，
// 没有正确的确认文字也恢复不了任何东西。
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var req backupRestoreRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionRestore, req.Key)
	audit.storageID = req.StorageID
	audit.archiveKey = req.Key
	audit.restoreTarget = req.TargetDir
	audit.confirmed = req.Confirm

	if !s.requireBackupPermission(w, audit) {
		return
	}

	// 先查一次任务名，把"确认文字对不对"这件事在审计里如实记下来。
	// 注意：Manage.RestoreFile 内部还会独立比对一次——这里只是为了
	// 留痕（有人试图恢复但输错了名字，这本身是一个真实的信号），
	// 判定权仍然只有一处。
	if owner, _, _, rerr := s.backupMgr.ResolveKey(r.Context(), req.StorageID, req.Key); rerr == nil {
		audit.taskID = owner.ID
		audit.taskName = owner.Name
		audit.confirmTextOK = strings.TrimSpace(req.ConfirmText) == owner.Name
	}

	res, err := s.backupMgr.RestoreFile(r.Context(), req.StorageID, req.Key, req.TargetDir,
		req.Confirm, req.ConfirmText)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.restored = res.Restored
	audit.overwritten = res.Overwritten
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"result": res})
}

// ---------------------------------------------------------------------------
// 存储配置
// ---------------------------------------------------------------------------

func (s *Server) handleBackupStorageList(w http.ResponseWriter, r *http.Request) {
	audit := s.beginBackupAudit(r, backup.ActionList, "storages")

	// 凭证已由 Manager 脱敏；这里再补上"是否已设置"与尾 4 位，
	// 让用户能确认"我填的是不是那一把钥匙"。
	//
	// ⚠️ 这两个判断必须基于**仍有凭证的原始配置**：
	// 脱敏副本里的 SecretKey 已被清空，对它调 HasSecret()
	// 永远是 false——界面会永远显示"未设置密钥"，而备份其实是好的。
	items := s.storageItems()
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"storages": items,
		"total":    len(items),
	})
}

// storageItems 组装存储列表响应（脱敏 + "是否已设置凭证"）。
func (s *Server) storageItems() []map[string]any {
	raw, err := s.backupMgr.RawStorages()
	if err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(raw))
	for _, st := range raw {
		red := st.Redacted()
		out = append(out, map[string]any{
			"storage":       &red,
			"has_secret":    st.HasSecret(),
			"secret_tail":   st.SecretTail(),
			"has_password":  st.HasPassword(),
			"password_tail": st.PasswordTail(),
		})
	}
	return out
}

// backupStorageRequest 是新增/编辑存储配置的请求体。
//
// SecretKey / Password 用 *string：**省略或 null 表示"不改动"**
// （编辑时不传密钥是常态，因为接口不回显它）。显式传空串才表示清空。
type backupStorageRequest struct {
	Name               string  `json:"name"`
	Type               string  `json:"type"`
	Path               string  `json:"path"`
	Endpoint           string  `json:"endpoint"`
	Bucket             string  `json:"bucket"`
	Region             string  `json:"region"`
	AccessKey          string  `json:"access_key"`
	SecretKey          *string `json:"secret_key"`
	PathStyle          bool    `json:"path_style"`
	BasePath           string  `json:"base_path"`
	Username           string  `json:"username"`
	Password           *string `json:"password"`
	InsecureSkipVerify bool    `json:"insecure_skip_verify"`
	Confirm            bool    `json:"confirm"`
}

func (q backupStorageRequest) toInput() backup.StorageInput {
	return backup.StorageInput{
		Name:               q.Name,
		Type:               q.Type,
		Path:               q.Path,
		Endpoint:           q.Endpoint,
		Bucket:             q.Bucket,
		Region:             q.Region,
		AccessKey:          q.AccessKey,
		SecretKey:          q.SecretKey,
		PathStyle:          q.PathStyle,
		BasePath:           q.BasePath,
		Username:           q.Username,
		Password:           q.Password,
		InsecureSkipVerify: q.InsecureSkipVerify,
		Confirm:            q.Confirm,
	}
}

func (s *Server) handleBackupStorageCreate(w http.ResponseWriter, r *http.Request) {
	var req backupStorageRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionStorageCreate, strings.TrimSpace(req.Name))
	audit.storageType = strings.TrimSpace(req.Type)

	if !s.requireBackupPermission(w, audit) {
		return
	}

	st, err := s.backupMgr.CreateStorage(req.toInput())
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.storageID = st.ID
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"storage": st})
}

func (s *Server) handleBackupStorageUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req backupStorageRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionStorageUpdate, id)
	audit.storageID = id
	audit.storageType = strings.TrimSpace(req.Type)

	if !s.requireBackupPermission(w, audit) {
		return
	}

	st, err := s.backupMgr.UpdateStorage(id, req.toInput())
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.record(backup.AuditEvent{
		Outcome:      backup.AuditAllowed,
		Status:       http.StatusOK,
		SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"storage": st})
}

func (s *Server) handleBackupStorageDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req backupStorageRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	confirmed := req.Confirm ||
		r.URL.Query().Get("confirm") == "true" ||
		r.URL.Query().Get("confirm") == "1"

	audit := s.beginBackupAudit(r, backup.ActionStorageDelete, id)
	audit.storageID = id
	audit.confirmed = confirmed

	if !s.requireBackupPermission(w, audit) {
		return
	}

	usedBy, err := s.backupMgr.DeleteStorage(r.Context(), id, confirmed)
	if err != nil {
		// 被引用时把引用方的名字写进响应：只说"仍被引用"，
		// 用户还得自己去列表里找是哪几个任务。
		if errors.Is(err, backup.ErrStorageInUse) {
			status, kind := backupErrorStatus(err)
			w.Header().Set("X-Lipanel-Confirm-Required", "")
			audit.record(backup.AuditEvent{
				Outcome: backup.AuditDenied, Status: status, Reason: err.Error(),
				Required:  backup.RequiredPermission(backup.ActionStorageDelete),
				Confirmed: confirmed,
			})
			writeJSON(w, s.logger, status, map[string]any{
				"error":   err.Error(),
				"kind":    kind,
				"status":  status,
				"used_by": usedBy,
				"hint":    "请先修改或删除这些备份任务，再删除该存储配置。",
			})
			return
		}
		s.writeBackupError(w, audit, err)
		return
	}
	audit.record(backup.AuditEvent{
		Outcome: backup.AuditAllowed, Status: http.StatusOK, SystemChange: true,
	})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{"deleted": true})
}

// handleBackupStorageTest 测试存储连通性。
//
// 可以测一个已保存的配置（传 id），也可以测一个还没保存的配置
// （传完整字段）——后者才是用户真正需要的："我先试试能不能连上，
// 再决定要不要存下来"。此时若只允许传 id，用户就必须先保存
// 一个可能连不上的配置。
func (s *Server) handleBackupStorageTest(w http.ResponseWriter, r *http.Request) {
	var req backupStorageRequest
	if !s.decodeBackupBody(w, r, &req) {
		return
	}
	audit := s.beginBackupAudit(r, backup.ActionStorageTest, strings.TrimSpace(req.Name))
	audit.storageType = strings.TrimSpace(req.Type)

	if !s.requireBackupPermission(w, audit) {
		return
	}

	// 传了 id 且没有其它字段时，测已保存的配置。
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id != "" && strings.TrimSpace(req.Type) == "" {
		st, err := s.backupMgr.FindStorageRaw(id)
		if err != nil {
			s.writeBackupError(w, audit, err)
			return
		}
		if st == nil {
			s.writeBackupError(w, audit,
				fmt.Errorf("%w: %s", backup.ErrStorageNotFound, id))
			return
		}
		audit.storageID = st.ID
		audit.storageType = st.Type
		if err := s.backupMgr.TestStorage(r.Context(), *st); err != nil {
			s.writeBackupError(w, audit, err)
			return
		}
		audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
		writeJSON(w, s.logger, http.StatusOK, map[string]any{
			"ok": true, "message": "连通性正常（已写入并删除测试对象）",
		})
		return
	}

	// 否则测请求里给的配置。未保存时密钥必须随请求带上；
	// 若省略且配了 id，则从已保存的配置里补。
	in := req.toInput()
	if in.SecretKey == nil || *in.SecretKey == "" || in.Password == nil || *in.Password == "" {
		if id != "" {
			if saved, ferr := s.backupMgr.FindStorageRaw(id); ferr == nil && saved != nil {
				if in.SecretKey == nil || *in.SecretKey == "" {
					if saved.SecretKey != "" {
						v := saved.SecretKey
						in.SecretKey = &v
					}
				}
				if in.Password == nil || *in.Password == "" {
					if saved.Password != "" {
						v := saved.Password
						in.Password = &v
					}
				}
			}
		}
	}
	norm, err := backup.ValidateStorage(in)
	if err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	st := backup.Storage{
		ID: "test", Name: norm.Name, Type: norm.Type, Path: norm.Path,
		Endpoint: norm.Endpoint, Bucket: norm.Bucket, Region: norm.Region,
		AccessKey: norm.AccessKey, PathStyle: norm.PathStyle, BasePath: norm.BasePath,
		Username: norm.Username, InsecureSkipVerify: norm.InsecureSkipVerify,
	}
	if norm.SecretKey != nil {
		st.SecretKey = *norm.SecretKey
	}
	if norm.Password != nil {
		st.Password = *norm.Password
	}
	if err := s.backupMgr.TestStorage(r.Context(), st); err != nil {
		s.writeBackupError(w, audit, err)
		return
	}
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"ok": true, "message": "连通性正常（已写入并删除测试对象）",
	})
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

func (s *Server) handleBackupAudit(w http.ResponseWriter, r *http.Request) {
	audit := s.beginBackupAudit(r, backup.ActionList, "audit")

	limit := backup.DefaultAuditQueryLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.writeBackupError(w, audit, &backup.ValidationError{
				Field: "limit", Reason: fmt.Sprintf("必须是正整数，实际收到 %q", v),
			})
			return
		}
		limit = n
	}
	filter := backup.AuditFilter{
		TaskID:  r.URL.Query().Get("task_id"),
		User:    r.URL.Query().Get("user"),
		Outcome: r.URL.Query().Get("outcome"),
		Action:  r.URL.Query().Get("action"),
		Limit:   limit,
	}
	events := s.backupMgr.Auditor().Query(filter)
	audit.record(backup.AuditEvent{Outcome: backup.AuditAllowed, Status: http.StatusOK})
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": events,
		"stats":  s.backupMgr.Auditor().Stats(),
		"total":  len(events),
		"filter": map[string]string{
			"task_id": filter.TaskID,
			"user":    filter.User,
			"outcome": filter.Outcome,
			"action":  filter.Action,
		},
	})
}
