package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/file"
)

// ============================================================================
// 文件管理接口（阶段四 4.2，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET    /api/files             列目录（?path=）
//	GET    /api/files/roots       白名单根目录与运行限制
//	GET    /api/files/content     读取文本（?path=）
//	PUT    /api/files/content     保存文本（JSON 体）
//	GET    /api/files/download    下载（?path=，支持 Range）
//	POST   /api/files/upload      multipart 上传
//	POST   /api/files/mkdir       新建目录
//	POST   /api/files/rename      同目录重命名
//	POST   /api/files/delete      删除
//	GET    /api/files/audit       文件操作审计
//
// 与 4.1 服务接口的三点差异（都是有理由的，不是风格随意）：
//
//  1. **这里没有 {name} 通配段**，因此不存在"/audit 被通配吃掉"的注册顺序问题；
//     固定段与固定段之间不会互相遮蔽。
//  2. **写操作走 POST 而不是 REST 风格的 DELETE/PATCH**：删除要带 recursive
//     标志、重命名要带新名字，用 JSON 体表达比查询串更清楚，
//     也让前端的统一 request 封装更容易复用。
//  3. **每次写操作都记审计**，包括被权限或路径校验拒绝的请求——
//     越权路径探测在文件模块里是最值得留痕的信号（见 audit.go 的说明）。
func (s *Server) registerFileRoutes(mux *http.ServeMux) {
	if s.fileMgr == nil {
		// 未注入文件管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/files/", s.auth.RequireAuth(http.HandlerFunc(s.handleFilesUnavailable)))
		mux.Handle("/api/files", s.auth.RequireAuth(http.HandlerFunc(s.handleFilesUnavailable)))
		return
	}

	mux.Handle("GET /api/files", s.auth.RequireAuth(http.HandlerFunc(s.handleFileList)))

	// ⚠️ "/api/files/" 这个**前缀兜底必须注册**，而且它承担着两个作用：
	//
	//   ① 未注册的 /api/files/* 子路径返回 **JSON 404**，
	//      而不是落到前端 SPA 兜底（那会返回 200 + text/html，
	//      前端只会报一句"后端返回了非 JSON 内容"，无从判断原因）。
	//      这是实测发现的真实缺陷：没有它时 /api/files/does-not-exist
	//      返回的是 `<!doctype html>`，见 TestUnregisteredFileAPIPathReturnsJSON。
	//   ② 它顺带承接了"未注入文件管理器"的分支（见上面的 if）。
	//
	// 之所以能安全地注册前缀兜底：本模块的其余路由**首段全是固定字符串**
	// （roots/content/download/upload/mkdir/rename/delete/audit），
	// 不存在 {name} 这类通配段，因此最具体的模式总能优先命中，
	// 不会出现 4.1 里"/audit 被通配吃掉"的问题。
	mux.Handle("/api/files/", s.auth.RequireAuth(http.HandlerFunc(s.handleFileNotFound)))

	mux.Handle("GET /api/files/roots", s.auth.RequireAuth(http.HandlerFunc(s.handleFileRoots)))
	mux.Handle("GET /api/files/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleFileAudit)))
	mux.Handle("GET /api/files/content", s.auth.RequireAuth(http.HandlerFunc(s.handleFileRead)))
	mux.Handle("PUT /api/files/content", s.auth.RequireAuth(http.HandlerFunc(s.handleFileWrite)))
	mux.Handle("GET /api/files/download", s.auth.RequireAuth(http.HandlerFunc(s.handleFileDownload)))
	mux.Handle("POST /api/files/upload", s.auth.RequireAuth(http.HandlerFunc(s.handleFileUpload)))
	mux.Handle("POST /api/files/mkdir", s.auth.RequireAuth(http.HandlerFunc(s.handleFileMkdir)))
	mux.Handle("POST /api/files/rename", s.auth.RequireAuth(http.HandlerFunc(s.handleFileRename)))
	mux.Handle("POST /api/files/delete", s.auth.RequireAuth(http.HandlerFunc(s.handleFileDelete)))
}

// handleFileNotFound 处理 /api/files/* 下未注册的子路径。
//
// 返回 JSON 404（而不是交给前端兜底），并且**列出可用接口**——
// 这类 404 多半是前端或调用方把路径写错了，直接把正确的接口清单
// 摆在响应里，比让人去翻源码快得多。
func (s *Server) handleFileNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "文件接口不存在: " + r.URL.Path,
		"hint": "可用接口见 GET /api/files/roots 返回的能力说明，" +
			"或参考下方 available 列表。",
		"available": []string{
			"GET    /api/files?path=",
			"GET    /api/files/roots",
			"GET    /api/files/audit",
			"GET    /api/files/content?path=",
			"PUT    /api/files/content",
			"GET    /api/files/download?path=",
			"POST   /api/files/upload",
			"POST   /api/files/mkdir",
			"POST   /api/files/rename",
			"POST   /api/files/delete",
		},
	})
}

// handleFilesUnavailable 在文件管理器未注入时给出明确提示。
func (s *Server) handleFilesUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "文件管理未启用（服务启动时未注入文件管理器）",
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// fileAudit 收口一次文件操作的审计写入。
//
// 为什么要做成结构体而不是每次手写 file.AuditEvent：
// 每个接口都要填 user/action/path/client_ip/duration 这几个固定字段，
// 散落八处必然出现"某个接口忘了填 client_ip"这种不一致。
// 这里把公共字段一次性备好，出口只填可变部分。
type fileAudit struct {
	srv     *Server
	user    string
	action  string
	path    string
	target  string
	ip      string
	started time.Time
}

// beginFileAudit 构造一次操作的审计上下文。
func (s *Server) beginFileAudit(r *http.Request, action, path string) *fileAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &fileAudit{
		srv:     s,
		user:    user,
		action:  action,
		path:    path,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计（outcome 见 file.AuditAllowed/Denied/Failed）。
func (a *fileAudit) record(outcome string, status int, reason, resolved string, n int64) {
	a.srv.fileMgr.Auditor().Record(file.AuditEvent{
		User:         a.user,
		Action:       a.action,
		Path:         a.path,
		Target:       a.target,
		ResolvedPath: resolved,
		Root:         a.srv.fileMgr.Resolver().Rel(resolved),
		Required:     file.RequiredPermission(a.action),
		Outcome:      outcome,
		Status:       status,
		Bytes:        n,
		DurationMS:   time.Since(a.started).Milliseconds(),
		ClientIP:     a.ip,
		Reason:       reason,
	})
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireFilePermission 判定当前用户能否执行某文件动作。
//
// 顺序与 4.1 一致且不可调换：**先判权限，再碰文件系统**。
// 被拒绝的请求绝不能产生任何副作用，这样审计里 denied 的含义才是确定的
// （"请求没到达文件系统"），而不是"跑了但被拦下"。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireFilePermission(w http.ResponseWriter, a *fileAudit, resolved string) bool {
	grantee := file.AdminGrantee(a.user)
	decision := file.CheckFilePermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(file.AuditDenied, http.StatusForbidden, decision.Reason, resolved, 0)
	// 响应头与插件/服务权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("文件操作被权限校验拒绝",
		"user", a.user, "action", a.action, "path", a.path, "required", decision.Required)
	writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
		"error":    decision.Reason,
		"hint":     decision.Hint,
		"required": decision.Required,
		"granted":  decision.Granted,
	})
	return false
}

// ---------------------------------------------------------------------------
// GET /api/files —— 列目录
// ---------------------------------------------------------------------------

// handleFileList 列出目录内容。
//
// 目录不存在/不是目录/越权都是**读操作**，按权限模型只需 file.read，
// 因此写操作才记审计（否则高频浏览会把环形缓冲刷满）。
// 但有一类例外：**越权路径探测即使发生在读操作上也要留痕**——
// 那是安全信号，而不是普通浏览。
func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	path := queryPath(r, "path")
	audit := s.beginFileAudit(r, file.ActionList, path)

	listing, err := s.fileMgr.List(path)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionList, path)
		if isPathViolation(err) {
			// 越权/非法路径：即使只是"读"，也必须留痕。
			audit.record(file.AuditDenied, status, err.Error(), "", 0)
		}
		return
	}
	writeJSON(w, s.logger, http.StatusOK, listing)
}

// handleFileRoots 返回白名单根目录与运行限制。
//
// 前端据此渲染"可访问区域"提示与上传大小上限，属于只读元信息。
func (s *Server) handleFileRoots(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := file.AdminGrantee(user)

	roots := s.fileMgr.Resolver().Roots()
	list := make([]map[string]string, 0, len(roots))
	for _, root := range roots {
		list = append(list, map[string]string{"path": root.Path})
	}
	limits := s.fileMgr.Limits()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"roots": list,
		// permissions 只是**体验优化**（无权限时置灰按钮），
		// 真正的强制点始终在 requireFilePermission。
		"permissions": grantee.Granted,
		"limits": map[string]any{
			"max_upload_bytes": limits.MaxUploadBytes,
			"max_edit_bytes":   limits.MaxEditBytes,
			"max_list_entries": limits.MaxListEntries,
		},
		"audit": s.fileMgr.Auditor().Stats(),
	})
}

// ---------------------------------------------------------------------------
// GET/PUT /api/files/content —— 读写文本
// ---------------------------------------------------------------------------

// handleFileRead 读取文本文件内容。
func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	path := queryPath(r, "path")
	audit := s.beginFileAudit(r, file.ActionRead, path)

	content, err := s.fileMgr.ReadText(path)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionRead, path)
		if isPathViolation(err) {
			audit.record(file.AuditDenied, status, err.Error(), "", 0)
		}
		return
	}
	writeJSON(w, s.logger, http.StatusOK, content)
}

// fileWriteRequest 是保存文本的请求体。
type fileWriteRequest struct {
	Path string `json:"path"`
	// Content 是文件完整内容（非增量补丁）。面板的编辑器是"全量保存"语义，
	// 增量需要版本号与冲突解决，那是另一个量级的功能。
	Content string `json:"content"`
	// Overwrite 必须显式为 true 才允许覆盖已有文件（默认拒绝）。
	Overwrite bool `json:"overwrite"`
}

// handleFileWrite 保存文本文件内容。
func (s *Server) handleFileWrite(w http.ResponseWriter, r *http.Request) {
	var req fileWriteRequest
	// bodyLimit 需要一点余量：JSON 里的中文按 \uXXXX 会被转义成 6 字节，
	// 直接卡在 maxEditBytes 上会让"刚好到上限的中文文件"永远保存不了。
	limit := s.fileMgr.Limits().MaxEditBytes*6 + 64*1024
	if err := decodeJSONBody(w, r, limit, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint":  "请求体必须是 JSON，且不超过可编辑上限的转义余量。",
		})
		return
	}

	audit := s.beginFileAudit(r, file.ActionWrite, req.Path)
	// 权限先判：被拒绝的请求绝不触碰文件系统。
	if !s.requireFilePermission(w, audit, "") {
		return
	}

	result, err := s.fileMgr.WriteText(req.Path, []byte(req.Content), req.Overwrite)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionWrite, req.Path)
		audit.record(file.AuditFailed, status, err.Error(), "", 0)
		return
	}

	audit.record(file.AuditAllowed, http.StatusOK, "", result.Path, result.Size)
	s.logger.Info("文件已保存",
		"user", audit.user, "path", result.Path, "bytes", result.Size, "created", result.Created)
	writeJSON(w, s.logger, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// GET /api/files/download —— 下载
// ---------------------------------------------------------------------------

// handleFileDownload 以附件形式下发文件。
//
// 用 http.ServeContent 而不是 io.Copy：
//   - 自动处理 Range（断点续传/多线程下载）与 If-Modified-Since；
//   - 自动给出 Content-Length，浏览器才能显示进度。
//
// 超时处理：server.go 里全局 WriteTimeout 是 60s，对大文件是致命的
// （下到一半连接被掐）。这里用 ResponseController 针对**本请求**延长写超时，
// 而不是把全局超时调大——全局调大会让慢速攻击也获得同样的宽容。
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	path := queryPath(r, "path")
	audit := s.beginFileAudit(r, file.ActionDownload, path)

	f, info, err := s.fileMgr.OpenForDownload(path)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionDownload, path)
		if isPathViolation(err) {
			audit.record(file.AuditDenied, status, err.Error(), "", 0)
		}
		return
	}
	defer func() { _ = f.Close() }()

	if ctl := http.NewResponseController(w); ctl != nil {
		if err := ctl.SetWriteDeadline(time.Now().Add(downloadTimeout)); err != nil {
			// 不支持 SetWriteDeadline 的环境（少见）只记录，不阻断下载。
			s.logger.Debug("无法延长下载写超时", "path", path, "err", err)
		}
	}

	// Content-Disposition 用 RFC 5987 的 filename* 承载 UTF-8 文件名，
	// 同时给出 ASCII 兜底：中文文件名在旧浏览器上会乱码，
	// 而只写 filename= 又会被 net/http 拒绝（非法 header 字符）。
	name := filepath.Base(info.Name())
	w.Header().Set("Content-Disposition", contentDisposition(name))
	w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(name)))
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	// 防止浏览器把上传的 HTML 当页面渲染（存储型 XSS 的经典入口）。
	w.Header().Set("X-Content-Type-Options", "nosniff")

	audit.record(file.AuditAllowed, http.StatusOK, "", path, info.Size())
	// ServeContent 需要 ReadSeeker；*os.File 满足。
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// contentDisposition 构造安全的 Content-Disposition 头。
//
// ASCII 兜底名里所有非安全字符都替换成下划线（避免 header 注入与乱码），
// UTF-8 原名放在 filename* 里由现代浏览器优先采用。
func contentDisposition(name string) string {
	var ascii strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			ascii.WriteRune('_')
			continue
		}
		ascii.WriteRune(r)
	}
	fallback := ascii.String()
	if fallback == "" {
		fallback = "download"
	}
	// url.PathEscape 用于 filename*，但它的转义集不含 '+' 等字符，
	// 这里自行做最小转义即可（浏览器按 RFC 5987 解析）。
	escaped := strings.NewReplacer(
		"%", "%25", " ", "%20", "'", "%27", "(", "%28", ")", "%29",
	).Replace(name)
	return fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", fallback, escaped)
}

// ---------------------------------------------------------------------------
// POST /api/files/upload —— 上传
// ---------------------------------------------------------------------------

// handleFileUpload 处理 multipart 上传。
//
// 流式落盘（MultipartReader 逐段读、直接写临时文件），**不调用 ParseMultipartForm**：
// 后者会把文件写进内存或临时目录再拷贝一遍，大文件下等于磁盘写两次，
// 而且它的 maxMemory 参数很容易被误当成"文件大小上限"。
//
// 两道大小限制互为兜底：
//   - http.MaxBytesReader 卡在 HTTP 层（含 multipart 边界开销）；
//   - Manager.Upload 内部的 LimitReader 卡在业务层（真实文件字节数）。
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	limits := s.fileMgr.Limits()
	// 给 multipart 边界与其它字段留 1 MiB 余量，否则"刚好等于上限"的文件会被误杀。
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxUploadBytes+1<<20)

	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "请求不是合法的 multipart 上传: " + err.Error(),
			"hint":  "请使用 multipart/form-data 提交 file 字段。",
		})
		return
	}

	// 上传期间读体可能很慢（大文件 + 慢网络），
	// 与下载同理地延长本请求的读超时，避免传一半被掐。
	if ctl := http.NewResponseController(w); ctl != nil {
		if err := ctl.SetReadDeadline(time.Now().Add(uploadTimeout)); err != nil {
			s.logger.Debug("无法延长上传读超时", "err", err)
		}
	}

	audit := s.beginFileAudit(r, file.ActionUpload, "")
	target := ""
	filename := ""
	overwrite := false
	var result *file.UploadResult
	var uploadErr error
	var failStatus int

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.writeUploadFailure(w, audit, target, err)
			return
		}

		switch part.FormName() {
		case "path":
			target = strings.TrimSpace(readSmallPart(part))
		case "filename":
			filename = strings.TrimSpace(readSmallPart(part))
		case "overwrite":
			overwrite = parseBool(readSmallPart(part))
		case "file":
			// 文件字段名可以是客户端给的名字，服务端以 filename 字段为准，
			// 没有时退回 part.FileName()——两者都经过 validateName 校验。
			audit.path = target
			if !s.requireFilePermission(w, audit, "") {
				return
			}
			if filename == "" {
				filename = filepath.Base(part.FileName())
			}
			if filename == "" || filename == "." || filename == string(filepath.Separator) {
				writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
					"error": "缺少文件名",
					"hint":  "请提供 filename 字段，或让 file 段自带文件名。",
				})
				return
			}
			result, uploadErr = s.fileMgr.Upload(file.UploadOptions{
				Path:      target,
				Filename:  filename,
				Reader:    part,
				Overwrite: overwrite,
			})
			if uploadErr != nil {
				failStatus = s.writeFileError(w, uploadErr, file.ActionUpload, filepath.Join(target, filename))
			}
			_ = part.Close()
		default:
			// 未知字段直接丢弃：不报错，便于前端将来加字段而不破坏旧后端。
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
		}
	}

	audit.path = target
	if uploadErr != nil {
		audit.record(file.AuditFailed, failStatus, uploadErr.Error(), "", 0)
		return
	}
	if result == nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "请求中没有 file 字段",
			"hint":  "上传表单必须包含名为 file 的文件字段。",
		})
		return
	}

	audit.record(file.AuditAllowed, http.StatusOK, "", result.Path, result.Size)
	s.logger.Info("文件已上传",
		"user", audit.user, "path", result.Path, "bytes", result.Size, "overwrite", overwrite)
	writeJSON(w, s.logger, http.StatusOK, result)
}

// writeUploadFailure 处理 multipart 解析阶段的失败（含超限）。
func (s *Server) writeUploadFailure(w http.ResponseWriter, audit *fileAudit, target string, err error) {
	audit.path = target
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		audit.record(file.AuditFailed, http.StatusRequestEntityTooLarge, err.Error(), "", 0)
		writeJSON(w, s.logger, http.StatusRequestEntityTooLarge, map[string]any{
			"error": fmt.Sprintf("上传内容超过上限（%d 字节）", maxErr.Limit),
			"hint":  "请分卷上传，或调大启动参数 -file-max-upload。",
		})
		return
	}
	audit.record(file.AuditFailed, http.StatusBadRequest, err.Error(), "", 0)
	writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
		"error": "读取上传内容失败: " + err.Error(),
		"hint":  "连接可能已中断，请重试。",
	})
}

// readSmallPart 读取 multipart 中的小字段（限 4 KiB，防止畸形请求撑爆内存）。
func readSmallPart(part io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(part, 4096))
	if err != nil {
		return ""
	}
	return string(b)
}

// parseBool 解析表单里的布尔值（前端可能传 "true"/"1"/"on"）。
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// POST /api/files/mkdir | rename | delete —— 三个写操作
// ---------------------------------------------------------------------------

// filePathRequest 是 mkdir/delete 的请求体。
type filePathRequest struct {
	Path string `json:"path"`
	// All 用于 mkdir：是否创建缺失的上级目录（默认 false）。
	All bool `json:"all"`
	// Recursive 用于 delete：是否递归删除非空目录（默认 false）。
	Recursive bool `json:"recursive"`
}

// fileRenameRequest 是 rename 的请求体。
type fileRenameRequest struct {
	Path string `json:"path"`
	// NewName 是**新文件名**（不是路径）：本阶段只支持同目录改名。
	NewName string `json:"new_name"`
	// Overwrite 为 true 时允许覆盖同名目标。
	Overwrite bool `json:"overwrite"`
}

// handleFileMkdir 新建目录。
func (s *Server) handleFileMkdir(w http.ResponseWriter, r *http.Request) {
	var req filePathRequest
	if err := decodeJSONBody(w, r, 8*1024, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	audit := s.beginFileAudit(r, file.ActionMkdir, req.Path)
	if !s.requireFilePermission(w, audit, "") {
		return
	}

	entry, err := s.fileMgr.Mkdir(req.Path, req.All)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionMkdir, req.Path)
		audit.record(file.AuditFailed, status, err.Error(), "", 0)
		return
	}
	audit.record(file.AuditAllowed, http.StatusOK, "", entry.Path, 0)
	s.logger.Info("目录已创建", "user", audit.user, "path", entry.Path, "all", req.All)
	writeJSON(w, s.logger, http.StatusOK, entry)
}

// handleFileRename 重命名。
func (s *Server) handleFileRename(w http.ResponseWriter, r *http.Request) {
	var req fileRenameRequest
	if err := decodeJSONBody(w, r, 8*1024, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	audit := s.beginFileAudit(r, file.ActionRename, req.Path)
	audit.target = req.NewName
	if !s.requireFilePermission(w, audit, "") {
		return
	}

	entry, err := s.fileMgr.Rename(req.Path, req.NewName, req.Overwrite)
	if err != nil {
		status := s.writeFileError(w, err, file.ActionRename, req.Path)
		audit.record(file.AuditFailed, status, err.Error(), "", 0)
		return
	}
	audit.record(file.AuditAllowed, http.StatusOK, "", entry.Path, 0)
	s.logger.Info("已重命名",
		"user", audit.user, "from", req.Path, "to", entry.Path)
	writeJSON(w, s.logger, http.StatusOK, entry)
}

// fileDeleteResponse 是删除成功的响应。
//
// 删除没有"结果对象"可返回，因此显式回一个 deleted 标记与路径：
// 前端据此给出确定的成功提示（"已删除 xxx"），而不是靠"没报错"猜测。
type fileDeleteResponse struct {
	Deleted bool   `json:"deleted"`
	Path    string `json:"path"`
	// Recursive 回显是否执行了递归删除，便于审计与界面提示对齐。
	Recursive bool `json:"recursive"`
}

// handleFileDelete 删除文件或目录。
func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	var req filePathRequest
	if err := decodeJSONBody(w, r, 8*1024, &req); err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	audit := s.beginFileAudit(r, file.ActionDelete, req.Path)
	if !s.requireFilePermission(w, audit, "") {
		return
	}

	if err := s.fileMgr.Delete(req.Path, req.Recursive); err != nil {
		status := s.writeFileError(w, err, file.ActionDelete, req.Path)
		audit.record(file.AuditFailed, status, err.Error(), "", 0)
		return
	}
	audit.record(file.AuditAllowed, http.StatusOK, "", "", 0)
	// 删除是最需要留痕的操作：用 Warn 级别打日志，便于在系统日志里直接看到。
	s.logger.Warn("已删除",
		"user", audit.user, "path", req.Path, "recursive", req.Recursive)
	writeJSON(w, s.logger, http.StatusOK, fileDeleteResponse{
		Deleted: true, Path: req.Path, Recursive: req.Recursive,
	})
}

// ---------------------------------------------------------------------------
// GET /api/files/audit —— 审计查询
// ---------------------------------------------------------------------------

// handleFileAudit 返回文件操作审计记录。
//
// 支持 ?user= / ?action= / ?path= / ?outcome= / ?limit= 过滤。
func (s *Server) handleFileAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := file.AuditFilter{
		User:    strings.TrimSpace(query.Get("user")),
		Action:  strings.TrimSpace(query.Get("action")),
		Path:    strings.TrimSpace(query.Get("path")),
		Outcome: strings.TrimSpace(query.Get("outcome")),
		Limit:   parseAuditLimit(query.Get("limit")),
	}
	auditor := s.fileMgr.Auditor()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": auditor.Query(filter),
		"stats":  auditor.Stats(),
		"filter": map[string]any{
			"user":    filter.User,
			"action":  filter.Action,
			"path":    filter.Path,
			"outcome": filter.Outcome,
			"limit":   effectiveAuditLimit(filter.Limit),
		},
		// scope_note 把"这份审计覆盖什么"写进响应，
		// 避免用户误以为它记录了系统里所有人的文件操作。
		"scope_note": "本审计只记录**经本面板发起**的文件操作（含被权限或路径校验拒绝的请求）。" +
			"在服务器上直接用 shell 执行的 cp/rm/vim 不会被记录。",
	})
}

// ---------------------------------------------------------------------------
// 公共辅助
// ---------------------------------------------------------------------------

// 大文件传输的超时。与 server.go 的全局 60s 不同，这两个值只在
// 上传/下载这两个接口上通过 ResponseController 生效。
const (
	downloadTimeout = 30 * time.Minute
	uploadTimeout   = 30 * time.Minute
)

// queryPath 取查询串里的 path 参数。
//
// 不用 strings.TrimSpace：路径里的空格是合法的（"我的 文件.txt"），
// 去掉会让用户永远访问不到该文件。空值判定交给 file 包（返回 ErrEmptyPath）。
func queryPath(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// decodeJSONBody 读取并解析 JSON 请求体，带大小上限。
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("请求体超过上限 %d 字节", maxErr.Limit)
		}
		if errors.Is(err, io.EOF) {
			return errors.New("请求体为空（应为 JSON）")
		}
		return fmt.Errorf("解析 JSON 请求体失败: %w", err)
	}
	return nil
}

// isPathViolation 判断错误是否属于"路径校验未通过"。
//
// 这类错误在文件模块里是**安全信号**（有人在探测越权路径），
// 即使发生在只读操作上也要留痕，因此单独识别。
func isPathViolation(err error) bool {
	return errors.Is(err, file.ErrOutsideRoot) ||
		errors.Is(err, file.ErrSymlinkEscape) ||
		errors.Is(err, file.ErrInvalidPath) ||
		errors.Is(err, file.ErrEmptyPath) ||
		errors.Is(err, file.ErrRelativePath)
}

// writeFileError 把 file 包的错误翻译成合适的 HTTP 状态码并写出响应。
//
// 这是"写操作必须有明确错误处理"要求的落点，也是"绝不裸奔 500"的保证。
// 状态码语义：
//
//	400 路径非法（相对路径、含 NUL、越权、符号链接逃逸、名称非法）
//	403 目标权限不足（文件系统层面，如 append-only 文件、只读挂载）
//	404 目标不存在
//	409 目标已存在 / 目录非空
//	413 内容超过上限
//	415 不是 UTF-8 文本（含二进制）
//	507 磁盘空间不足 / 配额用尽
//	500 其它错误（透传底层原因）
//
// 返回值是实际写出的状态码，供调用方写入审计记录
// （避免审计里的 status 与真实响应不一致——4.1 的同一做法）。
func (s *Server) writeFileError(w http.ResponseWriter, err error, action, path string) int {
	write := func(status int, payload map[string]any) int {
		writeJSON(w, s.logger, status, payload)
		return status
	}
	errText := err.Error()

	// 顺序说明：先判"路径越权/非法"，再判底层文件系统错误。
	// 因为越权错误在实现里也包着 os 的错误链，若不先判就会
	// 被翻译成 404/403，把"这是越权探测"这个关键信息丢掉。
	switch {
	case errors.Is(err, file.ErrEmptyPath):
		return write(http.StatusBadRequest, map[string]any{
			"error": "缺少 path 参数",
			"hint":  "所有文件接口都需要 path 参数，且必须是绝对路径（以 / 开头）。",
		})

	case errors.Is(err, file.ErrRelativePath):
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "面板不接受相对路径：请先用 GET /api/files 拿到条目的绝对路径，" +
				"再原样传回。",
			"path": path,
		})

	case errors.Is(err, file.ErrOutsideRoot), errors.Is(err, file.ErrSymlinkEscape):
		// 这两个是本模块最关键的安全出口：日志用 Warn，
		// 便于运维在日志里直接看到"有人在尝试越权访问"。
		s.logger.Warn("文件路径校验拒绝",
			"action", action, "path", path, "reason", errText)
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint": "该路径不在启动参数 -file-root 允许的根目录内。" +
				"若确有需要，请调整启动参数后重启面板。",
			"path": path,
		})

	case errors.Is(err, file.ErrInvalidPath):
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint":  "请检查路径或文件名的形态（不能为空、不能含 NUL 或多余的路径分隔符）。",
			"path":  path,
		})

	case errors.Is(err, file.ErrTooLarge):
		return write(http.StatusRequestEntityTooLarge, map[string]any{
			"error": errText,
			"hint": "可调整启动参数 -file-max-upload / -file-max-edit，" +
				"大文件建议下载后用本地编辑器处理。",
			"path": path,
		})

	case errors.Is(err, file.ErrBinaryFile):
		return write(http.StatusUnsupportedMediaType, map[string]any{
			"error": errText,
			"hint": "内置编辑器只处理 UTF-8 纯文本。二进制文件请下载后用本地工具修改，" +
				"避免在文本域里被破坏。",
			"path": path,
		})

	case errors.Is(err, file.ErrExists):
		return write(http.StatusConflict, map[string]any{
			"error": errText,
			"hint":  "目标已存在。若确认要覆盖，请勾选「覆盖」后重试。",
			"path":  path,
		})

	case errors.Is(err, file.ErrNotEmpty):
		return write(http.StatusConflict, map[string]any{
			"error": errText,
			"hint":  "目录非空。递归删除不可恢复，需显式确认 recursive=true。",
			"path":  path,
		})

	case errors.Is(err, file.ErrNotDirectory):
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint":  "该接口要求 path 指向一个目录。",
			"path":  path,
		})

	case errors.Is(err, file.ErrNotRegular):
		return write(http.StatusBadRequest, map[string]any{
			"error": errText,
			"hint":  "该接口只接受普通文件；目录、设备文件与链接目标不适用的请换用其它接口。",
			"path":  path,
		})

	case errors.Is(err, file.ErrDiskFull):
		// 磁盘满是运维必须立刻知道的事故，日志用 Error。
		s.logger.Error("文件写入失败：磁盘空间不足", "action", action, "path", path, "err", err)
		return write(http.StatusInsufficientStorage, map[string]any{
			"error": errText,
			"hint":  "服务器磁盘空间不足（或配额用尽）。请清理磁盘后重试。",
			"path":  path,
		})

	case errors.Is(err, fs.ErrNotExist):
		return write(http.StatusNotFound, map[string]any{
			"error": "文件或目录不存在：" + errText,
			"hint":  "请刷新列表确认该条目是否已被其它人删除或改名。",
			"path":  path,
		})

	case errors.Is(err, fs.ErrPermission):
		return write(http.StatusForbidden, map[string]any{
			"error": "权限不足：" + errText,
			"hint": "文件系统拒绝了本次操作。请检查该路径的属主与权限位，" +
				"或确认面板进程是否以足够的身份运行。",
			"path": path,
		})

	default:
		s.logger.Error("文件操作失败", "action", action, "path", path, "err", err)
		return write(http.StatusInternalServerError, map[string]any{
			"error":  errText,
			"path":   path,
			"action": action,
		})
	}
}
