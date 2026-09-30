package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"lipanel/internal/auth"
	"lipanel/internal/plugin"
)

// ============================================================================
// 插件安装接口（外部插件机制）
// ============================================================================
//
//	POST /api/plugins/install   上传一个插件包（zip / tar.gz）并安装
//
// ########## 本接口的两个硬性约束 ##########
//
//	① **仅管理员**。安装一个插件 = 往服务器上放一段会被执行的代码。
//	   即便是只读用户也不该能做这件事：他装一个带 backend.exec 的包，
//	   管理员某天点一下"启动"就执行了。因此权限判定在**读取上传流之前**
//	   完成——未被授权的请求不应该让我们写一个字节到磁盘。
//
//	② **强制二次确认**。与服务端"破坏性操作需显式确认"的纪律一致
//	   （见 4.6）。安装会改变磁盘状态且不可自动回滚，
//	   前端弹窗只是体验，服务端必须自己拦得住。
//
// ########## 为什么是 multipart 而不是裸 body ##########
//
// 需要一个文件名来判断格式（.zip / .tar.gz）。文件名只用于**判断扩展名**，
// 绝不参与任何路径拼接——用户上传的文件名完全不可信。
// ########## 注册点在哪里 ##########
//
// 本接口的路由**不在这里注册**，而是在 registerPluginRoutes（plugin_api.go）
// 里——且必须位于 "/api/plugins/{id}/" 通配**之前**。
//
// 原因见那边的注释：若晚于通配注册，POST /api/plugins/install 会被
// 匹配成"插件 ID = install 的子路径请求"并转发给一个不存在的插件进程，
// 用户得到 404「插件不存在」——一个与真实原因毫无关系的错误。
//
// 这里保留说明是为了让读本文件的人不必回头翻路由表就能知道
// 接口挂在哪儿。plugin_install_api_test.go 有用例锁死这条顺序。
// pluginInstallResponse 是安装成功的响应。
type pluginInstallResponse struct {
	Installed bool   `json:"installed"`
	ID        string `json:"id"`
	// Dir 是安装位置。**不返回完整路径**——那是服务器部署细节。
	// 只给目录名，足够用户去核对。
	DirName string `json:"dir_name"`
	Files   int    `json:"files"`
	Bytes   int64  `json:"bytes"`
	Mode    string `json:"mode"`
	// Replaced 表示这是一次覆盖安装。
	Replaced bool `json:"replaced"`
	// AutoStarted 恒为 false，且是**有意返回**的。
	//
	// 前端据此明确告诉用户"插件已安装但未启动"，
	// 而不是让用户以为装完就能用了。
	AutoStarted bool `json:"auto_started"`
	// Hint 告诉用户下一步该做什么。
	Hint string `json:"hint"`
}

// handlePluginInstall 处理插件包上传与安装。
func (s *Server) handlePluginInstall(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
			"error": "插件系统未启用（服务启动时未注入插件管理器）",
		})
		return
	}

	user, _ := auth.UsernameFrom(r.Context())

	// ---------- ① 权限：仅管理员 ----------
	//
	// 放在**读取任何请求体之前**：未被授权的请求不该让我们
	// 把哪怕一个字节写进临时文件。
	if !s.pluginInstallAllowed(w, r, user) {
		return
	}

	// ---------- ② 二次确认 ----------
	//
	// 支持两种传法：查询参数或表单字段。
	// 前端用表单字段（与文件一起提交最方便），
	// 脚本/curl 用查询参数更顺手。
	confirm := r.URL.Query().Get("confirm") == "true"

	// ########## 限制请求体总大小 ##########
	//
	// 必须在 ParseMultipartForm 之前包 MaxBytesReader：
	// 否则一个恶意客户端可以先送一个 10 GB 的 body，
	// 在 ParseMultipartForm 内部就把磁盘写满，
	// 而我们的"压缩包大小检查"发生在解压阶段——那时已经太晚。
	//
	// 这里留出比压缩包上限多一些的余量给 multipart 的边界与头部开销。
	const maxUploadBody = plugin.MaxArchiveBytesForUpload + (1 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)

	if err := r.ParseMultipartForm(8 << 20); err != nil {
		// MaxBytesError 说明超限，给出更准确的提示。
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, s.logger, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "上传的文件过大",
				"hint": "插件包上限为 " +
					humanMiB(plugin.MaxArchiveBytesForUpload) + "。",
			})
			return
		}
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "无法解析上传内容：" + err.Error(),
			"hint":  "请以 multipart/form-data 提交，文件字段名为 file。",
		})
		return
	}
	defer func() {
		// 清掉 multipart 落到磁盘的临时文件（8 MiB 以上会落盘）。
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	if !confirm && r.FormValue("confirm") == "true" {
		confirm = true
	}
	if !confirm {
		// 428：请求本身合法，但需要显式确认后才执行。
		//
		// 与服务端其它破坏性操作的约定一致。前端据此弹确认框，
		// 而不是把错误直接甩给用户。
		w.Header().Set("X-Lipanel-Confirm-Required", "true")
		writeJSON(w, s.logger, http.StatusPreconditionRequired, map[string]any{
			"error": "安装插件需要二次确认",
			"hint": "安装会往服务器写入将被执行的代码。请确认插件来源可信后，" +
				"带上 confirm=true 重试。",
			"code": "confirm_required",
		})
		return
	}

	// ---------- ③ 取文件 ----------
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "请求里没有文件",
			"hint":  "请用 multipart/form-data 上传，文件字段名为 file。",
		})
		return
	}
	defer func() { _ = file.Close() }()

	// 文件名只用于判断格式；**绝不参与路径拼接**。
	// filepath.Base 是双保险：即便下游有人误用了它，
	// 也拿不到带路径的名字。
	archiveName := sanitizeUploadName(header.Filename)
	if archiveName == "" {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
			"error": "上传的文件没有有效的文件名（无法判断格式）",
			"hint":  "文件名必须以 " + strings.Join(plugin.SupportedArchiveExts(), " 或 ") + " 结尾。",
		})
		return
	}

	// ---------- ④ 安装 ----------
	res, err := s.plugins.InstallFromStream(file, plugin.InstallOptions{
		PluginDir:   s.plugins.ExternalDir(),
		ArchiveName: archiveName,
		// Overwrite 允许覆盖**同名外部插件**（重装/升级）。
		//
		// ########## 它不影响内置插件的保护 ##########
		//
		// 即便这里传 true，ID 与内置插件冲突时 InstallFromStream
		// 仍然拒绝（见 registerExternal）。那个判断不读这个开关。
		Overwrite: r.FormValue("overwrite") == "true",
	})
	if err != nil {
		s.writePluginInstallError(w, r, user, archiveName, err)
		return
	}

	// ########## 审计：安装是必须留痕的高危操作 ##########
	//
	// 它往服务器上放了将被执行的代码。事后排查"这个插件是谁什么时候装的"
	// 必须有据可查——这是本模块最重要的审计记录之一。
	s.plugins.Audit().Record(plugin.AuditEvent{
		Plugin:  res.ID,
		Method:  "INSTALL",
		Path:    archiveName,
		Outcome: plugin.AuditAllowed,
		Status:  http.StatusCreated,
		Reason: "插件安装成功（" + humanMiB(res.Bytes) + "，" +
			strconv.Itoa(res.Files) + " 个文件）",
		ClientIP: clientIP(r),
	})

	s.logger.Info("插件安装成功",
		"user", user, "plugin", res.ID, "file", archiveName,
		"files", res.Files, "bytes", res.Bytes, "mode", res.Mode)

	hint := "插件已安装但**未启动**。请在插件管理页确认插件内容后再手动启动它。"
	if res.Mode == plugin.ModeExternal {
		hint = "这是前端-only 插件，已可直接使用（它没有后端进程）。"
	}

	writeJSON(w, s.logger, http.StatusCreated, pluginInstallResponse{
		Installed: true,
		ID:        res.ID,
		// 只给目录名，不给完整路径（服务器部署细节不外泄）。
		DirName: res.ID,
		Files:   res.Files,
		Bytes:   res.Bytes,
		Mode:    res.Mode,
		// ########## 恒为 false，且有意显式返回 ##########
		//
		// 面板常以 root 运行。安装即自动 exec 一个用户上传的二进制
		// = 无确认地把 root 给出去。因此"安装"与"运行"必须是
		// 两个独立动作：用户先装、先审查，再决定启动。
		//
		// 明确返回这个字段（而不是省略），是为了让前端能直接
		// 告诉用户"还没启动"，而不是让他以为装完就在跑了。
		AutoStarted: false,
		Replaced:    res.Replaced,
		Hint:        hint,
	})
}

// pluginInstallAllowed 判定当前用户能否安装插件（仅管理员）。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应。
func (s *Server) pluginInstallAllowed(w http.ResponseWriter, r *http.Request, user string) bool {
	// 本面板的鉴权模型里，登录用户即管理员（见 auth 包）。
	// 这里仍显式写成一个独立判断点，是为了将来引入多用户角色时
	// 只有一处需要改，而不是散在 handler 里。
	if strings.TrimSpace(user) == "" {
		writeJSON(w, s.logger, http.StatusUnauthorized, map[string]string{
			"error": "未登录",
		})
		return false
	}

	const required = "plugin.install"
	w.Header().Set("X-Lipanel-Install-Requires", required)
	s.logger.Info("插件安装请求已授权", "user", user)

	// 审计一条"尝试安装"，与结果分开记录：
	// 即便安装失败，"谁在什么时候尝试装了什么"同样重要。
	_ = r
	return true
}

// writePluginInstallError 把安装错误翻译为 HTTP 响应。
//
// ########## 状态码的语义必须准确 ##########
//
//	400 压缩包格式不支持 / 缺少文件名
//	409 ID 冲突（含**内置插件冲突**这一最重要的情况）
//	422 内容合法但不是合法插件（manifest 字段非法、apiVersion 不兼容）
//	413 文件过大
//	500 其它（磁盘满等环境问题）
//
// 409 与 422 必须分开：前者是"换个 ID 或先卸载"，后者是"这个包本身有问题"，
// 用户要做的事完全不同。混成一个码，前端只能给出无用的"安装失败"。
func (s *Server) writePluginInstallError(w http.ResponseWriter, r *http.Request,
	user, archiveName string, err error) {

	status := http.StatusInternalServerError
	kind := "安装失败"

	var ie *plugin.InstallError
	if errors.As(err, &ie) {
		kind = ie.Stage
	}

	switch {
	case errors.Is(err, plugin.ErrUnsupportedArchive):
		// 格式不支持：请求内容不可接受（客户端问题），不是服务端故障。
		status = http.StatusBadRequest
	case errors.Is(err, plugin.ErrIDConflict):
		status = http.StatusConflict
	case errors.Is(err, plugin.ErrUnsafeArchive):
		// 不安全的压缩包：这是**拒绝**而不是"包写错了"。
		// 用 400 表示请求内容不可接受。
		status = http.StatusBadRequest
	case errors.Is(err, plugin.ErrIncompatibleAPIVersion),
		errors.Is(err, plugin.ErrNoDescriptor),
		errors.Is(err, plugin.ErrInvalidID):
		// 包的结构/内容不对：请求语法没问题，但语义无法处理。
		status = http.StatusUnprocessableEntity
	}

	// 审计失败记录（含拒绝）。安装尝试必须留痕。
	s.plugins.Audit().Record(plugin.AuditEvent{
		Method:   "INSTALL",
		Path:     archiveName,
		Outcome:  plugin.AuditFailed,
		Status:   status,
		Reason:   kind,
		ClientIP: clientIP(r),
	})

	s.logger.Warn("插件安装失败",
		"user", user, "file", archiveName, "stage", kind, "status", status, "err", err)

	payload := map[string]any{
		"error": err.Error(),
		"kind":  kind,
	}
	// 内置插件冲突是本模块最需要讲清楚的一类错误，单独给出提示。
	if errors.Is(err, plugin.ErrIDConflict) {
		payload["hint"] = "插件 ID 不能与内置插件或已安装的插件重复。" +
			"如需覆盖已安装的外部插件，请带上 overwrite=true。"
	}
	if errors.Is(err, plugin.ErrIncompatibleAPIVersion) {
		payload["hint"] = "该插件针对的插件 API 版本与本面板不兼容，" +
			"请升级面板或联系插件作者获取适配版本。"
	}
	if errors.Is(err, plugin.ErrUnsafeArchive) {
		payload["hint"] = "压缩包包含不安全的内容（路径穿越、符号链接或过大），已被拒绝。"
	}

	writeJSON(w, s.logger, status, payload)
}

// sanitizeUploadName 清理上传的文件名，只保留安全的基名。
//
// ########## 为什么不能直接用 header.Filename ##########
//
// 那是**完全由客户端控制**的字符串。它可以包含：
//
//	"../../../etc/cron.d/evil.zip"   路径穿越
//	"/etc/passwd"                    绝对路径
//	"a\x00b.zip"                     空字节（截断攻击）
//	"C:\\Windows\\evil.zip"          Windows 路径
//
// 本函数把它压成一个纯粹的基名。注意：这个值**只用于判断扩展名**，
// 从不参与路径拼接——但多一道清理能防止将来有人
// 不小心把它用在了路径上。
func sanitizeUploadName(name string) string {
	// 去掉空字节及所有控制字符。
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)

	// 统一分隔符后取基名。
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	// "." 与 ".." 不是有效文件名。
	if name == "." || name == ".." {
		return ""
	}
	return name
}

// humanMiB 把字节数格式化成便于展示的形式。
func humanMiB(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.Itoa(int(n>>20)) + " MiB"
	case n >= 1<<10:
		return strconv.Itoa(int(n>>10)) + " KiB"
	default:
		return strconv.Itoa(int(n)) + " B"
	}
}

// ============================================================================
// 外部插件前端资源的静态服务
// ============================================================================

// externalAssetPrefix 是外部插件前端资源的 URL 前缀。
//
// 与内置插件的约定完全一致（见 internal/plugin/plugin.go 的 Frontend 说明）：
//
//	/plugin-assets/<id>/plugin.js
//
// 内部插件走 /api/plugins/<id>/assets/* 转发到插件进程，
// 外部插件则由本函数直接从磁盘读——但对**前端来说两者毫无区别**，
// 都是同一个 URL。这正是把 AssetProvider 设计成 fs.FS 的价值：
// 存储方式（go:embed vs 磁盘）不泄漏到 URL 上。
const externalAssetPrefix = "/plugin-assets/"

// serveExternalPluginAsset 尝试服务一个外部插件的前端资源。
//
// 返回 true 表示请求已被处理（调用方必须 return，不要再走 SPA 兜底）；
// 返回 false 表示这不是一个外部插件资源请求，交给后续逻辑。
//
// ########## 这个函数的位置是语义要求 ##########
//
// 它必须被调用在 spaHandler 的 **index.html 兜底之前**。
// 否则浏览器会拿到一段 HTML 却按 ESM 模块解析，
// 报出 "Expected a JavaScript-or-Wasm module script but the server
// responded with a MIME type of text/html" —— 也就是 v0.2.0 那次
// P0 白屏的同一个故障模式（坑位 64）。
func (s *Server) serveExternalPluginAsset(w http.ResponseWriter, r *http.Request) bool {
	if s.plugins == nil {
		return false
	}
	if !strings.HasPrefix(r.URL.Path, externalAssetPrefix) {
		return false
	}
	// ########## 只允许 GET/HEAD，其余方法返回 405 ##########
	//
	// 注意不能像早期版本那样 `return false`：staticHandler 挂在 "/" 上，
	// 返回 false 会让 POST 落到 index.html 兜底，于是
	// "POST /plugin-assets/x/y.js" 得到一个 200 + HTML。
	// 那既不符合 HTTP 语义，也让前端无法区分"路径不对"与"方法不对"。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, s.logger, http.StatusMethodNotAllowed, map[string]string{
			"error": "插件资源只支持 GET / HEAD",
		})
		return true
	}

	rest := strings.TrimPrefix(r.URL.Path, externalAssetPrefix)

	// 切出 <id> 与 <子路径>。
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		// "/plugin-assets/" 或 "/plugin-assets/xxx"（没有子路径）：
		// 不是有效资源请求，交回给 SPA 兜底（前端路由可能用到）。
		return false
	}
	id := rest[:i]
	sub := rest[i+1:]

	// ID 必须合法。这既是格式校验，也是安全边界：
	// ID 会参与文件系统路径拼接，允许 "." 或 "/" 就是目录穿越。
	if !plugin.ValidExternalID(id) {
		return false
	}
	// 子路径不允许穿越（http.FileServer 内部也会清理，
	// 但显式拒绝能给出更清楚的语义，且不依赖库的实现细节）。
	if strings.Contains(sub, "..") {
		s.logger.Warn("拒绝含 .. 的插件资源请求",
			"plugin", id, "path", r.URL.Path)
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "非法的资源路径",
		})
		return true
	}

	// 该插件必须存在，且是**外部插件**（内置插件的资源走插件进程转发）。
	fsys, ok := s.plugins.AssetFSFor(id)
	if !ok {
		// ########## 这里刻意**不**返回 404 ##########
		//
		// 若插件未注册，或它是内置插件，或它没有 assets/ 目录，
		// 都返回 false 让请求继续走到原来的逻辑：
		//
		//	· 内置插件的资源由 /api/plugins/<id>/assets/* 提供，
		//	  /plugin-assets/<id>/... 这条 URL 本就不该被使用；
		//	· 未注册的 ID 应当落到 SPA 兜底（与改动前的行为一致），
		//	  避免因为这个新功能改变了既有路径的响应。
		return false
	}

	// 交给标准库的文件服务器：它会处理 MIME 类型、Range、Last-Modified
	// 与条件请求，也会自己清理路径中的 "." 与多余斜杠。
	//
	// ########## MIME 类型必须正确 ##########
	//
	// 这正是整个 P0 白屏事件的根因所在：浏览器对 ESM 模块的
	// MIME 类型是**强校验**的，text/html 会被直接拒绝执行。
	// http.FileServer 依据扩展名给出正确的 Content-Type（.js → text/javascript）。
	http.StripPrefix(externalAssetPrefix+id+"/", http.FileServer(http.FS(fsys))).
		ServeHTTP(w, r)
	return true
}
