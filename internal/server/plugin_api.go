package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"lipanel/internal/plugin"
)

// registerPluginRoutes 注册插件系统相关接口。
//
// 路由设计（Go 1.22 ServeMux 的路径通配符）：
//
//	GET    /api/plugins            列出全部插件及状态
//	GET    /api/plugins/{id}       查询单个插件状态
//	POST   /api/plugins/{id}/start 启动插件
//	POST   /api/plugins/{id}/stop  停止插件
//	POST   /api/plugins/{id}/restart 重启插件
//	POST   /api/plugins/{id}/health  探测插件健康
//	ANY    /api/plugins/{id}/{...}   把请求转发给插件进程
//
// 路由冲突说明（重要）：Go 的 ServeMux 在匹配时「更具体的模式优先」，
// 因此 "/api/plugins/{id}/start" 这种精确模式不会被 "/api/plugins/{id}/"
// 这条通配模式吞掉——但前提是两条都要注册，缺一条就会出现
// 「start 被当成插件子路径转发出去」的诡异行为。
//
// 全部接口都要求登录：插件转发接口同样受保护，
// 否则任何人都能通过面板代理调用插件能力。
func (s *Server) registerPluginRoutes(mux *http.ServeMux) {
	if s.plugins == nil {
		// 未注入插件管理器（例如老测试只构造了最小 Server）时，
		// 仍然返回明确的 JSON 503，而不是让请求落到前端 HTML 兜底上。
		mux.Handle("/api/plugins/", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginsUnavailable)))
		mux.Handle("/api/plugins", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginsUnavailable)))
		return
	}

	// 集合接口：注意这里的模式没有结尾斜杠，
	// 因此只精确匹配 /api/plugins。
	mux.Handle("GET /api/plugins", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginList)))

	// 单插件管理与转发接口。
	mux.Handle("GET /api/plugins/{id}", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginGet)))
	mux.Handle("POST /api/plugins/{id}/start", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginStart)))
	mux.Handle("POST /api/plugins/{id}/stop", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginStop)))
	mux.Handle("POST /api/plugins/{id}/restart", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginRestart)))
	mux.Handle("POST /api/plugins/{id}/health", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginHealth)))

	// ########## 插件安装（外部插件机制）##########
	//
	// 必须在这里注册——也就是在下面的 "/api/plugins/{id}/" 通配之前。
	//
	// ########## 为什么这条顺序是**硬性**的 ##########
	//
	// 若晚于通配注册，POST /api/plugins/install 会被匹配成
	// "插件 ID = install 的子路径请求"（即 handlePluginProxy），
	// 于是安装请求会被转发给一个根本不存在的插件进程，
	// 用户得到的是 404「插件不存在」——一个与真实原因
	// 毫无关系的错误。
	//
	// 这是本项目连续踩过六次的同一个坑（见 开发计划.md 已知坑位），
	// plugin_install_api_test.go 里有专门用例锁死它。
	mux.Handle("POST /api/plugins/install", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginInstall)))

	// 审计接口（阶段三 3.3）。同样必须在 "/api/plugins/{id}/" 通配之前注册，
	// 否则 "/api/plugins/audit" 会被当成插件 ID = "audit" 的转发请求。
	mux.Handle("GET /api/plugins/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleAuditLog)))
	mux.Handle("GET /api/plugins/{id}/audit", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginAudit)))
	mux.Handle("GET /api/plugins/{id}/permissions", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginPermissions)))

	// 转发兜底：任何其它 /api/plugins/{id}/xxx 都交给插件自己处理。
	// 这条必须最后注册，且必须保留结尾斜杠才能匹配子路径。
	mux.Handle("/api/plugins/{id}/", s.auth.RequireAuth(http.HandlerFunc(s.handlePluginProxy)))
}

// handlePluginsUnavailable 在插件系统未启用时给出明确提示。
func (s *Server) handlePluginsUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "插件系统未启用（服务启动时未注入插件管理器）",
	})
}

// pluginListResponse 是 /api/plugins 的响应体。
type pluginListResponse struct {
	Plugins []plugin.Status `json:"plugins"`
	// Total / Running 便于前端直接展示统计，不必自己遍历。
	Total   int `json:"total"`
	Running int `json:"running"`
	// SocketDir 是插件 socket 目录，便于排查部署问题（需登录才可见）。
	SocketDir string `json:"socket_dir"`
	// Audit 是审计器状态，供插件管理页展示「审计是否在记录」。
	Audit plugin.AuditStats `json:"audit"`
}

// handlePluginList 返回全部插件及其实时状态。
func (s *Server) handlePluginList(w http.ResponseWriter, r *http.Request) {
	list := s.plugins.List()

	running := 0
	for _, p := range list {
		if p.Running() {
			running++
		}
	}

	writeJSON(w, s.logger, http.StatusOK, pluginListResponse{
		Plugins:   list,
		Total:     len(list),
		Running:   running,
		SocketDir: s.plugins.SocketDir(),
		Audit:     s.plugins.Audit().Stats(),
	})
}

// handlePluginGet 返回单个插件的状态。
func (s *Server) handlePluginGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	st, err := s.plugins.Get(id)
	if err != nil {
		s.writePluginError(w, err, id)
		return
	}
	writeJSON(w, s.logger, http.StatusOK, st)
}

// handlePluginStart 启动插件。
func (s *Server) handlePluginStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// 启动可能耗时（要等 socket 就绪），用请求上下文做超时传递，
	// 客户端断开时能及时中止等待。
	st, err := s.plugins.Start(r.Context(), id)
	if err != nil {
		s.writePluginError(w, err, id)
		return
	}
	// 返回完整状态：前端拿到后可直接更新列表行，无需再查一次。
	writeJSON(w, s.logger, http.StatusOK, st)
}

// handlePluginStop 停止插件。
func (s *Server) handlePluginStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	st, err := s.plugins.Stop(id)
	if err != nil {
		// external 模式的插件无法被核心停止，这属于「操作不被支持」，
		// 但状态确实已经变为 stopped（核心不再转发），因此返回 409 + 新状态，
		// 让前端既能提示原因，又能正确刷新界面。
		if errors.Is(err, plugin.ErrUnsupported) {
			writeJSON(w, s.logger, http.StatusConflict, map[string]any{
				"error":  err.Error(),
				"plugin": st,
			})
			return
		}
		s.writePluginError(w, err, id)
		return
	}
	writeJSON(w, s.logger, http.StatusOK, st)
}

// handlePluginRestart 重启插件。
func (s *Server) handlePluginRestart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	st, err := s.plugins.Restart(r.Context(), id)
	if err != nil {
		s.writePluginError(w, err, id)
		return
	}
	writeJSON(w, s.logger, http.StatusOK, st)
}

// handlePluginHealth 主动探测插件健康状态。
func (s *Server) handlePluginHealth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	st, err := s.plugins.Health(r.Context(), id)
	if err != nil {
		// 状态已经写入（healthy=false），因此连同状态一起返回，
		// 前端可以据此把该行标红。
		writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]any{
			"error":  err.Error(),
			"plugin": st,
		})
		return
	}
	writeJSON(w, s.logger, http.StatusOK, st)
}

// handlePluginProxy 把请求转发给对应插件进程。
//
// 这是「核心 → 插件」链路的核心入口。安全要点：
//
//  1. ID 必须通过 plugin.ValidID 校验——它是 socket 文件名的一部分，
//     放任 "../" 之类的字符会直接变成目录穿越。
//  2. 子路径由本函数从已知前缀裁剪得出，而不是信任原始 URL；
//     并且裁剪后再次校验必须以 "/" 开头、不含 ".." 段。
//  3. 鉴权已由外层 RequireAuth 保证，且 Proxy 会剥离 Cookie/Authorization，
//     插件拿不到面板会话凭据。
func (s *Server) handlePluginProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !plugin.ValidID(id) {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "非法插件 ID: " + id,
		})
		return
	}

	subPath, ok := pluginSubPath(r.URL.Path, id)
	if !ok {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "非法的插件子路径: " + r.URL.Path,
		})
		return
	}

	s.pluginProxy.ServeHTTP(w, r, id, subPath)
}

// pluginSubPath 从完整请求路径中裁出插件子路径。
//
// 例如 path = "/api/plugins/sysinfo/info"、id = "sysinfo" 时返回 "/info"。
// 返回 ok=false 表示路径形态不合法（含空字节、上跳段等），调用方应拒绝请求。
//
// 说明：这里刻意不直接使用 r.PathValue("...")——
// Go 1.22 的 ServeMux 只提供单段通配符，拿不到剩余的全部路径。
// 因此需要自己裁剪，并在裁剪后做严格的合法性检查。
func pluginSubPath(fullPath, id string) (string, bool) {
	prefix := "/api/plugins/" + id
	if !strings.HasPrefix(fullPath, prefix) {
		return "", false
	}

	rest := strings.TrimPrefix(fullPath, prefix)
	if rest == "" {
		// "/api/plugins/sysinfo" 无结尾斜杠：交给 GET /api/plugins/{id} 处理，
		// 走到这里说明是其它方法，视为不合法。
		return "", false
	}
	if !strings.HasPrefix(rest, "/") {
		return "", false
	}

	// 防御性检查：cleaned 路径里不应再出现 . 或 .. 段。
	// ServeMux 已经做过一次 clean 并会重定向，但多校验一次成本极低，
	// 而且能挡住「未来某天换了路由实现」的回归。
	for _, seg := range strings.Split(rest, "/") {
		if seg == ".." || seg == "." {
			return "", false
		}
	}
	if strings.ContainsRune(rest, 0) {
		return "", false
	}
	return rest, true
}

// handlePluginPermissions 返回某插件声明并已被核心接受的权限清单。
//
// 单独一个接口而不是塞进 /api/plugins/{id} 的响应里，是为了让它
// 独立可测、也让「查权限」这件事在插件页上能单独刷新。
func (s *Server) handlePluginPermissions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	st, err := s.plugins.Get(id)
	if err != nil {
		s.writePluginError(w, err, id)
		return
	}
	perms, err := s.plugins.Permissions(id)
	if err != nil {
		s.writePluginError(w, err, id)
		return
	}

	declared := make([]string, 0, len(perms))
	for _, p := range perms {
		declared = append(declared, p.Raw)
	}

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"plugin":      id,
		"permissions": declared,
		// declared_note 把「声明到底管什么」直接写进响应里：
		// 前端可以把这句话原样展示给用户，避免被理解成内核级沙箱。
		"scope_note": "权限声明约束的是「核心转发给该插件的调用」：" +
			"未声明的操作会被核心以 403 拒绝，请求不会到达插件进程。" +
			"它不是内核级沙箱，无法阻止插件进程直接读取文件或执行命令。",
		"state": st.State,
	})
}

// handleAuditLog 返回全局审计记录（支持 ?plugin= / ?outcome= / ?limit= 过滤）。
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		s.handlePluginsUnavailable(w, r)
		return
	}

	query := r.URL.Query()
	filter := plugin.AuditFilter{
		Plugin:  strings.TrimSpace(query.Get("plugin")),
		Outcome: strings.TrimSpace(query.Get("outcome")),
		Limit:   parseAuditLimit(query.Get("limit")),
	}
	s.writeAuditResponse(w, filter)
}

// handlePluginAudit 返回单个插件的审计记录。
func (s *Server) handlePluginAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !plugin.ValidID(id) {
		writeJSON(w, s.logger, http.StatusBadRequest, map[string]string{
			"error": "非法插件 ID: " + id,
		})
		return
	}
	// 插件必须存在：否则 /api/plugins/<乱写>/audit 会静默返回空列表，
	// 用户会以为「这个插件什么都没干」，而不是「根本没有这个插件」。
	if _, err := s.plugins.Get(id); err != nil {
		s.writePluginError(w, err, id)
		return
	}

	query := r.URL.Query()
	s.writeAuditResponse(w, plugin.AuditFilter{
		Plugin:  id,
		Outcome: strings.TrimSpace(query.Get("outcome")),
		Limit:   parseAuditLimit(query.Get("limit")),
	})
}

// writeAuditResponse 输出审计记录 + 统计信息。
//
// 记录与统计一起返回：前端表格要显示条目，顶部还要显示
// 「累计 N 条 / 拒绝 M 条」，分两次请求纯属浪费。
func (s *Server) writeAuditResponse(w http.ResponseWriter, filter plugin.AuditFilter) {
	auditor := s.plugins.Audit()

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": auditor.Query(filter),
		"stats":  auditor.Stats(),
		// by_plugin 让插件列表能显示每个插件的拒绝次数，
		// 而不必为每个插件单独请求一次审计接口。
		"by_plugin": auditor.CountByPlugin(),
		"filter": map[string]any{
			"plugin":  filter.Plugin,
			"outcome": filter.Outcome,
			"limit":   effectiveAuditLimit(filter.Limit),
		},
	})
}

// parseAuditLimit 解析 ?limit= 参数。
//
// 非法值一律回落到默认值而不是报错：审计页是排查工具，
// 一个写错的查询参数不该让整个页面打不开。
// 上限由 plugin.MaxAuditQueryLimit 在 Auditor 内部统一 clamp。
func parseAuditLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0 // 交给 Auditor 用默认值
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// effectiveAuditLimit 回显最终生效的条数上限（与 Auditor 的 clamp 规则一致）。
func effectiveAuditLimit(limit int) int {
	if limit <= 0 {
		return plugin.DefaultAuditQueryLimit
	}
	if limit > plugin.MaxAuditQueryLimit {
		return plugin.MaxAuditQueryLimit
	}
	return limit
}

// writePluginError 把插件包返回的错误翻译成合适的 HTTP 状态码。
//
// 状态码语义（前端据此给出不同提示）：
//
//	404 插件不存在
//	409 插件已在运行 / 状态冲突
//	503 插件未运行
//	500 其它内部错误
func (s *Server) writePluginError(w http.ResponseWriter, err error, id string) {
	switch {
	case errors.Is(err, plugin.ErrNotFound):
		writeJSON(w, s.logger, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, plugin.ErrAlreadyRunning):
		writeJSON(w, s.logger, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, plugin.ErrNotRunning):
		writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	case errors.Is(err, plugin.ErrUnsupported):
		writeJSON(w, s.logger, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		s.logger.Error("插件操作失败", "plugin", id, "err", err)
		writeJSON(w, s.logger, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
