package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// registerAPIRoutes 注册所有 /api 下的接口。
// 新增接口时统一在此登记，保证路由集中可查。
//
// 鉴权采用「按路由显式挂载」的白名单方式：只有包了 s.auth.RequireAuth 的接口才需要登录。
// 相比全局拦截 /api/*，这里多写一行，但新增接口不会因为白名单漏配而意外裸奔，
// 公开接口（health/login）也无需额外的豁免名单。
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	// ---------- 公开接口 ----------
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// ---------- 需要登录的接口 ----------
	mux.Handle("GET /api/auth/me", s.auth.RequireAuth(http.HandlerFunc(s.handleAuthMe)))
	mux.Handle("GET /api/system/info", s.auth.RequireAuth(http.HandlerFunc(s.handleSystemInfo)))

	// ---------- 服务管理（阶段四 4.1，核心自带）----------
	//
	// 这里是核心功能的统一登记处，因此服务路由的**注册入口**放在本函数；
	// 具体 handler 与实现细节在 service_api.go / internal/service 包。
	// 之所以不在本文件里逐个写 mux.Handle：服务有多条路由且要处理
	// "审计路径必须先于 {name} 通配注册"的顺序问题，
	// 集中在一个注册函数里比散落在两处更不容易写错。
	s.registerServiceRoutes(mux)

	// ---------- 文件管理（阶段四 4.2，核心自带）----------
	//
	// 同样是核心自带能力（不做成插件）：新增 file_api.go 承载 handler，
	// internal/file 承载路径安全、权限与审计。这里只负责"登记"。
	s.registerFileRoutes(mux)

	// ---------- 网站管理（阶段四 4.3，核心自带）----------
	//
	// 与 4.1/4.2 同一套架构：site_api.go 承载 handler，
	// internal/site 承载配置生成、nginx -t 校验与自动回滚、权限与审计。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（/api/sites/audit 与
	// /api/sites/capabilities 必须先于 /api/sites/{name} 注册），
	// 已由 registerSiteRoutes 集中处理，详见其注释与
	// site_api_test.go 中锁死该行为的测试。
	s.registerSiteRoutes(mux)

	// ---------- SSL 证书（阶段四 4.4，核心自带）----------
	//
	// 与 4.1/4.2/4.3 同一套架构：ssl_api.go 承载 handler，
	// internal/ssl 承载 ACME 客户端探测、证书解析、命令组装、
	// 权限与审计；而**配置写入**由 4.3 的 site.Manager 经
	// 「nginx -t + 失败自动回滚」链路完成——
	// 证书配置写坏同样是全站中断，因此绝不自己写文件。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（/api/ssl/audit 与
	// /api/ssl/capabilities 必须先于 /api/ssl/{name}/... 注册），
	// 已由 registerSSLRoutes 集中处理，详见其注释与
	// ssl_api_test.go 中锁死该行为的测试。
	s.registerSSLRoutes(mux)

	// 软件商店（4.5）：一并登记，理由同 4.4。
	// 注意：registerStoreRoutes 内部把 capabilities/audit/tasks 这些
	// **固定段**路由放在 /{name}/... 通配之前注册，详见其注释。
	s.registerStoreRoutes(mux)

	// ---------- 防火墙与端口管理（阶段四 4.6，核心自带）----------
	//
	// 与 4.1~4.5 同一套架构：firewall_api.go 承载 handler，
	// internal/firewall 承载后端探测、命令组装、规则解析、
	// 端口保护、权限与审计。
	//
	// ########## 本模块的接口有两处与其它模块不同 ##########
	//
	//  ① 删除必须带 confirm —— 否则返回 **428 Precondition Required**。
	//     计划明确要求"删除规则前必须二次确认，避免把 SSH 端口误关
	//     导致失联"。前端弹窗只是体验，服务端强制才是边界。
	//
	//  ② 受保护端口（面板自身 / SSH）默认拒绝删除（409），
	//     需要显式 force=true，且会被单独记入审计。
	//
	// 另外：本模块的写操作会**真实修改系统防火墙**，
	// 而一条错误的规则可以让用户同时失去 SSH 与面板的访问
	// （只能靠物理控制台恢复）。因此测试与端到端验证
	// 一律注入假执行器，绝不碰宿主机防火墙。
	s.registerFirewallRoutes(mux)

	// ---------- Web 终端（阶段五 5.1，核心自带）----------
	//
	// 与 4.1~4.6 同一套架构：terminal_api.go 承载 handler，
	// internal/terminal 承载 PTY 会话、手写 WebSocket、权限与审计。
	//
	// ########## 本模块在接口层的三个特殊之处 ##########
	//
	// ① **唯一的 WebSocket 端点**（GET /api/terminal/ws）。
	//    它同样挂 RequireAuth，且**鉴权必须发生在 Upgrade 之前**——
	//    一旦写出 101，HTTP 语义就结束了，再想返回 401/403 已不可能。
	//    另外 WebSocket 不受同源策略保护（浏览器会自动带 Cookie），
	//    因此 handler 内还额外做 Origin 校验防 CSWSH。
	//
	// ② **Windows 上返回 501 而不是 500**。
	//    Windows 没有 POSIX 伪终端，终端功能在该平台必然不可用。
	//    501 让前端能渲染「本平台不支持」的说明性提示，
	//    而不是把一个技术错误直接甩给用户。
	//
	// ③ 创建会话是本面板**最高危**的操作之一：服务器上从此多了一个
	//    以面板身份运行的 shell。因此全部创建/连接/断开都留痕
	//    （kind: terminal、source: core），且服务端强制
	//    「一个会话只能被一个客户端连接」。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（固定段路由必须先于通配注册），
	// 已由 registerTerminalRoutes 集中处理。
	s.registerTerminalRoutes(mux)

	// ---------- 计划任务 crontab（阶段五 5.2，核心自带）----------
	//
	// 与 4.1~4.6、5.1 同一套架构：cron_api.go 承载 handler，
	// internal/cron 承载表达式校验、crontab 解析、包装脚本、
	// 备份与回滚、权限与审计。
	//
	// ########## 本模块在接口层的三个特殊之处 ##########
	//
	// ① **它改的不是"现在"，而是"未来"**。
	//    其它模块的操作后果在按下按钮那一刻发生；计划任务的后果发生在
	//    未来某个无人值守的时刻，出错往往要好几天后才被发现。
	//    因此写操作走「先备份 → 再写 → 失败回滚 → 回滚失败也留痕」，
	//    并在响应与审计里如实报告回滚结果与备份路径。
	//
	// ② **审计必须记命令原文**。
	//    计划任务以面板身份（生产上通常是 root）执行任意 shell 命令，
	//    「谁让这台机器以后每天凌晨跑什么」必须可查，含被拒绝的请求。
	//
	// ③ **删除强制二次确认（428）**，且「没装 cron」是状态不是错误
	//    （GET /api/cron 返回 200 + available=false + 安装指引）。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（固定段路由必须先于通配注册），
	// 已由 registerCronRoutes 集中处理。
	s.registerCronRoutes(mux)

	// ---------- 备份恢复（阶段五 5.3，核心自带）----------
	//
	// 与 4.1~4.6、5.1、5.2 同一套架构：backup_api.go 承载 handler，
	// internal/backup 承载打包、存储后端（本地 / S3 / WebDAV）、
	// 保留策略、恢复与路径安全、权限与审计。
	//
	// ########## 本模块在接口层的三个特殊之处 ##########
	//
	// ① **恢复是本面板唯一不可逆的操作**。
	//    它会覆盖目标目录里与归档同名的文件，且没有撤销。
	//    因此服务端强制「confirm=true **且** confirm_text 逐字等于任务名」，
	//    缺任一返回 **428 Precondition Required**。
	//
	// ② **下载与删除只接受"能反查回任务"的对象名**。
	//    若接口直接拿一个对象名去存储上取，它就是一个
	//    「登录即可读取桶内任意对象」的入口。
	//
	// ③ **凭证一个字都不回显**。存储列表返回的是脱敏副本
	//    （Manager 内部就调了 Redacted），编辑时省略密钥字段
	//    表示"不改动"而不是"清空"。
	//
	// ⚠️ 该注册函数内部有**顺序要求**（固定段路由必须先于通配注册），
	// 已由 registerBackupRoutes 集中处理。
	s.registerBackupRoutes(mux)
}

// healthResponse 是 /api/health 的响应体，字段使用 snake_case 以便前端直接消费。
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
	// TokenTTLSeconds 告诉前端会话时长，便于提示「登录已过期」。
	TokenTTLSeconds int `json:"token_ttl_seconds"`
	// HasFixedSecret 为 false 表示签名密钥是每次启动随机生成的（重启需重新登录）。
	HasFixedSecret bool `json:"has_fixed_secret"`
}

// handleHealth 返回服务健康状态，供前端首屏探活与联调使用。
//
// 该接口保持公开且极轻量：它可能被监控系统高频轮询，
// 因此不读 /proc、不查 Cookie，只返回内存中的常量信息。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusOK, healthResponse{
		Status:          "ok",
		Version:         s.opts.Version,
		Time:            time.Now().Format(time.RFC3339),
		TokenTTLSeconds: int(s.auth.TTL().Seconds()),
		HasFixedSecret:  !s.auth.SecretGenerated(),
	})
}

// writeJSON 以统一格式写出 JSON 响应。
// 序列化失败属于编程错误，此时响应头可能已写出，只能记录日志。
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("写出 JSON 响应失败", "err", err)
	}
}
