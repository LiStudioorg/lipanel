// Package server 提供 lipanel 的 HTTP 服务骨架。
//
// 设计约束：
//   - 只依赖标准库 net/http，便于 CGO_ENABLED=0 静态编译与嵌入单二进制。
//   - 通过 Options 注入依赖，方便后续阶段替换为真实的面板能力（系统信息、服务管理等）。
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/file"
	"lipanel/internal/firewall"
	"lipanel/internal/plugin"
	"lipanel/internal/service"
	"lipanel/internal/site"
	"lipanel/internal/ssl"
	"lipanel/internal/store"
	"lipanel/internal/sysinfo"
	"lipanel/internal/terminal"
)

// Options 是构造 Server 所需的配置。
type Options struct {
	// Addr 是监听地址，例如 "127.0.0.1:8080"。
	Addr string
	// Logger 是结构化日志器；为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Version 是构建版本号，会出现在 /api/health 响应中。
	Version string
	// StaticDir 是前端静态资源目录；为空表示使用 WebFS 注入的内嵌资源。
	StaticDir string
	// WebFS 是内嵌的前端产物文件系统（以 dist 为根，含 index.html）。
	//
	// 由 main 通过 go:embed 注入：入口迁移到仓库根目录后根包是 package main，
	// 而 Go 不允许 import main 包，因此不能再由本包直接引用根包。
	// 注入方式也让本包与「前端产物存放位置」彻底解耦。
	WebFS fs.FS
	// WebBuilt 表示前端产物是否已真实构建（仅有 .gitkeep 时为 false），
	// 仅用于启动日志提示，避免用户对着空白页面猜测原因。
	WebBuilt bool
	// Auth 提供登录鉴权能力；为 nil 时使用 New 内部的默认实现（见 buildAuth）。
	Auth *auth.Authenticator
	// Plugins 提供插件管理能力；为 nil 时插件相关接口返回 503。
	// 由 main 注入，测试可传入自定义实例（见 plugin_api_test.go）。
	Plugins *plugin.Manager
	// Services 提供 systemd 服务管理能力（阶段四 4.1）。
	// 为 nil 时服务相关接口返回 503（与 Plugins 同样的降级策略）。
	//
	// 注意：即使注入了 Manager，系统本身没有 systemd 时
	// 它也只会返回「不可用」而不是报错——降级判断在 service 包内，
	// 这里不需要也不应该重复判断。
	Services *service.Manager
	// Files 提供文件管理能力（阶段四 4.2，核心自带）。
	// 为 nil 时文件相关接口返回 JSON 503，老测试无需改动即可继续通过。
	//
	// 与 service 的区别：文件管理不存在"系统不支持"的降级分支——
	// 它的可用性完全由「有没有配白名单根目录」决定，而这在构造
	// file.Manager 时就已经确定（没有根目录直接构造失败）。
	Files *file.Manager
	// Sites 提供 nginx 站点管理能力（阶段四 4.3，核心自带）。
	// 为 nil 时站点相关接口返回 JSON 503（与 Plugins/Services 同样的降级策略）。
	//
	// 与 Services 一样，即使注入了 Manager，系统本身没有 nginx 时
	// 它也只会返回「不可用」而不是报错——降级判断在 site 包内
	// （由 SystemAdapter 探测目录布局得出结论），这里不重复判断。
	Sites *site.Manager
	// SSL 提供 Let's Encrypt 证书管理能力（阶段四 4.4，核心自带）。
	// 为 nil 时 SSL 相关接口返回 JSON 503（与 Plugins/Services/Sites 同样的降级策略）。
	//
	// 与其它模块一样，"没装 certbot" 不等于"接口不可用"：
	// 那种情况下接口返回 200 且 available=false，
	// 让前端能渲染出带原因的说明页而不是一个红色错误框。
	SSL *ssl.Manager
	// SSLScheduler 提供自动续期的运行状态（可选）。
	//
	// 单独注入而不是从 SSL Manager 里取：调度器是**可选的**
	// （用户可以只用 -cert-renew-interval 0 关掉它），
	// 而状态接口需要在它不存在时也能正常返回。
	// 为 nil 时状态里 scheduler.running=false。
	SSLScheduler *ssl.RenewScheduler

	// Store 是软件商店管理器（阶段四 4.5，核心自带）。
	//
	// 为 nil 时 /api/store 返回 503（而不是 panic）：
	// 与 4.1~4.4 一致，只关心其它功能的测试无需构造它。
	Store *store.Manager

	// Firewall 是防火墙与端口管理器（阶段四 4.6，核心自带）。
	//
	// 为 nil 时 /api/firewall 返回 503（而不是 panic）：
	// 与 4.1~4.5 一致，只关心其它功能的测试无需构造它。
	//
	// 与其它模块一样，"系统没装防火墙"不等于"接口不可用"：
	// 那种情况下接口返回 200 且 available=false + 安装指引，
	// 让前端能渲染出带原因的说明页而不是一个红色错误框。
	Firewall *firewall.Manager

	// Terminal 是 Web 终端会话管理器（阶段五 5.1，核心自带）。
	//
	// 为 nil 时 /api/terminal 返回 503（而不是 panic）：
	// 与 4.1~4.6 一致，只关心其它功能的测试无需构造它。
	//
	// ########## 与其它模块最重要的区别：平台能力 ##########
	//
	// Windows 等没有伪终端（PTY）的平台上，终端功能**必然不可用**。
	// 但那种平台上注入的 Manager 依然是有效的：它只是会拒绝
	// 创建会话（ErrUnsupported），并在 status 里如实报告
	// supported=false + 原因。
	//
	// 这样设计是为了让 Windows 用户仍能使用面板的其它全部功能，
	// 而不是因为一个终端让整个面板起不来
	// （见 internal/terminal/errors.go 的优雅降级说明）。
	Terminal *terminal.Manager
}

// Server 封装 HTTP 服务及其依赖。
type Server struct {
	opts         Options
	logger       *slog.Logger
	auth         *auth.Authenticator
	sysinfo      *sysinfo.Collector
	plugins      *plugin.Manager
	pluginProxy  *plugin.Proxy
	serviceMgr   *service.Manager
	fileMgr      *file.Manager
	siteMgr      *site.Manager
	sslMgr       *ssl.Manager
	sslScheduler *ssl.RenewScheduler
	storeMgr     *store.Manager
	firewallMgr  *firewall.Manager
	terminalMgr  *terminal.Manager
	handler      http.Handler
	httpSrv      *http.Server
}

// New 根据 opts 构建 Server。返回错误说明配置非法，调用方应据此终止启动。
func New(opts Options) (*Server, error) {
	if opts.Addr == "" {
		return nil, errors.New("server: Addr 不能为空")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}

	s := &Server{opts: opts, logger: logger}

	// 注入鉴权组件：未显式传入时构造一个仅用于本地开发的默认实例。
	// 生产环境必须由 main 传入（见根目录 main.go 的启动参数校验）。
	if opts.Auth != nil {
		s.auth = opts.Auth
	} else {
		a, err := buildAuth(logger)
		if err != nil {
			return nil, err
		}
		s.auth = a
	}
	s.sysinfo = sysinfo.NewCollector()

	// 插件系统：仅在 main 注入 Manager 时启用。
	// 未注入时相关接口返回 503（而不是 panic），
	// 这样只关心系统信息的旧测试仍能构造最小 Server。
	if opts.Plugins != nil {
		s.plugins = opts.Plugins
		s.pluginProxy = plugin.NewProxy(opts.Plugins)
	}

	// 服务管理（阶段四 4.1）：同样只在 main 注入时启用。
	// 未注入时 /api/services 返回 503，老测试无需改动即可继续通过。
	s.serviceMgr = opts.Services

	// 文件管理（阶段四 4.2）：同上。
	s.fileMgr = opts.Files

	// 站点管理（阶段四 4.3）：同上。未注入时 /api/sites 返回 503。
	s.siteMgr = opts.Sites

	// SSL 证书管理（阶段四 4.4）：同上。未注入时 /api/ssl 返回 503。
	s.sslMgr = opts.SSL
	s.sslScheduler = opts.SSLScheduler

	// 软件商店（阶段四 4.5）：同上。未注入时 /api/store 返回 503。
	s.storeMgr = opts.Store

	// 防火墙与端口管理（阶段四 4.6）：同上。未注入时 /api/firewall 返回 503。
	//
	// 特别注意：本模块的默认执行器会**真实修改系统防火墙**。
	// 因此生产注入的是真实执行器，而测试与端到端验证
	// 一律注入假执行器（见 internal/server/firewall_api_test.go
	// 与 .e2e/run-firewall-e2e.sh）——绝不让测试碰宿主机防火墙。
	s.firewallMgr = opts.Firewall

	// Web 终端（阶段五 5.1）：同上。未注入时 /api/terminal 返回 503。
	//
	// 特别注意：本模块会**真实 fork 出 shell 进程**。
	// Windows 等无 PTY 平台上 Manager 仍可构造，但创建会话会返回
	// ErrUnsupported——降级判断在 terminal 包内，这里不重复判断。
	s.terminalMgr = opts.Terminal

	mux := http.NewServeMux()
	// 服务路由由 registerAPIRoutes 内部统一注册（核心自带功能，
	// 与其它 /api 接口登记在同一处）。
	s.registerAPIRoutes(mux)
	s.registerPluginRoutes(mux)

	staticHandler, err := s.staticHandler()
	if err != nil {
		return nil, fmt.Errorf("server: 初始化静态资源失败: %w", err)
	}
	// "/" 作为兜底路由，处理前端页面；API 路由已在上方优先注册。
	mux.Handle("/", staticHandler)

	s.handler = s.withRecovery(s.withRequestLog(mux))
	s.httpSrv = &http.Server{
		Addr:              opts.Addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Handler 返回组装好的路由，便于 httptest 做单元测试。
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe 启动服务并阻塞，直到出错或被 Shutdown/Close。
// http.ErrServerClosed 属于正常退出，会被转换为 nil。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("server: 监听 %s 失败: %w", s.opts.Addr, err)
	}
	s.logger.Info("HTTP 服务已启动", "addr", ln.Addr().String(), "version", s.opts.Version)

	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: 服务异常退出: %w", err)
	}
	return nil
}

// Shutdown 优雅关闭服务：停止接收新连接，并等待在途请求完成或 ctx 超时。
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("正在优雅关闭 HTTP 服务")
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server: 优雅关闭失败: %w", err)
	}
	return nil
}
