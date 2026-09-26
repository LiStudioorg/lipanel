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
	"log/slog"
	"net"
	"net/http"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/plugin"
	"lipanel/internal/sysinfo"
)

// Options 是构造 Server 所需的配置。
type Options struct {
	// Addr 是监听地址，例如 "127.0.0.1:8080"。
	Addr string
	// Logger 是结构化日志器；为 nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Version 是构建版本号，会出现在 /api/health 响应中。
	Version string
	// StaticDir 是前端静态资源目录；为空表示使用内置 embed 资源（见 static.go）。
	StaticDir string
	// Auth 提供登录鉴权能力；为 nil 时使用 New 内部的默认实现（见 buildAuth）。
	Auth *auth.Authenticator
	// Plugins 提供插件管理能力；为 nil 时插件相关接口返回 503。
	// 由 main 注入，测试可传入自定义实例（见 plugin_api_test.go）。
	Plugins *plugin.Manager
}

// Server 封装 HTTP 服务及其依赖。
type Server struct {
	opts        Options
	logger      *slog.Logger
	auth        *auth.Authenticator
	sysinfo     *sysinfo.Collector
	plugins     *plugin.Manager
	pluginProxy *plugin.Proxy
	handler     http.Handler
	httpSrv     *http.Server
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
	// 生产环境必须由 main 传入（见 cmd/lipanel 的启动参数校验）。
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

	mux := http.NewServeMux()
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
