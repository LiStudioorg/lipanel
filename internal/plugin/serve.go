package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Handler 是插件对外暴露的 HTTP 处理器。
//
// 路径约定（以 sysinfo 插件为例）：
//
//	GET /healthz  → 骨架自动提供，插件无需实现
//	GET /whoami   → 骨架自动提供，返回插件身份
//	GET /info     → 插件自定义路由（通过 http.ServeMux 注册）
//
// 插件作者只需关心业务路由，健康检查与身份接口由骨架统一提供，
// 保证核心侧的健康探测对所有插件行为一致。
type Handler interface {
	// Descriptor 返回插件的静态元数据。
	Descriptor() Descriptor
	// Routes 注册插件的业务路由。
	Routes(mux *http.ServeMux)
}

// Serve 以插件身份运行：监听环境变量指定的 Unix socket 并提供 HTTP 服务。
//
// 这个函数由主程序的插件子命令入口调用（见 cmd/lipanel/plugin_main.go），
// 是整个插件骨架在插件一侧的唯一入口。它阻塞直到收到 SIGTERM/SIGINT。
//
// 返回的 error 会由 main 以非 0 退出码结束进程，核心侧据此判定插件启动失败。
func Serve(h Handler, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	desc := h.Descriptor()
	if err := desc.Validate(); err != nil {
		return err
	}

	sockPath := os.Getenv(EnvSocketPath)
	if sockPath == "" {
		return fmt.Errorf("plugin: 未设置环境变量 %s，无法确定监听地址（该进程应由核心拉起）", EnvSocketPath)
	}

	// 环境变量里的 ID 必须与编译进去的一致，防止参数被篡改后
	// 出现「sysinfo 插件把自己注册成别的插件」这类混乱。
	if id := os.Getenv(EnvPluginID); id != "" && id != desc.ID {
		return fmt.Errorf("plugin: 环境变量 %s = %q 与插件自身 ID %q 不一致", EnvPluginID, id, desc.ID)
	}

	// 残留 socket 会导致 bind 失败；核心通常已清理，
	// 但插件自己也要兜底（例如被手工启动的场景）。
	if err := removeStaleSocket(sockPath); err != nil {
		return err
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("plugin: 监听 unix socket %s 失败: %w", sockPath, err)
	}
	defer func() { _ = ln.Close() }()

	// socket 文件权限 0600：只有属主（通常是 root）能连接。
	// 这是 Unix socket 方案相对 TCP 的核心优势——权限即访问控制。
	if err := os.Chmod(sockPath, 0o600); err != nil {
		logger.Warn("设置插件 socket 权限失败", "socket", sockPath, "err", err)
	}

	mux := http.NewServeMux()
	registerSkeletonRoutes(mux, desc, sockPath, logger)
	h.Routes(mux)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		// 插件日志交给核心的 stdout 汇合，便于单机排查。
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	// 收到 SIGTERM 后优雅退出：核心的停止流程会先发 SIGTERM，
	// 插件必须在超时内退出，否则会被 SIGKILL——那会留下 socket 文件。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	logger.Info("插件已就绪，开始监听",
		"plugin", desc.ID, "version", desc.Version, "socket", sockPath, "pid", os.Getpid())

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("plugin: %s 服务异常退出: %w", desc.ID, err)
		}
		return nil

	case <-ctx.Done():
		stop()
		logger.Info("插件收到退出信号，正在关闭", "plugin", desc.ID)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("plugin: %s 优雅关闭失败: %w", desc.ID, err)
		}
		<-serveErr
		// 主动清理 socket，避免残留文件影响下次启动。
		if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Warn("清理插件 socket 失败", "socket", sockPath, "err", err)
		}
		logger.Info("插件已退出", "plugin", desc.ID)
		return nil
	}
}

// removeStaleSocket 清理残留的 socket 文件。
// 与 process.prepareSocketPath 保持同样的保守策略：
// 只删 socket 类型的文件，遇到普通文件宁可报错也不静默删除。
func removeStaleSocket(sockPath string) error {
	info, err := os.Lstat(sockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("plugin: 检查 socket 路径 %s 失败: %w", sockPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("plugin: 路径 %s 已被非 socket 文件占用，拒绝覆盖", sockPath)
	}
	if err := os.Remove(sockPath); err != nil {
		return fmt.Errorf("plugin: 清理残留 socket %s 失败: %w", sockPath, err)
	}
	return nil
}

// registerSkeletonRoutes 注册骨架统一提供的接口。
// 这些接口由核心侧的健康探测与诊断逻辑依赖，插件不应该覆盖它们。
func registerSkeletonRoutes(mux *http.ServeMux, desc Descriptor, sockPath string, logger *slog.Logger) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writePluginJSON(w, logger, http.StatusOK, map[string]any{
			"status":  "ok",
			"plugin":  desc.ID,
			"version": desc.Version,
			"pid":     os.Getpid(),
			"time":    time.Now().Format(time.RFC3339),
		})
	})

	// whoami 用于核心与人工排查：确认「这个 socket 后面到底跑的是谁」。
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		writePluginJSON(w, logger, http.StatusOK, map[string]any{
			"plugin":      desc.ID,
			"name":        desc.Name,
			"version":     desc.Version,
			"builtin":     desc.Builtin,
			"pid":         os.Getpid(),
			"socket":      sockPath,
			"proxied":     r.Header.Get("X-Lipanel-Plugin-Proxy") == "1",
			"client_ip":   clientIP(r),
			"received_at": time.Now().Format(time.RFC3339),
			// 若这里出现了 cookie / authorization，说明核心侧剥离逻辑失效，
			// 是一个应当立即被测试捕获的安全回归。
			"leaked_cookie":      r.Header.Get("Cookie"),
			"leaked_authorized":  r.Header.Get("Authorization"),
			"leaked_custom_auth": r.Header.Get("X-Auth-Token"),
		})
	})
}

// writePluginJSON 是插件侧统一的 JSON 输出函数。
func writePluginJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("插件写出 JSON 响应失败", "err", err)
	}
}

// PluginJSON 导出给插件实现使用，避免每个插件重复写一遍响应函数。
func PluginJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	writePluginJSON(w, logger, status, payload)
}

// clientIP 从 RemoteAddr 中取出 IP 部分。
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if addr == "" {
		return ""
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
