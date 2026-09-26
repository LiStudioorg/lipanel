// lipanel 是轻量 Linux 面板的后端入口。
//
// 单二进制设计：前端构建产物通过 go:embed 打包进本二进制，
// 运行时不依赖任何外部文件（CGO_ENABLED=0 静态编译）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/server"
)

// version 可在构建时通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	if err := run(); err != nil {
		// 启动阶段失败：直接输出到 stderr 并以非 0 退出，便于 systemd 捕获。
		fmt.Fprintf(os.Stderr, "lipanel 启动失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", "127.0.0.1:8080", "HTTP 监听地址")
		staticDir = flag.String("static-dir", "", "前端静态资源目录（留空则使用内置 embed 资源）")
		logLevel  = flag.String("log-level", "info", "日志级别: debug|info|warn|error")

		adminUser = flag.String("admin-user", "admin", "管理员用户名")
		adminPass = flag.String("admin-password", "", "管理员明文密码（至少 6 位；与 -admin-password-hash 二选一）")
		adminHash = flag.String("admin-password-hash", "", "管理员密码的 bcrypt 哈希（推荐，避免明文出现在 ps 中）")
		jwtSecret = flag.String("jwt-secret", "", "JWT 签名密钥（至少 16 字节；留空则每次启动随机生成，重启后需重新登录）")
		tokenTTL  = flag.Duration("token-ttl", auth.DefaultTokenTTL, "登录会话有效期，如 2h、30m")
		secureCk  = flag.Bool("secure-cookie", false, "仅通过 HTTPS 传输会话 Cookie（反向代理已启用 TLS 时开启）")

		showVer = flag.Bool("version", false, "打印版本号后退出")
		showKey = flag.Bool("gen-secret", false, "生成一个随机 JWT 签名密钥后退出（便于写入配置）")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("lipanel", version)
		return nil
	}
	if *showKey {
		secret, err := auth.GenerateSecret()
		if err != nil {
			return err
		}
		fmt.Println(secret)
		return nil
	}

	logger, err := newLogger(*logLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	authenticator, err := buildAuthenticator(logger, authOptions{
		user:         *adminUser,
		password:     *adminPass,
		passwordHash: *adminHash,
		jwtSecret:    *jwtSecret,
		ttl:          *tokenTTL,
		secureCookie: *secureCk,
	})
	if err != nil {
		return err
	}

	srv, err := server.New(server.Options{
		Addr:      *addr,
		Logger:    logger,
		Version:   version,
		StaticDir: *staticDir,
		Auth:      authenticator,
	})
	if err != nil {
		return err
	}

	// 监听 SIGINT/SIGTERM，实现优雅关闭。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		// 服务自身出错退出。
		return err

	case <-ctx.Done():
		stop() // 恢复默认信号行为，二次 Ctrl+C 可强制退出。
		logger.Info("收到退出信号，开始关闭服务")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		// 等待 Serve 收尾，忽略其返回的 ErrServerClosed。
		if err := <-serveErr; err != nil {
			return err
		}
		logger.Info("服务已退出")
		return nil
	}
}

// newLogger 依据 level 构造结构化日志器，未知级别返回错误而非静默降级。
func newLogger(level string) (*slog.Logger, error) {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "info":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("非法日志级别 %q，可选: debug|info|warn|error", level)
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv})), nil
}

// authOptions 汇总鉴权相关的启动参数。
type authOptions struct {
	user         string
	password     string
	passwordHash string
	jwtSecret    string
	ttl          time.Duration
	secureCookie bool
}

// buildAuthenticator 依据启动参数构造鉴权组件。
//
// 密码来源优先级：-admin-password-hash > -admin-password > 开发默认口令。
// 明文密码在这里立即转为 bcrypt 哈希，之后进程内只保留哈希，
// 避免明文常驻内存（明文仍会短暂出现在命令行参数中，生产环境建议用哈希形式）。
func buildAuthenticator(logger *slog.Logger, o authOptions) (*auth.Authenticator, error) {
	username := strings.TrimSpace(o.user)
	if username == "" {
		return nil, errors.New("管理员用户名不能为空")
	}

	var hash string
	switch {
	case o.passwordHash != "":
		if !auth.IsBcryptHash(o.passwordHash) {
			return nil, errors.New("-admin-password-hash 不是合法的 bcrypt 哈希（应以 $2a$/$2b$ 开头、共 60 字符）")
		}
		hash = o.passwordHash

	case o.password != "":
		if len([]rune(o.password)) < auth.MinPasswordLength {
			return nil, fmt.Errorf("管理员密码过短，至少需要 %d 个字符", auth.MinPasswordLength)
		}
		h, err := auth.HashPassword(o.password)
		if err != nil {
			return nil, err
		}
		hash = h

	default:
		// 未配置密码：使用开发默认口令，并打印醒目告警。
		h, err := auth.HashPassword(defaultDevPassword)
		if err != nil {
			return nil, err
		}
		hash = h
		logger.Warn("未配置管理员密码，正在使用开发默认口令",
			"username", username,
			"password", defaultDevPassword,
			"hint", "生产环境请使用 -admin-password 或 -admin-password-hash 指定",
		)
	}

	store, err := auth.NewMemoryUserStore(username, hash)
	if err != nil {
		return nil, err
	}

	secret := []byte(o.jwtSecret)
	authenticator, err := auth.New(auth.Options{
		Store:        store,
		Secret:       secret,
		TTL:          o.ttl,
		SecureCookie: o.secureCookie,
	})
	if err != nil {
		return nil, err
	}

	if o.jwtSecret == "" {
		logger.Warn("未配置 JWT 签名密钥，已随机生成；进程重启后所有登录会话将失效",
			"hint", "可用 lipanel -gen-secret 生成一个固定密钥",
		)
	}
	if !o.secureCookie {
		logger.Info("会话 Cookie 未启用 Secure 标记（当前假设通过 localhost 或受信内网访问）",
			"hint", "若已配置 HTTPS 反向代理，请加上 -secure-cookie",
		)
	}

	logger.Info("管理员账号已就绪", "username", username, "token_ttl", authenticator.TTL().String())
	return authenticator, nil
}

// defaultDevPassword 是未配置密码时使用的开发口令。
// 刻意保持简短好记，以便本地联调；启动时必定打印 WARN 提醒替换。
const defaultDevPassword = "admin123"
