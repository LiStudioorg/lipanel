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
	"lipanel/internal/config"
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
		configPath = flag.String("config", "", "配置文件路径（JSON）。指定后首次启动会自动生成密码哈希与签名密钥并落盘")
		addr       = flag.String("addr", config.DefaultAddr, "HTTP 监听地址（覆盖配置文件）")
		staticDir  = flag.String("static-dir", "", "前端静态资源目录（留空则使用内置 embed 资源）")
		logLevel   = flag.String("log-level", config.DefaultLogLevel, "日志级别: debug|info|warn|error（覆盖配置文件）")

		adminUser = flag.String("admin-user", config.DefaultUsername, "管理员用户名（覆盖配置文件）")
		adminPass = flag.String("admin-password", "", "管理员明文密码（至少 6 位；与 -admin-password-hash 二选一）")
		adminHash = flag.String("admin-password-hash", "", "管理员密码的 bcrypt 哈希（推荐，避免明文出现在 ps 中）")
		jwtSecret = flag.String("jwt-secret", "", "JWT 签名密钥（至少 16 字节；留空则读取配置文件或自动生成）")
		tokenTTL  = flag.Duration("token-ttl", auth.DefaultTokenTTL, "登录会话有效期，如 2h、30m（覆盖配置文件）")
		secureCk  = flag.Bool("secure-cookie", false, "仅通过 HTTPS 传输会话 Cookie（反向代理已启用 TLS 时开启）")

		showVer  = flag.Bool("version", false, "打印版本号后退出")
		showKey  = flag.Bool("gen-secret", false, "生成一个随机 JWT 签名密钥后退出（便于写入配置）")
		showHash = flag.String("gen-password-hash", "", "把给定明文密码转成 bcrypt 哈希后退出（便于写入配置）")
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
	if *showHash != "" {
		hash, err := auth.HashPassword(*showHash)
		if err != nil {
			return err
		}
		fmt.Println(hash)
		return nil
	}

	// 记录哪些参数被显式指定：区分「没写」与「写成了默认值」，
	// 后者应当覆盖配置文件，只有 flag.Visit 能做到这一点。
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	bootstrap, err := config.Bootstrap(config.BootstrapOptions{
		Path:         *configPath,
		Set:          explicit,
		Addr:         *addr,
		LogLevel:     *logLevel,
		Username:     *adminUser,
		Password:     *adminPass,
		PasswordHash: *adminHash,
		JWTSecret:    *jwtSecret,
		TokenTTL:     *tokenTTL,
		SecureCookie: *secureCk,
	})
	if err != nil {
		return err
	}

	// 日志器在配置合并之后构造：配置文件里写的 log_level 也要生效。
	// 非法级别已在 config.Validate 中被拦截，这里不会静默降级。
	logger, err := newLogger(bootstrap.Config.LogLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	logBootstrap(logger, *configPath, bootstrap)

	authenticator, err := buildAuthenticator(logger, bootstrap.Config, *configPath)
	if err != nil {
		return err
	}

	srv, err := server.New(server.Options{
		Addr:      bootstrap.Config.Addr,
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

// logBootstrap 输出引导过程中的关键事件。
//
// 自动生成的密码只在这里出现一次：进程内只保留 bcrypt 哈希，
// 配置文件里也只有哈希，因此必须显式提示用户立即保存。
func logBootstrap(logger *slog.Logger, path string, res *config.BootstrapResult) {
	switch {
	case !res.Persistent:
		logger.Warn("未指定 -config，本次运行不会持久化任何凭据",
			"hint", "指定 -config /var/lib/lipanel/config.json 可自动生成并保存密码与密钥")
	case res.Created:
		logger.Info("已创建配置文件", "path", path)
	case res.Saved:
		logger.Info("已更新配置文件", "path", path)
	default:
		logger.Info("已加载配置文件", "path", path)
	}

	if res.PermissionWarning != "" {
		logger.Warn("配置文件权限过于宽松", "detail", res.PermissionWarning)
	}

	// 自动生成的密码：唯一一次明文展示机会。
	if p := res.GeneratedPassword; p != "" {
		logger.Warn("已自动生成管理员密码，请立即抄录保存（此密码不会再显示）",
			"username", res.Config.Auth.Username,
			"password", p,
			"hint", "如需自定义，可停止服务后用 -admin-password 重新指定",
		)
	}
	if res.GeneratedSecret {
		logger.Info("已自动生成 JWT 签名密钥并写入配置文件，重启后登录状态可保持",
			"path", path)
	}
	if res.PasswordRotated {
		logger.Info("管理员密码已按启动参数更新", "username", res.Config.Auth.Username)
	}
	if res.SecretRotated {
		logger.Warn("JWT 签名密钥已按启动参数更新，此前签发的所有会话立即失效")
	}
}

// buildAuthenticator 依据最终配置构造鉴权组件。
//
// 凭据来源已在 config.Bootstrap 中统一解析（CLI > 配置文件 > 自动生成），
// 这里只负责把结果转成 Authenticator，并处理「纯内存模式」的兜底逻辑。
func buildAuthenticator(logger *slog.Logger, cfg *config.Config, configPath string) (*auth.Authenticator, error) {
	username := strings.TrimSpace(cfg.Auth.Username)
	if username == "" {
		return nil, errors.New("管理员用户名不能为空")
	}

	hash := cfg.Auth.PasswordHash
	if hash == "" {
		// 走到这里说明既没有配置文件、也没有通过 CLI 指定密码，
		// 属于本地开发的纯内存模式：退回默认口令并打印醒目告警。
		h, err := auth.HashPassword(defaultDevPassword)
		if err != nil {
			return nil, err
		}
		hash = h
		logger.Warn("未配置管理员密码，正在使用开发默认口令",
			"username", username,
			"password", defaultDevPassword,
			"hint", "生产环境请指定 -config，或用 -admin-password / -admin-password-hash 传入",
		)
	}

	store, err := auth.NewMemoryUserStore(username, hash)
	if err != nil {
		return nil, err
	}

	ttl := cfg.TokenTTLDurationOrDefault()
	authenticator, err := auth.New(auth.Options{
		Store:        store,
		Secret:       []byte(cfg.Auth.JWTSecret),
		TTL:          ttl,
		SecureCookie: cfg.SecureCookie,
	})
	if err != nil {
		return nil, err
	}

	if cfg.Auth.JWTSecret == "" {
		logger.Warn("未配置 JWT 签名密钥，已随机生成；进程重启后所有登录会话将失效",
			"hint", "指定 -config 可自动生成并持久化密钥，或用 -gen-secret 生成后写入配置",
		)
	}
	if !cfg.SecureCookie {
		logger.Debug("会话 Cookie 未启用 Secure 标记",
			"hint", "若已配置 HTTPS 反向代理，请加上 -secure-cookie",
		)
	}

	logger.Info("管理员账号已就绪",
		"username", username,
		"token_ttl", authenticator.TTL().String(),
		"persistent", configPath != "",
	)
	return authenticator, nil
}

// defaultDevPassword 是未配置密码时使用的开发口令。
// 刻意保持简短好记，以便本地联调；启动时必定打印 WARN 提醒替换。
const defaultDevPassword = "admin123"
