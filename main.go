// lipanel 是轻量 Linux 面板的后端入口。
//
// 单二进制设计：前端构建产物通过 go:embed 打包进本二进制，
// 运行时不依赖任何外部文件（CGO_ENABLED=0 静态编译）。
//
// 为什么入口在仓库根目录（而不是 cmd/lipanel）：
// go:embed 的路径相对「声明该指令的包所在目录」解析，且不能用 ../ 向上
// 跨目录。前端产物位于 web/dist，所以承载 embed 的包必须在根目录。
// 既然根目录已经必须是一个包，入口就直接放在这里，避免为此多一层 cmd/。
//
// 历史说明：此前根目录是 package lipanel（webui.go 承载 embed），入口在
// cmd/lipanel。Go 规定一个目录只能有一个包，两者无法共存，因此现已合并
// 为本文件（package main）。
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/config"
	"lipanel/internal/plugin"
	"lipanel/internal/server"
)

// distFS 承载 web/dist 下的全部前端产物。
// all: 前缀让以 _ 或 . 开头的文件（如 Vite 可能产出的 .vite 目录）也被打包。
//
// 注意：本文件位于模块根目录，因此这里的路径与 web/dist 同级。
//
//go:embed all:web/dist
var distFS embed.FS

// webFS 返回以 web/dist 为根的文件系统，可直接交给 http.FS 使用。
// 例如 fsys.Open("index.html") 对应 web/dist/index.html。
func webFS() (fs.FS, error) {
	return fs.Sub(distFS, "web/dist")
}

// webBuilt 判断前端产物是否已真实构建。
// 以 index.html 是否存在为准：仅有占位文件 web/dist/.gitkeep 时返回 false，
// 以便启动阶段给出「请先构建前端」的明确提示，而不是返回空白页面。
func webBuilt() bool {
	f, err := distFS.Open("web/dist/index.html")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

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
	// 插件模式必须在 flag.Parse 之前判断：
	// flag 包遇到 "__plugin_sysinfo" 这类非 - 开头的参数会直接报错退出，
	// 而该参数正是核心拉起插件进程时传入的。
	if handled, err := maybeRunAsPlugin(); handled {
		return err
	}

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

		pluginSocketDir = flag.String("plugin-socket-dir", "",
			"插件 Unix socket 存放目录（留空则使用 <临时目录>/lipanel-plugins，权限 0700）")
		pluginAuditLog = flag.String("audit-log", "",
			"插件操作审计日志路径（JSONL，追加写入，权限 0600）；留空则审计只保留在内存中")
		pluginAuditBuf = flag.Int("audit-buffer", plugin.DefaultAuditCapacity,
			"插件操作审计在内存中保留的条数上限（供审计页查询）")
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

	// 插件管理器：注册全部内置插件，并把 socket 目录放在私有目录下。
	//
	// 审计器在管理器之前构造：审计路径打不开时应当在启动阶段就报错，
	// 而不是让用户在「以为有审计」的状态下运行。
	auditor, err := plugin.NewAuditor(plugin.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = auditor.Close() }()

	pluginManager, err := plugin.NewManager(plugin.Options{
		SocketDir: *pluginSocketDir,
		Logger:    logger,
		Audit:     auditor,
	})
	if err != nil {
		return err
	}
	if err := pluginManager.RegisterAllBuiltins(); err != nil {
		return err
	}
	logger.Info("插件系统已就绪",
		"builtin_count", len(plugin.BuiltinIDs()),
		"plugins", plugin.BuiltinIDs(),
		"socket_dir", pluginManager.SocketDir(),
		"audit_log", *pluginAuditLog,
		"audit_buffer", *pluginAuditBuf,
	)

	// 注入内嵌前端资源（go:embed 在根目录，见本文件顶部 distFS）。
	// 仅在没有用 -static-dir 覆盖时才需要解析；解析失败属构建错误，直接终止。
	var (
		embeddedFS    fs.FS
		embeddedBuilt bool
	)
	if *staticDir == "" {
		embeddedFS, err = webFS()
		if err != nil {
			return fmt.Errorf("解析内嵌前端资源失败: %w", err)
		}
		embeddedBuilt = webBuilt()
	}

	srv, err := server.New(server.Options{
		Addr:      bootstrap.Config.Addr,
		Logger:    logger,
		Version:   version,
		StaticDir: *staticDir,
		WebFS:     embeddedFS,
		WebBuilt:  embeddedBuilt,
		Auth:      authenticator,
		Plugins:   pluginManager,
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
		// 停止插件进程：核心退出却留下孤儿插件进程会占着 socket，
		// 下次启动时还会误连到一个「上辈子的」插件上。
		if err := pluginManager.Shutdown(shutdownCtx); err != nil {
			logger.Warn("停止插件进程时出现问题", "err", err)
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
