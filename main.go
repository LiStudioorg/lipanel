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
	"lipanel/internal/file"
	"lipanel/internal/plugin"
	"lipanel/internal/server"
	"lipanel/internal/service"
	"lipanel/internal/site"
	"lipanel/internal/ssl"
	"lipanel/internal/store"
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

		serviceTimeout = flag.Duration("service-timeout", service.DefaultCommandTimeout,
			"单个服务启停操作中每次 systemctl 调用的超时（如 30s、2m）")

		fileRoots = flag.String("file-root", file.DefaultRoot,
			"文件管理允许访问的根目录，多个用逗号分隔（安全白名单；用户无法访问其外的任何路径）")
		fileMaxUpload = flag.Int64("file-max-upload", file.DefaultMaxUploadBytes,
			"单次上传文件的大小上限（字节，默认 128MiB）")
		fileMaxEdit = flag.Int64("file-max-edit", file.DefaultMaxEditBytes,
			"内置文本编辑器可打开/保存的最大文件（字节，默认 2MiB）")

		nginxPrefix = flag.String("nginx-prefix", "",
			"nginx 的 prefix 目录（留空则自动探测 /etc/nginx）；"+
				"站点管理会读写其下的 sites-available/sites-enabled 或 conf.d")
		nginxConf = flag.String("nginx-conf", "",
			"nginx 主配置路径（留空则为 <nginx-prefix>/nginx.conf）；"+
				"用于解析它 include 了哪些站点目录")
		nginxCommandTimeout = flag.Duration("nginx-timeout", site.DefaultCommandTimeout,
			"单次 nginx 命令（-t 校验 / -s reload）的超时（如 30s、1m）")

		certbotPath = flag.String("certbot-path", "",
			"certbot 可执行文件路径（留空则按 PATH 查找 certbot，再退到 acme.sh）")
		certbotEmail = flag.String("certbot-email", "",
			"Let's Encrypt 账号邮箱（留空仍可签发，但收不到到期提醒）")
		certRenewDays = flag.Int("cert-renew-days", ssl.DefaultRenewDays,
			"证书剩余天数低于此值时判定为「即将过期」，并纳入自动续期（默认 30）")
		certRenewInterval = flag.Duration("cert-renew-interval", ssl.DefaultRenewInterval,
			"自动续期的检查间隔（默认 12h）；设为 0 可关闭自动续期")
		certDryRun = flag.Bool("cert-dry-run", false,
			"试运行模式：使用 ACME staging 环境且不写入证书文件。"+
				"该模式**不消耗**生产配额，适合先验证域名解析与 80 端口是否就绪")
		certCommandTimeout = flag.Duration("cert-timeout", ssl.DefaultCommandTimeout,
			"单次 certbot 命令的超时（如 2m、5m）。"+
				"申请需要与 CA 多次往返，超时设置过短会导致「证书已签发但本地未拿到」")

		storePkgManager = flag.String("store-package-manager", "",
			"强制指定软件商店使用的包管理器（apt / dnf / yum）；"+
				"留空则按发行版自动探测。仅在自动探测出错时才需要手工指定")
		storeStepTimeout = flag.Duration("store-step-timeout", store.DefaultStepTimeout,
			"软件商店单条命令（apt-get / dnf / curl / tar）的超时（默认 10m）。"+
				"装 MySQL 这类软件要下载上百 MB，超时过短会在解包中途被掐断")
		storeTaskTimeout = flag.Duration("store-task-timeout", store.DefaultTaskTimeout,
			"软件商店单个安装/卸载任务的超时（默认 45m）")
		storeStateDir = flag.String("store-state-dir", store.DefaultStateDir,
			"软件商店的状态目录（记录预编译安装、下载缓存）；"+
				"默认 "+store.DefaultStateDir)
		storeLogLimit = flag.Int("store-log-limit", store.DefaultLogLimit,
			"单个任务保留的日志行数上限（超出后丢弃最早的日志）")
		storeMaxTasks = flag.Int("store-max-tasks", store.DefaultMaxTasks,
			"内存中保留的最近任务数（面板重启后丢失，历史留痕见审计日志）")
		storeShutdownGrace = flag.Duration("store-shutdown-grace", store.DefaultShutdownGrace,
			"退出时等待正在进行的安装/卸载任务收尾的最长时间（默认 15m）。"+
				"该等待**不会中断**包管理器：超时后进程退出，但 apt/dpkg 可能仍在运行")
		storeDryRun = flag.Bool("store-dry-run", false,
			"试运行模式：只记录将要执行的命令，**不安装任何软件、不写任何系统文件**。"+
				"用于在正式机器上先看清楚面板到底会做什么")
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

	// 服务管理器（阶段四 4.1）。
	//
	// 审计采用「统一落盘、分别查询」：
	//   · 落盘：与插件审计**共用同一个 -audit-log 文件**（JSONL 追加写），
	//     一次 tail -f / 一套采集器即可覆盖面板的全部操作留痕；
	//   · 查询：两者各有独立类型、独立环形缓冲与独立查询接口
	//     （/api/services/audit 与 /api/plugins/audit），互不污染。
	//
	// 共用文件的并发安全性：两边都以 O_APPEND 打开，且每次写入都是
	// 单次 write 系统调用（一行数百字节的 JSON + '\n'），
	// 因此两条写入流不会互相截断或交错。
	//
	// 刻意**不**伪造一个 "core:systemd" 之类的插件 ID 来复用插件审计类型：
	// 那会让插件审计页冒出一个根本不存在的「插件」，统计也随之失真。
	serviceAuditor, err := service.NewAuditor(service.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = serviceAuditor.Close() }()

	serviceManager, err := service.NewManager(service.Options{
		Logger:         logger,
		CommandTimeout: *serviceTimeout,
		Auditor:        serviceAuditor,
	})
	if err != nil {
		return err
	}
	// 无 systemd 时只告警不阻断：面板其它功能必须照常可用
	// （计划要求：无 systemd 时优雅降级并提示）。
	if !serviceManager.Available() {
		logger.Warn("服务管理不可用，面板其它功能不受影响",
			"reason", serviceManager.UnavailableReason())
	}

	// 文件管理器（阶段四 4.2）。
	//
	// 审计同样是「统一落盘、分别查询」：与插件/服务审计共用同一个 -audit-log
	// 文件（JSONL 追加写），但有独立的类型、环形缓冲与查询接口
	// （/api/files/audit），互不污染。
	fileAuditor, err := file.NewAuditor(file.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = fileAuditor.Close() }()

	fileRootList := splitList(*fileRoots)
	fileManager, err := file.NewManager(file.ManagerOptions{
		Roots:          fileRootList,
		MaxUploadBytes: *fileMaxUpload,
		MaxEditBytes:   *fileMaxEdit,
		Logger:         logger,
		Auditor:        fileAuditor,
	})
	if err != nil {
		return fmt.Errorf("初始化文件管理失败: %w", err)
	}
	logger.Info("文件管理已就绪",
		"roots", fileRootList,
		"max_upload_bytes", *fileMaxUpload,
		"max_edit_bytes", *fileMaxEdit,
	)
	// 根目录设为 "/" 时给出显式告警：这不是错误（面板管理员本就该能管理整机），
	// 但它是**最容易被忽视的一处授权**——等于把整台服务器的文件读写交给了
	// 任何一个能登录面板的账号。宁可多一句提醒，也不要让用户事后才发现。
	if len(fileRootList) == 1 && fileRootList[0] == "/" {
		logger.Warn("文件管理的可访问根目录为 /（整机文件均可读写）",
			"hint", "如需收窄范围，可用 -file-root /home,/etc/nginx 指定白名单目录")
	}

	// 站点管理器（阶段四 4.3，核心自带）。
	//
	// 审计同样是「统一落盘、分别查询」：与插件/服务/文件审计共用同一个
	// -audit-log 文件（JSONL 追加写），但有独立的类型、环形缓冲与查询接口
	// （/api/sites/audit），互不污染。
	siteAuditor, err := site.NewAuditor(site.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = siteAuditor.Close() }()

	// nginx 目录布局适配器：探测 sites-available/sites-enabled 还是 conf.d。
	//
	// 探测依据是 nginx.conf 里**真实的 include 行**，而不是猜发行版名字
	// （用户完全可以自定义 nginx.conf，容器镜像里也常见
	// 「Ubuntu 的 os-release + 自写的 nginx.conf」这种组合）。
	siteAdapter := site.NewSystemAdapter(site.AdapterOptions{
		Prefix:   *nginxPrefix,
		ConfPath: *nginxConf,
	})

	// RootChecker 把「静态站根目录」的两道闸门合成一次判定：
	//
	//	① 4.2 的路径白名单（file.Resolver）——回答「这个路径能不能碰」；
	//	② 存在且是目录                   ——回答「这个路径现在能不能用」。
	//
	// 通过闭包注入而不是让 site 包 import file 包：那会让两个核心模块
	// 形成依赖环，而这里真正需要的只是"一个判断路径是否可用的函数"。
	//
	// 复用 4.2 的白名单是刻意的：站点根目录就是文件管理能碰到的那些目录，
	// 两处若各有一套规则，用户就会遇到"文件管理里能看到的目录，
	// 建站时却说不合法"这种无从解释的偏差。
	siteRootChecker := func(path string) error {
		real, err := fileManager.Resolver().ResolveExisting(path)
		if err != nil {
			return fmt.Errorf("站点根目录不在允许范围内: %w", err)
		}
		info, err := os.Stat(real)
		if err != nil {
			return fmt.Errorf("站点根目录不可用: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("站点根目录 %s 不是目录", real)
		}
		return nil
	}

	siteManager, err := site.NewManager(site.ManagerOptions{
		Logger:         logger,
		Adapter:        siteAdapter,
		Auditor:        siteAuditor,
		CommandTimeout: *nginxCommandTimeout,
		RootChecker:    siteRootChecker,
	})
	if err != nil {
		return fmt.Errorf("初始化站点管理失败: %w", err)
	}
	// 无 nginx 时只告警不阻断：面板其它功能必须照常可用
	// （与 4.1 无 systemd 的降级策略完全一致）。
	if !siteManager.Available() {
		logger.Warn("站点管理不可用，面板其它功能不受影响",
			"reason", siteManager.UnavailableReason())
	} else {
		logger.Info("站点管理已就绪",
			"nginx", siteAdapter.Executable(),
			"mode", siteAdapter.Mode(),
			"available_dir", siteAdapter.AvailableDir(),
			"enabled_dir", siteAdapter.EnabledDir(),
		)
	}

	// SSL 证书管理器（阶段四 4.4，核心自带）。
	//
	// 审计同样是「统一落盘、分别查询」：与插件/服务/文件/站点审计
	// 共用同一个 -audit-log 文件（JSONL 追加写），但有独立的类型、
	// 环形缓冲与查询接口（/api/ssl/audit），互不污染。
	sslAuditor, err := ssl.NewAuditor(ssl.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = sslAuditor.Close() }()

	// 站点提供器：把 site.Manager 适配成 ssl 包需要的最小视图。
	//
	// 用适配器而不是让 ssl 包直接依赖 site.Manager，有两个理由：
	//
	//	① 避免 ssl → site 的包依赖（site 也需要 ssl 的证书路径概念，
	//	   直接互相 import 会形成环）；
	//	② 更重要的是**收窄能力**：适配器只暴露证书模块真正需要的
	//	   四个字段，"证书模块会不会顺手改站点"这个问题
	//	   在类型层面就有了答案——它拿到的信息不足以做别的事。
	sslSiteProvider := &sslSiteAdapter{mgr: siteManager}

	// 配置写入器：把 SSL 配置交回 4.3 的 site.Manager 渲染与落盘。
	//
	// ########## 为什么必须走 site.Manager 而不是自己写文件 ##########
	//
	// 证书配置写错 = **整台机器的 HTTPS 全部不可用**。
	// site.Manager.SetSSL 复用的是 4.3 已经做对并被测试锁死的链路：
	//
	//	快照（配置内容 + 启用链接 + disabled 文件）
	//	→ 写盘 → nginx -t ─┬─ 通过 → reload ─┬─ 成功 → 完成
	//	                   │                 └─ 失败 → 回滚 → 复验
	//	                   └─ 失败 → 回滚 → 复验
	//
	// 让 ssl 包自己写配置，等于把这套带测试的链路复制一份，
	// 而复制品一旦出问题，用户丢的是全部站点的 HTTPS。
	sslRewriter := &sslConfigRewriter{mgr: siteManager}

	sslManager, err := ssl.NewManager(ssl.ManagerOptions{
		Logger: logger,
		Detector: ssl.NewDetector(ssl.DetectorOptions{
			CertbotPath: *certbotPath,
			Logger:      logger,
		}),
		Sites:          sslSiteProvider,
		Rewriter:       sslRewriter,
		Auditor:        sslAuditor,
		Email:          *certbotEmail,
		RenewDays:      *certRenewDays,
		CommandTimeout: *certCommandTimeout,
		DryRun:         *certDryRun,
	})
	if err != nil {
		return fmt.Errorf("初始化 SSL 证书管理失败: %w", err)
	}

	// 自动续期调度器（阶段四 4.4）。
	//
	// -cert-renew-interval 0 表示**不启动**调度器（只用手动续期）。
	// 这与"间隔为 0 时用默认值"不同，因此需要显式判断
	// （坑位 12：零值无法表达"我确实想要 0"）。
	var sslScheduler *ssl.RenewScheduler
	if *certRenewInterval != 0 {
		sslScheduler = ssl.NewRenewScheduler(ssl.RenewSchedulerOptions{
			Manager:  sslManager,
			Interval: *certRenewInterval,
			DryRun:   *certDryRun,
			Logger:   logger,
		})
	}

	// 探测一次 ACME 客户端可用性，把结论打进启动日志。
	//
	// 为什么在启动时主动探测（而不是等第一次请求）：
	// "这台机器能不能申请证书"是运维最关心的启动信息之一，
	// 而探测失败**不阻断启动**（面板其它功能必须照常可用，
	// 与 4.1 无 systemd 的降级策略一致）。
	if sslManager.Available() {
		cap := sslManager.Capabilities(context.Background())
		if cap.Available {
			logger.Info("SSL 证书管理已就绪",
				"client", cap.Client.Kind,
				"path", cap.Client.Path,
				"version", cap.Client.Version,
				"challenge", cap.ChallengeType,
				"renew_days", cap.RenewDays,
				"dry_run", cap.DryRun,
				"auto_renew", sslScheduler != nil,
			)
			for _, note := range cap.Notes {
				logger.Info("SSL 提示", "note", note)
			}
		} else {
			logger.Warn("SSL 证书管理不可用，面板其它功能不受影响",
				"reason", cap.Reason)
		}
	} else {
		logger.Warn("SSL 证书管理不可用，面板其它功能不受影响",
			"reason", sslManager.UnavailableReason())
	}

	// 软件商店（阶段四 4.5，核心自带）。
	//
	// ########## 本模块与其它四个模块最重要的差别 ##########
	//
	// 4.1~4.4 的写操作都是"改面板管得着的东西"（服务、文件、站点配置、证书）。
	// 软件商店不是：它**以 root 身份运行发行版包管理器**，
	// 而包的 postinst 脚本可以改动系统里的任何东西。
	// 因此这里额外做了三件事：
	//
	//	① 清单内嵌在二进制里（catalog.json 经 go:embed），
	//	   用户输入只用于查表，不能影响命令内容；
	//	② 官方源相关的系统路径可被 -store-* 之外的覆盖项重定向，
	//	   便于隔离测试；生产使用默认系统路径；
	//	③ 提供 -store-dry-run，让用户能先看清楚会执行什么。
	//
	// 审计同样"统一落盘、分别查询"：与插件/服务/文件/站点/SSL 审计
	// 共用同一个 -audit-log 文件（JSONL 追加写），有独立类型、
	// 环形缓冲与查询接口（/api/store/audit），互不污染。
	storeAuditor, err := store.NewAuditor(store.AuditOptions{
		Capacity: *pluginAuditBuf,
		Path:     *pluginAuditLog,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = storeAuditor.Close() }()

	// 环境探测：决定用哪个包管理器、发行版代号、架构。
	// 探测失败**不阻断启动**——面板其它功能必须照常可用
	// （与 4.1 无 systemd、4.3 无 nginx 的降级策略一致）。
	storeVars := store.DetectVars(store.AdapterOptions{ForceManager: *storePkgManager})

	storeManager, err := store.NewManager(store.Options{
		Logger:      logger,
		Auditor:     storeAuditor,
		Vars:        storeVars,
		SkipDetect:  true, // 环境已在上面探测过，避免二次探测得出不同结论
		StateDir:    *storeStateDir,
		StepTimeout: *storeStepTimeout,
		TaskTimeout: *storeTaskTimeout,
		LogLimit:    *storeLogLimit,
		MaxTasks:    *storeMaxTasks,
		DryRun:      *storeDryRun,

		// ########## 系统路径的隔离开关（仅测试与嵌入场景） ##########
		//
		// 追加官方源需要写三个位置。生产环境必须是系统路径
		// （否则 apt/dnf 根本不认这些源）；但端到端测试必须能
		// 在**不污染开发机**的前提下把这条链路跑完。
		//
		// 这里用环境变量而不是命令行参数，是刻意的：
		// 它不该出现在 --help 里引导用户去改（改错了面板写的源
		// 就不会被系统识别，表现为"追加官方源成功但装不上"，
		// 极难排查）。环境变量只在自动化测试的脚本里出现。
		ListDirOverride:    os.Getenv("LIPANEL_STORE_LIST_DIR"),
		KeyringDirOverride: os.Getenv("LIPANEL_STORE_KEYRING_DIR"),
		YumRepoDirOverride: os.Getenv("LIPANEL_STORE_YUM_REPO_DIR"),
	})
	if err != nil {
		return fmt.Errorf("初始化软件商店失败: %w", err)
	}

	if storeManager.Available() {
		logger.Info("软件商店已就绪",
			"env", storeVars.Describe(),
			"official_source", storeVars.SupportsOfficialSource(),
			"software", len(storeManager.Catalog().Software),
			"state_dir", *storeStateDir,
			"dry_run", *storeDryRun,
		)
		for _, note := range storeVars.ProbeNotes {
			logger.Info("软件商店提示", "note", note)
		}
		if *storeDryRun {
			logger.Warn("软件商店处于试运行模式（-store-dry-run）：" +
				"不会真的安装任何软件，也不会写入任何系统文件")
		}
	} else {
		logger.Warn("软件商店不可用，面板其它功能不受影响",
			"reason", storeManager.UnavailableReason())
	}

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
		Services:  serviceManager,
		Files:     fileManager,
		Sites:     siteManager,
		SSL:       sslManager,
		// 调度器单独注入：它是可选的（用户可能只想手动续期），
		// 而状态接口需要在它不存在时也能正常返回。
		SSLScheduler: sslScheduler,
		Store:        storeManager,
	})
	if err != nil {
		return err
	}

	// 监听 SIGINT/SIGTERM，实现优雅关闭。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 启动自动续期调度（阶段四 4.4）。
	//
	// 放在 ctx 建立之后：调度器随主进程的退出信号一起结束，
	// 因此**不会留下孤儿 goroutine** 在关闭过程中拉起 certbot。
	// Close 会等待 goroutine 真正退出（不只是发个取消信号），
	// 因此下面的 defer 能保证进程退出前续期任务已完全停止——
	// 这正是坑位 16 那类"看起来停了、其实还在跑"的同一个问题。
	if sslScheduler != nil {
		sslScheduler.Start(ctx)
		defer func() { _ = sslScheduler.Close() }()
	}

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

		// ########## 等待正在进行的安装任务收尾 ##########
		//
		// 这一段的顺序很关键，而且用的是**独立于 shutdownCtx 的超时**。
		//
		// 10 秒的 shutdownCtx 对 HTTP 收尾够用，但对装软件远远不够：
		// `apt-get install mysql-server` 要跑几分钟。若在它执行到一半时
		// 退出进程，dpkg 的数据库会停在"半安装（iF）"状态，
		// 用户下次启动面板看到的是一个坏掉的 apt ——
		// 而且这个问题**无法通过重试面板修复**，只能人工 dpkg --configure -a。
		//
		// 因此：先停止接收新请求（上面的 srv.Shutdown），
		// 再给正在跑的任务一段专门的等待时间。超时后**不杀进程**——
		// 我们只能选择"等它"或"留它继续跑"，绝不做第三种事。
		if storeManager.RunningTask() != nil || !storeManager.Idle() {
			storeCtx, storeCancel := context.WithTimeout(
				context.Background(), *storeShutdownGrace)
			logger.Info("有安装/卸载任务正在进行，等待其收尾（不会中断包管理器）",
				"grace", storeShutdownGrace.String())
			if err := storeManager.Shutdown(storeCtx); err != nil {
				logger.Warn("安装/卸载任务未在宽限期内结束；"+
					"进程退出后包管理器可能仍在运行，"+
					"请勿立即重启面板（会与它抢同一把全局锁）", "err", err)
			} else {
				logger.Info("安装/卸载任务已收尾")
			}
			storeCancel()
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

// splitList 把逗号分隔的启动参数拆成去空白、去空项的字符串切片。
//
// 单独一个函数而不是用 strings.Split 直接塞给调用方：
// `-file-root "/home, /srv "` 这种写法里的空格必须被去掉，
// 否则会得到一个叫 " /srv " 的根目录，file.NewResolver 会报
// "根目录不可用"，用户对着一个看起来完全正常的参数无从排查。
func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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

// ============================================================================
// SSL 与站点模块之间的适配器（阶段四 4.4）
// ============================================================================
//
// 这两个类型是 ssl 包与 site 包之间**唯一**的接触面。
//
// ########## 为什么用适配器而不是让两个包互相 import ##########
//
// ssl 需要 site 的"写入配置"能力，site 需要 ssl 的"证书路径"概念。
// 直接互相 import 会形成**循环依赖**，Go 编译器不会允许。
//
// 但这不只是绕开编译器限制——适配器同时收窄了能力：
//
//	sslSiteAdapter     只暴露证书模块真正需要的 4 个字段，
//	                   因此"证书模块顺手改站点配置"在类型层面就不可能；
//	sslConfigRewriter  只暴露"应用/移除 SSL"两个动作，
//	                   证书模块无法借它去删除站点或改域名。
//
// 与 4.3 用 RootChecker 闭包避免 site → file 依赖是同一个手法。

// sslSiteAdapter 把 site.Manager 适配成 ssl.SiteProvider。
type sslSiteAdapter struct {
	mgr *site.Manager
}

// GetSite 返回单个站点的最小视图。
func (a *sslSiteAdapter) GetSite(name string) (ssl.SiteRef, error) {
	s, err := a.mgr.Get(name)
	if err != nil {
		return ssl.SiteRef{}, err
	}
	return toSiteRef(s), nil
}

// ListSites 返回全部站点的最小视图。
func (a *sslSiteAdapter) ListSites() ([]ssl.SiteRef, error) {
	list, err := a.mgr.List()
	if err != nil {
		return nil, err
	}
	out := make([]ssl.SiteRef, 0, len(list))
	for _, s := range list {
		out = append(out, toSiteRef(s))
	}
	return out, nil
}

// toSiteRef 把 site.Site 映射成 ssl 需要的最小视图。
//
// 刻意只搬运 4 个字段：证书模块不需要知道站点的启用状态之外
// 任何"能改站点"的信息。
func toSiteRef(s site.Site) ssl.SiteRef {
	return ssl.SiteRef{
		Name:       s.Name,
		Domain:     s.Domain,
		Root:       s.Root,
		Upstream:   s.Upstream,
		Type:       s.Type,
		Enabled:    s.Enabled,
		ConfigPath: s.ConfigPath,
	}
}

// sslConfigRewriter 把 ssl.ConfigRewriter 的实现委托给 site.Manager。
//
// 它存在的意义只有一个：**让证书配置走 4.3 已验证的回滚链路**。
// 这里不做任何自己的文件操作——那正是要避免的事。
type sslConfigRewriter struct {
	mgr *site.Manager
}

// ApplySSL 把 TLS 配置写入站点（走 site.Manager 的完整校验与回滚链路）。
func (r *sslConfigRewriter) ApplySSL(ctx context.Context, siteName string, cfg ssl.SSLConfig) error {
	_, err := r.mgr.SetSSL(ctx, siteName, &site.SSLConfig{
		CertPath:     cfg.CertPath,
		KeyPath:      cfg.KeyPath,
		RedirectHTTP: cfg.RedirectHTTP,
		Protocols:    cfg.Protocols,
		Ciphers:      cfg.Ciphers,
	})
	if err != nil {
		// 把 site 包的错误原样带上去（含"是否已回滚"的信息）：
		// 调用方（ssl.Manager）需要它来判断这是"配置没写成功"
		// 还是"写坏了但已自动恢复"——两者对用户的含义完全不同。
		return fmt.Errorf("site: %w", err)
	}
	return nil
}

// RemoveSSL 从站点配置中移除 TLS 设置（回到纯 HTTP）。
func (r *sslConfigRewriter) RemoveSSL(ctx context.Context, siteName string) error {
	if _, err := r.mgr.SetSSL(ctx, siteName, nil); err != nil {
		return fmt.Errorf("site: %w", err)
	}
	return nil
}
