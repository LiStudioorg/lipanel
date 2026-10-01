package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lipanel/internal/backup"
)

// ============================================================================
// 自调用子命令：__backup_run（阶段五 5.3）
// ============================================================================
//
// 定时备份的落地链路（见 internal/backup/cronlink.go）：
//
//	crontab 行（5.2 生成）
//	  → /bin/sh '<cron-data>/jobs/<cronjobid>.sh'   ← 5.2 的日志包装脚本
//	    → '<面板二进制>' __backup_run <taskid> -backup-store '<tasks.json>'
//
// ########## 为什么必须在 flag.Parse 之前判断 ##########
//
// `__backup_run` 不是以 `-` 开头的参数。flag 包遇到位置参数会
// 直接报错退出（"flag provided but not defined"之类），
// 因此这段判断必须发生在 flag.Parse() **之前**——
// 这是 3.1 拉插件进程时踩过的同一个坑（见 plugin_main.go），
// 也是 main.go 把它放在最前面的原因。

// backupRunPrefix 是自调用子命令名（与 backup.cronlink 生成的一致）。
const backupRunPrefix = "__backup_run"

// backupRunOptions 是子命令的参数。
type backupRunOptions struct {
	taskID    string
	storePath string
	dataDir   string
	quiet     bool
}

// maybeRunAsBackupRunner 检查启动参数，若当前进程是被 cron 拉起的
// 备份执行进程，则执行备份并返回。
//
// 返回值语义与 maybeRunAsPlugin 一致：handled 为 true 表示
// "这个参数我已经处理了，调用方不要再往下走 flag.Parse()"。
func maybeRunAsBackupRunner() (handled bool, err error) {
	if len(os.Args) < 2 {
		return false, nil
	}
	if os.Args[1] != backupRunPrefix {
		return false, nil
	}

	opts, perr := parseBackupRunArgs(os.Args[2:])
	if perr != nil {
		return true, perr
	}
	return true, runBackupOnce(opts)
}

// parseBackupRunArgs 解析子命令参数。
//
// 刻意用独立的 FlagSet 而不是全局 flag：全局 flag 里有一百多个
// 面板参数，让子命令的解析与之共用会让"子命令意外接受了一个
// 面板参数"变成可能——而那条路径完全没有意义。
func parseBackupRunArgs(args []string) (backupRunOptions, error) {
	var opts backupRunOptions
	fs := flag.NewFlagSet(backupRunPrefix, flag.ContinueOnError)
	fs.StringVar(&opts.storePath, "backup-store", "",
		"备份配置文件路径（tasks.json）；不填则用 -backup-data-dir/tasks.json")
	fs.StringVar(&opts.dataDir, "backup-data-dir", backup.DefaultDataDir,
		"备份数据目录（历史、锁、staging）")
	fs.BoolVar(&opts.quiet, "quiet", false, "只记录异常，不打印常规信息")

	// 位置参数：任务 id。
	positional := []string{}
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return opts, fmt.Errorf("解析备份子命令参数失败: %w", err)
	}
	positional = append(positional, fs.Args()...)

	if len(positional) != 1 {
		return opts, fmt.Errorf(
			"用法: %s <任务id> [-backup-store <配置文件>] [-backup-data-dir <目录>]",
			backupRunPrefix)
	}
	opts.taskID = strings.TrimSpace(positional[0])
	if err := backup.ValidateTaskID(opts.taskID); err != nil {
		return opts, fmt.Errorf("非法任务 id %q", opts.taskID)
	}
	return opts, nil
}

// runBackupOnce 执行一次定时备份。
//
// 退出码语义（cron 会把非 0 退出记为失败，5.2 的包装脚本还会
// 把它写进任务日志——用户就是靠这条日志判断"昨晚到底跑没跑"）：
//
//	0  备份成功
//	1  备份失败（网络、权限、体积超限……）——**需要人看一眼**
//	2  配置或用法错误（任务不存在、配置文件读不了）
//	3  已有一次执行在进行，本次跳过（不是失败，但也没有产出）
func runBackupOnce(opts backupRunOptions) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("subcommand", backupRunPrefix, "task", opts.taskID)

	// 定时执行的日志由 5.2 的包装脚本落盘，这里只往 stderr 写，
	// 不重复写一份（两份日志必然漂移，而用户只会看其中一份）。
	storePath := opts.storePath
	if storePath == "" {
		storePath = opts.dataDir + "/tasks.json"
	}

	// 审计**不落盘**：cron 拉起的进程与面板本体是两个进程，
	// 两个进程同时往同一个 JSONL 追加虽然能工作，但会让
	// "面板审计页看到的顺序"变得难以解释。定时执行的留痕
	// 由**历史文件**（每任务一个，天然按任务隔离）承担，
	// 而历史正是用户在那个页面上要看的东西。
	auditor, err := backup.NewAuditor(backup.AuditOptions{Logger: logger})
	if err != nil {
		return err
	}
	defer func() { _ = auditor.Close() }()

	mgr, err := backup.NewManager(backup.Options{
		DataDir:   opts.dataDir,
		StorePath: storePath,
		// 源/恢复白名单在子进程里**不影响执行**（执行只用到源路径），
		// 但仍然要构造出合法的 Resolver，否则 NewManager 会失败。
		// 这里给 DefaultSourceRoot，因为源路径在任务定义里、
		// 且已经过面板本体的校验与用户的显式配置。
		SourceRoots: []string{backup.DefaultSourceRoot},
		// ########## 恢复根必须指向一个「已存在且可写」的目录 ##########
		//
		// 子进程由 cron 在无交互环境下拉起，且它**只做备份，从不恢复**，
		// 因此绝不能要求它去创建默认的 /var/lib/lipanel/restore：
		//   ① 面板可能以非 root 跑，那个目录建不了 → 整次备份直接失败；
		//   ② 即便建得了，也是一次"为不用的功能做的写操作"。
		// NewManager 会先创建数据目录本身，因此把恢复根指向它
		// 既存在又可写，是零副作用且总能成功的选择。
		// （恢复本身只在面板本体的 HTTP 接口里发生，那里有明确的目标。）
		RestoreRoots: []string{opts.dataDir},
		Logger:       logger,
		Auditor:      auditor,
		// 不在子进程里再挂一次 crontab：那是面板本体的职责，
		// 而子进程去改 crontab 会造成"每次执行都重写一遍 crontab"。
		Cron: nil,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 初始化备份管理器失败: %v\n", backupRunPrefix, err)
		os.Exit(2)
	}

	task, err := mgr.FindTaskByID(opts.taskID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 读取任务失败: %v\n", backupRunPrefix, err)
		os.Exit(2)
	}
	if task == nil {
		// 任务不存在是最值得警惕的一类：crontab 上还有那条行，
		// 但它指向的任务已经没了。必须说得足够明白，
		// 让用户知道要去面板的「计划任务」页把它删掉。
		fmt.Fprintf(os.Stderr,
			"%s: 任务 %s 不存在。crontab 上可能残留了一条指向它的计划任务，"+
				"请在面板的「计划任务」页删除对应条目。\n", backupRunPrefix, opts.taskID)
		os.Exit(2)
	}

	// 定时执行同样要能被 Ctrl+C / SIGTERM 打断（面板停机、
	// 用户在包装脚本日志里看到问题时都可能来 kill 它）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	entry, err := mgr.Execute(ctx, task, backup.TriggerCron, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 执行失败: %v\n", backupRunPrefix, err)
		os.Exit(1)
	}

	switch entry.Status {
	case backup.StatusOK:
		if !opts.quiet {
			logger.Info("定时备份完成",
				"archive", entry.ArchiveKey,
				"bytes", entry.ArchiveBytes,
				"files", entry.FileCount,
				"pruned", entry.Pruned,
				"duration_ms", time.Since(start).Milliseconds())
		}
		for _, w := range entry.Warnings {
			logger.Warn("打包告警", "detail", w)
		}
		return nil

	case backup.StatusSkipped:
		logger.Warn("本次定时执行已跳过（该任务已有一次执行在进行）",
			"reason", entry.Error)
		// 用退出码 3 而不是 0：跳过**不是成功**，cron 的日志里
		// 需要看得出"这次没有产出备份"。
		os.Exit(3)

	default:
		fmt.Fprintf(os.Stderr, "%s: 备份失败: %s\n", backupRunPrefix, entry.Error)
		for _, w := range entry.Warnings {
			fmt.Fprintf(os.Stderr, "%s: 告警: %s\n", backupRunPrefix, w)
		}
		os.Exit(1)
	}
	return nil
}
