package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lipanel/internal/cron"
)

// ============================================================================
// 与计划任务（crontab）的挂接（阶段五 5.3）
// ============================================================================
//
// 计划要求「备份任务复用 5.2 的 cron 机制（把备份任务挂到 crontab 上）」。
// 落地方式：每个启用中的备份任务，对应 crontab 上的**一条**普通计划任务。
//
// ########## crontab 行里到底写了什么 ##########
//
//	crontab 行（由 cron.Manager 生成，不含任何用户文本）
//	  → /bin/sh '<cron-data>/jobs/<cronjobid>.sh'    ← 5.2 的日志包装脚本
//	    → '<面板二进制>' __backup_run <taskid> -backup-store '<store.json>'
//
// ########## 为什么让面板"自己再执行自己"，而不是在面板里起定时器 ##########
//
// ① 备份是**长时间、可能卡死**的操作（往远端传几十 GB）。跑在独立
//    进程里，它可以被 cron 的日志包装记下开始/结束/退出码，也不会
//    因为一次卡住的上传把面板主进程拖住。
// ② 真实的面板会重启、会被升级、会被 systemd 拉起。进程内的定时器
//    在重启窗口里是**静默漏跑**的，而 crontab 不会——它记的是
//    "这台机器在该跑的时候要跑什么"，与面板活不活着无关。
// ③ 自调用二进制是本项目已有的成熟模式：内置插件就是
//    `exec.Command(自身二进制, "__plugin_<id>")` 拉起来的。
//
// ########## 命令文本的结构安全性 ##########
//
// 与 5.2 的 jobLine 同一理由：命令里**唯一**的可变部分是任务 id 与
// 存储配置文件路径，两者都由面板生成——id 先过 12 位 hex 形态校验，
// 路径来自启动参数且用单引号包住。用户的任何输入（源路径、任务名、
// 备注、前缀）**都不出现在命令里**，它们待在 tasks.json 里由子进程读。
// 因此"命令注入"在这里不是"要过滤好的危险面"，而是结构上不可能。

// cronLinkOptions 是挂接所需的运行期信息。
type cronLinkOptions struct {
	// Executable 是面板二进制的绝对路径（子进程入口）。
	Executable string
	// StorePath 是配置文件路径（子进程据此读到任务定义）。
	StorePath string
}

// cronCommandFor 生成挂到 crontab 上的命令文本。
func cronCommandFor(execPath, storePath, taskID string) string {
	// 单引号包裹两个参数：即便路径里有空格也不会被 shell 拆开。
	// 路径里若真含单引号，会被下面的引用逻辑拒绝（见 quoteShellArg）。
	return quoteShellArg(execPath) + " " + backupRunSubcommand + " " + taskID +
		" -backup-store " + quoteShellArg(storePath)
}

// backupRunSubcommand 是自调用子命令名。
//
// 名字刻意带 __ 前缀并与 5.2 的 __plugin_ 家族保持同一风格：
// 它们在 flag.Parse 之前被拦下，永远不会被当成普通参数。
const backupRunSubcommand = "__backup_run"

// quoteShellArg 用单引号包裹一个参数。
//
// 单引号是 shell 里唯一"里面什么都不解释"的引用方式，因此路径里
// 的 $、反引号、空格都安全。唯一的例外是单引号本身——它无法在
// 单引号串里表示，因此直接拒绝（面板自己的路径不该含单引号；
// 含了就说明部署方式很特别，明确报错比生成一条会跑歪的命令好）。
func quoteShellArg(s string) string {
	if strings.ContainsRune(s, '\'') {
		// 返回一个必然失败的命令：调用方在挂接前会先过
		// validateCronCommandPath 拦住这种情况。
		return "''"
	}
	return "'" + s + "'"
}

// commentFor 生成 crontab 上的备注（用户可见，因此要能看懂）。
func commentFor(task *Task) string {
	name := task.Name
	if name == "" {
		name = task.SourcePath
	}
	suffix := "[lipanel 备份] "
	// 备注上限 200 字节（cron.MaxCommentLen），超出要截断——
	// 但不静默截断到看不出是什么任务：保留名字前缀并加省略号。
	max := cron.MaxCommentLen - len(suffix)
	if max < 8 {
		max = 8
	}
	if len(name) > max {
		name = trimToBytes(name, max-3) + "..."
	}
	return suffix + name
}

// trimToBytes 按字节截断但不切开 UTF-8 字符。
func trimToBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	b := []byte(s)[:max]
	// 回退到最后一个完整字符边界（UTF-8 的续字节形如 10xxxxxx）。
	for len(b) > 0 && b[len(b)-1]&0xC0 == 0x80 {
		b = b[:len(b)-1]
	}
	return string(b)
}

// validateCronCommandPath 校验会被拼进 crontab 命令的路径。
func validateCronCommandPath(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("backup: 路径为空")
	}
	if strings.ContainsRune(p, '\'') {
		return fmt.Errorf("backup: 路径 %q 含单引号，无法安全地写进 crontab 命令", p)
	}
	if strings.ContainsAny(p, "\r\n\t") {
		return fmt.Errorf("backup: 路径 %q 含换行或制表符", p)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("backup: 路径 %q 必须是绝对路径（cron 的工作目录不可预期）", p)
	}
	return nil
}

// ErrCronDisabled 表示该任务被停用（用户主动要求不挂 crontab）。
var ErrCronDisabled = errors.New("backup: 任务已停用，不会挂到计划任务上")

// syncCron 把任务同步到 crontab。
//
// 返回值 jobID 是 crontab 上那条任务的 id（空表示没挂）。
// 语义：
//   - 任务停用   → 确保 crontab 上没有它（删掉），返回 ("", ErrCronDisabled)
//   - 任务启用   → 已挂则更新，未挂则新建
//
// ########## cron 不可用时为什么不报错 ##########
//
// "这台机器没装 cron"与"用户填错了东西"是两件完全不同的事。
// 对前者报错会让用户在没装 cron 的容器里根本存不下备份任务——
// 而备份任务即便不能定时跑，手动执行依然完全可用。
// 因此这里如实返回原因（CronReason），任务照常保存。
func (m *Manager) syncCron(ctx context.Context, task *Task) (string, string, error) {
	if m.cron == nil {
		return "", "计划任务模块未启用（面板启动时未注入 cron 管理器），任务已保存但不会定时执行", nil
	}
	if !task.Enabled {
		// 停用：把已有的一条删掉，并清空记录。
		if task.CronJobID != "" {
			if err := m.removeCronJob(ctx, task.CronJobID); err != nil {
				return "", "", err
			}
		}
		return "", "任务已停用（不会定时执行，可手动执行）", nil
	}

	execPath := m.cronOpts.Executable
	storePath := m.cronOpts.StorePath
	if err := validateCronCommandPath(execPath); err != nil {
		return "", fmt.Sprintf("无法确定面板二进制路径（%v），任务不会定时执行", err), nil
	}
	if err := validateCronCommandPath(storePath); err != nil {
		return "", fmt.Sprintf("配置文件路径不合法（%v），任务不会定时执行", err), nil
	}

	// 表达式先过 cron 的解析器：备份任务存下来但表达式非法时，
	// 不该在 crontab 上留一条 cron 永远不执行的垃圾行。
	if _, err := cron.ValidateExpr(task.Expr); err != nil {
		return "", "表达式不被计划任务模块支持（" +
			strings.TrimPrefix(err.Error(), "cron: ") + "），任务不会定时执行", nil
	}

	// crontab 不可读写（没装 cron / 隔离模式下的文件不可写）：
	// 不阻断保存，但如实说明。
	if err := m.cronAvailable(ctx); err != nil {
		return "", "计划任务当前不可用（" + err.Error() + "），任务已保存但不会定时执行", nil
	}

	cmd := cronCommandFor(execPath, storePath, task.ID)
	comment := commentFor(task)
	in := cron.JobInput{Expression: task.Expr, Command: cmd, Comment: comment}

	if task.CronJobID != "" {
		// 已挂：更新。表达式或备注变了都要改，否则用户会在 crontab 里
		// 看到一条与面板显示不一致的任务。
		res, err := m.cron.Update(ctx, task.CronJobID, in)
		if err == nil && res != nil && res.Job != nil {
			return res.Job.ID, "", nil
		}
		// 更新失败最可能是"那条 crontab 任务已被外部删掉"（404）。
		// 此时不该让整个保存失败——重新挂一条即可。
		if !errors.Is(err, cron.ErrJobNotFound) {
			return "", "任务已保存，但同步到计划任务失败：" + trimErr(err), nil
		}
		m.logger.Warn("crontab 上的对应任务已不存在，将重新创建", "task", task.ID, "cron_job", task.CronJobID)
		task.CronJobID = ""
	}

	res, err := m.cron.Create(ctx, in)
	if err != nil {
		return "", "任务已保存，但挂到计划任务失败：" + trimErr(err), nil
	}
	if res == nil || res.Job == nil {
		return "", "任务已保存，但挂到计划任务失败：未返回任务信息", nil
	}
	return res.Job.ID, "", nil
}

// removeCronJob 从 crontab 上删掉一条任务。
func (m *Manager) removeCronJob(ctx context.Context, jobID string) error {
	if m.cron == nil || jobID == "" {
		return nil
	}
	if err := cron.ValidateJobID(jobID); err != nil {
		// 形态非法的 id 不可能来自面板，忽略即可（防御性）。
		return nil
	}
	_, err := m.cron.Delete(ctx, jobID, true, nil)
	if err != nil && !errors.Is(err, cron.ErrJobNotFound) {
		return fmt.Errorf("backup: 从计划任务中删除失败（crontab 上可能存在残留条目，请在计划任务页确认）: %w", err)
	}
	return nil
}

// cronAvailable 判断 crontab 此刻是否可读写。
func (m *Manager) cronAvailable(ctx context.Context) error {
	if m.cron == nil {
		return errors.New("未注入计划任务管理器")
	}
	st := m.cron.Status(ctx)
	if !st.Available {
		if st.Reason != "" {
			return errors.New(st.Reason)
		}
		return errors.New("crontab 不可读写")
	}
	return nil
}

// trimErr 把错误压成一行短文本（crontab 备注与界面提示都要短）。
func trimErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// 去掉 "backup: " / "cron: " 这类模块前缀，它在这里没有信息量。
	for _, prefix := range []string{"backup: ", "cron: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	if len(msg) > 200 {
		msg = trimToBytes(msg, 197) + "..."
	}
	return msg
}

// executablePath 返回当前进程的可执行文件绝对路径。
//
// 解析失败时返回空串（调用方据此如实报告"无法定时执行"），
// 而不是 panic 或猜一个路径——猜错的后果是 crontab 里一条
// 永远运行失败的任务，而那正是"什么都没发生"那类故障。
func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}
