package store

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ============================================================================
// 命令执行器
// ============================================================================
//
// 与 4.1 service.Executor、4.3 site.Executor、4.4 ssl.Executor 同构：
// name 与 args 分开传递，**不经 shell**。抽成接口是为了可测——
// 安装链路的全部策略分支（系统源命中/未命中、官方源、预编译兜底）
// 必须能用假执行器穷举，否则测试会真的去装一个 MySQL。

// ExecResult 是一次命令执行的结果。
type ExecResult struct {
	// Stdout / Stderr 是标准输出与错误（已截断）。
	Stdout string
	Stderr string
	// ExitCode 是退出码（正常退出为 0）。
	ExitCode int
	// DurationMS 是耗时（毫秒）。
	DurationMS int64
}

// Combined 返回合并后的输出（stdout 在前）。
//
// 合并而不是分开处理：apt 把正常信息写 stdout、把错误写 stderr，
// 但**两者都可能包含我们需要的诊断信息**，分开只会让每个调用点
// 各写一遍判断。
func (r ExecResult) Combined() string {
	out := strings.TrimSpace(r.Stdout)
	errOut := strings.TrimSpace(r.Stderr)
	switch {
	case out == "":
		return errOut
	case errOut == "":
		return out
	default:
		return out + "\n" + errOut
	}
}

// Executor 执行外部命令。
//
// 实现必须带超时（由调用方通过 ctx 控制），且 ctx 取消时立即返回。
type Executor interface {
	// Run 执行 argv 命令。
	Run(ctx context.Context, name string, args []string) (ExecResult, error)
	// RunScript 执行一条经 `sh -c` 的管道命令。
	//
	// ########## 为什么接口里有这个方法 ##########
	//
	// 本模块只有一处需要 shell（官方安装脚本，见 command.go 的说明）。
	// 把它单独建模而不复用 Run("/bin/sh", []string{"-c", cmd})：
	//	① 让"哪些执行走了 shell"在实现与测试里都是显式的
	//	   （假执行器可以断言"这条路径只被官方脚本用过"）；
	//	② 真实现里可以给这条路径加上额外的日志与审计标记。
	RunScript(ctx context.Context, cmd string) (ExecResult, error)
}

// execExecutor 是默认执行器，基于 os/exec。
type execExecutor struct{}

// errExitNonZero 在命令非零退出时返回（携带退出码）。
var errExitNonZero = errors.New("store: 命令非零退出")

// Run 执行 argv 命令。
func (execExecutor) Run(ctx context.Context, name string, args []string) (ExecResult, error) {
	return runExec(ctx, name, args)
}

// RunScript 执行 `sh -c` 管道命令。
//
// 用 /bin/sh 而不是 bash：本模块唯一的脚本调用（NodeSource setup）
// 官方文档写的就是 bash，但它的实际内容只用 POSIX 语法；
// 而 /bin/sh 在所有目标发行版上都存在（bash 在精简镜像里可能没有）。
// 若某个官方脚本将来真的需要 bash，应当显式改这里并在 capabilities 里标注，
// 而不是默默依赖"sh 恰好是 bash 的符号链接"（Debian 上确实不是）。
func (execExecutor) RunScript(ctx context.Context, cmd string) (ExecResult, error) {
	return runExec(ctx, "/bin/sh", []string{"-c", cmd})
}

// runExec 是 execExecutor 的公共实现。
func runExec(ctx context.Context, name string, args []string) (ExecResult, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)

	// 环境变量：与 4.1/4.3/4.4 同样的纪律，外加三条与包管理器强相关的：
	//
	//	LANG/LC_ALL=C          输出被我们解析，必须固定语言
	//	DEBIAN_FRONTEND=noninteractive
	//	                       ########## 关键 ##########
	//	                       dpkg 的 conffile 冲突、debconf 提问在
	//	                       非交互模式下会挂起等待输入，而面板是
	//	                       无终端的后台进程——表现是"安装卡住"，
	//	                       用户只能看到一个永远不动的进度条。
	//	NEEDRESTART_MODE=a     Ubuntu 装了 needrestart 时会在安装后
	//	                       询问"要不要重启服务"，同样会阻塞；
	//	                       显式回答"自动处理"。
	//	APT_LISTCHANGES_FRONTEND=none
	//	                       不弹 changelog 分页器（less）。
	cmd.Env = append(cmd.Environ(),
		"LANG=C", "LC_ALL=C",
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=a",
		"APT_LISTCHANGES_FRONTEND=none",
	)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := ExecResult{
		Stdout:     truncate(stdout.String(), maxCapturedOutput),
		Stderr:     truncate(stderr.String(), maxCapturedOutput),
		DurationMS: time.Since(start).Milliseconds(),
	}

	if err == nil {
		return res, nil
	}
	// ctx 超时/取消：与其它模块一致，单独返回 ErrTimeout 语义，
	// 让上层能区分"命令失败"与"我们没等到结果"——
	// 对包管理器而言两者的后续动作不同（超时可能已经装了一半）。
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("%w: %s 未在超时时间内返回", ErrTimeout, name)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return res, fmt.Errorf("%w: %s 被取消", ErrTimeout, name)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, fmt.Errorf("%w: %s 退出码 %d", errExitNonZero, name, res.ExitCode)
	}
	if errors.Is(err, exec.ErrNotFound) {
		return res, fmt.Errorf("store: 找不到可执行文件 %s", name)
	}
	return res, fmt.Errorf("store: 执行 %s 失败: %w", name, err)
}

// maxCapturedOutput 是单条命令保留的输出上限。
//
// 256 KiB：apt 安装的完整输出（含下载进度条）可能上百 KB，
// 任务日志需要它来排查；但无上限会让一个出错的 dpkg
// 把内存打满。截断时**保留开头**——真正的原因几乎总在前面。
const maxCapturedOutput = 256 * 1024

// truncate 截断字符串到 n 字节（按字符边界安全截断）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// 按 rune 边界回退，避免把 UTF-8 序列截成半个字符。
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n...(输出过长已截断)"
}

// utf8Start 判断字节是否是 UTF-8 字符的起始字节。
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// tailLines 把输出切成逐行，丢弃多余的空白行（供任务日志消费）。
func tailLines(s string, maxLines int) []string {
	if s == "" {
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []string
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
		if len(out) >= maxLines {
			break
		}
	}
	return out
}
