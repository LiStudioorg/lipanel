//go:build windows

package plugin

import (
	"os"
	"os/exec"
)

// 本文件是 Windows 上的进程控制实现。
//
// Windows 与 Unix 的模型差异：
//   - 没有 POSIX 信号（SIGTERM/SIGKILL）与进程组。Windows 上的"优雅停止"
//     通常走控制台控制事件（GenerateConsoleCtrlEvent）或窗口消息；
//   - syscall.SysProcAttr 没有 Setpgid 字段，Kill/ESRCH 也不存在。
//
// 因此这里统一降级为 os.Process.Kill()：它能可靠地结束进程，但**不区分**
// 优雅与强制。调用方（Stop）会先等一个极短的窗口让对方自己退出，
// 超时后调用 killProcess 强制结束——语义上仍然可用。

// setProcessGroup 在 Windows 上没有进程组概念，因此不做任何事。
//
// 注意：这意味插件自己拉起的子进程不会被连带结束（Unix 上可以）。
// 对内置插件无影响——它们是同一个可执行文件的子命令，不会自我派生。
func setProcessGroup(cmd *exec.Cmd) {
	// 有意留空：Windows 无 Setpgid。
}

// terminateProcess 在 Windows 上无法发送 SIGTERM。
//
// 返回 nil 而不是错误：调用方会把"无法优雅停止"理解为"需要等待超时后强制杀掉"，
// 这是 Windows 上预期且正常的路径，不应产生告警日志。
func terminateProcess(pid int) error {
	return nil
}

// killProcess 强制结束进程（Windows 上的唯一可靠手段）。
func killProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// isProcessGone 判断错误是否表示"进程已不存在"。
//
// Windows 上没有 ESRCH；os.FindProcess 在 Windows 上总能成功，
// 因此真正的"已退出"信号来自 Kill 返回的 os.ErrProcessDone。
func isProcessGone(err error) bool {
	return err == nil || os.IsNotExist(err) || err == os.ErrProcessDone
}
