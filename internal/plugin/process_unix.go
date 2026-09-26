//go:build unix && !js

package plugin

import (
	"errors"
	"os/exec"
	"syscall"
)

// 本文件覆盖所有 Unix 系平台（Linux、Darwin、*BSD、Solaris/illumos、AIX）。
// 这些平台共享 fork/exec + 信号 + 进程组的语义，因此可以共用一个实现。

// setProcessGroup 让子进程成为新进程组的组长（pgid == pid）。
//
// 目的：停止插件时可以向**整个进程组**发信号，从而覆盖插件自己拉起的
// 子进程，避免它们变成孤儿继续占着 socket。
// Setpgid 字段只在 Unix 平台的 SysProcAttr 上存在，因此必须按平台拆分。
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateProcess 向进程组发送 SIGTERM（优雅退出）。
//
// 负 PID 表示"发给整个进程组"：这与 setProcessGroup 建立的进程组配套使用。
func terminateProcess(pid int) error {
	return syscall.Kill(-pid, syscall.SIGTERM)
}

// killProcess 向进程组发送 SIGKILL（强制回收）。
func killProcess(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// isProcessGone 判断错误是否表示"进程已不存在"。
//
// 竞态说明：进程可能在发信号前刚好自己退出，此时 kill 返回 ESRCH。
// 这不是错误，调用方据此跳过告警。
func isProcessGone(err error) bool {
	return errors.Is(err, syscall.ESRCH)
}
