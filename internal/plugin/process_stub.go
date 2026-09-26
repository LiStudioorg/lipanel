//go:build plan9 || js || wasip1

package plugin

import (
	"errors"
	"os"
	"os/exec"
)

// 本文件覆盖 Plan9 与 js/wasm（wasm 在浏览器/Node 里没有进程概念）。
//
// 这些平台上插件系统整体不可用：
//   - 没有 Unix domain socket，插件与本进程无法按设计通讯；
//   - 没有 POSIX 信号；
//   - js/wasm 上甚至无法 exec 子进程。
//
// 策略："能编译、能启动、插件相关接口明确报错"，而不是编译失败。
// 上层（Manager）在启动插件时会因 socket 不可用而失败，
// 用户看到的是"该平台不支持插件"，而不是一个跑不起来的面板。

// setProcessGroup 无进程组概念，不做任何事。
func setProcessGroup(cmd *exec.Cmd) {
	// 有意留空。
}

// terminateProcess 无信号机制，返回 ErrUnsupported。
func terminateProcess(pid int) error {
	return ErrUnsupported
}

// killProcess 尽力结束进程；js/wasm 上 FindProcess/Kill 均不可用，
// 返回 ErrUnsupported 由调用方记录。
func killProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Kill(); err != nil {
		return err
	}
	return nil
}

// isProcessGone 判断错误是否表示"进程已不存在"。
func isProcessGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone) || errors.Is(err, ErrUnsupported)
}
