//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package sysinfo

import (
	"os"
	"runtime"
)

// hasProcFS 表示本平台提供 /proc 虚拟文件系统。
//
// BSD 系与 Darwin **没有** /proc（FreeBSD 的 procfs 早已废弃且默认不挂载），
// 因此 /proc 系列采集项统一降级为 ErrNotSupported。
const hasProcFS = false

// osHostname 返回主机名。
func osHostname() (string, error) {
	return os.Hostname()
}

// readKernelVersion 在这些平台上无法通过 uname 获取内核版本。
//
// 为什么不能照搬 Linux 的写法：syscall.Uname / syscall.Utsname 在
// Go 1.27 的 darwin、freebsd、netbsd、openbsd、dragonfly 上**都不存在**
// （可自行核对 $GOROOT/src/syscall/zsyscall_<os>_<arch>.go，无 Uname 符号；
// Darwin 上的 syscall.Uname 也已被移除）。因此这里降级为返回运行时平台的
// 标识，保证面板至少能正确显示操作系统与架构。
//
// 需要真实内核版本时，可改用 golang.org/x/sys/unix.Uname——
// 但那会引入新的依赖，与「后端优先标准库、零新增依赖」的工程约束冲突，
// 故本阶段不采用。
func readKernelVersion() (version, arch string, err error) {
	return runtime.GOOS + " (uname 不可用)", runtime.GOARCH, nil
}
