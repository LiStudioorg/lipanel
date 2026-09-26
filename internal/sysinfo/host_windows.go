//go:build windows

package sysinfo

import (
	"os"
	"runtime"
)

// hasProcFS 表示本平台提供 /proc 虚拟文件系统。
//
// 本文件是 **Windows 的实现**。Windows 没有 Linux 那种 /proc 接口，
// 因此所有 /proc 系列采集项统一降级：返回 ErrNotSupported，
// 由 Collector 记入 Warnings 并留空字段，而不是让接口 500。
//
// 设计取舍：与其在 Windows 上硬凑一套原生实现
// （GetSystemTimes + GlobalMemoryStatusEx + GetDiskFreeSpaceEx），
// 不如先保证**能编译、能启动、能明确报告"这项不可用"**。
// 面板的核心场景是 Linux 服务器，Windows 产物主要用于本地调试。
//
// 注：本文件原先还覆盖 plan9/solaris/illumos/aix/js/wasip1。
// 发布矩阵收缩到 Linux + Windows 后，那些平台不再维护，
// 因此构建标签已收窄为 windows —— 这让被移除的平台**编译期直接失败**
// 并给出清晰提示，而不是"悄悄缺符号"。
const hasProcFS = false

// osHostname 返回主机名。
// Windows 上 os.Hostname 走 GetComputerName，始终可用。
func osHostname() (string, error) {
	return os.Hostname()
}

// readKernelVersion 在 Windows 上无法通过 uname 获取内核版本，
// 因此降级为返回 Go 运行时的平台标识：至少保证「面板能正常显示
// 操作系统与架构」这一最基本的信息，而不是整项为空。
//
// 返回的 error 为 nil：这不是"失败"，而是"本平台的可用信息就这么多"，
// 避免给用户一条其实无需处理的告警。
func readKernelVersion() (version, arch string, err error) {
	// Windows 没有 uname 意义上的"内核版本号"，用 GOOS 语义更贴切。
	return runtime.GOOS + " (uname 不可用)", runtime.GOARCH, nil
}
