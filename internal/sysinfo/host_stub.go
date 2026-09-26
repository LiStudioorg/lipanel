//go:build windows || plan9 || solaris || illumos || aix || js || wasip1

package sysinfo

import (
	"os"
	"runtime"
)

// hasProcFS 表示本平台提供 /proc 虚拟文件系统。
//
// 本文件覆盖的是**没有 /proc、也没有可移植 uname 封装**的平台
// （Windows、Plan9、Solaris/illumos、AIX、js/wasm）。它们不提供
// Linux 那种 /proc 接口，因此所有 /proc 系列采集项统一降级：
// 返回 ErrNotSupported，由 Collector 记入 Warnings 并留空字段。
//
// 设计取舍：与其在每个平台上硬凑一套原生实现（Windows 要走
// GetSystemTimes + GlobalMemoryStatusEx，Solaris 要读 kstat……），
// 不如先保证**能编译、能启动、能明确报告"这项不可用"**。
// 面板的核心场景是 Linux 服务器，其它平台拿到的是 Windows/macOS 上的
// 开发调试体验，而不是生产部署目标。
const hasProcFS = false

// osHostname 返回主机名。
//
// os.Hostname 在所有目标平台上都有实现（Windows 走 GetComputerName，
// Plan9 读 /dev/sysname），因此这里不需要平台分支。
func osHostname() (string, error) {
	return os.Hostname()
}

// readKernelVersion 在这些平台上无法通过 uname 系统调用获取内核版本，
// 因此降级为返回 Go 运行时的平台标识：至少保证「面板能正常显示
// 操作系统与架构」这一最基本的信息，而不是整项为空。
//
// 返回的 error 为 nil：这不是"失败"，而是"本平台的可用信息就这么多"，
// 避免给用户一条其实无需处理的告警。
func readKernelVersion() (version, arch string, err error) {
	// runtime.GOOS 例如 "windows"、"plan9"、"solaris"、"js"。
	// 对 Windows 而言这比 uname 语义更贴切（Windows 没有内核版本号的概念）。
	return runtime.GOOS + " (uname 不可用)", runtime.GOARCH, nil
}
