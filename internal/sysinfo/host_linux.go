//go:build linux || android

package sysinfo

import (
	"os"
	"syscall"
)

// hasProcFS 表示本平台提供 /proc 虚拟文件系统。
//
// Linux 与 Android 都有（Android 的内核就是 Linux），因此 /proc 系列采集器
// （CPU、内存、负载、开机时长、主机名兜底）在这些平台上都可用。
const hasProcFS = true

// osHostname 返回主机名。
// Linux/Android 上 os.Hostname 走 uname(2)，稳定可靠。
func osHostname() (string, error) {
	return os.Hostname()
}

// readKernelVersion 通过 uname(2) 系统调用获取内核版本与机器架构，
// 不执行外部 uname 命令。
//
// 注意 syscall.Utsname 的字段类型在不同平台并不一致：
// 在 Linux/Android 上是 [65]int8（byte），因此可以直接构造字符串。
func readKernelVersion() (version, arch string, err error) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "", "", err
	}
	return utsArrayToString(uts.Release), utsArrayToString(uts.Machine), nil
}

// utsArrayToString 把 Utsname 的定长字符数组转为字符串（以 NUL 结尾）。
//
// 参数用泛型而不是具体的 []int8：**同一个 syscall.Utsname 在不同
// GOARCH 上字段类型不同**——amd64/arm64/386/mips 上是 [65]int8，
// 而 arm/ppc64/ppc64le/riscv64/s390x 上是 [65]uint8。
// 写成固定类型必然有一半架构编译失败（这正是把 386 之外的目标漏掉的原因）。
func utsArrayToString[T int8 | uint8](chars [65]T) string {
	buf := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
