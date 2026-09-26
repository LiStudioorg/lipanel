//go:build windows || plan9 || solaris || illumos || aix || js || wasip1 || netbsd

package sysinfo

// fileSystemStats 在这些平台上没有可移植的 statfs 封装，因此降级。
//
// NetBSD 也归入此类：它的 syscall.Statfs_t 被定义为 [0]byte 占位类型
// （Go 未为 NetBSD 提供 statfs 绑定），根本无法从中取到容量数据。
//
// 说明：Windows 有 GetDiskFreeSpaceEx，Solaris 有 statvfs，
// 但两者都需要额外的 syscall 绑定，且本阶段的目标是"不因平台差异而
// 编译失败"。返回 ErrNotSupported 后，磁盘卡片会显示"该项不可用"，
// 而不是让整个 /api/system/info 报错。
//
// 需要这些平台的真实磁盘数据时，在本文件基础上补对应实现即可——
// 上层（readDiskInfo / collectDisk）完全不需要改动。
func fileSystemStats(path string) (fsStats, error) {
	return fsStats{}, ErrNotSupported
}
