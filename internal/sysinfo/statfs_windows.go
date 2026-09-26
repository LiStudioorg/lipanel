//go:build windows

package sysinfo

// fileSystemStats 在 Windows 上没有可移植的 statfs 封装，因此降级。
//
// Windows 有 GetDiskFreeSpaceEx，但需要额外的 syscall 绑定；
// 本阶段的目标是"不因平台差异而编译失败"。返回 ErrNotSupported 后，
// 磁盘卡片会显示"该项不可用"，而不是让整个 /api/system/info 报错。
//
// 需要 Windows 的真实磁盘数据时，在本文件补 GetDiskFreeSpaceEx 实现即可——
// 上层（readDiskInfo / collectDisk）完全不需要改动。
//
// 注：构建标签已从「windows || plan9 || solaris || ... || netbsd」收窄为
// windows：发布矩阵收缩后其它平台不再维护。
func fileSystemStats(path string) (fsStats, error) {
	return fsStats{}, ErrNotSupported
}
