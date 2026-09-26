//go:build linux || android

package sysinfo

import (
	"fmt"
	"syscall"
)

// fileSystemStats 通过 statfs(2) 读取文件系统容量。
//
// Linux 的 Statfs_t 字段是 int64（Bsize 是 int64，其余是 uint64），
// 与 BSD 系（多为 uint64/uint32）不同，因此必须按平台分别实现。
func fileSystemStats(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	// Bsize 是文件系统的块大小；Bavail 是「非 root 用户可用块数」，
	// 与 df 的 Avail 列一致，比 Bfree 更能反映真实可用空间。
	blockSize := uint64(st.Bsize)
	return fsStats{
		total:       st.Blocks * blockSize,
		free:        st.Bavail * blockSize,
		freeForRoot: st.Bfree * blockSize,
	}, nil
}
