//go:build openbsd

package sysinfo

import (
	"fmt"
	"syscall"
)

// fileSystemStats 通过 statfs(2) 读取文件系统容量。
//
// OpenBSD 的 Statfs_t 用的是 **F_ 前缀**字段名（F_bsize/F_blocks/
// F_bfree/F_bavail），与其它 BSD 完全不同，因此单独一个文件。
func fileSystemStats(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	blockSize := uint64(st.F_bsize)
	return fsStats{
		total:       st.F_blocks * blockSize,
		free:        clampToUint64(st.F_bavail) * blockSize,
		freeForRoot: st.F_bfree * blockSize,
	}, nil
}
