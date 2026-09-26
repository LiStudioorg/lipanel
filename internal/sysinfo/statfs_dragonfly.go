//go:build dragonfly

package sysinfo

import (
	"fmt"
	"syscall"
)

// fileSystemStats 通过 statfs(2) 读取文件系统容量。
//
// DragonFly BSD 的 Statfs_t 三个块计数字段都是 int64，需逐个转换。
func fileSystemStats(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	blockSize := clampToUint64(st.Bsize)
	return fsStats{
		total:       clampToUint64(st.Blocks) * blockSize,
		free:        clampToUint64(st.Bavail) * blockSize,
		freeForRoot: clampToUint64(st.Bfree) * blockSize,
	}, nil
}
