//go:build freebsd

package sysinfo

import (
	"fmt"
	"syscall"
)

// fileSystemStats 通过 statfs(2) 读取文件系统容量。
//
// FreeBSD 的 Statfs_t：Bsize/Blocks/Bfree 是 uint64，但 **Bavail 是 int64**
// （Ffree 同样是 int64）。直接与 uint64 相乘会编译失败，因此这里显式转换；
// 负值（异常文件系统上报）按 0 处理，避免换算成天文数字的"可用空间"。
func fileSystemStats(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	blockSize := uint64(st.Bsize)
	return fsStats{
		total:       st.Blocks * blockSize,
		free:        clampToUint64(st.Bavail) * blockSize,
		freeForRoot: st.Bfree * blockSize,
	}, nil
}
