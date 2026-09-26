//go:build darwin

package sysinfo

import (
	"fmt"
	"syscall"
)

// fileSystemStats 通过 statfs(2) 读取文件系统容量。
//
// Darwin 的 Statfs_t：Bsize 是 uint32，Blocks/Bfree/Bavail 都是 uint64。
// 字段名与 Linux 相同，但类型不同——这正是必须按平台分文件的原因。
func fileSystemStats(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	blockSize := uint64(st.Bsize)
	return fsStats{
		total:       st.Blocks * blockSize,
		free:        st.Bavail * blockSize,
		freeForRoot: st.Bfree * blockSize,
	}, nil
}
