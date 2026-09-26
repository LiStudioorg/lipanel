package sysinfo

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// memoryInfo 是 /proc/meminfo 的常用字段（单位：字节）。
type memoryInfo struct {
	Total     uint64
	Free      uint64
	Available uint64
	Cached    uint64
	Buffers   uint64
}

// used 计算「已用内存」。
//
// 口径说明：Linux 的 MemFree 会被 page cache 吃满，直接用它算使用率会让面板
// 长期显示 90%+，属于误导。这里采用与 free(1)、htop 一致的现代口径：
//
//	used = total - available
//
// MemAvailable 是内核估算的「不触发 swap 的情况下可分配给新应用的内存量」，
// 已经扣除了不可回收的缓存，最能反映真实压力。
func (m memoryInfo) used() uint64 {
	if m.Available >= m.Total {
		return 0
	}
	return m.Total - m.Available
}

// readMemoryInfo 读取并解析 /proc/meminfo。
func readMemoryInfo() (memoryInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memoryInfo{}, fmt.Errorf("读取 /proc/meminfo 失败: %w", err)
	}
	return parseMeminfo(string(data))
}

// parseMeminfo 解析 /proc/meminfo 内容。
// /proc/meminfo 的值统一以 kB 为单位（除了个别无单位字段），这里统一转成字节。
func parseMeminfo(content string) (memoryInfo, error) {
	var m memoryInfo
	var found bool

	for _, line := range strings.Split(content, "\n") {
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return memoryInfo{}, fmt.Errorf("解析 /proc/meminfo 字段 %q 失败: %w", key, err)
		}
		// 除 HugePages 等计数类字段外，内存量字段均带 kB 单位；无单位字段直接按字节处理。
		bytes := v
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			bytes = v * 1024
		}

		switch key {
		case "MemTotal":
			m.Total = bytes
			found = true
		case "MemFree":
			m.Free = bytes
		case "MemAvailable":
			m.Available = bytes
		case "Cached":
			m.Cached = bytes
		case "Buffers":
			m.Buffers = bytes
		}
	}

	if !found || m.Total == 0 {
		return memoryInfo{}, fmt.Errorf("/proc/meminfo 中未找到 MemTotal")
	}
	// 老内核（< 3.14）没有 MemAvailable，退化为 Free + Cached + Buffers，
	// 结果偏保守但不会把缓存算成已用内存。
	if m.Available == 0 {
		m.Available = m.Free + m.Cached + m.Buffers
	}
	return m, nil
}

// swapInfo 是交换分区信息（单位：字节）。
type swapInfo struct {
	Total uint64
	Free  uint64
}

// readSwapInfo 从 /proc/meminfo 读取交换分区使用情况。
// SwapTotal 为 0 表示未启用交换分区，属正常情况而非错误。
func readSwapInfo() (swapInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return swapInfo{}, fmt.Errorf("读取 /proc/meminfo 失败: %w", err)
	}
	var s swapInfo
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			// 单个字段异常不应让整个磁盘信息失败，跳过即可。
			continue
		}
		switch key {
		case "SwapTotal":
			s.Total = v * 1024
		case "SwapFree":
			s.Free = v * 1024
		}
	}
	return s, nil
}
