// Package sysinfo 采集 Linux 主机的基础信息：CPU、内存、磁盘与系统版本。
//
// 设计约束：
//   - 只使用标准库 + 读取 /proc、/etc/os-release，不调用外部命令（uname/lsblk）。
//     面板以 root 运行，避免执行外部二进制可显著缩小攻击面，且不依赖发行版差异。
//   - 每个子模块独立采集，任一失败只降级该字段并附带 warning，不整体报错，
//     保证「磁盘读不到」不会导致整个系统信息页空白。
package sysinfo

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// cpuStat 是 /proc/stat 中一行 CPU 的累计时间片（单位：USER_HZ）。
type cpuStat struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

// total 返回该 CPU 的非空闲时间片总和（含 steal：被虚拟化层偷走的时间，
// 从进程视角同样是「忙」，必须计入总量，否则虚拟机里使用率会偏低）。
func (c cpuStat) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// busy 返回非空闲时间片。
func (c cpuStat) busy() uint64 {
	return c.user + c.nice + c.system + c.irq + c.softirq + c.steal
}

// readCPUStat 读取 /proc/stat 的汇总行（第一行 "cpu ..."）。
func readCPUStat() (cpuStat, error) {
	if !hasProcFS {
		return cpuStat{}, ErrNotSupported
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuStat{}, fmt.Errorf("读取 /proc/stat 失败: %w", err)
	}
	return parseCPUStat(string(data))
}

// parseCPUStat 解析 /proc/stat 内容中的汇总 CPU 行。
// 抽成独立函数以便单测直接喂样本数据，不依赖真实主机负载。
func parseCPUStat(content string) (cpuStat, error) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields[0] 是 "cpu"，后面依次是各时间片；老内核字段更少，缺的补 0。
		if len(fields) < 5 {
			return cpuStat{}, fmt.Errorf("/proc/stat 汇总行字段过少: %q", line)
		}
		var vals [8]uint64
		for i := 0; i < len(vals) && i+1 < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return cpuStat{}, fmt.Errorf("解析 /proc/stat 字段 %q 失败: %w", fields[i+1], err)
			}
			vals[i] = v
		}
		return cpuStat{
			user: vals[0], nice: vals[1], system: vals[2], idle: vals[3],
			iowait: vals[4], irq: vals[5], softirq: vals[6], steal: vals[7],
		}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat 中未找到汇总 CPU 行")
}

// usageBetween 计算两个时间片快照之间的 CPU 使用率（百分比，0~100）。
// 第二个返回值表示是否可计算：两次采样之间没有时间推进时无意义。
func usageBetween(prev, cur cpuStat) (float64, bool) {
	totalDelta := cur.total() - prev.total()
	if cur.total() <= prev.total() || totalDelta == 0 {
		return 0, false
	}
	busyDelta := cur.busy() - prev.busy()
	// 计数器回绕或采样错位时钳制，避免出现负数或 >100 的荒谬数值。
	if busyDelta > totalDelta {
		busyDelta = totalDelta
	}
	return float64(busyDelta) / float64(totalDelta) * 100, true
}

// cpuCores 统计逻辑核心数（/proc/stat 中 cpuN 行数），失败时退回 runtime.NumCPU。
func cpuCores() (int, error) {
	if !hasProcFS {
		// 没有 /proc 时仍然可以给出逻辑核心数：runtime.NumCPU 在所有平台可用。
		// 这不是降级为"不可用"，而是换一个同样准确的数据来源。
		return runtime.NumCPU(), nil
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("读取 /proc/stat 失败: %w", err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		// 只统计 "cpu0"、"cpu1" 这类核心行，跳过汇总行 "cpu "。
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("/proc/stat 中未找到核心行")
	}
	return n, nil
}

// cpuModel 从 /proc/cpuinfo 提取 CPU 型号。
// ARM 平台字段名是 "Hardware" 或 "Model"，因此按优先级依次尝试。
func cpuModel() (string, error) {
	if !hasProcFS {
		return "", ErrNotSupported
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", fmt.Errorf("读取 /proc/cpuinfo 失败: %w", err)
	}
	content := string(data)
	for _, key := range []string{"model name", "Hardware", "Model", "cpu model"} {
		if v := findCPUInfoValue(content, key); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("/proc/cpuinfo 中未找到 CPU 型号字段")
}

// findCPUInfoValue 在 /proc/cpuinfo 文本中查找 "key : value" 形式的第一个值。
func findCPUInfoValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
