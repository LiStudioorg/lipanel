package sysinfo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNotSupported 表示当前平台不支持该采集项。
//
// 用于统一表达「这台机器上拿不到这个数据」，调用方（Collector）会把它
// 记入 Warnings 并留空该字段，而不是让整个 /api/system/info 返回 500。
var ErrNotSupported = errors.New("当前平台不支持该采集项")

// diskInfo 描述一个挂载点的容量使用情况（单位：字节）。
//
// 这是平台无关的内部数据结构：各平台的 statfs 系统调用返回的结构体
// 字段名与含义都不相同，因此由 fileSystemStats（见 host_statfs_*.go）
// 负责把它们统一归一化成本结构。
type diskInfo struct {
	Path    string
	Total   uint64
	Used    uint64
	Free    uint64
	Percent float64
}

// readDiskInfo 读取 path 所在文件系统的容量。
//
// 平台相关部分全部收敛在 fileSystemStats 里；本函数只做与 df 口径一致的
// 换算，因此可以在所有平台上编译与测试。
func readDiskInfo(path string) (diskInfo, error) {
	fs, err := fileSystemStats(path)
	if err != nil {
		return diskInfo{}, err
	}

	total := fs.total
	free := fs.free
	if total == 0 {
		return diskInfo{}, fmt.Errorf("statfs %s 返回总容量为 0", path)
	}

	// used 用 total - fs.freeForRoot（即 Bfree）而不是 total - free：
	// 两者口径与 df 一致——df 的 Used 含 root 保留块，Avail 不含。
	used := total - fs.freeForRoot
	// 计算使用率时以「已用 / (已用 + 可用)」为分母，与 df 的 Use% 口径一致
	// （预留的 root 保留块不计入分母）。
	percent := 0.0
	if used+free > 0 {
		percent = float64(used) / float64(used+free) * 100
	}

	return diskInfo{
		Path:    path,
		Total:   total,
		Used:    used,
		Free:    free,
		Percent: percent,
	}, nil
}

// clampToUint64 把可能为负的 int64 块数安全地转为 uint64。
//
// 某些平台的 statfs 结构体把块计数字段定义为 int64（FreeBSD 的 Bavail、
// DragonFly 的全部字段）。负值意味着文件系统上报了异常数据，
// 直接转 uint64 会得到天文数字，因此按 0 处理。
func clampToUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// fsStats 是各平台 statfs 结果的归一化形式（单位：字节）。
type fsStats struct {
	// total 是文件系统总容量。
	total uint64
	// free 是「非特权用户可用」容量（Linux 的 Bavail / BSD 的 Bavail），
	// 对应 df 的 Avail 列。
	free uint64
	// freeForRoot 是含保留块的空闲容量（Linux 的 Bfree），对应 df 的 Used 口径。
	freeForRoot uint64
}

// readUptime 读取 /proc/uptime，返回开机秒数。
//
// 第一个字段是系统运行总秒数（含小数），第二个是累计空闲时间，此处只用前者。
func readUptime() (uint64, error) {
	if !hasProcFS {
		return 0, ErrNotSupported
	}
	data, err := readFileTrimmed("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("读取 /proc/uptime 失败: %w", err)
	}
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, fmt.Errorf("/proc/uptime 内容为空")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("解析 /proc/uptime 字段 %q 失败: %w", fields[0], err)
	}
	if seconds < 0 {
		return 0, nil
	}
	return uint64(seconds), nil
}

// readLoadAvg 读取 /proc/loadavg 的前三个值（1/5/15 分钟平均负载）。
func readLoadAvg() ([3]float64, error) {
	var out [3]float64
	if !hasProcFS {
		return out, ErrNotSupported
	}
	data, err := readFileTrimmed("/proc/loadavg")
	if err != nil {
		return out, fmt.Errorf("读取 /proc/loadavg 失败: %w", err)
	}
	fields := strings.Fields(data)
	if len(fields) < 3 {
		return out, fmt.Errorf("/proc/loadavg 字段不足: %q", data)
	}
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return out, fmt.Errorf("解析 /proc/loadavg 字段 %q 失败: %w", fields[i], err)
		}
		out[i] = v
	}
	return out, nil
}

// readOSRelease 从 /etc/os-release 读取发行版名称。
// 优先 PRETTY_NAME（如 "Ubuntu 22.04.5 LTS"），退化为 NAME + VERSION。
// 部分精简镜像没有该文件，此时调用方应降级使用内核信息。
func readOSRelease() (string, error) {
	data, err := readFileTrimmed("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("读取 /etc/os-release 失败: %w", err)
	}

	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		// 跳过空行与注释。
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = unquoteShell(strings.TrimSpace(value))
	}

	if v := values["PRETTY_NAME"]; v != "" {
		return v, nil
	}
	name := values["NAME"]
	if name == "" {
		return "", fmt.Errorf("/etc/os-release 中未找到 PRETTY_NAME 或 NAME")
	}
	if v := values["VERSION"]; v != "" {
		return name + " " + v, nil
	}
	return name, nil
}

// readHostname 读取主机名。
//
// 优先 os.Hostname()（所有平台都可用），失败时退回 /proc 下的传统路径
// 作为兜底——某些精简容器里 os.Hostname 会因缺少 utsname 支持而失败。
func readHostname() (string, error) {
	if name, err := osHostname(); err == nil && name != "" {
		return name, nil
	}
	name, err := readFileTrimmed("/proc/sys/kernel/hostname")
	if err != nil {
		return "", fmt.Errorf("读取主机名失败: %w", err)
	}
	return name, nil
}

// unquoteShell 去掉 shell 风格字符串两端的引号。
// /etc/os-release 允许 PRETTY_NAME="Ubuntu 22.04.5 LTS" 这种写法。
func unquoteShell(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// readFileTrimmed 读取文件内容并去掉首尾空白，统一处理错误上下文。
func readFileTrimmed(path string) (string, error) {
	data, err := readFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
