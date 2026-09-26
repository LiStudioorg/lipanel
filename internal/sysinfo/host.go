package sysinfo

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// diskInfo 描述一个挂载点的容量使用情况（单位：字节）。
type diskInfo struct {
	Path    string
	Total   uint64
	Used    uint64
	Free    uint64
	Percent float64
}

// readDiskInfo 通过 statfs(2) 读取 path 所在文件系统的容量。
//
// 使用 syscall.Statfs 而非 df 命令：不依赖 coreutils、无进程创建开销，
// 也不存在解析本地化输出（不同 LANG 下 df 表头不同）的兼容问题。
func readDiskInfo(path string) (diskInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return diskInfo{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}

	// Bsize 是文件系统的块大小；Bavail 是「非 root 用户可用块数」，
	// 与 df 的 Avail 列一致，比 Bfree 更能反映真实可用空间。
	blockSize := uint64(st.Bsize)
	total := st.Blocks * blockSize
	free := st.Bavail * blockSize
	if total == 0 {
		return diskInfo{}, fmt.Errorf("statfs %s 返回总容量为 0", path)
	}

	used := total - st.Bfree*blockSize
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

// readUptime 读取 /proc/uptime，返回开机秒数。
// 第一个字段是系统运行总秒数（含小数），第二个是累计空闲时间，此处只用前者。
func readUptime() (uint64, error) {
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

// readKernelVersion 通过 uname(2) 系统调用获取内核版本，不执行外部 uname 命令。
func readKernelVersion() (version, arch string, err error) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "", "", fmt.Errorf("uname 系统调用失败: %w", err)
	}
	return utsnameString(uts.Release[:]), utsnameString(uts.Machine[:]), nil
}

// utsnameString 把 Utsname 的定长 int8 数组转为 Go 字符串（以 NUL 结尾）。
func utsnameString(chars []int8) string {
	buf := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
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

// readHostname 读取主机名。
func readHostname() (string, error) {
	name, err := readFileTrimmed("/proc/sys/kernel/hostname")
	if err != nil {
		return "", fmt.Errorf("读取主机名失败: %w", err)
	}
	return name, nil
}

// readFileTrimmed 读取文件内容并去掉首尾空白，统一处理错误上下文。
func readFileTrimmed(path string) (string, error) {
	data, err := readFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
