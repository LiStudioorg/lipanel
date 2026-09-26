package sysinfo

import (
	"os"
	"sync"
	"time"
)

// readFile 是 os.ReadFile 的薄封装，集中一处便于测试替换与错误上下文统一。
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Info 是 GET /api/system/info 的完整响应体。
// 字段使用 snake_case，与前端直接消费的 JSON 保持一致。
type Info struct {
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Kernel        string     `json:"kernel"`
	Arch          string     `json:"arch"`
	UptimeSeconds uint64     `json:"uptime_seconds"`
	CollectedAt   string     `json:"collected_at"`
	CPU           CPUInfo    `json:"cpu"`
	Memory        MemoryInfo `json:"memory"`
	Swap          SwapInfo   `json:"swap"`
	Disk          DiskInfo   `json:"disk"`
	// Warnings 收集降级采集的项目，前端可据此提示「某项信息不可用」，
	// 而不是让整个接口 500。
	Warnings []string `json:"warnings,omitempty"`
}

// CPUInfo 描述 CPU 概况。
type CPUInfo struct {
	Model        string     `json:"model"`
	Cores        int        `json:"cores"`
	UsagePercent float64    `json:"usage_percent"`
	LoadAvg      [3]float64 `json:"load_avg"`
}

// MemoryInfo 描述内存使用情况（单位：字节）。
type MemoryInfo struct {
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	CachedBytes  uint64  `json:"cached_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

// SwapInfo 描述交换分区（单位：字节）。
type SwapInfo struct {
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

// DiskInfo 描述根分区使用情况（单位：字节）。
type DiskInfo struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

// Collector 采集系统信息。
//
// CPU 使用率必须靠两次时间片快照的差值计算，因此 Collector 持有上一次快照；
// 该状态需要并发保护（多个请求可能同时到达）。
type Collector struct {
	// DiskPath 是要统计的挂载点，默认 "/"。
	DiskPath string
	// SampleInterval 是两次采样间隔不足时的等待时间。
	SampleInterval time.Duration

	mu       sync.Mutex
	last     cpuStat
	lastTime time.Time
}

// NewCollector 构造采集器，并在启动时先取一次 CPU 基线快照，
// 这样第一次请求就能直接算出使用率，避免首屏出现 0%。
func NewCollector() *Collector {
	c := &Collector{
		DiskPath:       "/",
		SampleInterval: 200 * time.Millisecond,
	}
	if st, err := readCPUStat(); err == nil {
		c.last = st
		c.lastTime = time.Now()
	}
	return c
}

// cpuUsage 计算自上次采样以来的 CPU 使用率。
//
// 若距上次采样过近（差值窗口太小，读数会剧烈抖动），则主动等待
// SampleInterval 再取第二次快照。等待期间释放锁，避免阻塞其它请求。
func (c *Collector) cpuUsage() (float64, error) {
	c.mu.Lock()
	prev, prevTime := c.last, c.lastTime
	c.mu.Unlock()

	// 基线缺失（启动时 /proc/stat 读取失败）时现场补一次。
	if prev.total() == 0 {
		cur, err := readCPUStat()
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		c.last, c.lastTime = cur, time.Now()
		c.mu.Unlock()
		return 0, nil
	}

	if elapsed := time.Since(prevTime); elapsed < c.SampleInterval {
		time.Sleep(c.SampleInterval - elapsed)
	}

	cur, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.last, c.lastTime = cur, time.Now()
	c.mu.Unlock()

	usage, ok := usageBetween(prev, cur)
	if !ok {
		// 两次快照完全相同（极短窗口内无 tick）时不报错，返回 0 更友好。
		return 0, nil
	}
	return usage, nil
}

// Collect 采集一次完整的系统信息。
// 任何子项失败都不会返回 error，而是记入 Warnings 并留空该字段。
func (c *Collector) Collect() Info {
	now := time.Now()
	info := Info{
		CollectedAt: now.Format(time.RFC3339),
		Warnings:    []string{},
	}

	if hostname, err := readHostname(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		info.Hostname = hostname
	}

	if osName, err := readOSRelease(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		info.OS = osName
	}

	if kernel, arch, err := readKernelVersion(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		info.Kernel, info.Arch = kernel, arch
	}

	if uptime, err := readUptime(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		info.UptimeSeconds = uptime
	}

	info.CPU = c.collectCPU(&info)
	info.Memory = collectMemory(&info)
	info.Swap = collectSwap(&info)
	info.Disk = c.collectDisk(&info)

	return info
}

func (c *Collector) collectCPU(info *Info) CPUInfo {
	var out CPUInfo

	if model, err := cpuModel(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		out.Model = model
	}

	if cores, err := cpuCores(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		out.Cores = cores
	}

	if usage, err := c.cpuUsage(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		out.UsagePercent = round2(usage)
	}

	if load, err := readLoadAvg(); err != nil {
		info.Warnings = append(info.Warnings, err.Error())
	} else {
		out.LoadAvg = [3]float64{round2(load[0]), round2(load[1]), round2(load[2])}
	}

	return out
}

func collectMemory(info *Info) MemoryInfo {
	mem, err := readMemoryInfo()
	if err != nil {
		info.Warnings = append(info.Warnings, err.Error())
		return MemoryInfo{}
	}

	out := MemoryInfo{
		TotalBytes:  mem.Total,
		UsedBytes:   mem.used(),
		FreeBytes:   mem.Available,
		CachedBytes: mem.Cached + mem.Buffers,
	}
	if mem.Total > 0 {
		out.UsagePercent = round2(float64(out.UsedBytes) / float64(mem.Total) * 100)
	}
	return out
}

func collectSwap(info *Info) SwapInfo {
	swap, err := readSwapInfo()
	if err != nil {
		info.Warnings = append(info.Warnings, err.Error())
		return SwapInfo{}
	}

	out := SwapInfo{TotalBytes: swap.Total}
	if swap.Total > 0 {
		out.UsedBytes = swap.Total - swap.Free
		out.UsagePercent = round2(float64(out.UsedBytes) / float64(swap.Total) * 100)
	}
	return out
}

func (c *Collector) collectDisk(info *Info) DiskInfo {
	path := c.DiskPath
	if path == "" {
		path = "/"
	}

	disk, err := readDiskInfo(path)
	if err != nil {
		info.Warnings = append(info.Warnings, err.Error())
		return DiskInfo{Path: path}
	}

	return DiskInfo{
		Path:         disk.Path,
		TotalBytes:   disk.Total,
		UsedBytes:    disk.Used,
		FreeBytes:    disk.Free,
		UsagePercent: round2(disk.Percent),
	}
}

// round2 保留两位小数，避免 JSON 里出现 12.340000000000002 这类浮点噪声。
func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
