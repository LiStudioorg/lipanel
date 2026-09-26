package sysinfo

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// 真实的 /proc/stat 片段（含汇总行与核心行），用于验证解析与核心计数。
const sampleProcStat = `cpu  1601820 67194 428000 38825966 26904 0 17273 38792 0 0
cpu0 403834 16998 107399 9711911 6655 0 3798 8630 0 0
cpu1 402961 21384 106625 9706105 6161 0 3945 9945 0 0
cpu2 400123 15200 108000 9701000 7000 0 4800 10000 0 0
cpu3 394902 13612 105976 9706950 7088 0 4730 10217 0 0
intr 12345678 0 0 0
ctxt 87654321
btime 1700000000
processes 12345
procs_running 1
procs_blocked 0
`

const sampleMeminfo = `MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8192000 kB
Buffers:          200000 kB
Cached:          4000000 kB
SwapCached:            0 kB
SwapTotal:       2097152 kB
SwapFree:        1048576 kB
`

func TestParseCPUStat(t *testing.T) {
	st, err := parseCPUStat(sampleProcStat)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if st.user != 1601820 || st.nice != 67194 || st.system != 428000 || st.idle != 38825966 {
		t.Errorf("解析结果与样本不符: %+v", st)
	}
	if st.iowait != 26904 || st.irq != 0 || st.softirq != 17273 || st.steal != 38792 {
		t.Errorf("解析结果与样本不符（后半段字段）: %+v", st)
	}
}

func TestParseCPUStatRejectsGarbage(t *testing.T) {
	if _, err := parseCPUStat("intr 123\nctxt 456\n"); err == nil {
		t.Fatal("缺少汇总行时应当报错")
	}
	if _, err := parseCPUStat("cpu 1 2\n"); err == nil {
		t.Fatal("字段过少时应当报错")
	}
	if _, err := parseCPUStat("cpu a b c d e\n"); err == nil {
		t.Fatal("非数字字段应当报错")
	}
}

// 使用率计算是面板最核心的数值，必须精确。
func TestUsageBetween(t *testing.T) {
	prev := cpuStat{user: 100, nice: 0, system: 50, idle: 850, iowait: 0}
	// 增加 100 个 tick，其中 20 个忙、80 个空闲 → 20%。
	cur := cpuStat{user: 120, nice: 0, system: 50, idle: 930, iowait: 0}

	got, ok := usageBetween(prev, cur)
	if !ok {
		t.Fatal("应当可以计算使用率")
	}
	if math.Abs(got-20) > 0.001 {
		t.Errorf("使用率 = %v, 期望 20", got)
	}
}

// 完全空闲时使用率应为 0。
func TestUsageBetweenIdle(t *testing.T) {
	prev := cpuStat{idle: 1000}
	cur := cpuStat{idle: 1100}

	got, ok := usageBetween(prev, cur)
	if !ok {
		t.Fatal("应当可以计算使用率")
	}
	if got != 0 {
		t.Errorf("空闲时使用率 = %v, 期望 0", got)
	}
}

// steal 时间必须计入「忙」，否则虚拟机内使用率会明显偏低。
func TestUsageBetweenCountsStealAsBusy(t *testing.T) {
	prev := cpuStat{idle: 1000}
	// 100 个 tick 中 50 个被 hypervisor 偷走、50 个空闲。
	cur := cpuStat{idle: 1050, steal: 50}

	got, ok := usageBetween(prev, cur)
	if !ok {
		t.Fatal("应当可以计算使用率")
	}
	if math.Abs(got-50) > 0.001 {
		t.Errorf("使用率 = %v, 期望 50（steal 应计入忙）", got)
	}
}

// 计数器未推进时必须报告「不可计算」，而不是给出 0% 或 NaN。
func TestUsageBetweenNoProgress(t *testing.T) {
	st := cpuStat{user: 100, idle: 900}
	if _, ok := usageBetween(st, st); ok {
		t.Error("两次快照相同时应返回 ok=false，避免误报 0%")
	}
}

// 计数器回绕时使用率必须被钳制在 100 以内，不能出现荒谬数值。
func TestUsageBetweenClamps(t *testing.T) {
	prev := cpuStat{user: 100, idle: 900}
	cur := cpuStat{user: 5000, idle: 950}

	got, ok := usageBetween(prev, cur)
	if !ok {
		t.Fatal("应当可以计算使用率")
	}
	if got > 100 {
		t.Errorf("使用率 = %v, 必须钳制在 100 以内", got)
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := parseMeminfo(sampleMeminfo)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 16384000 kB → 字节
	if want := uint64(16384000) * 1024; m.Total != want {
		t.Errorf("Total = %d, 期望 %d", m.Total, want)
	}
	if want := uint64(8192000) * 1024; m.Available != want {
		t.Errorf("Available = %d, 期望 %d", m.Available, want)
	}
	// used = total - available = (16384000-8192000) kB
	if want := uint64(8192000) * 1024; m.used() != want {
		t.Errorf("used() = %d, 期望 %d", m.used(), want)
	}
}

// 老内核没有 MemAvailable 时，应退化为 Free+Cached+Buffers，而不是把缓存算成已用。
func TestParseMeminfoFallsBackWithoutAvailable(t *testing.T) {
	m, err := parseMeminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nCached: 300 kB\nBuffers: 50 kB\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if want := uint64(450) * 1024; m.Available != want {
		t.Errorf("Available = %d, 期望 %d（Free+Cached+Buffers）", m.Available, want)
	}
}

func TestParseMeminfoRejectsMissingTotal(t *testing.T) {
	if _, err := parseMeminfo("MemFree: 100 kB\n"); err == nil {
		t.Fatal("缺少 MemTotal 时应当报错")
	}
}

// 已用内存绝不能超过总量（避免前端进度条超过 100%）。
func TestMemoryUsedNeverExceedsTotal(t *testing.T) {
	m := memoryInfo{Total: 1000, Available: 5000}
	if got := m.used(); got != 0 {
		t.Errorf("used() = %d, 期望 0（Available 大于 Total 时钳制）", got)
	}
}

func TestReadDiskInfo(t *testing.T) {
	d, err := readDiskInfo("/")
	if err != nil {
		t.Fatalf("statfs / 失败: %v", err)
	}
	if d.Total == 0 {
		t.Error("根分区总容量为 0")
	}
	if d.Used > d.Total {
		t.Errorf("已用 %d 超过总容量 %d", d.Used, d.Total)
	}
	if d.Percent < 0 || d.Percent > 100 {
		t.Errorf("使用率 = %v, 应在 0~100 之间", d.Percent)
	}
}

func TestReadDiskInfoRejectsBadPath(t *testing.T) {
	if _, err := readDiskInfo("/definitely/not/exist/path"); err == nil {
		t.Fatal("不存在的路径应当返回错误")
	}
}

func TestReadUptime(t *testing.T) {
	up, err := readUptime()
	if err != nil {
		t.Fatalf("读取 uptime 失败: %v", err)
	}
	if up == 0 {
		t.Error("开机时长不应为 0（除非刚启动）")
	}
}

func TestReadLoadAvg(t *testing.T) {
	load, err := readLoadAvg()
	if err != nil {
		t.Fatalf("读取 loadavg 失败: %v", err)
	}
	for i, v := range load {
		if v < 0 {
			t.Errorf("第 %d 个负载值为负数: %v", i, v)
		}
	}
}

func TestReadKernelVersion(t *testing.T) {
	kernel, arch, err := readKernelVersion()
	if err != nil {
		t.Fatalf("uname 失败: %v", err)
	}
	if kernel == "" || arch == "" {
		t.Errorf("内核版本 = %q, 架构 = %q, 均不应为空", kernel, arch)
	}
}

// /etc/os-release 存在时应能解析出 PRETTY_NAME；不存在时允许降级报错。
func TestReadOSRelease(t *testing.T) {
	name, err := readOSRelease()
	if err != nil {
		t.Skipf("本机没有可用的 /etc/os-release，跳过: %v", err)
	}
	if name == "" {
		t.Error("发行版名称为空")
	}
	if strings.HasPrefix(name, "\"") {
		t.Errorf("发行版名称未去掉引号: %q", name)
	}
}

func TestUnquoteShell(t *testing.T) {
	cases := map[string]string{
		`"Ubuntu 22.04.5 LTS"`: "Ubuntu 22.04.5 LTS",
		`'Debian'`:             "Debian",
		`Plain`:                "Plain",
		`"`:                    `"`,
		``:                     ``,
	}
	for in, want := range cases {
		if got := unquoteShell(in); got != want {
			t.Errorf("unquoteShell(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestFindCPUInfoValue(t *testing.T) {
	content := "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz\ncpu MHz\t\t: 2600.000\n"
	if got := findCPUInfoValue(content, "model name"); got != "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz" {
		t.Errorf("型号 = %q", got)
	}
	if got := findCPUInfoValue(content, "vendor_id"); got != "" {
		t.Errorf("不存在的字段应返回空串，实际 %q", got)
	}
}

func TestUtsnameString(t *testing.T) {
	raw := []int8{'x', '8', '6', '_', '6', '4', 0, 0}
	if got := utsnameString(raw); got != "x86_64" {
		t.Errorf("utsnameString = %q, 期望 %q", got, "x86_64")
	}
	if got := utsnameString(nil); got != "" {
		t.Errorf("空输入应返回空串，实际 %q", got)
	}
}

func TestRound2(t *testing.T) {
	cases := map[float64]float64{
		12.3456: 12.35,
		0.001:   0,
		100:     100,
		33.333:  33.33,
	}
	for in, want := range cases {
		if got := round2(in); math.Abs(got-want) > 0.0001 {
			t.Errorf("round2(%v) = %v, 期望 %v", in, got, want)
		}
	}
}

// Collect 是接口的数据来源，必须在真实机器上返回完整可用的一组字段。
func TestCollectOnRealHost(t *testing.T) {
	c := NewCollector()
	info := c.Collect()

	t.Logf("采集结果: %+v", info)
	if len(info.Warnings) > 0 {
		t.Logf("降级项: %v", info.Warnings)
	}

	if info.CollectedAt == "" {
		t.Error("collected_at 为空")
	}
	if info.CPU.Cores <= 0 {
		t.Errorf("CPU 核心数 = %d, 期望 > 0", info.CPU.Cores)
	}
	if info.CPU.UsagePercent < 0 || info.CPU.UsagePercent > 100 {
		t.Errorf("CPU 使用率 = %v, 应在 0~100 之间", info.CPU.UsagePercent)
	}
	if info.Memory.TotalBytes == 0 {
		t.Error("内存总量为 0")
	}
	if info.Memory.UsedBytes > info.Memory.TotalBytes {
		t.Errorf("已用内存 %d 超过总量 %d", info.Memory.UsedBytes, info.Memory.TotalBytes)
	}
	if info.Disk.TotalBytes == 0 {
		t.Error("磁盘总量为 0")
	}
	// 内核信息来自 uname 系统调用，任何 Linux 上都应成功。
	if info.Kernel == "" || info.Arch == "" {
		t.Errorf("内核/架构为空: kernel=%q arch=%q", info.Kernel, info.Arch)
	}
}

// CPU 使用率需要两次采样，连续调用必须稳定可算且不 panic。
func TestCollectCPUUsageTwice(t *testing.T) {
	c := NewCollector()
	c.SampleInterval = 50 * time.Millisecond

	first, err := c.cpuUsage()
	if err != nil {
		t.Fatalf("首次采样失败: %v", err)
	}
	second, err := c.cpuUsage()
	if err != nil {
		t.Fatalf("二次采样失败: %v", err)
	}
	for i, v := range []float64{first, second} {
		if v < 0 || v > 100 {
			t.Errorf("第 %d 次采样使用率 = %v, 应在 0~100 之间", i+1, v)
		}
	}
}

// 采集结果必须能序列化为 JSON，且字段名与前端约定一致（snake_case）。
func TestInfoJSONShape(t *testing.T) {
	c := NewCollector()
	data, err := json.Marshal(c.Collect())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}

	for _, key := range []string{
		"hostname", "os", "kernel", "arch", "uptime_seconds",
		"collected_at", "cpu", "memory", "swap", "disk",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("响应缺少字段 %q", key)
		}
	}

	cpu, ok := raw["cpu"].(map[string]any)
	if !ok {
		t.Fatalf("cpu 字段不是对象: %T", raw["cpu"])
	}
	for _, key := range []string{"model", "cores", "usage_percent", "load_avg"} {
		if _, ok := cpu[key]; !ok {
			t.Errorf("cpu 缺少字段 %q", key)
		}
	}

	mem, ok := raw["memory"].(map[string]any)
	if !ok {
		t.Fatalf("memory 字段不是对象: %T", raw["memory"])
	}
	for _, key := range []string{"total_bytes", "used_bytes", "free_bytes", "usage_percent"} {
		if _, ok := mem[key]; !ok {
			t.Errorf("memory 缺少字段 %q", key)
		}
	}
}

// 磁盘路径可配置，便于将来面板支持查看指定分区。
func TestCollectorDiskPath(t *testing.T) {
	c := NewCollector()
	c.DiskPath = "/tmp"
	info := c.Collect()

	if info.Disk.Path != "/tmp" {
		t.Errorf("磁盘路径 = %q, 期望 /tmp", info.Disk.Path)
	}
	if info.Disk.TotalBytes == 0 {
		t.Error("/tmp 的磁盘总量为 0")
	}
}
