package logs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ============================================================================
// 日志源白名单（安全边界）
// ============================================================================
//
// 本模块**只允许登记在这里的日志源**。新增一个来源必须在此显式定义：
// 它的类型、名称、能力、可用性探测方法与"实际从哪读"的细节 ——
// 而不允许在接口层构造任意日志源（那会引入 "登录即可读任意文件" 的入口）。
//
// 本机可用性（Available）是**运行期探测**的：每个源在探测时决定
// 它到底能不能读。这样接口与其它模块保持一致——「没装 journald /
// 没有 nginx」不是面板坏了，而是该源如实报告 unavailable + 修复指引。

// maxAppLogBytes 是单次读取单个应用日志文件的最大字节数，防止
// access.log 巨大把查询拖死或撑爆内存（单行截断见 reader.go）。
const maxAppLogBytes = 4 << 20 // 4 MiB

// systemLogFallbacks 是 journalctl 不可用时备选的系统日志文件。
// 按探测到的先后次序，取第一个存在且可读的作为 system 源的内容来源。
var systemLogFallbacks = []string{"/var/log/syslog", "/var/log/messages"}

// appLogFileNames 是 Nginx 应用日志的固定文件名（白名单）。
// Nginx 生成的配置里 access_log / error_log 都相对 prefix 的 logs/ 目录
// （见 internal/site/config.go 的模板），因此文件名只允许这两个。
var appLogFileNames = []string{"access.log", "error.log"}

// systemSourceID / nginx 源的固定 ID，接口与前端依赖它们。
const (
	SourceIDSystem   = "system"
	SourceIDNginxAcc = "nginx-access"
	SourceIDNginxErr = "nginx-error"
)

// probe 是一次探测的结论：该源可用 + 具体怎么读。
//
// 探测在构造时执行一次（面板启动时各源状态就定了）；运行期查询
// 再按 source 的读取计划执行。若某个文件在探测后被删除/轮转，
// 查询时以"读取失败"处理并如实报告，而不是探测时锁死。
type probeResult struct {
	available bool
	reason    string
	// journald 相关（system 源）：
	useJournald bool   // true 表示用 journalctl 读
	journalCtl  string // journalctl 可执行文件路径
	// file 相关（system 备用 或 nginx-app 源）：
	filePath string // 要读取的日志文件绝对路径
}

// sourceDef 是登记日志源的全部信息（类型层面不可被接口层构造）。
type sourceDef struct {
	id          string
	typ         SourceType
	name        string
	description string
	cap         Capability
	probe       func() probeResult
}

// registeredSources 返回全部日志源定义（解释器在 manager 里映射）。
func registeredSources(nginxLogsDir string) []sourceDef {
	return []sourceDef{
		{
			id:   SourceIDSystem,
			typ:  SourceSystem,
			name: "系统日志",
			description: "systemd 的 journald 日志（备选 syslog/messages）。" +
				"可用 journalctl -u 过滤 unit，按级别读取。",
			cap:   Capability{Search: true, Level: true, InitialLines: 100},
			probe: func() probeResult { return probeSystem() },
		},
		{
			id:   SourceIDNginxAcc,
			typ:  SourceApp,
			name: "Nginx 访问日志",
			description: "Nginx 的 access.log（相对 nginx prefix 的 logs/ 目录）。" +
				"来源目录由面板的 nginx prefix 决定。",
			cap: Capability{Search: true, Level: false, InitialLines: 100},
			probe: func() probeResult {
				if nginxLogsDir == "" {
					return probeResult{available: false,
						reason: "未配置 Nginx 日志目录（nginx prefix 未知）。"}
				}
				p := filepath.Join(nginxLogsDir, "access.log")
				return probeFile(p, "Nginx 访问日志", nginxLogsDir)
			},
		},
		{
			id:   SourceIDNginxErr,
			typ:  SourceApp,
			name: "Nginx 错误日志",
			description: "Nginx 的 error.log（相对 nginx prefix 的 logs/ 目录）。" +
				"来源目录由面板的 nginx prefix 决定。",
			cap: Capability{Search: true, Level: false, InitialLines: 100},
			probe: func() probeResult {
				if nginxLogsDir == "" {
					return probeResult{available: false,
						reason: "未配置 Nginx 日志目录（nginx prefix 未知）。"}
				}
				p := filepath.Join(nginxLogsDir, "error.log")
				return probeFile(p, "Nginx 错误日志", nginxLogsDir)
			},
		},
	}
}

// probeSystem 探测系统日志源：优先 journalctl，其次 syslog/messages。
func probeSystem() probeResult {
	if runtime.GOOS == "windows" {
		return probeResult{available: false,
			reason: "Windows 平台没有 journald 与 syslog，系统日志不可用。"}
	}

	if j, err := exec.LookPath("journalctl"); err == nil {
		// 探测 journalctl 是否真能列出日志（一次性、短超时由 caller 控制）。
		return probeResult{
			available:   true,
			useJournald: true,
			journalCtl:  j,
		}
	}

	// 备选文件：syslog / messages。
	for _, p := range systemLogFallbacks {
		if r := probeFile(p, p, filepath.Dir(p)); r.available {
			return probeResult{available: true, filePath: p}
		}
	}
	return probeResult{available: false,
		reason: "未检测到 journalctl，且 " +
			strings.Join(systemLogFallbacks, "、") + " 均不存在或不可读。" +
			"请确认系统使用 systemd 或存在上述日志文件。"}
}

// probeFile 探测一个白名单文件是否可读。
// dirMustBe 是当前允许读取的父目录（路径白名单附带校验，防御 prefix 混淆）。
func probeFile(path, label, dirMustBe string) probeResult {
	// 归一化后必须仍落在期望目录内（拒绝 ../ 与符号链接逃逸）。
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if parent != filepath.Clean(dirMustBe) {
		return probeResult{available: false,
			reason: fmt.Sprintf("%s 路径（%s）不在允许目录内，已拒绝。", label, path)}
	}
	info, err := os.Stat(path)
	if err != nil {
		return probeResult{available: false,
			reason: fmt.Sprintf("%s 不存在或不可访问：%v。", label, err)}
	}
	if info.IsDir() {
		return probeResult{available: false,
			reason: fmt.Sprintf("%s（%s）是目录而不是日志文件。", label, path)}
	}
	return probeResult{available: true, filePath: path}
}
