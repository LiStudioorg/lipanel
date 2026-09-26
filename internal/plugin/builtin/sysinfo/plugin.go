// Package sysinfo 是 lipanel 的第一个内置插件，也是插件骨架的参考实现。
//
// 它把「系统信息采集」以插件的形式重新暴露一遍，用来证明
// 「核心 → 插件进程」这条链路真的通了：数据来自插件进程，
// 经过 Unix socket，由核心的 /api/plugins/sysinfo/* 转发出去。
//
// 插件作者写一个新插件需要做的事情，本文件全部覆盖：
//
//  1. 实现 plugin.Handler 接口（Descriptor + Routes）；
//  2. 在本包的 init 中调用 plugin.RegisterBuiltin 注册工厂函数；
//  3. 前端如需界面，在 web/src/plugins/registry.js 里登记同名的 entry。
//
// 注意：插件进程是独立进程，不共享核心的内存状态，
// 因此它自己持有一个 sysinfo.Collector（CPU 使用率需要两次快照差值）。
package sysinfo

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"lipanel/internal/plugin"
	"lipanel/internal/sysinfo"
)

// ID 是插件的唯一标识，会出现在 URL /api/plugins/sysinfo/... 中。
const ID = "sysinfo"

// Version 是插件版本号，独立于主程序版本演进。
const Version = "0.1.0"

// init 把本插件登记到内置插件注册表。
//
// 主程序只用一行匿名 import 引用本包，本包自己完成登记——
// 新增插件时不需要改动 cmd/lipanel 的任何逻辑。
func init() {
	plugin.RegisterBuiltin(ID, func(logger *slog.Logger) plugin.Handler {
		return New(logger)
	})
}

// Plugin 实现 plugin.Handler 接口。
type Plugin struct {
	// collector 持有 CPU 采样基线，因此必须是长生命周期对象。
	collector *sysinfo.Collector
	logger    *slog.Logger
	startedAt time.Time
}

// New 构造插件实例。
func New(logger *slog.Logger) *Plugin {
	if logger == nil {
		logger = slog.Default()
	}
	return &Plugin{
		collector: sysinfo.NewCollector(),
		logger:    logger,
		startedAt: time.Now(),
	}
}

// Descriptor 返回插件元数据。
//
// Frontend 字段是「插件前端挂载插槽」的元数据：
// 核心会把它原样返回给前端，前端据此生成菜单项并决定渲染哪个组件。
func (p *Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:          ID,
		Name:        "系统信息（插件版）",
		Version:     Version,
		Description: "通过独立插件进程采集 CPU / 内存 / 磁盘信息，用于验证插件通讯链路。",
		Builtin:     true,
		Mode:        plugin.ModeManaged,
		Frontend: plugin.Frontend{
			// Entry 是前端静态注册表（web/src/plugins/registry.js）的 key。
			Entry:    ID,
			NavTitle: "系统信息（插件）",
			NavIcon:  "dashboard",
		},
	}
}

// Routes 注册插件的业务路由。
// /healthz 与 /whoami 由插件骨架自动提供，这里无需重复注册。
func (p *Plugin) Routes(mux *http.ServeMux) {
	// GET /info —— 完整的系统信息，等价于核心的 /api/system/info。
	mux.HandleFunc("GET /info", p.handleInfo)

	// GET /echo —— 回显请求信息。
	// 它的价值在于「可观测」：任何人都能用它确认
	// 路径改写、查询参数、请求头透传是否符合预期。
	mux.HandleFunc("GET /echo", p.handleEcho)

	// GET /runtime —— 返回插件自身的运行时长与进程信息。
	// 核心的插件管理页会用它展示「插件自己认为的运行状态」，
	// 与核心记录的 PID / 启动时间互为印证。
	mux.HandleFunc("GET /runtime", p.handleRuntime)
}

func (p *Plugin) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := p.collector.Collect()
	plugin.PluginJSON(w, p.logger, http.StatusOK, map[string]any{
		"plugin": ID,
		"info":   info,
	})
}

func (p *Plugin) handleEcho(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	plugin.PluginJSON(w, p.logger, http.StatusOK, map[string]any{
		"plugin":     ID,
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"headers":    headers,
		"remote":     r.RemoteAddr,
		"received_at": time.Now().Format(time.RFC3339),
		// 显式汇报凭据头是否为空，方便用一条 curl 就验证核心侧的剥离逻辑。
		"cookie_stripped":      r.Header.Get("Cookie") == "",
		"authorization_stripped": r.Header.Get("Authorization") == "",
	})
}

func (p *Plugin) handleRuntime(w http.ResponseWriter, r *http.Request) {
	exe, _ := os.Executable()
	plugin.PluginJSON(w, p.logger, http.StatusOK, map[string]any{
		"plugin":         ID,
		"version":        Version,
		"pid":            os.Getpid(),
		"ppid":           os.Getppid(),
		"executable":     exe,
		"started_at":     p.startedAt.Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(p.startedAt).Seconds()),
		"threads":        threadCount(),
	})
}

// goroutineCount 读取当前进程的线程数。
//
// 明确说明：这里返回的是 OS 线程数（/proc/self/status 的 Threads），
// 不是 Go 的 goroutine 数——读取 goroutine 数需要 runtime 包，
// 而本插件刻意保持「纯标准库 + /proc」的风格。字段名因此叫 threads。
func threadCount() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		const prefix = "Threads:"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
		if err != nil {
			return -1
		}
		return n
	}
	return -1
}
