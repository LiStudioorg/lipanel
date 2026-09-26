// 插件子命令入口。
//
// 背景：工程约束要求「单二进制、CGO_ENABLED=0、scp 到服务器直接跑」。
// 若内置插件做成独立的可执行文件，部署时就得同时分发多个文件，
// 一旦版本不一致还会出现难以排查的兼容问题。
//
// 因此内置插件采用「自身二进制 + 子命令」形态：
// 核心拉起插件时执行 <lipanel 可执行文件> __plugin_<id>，
// 本文件识别到该参数后不启动 HTTP 面板，而是以插件身份运行。
package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"lipanel/internal/plugin"
	// 匿名导入内置插件包：插件在各自的 init 中调用 plugin.RegisterBuiltin
	// 完成自我登记，主程序无需逐一声明。新增插件时只加一行 import。
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

// maybeRunAsPlugin 检查启动参数，若当前进程是被核心拉起的插件则进入插件模式。
//
// 返回值 handled=true 表示本进程是插件，已执行完毕（或失败），
// 调用方应直接退出，不要继续启动 HTTP 面板。
//
// 之所以放在 main 最前面、且不经过 flag.Parse()：
// flag 包遇到 "__plugin_sysinfo" 这种非 - 开头的参数会直接报错退出，
// 因此必须在 flag.Parse 之前拦截。
func maybeRunAsPlugin() (handled bool, err error) {
	if len(os.Args) < 2 {
		return false, nil
	}

	arg := os.Args[1]
	if !strings.HasPrefix(arg, plugin.PluginSubcommandPrefix) {
		return false, nil
	}

	id := strings.TrimPrefix(arg, plugin.PluginSubcommandPrefix)
	if !plugin.ValidID(id) {
		return true, fmt.Errorf("非法插件子命令 %q：期望 %s<id>", arg, plugin.PluginSubcommandPrefix)
	}

	// 插件进程的日志前缀带上插件 ID：单机排查时，
	// 核心与多个插件的日志会混在同一个 stdout 里，没有前缀根本分不清谁是谁。
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("plugin", id)

	handler, err := plugin.Build(id, logger)
	if err != nil {
		return true, err
	}

	logger.Info("插件进程启动中")
	if err := plugin.Serve(handler, logger); err != nil {
		return true, fmt.Errorf("插件 %s 运行失败: %w", id, err)
	}
	return true, nil
}
