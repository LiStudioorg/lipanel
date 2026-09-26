//go:build !unix && !windows

package plugin

// 本文件给**已不再维护的平台**一个能看懂的编译错误。
//
// 背景：发布矩阵已收缩为 Linux（13 架构）+ Windows（3 架构）。
// 此前为 45 平台写的 process_stub.go（plan9/js/wasip1）已删除。
//
// 这些平台没有 Unix domain socket，插件与本进程无法按设计通讯，
// 插件系统整体不可用；构建标签收窄后它们会在编译期失败，
// 而不是"悄悄缺符号"。
//
// 恢复某个平台时：删除本文件，并为它补上 setProcessGroup /
// terminateProcess / killProcess / isProcessGone 四个函数
// （参考 process_unix.go 与 process_windows.go）。
const _ int = "lipanel 插件系统只支持 unix 与 windows；" +
	"如需在此平台构建，请恢复 process_*.go 适配文件"
