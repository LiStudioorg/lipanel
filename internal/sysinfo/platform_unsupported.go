//go:build !linux && !android && !windows

package sysinfo

// 本文件给**已不再维护的平台**一个能看懂的编译错误。
//
// 背景：发布矩阵已收缩为 Linux（13 架构）+ Windows（3 架构）。
// 此前为 45 平台写的适配文件（host_bsd.go、statfs_darwin.go、
// statfs_freebsd.go、statfs_openbsd.go、statfs_dragonfly.go）已删除。
//
// 若没有本文件，被移除的平台会报一连串 "undefined: hasProcFS /
// fileSystemStats / osHostname / readKernelVersion"，看起来像代码写错了，
// 而不是"这个平台已不再维护"——那正是上次全平台红叉最难排查的地方。
//
// 说明：Go 会先列出未定义符号，本条提示出现在错误列表末尾；
// 但它明确写清了原因与恢复方式，比单纯一串 undefined 有用得多。
//
// 恢复某个平台时：删除本文件，并为它补回 hasProcFS / osHostname /
// readKernelVersion / fileSystemStats 四个符号（参考 host_linux.go 与
// host_windows.go），再把它加回 .github/workflows/release.yml 的矩阵。
const _ int = "lipanel 只支持 linux 与 windows；" +
	"如需在此平台构建，请恢复对应适配文件并加入 release.yml 矩阵"
