package terminal

import "syscall"

// syscallSignalZero 是 signal 0：不发送任何信号，只做权限与存在性检查。
//
// 测试用它探测"进程是否还存在"。单独抽成常量而不是到处写
// syscall.Signal(0)，是为了让测试代码可读，并集中处理平台差异
// （本项目的发布矩阵只含 Linux 与 Windows，而 Windows 上
// 终端模块本身不可用，测试自然也不会跑）。
const syscallSignalZero = syscall.Signal(0)
