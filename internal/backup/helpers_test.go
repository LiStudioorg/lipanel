package backup

import (
	"io"
	"log/slog"
	"runtime"
	"time"
)

// runtime_isWindows 报告当前是否运行在 Windows 上。
//
// 单独一个函数而不是到处写 runtime.GOOS == "windows"：
// 有几处用例是"在 Windows 上无法构造前置条件"（符号链接需要特权），
// 把它们统一收口，将来换平台时只改一处。
func runtime_isWindows() bool { return runtime.GOOS == "windows" }

// discardLogger 返回一个不输出任何东西的日志器。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fixedClock 返回一个固定时刻与读取它的函数。
//
// 固定时钟是**必须**的：ArchiveKeyFor 用的时间戳精确到秒，
// 而「保留策略」按名字排序决定删哪些。用真实时钟的话，
// 同一秒内造出来的几份归档会得到完全相同的名字，
// 用例就会变成随机通过。
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}
