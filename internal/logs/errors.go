package logs

import "errors"

// 日志模块的错误语义。
//
// 与其它核心模块一致，错误含义清晰、可被接口层映射为准确 HTTP 状态码，
// 绝不裸奔 500：
//
//	ErrSourceNotFound      日志源不存在（400，用户写错了 source）
//	ErrSourceUnavailable   日志源存在但不可用（503，环境缺 journald/nginx，不是 bug）
var (
	// ErrSourceNotFound 表示请求的日志源 ID 不在白名单内。
	ErrSourceNotFound = errors.New("logs: 日志源不存在")
	// ErrSourceUnavailable 表示日志源被识别但当前不可用（如本机无 journald）。
	ErrSourceUnavailable = errors.New("logs: 日志源当前不可用")
)
