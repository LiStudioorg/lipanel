package notify

import "errors"

// 通知模块的错误语义。
//
//	ErrChannelNotFound     渠道不存在（404）
//	ErrInvalidChannel      渠道配置非法（400）
//	ErrStoreUnavailable    存储不可用（503）
//	ErrNoCipher            未配置主密钥，凭证无法加密（配置问题）
var (
	// ErrChannelNotFound 表示要操作的渠道不存在。
	ErrChannelNotFound = errors.New("notify: 渠道不存在")
	// ErrInvalidChannel 表示渠道配置非法（字段级错误在响应里给出具体字段）。
	ErrInvalidChannel = errors.New("notify: 渠道配置非法")
	// ErrNoCipher 表示未配置主密钥（凭证加密不可用）。
	ErrNoCipher = errors.New("notify: 未配置主密钥，凭证加密不可用")
)
