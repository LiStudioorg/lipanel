package notify

import (
	"log/slog"
	"time"
)

// ChannelType 是通知渠道类型。
type ChannelType string

const (
	// TypeSMTP 邮件渠道（net/smtp）。
	TypeSMTP ChannelType = "smtp"
	// TypeDingTalk 钉钉自定义机器人 webhook。
	TypeDingTalk ChannelType = "dingtalk"
	// TypeWeCom 企业微信机器人 webhook。
	TypeWeCom ChannelType = "wecom"
	// TypeTelegram Telegram Bot。
	TypeTelegram ChannelType = "telegram"
)

// Credential 是渠道的敏感字段集合，落盘前被加密（见 crypto.go）。
type Credential struct {
	// SMTP 密码。
	SMTPPassword string `json:"smtp_password,omitempty"`
	// DingTalk/WeCom webhook 地址（其内嵌了 access_token）。
	WebhookURL string `json:"webhook_url,omitempty"`
	// Telegram bot token（形如 123456:ABC-...）。
	TelegramToken string `json:"telegram_token,omitempty"`
}

// Channel 是一条通知渠道配置。
type Channel struct {
	// ID 是渠道唯一标识（创建时生成）。
	ID string `json:"id"`
	// Name 是渠道名称（用户起名，如「线上告警」）。
	Name string `json:"name"`
	// Type 是渠道类型。
	Type ChannelType `json:"type"`
	// Enabled 表示该渠道是否启用（禁用的渠道不被 Notifier.Send 使用）。
	Enabled bool `json:"enabled"`

	// ---- SMTP ----
	SMTPHost string `json:"smtp_host,omitempty"`
	SMTPPort int    `json:"smtp_port,omitempty"`
	// SMTPUser 是登录邮箱（From）。
	SMTPUser string `json:"smtp_user,omitempty"`
	// SMTPFrom 是发件人显示名（可选，缺省用 SMTPUser）。
	SMTPFrom string `json:"smtp_from,omitempty"`
	// Receivers 是收件人（逗号/分号分隔多个）。
	Receivers string `json:"receivers,omitempty"`
	// SMTPUseTLS 是否使用 STARTTLS。
	SMTPUseTLS bool `json:"smtp_use_tls,omitempty"`

	// ---- Telegram ----
	TelegramChatID string `json:"telegram_chat_id,omitempty"`

	// ---- 通用 ----
	// Secret 是加密凭证（对外接口永不返回明文，只返回脱敏副本）。
	Secret Credential `json:"secret,omitempty"`

	// 元数据。
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// PublicChannel 是返回给前端的脱敏渠道视图（不含任何明文凭证）。
type PublicChannel struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Type           ChannelType `json:"type"`
	Enabled        bool        `json:"enabled"`
	SMTPHost       string      `json:"smtp_host,omitempty"`
	SMTPPort       int         `json:"smtp_port,omitempty"`
	SMTPUser       string      `json:"smtp_user,omitempty"`
	SMTPFrom       string      `json:"smtp_from,omitempty"`
	Receivers      string      `json:"receivers,omitempty"`
	SMTPUseTLS     bool        `json:"smtp_use_tls,omitempty"`
	TelegramChatID string      `json:"telegram_chat_id,omitempty"`
	// 已配置的敏感字段位（用布尔反映"有没有配置"，但不回显值）。
	HasSecret bool   `json:"has_secret"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Event 是发送给通知渠道的一条事件消息（Notifier.Send 的统一入参）。
type Event struct {
	// Title 是标题（一行）。
	Title string `json:"title"`
	// Message 是正文（可多行）。
	Message string `json:"message"`
	// Level 是级别（error/warn/info，可选，用于部分渠道配色）。
	Level string `json:"level,omitempty"`
	// Metric 是触发源标识（可选，如 backup:task-3，便于审计归类）。
	Metric string `json:"metric,omitempty"`
}

// SendResult 是一次发送的结果。
type SendResult struct {
	// ChannelID 是目标渠道 ID（空表示对所有启用渠道发送）。
	ChannelID string `json:"channel_id,omitempty"`
	// Sent 表示送达成功的渠道数。
	Sent int `json:"sent"`
	// Failed 表示失败的渠道数。
	Failed int `json:"failed"`
	// Errors 是每个失败渠道的错误摘要（已脱敏，不含任何凭证）。
	Errors map[string]string `json:"errors,omitempty"`
}

// NotifyOptions 是构造 Manager 的配置。
type NotifyOptions struct {
	// MasterSecret 是用于派生加密密钥的主密钥（auth.jwt_secret）。
	// 为空时加密不可用（退回内存明文 + 前置告警），但构造仍成功。
	MasterSecret string
	// StorePath 是凭证存储文件路径（JSON，0600）。为空则仅在内存保存（不落盘）。
	StorePath string
	// SendTimeout 是单次渠道发送超时；<=0 时用 DefaultSendTimeout。
	SendTimeout time.Duration
	// RetryTimes 是发送失败重试次数；<0 时用 DefaultRetryTimes。
	RetryTimes int
	// AuditCapacity 是审计环形缓冲容量；<=0 时用默认值。
	AuditCapacity int
	// AuditPath 非空时把审计以 JSONL 追加写入该文件（0600）。
	AuditPath string
	// Logger 为 nil 时用 slog.Default()。
	Logger *slog.Logger
}

// DefaultSendTimeout 是默认单渠道发送超时。
const DefaultSendTimeout = 10 * time.Second

// DefaultRetryTimes 是默认发送重试次数（失败后再试这么多次）。
const DefaultRetryTimes = 2
