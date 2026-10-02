package notify

import (
	"fmt"
)

// ============================================================================
// 渠道入参与校验
// ============================================================================

// ChannelInput 是创建/编辑渠道的入参（明文凭证在这里同步提交）。
type ChannelInput struct {
	Name    string
	Type    ChannelType
	Enabled bool

	SMTPHost   string
	SMTPPort   int
	SMTPUser   string
	SMTPFrom   string
	Receivers  string
	SMTPUseTLS bool

	TelegramChatID string

	// 明文凭证（仅创建/编辑时提交；编辑时空串=不改动）。
	SMTPPassword  string
	WebhookURL    string
	TelegramToken string
}

// validateChannelInput 校验渠道入参（白名单 + 类型特有字段）。
// 返回带字段名 / 具体原因的错误，接口层据此给出 400 + 可操作提示。
func validateChannelInput(in ChannelInput) error {
	if !validName(in.Name) {
		return fmt.Errorf("notify: 渠道名称非法（1-64 字符，中英文/数字/常用符号）")
	}
	if !validType(in.Type) {
		return fmt.Errorf("notify: 不支持的渠道类型 %q", in.Type)
	}
	switch in.Type {
	case TypeSMTP:
		if _, err := validatedSMTPServer(in.SMTPHost); err != nil {
			return err
		}
		if in.SMTPPort != 0 && !validSMTPPort(in.SMTPPort) {
			return fmt.Errorf("notify: SMTP 端口非法")
		}
		if in.SMTPUser == "" {
			return fmt.Errorf("notify: SMTP 账号（登录邮箱）不能为空")
		}
		if _, err := validReceivers(in.Receivers); err != nil {
			return err
		}
	case TypeDingTalk, TypeWeCom:
		if err := validWebhookURL(in.WebhookURL); err != nil {
			return err
		}
	case TypeTelegram:
		if err := validTelegramToken(in.TelegramToken); err != nil {
			return err
		}
		if err := validTelegramChatID(in.TelegramChatID); err != nil {
			return err
		}
	}
	return nil
}

// validateChannelInputUpdate 校验**编辑**入参。
// 与创建的差别：凭证字段允许为空串（表示"不改动"），因此不强制要求填写
// （webhook / telegram token / smtp 密码）。但类型相关的非凭证字段
// （SMTP host/账号、receivers、telegram chat_id）仍要合法。
func validateChannelInputUpdate(in ChannelInput) error {
	if !validName(in.Name) {
		return fmt.Errorf("notify: 渠道名称非法（1-64 字符，中英文/数字/常用符号）")
	}
	if !validType(in.Type) {
		return fmt.Errorf("notify: 不支持的渠道类型 %q", in.Type)
	}
	switch in.Type {
	case TypeSMTP:
		if _, err := validatedSMTPServer(in.SMTPHost); err != nil {
			return err
		}
		if in.SMTPPort != 0 && !validSMTPPort(in.SMTPPort) {
			return fmt.Errorf("notify: SMTP 端口非法")
		}
		if in.SMTPUser == "" {
			return fmt.Errorf("notify: SMTP 账号（登录邮箱）不能为空")
		}
		if in.Receivers != "" {
			if _, err := validReceivers(in.Receivers); err != nil {
				return err
			}
		}
	case TypeDingTalk, TypeWeCom:
		if in.WebhookURL != "" {
			if err := validWebhookURL(in.WebhookURL); err != nil {
				return err
			}
		}
	case TypeTelegram:
		if in.TelegramToken != "" {
			if err := validTelegramToken(in.TelegramToken); err != nil {
				return err
			}
		}
		if in.TelegramChatID != "" {
			if err := validTelegramChatID(in.TelegramChatID); err != nil {
				return err
			}
		}
	}
	return nil
}
