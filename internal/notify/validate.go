package notify

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
)

// ============================================================================
// 通知渠道输入校验（白名单）
// ============================================================================
//
// 与其它核心模块一致：所有用户输入**先白名单校验，再用于任何"发送动作"**。
// 这里校验的是"这个字符串能不能用"，不悄悄改写（校验函数只回答是与否）。

// ErrInvalidField 是某个字段非法（带具体原因，错误文本里说明）。
var ErrInvalidField = errors.New("notify: 字段非法")

// validID 校验渠道 ID 白名单（小写字母数字、短横线，长度 1..64）。
// 在实际使用中 ID 由服务端 newID 生成，这里仅作为防御性校验保留，
// 因为将来若放开"自定义 ID"，绝不能接受任意字符串。
func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-':
		default:
			return false
		}
	}
	return true
}

// nameRe 是渠道名称白名单：中英文、数字、空格、常用符号，长度 1..64。
func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r == ' ' || r == '-' || r == '_' || r == '.' || r == '（' || r == '）' || r == '(' || r == ')' {
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if r >= 0x4e00 && r <= 0x9fff { // 汉字
			continue
		}
		return false
	}
	return true
}

// validType 判断渠道类型是否在白名单内。
func validType(t ChannelType) bool {
	switch t {
	case TypeSMTP, TypeDingTalk, TypeWeCom, TypeTelegram:
		return true
	}
	return false
}

// validSMTPPort 校验 SMTP 端口。
func validSMTPPort(port int) bool {
	return port >= 1 && port <= 65535
}

// validEmail 校验单个邮箱地址。
func validEmail(addr string) bool {
	addr = strings.TrimSpace(addr)
	_, err := mail.ParseAddress(addr)
	return err == nil && strings.Contains(addr, "@")
}

// validReceivers 校验收件人列表（逗号/分号/换行分隔）。
// 每个都必须通过 validEmail。
func validReceivers(receivers string) ([]string, error) {
	var out []string
	for _, part := range strings.FieldsFunc(receivers, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !validEmail(part) {
			return nil, fmt.Errorf("%w: 收件人邮箱非法: %q", ErrInvalidField, part)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个收件人", ErrInvalidField)
	}
	return out, nil
}

// validWebhookURL 校验 webhook/bot 地址：必须是 http/https、有非空 host。
// 显式拒绝可能被利用的协议（如 file://、unix://）。
func validWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: URL 解析失败", ErrInvalidField)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: 只允许 http/https 协议，收到 %q", ErrInvalidField, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: URL 缺少主机名", ErrInvalidField)
	}
	// host 不能是 . 或包含非法字符，且每个标签不以前导/后置短横线开头结尾。
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "." || strings.Contains(host, "..") {
		return fmt.Errorf("%w: URL 主机名非法", ErrInvalidField)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: URL 主机名含非法标签", ErrInvalidField)
		}
	}
	return nil
}

// validTelegramToken 校验 Telegram bot token 形态。
// 形如 `123456789:AAAA-BBBB...`。
func validTelegramToken(token string) error {
	token = strings.TrimSpace(token)
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: Telegram token 应形如 <bot_id>:<auth>", ErrInvalidField)
	}
	if _, err := strconv.ParseInt(parts[0], 10, 64); err != nil {
		return fmt.Errorf("%w: Telegram bot id 应为数字", ErrInvalidField)
	}
	if parts[1] == "" {
		return fmt.Errorf("%w: Telegram token 认证段为空", ErrInvalidField)
	}
	return nil
}

// validTelegramChatID 校验 chat id（可为负整数，如 -100123456789）。
func validTelegramChatID(chatID string) error {
	chatID = strings.TrimSpace(chatID)
	if chatID == "" {
		return fmt.Errorf("%w: Telegram chat_id 不能为空", ErrInvalidField)
	}
	if _, err := strconv.ParseInt(chatID, 10, 64); err != nil {
		return fmt.Errorf("%w: Telegram chat_id 应为整数", ErrInvalidField)
	}
	return nil
}

// validatedSMTPServer 校验 SMTP 主机是否含非法字符，并返回归一化主机。
// 只做形态校验（允许 IP 或主机名），不解析 DNS（校验阶段不产生网络动作）。
func validatedSMTPServer(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("%w: SMTP 主机不能为空", ErrInvalidField)
	}
	if strings.ContainsAny(host, " \t;|`$&(){}[]<>") || strings.Contains(host, "../") {
		return "", fmt.Errorf("%w: SMTP 主机含非法字符", ErrInvalidField)
	}
	return host, nil
}
