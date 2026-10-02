package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// 四类渠道的发送实现 + 统一 Notifier 接口
// ============================================================================

// Notifier 是通知模块对外暴露的发送接口，供其它模块（backup 等）调用。
type Notifier interface {
	// Send 把一条事件发送到一个（或全部启用）渠道。
	// channelID 为空串时发送到所有启用渠道。
	Send(ctx context.Context, channelID string, ev Event) SendResult
}

// Sender 是单个渠道的实际发送函数签名（便于测试注入）。
type Sender func(ctx context.Context, ch Channel, secret map[string]string, ev Event) error

// ---- HTTP 客户端（可注入，便于测试用 mock server） ----

// httpClient 是所有 webhook/Bot HTTP 请求使用的客户端。
// Manager 构造时可通过 setHTTPClient 替换（测试注入 mock）。
var httpClient = &http.Client{Timeout: 10 * time.Second}

// telegramAPIBase 是 Telegram Bot API 的基址。单独抽出以便测试用本地
// mock server 顶替（生产始终为 api.telegram.org，不要改）。
var telegramAPIBase = "https://api.telegram.org"

// httpDo 发送一次 POST JSON 请求。
func httpDo(req *http.Request) (*http.Response, error) {
	return httpClient.Do(req)
}

// setHTTPClient 替换全局 HTTP 客户端（测试用）。
func setHTTPClient(c *http.Client) { httpClient = c }

// ---- SMTP 连接辅助 ----

// smtpDial 建立到 addr 的普通 SMTP 连接。
func smtpDial(ctx context.Context, addr string) (*smtp.Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// 设置行超时由外层 ctx 统一控制；smtp.Client 用 net.Conn。
	return smtp.NewClient(conn, mustHost(addr))
}

// smtpDialTLS 建立到 addr 的 TLS SMTP 连接（隐式 TLS，如 SMTPS 465）。
func smtpDialTLS(ctx context.Context, addr string, tlsCfg *tls.Config) (*smtp.Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = tconn.Close()
		return nil, err
	}
	return smtp.NewClient(tconn, mustHost(addr))
}

// mustHost 从 "host:port" 拆出 host（SMTP 认证用）。
func mustHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// sendSMTP 邮件渠道。
func sendSMTP(ctx context.Context, ch Channel, secret map[string]string, ev Event) error {
	host := ch.SMTPHost
	port := ch.SMTPPort
	if port == 0 {
		port = 25
	}
	user := ch.SMTPUser
	pass := secret["smtp_password"]
	from := ch.SMTPFrom
	if from == "" {
		from = user
	}
	receivers, err := validReceivers(ch.Receivers)
	if err != nil {
		return err
	}

	subject := "[" + levelLabel(ev.Level) + "] " + ev.Title
	body := ev.Title + "\n\n" + ev.Message
	msg := buildMail(from, receivers, subject, body)
	addr := host + ":" + strconv.Itoa(port)

	var client *smtp.Client
	if ch.SMTPUseTLS {
		client, err = smtpDialTLS(ctx, addr, &tls.Config{ServerName: host})
	} else {
		client, err = smtpDial(ctx, addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP 连接失败: %w", err)
	}
	defer client.Close()

	if pass != "" {
		if err := client.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM 失败: %w", err)
	}
	for _, r := range receivers {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("SMTP RCPT TO(%s)失败: %w", r, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA 失败: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("SMTP 写正文失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP 关闭 DATA 失败: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT 失败: %w", err)
	}
	return nil
}

// sendHTTPPayload 向 url POST 一个 JSON payload。
func sendHTTPPayload(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpDo(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return nil
}

// sendDingTalk 钉钉自定义机器人：向 webhook 发 `{"msgtype":"text","text":{"content":...}}`。
func sendDingTalk(ctx context.Context, ch Channel, secret map[string]string, ev Event) error {
	url := secret["webhook_url"]
	if url == "" {
		return fmt.Errorf("未配置钉钉 webhook")
	}
	content := ev.Title
	if ev.Message != "" {
		content += "\n" + ev.Message
	}
	payload, _ := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": content},
	})
	return sendHTTPPayload(ctx, url, payload)
}

// sendWeCom 企业微信机器人：向 webhook 发 `{"msgtype":"text","text":{"content":...}}`。
func sendWeCom(ctx context.Context, ch Channel, secret map[string]string, ev Event) error {
	url := secret["webhook_url"]
	if url == "" {
		return fmt.Errorf("未配置企业微信 webhook")
	}
	content := ev.Title + "\n" + ev.Message
	payload, _ := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": content},
	})
	return sendHTTPPayload(ctx, url, payload)
}

// sendTelegram Telegram Bot：调用 Bot API `sendMessage`。
func sendTelegram(ctx context.Context, ch Channel, secret map[string]string, ev Event) error {
	token := secret["telegram_token"]
	if token == "" {
		return fmt.Errorf("未配置 Telegram token")
	}
	if err := validTelegramChatID(ch.TelegramChatID); err != nil {
		return err
	}
	url := telegramAPIBase + "/bot" + token + "/sendMessage"
	text := ev.Title
	if ev.Message != "" {
		text += "\n" + ev.Message
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": strings.TrimSpace(ch.TelegramChatID),
		"text":    text,
	})
	return sendHTTPPayload(ctx, url, payload)
}

// levelLabel 把级别映射为渠道友好的前缀。
func levelLabel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "错误"
	case "warn", "warning":
		return "告警"
	default:
		return "通知"
	}
}

// buildMail 组装一封 UTF-8 纯文本邮件。
func buildMail(from string, receivers []string, subject, body string) string {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + strings.Join(receivers, ", ") + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

// truncate 截断字符串用于安全展示。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
