package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 通知渠道管理器（阶段五 5.4.2）
// ============================================================================
//
// Manager 负责渠道的增删改查、测试发送，以及统一的 Notifier 发送接口。
//
// 关键设计：
//   - 凭证在**构造/编辑时**用 Cipher 加密后交给 Store 落盘；
//   - 明文凭证只在**发送/测试发送**时临时解密，解密结果不上锁落盘、
//     不进审计、不进日志，仅存在于单次发送的调用栈内；
//   - 发送失败做固定次数的重试（平方退避），仍失败则如实记为 failed。

// Manager 是通知渠道管理器。
type Manager struct {
	mu       sync.RWMutex
	channels []Channel
	store    *Store
	cipher   *Cipher
	timeout  time.Duration
	retries  int
	logger   *slog.Logger
	auditor  *Auditor
	// perTypeSender 允许测试注入每个类型的发送实现。
	perTypeSender map[ChannelType]Sender
	// notifier 是把 Send 委托出去的实现（便于测试拦截）。
}

// New 构造通知管理器。
func New(opts NotifyOptions) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := opts.SendTimeout
	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}
	retries := opts.RetryTimes
	if retries < 0 {
		retries = DefaultRetryTimes
	}

	var cipher *Cipher
	if opts.MasterSecret != "" {
		c, err := NewCipher([]byte(opts.MasterSecret))
		if err != nil {
			return nil, err
		}
		cipher = c
	} else {
		logger.Warn("未配置主密钥，通知渠道凭证加密不可用且不会落盘（仅供开发/测试）")
	}

	auditor, err := NewAuditor(AuditOptions{
		Capacity: opts.AuditCapacity,
		Path:     opts.AuditPath,
		Logger:   logger,
	})
	if err != nil {
		return nil, err
	}

	store, err := NewStore(opts.StorePath, cipher)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		store:   store,
		cipher:  cipher,
		timeout: timeout,
		retries: retries,
		logger:  logger,
		auditor: auditor,
		perTypeSender: map[ChannelType]Sender{
			TypeSMTP:     sendSMTP,
			TypeDingTalk: sendDingTalk,
			TypeWeCom:    sendWeCom,
			TypeTelegram: sendTelegram,
		},
	}

	loaded, err := store.Load()
	if err != nil {
		return nil, err
	}
	m.channels = append([]Channel(nil), loaded...)
	return m, nil
}

// Auditor 返回审计器。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// EncryptionEnabled 报告凭证加密是否可用。
func (m *Manager) EncryptionEnabled() bool { return m.cipher != nil }

// StorePath 返回凭证存储路径（状态接口展示）。
func (m *Manager) StorePath() string { return m.store.path }

// Options 返回关键构造参数（状态接口展示）。
func (m *Manager) Options() NotifyOptions {
	return NotifyOptions{
		MasterSecret: "",
		StorePath:    m.store.path,
		SendTimeout:  m.timeout,
		RetryTimes:   m.retries,
	}
}

// List 返回渠道的脱敏视图。
func (m *Manager) List() []PublicChannel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PublicChannel, 0, len(m.channels))
	for i := range m.channels {
		out = append(out, publicChannel(&m.channels[i]))
	}
	return out
}

// Get 返回单个渠道的脱敏视图。
func (m *Manager) Get(id string) (PublicChannel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch, ok := m.findChannelLocked(id)
	if !ok {
		return PublicChannel{}, ErrChannelNotFound
	}
	return publicChannel(&ch), nil
}

func (m *Manager) findChannelLocked(id string) (Channel, bool) {
	for i := range m.channels {
		if m.channels[i].ID == id {
			return m.channels[i], true
		}
	}
	return Channel{}, false
}

// Create 新建渠道。in 携带明文凭证，内部校验后加密落盘。
func (m *Manager) Create(in ChannelInput) (Channel, error) {
	if err := validateChannelInput(in); err != nil {
		return Channel{}, err
	}
	now := time.Now().Format(time.RFC3339)
	ch := Channel{
		ID:             newID(),
		Name:           in.Name,
		Type:           in.Type,
		Enabled:        in.Enabled,
		SMTPHost:       strings.TrimSpace(in.SMTPHost),
		SMTPPort:       in.SMTPPort,
		SMTPUser:       strings.TrimSpace(in.SMTPUser),
		SMTPFrom:       strings.TrimSpace(in.SMTPFrom),
		Receivers:      strings.TrimSpace(in.Receivers),
		SMTPUseTLS:     in.SMTPUseTLS,
		TelegramChatID: strings.TrimSpace(in.TelegramChatID),
		CreatedAt:      now,
		UpdatedAt:      now,
		Secret: Credential{
			SMTPPassword:  in.SMTPPassword,
			WebhookURL:    strings.TrimSpace(in.WebhookURL),
			TelegramToken: strings.TrimSpace(in.TelegramToken),
		},
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.encryptChannelLocked(&ch); err != nil {
		return Channel{}, err
	}
	m.channels = append(m.channels, ch)
	if err := m.store.Save(m.channels); err != nil {
		return Channel{}, err
	}
	return ch, nil
}

// Update 编辑渠道。in 中空串的凭证字段表示"不改动"（而非清空）。
func (m *Manager) Update(id string, in ChannelInput) (Channel, error) {
	if err := validateChannelInputUpdate(in); err != nil {
		return Channel{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.findChannelLocked(id)
	if !ok {
		return Channel{}, ErrChannelNotFound
	}

	now := time.Now().Format(time.RFC3339)
	updated := old
	updated.Name = in.Name
	updated.Type = in.Type
	updated.Enabled = in.Enabled
	updated.SMTPHost = strings.TrimSpace(in.SMTPHost)
	updated.SMTPPort = in.SMTPPort
	updated.SMTPUser = strings.TrimSpace(in.SMTPUser)
	updated.SMTPFrom = strings.TrimSpace(in.SMTPFrom)
	updated.Receivers = strings.TrimSpace(in.Receivers)
	updated.SMTPUseTLS = in.SMTPUseTLS
	updated.TelegramChatID = strings.TrimSpace(in.TelegramChatID)
	updated.UpdatedAt = now

	// 凭证合并：用户提交了明文就加密覆盖；没提交（空串）就保留既有密文。
	if in.SMTPPassword != "" {
		if err := m.remapSecretPassword(&updated, in.SMTPPassword); err != nil {
			return Channel{}, err
		}
	}
	if in.WebhookURL != "" {
		if err := m.remapSecretWebhook(&updated, strings.TrimSpace(in.WebhookURL)); err != nil {
			return Channel{}, err
		}
	}
	if in.TelegramToken != "" {
		if err := m.remapSecretTelegram(&updated, strings.TrimSpace(in.TelegramToken)); err != nil {
			return Channel{}, err
		}
	}

	// 替换回列表。
	for i := range m.channels {
		if m.channels[i].ID == id {
			m.channels[i] = updated
			break
		}
	}
	if err := m.store.Save(m.channels); err != nil {
		return Channel{}, err
	}
	return updated, nil
}

// Delete 删除渠道。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i := range m.channels {
		if m.channels[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrChannelNotFound
	}
	m.channels = append(m.channels[:idx], m.channels[idx+1:]...)
	return m.store.Save(m.channels)
}

// encryptChannelLocked 把渠道内明文凭证加密（调用方已持写锁）。
func (m *Manager) encryptChannelLocked(ch *Channel) error {
	if err := m.store.EncryptChannel(ch); err != nil {
		return fmt.Errorf("加密渠道凭证失败: %w", err)
	}
	return nil
}

func (m *Manager) remapSecretPassword(ch *Channel, plain string) error {
	v, err := m.store.EncryptField(plain)
	if err != nil {
		return err
	}
	ch.Secret.SMTPPassword = v
	return nil
}

func (m *Manager) remapSecretWebhook(ch *Channel, plain string) error {
	v, err := m.store.EncryptField(plain)
	if err != nil {
		return err
	}
	ch.Secret.WebhookURL = v
	return nil
}

func (m *Manager) remapSecretTelegram(ch *Channel, plain string) error {
	v, err := m.store.EncryptField(plain)
	if err != nil {
		return err
	}
	ch.Secret.TelegramToken = v
	return nil
}

// Send 实现 Notifier 接口：发送到指定渠道或全部启用渠道。
func (m *Manager) Send(ctx context.Context, channelID string, ev Event) SendResult {
	if ev.Title == "" && ev.Message == "" {
		return SendResult{ChannelID: channelID, Failed: 1,
			Errors: map[string]string{channelID: "通知标题与内容不能同时为空"}}
	}

	targets := m.selectTargets(channelID)
	res := SendResult{ChannelID: channelID, Errors: map[string]string{}}
	if channelID != "" && len(targets) == 0 {
		res.Failed = 1
		res.Errors[channelID] = "渠道不存在或未启用"
		return res
	}
	for _, ch := range targets {
		if err := m.sendOne(ctx, ch, ev); err != nil {
			res.Failed++
			res.Errors[ch.ID] = err.Error()
			m.logger.Warn("通知发送失败", "channel", ch.ID, "err", err)
		} else {
			res.Sent++
		}
	}
	return res
}

// selectTargets 选出要发送的渠道副本（读锁内拷贝）。
func (m *Manager) selectTargets(channelID string) []Channel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var targets []Channel
	for i := range m.channels {
		ch := m.channels[i]
		if channelID == "" {
			if ch.Enabled {
				targets = append(targets, ch)
			}
		} else if ch.ID == channelID {
			targets = append(targets, ch)
		}
	}
	return targets
}

// sendOne 对单个渠道发送，含重试。
func (m *Manager) sendOne(ctx context.Context, ch Channel, ev Event) error {
	secret, err := m.store.DecryptChannel(&ch)
	if err != nil {
		return fmt.Errorf("凭证解密失败: %w", err)
	}
	sender := m.perTypeSender[ch.Type]
	if sender == nil {
		return fmt.Errorf("不支持的渠道类型: %s", ch.Type)
	}

	var lastErr error
	attempts := m.retries + 1
	for i := 0; i < attempts; i++ {
		if err := sender(ctx, ch, secret, ev); err != nil {
			lastErr = err
			if i < attempts-1 {
				backoff := time.Duration((i+1)*(i+1)) * 200 * time.Millisecond
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			continue
		}
		return nil
	}
	return lastErr
}

// Test 向某渠道发送一条测试事件，仅用于验证配置可用。
func (m *Manager) Test(ctx context.Context, channelID string) SendResult {
	return m.Send(ctx, channelID, Event{
		Title:   "lipanel 测试通知",
		Message: "这是一条来自 lipanel 的测试通知，收到即表示渠道配置可用。",
		Level:   "info",
	})
}

// newID 生成渠道 ID。
func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("ch-%d", time.Now().UnixNano())
	}
	return "ch-" + hex.EncodeToString(b)
}

var _ Notifier = (*Manager)(nil)
