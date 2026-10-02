package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ============================================================================
// 通知渠道持久化（JSON，0600）
// ============================================================================
//
// 渠道配置（含加密后的凭证）落盘到独立文件（-notify-store），
// **不**改动现有 config 结构。文件权限 0600、目录 0700。
//
// 写入用「临时文件 + rename」原子替换，绝不出现半个 JSON。
// 凭证在落盘前已经过 AES-GCM 加密（见 crypto.go），因此文件即使泄露，
// 没有主密钥也无法解密。

var (
	// ErrStoreUnavailable 表示无法加载/保存持久化数据。
	ErrStoreUnavailable = errors.New("notify: 通知渠道存储不可用")
)

// storeFile 是磁盘上的 JSON 结构。
type storeFile struct {
	Version  int       `json:"version"`
	Channels []Channel `json:"channels"`
}

// Store 负责渠道的加载与保存。
type Store struct {
	path   string
	cipher *Cipher
}

// NewStore 构造一个存储。path 为空时只保存在内存（不落盘）。
func NewStore(path string, cipher *Cipher) (*Store, error) {
	return &Store{path: path, cipher: cipher}, nil
}

// Load 从磁盘读取渠道；文件不存在返回空列表（首次启动）。
func (s *Store) Load() ([]Channel, error) {
	if s.path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: 读取 %s 失败: %v", ErrStoreUnavailable, s.path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: 解析 %s 失败: %v", ErrStoreUnavailable, s.path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%w: 存储版本 %d 不被支持", ErrStoreUnavailable, f.Version)
	}
	return f.Channels, nil
}

// Save 把渠道列表原子写入磁盘。
func (s *Store) Save(channels []Channel) error {
	if s.path == "" {
		return nil
	}
	f := storeFile{Version: 1, Channels: channels}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: 序列化失败: %v", ErrStoreUnavailable, err)
	}

	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("%w: 创建目录失败: %v", ErrStoreUnavailable, err)
		}
	}
	// 临时文件 + rename 原子替换。
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("%w: 写临时文件失败: %v", ErrStoreUnavailable, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("%w: 替换存储文件失败: %v", ErrStoreUnavailable, err)
	}
	return nil
}

// EncryptField 对单个明文字段加密（若明文为空串则原样返回空串）。
// 调用方负责：对**新提交的明文**加密；已有密文不再重复加密。
//
// 密码学：未配置主密钥（cipher 为 nil）时，任何需要加密字段的凭证落盘
// 都不被允许 —— 返回 ErrNoCipher。绝不把明文静默落盘。
func (s *Store) EncryptField(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if s.cipher == nil {
		return "", ErrNoCipher
	}
	return s.cipher.Encrypt(plaintext)
}

// EncryptChannel 把渠道内**已提交的明文**凭证全部加密。
// 仅用于新建渠道（全是新明文）；编辑路径由 Manager 的 remapSecret* 逐字段处理。
func (s *Store) EncryptChannel(ch *Channel) error {
	if s.cipher == nil {
		// 任一凭证不为空就要加密：无主密钥则拒绝整个创建，绝不落盘明文。
		if ch.Secret.SMTPPassword != "" || ch.Secret.WebhookURL != "" || ch.Secret.TelegramToken != "" {
			return ErrNoCipher
		}
		return nil
	}
	cred := Credential{}
	for _, k := range []struct {
		newV string
		dst  *string
	}{
		{ch.Secret.SMTPPassword, &cred.SMTPPassword},
		{ch.Secret.WebhookURL, &cred.WebhookURL},
		{ch.Secret.TelegramToken, &cred.TelegramToken},
	} {
		if k.newV != "" {
			v, err := s.EncryptField(k.newV)
			if err != nil {
				return err
			}
			*k.dst = v
		}
	}
	ch.Secret = cred
	return nil
}

// DecryptChannel 解密渠道内加密凭证，返回明文凭证 map。
// 只在**发送/测试发送**时才解密，且解密结果不落盘、不进入审计。
func (s *Store) DecryptChannel(ch *Channel) (map[string]string, error) {
	out := map[string]string{}
	if s.cipher == nil {
		return nil, ErrNoCipher
	}
	if ch.Secret.SMTPPassword != "" {
		v, err := s.cipher.Decrypt(ch.Secret.SMTPPassword)
		if err != nil {
			return nil, err
		}
		out["smtp_password"] = v
	}
	if ch.Secret.WebhookURL != "" {
		v, err := s.cipher.Decrypt(ch.Secret.WebhookURL)
		if err != nil {
			return nil, err
		}
		out["webhook_url"] = v
	}
	if ch.Secret.TelegramToken != "" {
		v, err := s.cipher.Decrypt(ch.Secret.TelegramToken)
		if err != nil {
			return nil, err
		}
		out["telegram_token"] = v
	}
	return out, nil
}

// Public 返回渠道的脱敏视图（绝不含明文凭证）。
func publicChannel(ch *Channel) PublicChannel {
	return PublicChannel{
		ID:             ch.ID,
		Name:           ch.Name,
		Type:           ch.Type,
		Enabled:        ch.Enabled,
		SMTPHost:       ch.SMTPHost,
		SMTPPort:       ch.SMTPPort,
		SMTPUser:       ch.SMTPUser,
		SMTPFrom:       ch.SMTPFrom,
		Receivers:      ch.Receivers,
		SMTPUseTLS:     ch.SMTPUseTLS,
		TelegramChatID: ch.TelegramChatID,
		HasSecret:      ch.Secret.SMTPPassword != "" || ch.Secret.WebhookURL != "" || ch.Secret.TelegramToken != "",
		CreatedAt:      ch.CreatedAt,
		UpdatedAt:      ch.UpdatedAt,
	}
}

// PublicChannelOf 返回单个渠道的脱敏视图（供接口层在 Write 后直接返回）。
func PublicChannelOf(ch Channel) PublicChannel {
	return publicChannel(&ch)
}
