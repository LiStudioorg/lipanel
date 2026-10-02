// Package notify 提供通知渠道能力（阶段五 5.4.2，核心自带）。
//
// 支持四类渠道：邮件（SMTP）、钉钉 webhook、企业微信 webhook、Telegram Bot。
// 提供统一的 Notifier.Send(ctx, event) 接口给其它模块调用。
//
// #################### 凭证加密（安全边界） ####################
//
// 各渠道的敏感字段（SMTP 密码、webhook 内嵌的 token、Telegram bot token）
// 绝不明文存储：它们用 AES-256-GCM 加密后落盘。
//
// 加密密钥的派生方式（用户明确要求，不使用简单哈希）：
//
//	IKM  = auth.jwt_secret（已在配置文件里持久化的高熵随机串）
//	salt = nil
//	info = "lipanel-notify-v1"
//	输出 32 字节 → AES-256-GCM 密钥
//
// 这样即使 jwt_secret 泄露，攻击者也无法直接推出加密密钥（HKDF 的
// 密码学隔离：同一份 IKM 派生出用途不同的密钥），同时两个用途
// （JWT 签名、凭证加密）互不牵连。将来换用途时用不同的 info
// 派生不同密钥即可（如 "lipanel-notify-v2"）。
//
// HKDF 来自 golang.org/x/crypto/hkdf，属于已依赖的 golang.org/x/crypto
// 模块的子包，不算新增依赖。
package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// encryptionInfo 是 HKDF 的用途标签。换用途时改这里（并触发存量重加密）。
const encryptionInfo = "lipanel-notify-v1"

// ciphertextPrefix 标记已加密的密文字符串，便于区分"明文"与"密文"。
// 兼容性：新写入的敏感字段一律加密；读取时若发现未带前缀的老数据，
// 视为已泄露（历史遗留），由上层决定是否拒绝使用并提示重填。
const ciphertextPrefix = "enc:v1:"

// deriveKey 用 HKDF-SHA256 从 IKM 派生 32 字节 AES-256-GCM 密钥。
// info 是用途标签——不同用途（不同 info）派生出的密钥互不相同，
// 这是密码学意义上的用途隔离（用户明确要求，而非简单的哈希）。
func deriveKey(ikm []byte, info string) ([]byte, error) {
	if len(ikm) < 16 {
		return nil, errors.New("notify: 派生加密密钥的 IKM 过短（至少 16 字节）")
	}
	// HKDF-Extract: PRK = HMAC-SHA256(salt=nil, IKM)
	// HKDF-Expand: OKM = HKDF-Expand(PRK, info, L=32)
	reader := hkdf.New(sha256.New, ikm, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("notify: HKDF 派生密钥失败: %w", err)
	}
	return key, nil
}

// Cipher 封装加解密能力。持有派生出的密钥。
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher 从主密钥（jwt_secret 的字节）构造 Cipher，使用默认用途标签。
func NewCipher(masterSecret []byte) (*Cipher, error) {
	return newCipherWithInfo(masterSecret, encryptionInfo)
}

// newCipherWithInfo 用指定用途标签派生密钥并构造 Cipher。
// 单独抽出便于测试「不同 info 派生出不同密钥」的用途隔离语义。
func newCipherWithInfo(masterSecret []byte, info string) (*Cipher, error) {
	key, err := deriveKey(masterSecret, info)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("notify: 初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("notify: 初始化 GCM 失败: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt 加密一段明文，返回 base64 编码、带前缀的密文。
// 附带认证标签：任何篡改（含密文被替换成其它合法密文）都会在
// Decrypt 时被拒绝。
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("notify: 生成随机 nonce 失败: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertextPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt 解密带前缀的密文，还原明文。空串或未带前缀的输入：
//   - 空串 → 返回 ""，nil（视为"没有该字段"）。
//   - 未带前缀且非空 → 返回错误（明文泄露的老数据，上层应拒绝使用）。
func (c *Cipher) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !hasPrefix(encoded, ciphertextPrefix) {
		return "", errors.New("notify: 字段以明文存储（缺少加密前缀），视为已泄露，拒绝使用")
	}
	raw := encoded[len(ciphertextPrefix):]
	sealed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("notify: 密文 base64 解码失败: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return "", errors.New("notify: 密文过短")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	plain, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("notify: 解密失败（可能密钥已更换或密文被篡改）: %w", err)
	}
	return string(plain), nil
}

// hasPrefix 避免与 strings.HasPrefix 混淆（这里明确只做精确前缀判断）。
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
