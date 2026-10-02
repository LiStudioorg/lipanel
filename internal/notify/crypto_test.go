package notify

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// HKDF 密钥派生 + AES-GCM 加解密
// ---------------------------------------------------------------------------

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher([]byte("this-is-a-test-master-secret-at-least-16-bytes"))
	if err != nil {
		t.Fatalf("NewCipher 失败: %v", err)
	}
	plain := "s3cret-token-面向HTTPS"
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt 失败: %v", err)
	}
	// 必须带前缀，且不等于明文。
	if !strings.HasPrefix(enc, ciphertextPrefix) {
		t.Errorf("密文应以 %s 开头", ciphertextPrefix)
	}
	if strings.Contains(enc, plain) {
		t.Error("密文不应包含明文")
	}

	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt 失败: %v", err)
	}
	if dec != plain {
		t.Errorf("往返后明文不一致: %q != %q", dec, plain)
	}
}

func TestCipherDifferentNonce(t *testing.T) {
	c, _ := NewCipher([]byte("long-enough-master-secret-for-aes-256"))
	a, _ := c.Encrypt("same")
	b, _ := c.Encrypt("same")
	if a == b {
		t.Error("相同明文两次加密应产生不同密文（随机 nonce）")
	}
}

func TestCipherWrongKeyFails(t *testing.T) {
	c1, _ := NewCipher([]byte("master-secret-key-one-0123456789"))
	c2, _ := NewCipher([]byte("master-secret-key-two-0123456789"))
	enc, _ := c1.Encrypt("secret-payload")
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatal("用错误密钥解密应失败")
	}
}

func TestCipherDerivationSignature(t *testing.T) {
	// 同样的 IKM + info 应派生出同样的密钥（确定性）。
	c1, err1 := NewCipher([]byte("same-ikm-0123456789abcdef"))
	c2, err2 := NewCipher([]byte("same-ikm-0123456789abcdef"))
	if err1 != nil || err2 != nil {
		t.Fatalf("NewCipher 失败: %v %v", err1, err2)
	}
	// 换个 info 派生出的密钥不同（用途隔离）。
	other, err := newCipherWithInfo([]byte("same-ikm-0123456789abcdef"), "lipanel-notify-v2")
	if err != nil {
		t.Fatalf("newCipherWithInfo 失败: %v", err)
	}
	a, _ := c1.Encrypt("x")
	// 用 c2 解 c1 的密文（同密钥）应成功。
	if dec, err := c2.Decrypt(a); err != nil || dec != "x" {
		t.Errorf("同密钥解密应成功: %v %q", err, dec)
	}
	// 用不同 info 的密钥解 c1 的密文应失败（用途隔离的实证）。
	if _, err := other.Decrypt(a); err == nil {
		t.Error("不同 info 派生的密钥解密应失败（用途隔离）")
	}
}

func TestCipherRejectsShortIKM(t *testing.T) {
	if _, err := NewCipher([]byte("short")); err == nil {
		t.Error("过短 IKM 应报错")
	}
}

func TestCipherRejectsPlaintextPrefixedData(t *testing.T) {
	c, _ := NewCipher([]byte("long-enough-master-secret-for-aes-256"))
	// 未带前缀的非空字符串 → 视为明文泄露，拒绝解密。
	if _, err := c.Decrypt("this-is-plain-secret"); err == nil {
		t.Error("未加密的明文历史数据应被拒绝")
	}
	// 空串视为无字段，返回空而非错误。
	dec, err := c.Decrypt("")
	if err != nil || dec != "" {
		t.Errorf("空串应返回空且无错误: %q %v", dec, err)
	}
}

func TestCipherTamperDetected(t *testing.T) {
	c, _ := NewCipher([]byte("long-enough-master-secret-for-aes-256"))
	enc, _ := c.Encrypt("hello")
	// 篡改最后一个字符。
	if enc == "" {
		t.Fatal("enc empty")
	}
	tampered := enc[:len(enc)-1] + "X"
	if _, err := c.Decrypt(tampered); err == nil {
		t.Error("篡改后的密文应被 GCM 认证拒绝")
	}
}
