package notify

import (
	"testing"
)

// 未配置主密钥时：创建带凭证的渠道必须被拒绝（ErrNoCipher），绝不落盘明文；
// 创建不带凭证的渠道仍可成功（无需加密）。
func TestNoMasterSecretRejectsSecrets(t *testing.T) {
	m, err := New(NotifyOptions{
		MasterSecret: "", // 不配置主密钥
		StorePath:    t.TempDir() + "/notify.json",
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if m.EncryptionEnabled() {
		t.Fatal("未配置主密钥时加密应不可用")
	}

	// 带 webhook（凭证）→ 拒绝。
	_, err = m.Create(mkDingTalkInput("https://example.com/send?token=SECRET"))
	if err == nil {
		t.Fatal("未配置主密钥时创建带凭证渠道应报错")
	}

	// 不带凭证的渠道（如停用的 SMTP 缺账号会被校验拦，这里用一个无凭证的合法渠道）：
	// SMTP 必须账号，因此用一个留空 webhook 的 dingtalk 构造非法？—— 直接验证
	// EncryptChannel 在没有凭证字段时不报错。
	store := m.store
	c := Channel{Secret: Credential{}}
	if err := store.EncryptChannel(&c); err != nil {
		t.Errorf("无凭证字段时加密不得报错: %v", err)
	}
	// 有凭证字段时报 ErrNoCipher。
	c2 := Channel{Secret: Credential{WebhookURL: "https://example.com/send?token=SECRET"}}
	if err := store.EncryptChannel(&c2); err != ErrNoCipher {
		t.Errorf("应返回 ErrNoCipher, got %v", err)
	}
}

// 正常主密钥下能创建带凭证渠道。
func TestMasterSecretAllowsSecrets(t *testing.T) {
	m, _ := newTestManager(t, nil)
	if !m.EncryptionEnabled() {
		t.Fatal("配置主密钥后加密应可用")
	}
	if _, err := m.Create(mkDingTalkInput("https://example.com/send?token=SECRET")); err != nil {
		t.Fatalf("有主密钥时应能创建: %v", err)
	}
}
