package notify

import "testing"

// ---------------------------------------------------------------------------
// 输入校验（白名单）
// ---------------------------------------------------------------------------

func TestValidName(t *testing.T) {
	valid := []string{"线上告警", "ops-alert", "告警中心 2024", "A_b.c", "测试-1"}
	for _, s := range valid {
		if !validName(s) {
			t.Errorf("应合法: %q", s)
		}
	}
	invalid := []string{"", "a/bb", "a;rm -rf", "a`b", "abc$def", "a\rb", "a\nb", "x"}
	for _, s := range invalid {
		if len(s) == 1 && s == "x" {
			continue // 单字符合法
		}
		if validName(s) {
			t.Errorf("应非法: %q", s)
		}
	}
}

func TestValidType(t *testing.T) {
	for _, tp := range []ChannelType{TypeSMTP, TypeDingTalk, TypeWeCom, TypeTelegram} {
		if !validType(tp) {
			t.Errorf("合法类型 %s 应通过", tp)
		}
	}
	if validType("sms") {
		t.Error("短信等不支持类型应被拒")
	}
}

func TestValidWebhookURL(t *testing.T) {
	good := []string{
		"https://oapi.dingtalk.com/robot/send?access_token=abc123",
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xyz",
	}
	for _, u := range good {
		if err := validWebhookURL(u); err != nil {
			t.Errorf("应合法 URL: %q (%v)", u, err)
		}
	}
	bad := []string{
		"", "ftp://x/y", "file:///etc/passwd", "unix:///var/run/x",
		"https://", "http://", "http://exa mple.com/x", "https://-bad.com/x",
	}
	for _, u := range bad {
		if err := validWebhookURL(u); err == nil {
			t.Errorf("应非法 URL: %q", u)
		}
	}
}

func TestValidTelegramToken(t *testing.T) {
	if err := validTelegramToken("123456789:AA-abcdefghijk"); err != nil {
		t.Errorf("合法 token 应通过: %v", err)
	}
	for _, bad := range []string{"", "not-a-token", "abc:def", "123456:", "123456:"} {
		if err := validTelegramToken(bad); err == nil {
			t.Errorf("应非法 token: %q", bad)
		}
	}
}

func TestValidTelegramChatID(t *testing.T) {
	if err := validTelegramChatID("-100123456789"); err != nil {
		t.Errorf("合法 chat_id 应通过: %v", err)
	}
	if err := validTelegramChatID("12345"); err != nil {
		t.Errorf("正整数 chat_id 应通过: %v", err)
	}
	for _, bad := range []string{"", "abc", "-abc", "1.5"} {
		if err := validTelegramChatID(bad); err == nil {
			t.Errorf("应非法 chat_id: %q", bad)
		}
	}
}

func TestValidReceivers(t *testing.T) {
	list, err := validReceivers("a@example.com;b@example.com, c@example.com")
	if err != nil || len(list) != 3 {
		t.Errorf("应解析出 3 个收件人: %v %v", list, err)
	}
	if _, err := validReceivers(""); err == nil {
		t.Error("空收件人应报错")
	}
	if _, err := validReceivers("not-an-email"); err == nil {
		t.Error("非法邮箱应报错")
	}
}

func TestValidateChannelInput(t *testing.T) {
	// 合法 SMTP。
	err := validateChannelInput(ChannelInput{
		Name: "告警邮箱", Type: TypeSMTP,
		SMTPHost: "smtp.example.com", SMTPPort: 587,
		SMTPUser: "a@example.com", SMTPPassword: "secret",
		Receivers: "b@example.com",
	})
	if err != nil {
		t.Errorf("合法 SMTP 应通过: %v", err)
	}
	// 非法 host（注入载荷）应被拒。
	err = validateChannelInput(ChannelInput{
		Name: "x", Type: TypeSMTP,
		SMTPHost: "smtp;rm -rf /", SMTPPort: 587,
		SMTPUser: "a@example.com", Receivers: "b@example.com",
	})
	if err == nil {
		t.Error("含注入字符的 host 应被拒")
	}
	// 非法 URL。
	err = validateChannelInput(ChannelInput{Name: "x", Type: TypeDingTalk, WebhookURL: "file:///etc"})
	if err == nil {
		t.Error("文件协议 webhook 应被拒")
	}
	// 不存在的类型。
	err = validateChannelInput(ChannelInput{Name: "x", Type: "sms"})
	if err == nil {
		t.Error("不支持的类型应被拒")
	}
}
