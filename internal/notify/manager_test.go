package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testMaster = "test-master-secret-for-notify-0123456789"

// newTestManager 构造一个可配置的 Manager（临时存储 + 注入的发送器）。
func newTestManager(t *testing.T, opts func(*NotifyOptions)) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "notify.json")
	o := NotifyOptions{
		MasterSecret: testMaster,
		StorePath:    storePath,
		SendTimeout:  3 * time.Second,
		RetryTimes:   1,
	}
	if opts != nil {
		opts(&o)
	}
	m, err := New(o)
	if err != nil {
		t.Fatalf("构造 Manager 失败: %v", err)
	}
	return m, storePath
}

// setSender 给某类型注入一个测试发送器，并返回一个计数器。
func setSender(m *Manager, tp ChannelType, fn Sender) *atomic.Int32 {
	var calls atomic.Int32
	m.mu.Lock()
	if fn != nil {
		base := fn
		m.perTypeSender[tp] = func(ctx context.Context, ch Channel, s map[string]string, ev Event) error {
			calls.Add(1)
			return base(ctx, ch, s, ev)
		}
	} else {
		m.perTypeSender[tp] = func(ctx context.Context, ch Channel, s map[string]string, ev Event) error {
			calls.Add(1)
			return nil
		}
	}
	m.mu.Unlock()
	return &calls
}

func mkDingTalkInput(webhook string) ChannelInput {
	return ChannelInput{
		Name: "测试钉钉", Type: TypeDingTalk, Enabled: true,
		WebhookURL: webhook,
	}
}

// ---------------------------------------------------------------------------
// 凭证加密、脱敏、持久化、不泄露
// ---------------------------------------------------------------------------

func TestManagerEncryptsAndRedactsCredential(t *testing.T) {
	m, storePath := newTestManager(t, nil)
	ch, err := m.Create(mkDingTalkInput("https://oapi.dingtalk.com/send?access_token=TOPSECRETTOKEN"))
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	// 磁盘上不应含明文 token。
	data, _ := os.ReadFile(storePath)
	if strings.Contains(string(data), "TOPSECRETTOKEN") {
		t.Error("凭证不应以明文落盘")
	}
	// 列表脱敏：不应含明文 token。
	pub := m.List()
	if len(pub) != 1 {
		t.Fatalf("应有 1 个渠道, got %d", len(pub))
	}
	if strings.Contains(jsonString(pub), "TOPSECRETTOKEN") {
		t.Error("脱敏视图不应含明文 token")
	}
	if !pub[0].HasSecret {
		t.Error("应该报告 has_secret=true")
	}
	// 内部渠道的 Secret 应是密文（带前缀）。
	inner, _ := m.findChannelLocked(ch.ID)
	if !strings.HasPrefix(inner.Secret.WebhookURL, ciphertextPrefix) {
		t.Error("内部渠道 webhook 应为密文")
	}
	// 解密能还原明文（发送路径）。
	sec, err := m.store.DecryptChannel(&inner)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if sec["webhook_url"] != "https://oapi.dingtalk.com/send?access_token=TOPSECRETTOKEN" {
		t.Error("解密应还原原始 webhook")
	}
}

func TestManagerPersistsAcrossRestart(t *testing.T) {
	m, storePath := newTestManager(t, nil)
	if _, err := m.Create(mkDingTalkInput("https://example.com/webhook?token=ABC")); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 用同样的主密钥重新构造（模拟重启）。
	m2, err := New(NotifyOptions{MasterSecret: testMaster, StorePath: storePath})
	if err != nil {
		t.Fatalf("重启构造失败: %v", err)
	}
	if len(m2.List()) != 1 {
		t.Fatalf("重启后应有 1 个渠道, got %d", len(m2.List()))
	}
	// 且能解密（密钥一致）。
	inner, _ := m2.findChannelLocked(m2.List()[0].ID)
	sec, err := m2.store.DecryptChannel(&inner)
	if err != nil || sec["webhook_url"] == "" {
		t.Errorf("重启后应能解密凭证: err=%v", err)
	}
}

func TestStoreRejectsChangedMasterSecret(t *testing.T) {
	m, storePath := newTestManager(t, nil)
	if _, err := m.Create(mkDingTalkInput("https://example.com/h?token=SECRET")); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	// 用不同的主密钥重新构造 → 解密应失败。
	m2, err := New(NotifyOptions{MasterSecret: testMaster + "-changed", StorePath: storePath})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	inner, ok := m2.findChannelLocked(m2.List()[0].ID)
	if !ok {
		t.Fatal("渠道应还在")
	}
	if _, err := m2.store.DecryptChannel(&inner); err == nil {
		t.Error("主密钥改变后解密应失败")
	}
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func TestManagerCRUD(t *testing.T) {
	m, _ := newTestManager(t, nil)
	ch, err := m.Create(mkDingTalkInput("https://example.com/send?token=SEC"))
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	// 改名字。
	upd := mkDingTalkInput("https://example.com/send?token=NEWTOKEN")
	upd.Name = "改名钉钉"
	got, err := m.Update(ch.ID, upd)
	if err != nil {
		t.Fatalf("Update 失败: %v", err)
	}
	if got.Name != "改名钉钉" {
		t.Errorf("更新后名称不符: %q", got.Name)
	}
	// webhook 被新 token 覆盖。
	inner, _ := m.findChannelLocked(ch.ID)
	sec, _ := m.store.DecryptChannel(&inner)
	if sec["webhook_url"] != "https://example.com/send?token=NEWTOKEN" {
		t.Errorf("webhook 应被更新: %q", sec["webhook_url"])
	}
	// 删除。
	if err := m.Delete(ch.ID); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if len(m.List()) != 0 {
		t.Error("删除后列表应为空")
	}
	// 删除不存在的报错。
	if err := m.Delete("nope"); err == nil {
		t.Error("删除不存在渠道应报错")
	}
}

func TestUpdateBlankSecretKeepsOld(t *testing.T) {
	m, _ := newTestManager(t, nil)
	ch, _ := m.Create(mkDingTalkInput("https://example.com/send?token=ORIGINAL"))
	// 编辑时 webhook_url 为空串 = 不改动。
	in := mkDingTalkInput("")
	in.Name = "改名"
	in.Enabled = false
	_, err := m.Update(ch.ID, in)
	if err != nil {
		t.Fatalf("Update 失败: %v", err)
	}
	inner, _ := m.findChannelLocked(ch.ID)
	sec, _ := m.store.DecryptChannel(&inner)
	if sec["webhook_url"] != "https://example.com/send?token=ORIGINAL" {
		t.Errorf("空 webhook 应保留旧值: %q", sec["webhook_url"])
	}
}

// ---------------------------------------------------------------------------
// 发送（mock HTTP server）+ 重试
// ---------------------------------------------------------------------------

func TestSendDingTalkHTTP(t *testing.T) {
	var received string
	var status atomic.Int32
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		received = string(buf[:n])
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	m, _ := newTestManager(t, nil)
	calls := setSender(m, TypeDingTalk, sendDingTalk)
	ch, _ := m.Create(mkDingTalkInput(srv.URL + "/robot/send?access_token=TOKEN"))

	res := m.Send(context.Background(), ch.ID, Event{Title: "磁盘告警", Message: "超过 90%"})
	if res.Sent != 1 || res.Failed != 0 {
		t.Fatalf("应发送成功: %+v", res)
	}
	if calls.Load() != 1 {
		t.Errorf("应调用发送 1 次, got %d", calls.Load())
	}
	// 请求体是钉钉格式，且含标题与正文。
	var body struct {
		MsgType string `json:"msgtype"`
		Text    struct {
			Content string `json:"content"`
		} `json:"text"`
	}
	if err := json.Unmarshal([]byte(received), &body); err != nil {
		t.Fatalf("请求体应合法 JSON: %v", err)
	}
	if body.MsgType != "text" || !strings.Contains(body.Text.Content, "磁盘告警") {
		t.Errorf("钉钉请求体不符: %+v", body)
	}
	// 凭证不进入请求体（access_token 在 query 里，不在 body）。
	if strings.Contains(received, "TOKEN") {
		t.Error("请求体不应泄露明文 token")
	}
}

func TestSendTelegram(t *testing.T) {
	var received string
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		received = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// 把 Telegram API 基址指向本地 mock server。
	oldBase := telegramAPIBase
	telegramAPIBase = srv.URL
	defer func() { telegramAPIBase = oldBase }()

	m, _ := newTestManager(t, nil)
	ch, err := m.Create(ChannelInput{
		Name: "TG", Type: TypeTelegram, Enabled: true,
		TelegramToken: "123456:ABC-secret", TelegramChatID: "-100123456",
	})
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	res := m.Send(context.Background(), ch.ID, Event{Title: "hello"})
	if res.Sent != 1 || calls.Load() == 0 {
		t.Fatalf("应成功发送到 mock: %+v calls=%d", res, calls.Load())
	}
	var body struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal([]byte(received), &body); err != nil {
		t.Fatalf("请求体应合法 JSON: %v (%q)", err, received)
	}
	if body.ChatID != "-100123456" || body.Text != "hello" {
		t.Errorf("Telegram 请求体不符: %+v", body)
	}
	// token 不应出现在请求体中（token 在 URL path 里）。
	if strings.Contains(received, "ABC-secret") {
		t.Error("请求体不应泄露 token")
	}
}

func TestSendRetriesThenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	m, _ := newTestManager(t, nil)
	m.retries = 2 // 最多 3 次尝试
	calls := setSender(m, TypeDingTalk, sendDingTalk)

	ch, _ := m.Create(mkDingTalkInput(srv.URL))
	res := m.Send(context.Background(), ch.ID, Event{Title: "x"})
	if res.Failed != 1 || res.Sent != 0 {
		t.Fatalf("应失败: %+v", res)
	}
	if calls.Load() != 3 {
		t.Errorf("应重试共 3 次尝试, got %d", calls.Load())
	}
	// 真实错误来自 mock 的 HTTP 500。
	if !strings.Contains(res.Errors[ch.ID], "500") {
		t.Errorf("错误应含 HTTP 500: %q", res.Errors[ch.ID])
	}
}

type httpMockErr struct{ code int }

func (e *httpMockErr) Error() string { return "http error " + string(rune('0'+e.code)) }

// jsonString 序列化便于断言不含敏感串。
func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
