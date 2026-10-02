package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/notify"
)

// ============================================================================
// 通知渠道接口测试（阶段五 5.4.2）
// ============================================================================

// newNotifyServer 构造一个注入了通知管理器的 Server（可测试发送）。
// 用临时存储，不落真实凭证、不外发真实 webhook。
func newNotifyServer(t *testing.T, dir string) *Server {
	t.Helper()
	mgr, err := notify.New(notify.NotifyOptions{
		MasterSecret: "server-test-master-secret-0123456789",
		StorePath:    dir + "/notify.json",
		SendTimeout:  2 * time.Second,
		RetryTimes:   0,
	})
	if err != nil {
		t.Fatalf("构造通知管理器失败: %v", err)
	}
	hash, _ := auth.HashPassword(testPass)
	store, _ := auth.NewMemoryUserStore(testUser, hash)
	authenticator, _ := auth.New(auth.Options{
		Store:  store,
		Secret: []byte("test-secret-at-least-16-bytes-long"),
		TTL:    time.Hour,
	})
	s, err := New(Options{
		Addr:     "127.0.0.1:0",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Auth:     authenticator,
		WebFS:    testFS(),
		WebBuilt: true,
		Notify:   mgr,
	})
	if err != nil {
		t.Fatalf("构造 Server 失败: %v", err)
	}
	return s
}

func TestNotifyEndpointsRequireAuth(t *testing.T) {
	s := newNotifyServer(t, t.TempDir())
	paths := []struct{ method, path string }{
		{"GET", "/api/notify"},
		{"POST", "/api/notify"},
		{"GET", "/api/notify/capabilities"},
		{"POST", "/api/notify/test"},
		{"GET", "/api/notify/audit"},
	}
	for _, tc := range paths {
		rec := doJSON(t, s, tc.method, tc.path, map[string]any{})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未登录状态码 = %d，期望 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestNotifyUnavailableWhenNoManager(t *testing.T) {
	s := newAuthedServerNoLogs(t) // 未注入 Notify
	rec := loginAndDo(t, s, "GET", "/api/notify")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("未注入通知管理器状态码 = %d，期望 503", rec.Code)
	}
}

func TestNotifyCreateListRedact(t *testing.T) {
	dir := t.TempDir()
	s := newNotifyServer(t, dir)
	cookie := login(t, s)

	// 创建钉钉渠道（带 webhook token）。
	rec := doJSON(t, s, "POST", "/api/notify", map[string]any{
		"name": "线上告警", "type": "dingtalk", "enabled": true,
		"webhook_url": "https://oapi.example.com/robot/send?access_token=SUPERSECRETTOKEN",
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("创建渠道状态码 = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Errorf("创建响应应有 has_secret=true: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SUPERSECRETTOKEN") {
		t.Error("创建响应不应泄露明文 token")
	}

	// 列表同样脱敏。
	rec = loginAndDo(t, s, "GET", "/api/notify")
	if rec.Code != http.StatusOK {
		t.Fatalf("列表状态码 = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SUPERSECRETTOKEN") {
		t.Error("列表不应泄露明文 token")
	}
	if !strings.Contains(rec.Body.String(), "线上告警") {
		t.Error("列表应包含渠道名称")
	}

	// 磁盘上也不含明文。
	disk, err := os.ReadFile(dir + "/notify.json")
	if err != nil {
		t.Fatalf("读存储文件失败: %v", err)
	}
	if strings.Contains(string(disk), "SUPERSECRETTOKEN") {
		t.Error("落盘文件不应含明文 token")
	}
}

func TestNotifyInvalidRejected(t *testing.T) {
	s := newNotifyServer(t, t.TempDir())
	cookie := login(t, s)
	// 非法 URL 协议。
	rec := doJSON(t, s, "POST", "/api/notify", map[string]any{
		"name": "x", "type": "dingtalk", "webhook_url": "file:///etc/passwd",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法协议应 400, got %d: %s", rec.Code, rec.Body.String())
	}
	// 不存在的类型。
	rec = doJSON(t, s, "POST", "/api/notify", map[string]any{"name": "x", "type": "sms"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("不支持类型应 400, got %d", rec.Code)
	}
}

func TestNotifyTestSendsToMockAndAudits(t *testing.T) {
	dir := t.TempDir()
	s := newNotifyServer(t, dir)
	cookie := login(t, s)

	// 本地 mock server 充当钉钉 webhook。
	var gotBody string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
	}))
	defer mock.Close()

	// 创建指向 mock 的钉钉渠道。
	rec := doJSON(t, s, "POST", "/api/notify", map[string]any{
		"name": "mock-ding", "type": "dingtalk", "enabled": true,
		"webhook_url": mock.URL,
	}, cookie)
	id := extractJString(rec.Body.String(), "id")
	if id == "" {
		t.Fatalf("创建未返回 id: %s", rec.Body.String())
	}

	// 测试发送。
	rec = doJSON(t, s, "POST", "/api/notify/test?channel="+id, map[string]any{}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("测试发送状态码 = %d: %s", rec.Code, rec.Body.String())
	}
	// mock 收到钉钉格式请求体（含标题）。
	if !strings.Contains(gotBody, "lipanel 测试通知") {
		t.Errorf("mock 应收到测试通知内容: %s", gotBody)
	}

	// 审计里应有 test 动作。
	rec = loginAndDo(t, s, "GET", "/api/notify/audit")
	if !strings.Contains(rec.Body.String(), `"test"`) {
		t.Errorf("审计应含 test 动作: %s", rec.Body.String())
	}
}

// extractJString 从 JSON 里取某字符串字段值（仅测试用）。
func extractJString(body, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
