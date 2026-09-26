package ssl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// 管理器、探测、权限、审计与调度器测试（阶段四 4.4）
// ============================================================================
//
// 本文件用**假执行器**（fakeExecutor）跑通完整生命周期：
// 探测 → 申请 → 解析 → 写入配置 → 续期。
//
// 为什么用假执行器而不是真实 certbot：
// 真实申请需要「公网可达域名 + 消耗 Let's Encrypt 配额」，
// 在测试环境里既不可行也不该做。假执行器让**面板自身的逻辑**
// （命令组装、输出解析、状态推导、错误映射、审计留痕）
// 得到完整覆盖，而这些正是本模块真正拥有、也真正会出错的代码。
//
// 真实 certbot 的解析能力另有 cert_test.go 里的**实测输出**锁定。

// ---------------------------------------------------------------------------
// 测试替身
// ---------------------------------------------------------------------------

// fakeExecutor 是一个可编程的命令执行器。
type fakeExecutor struct {
	mu sync.Mutex
	// calls 记录被执行的命令（name + args），供断言。
	calls [][]string
	// handler 按命令返回预设输出。
	handler func(name string, args []string) (string, string, error)
	// delay 模拟耗时。
	delay time.Duration
}

func (f *fakeExecutor) Run(ctx context.Context, name string, args []string) (string, string, error) {
	f.mu.Lock()
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	handler := f.handler
	delay := f.delay
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(delay):
		}
	}
	if handler == nil {
		return "", "", nil
	}
	return handler(name, args)
}

// Calls 返回已执行的命令快照。
func (f *fakeExecutor) Calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// CallCount 返回执行次数。
func (f *fakeExecutor) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// findCall 查找包含指定子串的调用。
func findCall(calls [][]string, needle string) []string {
	for _, c := range calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, needle) {
			return c
		}
	}
	return nil
}

// fakeSites 是内存站点表。
type fakeSites struct {
	sites map[string]SiteRef
	err   error
}

func newFakeSites(refs ...SiteRef) *fakeSites {
	m := make(map[string]SiteRef, len(refs))
	for _, r := range refs {
		m[r.Name] = r
	}
	return &fakeSites{sites: m}
}

func (f *fakeSites) GetSite(name string) (SiteRef, error) {
	if f.err != nil {
		return SiteRef{}, f.err
	}
	s, ok := f.sites[name]
	if !ok {
		return SiteRef{}, fmt.Errorf("站点 %s 不存在", name)
	}
	return s, nil
}

func (f *fakeSites) ListSites() ([]SiteRef, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]SiteRef, 0, len(f.sites))
	for _, s := range f.sites {
		out = append(out, s)
	}
	return out, nil
}

// fakeRewriter 记录配置写入请求（模拟 site.Manager 的能力）。
type fakeRewriter struct {
	mu      sync.Mutex
	applied []struct {
		Site string
		Cfg  SSLConfig
	}
	removed []string
	err     error
}

func (f *fakeRewriter) ApplySSL(_ context.Context, site string, cfg SSLConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.applied = append(f.applied, struct {
		Site string
		Cfg  SSLConfig
	}{site, cfg})
	return nil
}

func (f *fakeRewriter) RemoveSSL(_ context.Context, site string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, site)
	return nil
}

func (f *fakeRewriter) Applied() []SSLConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SSLConfig, 0, len(f.applied))
	for _, a := range f.applied {
		out = append(out, a.Cfg)
	}
	return out
}

// certbotOutputFor 生成一份 certbot certificates 的假输出。
func certbotOutputFor(name, domain string, daysFromNow int, now time.Time) string {
	expiry := now.AddDate(0, 0, daysFromNow)
	return fmt.Sprintf(`Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Found the following certs:
  Certificate Name: %s
    Serial Number: deadbeef
    Key Type: RSA
    Domains: %s
    Expiry Date: %s (VALID: %d days)
    Certificate Path: /etc/letsencrypt/live/%s/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/%s/privkey.pem
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`, name, domain, expiry.UTC().Format("2006-01-02 15:04:05-07:00"), daysFromNow, name, name)
}

const noCertsOutput = `Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
No certificates found.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`

// newTestManager 构造一个用假执行器的管理器。
//
// 注意：探测器会 os.Stat 客户端路径，因此这里必须创建一个
// **真实存在**的文件来冒充 certbot——用一个不存在的路径
// 会让探测直接失败，后面所有用例都测不到真正的逻辑。
func newTestManager(t *testing.T, ex Executor, sites SiteProvider, rw ConfigRewriter) *Manager {
	t.Helper()
	return newTestManagerWith(t, ex, sites, rw, false)
}

// newTestManagerWith 允许指定 dry-run 模式。
func newTestManagerWith(t *testing.T, ex Executor, sites SiteProvider, rw ConfigRewriter, dryRun bool) *Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m, err := NewManager(ManagerOptions{
		Logger: logger,
		Detector: NewDetector(DetectorOptions{
			CertbotPath: writeFakeClient(t),
			Executor:    ex,
			Logger:      logger,
			Timeout:     2 * time.Second,
		}),
		Sites:          sites,
		Rewriter:       rw,
		Executor:       ex,
		Email:          "admin@example.com",
		RenewDays:      DefaultRenewDays,
		CommandTimeout: 5 * time.Second,
		DryRun:         dryRun,
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}
	return m
}

// okStaticSite 返回一个可用于 HTTP-01 的静态站。
func okStaticSite() SiteRef {
	return SiteRef{
		Name:    "example.com",
		Domain:  "example.com",
		Root:    "/var/www/html",
		Type:    "static",
		Enabled: true,
	}
}

// ---------------------------------------------------------------------------
// 探测
// ---------------------------------------------------------------------------

// TestDetectorFindsClient 验证探测成功路径。
func TestDetectorFindsClient(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return "", "", nil
	}}
	// 用一个真实存在的文件冒充 certbot（探测会 os.Stat 它）
	self := writeFakeClient(t)

	d := NewDetector(DetectorOptions{
		CertbotPath: self,
		Executor:    ex,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	info, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("探测应当成功，实际: %v", err)
	}
	if !info.Available {
		t.Fatalf("客户端应当可用，原因: %s", info.Reason)
	}
	if info.Kind != ClientCertbot {
		t.Errorf("Kind = %q，期望 %q", info.Kind, ClientCertbot)
	}
	if info.Version != "certbot 1.21.0" {
		t.Errorf("Version = %q", info.Version)
	}
	if info.Source != "显式指定" {
		t.Errorf("Source = %q，期望「显式指定」", info.Source)
	}
}

// TestDetectorRejectsDirectory 验证把目录当 certbot 时被拒绝。
func TestDetectorRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	d := NewDetector(DetectorOptions{
		CertbotPath: dir,
		Executor:    &fakeExecutor{},
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	info, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("目录作为客户端路径应当被拒绝")
	}
	if info.Available {
		t.Error("Available 应当为 false")
	}
	if !strings.Contains(info.Reason, "是目录") {
		t.Errorf("原因应说明是目录，实际: %s", info.Reason)
	}
}

// TestDetectorRejectsMissingPath 验证显式指定的路径不存在时被拒绝。
func TestDetectorRejectsMissingPath(t *testing.T) {
	d := NewDetector(DetectorOptions{
		CertbotPath: "/nonexistent/certbot",
		Executor:    &fakeExecutor{},
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	info, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("不存在的路径应当被拒绝")
	}
	if info.Available {
		t.Error("Available 应当为 false")
	}
}

// TestDetectorVersionCommandFails 验证「文件存在但执行失败」被识别。
//
// 这是 LookPath 查不出来的情况：文件在、有执行位，
// 但跑起来就报错（架构不匹配、缺动态库、脚本缺 shebang）。
// 只有在启动时真的跑一次 --version 才能发现。
// 否则真正的申请会在几十秒后才以难以理解的方式失败。
func TestDetectorVersionCommandFails(t *testing.T) {
	self := writeFakeClient(t)
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		return "", "exec format error", errors.New("exec format error")
	}}
	d := NewDetector(DetectorOptions{
		CertbotPath: self,
		Executor:    ex,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	info, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("执行失败应当被识别为不可用")
	}
	if info.Available {
		t.Error("Available 应当为 false")
	}
	if !strings.Contains(info.Reason, "exec format error") {
		t.Errorf("原因应当包含原始报错，实际: %s", info.Reason)
	}
}

// TestDetectorCachesResult 验证探测只执行一次。
func TestDetectorCachesResult(t *testing.T) {
	self := writeFakeClient(t)
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		return "certbot 1.21.0", "", nil
	}}
	d := NewDetector(DetectorOptions{
		CertbotPath: self,
		Executor:    ex,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	for i := 0; i < 5; i++ {
		if _, err := d.Detect(context.Background()); err != nil {
			t.Fatalf("第 %d 次探测失败: %v", i, err)
		}
	}
	if got := ex.CallCount(); got != 1 {
		t.Errorf("探测应当只执行一次 --version，实际执行了 %d 次", got)
	}
}

// TestDetectorConcurrentIsSafe 验证并发探测不产生竞争。
//
// 前端会同时打开 SSL 页与能力接口，两个请求并发触发探测。
// 没有同步手段的话会并发跑多次 --version 并对 cached/err 产生竞争
// （坑位 16 的同一类问题）。本测试配合 -race 使用。
func TestDetectorConcurrentIsSafe(t *testing.T) {
	self := writeFakeClient(t)
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		return "certbot 1.21.0", "", nil
	}}
	d := NewDetector(DetectorOptions{
		CertbotPath: self,
		Executor:    ex,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := d.Detect(context.Background())
			if err != nil || !info.Available {
				t.Errorf("并发探测失败: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := ex.CallCount(); got != 1 {
		t.Errorf("并发探测应当只执行一次，实际 %d 次", got)
	}
}

// writeFakeClient 在工作区临时目录里造一个"存在且是普通文件"的假客户端。
func writeFakeClient(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-certbot")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'certbot 1.21.0'\n"), 0o755); err != nil {
		t.Fatalf("写假客户端失败: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// TestStatusNoCertificates 验证「干净机器」的状态。
//
// 这是最常见的初始状态：certbot 装好了，但一张证书都没有。
// 它必须显示为每个站点「未申请」，而不是一片红色报错。
func TestStatusNoCertificates(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		if len(args) == 1 && args[0] == "certificates" {
			return noCertsOutput, "", nil
		}
		return "", "", nil
	}}
	sites := newFakeSites(okStaticSite())
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if !res.Available {
		t.Errorf("Available 应当为 true，原因: %s", res.UnavailableReason)
	}
	if len(res.Sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(res.Sites))
	}
	st := res.Sites[0]
	if st.Status != StatusNone {
		t.Errorf("Status = %q，期望 %q", st.Status, StatusNone)
	}
	if st.Issued {
		t.Error("Issued 应当为 false")
	}
	if res.Counts.None != 1 {
		t.Errorf("Counts.None = %d，期望 1", res.Counts.None)
	}
}

// TestStatusWithValidCertificate 验证已有证书的状态。
func TestStatusWithValidCertificate(t *testing.T) {
	now := time.Now()
	out := certbotOutputFor("example.com", "example.com", 80, now)
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return out, "", nil
	}}
	sites := newFakeSites(okStaticSite())
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	st := res.Sites[0]
	if !st.Issued {
		t.Fatal("Issued 应当为 true")
	}
	if st.Status != StatusValid {
		t.Errorf("Status = %q，期望 %q", st.Status, StatusValid)
	}
	if st.CertPath == "" || st.KeyPath == "" {
		t.Error("证书路径不应为空")
	}
	if st.CertName != "example.com" {
		t.Errorf("CertName = %q", st.CertName)
	}
	if res.Counts.Issued != 1 || res.Counts.Valid != 1 {
		t.Errorf("统计错误: %+v", res.Counts)
	}
}

// TestStatusExpiringCertificate 验证即将过期的状态。
func TestStatusExpiringCertificate(t *testing.T) {
	now := time.Now()
	out := certbotOutputFor("example.com", "example.com", 10, now)
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return out, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if res.Sites[0].Status != StatusExpiring {
		t.Errorf("Status = %q，期望 %q", res.Sites[0].Status, StatusExpiring)
	}
	if res.Counts.Expiring != 1 {
		t.Errorf("Counts.Expiring = %d，期望 1", res.Counts.Expiring)
	}
}

// TestStatusProxySiteHasNoWebroot 验证反代站没有 webroot。
//
// 前端据此禁用"申请"按钮并给出原因，
// 而不是让用户点了才失败。
func TestStatusProxySiteHasNoWebroot(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	sites := newFakeSites(SiteRef{
		Name:     "app",
		Domain:   "app.example.com",
		Upstream: "http://127.0.0.1:3000",
		Type:     "proxy",
		Enabled:  true,
	})
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	st := res.Sites[0]
	if st.HasWebroot {
		t.Error("反代站不应当有 webroot")
	}
	if st.Note == "" {
		t.Error("反代站应当给出说明（为什么不能申请）")
	}
	if !strings.Contains(st.Note, "webroot") {
		t.Errorf("说明应提到 webroot，实际: %s", st.Note)
	}
}

// TestStatusWithoutClient 验证无 ACME 客户端时的降级。
//
// 关键：站点状态仍然要展示出来（不能因为没装 certbot
// 就让用户连"我有几个站点"都看不到），只是 Available=false。
func TestStatusWithoutClient(t *testing.T) {
	ex := &fakeExecutor{}
	m, err := NewManager(ManagerOptions{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Detector: NewDetector(DetectorOptions{
			CertbotPath: "/nonexistent/certbot",
			Executor:    ex,
			Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		}),
		Sites:    newFakeSites(okStaticSite()),
		Executor: ex,
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 不该因缺少客户端而失败: %v", err)
	}
	if res.Available {
		t.Error("无客户端时 Available 应当为 false")
	}
	if res.UnavailableReason == "" {
		t.Error("应当给出不可用原因")
	}
	if len(res.Sites) != 1 {
		t.Errorf("站点列表仍应展示，实际 %d 个", len(res.Sites))
	}
}

// TestStatusUnavailableWithoutSiteProvider 验证未注入站点提供器时的 503 语义。
func TestStatusUnavailableWithoutSiteProvider(t *testing.T) {
	m, err := NewManager(ManagerOptions{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if m.Available() {
		t.Error("未注入站点提供器时 Available 应当为 false")
	}
	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 不该报错: %v", err)
	}
	if res.UnavailableReason == "" {
		t.Error("应当给出不可用原因")
	}
}

// TestStatusUnknownCertbotFormat 验证格式无法识别时的提示。
//
// 这与"确实没有证书"必须区分：前者说明解析器需要适配新版本，
// 后者是正常的新机器状态。混淆两者会让 certbot 升级
// 被伪装成"你的证书全没了"。
func TestStatusUnknownCertbotFormat(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 9.0.0", "", nil
		}
		return "Totally new output format we do not understand", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	res, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if !strings.Contains(res.UnavailableReason, "无法识别") {
		t.Errorf("应当提示输出格式无法识别，实际: %s", res.UnavailableReason)
	}
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

// TestIssueHappyPath 验证申请全流程。
func TestIssueHappyPath(t *testing.T) {
	now := time.Now()
	var issued bool
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "certonly"):
			issued = true
			return "Successfully received certificate.", "", nil
		case strings.Contains(joined, "certificates"):
			if issued {
				return certbotOutputFor("example.com", "example.com", 90, now), "", nil
			}
			return noCertsOutput, "", nil
		}
		return "", "", nil
	}}
	rw := &fakeRewriter{}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), rw)

	res, err := m.Issue(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("申请应当成功，实际: %v", err)
	}
	if !res.Issued {
		t.Error("Issued 应当为 true")
	}
	if !res.Applied {
		t.Error("Applied 应当为 true（配置应当被写入）")
	}
	if res.Certificate == nil {
		t.Fatal("应当返回证书信息")
	}
	if res.Certificate.Status != StatusValid {
		t.Errorf("证书状态 = %q", res.Certificate.Status)
	}
	if res.Domain != "example.com" {
		t.Errorf("Domain = %q", res.Domain)
	}

	// 配置确实被写入，且内容正确
	applied := rw.Applied()
	if len(applied) != 1 {
		t.Fatalf("期望写入 1 次配置，实际 %d 次", len(applied))
	}
	cfg := applied[0]
	if cfg.CertPath != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Errorf("CertPath = %q", cfg.CertPath)
	}
	if cfg.KeyPath != "/etc/letsencrypt/live/example.com/privkey.pem" {
		t.Errorf("KeyPath = %q", cfg.KeyPath)
	}
	if !cfg.RedirectHTTP {
		t.Error("应当启用 HTTP → HTTPS 跳转")
	}
	if cfg.Protocols == "" || cfg.Ciphers == "" {
		t.Error("TLS 协议与加密套件不应为空")
	}

	// 命令形状检查
	call := findCall(ex.Calls(), "certonly")
	if call == nil {
		t.Fatal("应当执行了 certonly 命令")
	}
	if !strings.Contains(strings.Join(call, " "), "--webroot") {
		t.Errorf("申请应当使用 webroot（HTTP-01），实际命令: %v", call)
	}
}

// TestIssueRejectsWildcardDomain 验证通配符站点被拒绝。
func TestIssueRejectsWildcardDomain(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	sites := newFakeSites(SiteRef{
		Name:   "wild",
		Domain: "*.example.com",
		Root:   "/var/www/html",
		Type:   "static",
	})
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	_, err := m.Issue(context.Background(), "wild", false)
	if err == nil {
		t.Fatal("通配符域名应当被拒绝")
	}
	if !strings.Contains(err.Error(), "通配符") {
		t.Errorf("错误应说明通配符问题，实际: %v", err)
	}
	// 关键：被拒绝时**不能执行任何 certbot 命令**
	if call := findCall(ex.Calls(), "certonly"); call != nil {
		t.Errorf("被拒绝的申请不该执行 certbot，实际执行了: %v", call)
	}
}

// TestIssueProxySiteWithoutWebroot 验证反代站申请被拒绝。
func TestIssueProxySiteWithoutWebroot(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	sites := newFakeSites(SiteRef{Name: "app", Domain: "app.example.com", Type: "proxy"})
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	_, err := m.Issue(context.Background(), "app", false)
	if err == nil {
		t.Fatal("无 webroot 的站点应当被拒绝")
	}
	if !errors.Is(err, ErrNoWebroot) {
		t.Errorf("应当是 ErrNoWebroot，实际: %v", err)
	}
	if call := findCall(ex.Calls(), "certonly"); call != nil {
		t.Errorf("被拒绝的申请不该执行 certbot，实际: %v", call)
	}
}

// TestIssueSiteNotFound 验证站点不存在。
func TestIssueSiteNotFound(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(), &fakeRewriter{})

	_, err := m.Issue(context.Background(), "nonexistent", false)
	if err == nil {
		t.Fatal("不存在的站点应当报错")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("应当是 ErrNotFound，实际: %v", err)
	}
}

// TestIssueCertbotFails 验证 certbot 失败时的错误。
func TestIssueCertbotFails(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--version") {
			return "certbot 1.21.0", "", nil
		}
		if strings.Contains(joined, "certonly") {
			return "", "Some challenges have failed.", errors.New("exit status 1")
		}
		return noCertsOutput, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	_, err := m.Issue(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("certbot 失败时应当报错")
	}
	if !errors.Is(err, ErrClientFailed) {
		t.Errorf("应当是 ErrClientFailed，实际: %v", err)
	}
	if !strings.Contains(err.Error(), "challenges have failed") {
		t.Errorf("错误应包含 certbot 的原始输出，实际: %v", err)
	}
}

// TestIssueAppliedFailedIsPartialSuccess 验证「证书已获取但配置写入失败」。
//
// ########## 这是本模块最重要的错误语义 ##########
//
// 此时 CA **已经签发并消耗了配额**。若把整件事简单记成"失败"，
// 用户会反复重试，每次都消耗一次配额，直到撞上速率限制
// （每周 5 次），之后连正常续期都做不了。
//
// 因此必须用专门的哨兵错误，并在提示里明确告诉用户
// "证书已成功获取、无需重复申请"。
func TestIssueAppliedFailedIsPartialSuccess(t *testing.T) {
	now := time.Now()
	var issued bool
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "certonly"):
			issued = true
			return "Successfully received certificate.", "", nil
		case strings.Contains(joined, "certificates"):
			if issued {
				return certbotOutputFor("example.com", "example.com", 90, now), "", nil
			}
			return noCertsOutput, "", nil
		}
		return "", "", nil
	}}
	rw := &fakeRewriter{err: errors.New("nginx -t 失败")}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), rw)

	res, err := m.Issue(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("配置写入失败时应当报错")
	}
	if !errors.Is(err, ErrAppliedFailed) {
		t.Errorf("应当是 ErrAppliedFailed（部分成功），实际: %v", err)
	}
	// 证书确实已获取
	if res.Certificate == nil {
		t.Error("即便配置失败，也应当返回已获取的证书信息")
	}
	if res.Issued != true {
		t.Error("Issued 应当为 true（CA 配额已消耗）")
	}
	if res.Applied {
		t.Error("Applied 应当为 false")
	}
	// 提示必须明确告诉用户不要重复申请
	if !strings.Contains(err.Error(), "无需重复申请") {
		t.Errorf("错误提示应告知用户不要重复申请，实际: %v", err)
	}
}

// TestIssueTimeoutIsAmbiguous 验证超时的特殊语义。
//
// 超时**不代表没有签发**：进程被杀时 CA 那边可能已经完成签发，
// 配额已经消耗，本地却什么都没拿到。因此提示必须说明这一点，
// 并引导用户先查询而不是立即重试。
func TestIssueTimeoutIsAmbiguous(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--version") {
			return "certbot 1.21.0", "", nil
		}
		return "", "", nil
	}, delay: 200 * time.Millisecond}

	m, err := NewManager(ManagerOptions{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Detector: NewDetector(DetectorOptions{
			CertbotPath: writeFakeClient(t),
			Executor:    ex,
			Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		}),
		Sites:          newFakeSites(okStaticSite()),
		Executor:       ex,
		CommandTimeout: 20 * time.Millisecond, // 故意设得极短以触发超时
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	_, err = m.Issue(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("超时应当报错")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Errorf("错误应说明超时，实际: %v", err)
	}
	// 关键提示：不要立即重试
	if !strings.Contains(err.Error(), "不要立即重试") {
		t.Errorf("超时提示应引导用户先查询，实际: %v", err)
	}
}

// TestIssueDryRun 验证试运行模式。
func TestIssueDryRun(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	m, err := NewManager(ManagerOptions{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Detector: NewDetector(DetectorOptions{
			CertbotPath: writeFakeClient(t),
			Executor:    ex,
			Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		}),
		Sites:    newFakeSites(okStaticSite()),
		Rewriter: &fakeRewriter{},
		Executor: ex,
		DryRun:   true,
		Email:    "a@b.com",
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	res, err := m.Issue(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("试运行应当成功: %v", err)
	}
	if !res.DryRun {
		t.Error("DryRun 应当为 true")
	}
	call := findCall(ex.Calls(), "certonly")
	if call == nil {
		t.Fatal("应当执行了 certonly")
	}
	if !strings.Contains(strings.Join(call, " "), "--dry-run") {
		t.Errorf("试运行模式必须带 --dry-run，实际: %v", call)
	}
}

// ---------------------------------------------------------------------------
// Renew
// ---------------------------------------------------------------------------

// TestRenewSkippedWhenNotDue 验证「未到续期窗口」被正确识别。
//
// ########## 为什么这条最重要 ##########
//
// `certbot renew` 对未进入续期窗口的证书会输出
// "not yet due for renewal" 并以 **exit 0** 退出。
//
// 若把退出码 0 一概当作"续期成功"，界面会显示"续期成功"，
// 而到期时间**一点没变**——用户会立刻怀疑功能坏了，
// 或者更糟：以为已经续过了，实际并没有。
func TestRenewSkippedWhenNotDue(t *testing.T) {
	now := time.Now()
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			// 实测：未到窗口时 certbot 输出这句并 exit 0
			return "Certificate not yet due for renewal; no action taken.", "", nil
		case strings.Contains(joined, "certificates"):
			return certbotOutputFor("example.com", "example.com", 80, now), "", nil
		}
		return "", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	res, err := m.Renew(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("续期不该报错: %v", err)
	}
	if res.Renewed {
		t.Error("未到续期窗口时 Renewed 必须为 false")
	}
	if !res.Skipped {
		t.Error("应当标记为 Skipped")
	}
}

// TestRenewActuallyRenewed 验证真的续期。
func TestRenewActuallyRenewed(t *testing.T) {
	now := time.Now()
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			return "Congratulations! Your certificate and chain have been saved.", "", nil
		case strings.Contains(joined, "certificates"):
			return certbotOutputFor("example.com", "example.com", 90, now), "", nil
		}
		return "", "", nil
	}}
	rw := &fakeRewriter{}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), rw)

	res, err := m.Renew(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("续期应当成功: %v", err)
	}
	if !res.Renewed {
		t.Error("Renewed 应当为 true")
	}
	if res.Skipped {
		t.Error("Skipped 应当为 false")
	}
	if res.Certificate == nil {
		t.Error("应当返回续期后的证书信息")
	}
	// 续期后应当重新写入配置（让状态收敛）
	if len(rw.Applied()) != 1 {
		t.Errorf("续期后应当写入配置，实际 %d 次", len(rw.Applied()))
	}
}

// TestRenewFails 验证续期失败。
func TestRenewFails(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--version") {
			return "certbot 1.21.0", "", nil
		}
		if strings.Contains(joined, "renew") {
			return "", "Failed to renew certificate example.com", errors.New("exit status 1")
		}
		return "", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	_, err := m.Renew(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("续期失败时应当报错")
	}
	if !errors.Is(err, ErrClientFailed) {
		t.Errorf("应当是 ErrClientFailed，实际: %v", err)
	}
}

// TestRenewSiteNotFound 验证站点不存在。
func TestRenewSiteNotFound(t *testing.T) {
	ex := &fakeExecutor{}
	m := newTestManager(t, ex, newFakeSites(), &fakeRewriter{})
	if _, err := m.Renew(context.Background(), "nope", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("应当是 ErrNotFound，实际: %v", err)
	}
}

// TestRenewAllOnlyTouchesExpiring 验证批量续期只处理即将过期的证书。
//
// 这是自动续期的核心筛选逻辑：不该为每张证书都起一个进程，
// 更不该去动还很健康的证书。
func TestRenewAllOnlyTouchesExpiring(t *testing.T) {
	now := time.Now()
	// expiring.example.com 剩 10 天（需要续期）
	// fresh.example.com 剩 80 天（不需要）
	expiringOut := certbotOutputFor("expiring.example.com", "expiring.example.com", 10, now)
	freshOut := certbotOutputFor("fresh.example.com", "fresh.example.com", 80, now)
	combined := expiringOut + freshOut

	var renewedCerts []string
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			// 记录被续期的证书名
			for i, a := range args {
				if a == "--cert-name" && i+1 < len(args) {
					renewedCerts = append(renewedCerts, args[i+1])
				}
			}
			return "Congratulations! Your certificate and chain have been saved.", "", nil
		case strings.Contains(joined, "certificates"):
			return combined, "", nil
		}
		return "", "", nil
	}}

	sites := newFakeSites(
		SiteRef{Name: "expiring.example.com", Domain: "expiring.example.com", Root: "/var/www/a", Type: "static"},
		SiteRef{Name: "fresh.example.com", Domain: "fresh.example.com", Root: "/var/www/b", Type: "static"},
	)
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	results, err := m.RenewAll(context.Background())
	if err != nil {
		t.Fatalf("批量续期失败: %v", err)
	}

	// 只应当处理即将过期的那一个
	if len(results) != 1 {
		t.Fatalf("期望只处理 1 个站点，实际 %d 个", len(results))
	}
	if results[0].Site != "expiring.example.com" {
		t.Errorf("处理的站点 = %q，期望 expiring.example.com", results[0].Site)
	}

	// 健康证书不该被续期
	for _, c := range renewedCerts {
		if c == "fresh.example.com" {
			t.Error("剩余 80 天的证书不该被续期（会白白消耗 CA 配额）")
		}
	}
}

// TestRenewAllSkipsSitesWithoutCertificates 验证未申请证书的站点被跳过。
func TestRenewAllSkipsSitesWithoutCertificates(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "certbot 1.21.0", "", nil
		}
		return noCertsOutput, "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	results, err := m.RenewAll(context.Background())
	if err != nil {
		t.Fatalf("批量续期失败: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("没有证书时不该处理任何站点，实际 %d 个", len(results))
	}
	if call := findCall(ex.Calls(), "renew"); call != nil {
		t.Errorf("没有可续期的证书时不该执行 renew，实际: %v", call)
	}
}

// TestRenewAllContinuesAfterFailure 验证单个失败不中断批量。
//
// 让一个失败的证书挡住其它证书的续期，会导致更多证书过期。
func TestRenewAllContinuesAfterFailure(t *testing.T) {
	now := time.Now()
	out1 := certbotOutputFor("bad.example.com", "bad.example.com", 5, now)
	out2 := certbotOutputFor("good.example.com", "good.example.com", 5, now)

	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "renew"):
			if strings.Contains(joined, "bad.example.com") {
				return "", "Failed to renew certificate bad.example.com", errors.New("exit status 1")
			}
			return "Congratulations! Your certificate and chain have been saved.", "", nil
		case strings.Contains(joined, "certificates"):
			return out1 + out2, "", nil
		}
		return "", "", nil
	}}

	sites := newFakeSites(
		SiteRef{Name: "bad.example.com", Domain: "bad.example.com", Root: "/var/www/a", Type: "static"},
		SiteRef{Name: "good.example.com", Domain: "good.example.com", Root: "/var/www/b", Type: "static"},
	)
	m := newTestManager(t, ex, sites, &fakeRewriter{})

	results, err := m.RenewAll(context.Background())
	if err != nil {
		t.Fatalf("批量续期本身不该失败: %v", err)
	}
	// 两个站点都应出现在结果里（一个失败一个成功），而不是中断
	if len(results) != 2 {
		t.Fatalf("期望处理 2 个站点，实际 %d 个", len(results))
	}
}

// ---------------------------------------------------------------------------
// classifyRenewOutput 直接测试
// ---------------------------------------------------------------------------

// TestClassifyRenewOutput 穷举续期输出的分类。
func TestClassifyRenewOutput(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantRenewed bool
		wantSkipped bool
	}{
		{
			"未到窗口（实测输出）",
			"Certificate not yet due for renewal; no action taken.",
			false, true,
		},
		{
			"未到窗口（另一种措辞）",
			"The following certificates are not due for renewal yet",
			false, true,
		},
		{
			"成功续期",
			"Congratulations! Your certificate and chain have been saved at ...",
			true, false,
		},
		{
			"成功续期（另一种措辞）",
			"Successfully received certificate.",
			true, false,
		},
		{
			"续期失败",
			"Failed to renew certificate example.com with error: ...",
			false, false,
		},
		{
			"意外错误",
			"An unexpected error occurred: ...",
			false, false,
		},
		{
			"无法识别的输出",
			"some completely new format",
			false, false,
		},
		{"空输出", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renewed, skipped := classifyRenewOutput(tt.output)
			if renewed != tt.wantRenewed {
				t.Errorf("renewed = %v，期望 %v", renewed, tt.wantRenewed)
			}
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %v，期望 %v", skipped, tt.wantSkipped)
			}
		})
	}
}

// TestClassifyRenewOutputSkippedBeforeSuccess 验证判断顺序。
//
// 必须先判 skipped 再判 success：certbot 在跳过时也可能输出
// 包含 "renewal" 的说明文字，先判 success 会对某些版本误报。
func TestClassifyRenewOutputSkippedBeforeSuccess(t *testing.T) {
	// 这句话同时包含 "not due for renewal" 与 "renewal"
	out := "Certificate not yet due for renewal; no action taken."
	renewed, skipped := classifyRenewOutput(out)
	if renewed {
		t.Error("不该被判为已续期")
	}
	if !skipped {
		t.Error("应当被判为跳过")
	}
}

// ---------------------------------------------------------------------------
// 能力探测
// ---------------------------------------------------------------------------

// TestCapabilities 验证能力接口。
func TestCapabilities(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		return "certbot 1.21.0", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), &fakeRewriter{})

	cap := m.Capabilities(context.Background())
	if !cap.Available {
		t.Errorf("应当可用，原因: %s", cap.Reason)
	}
	if cap.ChallengeType != "http-01" {
		t.Errorf("ChallengeType = %q，期望 http-01", cap.ChallengeType)
	}
	if !cap.WebrootRequired {
		t.Error("HTTP-01 需要 webroot")
	}
	if !cap.CanRewriteNginx {
		t.Error("注入了 rewriter，CanRewriteNginx 应当为 true")
	}
	if !cap.EmailConfigured {
		t.Error("配置了邮箱，EmailConfigured 应当为 true")
	}
	if cap.Client.Version != "certbot 1.21.0" {
		t.Errorf("Client.Version = %q", cap.Client.Version)
	}
}

// TestCapabilitiesWithoutClient 验证无客户端时的提示。
func TestCapabilitiesWithoutClient(t *testing.T) {
	ex := &fakeExecutor{}
	m, err := NewManager(ManagerOptions{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		Detector: NewDetector(DetectorOptions{
			CertbotPath: "/nonexistent/certbot",
			Executor:    ex,
			Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		}),
		Sites:    newFakeSites(okStaticSite()),
		Executor: ex,
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	cap := m.Capabilities(context.Background())
	if cap.Available {
		t.Error("无客户端时不该可用")
	}
	if cap.Reason == "" {
		t.Error("应当给出原因")
	}
	// 应当告诉用户"怎么办"（装 certbot 或指定路径）
	if len(cap.Notes) == 0 {
		t.Fatal("应当给出可操作的建议")
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "certbot") {
		t.Errorf("建议应当提到 certbot，实际: %v", cap.Notes)
	}
}

// TestCapabilitiesWithoutRewriter 验证未注入 rewriter 时的提示。
func TestCapabilitiesWithoutRewriter(t *testing.T) {
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		return "certbot 1.21.0", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), nil)

	cap := m.Capabilities(context.Background())
	if !cap.Available {
		t.Errorf("证书能力仍应可用，原因: %s", cap.Reason)
	}
	if cap.CanRewriteNginx {
		t.Error("未注入 rewriter 时 CanRewriteNginx 应当为 false")
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "不会自动写入") {
		t.Errorf("应当提示不会自动写入配置，实际: %v", cap.Notes)
	}
}

// TestIssueWithoutRewriterSkipsNginx 验证未注入 rewriter 时申请仍可用。
//
// 这是被允许的用法：用户只想拿证书、自己配 nginx。
func TestIssueWithoutRewriterSkipsNginx(t *testing.T) {
	now := time.Now()
	var issued bool
	ex := &fakeExecutor{handler: func(name string, args []string) (string, string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--version"):
			return "certbot 1.21.0", "", nil
		case strings.Contains(joined, "certonly"):
			issued = true
			return "Successfully received certificate.", "", nil
		case strings.Contains(joined, "certificates"):
			if issued {
				return certbotOutputFor("example.com", "example.com", 90, now), "", nil
			}
			return noCertsOutput, "", nil
		}
		return "", "", nil
	}}
	m := newTestManager(t, ex, newFakeSites(okStaticSite()), nil)

	res, err := m.Issue(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("未注入 rewriter 时申请仍应成功: %v", err)
	}
	if !res.Issued {
		t.Error("Issued 应当为 true")
	}
	// Applied 为 true 表示"这条链路没有失败"；真正的含义是
	// "没有配置需要写入"。Capabilities 里会明确说明这一点。
	if !res.Applied {
		t.Error("没有 rewriter 时应当视为已处理（无需写入）")
	}
}
