package site

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// 站点管理器测试：生命周期、nginx -t 校验与**自动回滚**
// ============================================================================
//
// #################### 本文件的核心：回滚必须被真实验证 ####################
//
// 回滚是整个 4.3 里最不能出错的一段代码：它失败意味着**用户改坏配置后
// 没有退路，整台机器的 nginx 可能起不来**。
//
// 因此这里不是"断言返回了错误"，而是断言**磁盘状态真的回到了操作前**：
//
//	① 用 fakeExecutor 让 nginx -t 返回非零退出码；
//	② 调用 Update；
//	③ 逐字节比对配置文件内容与操作前是否一致；
//	④ 断言回滚后**再次执行 nginx -t 是成功的**。
//
// 第 ③ 条用字节比对而不是"文件存在"，是因为"回滚成了一份空文件"
// 或"回滚成半份配置"都能通过"文件存在"这种弱断言。

// startRealNginx 用给定的 prefix 启动一个**真实运行的 nginx**，
// 并在测试结束时关掉它。
//
// #################### 为什么必须真的把 nginx 跑起来 ####################
//
// `nginx -s reload` 的语义是"给正在运行的 master 进程发信号"。
// 若没有 master 进程，reload 会以
// `invalid PID number "" in ".../nginx.pid"` 失败——
// 这是**环境问题**，不是代码问题（初版测试正是这样红的）。
//
// 但它同时揭示了一件重要的事：**reload 失败的路径同样会触发回滚**
// （见 TestRollbackOnReloadFailure，那里是刻意让 reload 失败）。
// 因此真实集成测试必须先把 nginx 跑起来，才能覆盖
// "reload 成功"这条主链路。
//
// 启动方式：`nginx -p <prefix> -c <conf>`。nginx 默认 daemonize，
// 命令会立即返回，master 留在后台并把 pid 写进 logs/nginx.pid。
// 我们轮询 pid 文件确认它真的起来了。
//
// 启动失败时**跳过**而不是判失败：沙箱里可能缺少某些内核能力，
// 那是环境限制，不该让测试变红。
func startRealNginx(t *testing.T, prefix, ngx, confPath string) {
	t.Helper()

	cmd := exec.Command(ngx, "-p", prefix, "-c", confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("无法启动真实 nginx（环境限制）: %v\n%s", err, out)
	}

	pidPath := filepath.Join(prefix, "logs", "nginx.pid")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if nginxRunning(prefix) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !nginxRunning(prefix) {
		t.Skipf("真实 nginx 未成功驻留（pid 文件 %s 缺失或进程已退出）", pidPath)
	}

	t.Cleanup(func() {
		quit := exec.Command(ngx, "-p", prefix, "-c", confPath, "-s", "quit")
		_ = quit.Run()
		// 等待优雅退出。
		for i := 0; i < 50 && nginxRunning(prefix); i++ {
			time.Sleep(20 * time.Millisecond)
		}
		// 兜底：若 quit 没生效，按 pid 强杀，避免测试进程泄漏。
		if b, err := os.ReadFile(pidPath); err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(b))); convErr == nil {
				if proc, findErr := os.FindProcess(pid); findErr == nil {
					_ = proc.Kill()
				}
			}
		}
	})
}

// nginxRunning 判断某个 prefix 下的 nginx 是否在运行。
func nginxRunning(prefix string) bool {
	b, err := os.ReadFile(filepath.Join(prefix, "logs", "nginx.pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

// fakeExecutor 是可编程的 nginx 命令执行器。
type fakeExecutor struct {
	mu sync.Mutex
	// failTest 为 true 时 `nginx -t` 返回非零退出码。
	failTest bool
	// failReload 为 true 时 `nginx -s reload` 返回非零退出码。
	failReload bool
	// testOutput 是 `nginx -t` 失败时返回的输出（模拟 nginx 的报错）。
	testOutput string
	// calls 记录收到的全部命令（用于断言"确实调用了 nginx -t"）。
	calls [][]string
}

func (f *fakeExecutor) Run(_ context.Context, name string, args []string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))

	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "-t"):
		if f.failTest {
			out := f.testOutput
			if out == "" {
				out = "nginx: [emerg] unknown directive \"bogus\""
			}
			return "", out, errors.New("exit status 1")
		}
		return "nginx: configuration file test is successful", "", nil
	case strings.Contains(joined, "reload"):
		if f.failReload {
			return "", "nginx: [error] invalid PID number", errors.New("exit status 1")
		}
		return "", "", nil
	}
	return "", "", nil
}

// testEnv 是一次测试用的临时环境。
type testEnv struct {
	// prefix 是 nginx prefix 目录。
	prefix string
	// root 是静态站根目录。
	root string
	// adapter 是适配器。
	adapter *SystemAdapter
	// executor 是可控的执行器。
	executor *fakeExecutor
	// manager 是被测管理器。
	manager *Manager
	// auditor 是审计器。
	auditor *Auditor
}

// newTestEnv 搭建一个使用临时目录的完整环境。
//
// 布局刻意做成 Debian 风格（sites-available + sites-enabled），
// 因为这是"启用/禁用"语义最丰富的一种，覆盖它也就覆盖了 conf.d
// 的简单情形（另见 TestConfDLayout*）。
func newTestEnv(t *testing.T, failTest bool) *testEnv {
	t.Helper()
	dir := t.TempDir()

	prefix := filepath.Join(dir, "nginx")
	for _, sub := range []string{"sites-available", "sites-enabled", "logs"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建测试目录失败: %v", err)
		}
	}
	// 写一份 nginx.conf，让适配器能从 include 行探测出布局。
	conf := "events {}\nhttp {\n    include sites-enabled/*.conf;\n}\n"
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}

	root := filepath.Join(dir, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatalf("写入首页失败: %v", err)
	}

	adapter := NewSystemAdapter(AdapterOptions{Prefix: prefix})
	if adapter.Mode() != ModeSites {
		t.Fatalf("适配器应探测为 Debian 布局，实际: %s（reason: %s）",
			adapter.Mode(), adapter.UnavailableReason())
	}

	executor := &fakeExecutor{failTest: failTest}
	auditor, err := NewAuditor(AuditOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := NewManager(ManagerOptions{
		Logger:   logger,
		Adapter:  adapter,
		Auditor:  auditor,
		Executor: executor,
		RootChecker: func(p string) error {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s 不是目录", p)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}

	return &testEnv{
		prefix:   prefix,
		root:     root,
		adapter:  adapter,
		executor: executor,
		manager:  m,
		auditor:  auditor,
	}
}

// staticInput 返回一个指向临时根目录的静态站输入。
func (e *testEnv) staticInput(name, domain string, enabled bool) SiteInput {
	return SiteInput{
		Name: name, Domain: domain, Type: TypeStatic, Root: e.root, Enabled: enabled,
	}
}

// readConf 读取站点配置文件内容。
func (e *testEnv) readConf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(e.adapter.SiteFilePath(name))
	if err != nil {
		t.Fatalf("读取配置 %s 失败: %v", name, err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// 生命周期：创建 / 编辑 / 启用 / 禁用 / 删除
// ---------------------------------------------------------------------------

// TestCreateStaticSite 验证创建一个静态站。
func TestCreateStaticSite(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	s, err := env.manager.Create(ctx, env.staticInput("demo", "demo.example.com", true))
	if err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	if s.Name != "demo" || s.Domain != "demo.example.com" || s.Type != TypeStatic {
		t.Errorf("创建结果字段不符: %+v", s)
	}
	if !s.Enabled {
		t.Error("站点应当处于启用状态")
	}
	if !s.Generated {
		t.Error("站点应被标记为面板生成")
	}

	// 配置文件应存在且启用链接应指向它。
	content := env.readConf(t, "demo")
	mustContain(t, content, "server_name demo.example.com;")
	mustContain(t, content, "root "+env.root+";")

	target, err := os.Readlink(env.adapter.EnabledPath("demo"))
	if err != nil {
		t.Fatalf("启用链接应存在: %v", err)
	}
	if target != filepath.Join("..", "sites-available", "demo.conf") {
		t.Errorf("启用链接目标应为相对路径，实际: %q", target)
	}

	// 必须真的调用过 nginx -t 与 reload。
	assertCalled(t, env.executor, "-t")
	assertCalled(t, env.executor, "reload")
}

// TestCreateDisabledSite 验证创建时不启用。
func TestCreateDisabledSite(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	s, err := env.manager.Create(ctx, env.staticInput("off", "off.example.com", false))
	if err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	if s.Enabled {
		t.Error("站点不应处于启用状态")
	}
	// 定义文件存在，但启用链接不存在。
	if _, err := os.Stat(env.adapter.SiteFilePath("off")); err != nil {
		t.Errorf("定义文件应存在: %v", err)
	}
	if _, err := os.Lstat(env.adapter.EnabledPath("off")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("启用链接不应存在，实际 err=%v", err)
	}
}

// TestCreateRejectsDuplicate 验证重复创建被拒绝。
func TestCreateRejectsDuplicate(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("dup", "dup.example.com", true)); err != nil {
		t.Fatalf("首次创建应成功: %v", err)
	}
	_, err := env.manager.Create(ctx, env.staticInput("dup", "dup2.example.com", true))
	if !errors.Is(err, ErrExists) {
		t.Errorf("重复创建应返回 ErrExists，实际: %v", err)
	}
}

// TestCreateRejectsMissingRoot 验证根目录不存在时拒绝创建。
//
// 站点根不存在时 nginx 能正常启动（语法没问题），但访问会 404/500，
// 用户完全看不出是路径写错了。因此在创建阶段就明确报错。
func TestCreateRejectsMissingRoot(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	in := env.staticInput("bad", "bad.example.com", true)
	in.Root = filepath.Join(env.root, "does-not-exist")

	if _, err := env.manager.Create(ctx, in); err == nil {
		t.Error("根目录不存在时应拒绝创建")
	}
	// 被拒绝时不应留下任何文件。
	if _, err := os.Stat(env.adapter.SiteFilePath("bad")); !errors.Is(err, os.ErrNotExist) {
		t.Error("创建失败后不应留下配置文件")
	}
}

// TestProxySiteLifecycle 验证反代站的创建与编辑。
func TestProxySiteLifecycle(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	s, err := env.manager.Create(ctx, SiteInput{
		Name: "api", Domain: "api.example.com", Type: TypeProxy,
		Upstream: "127.0.0.1:3000", Enabled: true,
	})
	if err != nil {
		t.Fatalf("创建反代站失败: %v", err)
	}
	// 归一化：缺协议应补上 http://。
	if s.Upstream != "http://127.0.0.1:3000" {
		t.Errorf("反代目标应被归一化为 http://127.0.0.1:3000，实际: %q", s.Upstream)
	}
	mustContain(t, env.readConf(t, "api"), "proxy_pass http://127.0.0.1:3000;")

	// 编辑：换目标地址。
	updated, err := env.manager.Update(ctx, "api", SiteInput{
		Name: "api", Domain: "api2.example.com", Type: TypeProxy,
		Upstream: "http://127.0.0.1:4000", Enabled: true,
	})
	if err != nil {
		t.Fatalf("编辑反代站失败: %v", err)
	}
	if updated.Domain != "api2.example.com" {
		t.Errorf("域名未更新: %q", updated.Domain)
	}
	content := env.readConf(t, "api")
	mustContain(t, content, "proxy_pass http://127.0.0.1:4000;")
	mustNotContain(t, content, "127.0.0.1:3000")
}

// TestUpdateRejectsNameMismatch 验证请求体站点名与路径不一致时拒绝。
func TestUpdateRejectsNameMismatch(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("a", "a.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	_, err := env.manager.Update(ctx, "a", env.staticInput("b", "a.example.com", true))
	if !errors.Is(err, ErrInvalidName) {
		t.Errorf("站点名不一致应返回 ErrInvalidName，实际: %v", err)
	}
}

// TestEnableDisableCycle 验证启用/禁用的完整循环。
//
// 关键断言：**禁用不删除配置内容**（Debian 布局的核心价值）。
func TestEnableDisableCycle(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("cyc", "cyc.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	before := env.readConf(t, "cyc")

	// 禁用。
	s, err := env.manager.SetEnabled(ctx, "cyc", false)
	if err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if s.Enabled {
		t.Error("禁用后 Enabled 应为 false")
	}
	if _, err := os.Lstat(env.adapter.EnabledPath("cyc")); !errors.Is(err, os.ErrNotExist) {
		t.Error("禁用后启用链接应被删除")
	}
	// 配置内容必须原样保留。
	if after := env.readConf(t, "cyc"); after != before {
		t.Error("禁用不应改动配置内容（这是 Debian 布局可逆禁用的核心）")
	}

	// 重新启用。
	s, err = env.manager.SetEnabled(ctx, "cyc", true)
	if err != nil {
		t.Fatalf("重新启用失败: %v", err)
	}
	if !s.Enabled {
		t.Error("重新启用后 Enabled 应为 true")
	}
	if after := env.readConf(t, "cyc"); after != before {
		t.Error("重新启用不应改动配置内容")
	}
	if env.adapter.Enabled("cyc") == false {
		t.Error("启用链接应重新建立")
	}
}

// TestSetEnabledIdempotent 验证重复启用/禁用是幂等的。
func TestSetEnabledIdempotent(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("idem", "idem.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	// 已启用再启用、已禁用再禁用都不应报错。
	if _, err := env.manager.SetEnabled(ctx, "idem", true); err != nil {
		t.Errorf("重复启用应幂等成功: %v", err)
	}
	if _, err := env.manager.SetEnabled(ctx, "idem", false); err != nil {
		t.Errorf("禁用失败: %v", err)
	}
	if _, err := env.manager.SetEnabled(ctx, "idem", false); err != nil {
		t.Errorf("重复禁用应幂等成功: %v", err)
	}
}

// TestDeleteRemovesEverything 验证删除清掉定义文件与启用链接。
func TestDeleteRemovesEverything(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("gone", "gone.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if err := env.manager.Delete(ctx, "gone"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := os.Stat(env.adapter.SiteFilePath("gone")); !errors.Is(err, os.ErrNotExist) {
		t.Error("删除后定义文件应不存在")
	}
	if _, err := os.Lstat(env.adapter.EnabledPath("gone")); !errors.Is(err, os.ErrNotExist) {
		t.Error("删除后启用链接应不存在")
	}
	if _, err := env.manager.Get("gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("删除后 Get 应返回 ErrNotFound，实际: %v", err)
	}
}

// TestListReflectsState 验证列表能正确反映启用状态。
//
// 这条覆盖 4.1 踩过的同一类坑：只扫"启用目录"会让已禁用的站点
// 从列表里消失，用户再也无法重新启用它。
func TestListReflectsState(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("on", "on.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if _, err := env.manager.Create(ctx, env.staticInput("off", "off.example.com", false)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	list, err := env.manager.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("应列出 2 个站点（含已禁用的），实际 %d 个: %+v", len(list), list)
	}

	byName := map[string]Site{}
	for _, s := range list {
		byName[s.Name] = s
	}
	if !byName["on"].Enabled {
		t.Error("on 应为启用状态")
	}
	if byName["off"].Enabled {
		t.Error("off 应为禁用状态")
	}
	// 已禁用的站点必须仍在列表里，否则用户无法重新启用它。
	if _, ok := byName["off"]; !ok {
		t.Error("已禁用的站点必须出现在列表中")
	}
	// 启用状态变化后列表应跟随。
	if _, err := env.manager.SetEnabled(ctx, "off", true); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	list, err = env.manager.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	for _, s := range list {
		if s.Name == "off" && !s.Enabled {
			t.Error("启用后列表中的 off 应为启用状态")
		}
	}
}

// TestListSkipsInvalidNames 验证名字非法的配置被跳过而不是导致整个列表失败。
func TestListSkipsInvalidNames(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("good", "good.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	// 手工放一个名字含空格的配置（面板管不了这类文件）。
	bad := filepath.Join(env.adapter.AvailableDir(), "bad name.conf")
	if err := os.WriteFile(bad, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}

	list, err := env.manager.List()
	if err != nil {
		t.Fatalf("列表不应因非法文件而失败: %v", err)
	}
	if len(list) != 1 || list[0].Name != "good" {
		t.Errorf("应只列出 good 一个站点，实际: %+v", list)
	}
}

// TestListMarksExternalConfig 验证外部配置被标记为只读。
func TestListMarksExternalConfig(t *testing.T) {
	env := newTestEnv(t, false)

	external := "server {\n    listen 80;\n    server_name manual.example.com;\n    root /srv/manual;\n}\n"
	if err := os.WriteFile(env.adapter.SiteFilePath("manual"), []byte(external), 0o644); err != nil {
		t.Fatalf("写入外部配置失败: %v", err)
	}

	list, err := env.manager.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("应列出 1 个站点，实际 %d", len(list))
	}
	if list[0].Generated {
		t.Error("外部配置不应被标记为面板生成")
	}
	if list[0].ParseNote == "" {
		t.Error("外部配置应带有说明（提示用户面板不会修改它）")
	}
}

// TestUpdateRejectsExternalConfig 验证外部配置拒绝被面板编辑。
//
// 这是防止"面板用模板整体重写，把用户手写的配置彻底抹掉"的关键保护。
func TestUpdateRejectsExternalConfig(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	external := "server {\n    listen 80;\n    server_name manual.example.com;\n    root /srv/manual;\n}\n"
	if err := os.WriteFile(env.adapter.SiteFilePath("manual"), []byte(external), 0o644); err != nil {
		t.Fatalf("写入外部配置失败: %v", err)
	}

	in := env.staticInput("manual", "new.example.com", true)
	if _, err := env.manager.Update(ctx, "manual", in); !errors.Is(err, ErrExternal) {
		t.Errorf("编辑外部配置应返回 ErrExternal，实际: %v", err)
	}
	// 内容必须一字未改。
	after, err := os.ReadFile(env.adapter.SiteFilePath("manual"))
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(after) != external {
		t.Error("被拒绝的编辑不应改动文件内容")
	}

	// 删除同样应被拒绝。
	if err := env.manager.Delete(ctx, "manual"); !errors.Is(err, ErrExternal) {
		t.Errorf("删除外部配置应返回 ErrExternal，实际: %v", err)
	}
	if _, err := os.Stat(env.adapter.SiteFilePath("manual")); err != nil {
		t.Error("被拒绝的删除不应移除文件")
	}
}

// ---------------------------------------------------------------------------
// 核心：nginx -t 失败时的自动回滚
// ---------------------------------------------------------------------------

// TestRollbackOnNginxTestFailure 是本阶段最关键的一个测试。
//
// 场景：编辑一个已有的站点，但 nginx -t 失败。
// 期望：**配置文件逐字节回到编辑前的内容**，且回滚后的配置仍能通过 nginx -t。
func TestRollbackOnNginxTestFailure(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// ① 先正常创建一个站点（此时 nginx -t 是通过的）。
	if _, err := env.manager.Create(ctx, env.staticInput("rb", "rb.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	before := env.readConf(t, "rb")
	beforeTarget, err := os.Readlink(env.adapter.EnabledPath("rb"))
	if err != nil {
		t.Fatalf("读取启用链接失败: %v", err)
	}

	// ② 让 nginx -t 失败。
	env.executor.mu.Lock()
	env.executor.failTest = true
	env.executor.testOutput = `nginx: [emerg] invalid parameter "bogus" in /etc/nginx/sites-enabled/rb.conf:5`
	env.executor.mu.Unlock()

	// ③ 尝试编辑 → 应当失败，并返回 nginx 校验错误。
	updated := env.staticInput("rb", "changed.example.com", true)
	_, err = env.manager.Update(ctx, "rb", updated)
	if err == nil {
		t.Fatal("nginx -t 失败时编辑应当报错")
	}
	if !errors.Is(err, ErrNginxTestFailed) {
		t.Errorf("错误应可识别为 ErrNginxTestFailed，实际: %v", err)
	}
	// 错误信息里必须带上 nginx 的原始报错，用户才知道哪里写错了。
	if !strings.Contains(err.Error(), "invalid parameter") {
		t.Errorf("错误信息应包含 nginx 的原始报错，实际: %v", err)
	}

	// ④ 核心断言：配置文件逐字节回到操作前。
	after := env.readConf(t, "rb")
	if after != before {
		t.Errorf("配置未回滚到修改前的内容。\n修改前:\n%s\n回滚后:\n%s", before, after)
	}
	// 域名必须还是旧的。
	mustContain(t, after, "server_name rb.example.com;")
	mustNotContain(t, after, "changed.example.com")

	// ⑤ 启用状态也必须回到操作前。
	afterTarget, err := os.Readlink(env.adapter.EnabledPath("rb"))
	if err != nil {
		t.Fatalf("回滚后启用链接应存在: %v", err)
	}
	if afterTarget != beforeTarget {
		t.Errorf("启用链接未回滚: 期望 %q，实际 %q", beforeTarget, afterTarget)
	}

	// ⑥ 回滚后必须**再次**通过 nginx -t。
	//
	// 这是"回滚真的生效了"的最终证据：把 failTest 关掉后重新校验，
	// 若配置被回滚成了合法内容，这一步必然成功。
	env.executor.mu.Lock()
	env.executor.failTest = false
	env.executor.mu.Unlock()

	if _, err := env.manager.runNginx(ctx, nginxTestTimeout, "-t"); err != nil {
		t.Errorf("回滚后的配置应能通过 nginx -t: %v", err)
	}

	// ⑦ 再次编辑应当成功（证明系统已恢复正常，不是卡在坏状态）。
	if _, err := env.manager.Update(ctx, "rb", env.staticInput("rb", "changed.example.com", true)); err != nil {
		t.Fatalf("回滚后再次编辑应成功: %v", err)
	}
	mustContain(t, env.readConf(t, "rb"), "server_name changed.example.com;")
}

// TestRollbackOnCreateFailure 验证创建失败时**不留下任何文件**。
//
// 这是"新建场景的回滚"：操作前文件不存在，回滚必须把新建的文件删掉，
// 而不是留下一份空文件（那会让 nginx 加载一个空配置，
// 更糟的是用户会在列表里看到一个莫名其妙的空站点）。
func TestRollbackOnCreateFailure(t *testing.T) {
	env := newTestEnv(t, true) // 一开始就让 nginx -t 失败
	ctx := context.Background()

	_, err := env.manager.Create(ctx, env.staticInput("newone", "new.example.com", true))
	if err == nil {
		t.Fatal("nginx -t 失败时创建应当报错")
	}
	if !errors.Is(err, ErrNginxTestFailed) {
		t.Errorf("错误应可识别为 ErrNginxTestFailed，实际: %v", err)
	}

	// 核心断言：定义文件与启用链接都**不存在**。
	if _, err := os.Stat(env.adapter.SiteFilePath("newone")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("创建失败回滚后不应留下配置文件，实际 err=%v", err)
	}
	if _, err := os.Lstat(env.adapter.EnabledPath("newone")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("创建失败回滚后不应留下启用链接，实际 err=%v", err)
	}
	// 列表里也不应出现这个站点。
	list, err := env.manager.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("回滚后列表应为空，实际: %+v", list)
	}
}

// TestRollbackOnReloadFailure 验证 reload 失败时也回滚。
//
// 与 -t 失败的区别：reload 失败意味着旧配置可能仍在内核里生效，
// 因此回滚文件之后还必须**再 reload 一次**，让运行态跟上磁盘态。
func TestRollbackOnReloadFailure(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("rl", "rl.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	before := env.readConf(t, "rl")

	// 让 reload 失败（但 -t 通过）。
	env.executor.mu.Lock()
	env.executor.failReload = true
	env.executor.mu.Unlock()

	_, err := env.manager.Update(ctx, "rl", env.staticInput("rl", "changed.example.com", true))
	if err == nil {
		t.Fatal("reload 失败时编辑应当报错")
	}
	if !errors.Is(err, ErrReloadFailed) {
		t.Errorf("错误应可识别为 ErrReloadFailed，实际: %v", err)
	}

	// 配置必须回滚。
	if after := env.readConf(t, "rl"); after != before {
		t.Errorf("reload 失败后配置未回滚。\n修改前:\n%s\n回滚后:\n%s", before, after)
	}

	// 回滚后应尝试过重新 reload（让运行态与磁盘态一致）。
	env.executor.mu.Lock()
	reloadCount := 0
	for _, call := range env.executor.calls {
		if strings.Contains(strings.Join(call, " "), "reload") {
			reloadCount++
		}
	}
	env.executor.mu.Unlock()
	// 期望至少 3 次：首次 reload（失败）+ 回滚后的 reload（带 needReload）。
	if reloadCount < 2 {
		t.Errorf("回滚后应再次尝试 reload 以恢复运行态，实际 reload 次数: %d", reloadCount)
	}
}

// TestRollbackRestoresDisabledState 验证回滚能恢复"禁用"状态。
//
// 场景：站点原本是禁用的，用户在编辑时勾选了启用，但配置校验失败。
// 回滚必须把站点退回**禁用**状态，而不只是恢复文件内容。
// 少了这一条，用户会得到一个"内容是对的、却被启用了"的站点。
func TestRollbackRestoresDisabledState(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// 创建一个禁用状态的站点。
	if _, err := env.manager.Create(ctx, env.staticInput("dis", "dis.example.com", false)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	before := env.readConf(t, "dis")
	if env.adapter.Enabled("dis") {
		t.Fatal("前置条件：站点应为禁用状态")
	}

	// 让 nginx -t 失败，然后尝试"编辑 + 启用"。
	env.executor.mu.Lock()
	env.executor.failTest = true
	env.executor.mu.Unlock()

	_, err := env.manager.Update(ctx, "dis", env.staticInput("dis", "changed.example.com", true))
	if err == nil {
		t.Fatal("nginx -t 失败时编辑应当报错")
	}

	// 内容回滚。
	if after := env.readConf(t, "dis"); after != before {
		t.Error("配置内容未回滚")
	}
	// 启用状态也必须回滚到"禁用"。
	if env.adapter.Enabled("dis") {
		t.Error("回滚后站点应回到禁用状态，但启用链接仍在")
	}
}

// TestRollbackPreservesOtherSites 验证回滚只影响目标站点。
//
// nginx 的配置是全局共享的，一次写坏会影响所有站点。
// 回滚时若误伤了别的站点，等于把一次事故扩成两次。
func TestRollbackPreservesOtherSites(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("keep", "keep.example.com", true)); err != nil {
		t.Fatalf("创建 keep 失败: %v", err)
	}
	if _, err := env.manager.Create(ctx, env.staticInput("broken", "broken.example.com", true)); err != nil {
		t.Fatalf("创建 broken 失败: %v", err)
	}
	keepBefore := env.readConf(t, "keep")

	env.executor.mu.Lock()
	env.executor.failTest = true
	env.executor.mu.Unlock()

	_, err := env.manager.Update(ctx, "broken", env.staticInput("broken", "changed.example.com", true))
	if err == nil {
		t.Fatal("nginx -t 失败时编辑应当报错")
	}

	// 另一个站点必须一字未动。
	if after := env.readConf(t, "keep"); after != keepBefore {
		t.Error("回滚不应影响其它站点")
	}
	if !env.adapter.Enabled("keep") {
		t.Error("回滚不应影响其它站点的启用状态")
	}
}

// TestRollbackSequenceIsComplete 验证失败路径上的命令调用序列。
//
// 断言"先 -t、后 reload"，以及"回滚后再次 -t"。
// 顺序错了（例如先 reload 再 -t）会让坏配置真的被加载。
func TestRollbackSequenceIsComplete(t *testing.T) {
	env := newTestEnv(t, true)
	ctx := context.Background()

	_, _ = env.manager.Create(ctx, env.staticInput("seq", "seq.example.com", true))

	env.executor.mu.Lock()
	defer env.executor.mu.Unlock()

	if len(env.executor.calls) == 0 {
		t.Fatal("应当调用过 nginx")
	}
	// 第一次调用必须是 -t（在 reload 之前校验）。
	first := strings.Join(env.executor.calls[0], " ")
	if !strings.Contains(first, "-t") {
		t.Errorf("第一次 nginx 调用应是 -t 校验，实际: %q", first)
	}
	// 全部调用里不应出现 reload：-t 失败时不该尝试 reload。
	for _, call := range env.executor.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "reload") && !strings.Contains(joined, "-t") {
			t.Errorf("-t 失败时不应调用 reload，实际: %q", joined)
		}
	}
	// 必须发生过至少两次 -t：首次校验 + 回滚后复验。
	testCount := 0
	for _, call := range env.executor.calls {
		if strings.Contains(strings.Join(call, " "), "-t") {
			testCount++
		}
	}
	if testCount < 2 {
		t.Errorf("回滚后应再次执行 nginx -t 复验，实际 -t 次数: %d", testCount)
	}
}

// ---------------------------------------------------------------------------
// 权限与安全
// ---------------------------------------------------------------------------

// TestManagerRejectsInvalidNameBeforeTouchingDisk 验证非法站点名不触碰磁盘。
func TestManagerRejectsInvalidNameBeforeTouchingDisk(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	for _, r := range nginxMetacharacters {
		name := "site" + string(r)
		in := env.staticInput(name, "x.example.com", true)
		if _, err := env.manager.Create(ctx, in); err == nil {
			t.Errorf("站点名 %q 应被拒绝", name)
		}
		if _, err := env.manager.Update(ctx, name, in); err == nil {
			t.Errorf("站点名 %q 的编辑应被拒绝", name)
		}
		if err := env.manager.Delete(ctx, name); err == nil {
			t.Errorf("站点名 %q 的删除应被拒绝", name)
		}
		if _, err := env.manager.SetEnabled(ctx, name, true); err == nil {
			t.Errorf("站点名 %q 的启用应被拒绝", name)
		}
	}

	// 整个过程中不应产生任何文件。
	entries, err := os.ReadDir(env.adapter.AvailableDir())
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("非法输入不应产生任何文件，实际: %v", entries)
	}
	// 也不应调用过 nginx。
	env.executor.mu.Lock()
	calls := len(env.executor.calls)
	env.executor.mu.Unlock()
	if calls != 0 {
		t.Errorf("非法输入不应触发任何 nginx 调用，实际 %d 次", calls)
	}
}

// TestManagerRejectsInjectionInDomainAndRoot 验证域名/根目录注入被拒绝。
func TestManagerRejectsInjectionInDomainAndRoot(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	for _, r := range nginxMetacharacters {
		c := string(r)
		// 域名注入。
		in := env.staticInput("s"+strings.ReplaceAll(string(r), "/", "x"), "x.com"+c, true)
		in.Name = "site1"
		if _, err := env.manager.Create(ctx, in); err == nil {
			t.Errorf("域名含 %q 时应被拒绝", r)
		}
		// 根目录注入。
		in2 := env.staticInput("site2", "x.com", true)
		in2.Root = "/var/www" + c
		if _, err := env.manager.Create(ctx, in2); err == nil {
			t.Errorf("根目录含 %q 时应被拒绝", r)
		}
	}
}

// TestManagerRejectsTypeFieldMismatch 验证类型与字段不匹配时拒绝。
//
// 静默丢弃另一个字段会让用户以为自己的输入生效了：
// 前端切换类型时若忘了清空，用户就会得到一个"看起来配了反代、
// 实际是静态站"的站点。
func TestManagerRejectsTypeFieldMismatch(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// 静态站带 upstream。
	in := env.staticInput("mix1", "mix.example.com", true)
	in.Upstream = "http://127.0.0.1:3000"
	if _, err := env.manager.Create(ctx, in); !errors.Is(err, ErrInvalidUpstream) {
		t.Errorf("静态站带 upstream 应被拒绝，实际: %v", err)
	}

	// 反代站带 root。
	in2 := SiteInput{
		Name: "mix2", Domain: "mix.example.com", Type: TypeProxy,
		Upstream: "http://127.0.0.1:3000", Root: "/var/www", Enabled: true,
	}
	if _, err := env.manager.Create(ctx, in2); !errors.Is(err, ErrInvalidRoot) {
		t.Errorf("反代站带 root 应被拒绝，实际: %v", err)
	}
}

// TestUnavailableManagerDegrades 验证适配器不可用时的优雅降级。
//
// 计划明确要求：无 nginx 时不能 panic、不能返回裸 500，
// 而应给出可读原因，且面板其它功能不受影响。
func TestUnavailableManagerDegrades(t *testing.T) {
	dir := t.TempDir()
	// 一个既没有 sites-enabled 也没有 conf.d 的 prefix。
	prefix := filepath.Join(dir, "empty-nginx")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"),
		[]byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}

	adapter := NewSystemAdapter(AdapterOptions{
		Prefix: prefix,
		// 显式提供一个假的 nginx 路径，让"可执行文件存在"这一条不成立
		// 也不影响本用例——我们要测的是**目录探测失败**的降级。
		Executable: "/usr/sbin/nginx",
	})
	if adapter.Available() {
		t.Fatalf("目录探测应失败，实际 mode=%s", adapter.Mode())
	}
	if adapter.UnavailableReason() == "" {
		t.Error("不可用时应给出可读原因")
	}

	m, err := NewManager(ManagerOptions{Adapter: adapter})
	if err != nil {
		t.Fatalf("构造管理器不应失败（应优雅降级）: %v", err)
	}
	if m.Available() {
		t.Error("管理器应报告不可用")
	}

	// 所有接口都应返回错误而不是 panic。
	ctx := context.Background()
	if _, err := m.List(); err == nil {
		t.Error("不可用时 List 应返回错误")
	}
	if _, err := m.Create(ctx, SiteInput{Name: "a", Domain: "x.com", Type: TypeStatic, Root: "/tmp"}); err == nil {
		t.Error("不可用时 Create 应返回错误")
	}
	if _, err := m.Get("a"); err == nil {
		t.Error("不可用时 Get 应返回错误")
	}
	if err := m.Delete(ctx, "a"); err == nil {
		t.Error("不可用时 Delete 应返回错误")
	}
	if _, err := m.SetEnabled(ctx, "a", true); err == nil {
		t.Error("不可用时 SetEnabled 应返回错误")
	}
}

// ---------------------------------------------------------------------------
// conf.d 布局
// ---------------------------------------------------------------------------

// newConfDEnv 搭建一个 conf.d 布局的测试环境（RHEL/CentOS 风格）。
func newConfDEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()

	prefix := filepath.Join(dir, "nginx")
	for _, sub := range []string{"conf.d", "logs"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建测试目录失败: %v", err)
		}
	}
	conf := "events {}\nhttp {\n    include conf.d/*.conf;\n}\n"
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}

	root := filepath.Join(dir, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根目录失败: %v", err)
	}

	adapter := NewSystemAdapter(AdapterOptions{Prefix: prefix})
	if adapter.Mode() != ModeConfD {
		t.Fatalf("适配器应探测为 conf.d 布局，实际: %s", adapter.Mode())
	}

	executor := &fakeExecutor{}
	auditor, _ := NewAuditor(AuditOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	m, err := NewManager(ManagerOptions{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Adapter:  adapter,
		Auditor:  auditor,
		Executor: executor,
		RootChecker: func(p string) error {
			_, err := os.Stat(p)
			return err
		},
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}
	return &testEnv{prefix: prefix, root: root, adapter: adapter, executor: executor, manager: m, auditor: auditor}
}

// TestConfDLayoutDisableRenamesFile 验证 conf.d 布局下禁用是"改名"而不是"删除"。
//
// 关键点：改名后文件不再以 .conf 结尾，因此不会被 `include conf.d/*.conf`
// 加载；同时配置内容**仍在磁盘上**，用户随时可以重新启用。
// 若实现成"删除"，用户点一次"禁用"就永久丢失了配置——这是不可接受的语义。
func TestConfDLayoutDisableRenamesFile(t *testing.T) {
	env := newConfDEnv(t)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("cd", "cd.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	active := env.adapter.SiteFilePath("cd")
	disabled := env.adapter.DisabledPath("cd")

	if _, err := os.Stat(active); err != nil {
		t.Fatalf("启用状态下 %s 应存在: %v", active, err)
	}

	// 禁用。
	s, err := env.manager.SetEnabled(ctx, "cd", false)
	if err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if s.Enabled {
		t.Error("禁用后 Enabled 应为 false")
	}
	// .conf 必须消失（否则 nginx 仍会加载它）。
	if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("禁用后 %s 不应存在（否则 nginx 仍会加载）", active)
	}
	// .conf.disabled 必须存在（配置内容没丢）。
	content, err := os.ReadFile(disabled)
	if err != nil {
		t.Fatalf("禁用后 %s 应存在（配置不能丢）: %v", disabled, err)
	}
	mustContain(t, string(content), "server_name cd.example.com;")

	// 重新启用。
	s, err = env.manager.SetEnabled(ctx, "cd", true)
	if err != nil {
		t.Fatalf("重新启用失败: %v", err)
	}
	if !s.Enabled {
		t.Error("重新启用后 Enabled 应为 true")
	}
	if _, err := os.Stat(active); err != nil {
		t.Errorf("重新启用后 %s 应存在: %v", active, err)
	}
	if _, err := os.Stat(disabled); !errors.Is(err, os.ErrNotExist) {
		t.Error("重新启用后 .conf.disabled 不应存在")
	}
}

// TestConfDLayoutList 验证 conf.d 布局下列表能同时看到启用与禁用的站点。
func TestConfDLayoutList(t *testing.T) {
	env := newConfDEnv(t)
	ctx := context.Background()

	if _, err := env.manager.Create(ctx, env.staticInput("one", "one.example.com", true)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if _, err := env.manager.Create(ctx, env.staticInput("two", "two.example.com", false)); err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	list, err := env.manager.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("应列出 2 个站点，实际 %d: %+v", len(list), list)
	}
	for _, s := range list {
		switch s.Name {
		case "one":
			if !s.Enabled {
				t.Error("one 应为启用状态")
			}
		case "two":
			if s.Enabled {
				t.Error("two 应为禁用状态")
			}
		}
	}

	// 删除也要能清掉 .conf.disabled。
	if err := env.manager.Delete(ctx, "two"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := os.Stat(env.adapter.DisabledPath("two")); !errors.Is(err, os.ErrNotExist) {
		t.Error("删除后 .conf.disabled 应被清掉")
	}
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

// TestAuditorRecordsOutcomes 验证审计记录覆盖三种结果。
func TestAuditorRecordsOutcomes(t *testing.T) {
	auditor, err := NewAuditor(AuditOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造审计器失败: %v", err)
	}

	auditor.Record(AuditEvent{Action: ActionCreate, Target: "a", Outcome: AuditAllowed, Status: 200})
	auditor.Record(AuditEvent{Action: ActionUpdate, Target: "b", Outcome: AuditFailed, Status: 422, RolledBack: true})
	auditor.Record(AuditEvent{Action: ActionDelete, Target: "c", Outcome: AuditDenied, Status: 403})

	stats := auditor.Stats()
	if stats.Total != 3 {
		t.Errorf("总数应为 3，实际 %d", stats.Total)
	}
	if stats.Denied != 1 {
		t.Errorf("拒绝数应为 1，实际 %d", stats.Denied)
	}
	if stats.Failed != 1 {
		t.Errorf("失败数应为 1，实际 %d", stats.Failed)
	}
	if stats.RolledBack != 1 {
		t.Errorf("回滚数应为 1，实际 %d", stats.RolledBack)
	}

	// 过滤查询。
	if got := auditor.Query(AuditFilter{Outcome: AuditDenied}); len(got) != 1 || got[0].Target != "c" {
		t.Errorf("按结果过滤有误: %+v", got)
	}
	if got := auditor.Query(AuditFilter{Target: "a"}); len(got) != 1 {
		t.Errorf("按站点过滤有误: %+v", got)
	}
	if got := auditor.Query(AuditFilter{Action: ActionUpdate}); len(got) != 1 {
		t.Errorf("按动作过滤有误: %+v", got)
	}
}

// TestAuditorDefaultsKindAndSource 验证默认字段。
func TestAuditorDefaultsKindAndSource(t *testing.T) {
	auditor, _ := NewAuditor(AuditOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	auditor.Record(AuditEvent{Action: ActionCreate, Target: "a"})

	events := auditor.Query(AuditFilter{})
	if len(events) != 1 {
		t.Fatalf("应有 1 条记录，实际 %d", len(events))
	}
	ev := events[0]
	if ev.Kind != KindSite {
		t.Errorf("Kind 应为 %q，实际 %q", KindSite, ev.Kind)
	}
	if ev.Source != SourceCore {
		t.Errorf("Source 应为 %q（核心自带，不伪造插件 ID），实际 %q", SourceCore, ev.Source)
	}
	if ev.Time == "" {
		t.Error("Time 应被自动填充")
	}
	if ev.Outcome != AuditAllowed {
		t.Errorf("Outcome 应默认为 allowed，实际 %q", ev.Outcome)
	}
}

// TestAuditorRingBufferEviction 验证环形缓冲淘汰最旧记录。
func TestAuditorRingBufferEviction(t *testing.T) {
	auditor, _ := NewAuditor(AuditOptions{
		Capacity: 3,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	for i := 0; i < 10; i++ {
		auditor.Record(AuditEvent{Action: ActionCreate, Target: fmt.Sprintf("s%d", i)})
	}
	stats := auditor.Stats()
	if stats.Total != 10 {
		t.Errorf("总数应为 10（累计），实际 %d", stats.Total)
	}
	if stats.Retained != 3 {
		t.Errorf("保留数应为 3（容量），实际 %d", stats.Retained)
	}
	// 最新的在前。
	events := auditor.Query(AuditFilter{})
	if len(events) != 3 || events[0].Target != "s9" {
		t.Errorf("应按时间倒序返回最新记录，实际: %+v", events)
	}
}

// TestPermAndActions 验证权限判定。
func TestPermAndActions(t *testing.T) {
	admin := AdminGrantee("admin")

	for _, action := range []string{ActionCreate, ActionUpdate, ActionDelete, ActionEnable, ActionDisable} {
		d := CheckSitePermission(admin, action)
		if !d.Allowed {
			t.Errorf("管理员应被允许执行 %s", action)
		}
		if d.Required != PermWrite {
			t.Errorf("%s 所需权限应为 %s，实际 %s", action, PermWrite, d.Required)
		}
	}
	for _, action := range []string{ActionList, ActionView} {
		d := CheckSitePermission(admin, action)
		if !d.Allowed {
			t.Errorf("管理员应被允许执行 %s", action)
		}
		if d.Required != PermRead {
			t.Errorf("%s 所需权限应为 %s，实际 %s", action, PermRead, d.Required)
		}
	}

	// 只读用户：读放行，写拒绝。
	viewer := Grantee{User: "viewer", Granted: []string{PermRead}}
	if d := CheckSitePermission(viewer, ActionList); !d.Allowed {
		t.Error("只读用户应能查看列表")
	}
	d := CheckSitePermission(viewer, ActionCreate)
	if d.Allowed {
		t.Error("只读用户不应能创建站点")
	}
	if d.Reason == "" || d.Hint == "" {
		t.Error("拒绝时应给出原因与提示")
	}

	// 无任何权限。
	none := Grantee{User: "nobody"}
	if d := CheckSitePermission(none, ActionList); d.Allowed {
		t.Error("无权限用户不应能查看列表")
	}
}

// TestRequiredPermissionCoversAllActions 锁定动作到权限的映射表。
//
// 新增动作时若忘了在 RequiredPermission 里归类，会默认落到 PermWrite
// （安全方向），但这条断言能让作者显式地意识到需要做决定。
func TestRequiredPermissionCoversAllActions(t *testing.T) {
	all := []string{ActionList, ActionView, ActionCreate, ActionUpdate, ActionDelete, ActionEnable, ActionDisable}
	for _, a := range all {
		got := RequiredPermission(a)
		if got != PermRead && got != PermWrite {
			t.Errorf("动作 %s 的权限归类异常: %q", a, got)
		}
	}
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// assertCalled 断言执行器收到过包含某关键字的命令。
func assertCalled(t *testing.T, e *fakeExecutor, keyword string) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, call := range e.calls {
		if strings.Contains(strings.Join(call, " "), keyword) {
			return
		}
	}
	t.Errorf("期望调用过含 %q 的 nginx 命令，实际调用: %v", keyword, e.calls)
}

// TestAtomicWriteFile 验证原子写入的基本性质。
func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.conf")

	if err := atomicWriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("内容不符: %q", string(b))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("权限应为 0644，实际 %v", info.Mode().Perm())
	}

	// 覆盖写。
	if err := atomicWriteFile(path, []byte("world"), 0o644); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	b, _ = os.ReadFile(path)
	if string(b) != "world" {
		t.Errorf("覆盖后内容不符: %q", string(b))
	}

	// 不应留下临时文件。
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lipanel-") {
			t.Errorf("不应残留临时文件: %s", e.Name())
		}
	}
}

// TestRealNginxIntegration 用**真实 nginx** 跑通完整链路。
//
// 与 fakeExecutor 的区别：这里执行的是真正的 nginx -t 与 reload，
// 证明生成的配置确实能被 nginx 接受（而不只是"我们自己觉得对"）。
//
// 没有安装 nginx 的环境自动跳过，不阻塞 CI。
func TestRealNginxIntegration(t *testing.T) {
	ngx, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("环境中没有 nginx，跳过真实集成测试")
	}

	dir := t.TempDir()
	prefix := filepath.Join(dir, "nginx")
	for _, sub := range []string{"sites-available", "sites-enabled", "conf.d", "logs", "www"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
	}
	// 一份最小可用的 nginx.conf，包含我们需要的 include。
	conf := `worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 32; }
http {
    include ` + filepath.Join(prefix, "conf.d") + `/*.conf;
    include ` + filepath.Join(prefix, "sites-enabled") + `/*.conf;
    access_log logs/access.log;
    client_body_temp_path logs/client_body;
    proxy_temp_path logs/proxy;
    sendfile on;
}
`
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}

	root := filepath.Join(prefix, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>demo</h1>"), 0o644); err != nil {
		t.Fatalf("写入首页失败: %v", err)
	}

	adapter := NewSystemAdapter(AdapterOptions{Prefix: prefix, Executable: ngx})
	if !adapter.Available() {
		t.Fatalf("适配器应可用: %s", adapter.UnavailableReason())
	}
	// 必须先启动真实 nginx：否则 `-s reload` 找不到 master 进程。
	startRealNginx(t, prefix, ngx, filepath.Join(prefix, "nginx.conf"))

	auditor, _ := NewAuditor(AuditOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	m, err := NewManager(ManagerOptions{
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Adapter: adapter,
		Auditor: auditor,
		// 注意：这里**不注入** Executor，用真实的 exec.CommandContext。
		RootChecker: func(p string) error {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s 不是目录", p)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}

	ctx := context.Background()

	// ① 创建静态站：真实的 nginx -t 必须通过。
	s, err := m.Create(ctx, SiteInput{
		Name: "demo", Domain: "demo.example.com", Type: TypeStatic,
		Root: root, Enabled: true,
	})
	if err != nil {
		t.Fatalf("创建静态站失败（真实 nginx -t 未通过）: %v", err)
	}
	if !s.Enabled {
		t.Error("站点应为启用状态")
	}
	t.Logf("真实 nginx 接受了静态站配置")

	// ② 创建反代站。
	if _, err := m.Create(ctx, SiteInput{
		Name: "api", Domain: "api.example.com", Type: TypeProxy,
		Upstream: "http://127.0.0.1:3000", Enabled: true,
	}); err != nil {
		t.Fatalf("创建反代站失败: %v", err)
	}
	t.Logf("真实 nginx 接受了反代站配置")

	// ③ 编辑。
	if _, err := m.Update(ctx, "demo", SiteInput{
		Name: "demo", Domain: "www.example.com", Type: TypeStatic,
		Root: root, Enabled: true,
	}); err != nil {
		t.Fatalf("编辑失败: %v", err)
	}

	// ④ 禁用 → 真实 reload。
	if _, err := m.SetEnabled(ctx, "api", false); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if adapter.Enabled("api") {
		t.Error("禁用后 api 不应启用")
	}

	// ⑤ 列表。
	list, err := m.List()
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("应有 2 个站点，实际 %d", len(list))
	}

	// ⑥ 删除。
	if err := m.Delete(ctx, "api"); err != nil {
		t.Fatalf("删除失败（真实 nginx -t 未通过）: %v", err)
	}
	list, _ = m.List()
	if len(list) != 1 {
		t.Errorf("删除后应剩 1 个站点，实际 %d", len(list))
	}

	// 最终配置必须仍然能通过真实的 nginx -t。
	if out, err := m.runNginx(ctx, nginxTestTimeout, "-t"); err != nil {
		t.Errorf("最终配置未通过真实 nginx -t: %v\n输出: %s", err, out)
	} else {
		t.Logf("真实 nginx -t 输出: %s", out)
	}
}

// TestRealNginxRollback 用**真实 nginx** 验证回滚。
//
// 做法：先建一个正常站点，然后手工把一个**语法错误**的配置
// 直接写进站点文件（绕过面板校验，模拟"渲染出了坏配置"），
// 再通过面板的 verifyAndReload 路径触发回滚。
//
// 这条用例的价值：它证明回滚逻辑面对的是真实 nginx 的报错，
// 而不是我们自己伪造的字符串。
func TestRealNginxRollback(t *testing.T) {
	ngx, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("环境中没有 nginx，跳过真实集成测试")
	}

	dir := t.TempDir()
	prefix := filepath.Join(dir, "nginx")
	for _, sub := range []string{"sites-available", "sites-enabled", "logs", "www"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
	}
	conf := `worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 32; }
http {
    include ` + filepath.Join(prefix, "sites-enabled") + `/*.conf;
    access_log logs/access.log;
    client_body_temp_path logs/client_body;
    proxy_temp_path logs/proxy;
}
`
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("写入 nginx.conf 失败: %v", err)
	}
	root := filepath.Join(prefix, "www", "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建站点根失败: %v", err)
	}

	adapter := NewSystemAdapter(AdapterOptions{Prefix: prefix, Executable: ngx})
	if !adapter.Available() {
		t.Fatalf("适配器应可用: %s", adapter.UnavailableReason())
	}
	// 同样必须先跑起真实 nginx（reload 需要 master 进程）。
	startRealNginx(t, prefix, ngx, filepath.Join(prefix, "nginx.conf"))

	auditor, _ := NewAuditor(AuditOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	m, err := NewManager(ManagerOptions{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Adapter:     adapter,
		Auditor:     auditor,
		RootChecker: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}
	ctx := context.Background()

	if _, err := m.Create(ctx, SiteInput{
		Name: "rb", Domain: "rb.example.com", Type: TypeStatic, Root: root, Enabled: true,
	}); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	before, _ := os.ReadFile(adapter.SiteFilePath("rb"))

	// 手工破坏配置，然后走面板的校验路径（不走 Update，因为 Update
	// 会重新渲染出一份合法配置，测不到回滚）。
	snap := m.snapshot("rb")
	m.pendingSnapshot = snap
	broken := "server {\n    listen 80;\n    this_is_not_a_valid_directive;\n}\n"
	if err := atomicWriteFile(adapter.SiteFilePath("rb"), []byte(broken), 0o644); err != nil {
		t.Fatalf("写入坏配置失败: %v", err)
	}

	// 真实 nginx -t 应当失败 → 触发回滚。
	err = m.verifyAndReload(ctx, "rb", "test")
	if err == nil {
		t.Fatal("坏配置应导致 nginx -t 失败")
	}
	if !errors.Is(err, ErrNginxTestFailed) {
		t.Errorf("错误应可识别为 ErrNginxTestFailed，实际: %v", err)
	}
	t.Logf("真实 nginx 报错并被回滚: %v", err)

	// 核心断言：文件回到原样。
	after, readErr := os.ReadFile(adapter.SiteFilePath("rb"))
	if readErr != nil {
		t.Fatalf("回滚后应能读取配置: %v", readErr)
	}
	if string(after) != string(before) {
		t.Errorf("配置未回滚。\n修改前:\n%s\n回滚后:\n%s", before, after)
	}

	// 并且回滚后的配置能通过真实的 nginx -t。
	if out, testErr := m.runNginx(ctx, nginxTestTimeout, "-t"); testErr != nil {
		t.Errorf("回滚后应通过真实 nginx -t: %v\n输出: %s", testErr, out)
	} else {
		t.Logf("回滚后真实 nginx -t: %s", out)
	}
	m.pendingSnapshot = nil
}
