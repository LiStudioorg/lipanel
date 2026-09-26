package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExecutor 记录被执行的 argv，用于断言「恶意输入绝不出现在命令里」。
//
// 这是本包最重要的测试基础设施：命令注入的防护必须能被**穷举验证**，
// 而不是靠阅读代码相信它。
type fakeExecutor struct {
	mu    sync.Mutex
	calls [][]string

	// handler 决定每次调用的返回；为 nil 时返回空输出与 nil 错误。
	handler func(args []string) (string, string, error)
}

func (f *fakeExecutor) Run(_ context.Context, name string, args []string) (string, string, error) {
	f.mu.Lock()
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	handler := f.handler
	f.mu.Unlock()

	if handler != nil {
		return handler(args)
	}
	return "", "", nil
}

func (f *fakeExecutor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// lastCall 返回最后一次执行的完整 argv。
func (f *fakeExecutor) lastCall() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

// allCalls 返回全部 argv 的扁平文本，便于整体断言。
func (f *fakeExecutor) allCalls() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sb strings.Builder
	for _, c := range f.calls {
		sb.WriteString(strings.Join(c, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// newTestManager 构造一个注入了 fakeExecutor 的 Manager（systemctl 视为存在）。
func newTestManager(t *testing.T, ex Executor) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Logger:   discardLogger(),
		Executor: ex,
		LookPath: func(string) (string, error) { return "/usr/bin/systemctl", nil },
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

// newNoSystemdManager 模拟没有 systemctl 的环境。
func newNoSystemdManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Logger:   discardLogger(),
		LookPath: func(string) (string, error) { return "", errors.New("executable file not found") },
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

// ============================================================================
// 服务名白名单（防线二）
// ============================================================================

func TestValidUnitName(t *testing.T) {
	valid := []string{
		"nginx.service",
		"cron.service",
		"ssh.service",
		"docker.service",
		"systemd-journald.service",
		"user@1000.service",
		"getty@tty1.service",
		"foo_bar.service",
		"foo:bar.service",
		"a.service",
		"my-app.service",
		"a1234567890.service",
		"foo\\bar.service",
	}
	for _, name := range valid {
		if !ValidUnitName(name) {
			t.Errorf("ValidUnitName(%q) = false，期望 true", name)
		}
	}

	invalid := []struct{ name, why string }{
		{"", "空字符串"},
		{"nginx", "无 .service 后缀也应允许？→ 形态上允许，但下面单列"},
		{"../etc/passwd", "路径穿越"},
		{"../../bin/sh", "路径穿越"},
		{"/etc/passwd", "绝对路径"},
		{"foo/bar.service", "含斜杠"},
		{"foo bar.service", "含空格"},
		{"foo;reboot.service", "含分号（命令注入）"},
		{"foo$(id).service", "含 $() 命令替换"},
		{"foo`id`.service", "含反引号命令替换"},
		{"foo|bar.service", "含管道符"},
		{"foo&bar.service", "含 & 后台符"},
		{"foo>out.service", "含重定向符"},
		{"foo\nbar.service", "含换行符"},
		{"foo\tbar.service", "含制表符"},
		{"..", "上跳段"},
		{"foo..bar.service", "含 .."},
		{"-now.service", "以连字符开头（选项注入）"},
		{"--now", "选项注入"},
		{"-H.service", "选项注入"},
		{strings.Repeat("a", MaxUnitNameLen+1) + ".service", "超长"},
		{"foo\x00.service", "含空字节"},
		{"./foo.service", "相对路径"},
		{"foo\"bar.service", "含双引号"},
		{"foo'bar.service", "含单引号"},
	}
	for _, tc := range invalid {
		if tc.name == "nginx" {
			// 显式记录：不带 .service 后缀的名字**形态合法**。
			// systemd 允许省略后缀（会按默认后缀补全），
			// 因此这里不禁止；真正的把关是 Show 的 LoadState 查询。
			if !ValidUnitName(tc.name) {
				t.Errorf("ValidUnitName(%q) = false，但无后缀名应当形态合法", tc.name)
			}
			continue
		}
		if ValidUnitName(tc.name) {
			t.Errorf("ValidUnitName(%q) = true，期望 false（%s）", tc.name, tc.why)
		}
	}
}

// TestNoArgumentInjection 是本包最关键的用例：断言恶意服务名
// 绝不会作为独立 argv 元素之外的任何形式进入命令。
func TestNoArgumentInjection(t *testing.T) {
	malicious := []string{
		"; reboot",
		"$(reboot)",
		"`reboot`",
		"&& reboot",
		"| reboot",
		"--now",
		"-H",
		"../../etc/passwd",
		"foo bar",
		"foo\nreboot",
	}

	for _, bad := range malicious {
		ex := &fakeExecutor{}
		m := newTestManager(t, ex)

		// 三个写操作都必须拒绝非法名字。
		for _, action := range []Action{ActionStart, ActionStop, ActionRestart} {
			_, err := m.Do(context.Background(), action, bad)
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("Do(%s, %q) 错误 = %v，期望 ErrInvalidName", action, bad, err)
			}
		}
		// 查询也必须拒绝。
		if _, err := m.Show(context.Background(), bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Show(%q) 错误 = %v，期望 ErrInvalidName", bad, err)
		}

		// 核心断言：非法名字被拒后，**一次命令都不该执行**。
		if n := ex.callCount(); n != 0 {
			t.Errorf("非法服务名 %q 触发了 %d 次命令执行，期望 0 次；argv=%v",
				bad, n, ex.allCalls())
		}
	}
}

// TestArgumentsPassedAsSeparateArgv 断言合法调用下，
// 服务名是**独立的 argv 元素**（而非拼进某个字符串），且带 -- 分隔符。
func TestArgumentsPassedAsSeparateArgv(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			// show 查询返回一个存在的服务。
			if len(args) > 0 && args[3] == "show" {
				return "LoadState=loaded\nActiveState=active\nSubState=running\n", "", nil
			}
			return "", "", nil
		},
	}
	m := newTestManager(t, ex)

	if _, err := m.Do(context.Background(), ActionStart, "nginx.service"); err != nil {
		t.Fatalf("Do 失败: %v", err)
	}

	// 注意：Do 的最后一次调用是**回读状态的 show**，而不是 start。
	// 因此要断言的是「存在一条 start 调用」，不能直接看 lastCall。
	// （这一点最初写错了，被这个用例抓出来。）
	//
	// 识别方式：操作调用的形态是 `... <action> -- <name>`，
	// 而 show 查询是 `... show -p X ... -- <name>`——
	// 两者的区别是操作调用里 action 紧邻 "--"（倒数第三个元素）。
	var startCall []string
	ex.mu.Lock()
	for _, c := range ex.calls {
		if len(c) >= 3 && c[len(c)-2] == "--" && c[len(c)-3] == "start" {
			startCall = c
		}
	}
	ex.mu.Unlock()

	if startCall == nil {
		t.Fatalf("未找到 start 调用；全部调用=\n%s", ex.allCalls())
	}

	// 期望形态：[/usr/bin/systemctl --no-pager --no-legend --plain start -- nginx.service]
	joined := strings.Join(startCall, " ")
	if !strings.Contains(joined, "start -- nginx.service") {
		t.Errorf("argv = %v，期望包含 %q", startCall, "start -- nginx.service")
	}
	// 服务名必须是最后一个独立元素，且不等于任何选项。
	if got := startCall[len(startCall)-1]; got != "nginx.service" {
		t.Errorf("最后一个 argv 元素 = %q，期望 nginx.service", got)
	}
	// 必须带 -- 分隔符，否则 - 开头的名字会被当作选项。
	foundSep := false
	for i, a := range startCall {
		if a == "--" && i == len(startCall)-2 {
			foundSep = true
		}
	}
	if !foundSep {
		t.Errorf("argv = %v，期望在服务名前有 -- 分隔符", startCall)
	}
	// 统一前置参数必须存在。
	for _, want := range []string{"--no-pager", "--no-legend", "--plain"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv = %v，期望包含 %s", startCall, want)
		}
	}
}

// TestNoShellInvocation 断言执行器收到的可执行文件名恒为 systemctl，
// 绝不会出现 sh/bash 之类会解释元字符的宿主。
func TestNoShellInvocation(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			if len(args) > 0 && args[3] == "show" {
				return "LoadState=loaded\nActiveState=active\nSubState=running\n", "", nil
			}
			return "", "", nil
		},
	}
	m := newTestManager(t, ex)
	if _, err := m.Do(context.Background(), ActionRestart, "nginx.service"); err != nil {
		t.Fatalf("Do 失败: %v", err)
	}

	ex.mu.Lock()
	defer ex.mu.Unlock()
	for _, call := range ex.calls {
		switch call[0] {
		case "sh", "bash", "/bin/sh", "/bin/bash", "zsh", "dash":
			t.Fatalf("检测到 shell 调用: %v —— 命令注入防线被破坏", call)
		}
	}
}

// ============================================================================
// 操作类型
// ============================================================================

func TestActionValid(t *testing.T) {
	for _, a := range []Action{ActionStart, ActionStop, ActionRestart} {
		if !a.Valid() {
			t.Errorf("Action(%q).Valid() = false，期望 true", a)
		}
	}
	for _, a := range []Action{"", "enable", "disable", "mask", "kill", "START", "status"} {
		if Action(a).Valid() {
			t.Errorf("Action(%q).Valid() = true，期望 false（不在支持范围内）", a)
		}
	}
}

func TestDoRejectsUnsupportedAction(t *testing.T) {
	ex := &fakeExecutor{}
	m := newTestManager(t, ex)

	for _, a := range []Action{"enable", "disable", "mask", "kill", ""} {
		_, err := m.Do(context.Background(), a, "nginx.service")
		if !errors.Is(err, ErrUnsupportedAction) {
			t.Errorf("Do(%q) 错误 = %v，期望 ErrUnsupportedAction", a, err)
		}
	}
	if n := ex.callCount(); n != 0 {
		t.Errorf("不支持的操作触发了 %d 次命令执行，期望 0 次", n)
	}
}

// ============================================================================
// 状态归一化
// ============================================================================

func TestNormalizeState(t *testing.T) {
	cases := []struct {
		active, sub, want string
	}{
		{"active", "running", StateRunning},
		{"active", "exited", StateRunning},
		{"reloading", "running", StateRunning},
		{"inactive", "dead", StateStopped},
		{"failed", "failed", StateFailed},
		{"activating", "start", StateActivating},
		{"deactivating", "stop", StateActivating},
		{"", "dead", StateStopped},
		{"some-future-state", "x", StateUnknown},
	}
	for _, tc := range cases {
		if got := normalizeState(tc.active, tc.sub); got != tc.want {
			t.Errorf("normalizeState(%q, %q) = %q，期望 %q", tc.active, tc.sub, got, tc.want)
		}
	}
}

// ============================================================================
// 列表解析
// ============================================================================

func TestParseUnitList(t *testing.T) {
	// 真实 systemctl 输出的形态（列对齐，DESCRIPTION 可含空格）。
	out := `  nginx.service                        loaded    active   running A high performance web server
  cron.service                         loaded    active   running Regular background program processing daemon
  apparmor.service                     loaded    inactive dead    Load AppArmor profiles
  redis-server.service                 loaded    failed   failed  Advanced key-value store

`
	got := parseUnitList(out)
	if len(got) != 4 {
		t.Fatalf("解析出 %d 条，期望 4 条；got=%+v", len(got), got)
	}

	want := Service{
		Name:        "nginx.service",
		LoadState:   "loaded",
		ActiveState: "active",
		SubState:    "running",
		State:       StateRunning,
		Description: "A high performance web server",
	}
	if got[0] != want {
		t.Errorf("第一条 = %+v，期望 %+v", got[0], want)
	}
	if got[2].State != StateStopped {
		t.Errorf("apparmor 状态 = %q，期望 %q", got[2].State, StateStopped)
	}
	if got[3].State != StateFailed {
		t.Errorf("redis 状态 = %q，期望 %q", got[3].State, StateFailed)
	}
}

func TestParseUnitListSkipsMalformedLines(t *testing.T) {
	// 空行、表头、字段不足的行都不该让解析失败（也不该产出垃圾条目）。
	out := `UNIT LOAD ACTIVE SUB DESCRIPTION
  nginx.service loaded active running Web server
  broken line
   
  not-a-service.target loaded active active Some target
`
	got := parseUnitList(out)
	if len(got) != 1 {
		t.Fatalf("解析出 %d 条，期望 1 条；got=%+v", len(got), got)
	}
	if got[0].Name != "nginx.service" {
		t.Errorf("条目名 = %q，期望 nginx.service", got[0].Name)
	}
}

// ============================================================================
// 内部服务过滤
// ============================================================================

func TestIsInternalUnit(t *testing.T) {
	internal := []string{
		"systemd-journald.service",
		"systemd-udevd.service",
		"systemd-logind.service",
		"user@1000.service",
		"user-runtime-dir@1000.service",
		"dbus.service",
		"dbus-org.freedesktop.timesync1.service",
		"foo.slice",
		"bar.scope",
		"baz.timer",
	}
	for _, name := range internal {
		if !isInternalUnit(name) {
			t.Errorf("isInternalUnit(%q) = false，期望 true（内部服务应被隐藏）", name)
		}
	}

	visible := []string{
		"nginx.service",
		"cron.service",
		"ssh.service",
		"docker.service",
		"mysql.service",
		"lipanel-test.service",
	}
	for _, name := range visible {
		if isInternalUnit(name) {
			t.Errorf("isInternalUnit(%q) = true，期望 false（用户服务不该被隐藏）", name)
		}
	}
}

func TestListFiltersInternalServices(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			// list-units 与 list-unit-files 都要给出内容：
			// List 现在合并两个来源。
			for _, a := range args {
				if a == "list-unit-files" {
					return `  nginx.service       enabled
  cron.service        enabled
`, "", nil
				}
			}
			return `  nginx.service       loaded active running Web server
  systemd-journald.service loaded active running Journal
  user@1000.service   loaded active running User manager
  cron.service        loaded active running Cron
`, "", nil
		},
	}
	m := newTestManager(t, ex)

	list, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	names := make([]string, 0, len(list))
	for _, s := range list {
		names = append(names, s.Name)
	}
	// 只剩两个用户服务，且按名称升序。
	want := []string{"cron.service", "nginx.service"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("过滤后 = %v，期望 %v", names, want)
	}
}

// TestListIncludesInstalledButNotLoadedUnits 是本阶段发现的一个真实缺陷的回归测试。
//
// 缺陷描述：只查 `list-units` 时，一个**已安装但从未启动**的服务不存在于
// 输出里（systemd 未把它载入内存）；而 `systemctl stop` 之后单元会被卸载，
// 于是「用户在面板上刚停止的服务」会从列表里消失，看起来像被删掉了，
// 也无法再启动。修复方式是合并 list-unit-files（全集）与 list-units（实时状态）。
//
// 这个用例锁死修复：只存在于 list-unit-files 的单元必须出现在结果里，
// 且状态为 stopped。
func TestListIncludesInstalledButNotLoadedUnits(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			for _, a := range args {
				if a == "list-unit-files" {
					return `  nginx.service        enabled
  lipanel-test.service disabled
  stopped-and-unloaded.service static
`, "", nil
				}
			}
			// list-units 只报告正在运行的 nginx。
			return `  nginx.service loaded active running Web server
`, "", nil
		},
	}
	m := newTestManager(t, ex)

	list, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}

	byName := map[string]Service{}
	for _, s := range list {
		byName[s.Name] = s
	}

	// 1. 已安装但未载入的单元必须出现，且状态为 stopped。
	for _, name := range []string{"lipanel-test.service", "stopped-and-unloaded.service"} {
		svc, ok := byName[name]
		if !ok {
			t.Fatalf("%s 未出现在列表中——「停止后消失」的缺陷回归了", name)
		}
		if svc.State != StateStopped {
			t.Errorf("%s 状态 = %q，期望 %q", name, svc.State, StateStopped)
		}
	}

	// 2. 运行中的单元状态必须被 list-units 的结果覆盖（而不是停在默认的 stopped）。
	if got := byName["nginx.service"].State; got != StateRunning {
		t.Errorf("nginx.service 状态 = %q，期望 %q（实时状态未覆盖）", got, StateRunning)
	}
	if got := byName["nginx.service"].UnitFileState; got != "enabled" {
		t.Errorf("nginx.service 的 UnitFileState = %q，期望 enabled（来自 list-unit-files）", got)
	}
}

func TestParseUnitFileList(t *testing.T) {
	out := `  apparmor.service              enabled         enabled
  apport-forward@.service       static          -
  not-a-service.target          enabled         enabled
  short
`
	got := parseUnitFileList(out)
	if len(got) != 2 {
		t.Fatalf("解析出 %d 条，期望 2 条；got=%+v", len(got), got)
	}
	if got[0].Name != "apparmor.service" || got[0].UnitFileState != "enabled" {
		t.Errorf("首条 = %+v，期望 apparmor.service/enabled", got[0])
	}
	// unit-files 不含运行状态，默认应为 stopped（会被 list-units 覆盖）。
	if got[0].State != StateStopped {
		t.Errorf("State = %q，期望 %q（由 list-units 覆盖）", got[0].State, StateStopped)
	}
}

func TestListIsSorted(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			for _, a := range args {
				if a == "list-unit-files" {
					return "  zzz.service enabled\n  aaa.service enabled\n  mmm.service enabled\n", "", nil
				}
			}
			return `  zzz.service loaded active running Z
  aaa.service loaded active running A
  mmm.service loaded active running M
`, "", nil
		},
	}
	m := newTestManager(t, ex)
	list, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name > list[i].Name {
			t.Fatalf("列表未按名称排序: %v", list)
		}
	}
}

func TestRunningCount(t *testing.T) {
	list := []Service{
		{Name: "a.service", State: StateRunning},
		{Name: "b.service", State: StateStopped},
		{Name: "c.service", State: StateRunning},
		{Name: "d.service", State: StateFailed},
	}
	if got := RunningCount(list); got != 2 {
		t.Errorf("RunningCount = %d，期望 2", got)
	}
	if got := RunningCount(nil); got != 0 {
		t.Errorf("RunningCount(nil) = %d，期望 0", got)
	}
}

// ============================================================================
// 错误分类（计划要求：不能裸奔报 500）
// ============================================================================

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name    string
		stderr  string
		wantErr error
	}{
		{
			"服务不存在",
			"Failed to start nonexistent-xyz.service: Unit nonexistent-xyz.service not found.",
			ErrNotFound,
		},
		{
			"权限不足-需要交互认证",
			"Failed to start cron.service: Interactive authentication required.\nSee system logs and 'systemctl status cron.service' for details.",
			ErrPermission,
		},
		{
			"权限不足-Access denied",
			"Failed to stop nginx.service: Access denied",
			ErrPermission,
		},
		{
			"权限不足-Permission denied",
			"Permission denied",
			ErrPermission,
		},
		{
			"未加载",
			"Unit foo.service not loaded.",
			ErrNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyError(tc.stderr, errors.New("exit status 1"))
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("classifyError(%q) = %v，期望匹配 %v", tc.stderr, err, tc.wantErr)
			}
		})
	}
}

func TestClassifyErrorKeepsFirstLineOnly(t *testing.T) {
	stderr := "Failed to start cron.service: Interactive authentication required.\nSee system logs and 'systemctl status cron.service' for details."
	err := classifyError(stderr, errors.New("exit status 1"))
	// 第二行的 "See system logs..." 对用户无价值，不该出现在提示里。
	if strings.Contains(err.Error(), "See system logs") {
		t.Errorf("错误信息包含了多行 stderr 的第二行: %v", err)
	}
}

func TestClassifyErrorEmptyStderrWrapsOriginal(t *testing.T) {
	orig := errors.New("fork/exec: permission denied")
	err := classifyError("", orig)
	if !errors.Is(err, orig) {
		t.Errorf("stderr 为空时应包装原始错误，got=%v", err)
	}
}

// TestNotRespondingServiceReturnsErrNotFound 覆盖「服务不存在」的端到端路径。
func TestNotRespondingServiceReturnsErrNotFound(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			if len(args) > 0 && args[3] == "show" {
				return "LoadState=not-found\nActiveState=inactive\nSubState=dead\n", "", nil
			}
			return "", "", nil
		},
	}
	m := newTestManager(t, ex)

	_, err := m.Do(context.Background(), ActionStart, "nonexistent-xyz.service")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("错误 = %v，期望 ErrNotFound", err)
	}
	// 服务不存在时只应执行 show 查询，不该真的去 start。
	if txt := ex.allCalls(); strings.Contains(txt, "start --") {
		t.Errorf("服务不存在却执行了 start: %s", txt)
	}
}

// ============================================================================
// 无 systemd 环境（计划要求：优雅降级并提示）
// ============================================================================

func TestNoSystemdDegradesGracefully(t *testing.T) {
	m := newNoSystemdManager(t)

	if m.Available() {
		t.Fatal("Available() = true，期望 false")
	}
	if m.UnavailableReason() == "" {
		t.Error("UnavailableReason() 为空，期望给出明确原因")
	}

	// 所有操作都必须返回 ErrSystemdUnavailable，而不是 panic 或空结果。
	if _, err := m.List(context.Background()); !errors.Is(err, ErrSystemdUnavailable) {
		t.Errorf("List 错误 = %v，期望 ErrSystemdUnavailable", err)
	}
	if _, err := m.Show(context.Background(), "nginx.service"); !errors.Is(err, ErrSystemdUnavailable) {
		t.Errorf("Show 错误 = %v，期望 ErrSystemdUnavailable", err)
	}
	for _, a := range []Action{ActionStart, ActionStop, ActionRestart} {
		if _, err := m.Do(context.Background(), a, "nginx.service"); !errors.Is(err, ErrSystemdUnavailable) {
			t.Errorf("Do(%s) 错误 = %v，期望 ErrSystemdUnavailable", a, err)
		}
	}

	// 构造本身不该失败：没有 systemd 时面板仍要能启动。
	if m.UnavailableReason() == "" {
		t.Error("UnavailableReason 应给出可展示的提示")
	}
}

// ============================================================================
// 超时
// ============================================================================

// slowExecutor 模拟卡住的 systemctl。
type slowExecutor struct{}

func (slowExecutor) Run(ctx context.Context, _ string, _ []string) (string, string, error) {
	<-ctx.Done()
	return "", "", ctx.Err()
}

func TestCommandTimeout(t *testing.T) {
	m, err := NewManager(Options{
		Logger:         discardLogger(),
		Executor:       slowExecutor{},
		LookPath:       func(string) (string, error) { return "/usr/bin/systemctl", nil },
		CommandTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	start := time.Now()
	_, err = m.Do(context.Background(), ActionStart, "nginx.service")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("期望超时错误，但 err = nil")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("错误 = %v，期望 ErrTimeout", err)
	}
	// Do 内部会做 3 次 systemctl 调用（存在性检查 / 操作 / 状态回读），
	// 每次都应遵循配置的 50ms 超时，因此总耗时应在百毫秒量级。
	// 早期版本这两次查询用了固定的 15s 列表超时，实际耗时 15s——
	// 这条断言就是用来锁死「配置的超时对 Do 的全部子调用都生效」的。
	if elapsed > 1*time.Second {
		t.Errorf("耗时 %v，远超配置的 3×50ms——说明有子调用未遵循配置超时", elapsed)
	}
}

// ============================================================================
// 并发安全
// ============================================================================

func TestManagerConcurrentUse(t *testing.T) {
	ex := &fakeExecutor{
		handler: func(args []string) (string, string, error) {
			if len(args) > 0 && args[3] == "show" {
				return "LoadState=loaded\nActiveState=active\nSubState=running\n", "", nil
			}
			return "", "", nil
		},
	}
	m := newTestManager(t, ex)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := m.List(context.Background()); err != nil {
				t.Errorf("List 失败: %v", err)
			}
			if _, err := m.Show(context.Background(), fmt.Sprintf("svc%d.service", i)); err != nil {
				t.Errorf("Show 失败: %v", err)
			}
			m.Auditor().Record(AuditEvent{Target: "x.service", Action: "start"})
		}(i)
	}
	wg.Wait()
}

func TestParseBoolHelper(t *testing.T) {
	if !parseBool("true") || parseBool("false") || parseBool("garbage") {
		t.Error("parseBool 行为异常")
	}
}
