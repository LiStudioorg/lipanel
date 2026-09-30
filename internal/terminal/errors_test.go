package terminal

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// ============================================================================
// 平台能力与优雅降级测试（阶段五 5.1）
// ============================================================================
//
// #################### 本文件为什么重要 ####################
//
// "优雅降级"的代码有一个共同的尴尬：**它只在别的平台上运行**。
// 在 Linux 开发机上，README 里写着"Windows 会返回不支持"，
// 但那一行代码永远不会被执行，也永远不会被测试覆盖——
// 直到用户在 Windows 上打开面板，发现是一个红色报错或白屏。
//
// 破解办法就是把平台判定拆成**接收 goos 参数的纯函数**
// （见 errors.go 的 supportedFor / unsupportedReasonFor），
// 于是可以在 Linux 上断言 Windows 的行为。

// 纯函数必须对每个平台给出正确的判定。
func TestSupportedForAllPlatforms(t *testing.T) {
	cases := []struct {
		goos string
		want bool
	}{
		// creack/pty 有真实实现的平台（与 pty_unsupported.go 的约束一致）
		{"linux", true},
		{"darwin", true},
		{"freebsd", true},
		{"dragonfly", true},
		{"netbsd", true},
		{"openbsd", true},
		{"solaris", true},
		{"zos", true},

		// 无 PTY 实现的平台 —— 必须降级而不是崩溃
		{"windows", false},
		{"plan9", false},
		{"js", false},
		{"aix", false},
		{"android", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			if got := supportedFor(tc.goos); got != tc.want {
				t.Errorf("supportedFor(%q) = %v，期望 %v", tc.goos, got, tc.want)
			}
		})
	}
}

// Windows 必须被判为不支持 —— 这是发布矩阵里的三个真实目标。
//
// 单独一个用例（而非塞进上表）是为了让它在失败时**最显眼**：
// 一旦有人误把 windows 加进 support 列表，CI 里第一个红的就是它。
func TestWindowsIsUnsupported(t *testing.T) {
	if supportedFor("windows") {
		t.Fatal("windows 被判为支持 Web 终端。" +
			"Windows 没有 POSIX 伪终端，pty.Start 会返回 ErrUnsupported，" +
			"把它当支持会让用户在 Windows 上拿到一个失败的终端")
	}
}

// 降级文案必须同时包含「技术原因」与「可行动建议」，
// 并且明确告知其它功能不受影响。
//
// 这是前端 n-alert 里直接展示给用户的文本，写得含糊就等于没写。
func TestWindowsReasonIsActionable(t *testing.T) {
	reason := unsupportedReasonFor("windows")

	if !strings.Contains(reason, "PTY") {
		t.Errorf("未说明技术原因（PTY）: %q", reason)
	}
	if !strings.Contains(reason, "Linux") {
		t.Errorf("未说明该去哪儿用: %q", reason)
	}
	// 避免用户以为整个面板在 Windows 上不可用。
	for _, fn := range []string{"服务", "文件", "网站", "SSL", "软件商店"} {
		if !strings.Contains(reason, fn) {
			t.Errorf("未说明「%s」功能不受影响: %q", fn, reason)
		}
	}
}

// 支持的平台上不产生原因文本（供 omitempty 使用）。
func TestSupportedPlatformsHaveNoReason(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		if got := unsupportedReasonFor(goos); got != "" {
			t.Errorf("supportedFor(%q)=true 时 reason 应为空，实际 %q", goos, got)
		}
	}
}

// 未知平台也要给出可读文案（不能是空串，否则前端弹一个空提示）。
func TestUnknownPlatformReasonNotEmpty(t *testing.T) {
	for _, goos := range []string{"plan9", "js", "aix"} {
		got := unsupportedReasonFor(goos)
		if strings.TrimSpace(got) == "" {
			t.Errorf("%q 的降级文案为空", goos)
		}
		if !strings.Contains(got, goos) {
			t.Errorf("%q 的文案未提及平台名: %q", goos, got)
		}
	}
}

// 本机平台的行为必须与纯函数一致（防止两者漂移）。
func TestCurrentCapabilityMatchesHost(t *testing.T) {
	cap := CurrentCapability()

	if cap.OS != runtime.GOOS {
		t.Errorf("Capability.OS = %q，期望 %q", cap.OS, runtime.GOOS)
	}
	if cap.Supported != supportedFor(runtime.GOOS) {
		t.Errorf("Capability.Supported = %v，与 supportedFor(%q) 不一致",
			cap.Supported, runtime.GOOS)
	}
	if Supported() != supportedFor(runtime.GOOS) {
		t.Error("Supported() 与 supportedFor(runtime.GOOS) 不一致")
	}

	// 不支持时必须有原因 + 建议；支持时两者都必须为空。
	if cap.Supported {
		if cap.Reason != "" || cap.Hint != "" {
			t.Errorf("支持的平台上不应带 Reason/Hint: %q / %q", cap.Reason, cap.Hint)
		}
	} else {
		if cap.Reason == "" {
			t.Error("不支持的平台上 Reason 为空，前端会弹空提示")
		}
		if cap.Hint == "" {
			t.Error("不支持的平台上 Hint 为空")
		}
	}
}

// ErrUnsupported 必须能被 errors.Is 判定。
//
// 上层（server 层的 501 分支）依赖这一点做精确分类；
// 若它退化成字符串比较，一次补丁升级就会静默失效。
func TestErrUnsupportedIsMatchable(t *testing.T) {
	wrapped := errors.Join(ErrUnsupported, errors.New("underlying"))
	if !errors.Is(wrapped, ErrUnsupported) {
		t.Fatal("errors.Is 无法匹配 ErrUnsupported")
	}

	// 常见包装形态也必须可判定。
	doubleWrapped := errors.Join(errors.Join(ErrUnsupported))
	if !errors.Is(doubleWrapped, ErrUnsupported) {
		t.Fatal("双层包装后 errors.Is 失败")
	}

	// 不相关的错误不能被误判为不支持。
	if errors.Is(errors.New("terminal: 别的错误"), ErrUnsupported) {
		t.Fatal("无关错误被误判为 ErrUnsupported")
	}
}

// wrapUnsupported 只翻译库里真正的不支持错误，其它错误原样放行。
func TestWrapUnsupportedOnlyTranslatesPtyUnsupported(t *testing.T) {
	// nil 进 nil 出。
	if got := wrapUnsupported(nil); got != nil {
		t.Errorf("wrapUnsupported(nil) = %v，期望 nil", got)
	}

	// 普通错误不应被当成"不支持"（否则真实故障会被说成平台限制）。
	ordinary := errors.New("fork/exec /bin/sh: no such file or directory")
	if got := wrapUnsupported(ordinary); got != nil {
		t.Errorf("普通错误被误判为不支持: %v", got)
	}
}

// 在真实的不支持平台上，创建会话必须返回 ErrUnsupported 且不留进程。
//
// 本用例只在非 PTY 平台（Windows）生效；在 Linux 上跳过。
// 它的价值是将来真的在 Windows 上跑测试时能验证端到端行为。
func TestCreateReturnsErrUnsupportedOnUnsupportedPlatform(t *testing.T) {
	if Supported() {
		t.Skipf("当前平台 %s 支持 PTY，跳过降级路径的端到端验证"+
			"（该分支的行为已由 supportedFor 的纯函数测试覆盖）", runtime.GOOS)
	}

	// 不支持时 NewManager 必须**成功**（而不是让面板启动失败）。
	mgr, err := NewManager(ManagerOptions{Logger: testLogger()})
	if err != nil {
		t.Fatalf("不支持的平台上 NewManager 应当优雅降级而不是报错: %v", err)
	}

	_, err = mgr.Create("tester", 80, 24)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Create 的错误 = %v，期望 ErrUnsupported", err)
	}
	if mgr.Count() != 0 {
		t.Errorf("创建失败后会话数 = %d，期望 0", mgr.Count())
	}

	// status 必须如实报告不支持。
	if mgr.Supported() {
		t.Error("Manager.Supported() 为 true")
	}
	if mgr.Capability().Reason == "" {
		t.Error("Capability().Reason 为空")
	}
}
