package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 外部插件：扫描 / 加载 / 校验测试
// ============================================================================
//
// 本文件覆盖四组用例：
//
//	① descriptor.json 的解析与严格校验（ID / semver / apiVersion / 字段名）
//	② 目录扫描（正常、缺失、单插件失败不影响其它）
//	③ ID 冲突（**外部插件绝不能覆盖内置插件**）
//	④ 前端 entry 的越界防护

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

// newExternalTestManager 构造一个用于外部插件测试的 Manager。
func newExtTestManager(t *testing.T) *Manager {
	t.Helper()

	m, err := NewManager(Options{
		SocketDir:      t.TempDir(),
		Logger:         testLogger(),
		DisableWatcher: true, // 测试里不跑崩溃监测 goroutine
	})
	if err != nil {
		t.Fatalf("构造 Manager 失败: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// writePluginDir 在 root 下造一个外部插件目录，返回其路径。
//
// descriptorJSON 为 "" 时不写 descriptor.json（用于测"缺失"用例）。
func writePluginDir(t *testing.T, root, name, descriptorJSON string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建插件目录失败: %v", err)
	}
	if descriptorJSON != "" {
		path := filepath.Join(dir, DescriptorFileName)
		if err := os.WriteFile(path, []byte(descriptorJSON), 0o644); err != nil {
			t.Fatalf("写 descriptor.json 失败: %v", err)
		}
	}
	return dir
}

// goodDescriptor 返回一份最小合法的前端-only 插件声明。
func goodDescriptor(id string) string {
	return `{
  "apiVersion": "1",
  "id": "` + id + `",
  "name": "测试插件 ` + id + `",
  "version": "1.0.0",
  "description": "用于测试",
  "permissions": ["system.read"],
  "frontend": {
    "entry": "/plugin-assets/` + id + `/plugin.js",
    "assets": "/plugin-assets/` + id + `/",
    "nav_title": "测试"
  }
}`
}

// ---------------------------------------------------------------------------
// ① descriptor.json 解析与校验
// ---------------------------------------------------------------------------

func TestParseExternalDescriptorValid(t *testing.T) {
	raw := `{
	  "apiVersion": "1",
	  "id": "hello",
	  "name": "Hello",
	  "version": "1.2.3",
	  "description": "示例",
	  "permissions": ["system.read", "process.read"],
	  "frontend": {
	    "entry": "/plugin-assets/hello/plugin.js",
	    "assets": "/plugin-assets/hello/",
	    "type": "esm",
	    "nav_title": "Hello",
	    "nav_icon": "smile"
	  }
	}`

	desc, err := ParseExternalDescriptor([]byte(raw), "hello")
	if err != nil {
		t.Fatalf("合法声明被拒绝: %v", err)
	}

	if desc.ID != "hello" {
		t.Errorf("ID = %q", desc.ID)
	}
	if desc.Version != "1.2.3" {
		t.Errorf("Version = %q", desc.Version)
	}
	// 外部插件的两个标志必须正确设置。
	if !desc.External {
		t.Error("External 应为 true")
	}
	if desc.Builtin {
		t.Error("Builtin 应为 false（外部插件不是内置插件）")
	}
	// 没有 backend → 前端-only → ModeExternal（核心不拉起进程）。
	if desc.Mode != ModeExternal {
		t.Errorf("Mode = %q，期望 %q（无 backend 时是前端-only）",
			desc.Mode, ModeExternal)
	}
	if desc.Frontend.NavTitle != "Hello" {
		t.Errorf("NavTitle = %q", desc.Frontend.NavTitle)
	}
}

// 带 backend.exec 的插件应推导为 ModeManaged（核心拉起进程）。
func TestParseExternalDescriptorWithBackend(t *testing.T) {
	raw := `{
	  "apiVersion": "1",
	  "id": "withbe",
	  "name": "带后端",
	  "version": "0.1.0",
	  "backend": { "exec": "backend" },
	  "frontend": { "entry": "/plugin-assets/withbe/plugin.js", "nav_title": "带后端" }
	}`

	desc, err := ParseExternalDescriptor([]byte(raw), "withbe")
	if err != nil {
		t.Fatalf("合法声明被拒绝: %v", err)
	}
	if desc.Mode != ModeManaged {
		t.Errorf("Mode = %q，期望 %q（有 backend.exec）", desc.Mode, ModeManaged)
	}
}

// ########## 目录名与 ID 必须一致 ##########
//
// 不一致会让"用户看到的目录名"与"实际注册的插件"对不上：
// 装的是 evil/ 但注册成了 sysinfo——用户以为装的是 A，跑的是 B。
func TestParseExternalDescriptorDirNameMismatch(t *testing.T) {
	_, err := ParseExternalDescriptor([]byte(goodDescriptor("aaa")), "bbb")
	if err == nil {
		t.Fatal("目录名与 ID 不一致时应报错")
	}
	if !strings.Contains(err.Error(), "不一致") {
		t.Errorf("错误信息未说明原因: %v", err)
	}
}

// ID 校验：只允许小写字母/数字/连字符，首位必须是字母。
func TestExternalIDValidation(t *testing.T) {
	valid := []string{"ab", "hello", "my-plugin", "a1", "plugin-2-x", strings.Repeat("a", 63)}
	for _, id := range valid {
		if !ValidExternalID(id) {
			t.Errorf("ID %q 应合法", id)
		}
	}

	invalid := []string{
		"",                      // 空
		"a",                     // 太短（至少 2 位）
		"1abc",                  // 首位不是字母
		"-abc",                  // 首位是连字符
		"Abc",                   // 含大写
		"my_plugin",             // 含下划线
		"my.plugin",             // 含点（目录穿越风险）
		"../evil",               // 目录穿越
		"a/b",                   // 含斜杠
		"abc-",                  // 以连字符结尾
		strings.Repeat("a", 64), // 太长（上限 63）
	}
	for _, id := range invalid {
		if ValidExternalID(id) {
			t.Errorf("ID %q 应被拒绝", id)
		}
	}
}

// ID 非法时必须在注册之前就拒绝。
func TestParseExternalDescriptorRejectsBadID(t *testing.T) {
	for _, bad := range []string{"Abc", "1abc", "a", "../evil", "my_plugin"} {
		raw := `{"apiVersion":"1","id":"` + bad + `","name":"x","version":"1.0.0"}`
		if _, err := ParseExternalDescriptor([]byte(raw), bad); err == nil {
			t.Errorf("ID %q 应被拒绝", bad)
		}
	}
}

// semver 校验。
func TestExternalSemverValidation(t *testing.T) {
	valid := []string{"1.0.0", "0.0.1", "v1.2.3", "1.0.0-beta.1", "1.0.0+build.5", "10.20.30"}
	for _, v := range valid {
		if !ValidSemver(v) {
			t.Errorf("%q 应是合法 semver", v)
		}
	}

	invalid := []string{"", "1.0", "1", "latest", "1.0.0.0", "v", "abc", "1..0"}
	for _, v := range invalid {
		if ValidSemver(v) {
			t.Errorf("%q 不是合法 semver，应被拒绝", v)
		}
	}

	raw := `{"apiVersion":"1","id":"aa","name":"x","version":"latest"}`
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
		t.Error("非法 version 应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// apiVersion 兼容性
// ---------------------------------------------------------------------------

func TestAPIVersionCompatibility(t *testing.T) {
	// 主版本相同 → 兼容（包括带次版本号的情况）。
	compatible := []string{"1", "1.0", "1.1", "1.99"}
	for _, v := range compatible {
		if !apiVersionCompatible(v) {
			t.Errorf("apiVersion %q 应与主版本 1 兼容", v)
		}
	}

	// 主版本不同 → 不兼容。
	incompatible := []string{"2", "2.0", "0", "3.1"}
	for _, v := range incompatible {
		if apiVersionCompatible(v) {
			t.Errorf("apiVersion %q 不应与主版本 1 兼容", v)
		}
	}
}

// apiVersion 缺失必须拒绝（不能默认成兼容）。
func TestParseExternalDescriptorRequiresAPIVersion(t *testing.T) {
	raw := `{"id":"aa","name":"x","version":"1.0.0"}`
	_, err := ParseExternalDescriptor([]byte(raw), "aa")
	if err == nil {
		t.Fatal("缺少 apiVersion 应被拒绝")
	}
	if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("错误信息未提到 apiVersion: %v", err)
	}
}

// apiVersion 不兼容时必须返回可识别的错误，且提示要能指导用户。
func TestParseExternalDescriptorRejectsIncompatibleAPIVersion(t *testing.T) {
	raw := `{"apiVersion":"2","id":"aa","name":"x","version":"1.0.0"}`
	_, err := ParseExternalDescriptor([]byte(raw), "aa")
	if err == nil {
		t.Fatal("不兼容的 apiVersion 应被拒绝")
	}
	if !errors.Is(err, ErrIncompatibleAPIVersion) {
		t.Errorf("错误应可用 errors.Is 识别为 ErrIncompatibleAPIVersion: %v", err)
	}
	// 提示里要同时提到插件声明的版本与面板支持的版本。
	if !strings.Contains(err.Error(), "2") || !strings.Contains(err.Error(), CurrentAPIVersion) {
		t.Errorf("错误信息未说清版本冲突: %v", err)
	}
}

// apiVersion 格式非法（非数字）应被拒绝。
func TestParseExternalDescriptorRejectsMalformedAPIVersion(t *testing.T) {
	for _, bad := range []string{"v1", "abc", "1.x", "-1"} {
		raw := `{"apiVersion":"` + bad + `","id":"aa","name":"x","version":"1.0.0"}`
		if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
			t.Errorf("apiVersion %q 应被拒绝", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// 严格字段校验
// ---------------------------------------------------------------------------

// ########## 拼错的字段名必须被拒绝 ##########
//
// "permission"（漏了 s）若被静默忽略，插件会注册成功但**权限为空**，
// 于是所有调用 403。作者会去查路由、查代理，唯独不会怀疑拼写。
func TestParseExternalDescriptorRejectsUnknownFields(t *testing.T) {
	raw := `{
	  "apiVersion": "1",
	  "id": "aa",
	  "name": "x",
	  "version": "1.0.0",
	  "permission": ["system.read"]
	}`
	_, err := ParseExternalDescriptor([]byte(raw), "aa")
	if err == nil {
		t.Fatal("未知字段 permission 应被拒绝（而非静默忽略）")
	}
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("错误信息应指出是哪个字段: %v", err)
	}
}

func TestParseExternalDescriptorRejectsBadJSON(t *testing.T) {
	if _, err := ParseExternalDescriptor([]byte(`{not json`), "aa"); err == nil {
		t.Error("非法 JSON 应被拒绝")
	}
	if _, err := ParseExternalDescriptor([]byte(``), "aa"); err == nil {
		t.Error("空内容应被拒绝")
	}
}

// 缺 name / version 必须拒绝。
func TestParseExternalDescriptorRequiresNameAndVersion(t *testing.T) {
	base := `{"apiVersion":"1","id":"aa","version":"1.0.0"}`
	if _, err := ParseExternalDescriptor([]byte(base), "aa"); err == nil {
		t.Error("缺少 name 应被拒绝")
	}

	base2 := `{"apiVersion":"1","id":"aa","name":"x"}`
	if _, err := ParseExternalDescriptor([]byte(base2), "aa"); err == nil {
		t.Error("缺少 version 应被拒绝")
	}
}

// 非法权限声明必须拒绝（复用内置插件的解析器）。
func TestParseExternalDescriptorRejectsBadPermissions(t *testing.T) {
	cases := []string{
		"sytem.read",              // 域拼错
		"system.read,system.read", // 同一域.动作重复
		"system",                  // 缺少动作
		"System.read",             // 域含大写
	}
	// 注意：尾随逗号（"system.read,"）是**有意允许**的简写——
	// permission.go 在 Split 后会跳过空段。因此它不是非法输入。
	for _, perm := range cases {
		raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0","permissions":["` + perm + `"]}`
		if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
			t.Errorf("非法权限 %q 应被拒绝", perm)
		}
	}
}

// ---------------------------------------------------------------------------
// ④ 前端 entry 的越界防护
// ---------------------------------------------------------------------------

// ########## entry 必须落在本插件自己的资源目录下 ##########
//
// 允许任意路径 → 插件可以把入口指向别的插件的前端（冒充），
// 或指向主程序产物，甚至站外地址。
func TestExternalFrontendEntryMustBeOwnAssets(t *testing.T) {
	bad := []string{
		"/plugin-assets/other/plugin.js",      // 指向别的插件
		"/assets/index.js",                    // 指向主程序产物
		"https://evil.example.com/x.js",       // 站外
		"//evil.example.com/x.js",             // 协议相对
		"plugin.js",                           // 相对路径
		"/plugin-assets/aa/../../../etc/x.js", // 穿越
		"/plugin-assets/aa/",                  // 只有目录，没有文件名
		"/plugin-assets/aab/plugin.js",        // 前缀相似但不是自己的目录
	}
	for _, entry := range bad {
		raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
		  "frontend":{"entry":"` + entry + `","nav_title":"t"}}`
		if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
			t.Errorf("entry %q 应被拒绝", entry)
		}
	}

	// 合法：自己的插件目录下。
	good := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
	  "frontend":{"entry":"/plugin-assets/aa/plugin.js","nav_title":"t"}}`
	if _, err := ParseExternalDescriptor([]byte(good), "aa"); err != nil {
		t.Errorf("合法的 entry 被拒绝: %v", err)
	}
}

// assets 若声明，同样必须指向自己的目录。
func TestExternalFrontendAssetsMustBeOwnDir(t *testing.T) {
	raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
	  "frontend":{"entry":"/plugin-assets/aa/plugin.js","assets":"/plugin-assets/other/","nav_title":"t"}}`
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
		t.Error("指向别的目录的 assets 应被拒绝")
	}
}

// frontend.type 只支持 esm。
func TestExternalFrontendTypeRestricted(t *testing.T) {
	raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
	  "frontend":{"entry":"/plugin-assets/aa/plugin.js","type":"umd","nav_title":"t"}}`
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
		t.Error("type=umd 应被拒绝（当前只支持 esm）")
	}
}

// 声明了 nav_title 却没有 entry：会进菜单但点了必然空页。
func TestExternalFrontendNavTitleWithoutEntry(t *testing.T) {
	raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
	  "frontend":{"nav_title":"t"}}`
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
		t.Error("有 nav_title 无 entry 应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// backend.exec 校验
// ---------------------------------------------------------------------------

// 绝对路径必须拒绝：否则插件可以声明 exec="/bin/sh" 直接拿 shell。
func TestExternalBackendExecRejectsAbsolute(t *testing.T) {
	bad := []string{
		"/bin/sh",
		"/usr/bin/env",
		"../../bin/sh",
		"a/../../sh",
		"..\\..\\sh", // Windows 变体
	}
	for _, exec := range bad {
		raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
		  "backend":{"exec":"` + strings.ReplaceAll(exec, `\`, `\\`) + `"}}`
		if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
			t.Errorf("绝对/穿越路径 %q 应被拒绝", exec)
		}
	}

	// 合法的相对路径。
	good := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
	  "backend":{"exec":"backend"}}`
	if _, err := ParseExternalDescriptor([]byte(good), "aa"); err != nil {
		t.Errorf("合法的相对 exec 被拒绝: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ② 目录扫描
// ---------------------------------------------------------------------------

func TestLoadExternalScansDirectory(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "aaa", goodDescriptor("aaa"))
	writePluginDir(t, root, "bbb", goodDescriptor("bbb"))

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(res.Loaded) != 2 {
		t.Fatalf("加载了 %d 个插件，期望 2 个（loaded=%v failed=%v）",
			len(res.Loaded), res.Loaded, res.Failed)
	}
	if len(res.Failed) != 0 {
		t.Errorf("不应有失败项: %v", res.Failed)
	}
	// 插件应真的进了注册表。
	for _, id := range []string{"aaa", "bbb"} {
		if _, err := m.Get(id); err != nil {
			t.Errorf("插件 %s 未注册: %v", id, err)
		}
	}
}

// ########## 目录不存在不是错误 ##########
//
// 默认路径 /opt/lipanel/plugins 在多数机器上不存在。
// 若这算错误，面板就起不来了——而用户根本没打算用外部插件。
func TestLoadExternalMissingDirIsNotError(t *testing.T) {
	m := newExtTestManager(t)
	res, err := m.LoadExternal(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("目录不存在不应返回错误: %v", err)
	}
	if len(res.Loaded) != 0 || len(res.Failed) != 0 {
		t.Errorf("结果应为空: %+v", res)
	}
}

// 空 pluginDir 同样不应报错（未配置该功能）。
func TestLoadExternalEmptyDirIsNoop(t *testing.T) {
	m := newExtTestManager(t)
	for _, dir := range []string{"", "   "} {
		res, err := m.LoadExternal(dir)
		if err != nil {
			t.Fatalf("空目录参数不应报错: %v", err)
		}
		if len(res.Loaded) != 0 {
			t.Errorf("结果应为空")
		}
	}
}

// ########## 单个插件失败不能影响其它插件 ##########
//
// 用户手工丢了个写错的插件进来，不能让整个目录扫描失败——
// 否则他连其它正常的插件都用不了。
func TestLoadExternalOneBadPluginDoesNotBlockOthers(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "good", goodDescriptor("good"))
	writePluginDir(t, root, "badjson", `{not json`)
	writePluginDir(t, root, "badid", `{"apiVersion":"1","id":"BAD","name":"x","version":"1.0.0"}`)
	writePluginDir(t, root, "nodesc", "") // 没有 descriptor.json
	writePluginDir(t, root, "good2", goodDescriptor("good2"))

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描不应整体失败: %v", err)
	}

	if len(res.Loaded) != 2 {
		t.Errorf("应有 2 个加载成功，实际 %v", res.Loaded)
	}
	if len(res.Failed) != 3 {
		t.Errorf("应有 3 个失败，实际 %d: %v", len(res.Failed), res.Failed)
	}
	// 每个失败都要有原因，否则用户无从下手。
	for _, f := range res.Failed {
		if f.Reason == "" {
			t.Errorf("失败项 %s 没有原因", f.Dir)
		}
	}
}

// 缺少 descriptor.json 时的错误信息要指明该放什么文件。
func TestLoadExternalMissingDescriptorMessage(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "nodesc", "")

	m := newExtTestManager(t)
	res, _ := m.LoadExternal(root)

	if len(res.Failed) != 1 {
		t.Fatalf("应有 1 个失败: %+v", res)
	}
	if !strings.Contains(res.Failed[0].Reason, DescriptorFileName) {
		t.Errorf("错误信息应提到 %s: %s", DescriptorFileName, res.Failed[0].Reason)
	}
}

// 非目录与隐藏目录应被跳过，而不是当作失败。
func TestLoadExternalSkipsNonDirsAndHidden(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "real", goodDescriptor("real"))

	// 噪音文件。
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 隐藏目录（编辑器/系统产物）。
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "__MACOSX"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(res.Loaded) != 1 || res.Loaded[0] != "real" {
		t.Errorf("应只加载 real: %v", res.Loaded)
	}
	if len(res.Failed) != 0 {
		t.Errorf("隐藏目录与文件不应算失败: %v", res.Failed)
	}
	if len(res.Skipped) != 3 {
		t.Errorf("应跳过 3 项，实际 %v", res.Skipped)
	}
}

// 声明了 backend.exec 但文件不存在：加载时就报错，而不是等启动时。
func TestLoadExternalMissingBackendExecutable(t *testing.T) {
	root := t.TempDir()
	raw := `{"apiVersion":"1","id":"nobin","name":"x","version":"1.0.0",
	  "backend":{"exec":"backend"}}`
	writePluginDir(t, root, "nobin", raw)

	m := newExtTestManager(t)
	res, _ := m.LoadExternal(root)

	if len(res.Failed) != 1 {
		t.Fatalf("缺少可执行文件应加载失败: %+v", res)
	}
	if !strings.Contains(res.Failed[0].Reason, "backend.exec") {
		t.Errorf("错误应提到 backend.exec: %s", res.Failed[0].Reason)
	}
}

// backend.exec 真实存在时加载成功。
func TestLoadExternalWithExecutable(t *testing.T) {
	root := t.TempDir()
	dir := writePluginDir(t, root, "withbin", `{"apiVersion":"1","id":"withbin",
	  "name":"x","version":"1.0.0","backend":{"exec":"backend"}}`)

	bin := filepath.Join(dir, "backend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(res.Failed) != 0 {
		t.Fatalf("不应失败: %v", res.Failed)
	}

	// 可执行文件路径应被绑定到进程句柄上。
	m.mu.RLock()
	e := m.registry["withbin"]
	m.mu.RUnlock()
	if e == nil || e.proc == nil {
		t.Fatal("插件或进程句柄未建立")
	}
	if !strings.HasSuffix(e.proc.execPath, "backend") {
		t.Errorf("execPath = %q，期望指向 backend", e.proc.execPath)
	}
}

// ---------------------------------------------------------------------------
// ③ ID 冲突：外部插件绝不能覆盖内置插件
// ---------------------------------------------------------------------------

// ########## 这是本模块最重要的一条安全规则 ##########
//
// 若允许外部插件覆盖内置插件，攻击者只需往插件目录里丢一个
// ID 为 "sysinfo" 的目录，就能替换掉内置插件的后端与前端——
// 而界面上显示的还是"系统信息（插件）"（用户看的是内置插件的注册信息），
// 点进去跑的却已经是攻击者的代码。
func TestExternalPluginCannotOverrideBuiltin(t *testing.T) {
	root := t.TempDir()

	// 先用一个假的内置插件占住 ID。
	const builtinID = "sysinfo"
	writePluginDir(t, root, builtinID, goodDescriptor(builtinID))

	m := newExtTestManager(t)

	// 手动注册一个"内置插件"（模拟 main 里 RegisterAllBuiltins 的结果）。
	if err := m.Register(Descriptor{
		ID:          builtinID,
		Name:        "系统信息（插件版）",
		Version:     "0.2.0",
		Builtin:     true,
		Mode:        ModeManaged,
		Permissions: []string{"system.read"},
	}); err != nil {
		t.Fatalf("注册内置插件失败: %v", err)
	}

	// 扫描同 ID 的外部插件。
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描不应整体失败: %v", err)
	}

	if len(res.Loaded) != 0 {
		t.Fatalf("外部插件不应加载成功: %v", res.Loaded)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("应有 1 个失败: %+v", res)
	}

	reason := res.Failed[0].Reason
	if !strings.Contains(reason, "内置插件") {
		t.Errorf("错误应说明冲突对象是内置插件: %s", reason)
	}

	// ########## 关键断言：内置插件未被篡改 ##########
	got, err := m.Get(builtinID)
	if err != nil {
		t.Fatalf("内置插件消失了: %v", err)
	}
	if !got.Builtin {
		t.Error("内置插件的 Builtin 标志被改成了 false —— 它被外部插件覆盖了")
	}
	if got.Name != "系统信息（插件版）" {
		t.Errorf("内置插件的 Name 被改成了 %q —— 它被覆盖了", got.Name)
	}
	if got.External {
		t.Error("内置插件被标记为 External —— 它被外部插件覆盖了")
	}
}

// 两个外部插件同 ID：后加载的被拒绝（而不是静默覆盖）。
func TestExternalDuplicateIDRejected(t *testing.T) {
	root := t.TempDir()
	// 造两个目录，但 descriptor 里的 ID 都是 "same"。
	// 注意目录名必须与 ID 一致，所以这里只能靠**目录名相同**
	// 之外的路径：直接用 registerExternal 验证。
	writePluginDir(t, root, "same", goodDescriptor("same"))

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(res.Loaded) != 1 {
		t.Fatalf("第一次应加载成功: %+v", res)
	}

	// 再手动构造一个同 ID 的插件注册。
	dup := &Descriptor{
		ID: "same", Name: "重复", Version: "1.0.0",
		Mode: ModeExternal, External: true, Dir: root,
	}
	if err := m.registerExternal(dup); err == nil {
		t.Fatal("重复 ID 应被拒绝")
	} else if !errors.Is(err, ErrIDConflict) {
		t.Errorf("应返回 ErrIDConflict: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 外部插件的资源文件系统
// ---------------------------------------------------------------------------

func TestExternalDirFS(t *testing.T) {
	root := t.TempDir()
	dir := writePluginDir(t, root, "aa", goodDescriptor("aa"))

	// 没有 assets/ 目录 → 返回 false（该插件没有前端资源）。
	desc := &Descriptor{ID: "aa", External: true, Dir: dir}
	if _, ok := ExternalDirFS(desc); ok {
		t.Error("没有 assets/ 目录时不应返回文件系统")
	}

	// 建 assets/ 后应可用。
	assetsDir := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "plugin.js"), []byte("export default {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys, ok := ExternalDirFS(desc)
	if !ok {
		t.Fatal("有 assets/ 目录时应返回文件系统")
	}
	data, err := fs.ReadFile(fsys, "plugin.js")
	if err != nil {
		t.Fatalf("读取 plugin.js 失败: %v", err)
	}
	if !strings.Contains(string(data), "export default") {
		t.Errorf("内容不符: %s", data)
	}
}

// ---------------------------------------------------------------------------
// 解压：zip slip 三层防御
// ---------------------------------------------------------------------------

// ########## zip slip：本期最关键的安全测试 ##########
//
// 这是真实存在过的漏洞类型（多个知名项目被 CVE 过）：
// 攻击者构造条目名 "../../etc/cron.d/evil"，解压时就写出了目标目录。
func TestSafeJoinRejectsTraversal(t *testing.T) {
	root := t.TempDir()

	bad := []string{
		"../evil.txt",
		"../../evil.txt",
		"../../../etc/passwd",
		"a/../../evil.txt", // 嵌套 ..（第一层检查要能看穿）
		"a/b/../../../evil.txt",
		"..\\evil.txt", // Windows 分隔符变体
		"a\\..\\..\\evil.txt",
		"/etc/passwd", // 绝对路径
		"/tmp/evil.txt",
		"C:/Windows/evil.txt", // 盘符
		"./../evil.txt",
		"..",
	}
	for _, name := range bad {
		if _, err := safeJoin(root, name); err == nil {
			t.Errorf("条目 %q 应被拒绝（zip slip）", name)
		}
	}
}

func TestSafeJoinAcceptsNormalPaths(t *testing.T) {
	root := t.TempDir()

	good := []string{
		"descriptor.json",
		"assets/plugin.js",
		"a/b/c/d.txt",
		"./descriptor.json",
		"a/./b.txt",
		"assets\\plugin.js", // 反斜杠会被归一化成路径分隔符
	}
	for _, name := range good {
		got, err := safeJoin(root, name)
		if err != nil {
			t.Errorf("条目 %q 应被接受: %v", name, err)
			continue
		}
		// 结果必须落在 root 之内。
		rel, err := filepath.Rel(root, got)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("条目 %q 解析到 root 之外: %s", name, got)
		}
	}
}

// 端到端：含 ../ 的 zip 必须被拒绝，且**磁盘上不能出现越界文件**。
func TestExtractZipRejectsZipSlip(t *testing.T) {
	// 在 t.TempDir() 下建两个同级目录：
	//	root/  ← 解压目标
	//	evil.txt 会被写到 root 的**上一级**（若防护失效）
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	// 第一个条目是正常文件（证明它确实是个能解的包）。
	w, err := zw.Create("descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"id":"x"}`)); err != nil {
		t.Fatal(err)
	}

	// 第二个条目是穿越攻击。
	w, err = zw.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("含 ../ 的 zip 应被拒绝")
	} else if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("应返回 ErrUnsafeArchive: %v", err)
	}

	// ########## 最重要的断言：越界文件不存在 ##########
	outside := filepath.Join(base, "evil.txt")
	if _, err := os.Stat(outside); err == nil {
		t.Fatalf("越界文件被写出了: %s —— zip slip 防护失效", outside)
	}
}

// 嵌套穿越：a/../../evil.txt。
func TestExtractZipRejectsNestedTraversal(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "nested.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("a/b/../../../evil.txt")
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("嵌套穿越应被拒绝")
	}
	if _, err := os.Stat(filepath.Join(base, "evil.txt")); err == nil {
		t.Fatal("越界文件被写出了")
	}
}

// Windows 分隔符变体：..\..\evil.txt。
func TestExtractZipRejectsBackslashTraversal(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "win.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create(`..\..\evil.txt`)
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("反斜杠穿越应被拒绝")
	}
	if _, err := os.Stat(filepath.Join(base, "evil.txt")); err == nil {
		t.Fatal("越界文件被写出了")
	}
}

// 符号链接条目必须被拒绝。
//
// 攻击手法：先放一个指向 /etc 的符号链接，再"写入"该链接下的文件。
func TestExtractZipRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "symlink.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	// 构造一个符号链接条目（Unix 模式位）。
	hdr := &zip.FileHeader{Name: "link"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("/etc")); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	_ = f.Close()

	_, err = ExtractArchive(zipPath, "zip", dst)
	if err == nil {
		t.Fatal("符号链接条目应被拒绝")
	}
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("应返回 ErrUnsafeArchive: %v", err)
	}
}

// tar.gz 的穿越同样要拦。
func TestExtractTarGzRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(base, "evil.tar.gz")
	f, _ := os.Create(tarPath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	body := []byte("pwned")
	_ = tw.WriteHeader(&tar.Header{
		Name:     "../../evil.txt",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	if _, err := ExtractArchive(tarPath, "targz", dst); err == nil {
		t.Fatal("tar.gz 穿越应被拒绝")
	}
	if _, err := os.Stat(filepath.Join(base, "evil.txt")); err == nil {
		t.Fatal("越界文件被写出了")
	}
}

// tar.gz 里的符号链接必须被拒绝。
func TestExtractTarGzRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	tarPath := filepath.Join(base, "link.tar.gz")
	f, _ := os.Create(tarPath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	_ = tw.WriteHeader(&tar.Header{
		Name: "link", Linkname: "/etc", Typeflag: tar.TypeSymlink,
	})
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	if _, err := ExtractArchive(tarPath, "targz", dst); err == nil {
		t.Fatal("tar.gz 符号链接应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// 解压：大小上限（zip bomb）
// ---------------------------------------------------------------------------

// ########## zip bomb 防御 ##########
//
// 一个几十 KB 的 zip 可以解压出几 GB。若不设上限，
// 上传一个包就能把服务器磁盘写满或把内存耗尽。
//
// 这条用例构造一个真实的高压缩比文件（全零数据），
// 验证它被压缩比检查拦下。
func TestExtractZipRejectsHighCompressionRatio(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "bomb.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	w, _ := zw.Create("bomb.bin")
	// 8 MiB 的全零数据，压缩后只有几 KB → 压缩比远超 200。
	zeros := make([]byte, 8<<20)
	if _, err := w.Write(zeros); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	_ = f.Close()

	info, _ := os.Stat(zipPath)
	t.Logf("压缩包大小 = %d 字节，解压后 8 MiB，压缩比约 %d",
		info.Size(), int64(8<<20)/max(info.Size(), 1))

	_, err := ExtractArchive(zipPath, "zip", dst)
	if err == nil {
		t.Fatal("高压缩比的 zip 应被拒绝")
	}
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("应返回 ErrUnsafeArchive: %v", err)
	}
	if !strings.Contains(err.Error(), "压缩") {
		t.Errorf("错误信息应说明是压缩比问题: %v", err)
	}
}

// 单文件超过上限应被拒绝。
//
// 注意：这里必须用**不可压缩**的随机数据，否则会先被压缩比检查拦下，
// 测不到单文件上限这条路径。
func TestExtractZipRejectsOversizedSingleFile(t *testing.T) {
	if testing.Short() {
		t.Skip("需要写 64 MiB 数据，-short 下跳过")
	}
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "big.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	w, _ := zw.Create("big.bin")
	// 声明一个超过 maxSingleFileBytes 的文件（用低压缩比的数据填充）。
	big := make([]byte, maxSingleFileBytes+1024)
	for i := range big {
		big[i] = byte(i * 7919) // 伪随机，压缩比接近 1
	}
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("超大单文件应被拒绝")
	}
}

// 条目数超过上限应在**写盘前**就拒绝。
func TestExtractZipRejectsTooManyEntries(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "many.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	// 条目数上限是 2000，这里超一点即可。
	for i := 0; i < maxExtractFiles+5; i++ {
		w, err := zw.Create("f" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)) +
			string(rune('0'+i/260)) + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	_ = zw.Close()
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("条目数超限应被拒绝")
	}
}

// 空压缩包应被拒绝（多半是打包出错）。
func TestExtractZipRejectsEmptyArchive(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "empty.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	_ = zw.Close()
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("空压缩包应被拒绝")
	}
}

// 超过压缩包自身大小上限的应被拒绝。
func TestExtractZipRejectsOversizedArchive(t *testing.T) {
	if testing.Short() {
		t.Skip("需要写 32 MiB 数据，-short 下跳过")
	}
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "huge.zip")
	f, _ := os.Create(zipPath)
	// 直接写超过上限的垃圾数据（不需要是合法 zip——
	// 大小检查发生在打开压缩包之前）。
	big := make([]byte, maxArchiveBytes+1024)
	if _, err := f.Write(big); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := ExtractArchive(zipPath, "zip", dst); err == nil {
		t.Fatal("超大压缩包应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// 解压：正常路径
// ---------------------------------------------------------------------------

func TestExtractZipHappyPath(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "root")
	_ = os.MkdirAll(dst, 0o755)

	zipPath := filepath.Join(base, "good.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	// 一个真实的插件包结构。
	files := map[string]string{
		"descriptor.json":  goodDescriptor("aa"),
		"assets/plugin.js": "export default { component: {} }",
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = zw.Close()
	_ = f.Close()

	res, err := ExtractArchive(zipPath, "zip", dst)
	if err != nil {
		t.Fatalf("正常 zip 解压失败: %v", err)
	}
	if res.Files != 2 {
		t.Errorf("解压文件数 = %d，期望 2", res.Files)
	}

	// 内容应正确落盘。
	for name := range files {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(name))); err != nil {
			t.Errorf("文件 %s 未解压出来: %v", name, err)
		}
	}

	// 解压结果应能被加载器直接读取。
	//
	// 注意目录名必须与插件 id 一致（"aa"）——这是 ParseExternalDescriptor
	// 的硬性要求，因此这里把内容放到名为 aa 的子目录里再读。
	final := filepath.Join(base, "aa")
	if err := os.Rename(dst, final); err != nil {
		t.Fatalf("重命名失败: %v", err)
	}
	if _, err := ReadExternalDescriptor(final); err != nil {
		t.Errorf("解压出的插件应可加载: %v", err)
	}
}

// 不支持的扩展名应被拒绝。
func TestExtractArchiveUnsupportedKind(t *testing.T) {
	if _, err := ExtractArchive("/nonexistent", "rar", t.TempDir()); err == nil {
		t.Error("不支持的压缩格式应被拒绝")
	}
}

func TestArchiveKindOf(t *testing.T) {
	cases := map[string]string{
		"a.zip":    "zip",
		"A.ZIP":    "zip",
		"a.tar.gz": "targz",
		"a.tgz":    "targz",
		"A.TAR.GZ": "targz",
		"a.rar":    "",
		"a":        "",
		"a.tar":    "",
	}
	for name, want := range cases {
		if got := ArchiveKindOf(name); got != want {
			t.Errorf("ArchiveKindOf(%q) = %q，期望 %q", name, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 端到端：安装流程（解压 → 校验 → 加载）
// ---------------------------------------------------------------------------

// 完整走一遍：上传的 zip → 解压 → 加载进注册表。
func TestInstallFromZipEndToEnd(t *testing.T) {
	base := t.TempDir()
	pluginDir := filepath.Join(base, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 造一个 hello-world 包。
	zipPath := filepath.Join(base, "hello-world.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)

	w, _ := zw.Create("descriptor.json")
	_, _ = w.Write([]byte(goodDescriptor("hello-world")))
	w, _ = zw.Create("assets/plugin.js")
	_, _ = w.Write([]byte("export default { component: {} }"))
	_ = zw.Close()
	_ = f.Close()

	m := newExtTestManager(t)

	// ########## 解压到**插件目录内**的临时目录 ##########
	//
	// 这里刻意不用 os.TempDir()：目标目录与临时目录若在**不同文件系统**上，
	// 最后一次 os.Rename 会失败（EXDEV: invalid cross-device link）。
	// 本用例第一次就是这么挂的——而同样的错误在真实部署里也会发生：
	// /opt 常常是一个独立分区，而 /tmp 可能是 tmpfs。
	//
	// 因此安装流程必须把临时目录建在**目标目录的父目录**下，
	// 保证最后一步的 rename 是同设备内的原子操作。
	staging := filepath.Join(pluginDir, ".install-hello-world-tmp")
	_ = os.MkdirAll(staging, 0o755)
	res, err := ExtractArchive(zipPath, "zip", staging)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("解压文件数 = %d", res.Files)
	}

	// 移到插件目录（模拟安装）——同设备内，rename 是原子的。
	final := filepath.Join(pluginDir, "hello-world")
	if err := os.Rename(staging, final); err != nil {
		t.Fatalf("移动到插件目录失败: %v", err)
	}

	// 加载。
	lr, err := m.LoadExternal(pluginDir)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(lr.Loaded) != 1 || lr.Loaded[0] != "hello-world" {
		t.Fatalf("未加载成功: %+v", lr)
	}

	// 前端资源应可取到。
	fsys, ok := m.AssetFSFor("hello-world")
	if !ok {
		t.Fatal("未取到前端资源文件系统")
	}
	data, err := fs.ReadFile(fsys, "plugin.js")
	if err != nil {
		t.Fatalf("读取前端资源失败: %v", err)
	}
	if !bytes.Contains(data, []byte("export default")) {
		t.Errorf("前端内容不符: %s", data)
	}
}

// ---------------------------------------------------------------------------
// auto_start 的行为
// ---------------------------------------------------------------------------

// ########## auto_start 当前被忽略，但必须给出警告 ##########
//
// 静默忽略是最糟的处理：用户写了 auto_start: true，面板却不启动它，
// 用户会以为插件已经在跑了。因此这里验证警告确实被触发。
func TestExternalAutoStartIsWarnedNotHonored(t *testing.T) {
	root := t.TempDir()
	raw := `{"apiVersion":"1","id":"auto","name":"x","version":"1.0.0",
	  "backend":{"exec":"backend","auto_start":true}}`
	dir := writePluginDir(t, root, "auto", raw)
	if err := os.WriteFile(filepath.Join(dir, "backend"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := newExtTestManager(t)
	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(res.Loaded) != 1 {
		t.Fatalf("应加载成功: %+v", res)
	}

	// 关键：插件注册了，但状态必须是 **stopped**。
	//
	// 面板常以 root 运行，自动 exec 一个用户上传的二进制
	// 等于无确认地给它 root。因此必须由管理员手动启动。
	st, err := m.Get("auto")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if st.State != StateStopped {
		t.Errorf("状态 = %q，期望 %q（auto_start 不得自动执行用户上传的二进制）",
			st.State, StateStopped)
	}
}

// 前端-only 插件不创建进程句柄。
func TestFrontendOnlyPluginHasNoProcess(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "feonly", goodDescriptor("feonly"))

	m := newExtTestManager(t)
	if _, err := m.LoadExternal(root); err != nil {
		t.Fatal(err)
	}

	m.mu.RLock()
	e := m.registry["feonly"]
	m.mu.RUnlock()

	if e == nil {
		t.Fatal("插件未注册")
	}
	if e.proc != nil {
		t.Error("前端-only 插件不应有进程句柄")
	}
	if e.desc.Mode != ModeExternal {
		t.Errorf("Mode = %q，期望 %q", e.desc.Mode, ModeExternal)
	}
}

// ---------------------------------------------------------------------------
// 与内置插件共存
// ---------------------------------------------------------------------------

// 外部插件与内置插件应能同时存在于注册表，且互不干扰。
func TestExternalCoexistsWithBuiltin(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "ext-one", goodDescriptor("ext-one"))
	writePluginDir(t, root, "ext-two", goodDescriptor("ext-two"))

	m := newExtTestManager(t)

	// 注册一个内置插件。
	if err := m.Register(Descriptor{
		ID: "builtin-x", Name: "内置", Version: "1.0.0",
		Builtin: true, Mode: ModeManaged, Permissions: []string{"system.read"},
	}); err != nil {
		t.Fatal(err)
	}

	res, err := m.LoadExternal(root)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(res.Loaded) != 2 {
		t.Fatalf("应加载 2 个外部插件: %+v", res)
	}

	// 三个都在。
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("注册表应有 3 个插件，实际 %d", len(list))
	}

	// 内置/外部标志正确。
	byID := map[string]Status{}
	for _, s := range list {
		byID[s.ID] = s
	}
	if !byID["builtin-x"].Builtin || byID["builtin-x"].External {
		t.Error("builtin-x 的标志不正确")
	}
	for _, id := range []string{"ext-one", "ext-two"} {
		if byID[id].Builtin || !byID[id].External {
			t.Errorf("%s 应标记为外部插件", id)
		}
	}

	// ExternalPlugins 只返回外部插件。
	ext := m.ExternalPlugins()
	if len(ext) != 2 {
		t.Errorf("ExternalPlugins 返回 %d 个，期望 2", len(ext))
	}
}

// 外部插件的 Dir 不应出现在 JSON 序列化结果里（含服务器绝对路径）。
func TestExternalPluginDirNotSerialized(t *testing.T) {
	root := t.TempDir()
	writePluginDir(t, root, "secdir", goodDescriptor("secdir"))

	m := newExtTestManager(t)
	if _, err := m.LoadExternal(root); err != nil {
		t.Fatal(err)
	}

	st, err := m.Get("secdir")
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(root)) {
		t.Errorf("Dir 泄露到了 JSON 里（含服务器绝对路径）: %s", data)
	}
	if bytes.Contains(data, []byte(`"dir"`)) {
		t.Errorf("JSON 里不应有 dir 字段: %s", data)
	}
}

// ---------------------------------------------------------------------------
// 作者信息的两种写法
// ---------------------------------------------------------------------------

// ########## 顶层平铺的 author / license 必须被接受 ##########
//
// 这是作者的第一直觉，而它错了也没有任何安全或功能后果
// （就是个署名）。用 unknown field "author" 拒绝它，
// 作者根本猜不到正确写法是塞进 "extra" 段——
// 本项目的示例包就因为这一条加载失败过。
//
// 注意：ParseExternalDescriptor 返回的是公共 Descriptor，
// 而作者信息是纯展示元数据、**不进入注册表**（见 plugin.Descriptor 定义）。
// 因此这里直接验证解析层：用同一个 strictUnmarshal 解析成 ExternalDescriptor。
func TestExternalTopLevelAuthorInfoAccepted(t *testing.T) {
	raw := `{
	  "apiVersion": "1",
	  "id": "aa",
	  "name": "x",
	  "version": "1.0.0",
	  "author": "张三",
	  "homepage": "https://example.com",
	  "license": "MIT"
	}`

	// 整条链路必须通（不再因为 author 而报 unknown field）。
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err != nil {
		t.Fatalf("顶层 author/license 应被接受: %v", err)
	}

	// 并且值确实被解析进了 Extra。
	var ext ExternalDescriptor
	if err := strictUnmarshal([]byte(raw), &ext); err != nil {
		t.Fatalf("strictUnmarshal 应接受顶层 author: %v", err)
	}
	ext.normalizeAuthorInfo()

	if ext.Extra == nil {
		t.Fatal("作者信息未被归并到 Extra")
	}
	if ext.Extra.Author != "张三" {
		t.Errorf("Author = %q，期望 张三", ext.Extra.Author)
	}
	if ext.Extra.License != "MIT" {
		t.Errorf("License = %q，期望 MIT", ext.Extra.License)
	}
	if ext.Extra.Homepage != "https://example.com" {
		t.Errorf("Homepage = %q", ext.Extra.Homepage)
	}
}

// "extra" 段写法同样可用，且它优先于顶层。
func TestExternalExtraSectionAuthorInfo(t *testing.T) {
	raw := `{
	  "apiVersion": "1",
	  "id": "aa",
	  "name": "x",
	  "version": "1.0.0",
	  "author": "顶层的",
	  "extra": { "author": "分段里的", "license": "Apache-2.0" }
	}`

	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	var ext ExternalDescriptor
	if err := strictUnmarshal([]byte(raw), &ext); err != nil {
		t.Fatal(err)
	}
	ext.normalizeAuthorInfo()

	// "extra" 段优先：它是更明确的写法。
	if ext.Extra.Author != "分段里的" {
		t.Errorf("Author = %q，期望「分段里的」（extra 段优先）", ext.Extra.Author)
	}
	if ext.Extra.License != "Apache-2.0" {
		t.Errorf("License = %q", ext.Extra.License)
	}
}

// ########## 拼错 author 仍然要拒绝 ##########
//
// 这一条界定了上面让步的边界：接受的是**那三个已知的字段名**，
// 不是"放过所有未知字段"。拼错的名字（auther）仍会被拒绝，
// 因为它可能是别的字段的笔误。
func TestExternalAuthorTypoStillRejected(t *testing.T) {
	raw := `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0","auther":"张三"}`
	if _, err := ParseExternalDescriptor([]byte(raw), "aa"); err == nil {
		t.Error("拼错的字段名仍应被拒绝")
	}
}
