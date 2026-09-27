package plugin

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 外部插件安装流程测试
// ============================================================================
//
// 本文件覆盖安装的完整生命周期：
//
//	① 正常安装（上传 → 解压 → 校验 → 落地 → 注册）
//	② **内置插件保护**（任何情况下都不能被覆盖）
//	③ 覆盖安装（重装/升级）
//	④ 失败时的清理（不留半成品目录）
//	⑤ 各种非法输入的拒绝

// buildZip 构造一个内存中的 zip，返回其字节。
//
// files 的 key 是条目名，value 是内容。key 用 "/" 分隔（会被转成 zip 的路径）。
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// 排序保证输出稳定（map 遍历顺序随机），便于排查。
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("创建 zip 条目失败: %v", err)
		}
		if _, err := w.Write([]byte(files[name])); err != nil {
			t.Fatalf("写 zip 条目失败: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	return buf.Bytes()
}

// helloWorldZip 构造一个最小可用的 hello-world 插件包。
func helloWorldZip(t *testing.T, id string) []byte {
	t.Helper()
	return buildZip(t, map[string]string{
		DescriptorFileName: goodDescriptor(id),
		"assets/plugin.js": "export default { component: { setup() { return () => null } } }",
	})
}

// newInstallTestEnv 准备一个安装测试环境。
func newInstallTestEnv(t *testing.T) (*Manager, string) {
	t.Helper()
	pluginDir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("创建插件目录失败: %v", err)
	}
	return newExtTestManager(t), pluginDir
}

// ---------------------------------------------------------------------------
// ① 正常安装
// ---------------------------------------------------------------------------

func TestInstallFromStreamHappyPath(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)
	raw := helloWorldZip(t, "hello-world")

	res, err := m.InstallFromStream(bytes.NewReader(raw), InstallOptions{
		PluginDir:   pluginDir,
		ArchiveName: "hello-world.zip",
	})
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}

	if res.ID != "hello-world" {
		t.Errorf("ID = %q", res.ID)
	}
	if res.Files != 2 {
		t.Errorf("Files = %d，期望 2", res.Files)
	}
	if res.Replaced {
		t.Error("首次安装不应标记为覆盖")
	}

	// 目录应存在且内容完整。
	dir := filepath.Join(pluginDir, "hello-world")
	if _, err := os.Stat(filepath.Join(dir, DescriptorFileName)); err != nil {
		t.Errorf("descriptor.json 未落地: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "assets", "plugin.js")); err != nil {
		t.Errorf("前端资源未落地: %v", err)
	}

	// 应已注册。
	st, err := m.Get("hello-world")
	if err != nil {
		t.Fatalf("插件未注册: %v", err)
	}
	if st.Builtin || !st.External {
		t.Errorf("标志不正确: builtin=%v external=%v", st.Builtin, st.External)
	}

	// ########## 安装后不得残留临时文件 ##########
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".install-") || strings.HasPrefix(e.Name(), ".upload-") {
			t.Errorf("残留了临时项: %s", e.Name())
		}
	}
}

// 安装后前端资源应能直接取到（无需重启面板）。
func TestInstallMakesAssetsImmediatelyAvailable(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	if _, err := m.InstallFromStream(bytes.NewReader(helloWorldZip(t, "live")), InstallOptions{
		PluginDir:   pluginDir,
		ArchiveName: "live.zip",
	}); err != nil {
		t.Fatalf("安装失败: %v", err)
	}

	// 关键：不重新扫描、不重启，直接就能取到资源。
	fsys, ok := m.AssetFSFor("live")
	if !ok {
		t.Fatal("安装后应立即能取到前端资源")
	}
	data, err := readFileFromFS(fsys, "plugin.js")
	if err != nil {
		t.Fatalf("读取资源失败: %v", err)
	}
	if !strings.Contains(data, "export default") {
		t.Errorf("资源内容不符: %s", data)
	}
}

// 不支持的格式必须拒绝，且不落盘。
func TestInstallRejectsUnsupportedFormat(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	_, err := m.InstallFromStream(strings.NewReader("whatever"), InstallOptions{
		PluginDir:   pluginDir,
		ArchiveName: "plugin.rar",
	})
	if err == nil {
		t.Fatal("不支持的格式应被拒绝")
	}

	var ie *InstallError
	if !errors.As(err, &ie) {
		t.Fatalf("应是 *InstallError: %v", err)
	}
	if !strings.Contains(ie.Stage, "格式") {
		t.Errorf("阶段应说明是格式问题: %s", ie.Stage)
	}

	// 目录里不应留下任何东西。
	assertDirEmpty(t, pluginDir)
}

// 空文件必须拒绝。
func TestInstallRejectsEmptyUpload(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	if _, err := m.InstallFromStream(bytes.NewReader(nil), InstallOptions{
		PluginDir:   pluginDir,
		ArchiveName: "empty.zip",
	}); err == nil {
		t.Fatal("空文件应被拒绝")
	}
	assertDirEmpty(t, pluginDir)
}

// 未配置插件目录时必须明确报错（而不是静默失败）。
func TestInstallRequiresPluginDir(t *testing.T) {
	m, _ := newInstallTestEnv(t)

	_, err := m.InstallFromStream(bytes.NewReader(helloWorldZip(t, "x")), InstallOptions{
		PluginDir:   "",
		ArchiveName: "x.zip",
	})
	if err == nil {
		t.Fatal("未配置插件目录应报错")
	}
	if !strings.Contains(err.Error(), "-plugin-dir") {
		t.Errorf("错误应提示如何配置: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ② 内置插件保护（本文件最重要的一组用例）
// ---------------------------------------------------------------------------

// ########## 上传同 ID 的包绝不能替换内置插件 ##########
//
// 攻击场景：内置插件叫 sysinfo，攻击者上传一个 descriptor.json 里
// id 也是 sysinfo 的包。若允许覆盖，内置插件的后端与前端就被
// 攻击者的代码替换了——而界面上显示的仍是内置插件的名字
// （用户看的是注册信息），点进去跑的却是攻击者的代码。
func TestInstallCannotOverrideBuiltin(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	const builtinID = "hello"
	// 先注册一个"内置插件"。
	if err := m.Register(Descriptor{
		ID: builtinID, Name: "内置的 Hello", Version: "9.9.9",
		Builtin: true, Mode: ModeManaged,
		Permissions: []string{"system.read"},
	}); err != nil {
		t.Fatal(err)
	}

	// 攻击者上传同 ID 的外部插件（甚至带 Overwrite=true）。
	raw := helloWorldZip(t, builtinID)
	for _, overwrite := range []bool{false, true} {
		_, err := m.InstallFromStream(bytes.NewReader(raw), InstallOptions{
			PluginDir:   pluginDir,
			ArchiveName: "evil.zip",
			Overwrite:   overwrite,
		})
		if err == nil {
			t.Fatalf("Overwrite=%v：覆盖内置插件应被拒绝", overwrite)
		}
		if !errors.Is(err, ErrIDConflict) {
			t.Errorf("Overwrite=%v：应返回 ErrIDConflict，实际 %v", overwrite, err)
		}
	}

	// ########## 关键断言：内置插件完好无损 ##########
	got, err := m.Get(builtinID)
	if err != nil {
		t.Fatalf("内置插件消失了: %v", err)
	}
	if !got.Builtin {
		t.Error("内置插件被覆盖了（Builtin 变成了 false）")
	}
	if got.Name != "内置的 Hello" {
		t.Errorf("内置插件的 Name 被改成了 %q", got.Name)
	}
	if got.Version != "9.9.9" {
		t.Errorf("内置插件的 Version 被改成了 %q", got.Version)
	}
	if got.External {
		t.Error("内置插件被标记为外部插件")
	}

	// 磁盘上不能留下攻击者的目录。
	if _, err := os.Stat(filepath.Join(pluginDir, builtinID)); err == nil {
		t.Error("攻击者的目录被写到磁盘上了")
	}
	assertNoTempLeftovers(t, pluginDir)
}

// 已安装的同名外部插件，不带 Overwrite 时应被拒绝。
func TestInstallRejectsDuplicateWithoutOverwrite(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)
	raw := helloWorldZip(t, "dup")

	if _, err := m.InstallFromStream(bytes.NewReader(raw), InstallOptions{
		PluginDir: pluginDir, ArchiveName: "dup.zip",
	}); err != nil {
		t.Fatalf("首次安装失败: %v", err)
	}

	_, err := m.InstallFromStream(bytes.NewReader(raw), InstallOptions{
		PluginDir: pluginDir, ArchiveName: "dup.zip",
	})
	if err == nil {
		t.Fatal("重复安装（不带 Overwrite）应被拒绝")
	}
	if !errors.Is(err, ErrIDConflict) {
		t.Errorf("应返回 ErrIDConflict: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ③ 覆盖安装（重装 / 升级）
// ---------------------------------------------------------------------------

func TestInstallWithOverwriteReplacesExternal(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	// 先装 v1。
	v1 := buildZip(t, map[string]string{
		DescriptorFileName: `{"apiVersion":"1","id":"up","name":"升级测试","version":"1.0.0",
		  "frontend":{"entry":"/plugin-assets/up/plugin.js","nav_title":"升级"}}`,
		"assets/plugin.js": "v1",
	})
	if _, err := m.InstallFromStream(bytes.NewReader(v1), InstallOptions{
		PluginDir: pluginDir, ArchiveName: "up.zip",
	}); err != nil {
		t.Fatalf("首次安装失败: %v", err)
	}

	// 再装 v2（同 ID，不同版本与内容）。
	v2 := buildZip(t, map[string]string{
		DescriptorFileName: `{"apiVersion":"1","id":"up","name":"升级测试","version":"2.0.0",
		  "frontend":{"entry":"/plugin-assets/up/plugin.js","nav_title":"升级"}}`,
		"assets/plugin.js": "v2",
	})

	res, err := m.InstallFromStream(bytes.NewReader(v2), InstallOptions{
		PluginDir: pluginDir, ArchiveName: "up.zip", Overwrite: true,
	})
	if err != nil {
		t.Fatalf("覆盖安装失败: %v", err)
	}
	if !res.Replaced {
		t.Error("应标记为覆盖安装")
	}

	// 注册表里的版本应更新。
	st, err := m.Get("up")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if st.Version != "2.0.0" {
		t.Errorf("Version = %q，期望 2.0.0（注册表未更新）", st.Version)
	}

	// 磁盘上的内容应是 v2。
	data, err := os.ReadFile(filepath.Join(pluginDir, "up", "assets", "plugin.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "v2" {
		t.Errorf("磁盘内容 = %q，期望 v2", data)
	}

	// 不应有残留的备份目录。
	assertNoTempLeftovers(t, pluginDir)

	// 注册表里只能有一个 up（不能重复注册）。
	count := 0
	for _, s := range m.List() {
		if s.ID == "up" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("注册表里有 %d 个 up，期望 1", count)
	}
}

// ---------------------------------------------------------------------------
// ④ 失败时必须清理干净
// ---------------------------------------------------------------------------

// ########## 安装失败不能留半成品目录 ##########
//
// 留着半成品的后果：面板每次启动都会尝试加载它并再次失败（日志刷屏）、
// 用户看到目录存在以为装好了、想重装还得先手工删。
func TestInstallFailureLeavesNoResidue(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{
			"缺少 descriptor.json",
			map[string]string{"assets/plugin.js": "x"},
		},
		{
			"descriptor.json 非法 JSON",
			map[string]string{DescriptorFileName: "{not json"},
		},
		{
			"ID 非法",
			map[string]string{DescriptorFileName: `{"apiVersion":"1","id":"BAD","name":"x","version":"1.0.0"}`},
		},
		{
			"apiVersion 不兼容",
			map[string]string{DescriptorFileName: `{"apiVersion":"99","id":"aa","name":"x","version":"1.0.0"}`},
		},
		{
			"semver 非法",
			map[string]string{DescriptorFileName: `{"apiVersion":"1","id":"aa","name":"x","version":"latest"}`},
		},
		{
			"权限非法",
			map[string]string{DescriptorFileName: `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0","permissions":["bogus.read"]}`},
		},
		{
			"entry 指向他人资源",
			map[string]string{DescriptorFileName: `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
			  "frontend":{"entry":"/plugin-assets/other/plugin.js","nav_title":"t"}}`},
		},
		{
			"backend.exec 不存在",
			map[string]string{DescriptorFileName: `{"apiVersion":"1","id":"aa","name":"x","version":"1.0.0",
			  "backend":{"exec":"missing"}}`},
		},
		// 注意：这里**没有**"目录名与 ID 不一致"这一项。
		//
		// 安装流程刻意跳过该检查：暂存目录名是随机的（.install-*），
		// 与插件 ID 必然不同。安装器在通过校验后用 desc.ID
		// 自己命名最终目录，因此最终目录名一定与 ID 一致。
		//
		// 该检查对「磁盘扫描」路径仍然生效，由
		// TestParseExternalDescriptorDirNameMismatch 覆盖。
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, pluginDir := newInstallTestEnv(t)

			_, err := m.InstallFromStream(bytes.NewReader(buildZip(t, tc.files)), InstallOptions{
				PluginDir: pluginDir, ArchiveName: "bad.zip",
			})
			if err == nil {
				t.Fatal("非法包应被拒绝")
			}

			// ########## 核心断言：目录必须是空的 ##########
			assertDirEmpty(t, pluginDir)

			// 注册表里也不该多出条目。
			if len(m.List()) != 0 {
				t.Errorf("注册表里多了条目: %v", m.List())
			}
		})
	}
}

// zip slip 的包通过安装接口上传时同样必须被拒绝。
func TestInstallRejectsZipSlip(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)
	base := filepath.Dir(pluginDir)

	// 恶意包：先放一个合法的 descriptor.json，再带一个穿越条目。
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(DescriptorFileName)
	_, _ = w.Write([]byte(goodDescriptor("evil")))
	w, _ = zw.Create("../../../pwned.txt")
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()

	_, err := m.InstallFromStream(&buf, InstallOptions{
		PluginDir: pluginDir, ArchiveName: "evil.zip",
	})
	if err == nil {
		t.Fatal("含 zip slip 的包应被拒绝")
	}
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("应返回 ErrUnsafeArchive: %v", err)
	}

	var ie *InstallError
	if errors.As(err, &ie) && !strings.Contains(ie.Stage, "安全") {
		t.Errorf("阶段应标为安全检查: %s", ie.Stage)
	}

	// 越界文件绝不能存在。
	if _, err := os.Stat(filepath.Join(base, "pwned.txt")); err == nil {
		t.Fatal("越界文件被写出了 —— zip slip 防护失效")
	}
	assertDirEmpty(t, pluginDir)
}

// 带符号链接的包必须被拒绝。
func TestInstallRejectsSymlinkArchive(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "link"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(hdr)
	_, _ = w.Write([]byte("/etc"))
	_ = zw.Close()

	if _, err := m.InstallFromStream(&buf, InstallOptions{
		PluginDir: pluginDir, ArchiveName: "link.zip",
	}); err == nil {
		t.Fatal("含符号链接的包应被拒绝")
	}
	assertDirEmpty(t, pluginDir)
}

// ---------------------------------------------------------------------------
// ⑤ 前端-only 与带后端两种形态
// ---------------------------------------------------------------------------

// 前端-only 插件安装后不创建进程，也不自动启动。
func TestInstallFrontendOnlyPlugin(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	res, err := m.InstallFromStream(bytes.NewReader(helloWorldZip(t, "feonly2")), InstallOptions{
		PluginDir: pluginDir, ArchiveName: "p.zip",
	})
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}
	if res.Mode != ModeExternal {
		t.Errorf("Mode = %q，期望 %q（前端-only）", res.Mode, ModeExternal)
	}

	st, err := m.Get("feonly2")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateStopped {
		t.Errorf("State = %q，期望 %q", st.State, StateStopped)
	}
}

// ########## 带后端的插件安装后必须是 stopped ##########
//
// 面板常以 root 运行。安装即自动 exec = 无确认地把 root 给出去。
// 安装与运行必须是两个独立动作：用户先装、先审查，再决定启动。
func TestInstallWithBackendStaysStopped(t *testing.T) {
	m, pluginDir := newInstallTestEnv(t)

	// 包内带一个可执行文件。注意 zip 的可执行位需要显式设置。
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, _ := zw.Create(DescriptorFileName)
	_, _ = w.Write([]byte(`{"apiVersion":"1","id":"withbe2","name":"带后端","version":"1.0.0",
	  "backend":{"exec":"backend","auto_start":true}}`))

	hdr := &zip.FileHeader{Name: "backend"}
	hdr.SetMode(0o755)
	w, _ = zw.CreateHeader(hdr)
	_, _ = w.Write([]byte("#!/bin/sh\necho hi\n"))
	_ = zw.Close()

	res, err := m.InstallFromStream(&buf, InstallOptions{
		PluginDir: pluginDir, ArchiveName: "be.zip",
	})
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}
	if res.Mode != ModeManaged {
		t.Errorf("Mode = %q，期望 %q", res.Mode, ModeManaged)
	}

	// ########## 即使声明了 auto_start: true，也必须是 stopped ##########
	st, err := m.Get("withbe2")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateStopped {
		t.Errorf("State = %q，期望 %q。"+
			"auto_start 不得让核心自动执行用户上传的二进制",
			st.State, StateStopped)
	}
	if st.PID != 0 {
		t.Errorf("PID = %d，期望 0（没有进程被拉起）", st.PID)
	}
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// assertDirEmpty 断言目录里没有任何条目。
func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("目录应为空，实际有: %v", names)
	}
}

// assertNoTempLeftovers 断言没有安装过程残留的临时项。
func assertNoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".install-") ||
			strings.HasPrefix(name, ".upload-") ||
			strings.Contains(name, ".old-") {
			t.Errorf("残留了安装临时项: %s", name)
		}
	}
}

// readFileFromFS 从 fs.FS 读取文件内容（测试辅助）。
func readFileFromFS(fsys fs.FS, name string) (string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
