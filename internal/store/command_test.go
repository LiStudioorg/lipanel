package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 命令组装测试（纯函数，可穷举）
// ============================================================================

// TestBuildAptInstall 验证 apt 安装命令的 argv。
func TestBuildAptInstall(t *testing.T) {
	c, err := BuildAptInstall("/usr/bin/apt-get", []string{"php8.3-fpm", "php8.3-cli"})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if c.Name != "/usr/bin/apt-get" {
		t.Fatalf("Name = %q", c.Name)
	}
	want := []string{"install", "-y", "--no-install-recommends",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"php8.3-fpm", "php8.3-cli"}
	if strings.Join(c.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("Args = %v\nwant %v", c.Args, want)
	}
	// 绝不能出现 shell 与分隔符。
	joined := strings.Join(c.Args, " ")
	for _, bad := range []string{";", "&&", "|", "`", "$(", "sh -c", "/bin/sh"} {
		if strings.Contains(joined, bad) {
			t.Errorf("argv 里出现了 %q", bad)
		}
	}
	if c.Args[0] != "install" {
		t.Errorf("第一条参数应是子命令，实际 %v", c.Args)
	}
}

// TestBuildCommandsRejectInjection 穷举命令组装层的注入载荷。
//
// 这是"安全底线"的第二道闸门（第一道是 validate.go 的白名单）：
// 即使有调用点绕过校验直接传包名，组装函数也必须拒绝。
func TestBuildCommandsRejectInjection(t *testing.T) {
	payloads := []string{
		"php; id", "php && id", "php|id", "php`id`", "php$(id)",
		"../../etc/passwd", "-rf", "--force-yes", "php\nid", "php id",
	}
	builders := map[string]func(pkgs []string) (Command, error){
		"apt-install":   func(p []string) (Command, error) { return BuildAptInstall("/usr/bin/apt-get", p) },
		"apt-remove":    func(p []string) (Command, error) { return BuildAptRemove("/usr/bin/apt-get", p) },
		"rpm-install":   func(p []string) (Command, error) { return BuildRPMInstall("/usr/bin/dnf", p) },
		"rpm-remove":    func(p []string) (Command, error) { return BuildRPMRemove("/usr/bin/dnf", p) },
		"dpkg-query":    func(p []string) (Command, error) { return BuildDpkgQuery("/usr/bin/dpkg-query", p) },
		"rpm-query":     func(p []string) (Command, error) { return BuildRPMQuery("/usr/bin/rpm", p) },
		"rpm-avail":     func(p []string) (Command, error) { return BuildRPMAvailable("/usr/bin/dnf", p[0]) },
		"apt-candidate": func(p []string) (Command, error) { return BuildAptCandidate("/usr/bin/apt-cache", p[0]) },
	}
	for name, build := range builders {
		for _, payload := range payloads {
			if _, err := build([]string{payload}); err == nil {
				t.Errorf("%s 未拒绝载荷 %q", name, payload)
			}
		}
	}
}

// TestBuildRPMCommands 验证 rpm 系命令组装。
func TestBuildRPMCommands(t *testing.T) {
	inst, err := BuildRPMInstall("/usr/bin/dnf", []string{"nodejs"})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if !strings.Contains(strings.Join(inst.Args, " "), "--setopt=install_weak_deps=False") {
		t.Errorf("rpm 安装应禁用弱依赖（等价于 apt 的 --no-install-recommends）: %v", inst.Args)
	}
	if inst.Args[len(inst.Args)-1] != "nodejs" {
		t.Errorf("包名应在最后: %v", inst.Args)
	}

	rem, err := BuildRPMRemove("/usr/bin/yum", []string{"redis"})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if strings.Join(rem.Args, " ") != "-y remove redis" {
		t.Errorf("卸载参数 = %v", rem.Args)
	}

	avail, err := BuildRPMAvailable("/usr/bin/dnf", "nodejs")
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	// --showduplicates 必须存在：否则 dnf 只列最新版，无法确认指定版本是否存在。
	if !strings.Contains(strings.Join(avail.Args, " "), "--showduplicates") {
		t.Errorf("可用版本查询必须带 --showduplicates: %v", avail.Args)
	}
}

// TestBuildDpkgQueryFormat 验证 dpkg 查询的格式串。
//
// 格式串必须带 ${db:Status-Abbrev}：只看 ${Version} 会把
// "已卸载但残留配置（rc）"的包也算成已安装。
func TestBuildDpkgQueryFormat(t *testing.T) {
	c, err := BuildDpkgQuery("/usr/bin/dpkg-query", []string{"nginx"})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	joined := strings.Join(c.Args, " ")
	if !strings.Contains(joined, "db:Status-Abbrev") {
		t.Fatalf("格式串缺少状态标记: %v", c.Args)
	}
	if !strings.Contains(joined, "${Package}") || !strings.Contains(joined, "${Version}") {
		t.Fatalf("格式串缺少包名或版本: %v", c.Args)
	}
}

// TestBuildDownloadAndExtract 验证下载与解包命令。
func TestBuildDownloadAndExtract(t *testing.T) {
	dl, err := BuildDownload("/usr/bin/curl",
		"https://nodejs.org/dist/latest-v22.x/node-v22.14.0-linux-x64.tar.gz",
		"/var/lib/lipanel/store/cache/nodejs-22.tar.gz")
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	joined := strings.Join(dl.Args, " ")
	if !strings.Contains(joined, "-fsSL") || !strings.Contains(joined, "--retry") {
		t.Errorf("下载参数缺少失败即错/重试: %v", dl.Args)
	}
	if !strings.Contains(joined, "-- https://") {
		t.Errorf("URL 前应有 -- 分隔符: %v", dl.Args)
	}

	ex, err := BuildExtract("/usr/bin/tar",
		"/var/lib/lipanel/store/cache/nodejs-22.tar.gz", "/usr/local/lib/lipanel/nodejs-22")
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	exJoined := strings.Join(ex.Args, " ")
	want := "-xzf /var/lib/lipanel/store/cache/nodejs-22.tar.gz -C /usr/local/lib/lipanel/nodejs-22 --strip-components=1"
	if exJoined != want {
		t.Errorf("解包参数 =\n  %s\nwant\n  %s", exJoined, want)
	}

	// 非法路径必须被拒（archive/dest 都是固定路径）。
	if _, err := BuildDownload("/usr/bin/curl", "https://x.test/a.tar.gz", "/tmp/../etc/passwd"); err == nil {
		t.Error("含 .. 的下载目标应被拒绝")
	}
	// http 必须被拒。
	if _, err := BuildDownload("/usr/bin/curl", "http://x.test/a.tar.gz", "/tmp/a.tar.gz"); err == nil {
		t.Error("http 下载应被拒绝")
	}
}

// TestBuildKeyDownload 验证 GPG 公钥下载命令。
func TestBuildKeyDownload(t *testing.T) {
	c, err := BuildCurlKeyDownload("/usr/bin/curl",
		"https://packages.sury.org/php/apt.gpg", "/usr/share/keyrings/lipanel-sury-php.gpg")
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if !strings.Contains(strings.Join(c.Args, " "), "-o /usr/share/keyrings/lipanel-sury-php.gpg") {
		t.Errorf("参数 = %v", c.Args)
	}
	if _, err := BuildCurlKeyDownload("/usr/bin/curl", "https://x.test/k", "/etc/../etc/shadow"); err == nil {
		t.Error("含 .. 的 keyring 路径应被拒绝")
	}
}

// TestBuildOfficialScript 验证唯一的 shell 形态命令。
func TestBuildOfficialScript(t *testing.T) {
	p, err := BuildOfficialScript("/usr/bin/curl", "https://deb.nodesource.com/setup_22.x")
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if p.Cmd != "curl -fsSL --retry 2 --connect-timeout 15 -- 'https://deb.nodesource.com/setup_22.x' | sh" {
		t.Fatalf("脚本命令 = %q", p.Cmd)
	}
	// 管道右侧固定是 sh，不可能被清单改成别的东西。
	if !strings.HasSuffix(p.Cmd, "| sh") {
		t.Error("管道右侧必须是 sh")
	}
	// URL 非法时拒绝（这些载荷若进入 shell 就是命令注入）。
	for _, bad := range []string{
		"https://x.test/$(id)", "https://x.test/`id`", "https://x.test/a';id;'",
		"https://x.test/a|id", "https://x.test/a;id", "http://x.test/a",
	} {
		if _, err := BuildOfficialScript("/usr/bin/curl", bad); err == nil {
			t.Errorf("脚本 URL %q 应被拒绝", bad)
		}
	}
	// curl 路径也过白名单。
	if _, err := BuildOfficialScript("curl; id", "https://x.test/a"); err == nil {
		t.Error("非法 curl 路径应被拒绝")
	}
}

// TestPickIndexedFile 验证从官方索引里挑文件名。
func TestPickIndexedFile(t *testing.T) {
	index := strings.Join([]string{
		"abcdef0123456789  node-v22.14.0-linux-arm64.tar.gz",
		"1234567890abcdef *node-v22.14.0-linux-x64.tar.gz",
		"aaaabbbbccccdddd  node-v22.14.0-linux-armv7l.tar.gz",
		"ffffffffffffffff  node-v22.14.0.tar.gz",
		"1111111111111111  node-v22.14.0-linux-x64.msi",
		"",
		"garbage line without two fields",
	}, "\n")

	got := PickIndexedFile(index, "node-v", "-linux-x64.tar.gz")
	if got != "node-v22.14.0-linux-x64.tar.gz" {
		t.Fatalf("got %q", got)
	}
	// 索引里带路径的文件名一律不取（格式变了就该失败，而不是拼出子目录 URL）。
	got = PickIndexedFile("aaaa  sub/dir/node-v22.14.0-linux-x64.tar.gz", "node-v", "-linux-x64.tar.gz")
	if got != "" {
		t.Fatalf("带路径的文件名不应被取用，got %q", got)
	}
	// 没有匹配时返回空串。
	if got := PickIndexedFile(index, "php-", "-linux-x64.tar.gz"); got != "" {
		t.Fatalf("不该匹配到 %q", got)
	}
	// 多个匹配时取版本最大的。
	multi := "a  node-v20.1.0-linux-x64.tar.gz\nb  node-v22.14.0-linux-x64.tar.gz\nc  node-v22.9.0-linux-x64.tar.gz"
	if got := PickIndexedFile(multi, "node-v", "-linux-x64.tar.gz"); got != "node-v22.14.0-linux-x64.tar.gz" {
		t.Fatalf("应取最大版本，got %q", got)
	}
}

// TestJoinURLFile 验证索引目录与文件名拼接。
func TestJoinURLFile(t *testing.T) {
	got, err := JoinURLFile("https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt", "node-v22.14.0-linux-x64.tar.gz")
	if err != nil {
		t.Fatalf("拼接失败: %v", err)
	}
	want := "https://nodejs.org/dist/latest-v22.x/node-v22.14.0-linux-x64.tar.gz"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := JoinURLFile("https://x.test/SHA", "../../etc/passwd"); err == nil {
		t.Error("含路径分隔符的文件名应被拒绝")
	}
	if _, err := JoinURLFile("https://x.test", "a.tar.gz"); err == nil {
		t.Error("索引 URL 没有目录时应被拒绝")
	}
}

// TestParseAptPolicyCandidate 验证 apt-cache policy 解析。
func TestParseAptPolicyCandidate(t *testing.T) {
	out := `nginx:
  Installed: (none)
  Candidate: 1.26.2-1~jammy
  Version table:
     1.26.2-1~jammy 500
        500 https://nginx.org/packages/ubuntu jammy/nginx amd64 Packages
`
	if got := ParseAptPolicyCandidate(out); got != "1.26.2-1~jammy" {
		t.Fatalf("got %q", got)
	}
	// 没有候选版本。
	none := "php7.4-fpm:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n"
	if got := ParseAptPolicyCandidate(none); got != "" {
		t.Fatalf("无候选时应返回空，got %q", got)
	}
	// 格式不认识时**不猜**。
	if got := ParseAptPolicyCandidate("some unexpected output\n"); got != "" {
		t.Fatalf("无法解析时应返回空，got %q", got)
	}
	// 缩进变化（apt 在不同版本里缩进不同）不影响解析。
	if got := ParseAptPolicyCandidate("p:\nCandidate:   7.0.15-1rl1\n"); got != "7.0.15-1rl1" {
		t.Fatalf("got %q", got)
	}
}

// TestParseDpkgQuery 验证 dpkg-query 输出解析。
func TestParseDpkgQuery(t *testing.T) {
	out := "php8.3-fpm|8.3.13-1+ubuntu22.04.1+deb.sury.org+1|ii \n" +
		"php8.3-cli|8.3.13-1+ubuntu22.04.1+deb.sury.org+1|ii \n" +
		"redis-server|5:7.0.15-1|rc \n" + // 已卸载但残留配置：不算安装
		"nginx|1.18.0-6ubuntu14|iF \n" // 配置未完成：不算安装
	got := ParseDpkgQuery(out)
	if len(got) != 2 {
		t.Fatalf("应只识别 2 个真正装好的包，got %v", got)
	}
	if got["php8.3-fpm"] != "8.3.13-1+ubuntu22.04.1+deb.sury.org+1" {
		t.Errorf("版本解析错误: %v", got)
	}
	if _, ok := got["nginx"]; ok {
		t.Error("iF（配置未完成）不应算已安装")
	}
	if _, ok := got["redis-server"]; ok {
		t.Error("rc（残留配置）不应算已安装")
	}
}

// TestParseRPMQuery 验证 rpm 查询输出解析（含"未安装"提示行）。
func TestParseRPMQuery(t *testing.T) {
	out := "nodejs|22.14.0\npackage redis is not installed\nnginx|1.26.2\n\n"
	got := ParseRPMQuery(out)
	if len(got) != 2 {
		t.Fatalf("应识别 2 个包，got %v", got)
	}
	if got["nodejs"] != "22.14.0" || got["nginx"] != "1.26.2" {
		t.Fatalf("解析错误: %v", got)
	}
}

// TestParseRPMAvailable 验证 dnf 可用版本解析。
func TestParseRPMAvailable(t *testing.T) {
	out := `Available Packages
nodejs.x86_64                 1:18.20.4-1.el9          nodesource-nodejs
nodejs.x86_64                 1:20.17.0-1.el9          nodesource-nodejs
nodejs.x86_64                 1:22.14.0-1.el9          nodesource-nodejs
`
	got := ParseRPMAvailable(out)
	if len(got) != 3 {
		t.Fatalf("应解析出 3 个版本，got %v", got)
	}
	// 表头行必须被过滤（它只有一个字段）。
	for _, v := range got {
		if strings.Contains(v, "Available") {
			t.Errorf("表头被当成版本: %v", got)
		}
	}
}

// TestParseAptUpdateFailure 验证从冗长输出里提取原因。
func TestParseAptUpdateFailure(t *testing.T) {
	out := `Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Ign:2 https://packages.sury.org/php jammy InRelease
Err:2 https://packages.sury.org/php jammy InRelease
  404  Not Found
Reading package lists...
E: The repository 'https://packages.sury.org/php jammy InRelease' is not signed.
`
	got := ParseAptUpdateFailure(out)
	if !strings.Contains(got, "not signed") {
		t.Fatalf("应提取 E: 行，got %q", got)
	}
	// 没有 E:/W: 时退回首行。
	if got := ParseAptUpdateFailure("\n\nsomething bad\nmore\n"); got != "something bad" {
		t.Fatalf("got %q", got)
	}
}

// TestRenderCommand 验证展示文本的引号处理（复制到终端能原样跑）。
func TestRenderCommand(t *testing.T) {
	got := RenderCommand("/usr/bin/apt-get", []string{"install", "-y", "--", "a b"})
	want := "/usr/bin/apt-get install -y -- 'a b'"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// 含单引号的参数用 '\'' 转义（POSIX 唯一可靠写法）。
	got = RenderCommand("sh", []string{"-c", "echo 'x'"})
	if !strings.Contains(got, `'\''`) {
		t.Fatalf("单引号未正确转义: %q", got)
	}
}

// TestVersionMatches 穷举版本匹配（"版本校验"的核心判定）。
func TestVersionMatches(t *testing.T) {
	cases := []struct {
		have, want string
		ok         bool
	}{
		{"8.3.13-1+ubuntu22.04.1+deb.sury.org+1", "8.3", true},
		{"1:8.0.36-0ubuntu0.22.04.1", "8.0", true},
		{"5:7.0.15-1rl1", "7.0", true},
		{"22.14.0-1nodesource1", "22", true},
		{"1:22.14.0-1.el9", "22", true},
		{"8.3.13", "8.3", true},
		{"8.3", "8.3", true},
		// 关键负例：Ubuntu 22.04 的 nodejs 是 12.x，用户选了 22 —— 必须不匹配。
		{"12.22.9~dfsg-1ubuntu3.2", "22", false},
		{"18.19.1+dfsg-6ubuntu5", "20", false},
		{"6.0.16-1ubuntu0.1", "7.0", false},
		{"1.18.0-6ubuntu14", "1.26", false},
		// 段数不足。
		{"8", "8.3", false},
		// 空输入。
		{"", "8.3", false},
		{"8.3", "", false},
		// 前缀纠缠："2" 不应匹配 "22.14.0"。
		{"22.14.0", "2", false},
	}
	for _, tc := range cases {
		if got := VersionMatches(tc.have, tc.want); got != tc.ok {
			t.Errorf("VersionMatches(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}

// ============================================================================
// apt / yum（dnf）适配测试（计划要求："apt/yum 适配"测试）
// ============================================================================

// TestDetectVarsUbuntu 验证 Ubuntu 环境探测。
func TestDetectVarsUbuntu(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy
`)
	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		GOARCH:        "amd64",
		LookPath:      fakeLookPath("apt-get", "apt-cache", "dpkg-query", "curl", "tar"),
	})
	if v.Family != FamilyDebian {
		t.Errorf("Family = %q", v.Family)
	}
	if v.Manager != PackageManagerAPT {
		t.Errorf("Manager = %q", v.Manager)
	}
	if v.Codename != "jammy" {
		t.Errorf("Codename = %q", v.Codename)
	}
	if v.Arch != "x64" {
		t.Errorf("Arch = %q", v.Arch)
	}
	if !v.Available() || !v.SupportsOfficialSource() {
		t.Errorf("应可用且支持官方源: %+v", v)
	}
	if v.Tools.DpkgQuery == "" || v.Tools.AptCache == "" {
		t.Errorf("辅助工具未探测到: %+v", v.Tools)
	}
}

// TestDetectVarsDebian 验证 Debian（用 DEBIAN_CODENAME 兜底）。
func TestDetectVarsDebian(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
VERSION_ID="12"
ID=debian
VERSION_CODENAME=bookworm
`)
	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		LookPath:      fakeLookPath("apt-get", "apt-cache", "dpkg-query"),
	})
	if v.Family != FamilyDebian || v.Codename != "bookworm" || v.Manager != PackageManagerAPT {
		t.Fatalf("探测结果错误: %+v", v)
	}
}

// TestDetectVarsRocky 验证 RHEL 系（dnf 优先于 yum）。
func TestDetectVarsRocky(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, `PRETTY_NAME="Rocky Linux 9.4"
VERSION_ID="9.4"
ID=rocky
ID_LIKE="rhel centos fedora"
`)
	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		GOARCH:        "arm64",
		LookPath:      fakeLookPath("dnf", "yum", "rpm", "curl", "tar"),
	})
	if v.Family != FamilyRHEL {
		t.Errorf("Family = %q", v.Family)
	}
	if v.Manager != PackageManagerDNF {
		t.Errorf("应优先 dnf，实际 %q", v.Manager)
	}
	// rpm 系的代号是裸大版本号（清单模板自己决定加不加 el 前缀）。
	if v.Codename != "9" {
		t.Errorf("Codename = %q，应为裸大版本号 9", v.Codename)
	}
	if v.Arch != "arm64" {
		t.Errorf("Arch = %q", v.Arch)
	}
}

// TestDetectVarsCentOS7UsesYum 验证没有 dnf 时退回 yum。
func TestDetectVarsCentOS7UsesYum(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, `PRETTY_NAME="CentOS Linux 7 (Core)"
VERSION_ID="7"
ID=centos
ID_LIKE="rhel fedora"
`)
	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		LookPath:      fakeLookPath("yum", "rpm"),
	})
	if v.Manager != PackageManagerYUM {
		t.Fatalf("Manager = %q，应为 yum", v.Manager)
	}
	if v.Codename != "7" {
		t.Fatalf("Codename = %q", v.Codename)
	}
}

// TestDetectVarsNoPackageManager 验证无包管理器时的优雅降级。
//
// 与 4.1 无 systemd、4.3 无 nginx 一致：面板其它功能必须照常可用。
func TestDetectVarsNoPackageManager(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, "ID=alpine\nVERSION_ID=3.19\n")

	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		LookPath:      fakeLookPath(), // 什么都没有
	})
	if v.Available() {
		t.Fatalf("不应报告可用: %+v", v)
	}
	if v.UnavailableReason() == "" {
		t.Fatal("不可用时必须给出原因")
	}
	if !strings.Contains(v.UnavailableReason(), "apt-get") {
		t.Errorf("原因应提到缺少哪些包管理器: %q", v.UnavailableReason())
	}
}

// TestDetectVarsUnknownDistroFallsBackToPath 验证未识别发行版时按 PATH 兜底。
func TestDetectVarsUnknownDistroFallsBackToPath(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, "ID=weirdos\nPRETTY_NAME=\"Weird OS\"\n")

	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		LookPath:      fakeLookPath("apt-get", "apt-cache", "dpkg-query"),
	})
	if v.Family != FamilyUnknown {
		t.Errorf("Family = %q，应为 unknown", v.Family)
	}
	if v.Manager != PackageManagerAPT {
		t.Errorf("Manager = %q，应按 PATH 兜底为 apt", v.Manager)
	}
	// 没有代号 → 官方源不可用（写不出合法的源条目）。
	if v.Codename != "" {
		t.Errorf("Codename = %q，未知发行版不应猜代号", v.Codename)
	}
	if v.SupportsOfficialSource() {
		t.Error("无代号时不应报告支持官方源")
	}
	if !v.Available() {
		t.Error("有 apt-get 就应当可以安装软件")
	}
}

// TestDetectVarsForceManager 验证强制指定包管理器。
func TestDetectVarsForceManager(t *testing.T) {
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, "ID=ubuntu\nVERSION_ID=22.04\nVERSION_CODENAME=jammy\n")

	v := DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		ForceManager:  PackageManagerDNF,
		LookPath:      fakeLookPath("apt-get", "dnf", "rpm"),
	})
	if v.Manager != PackageManagerDNF {
		t.Fatalf("应被强制为 dnf，实际 %q", v.Manager)
	}

	// 指定了不存在的管理器 → 退回自动探测并给出提示。
	v = DetectVars(AdapterOptions{
		OSReleasePath: osRelease,
		ForceManager:  "pacman",
		LookPath:      fakeLookPath("apt-get", "apt-cache"),
	})
	if v.Manager != PackageManagerAPT {
		t.Fatalf("指定不存在的管理器后应退回自动探测，实际 %q", v.Manager)
	}
	found := false
	for _, n := range v.ProbeNotes {
		if strings.Contains(n, "pacman") {
			found = true
		}
	}
	if !found {
		t.Errorf("应提示指定的管理器不存在: %v", v.ProbeNotes)
	}
}

// TestParseOSRelease 验证 os-release 解析。
func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	writeFile(t, p, `# 注释行
NAME="Ubuntu"
ID=ubuntu
VERSION_ID=22.04
EMPTY=
QUOTED='single'
NOEQUALS
`)
	got, notes := ParseOSRelease(p)
	if len(notes) != 0 {
		t.Errorf("不应有告警: %v", notes)
	}
	if got["NAME"] != "Ubuntu" || got["ID"] != "ubuntu" || got["VERSION_ID"] != "22.04" {
		t.Fatalf("解析错误: %v", got)
	}
	if got["QUOTED"] != "single" {
		t.Errorf("单引号未去除: %v", got)
	}
	if _, ok := got["NOEQUALS"]; ok {
		t.Error("无等号的行不应被解析")
	}
	if got["EMPTY"] != "" {
		t.Errorf("空值应解析为空串: %v", got)
	}
	// 文件不存在时返回告警而不是 panic。
	got, notes = ParseOSRelease(filepath.Join(dir, "nope"))
	if len(got) != 0 || len(notes) == 0 {
		t.Errorf("文件不存在时应返回空 map 与告警: %v %v", got, notes)
	}
}

// TestNormalizeArch 验证架构映射。
func TestNormalizeArch(t *testing.T) {
	cases := map[string]string{
		"amd64": "x64", "arm64": "arm64", "arm": "armv7l",
		"386": "", "riscv64": "", "ppc64le": "",
	}
	for in, want := range cases {
		if got := normalizeArch(in); got != want {
			t.Errorf("normalizeArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFamilyOf 验证家族判定（含 ID_LIKE 兜底）。
func TestFamilyOf(t *testing.T) {
	cases := []struct {
		release map[string]string
		want    string
	}{
		{map[string]string{"ID": "ubuntu"}, FamilyDebian},
		{map[string]string{"ID": "debian"}, FamilyDebian},
		{map[string]string{"ID": "linuxmint"}, FamilyDebian},
		{map[string]string{"ID": "rocky"}, FamilyRHEL},
		{map[string]string{"ID": "almalinux"}, FamilyRHEL},
		{map[string]string{"ID": "fedora"}, FamilyRHEL},
		{map[string]string{"ID": "amzn"}, FamilyRHEL},
		// ID 不认识但 ID_LIKE 自报像谁。
		{map[string]string{"ID": "pop_os", "ID_LIKE": "ubuntu debian"}, FamilyDebian},
		{map[string]string{"ID": "unknown", "ID_LIKE": "rhel"}, FamilyRHEL},
		{map[string]string{"ID": "alpine"}, FamilyUnknown},
		{map[string]string{}, FamilyUnknown},
	}
	for _, tc := range cases {
		if got := familyOf(tc.release); got != tc.want {
			t.Errorf("familyOf(%v) = %q, want %q", tc.release, got, tc.want)
		}
	}
}

// TestVarsDescribe 验证环境描述（启动日志）。
func TestVarsDescribe(t *testing.T) {
	v := Vars{
		Manager: PackageManagerAPT, Family: FamilyDebian,
		DistroID: "ubuntu", DistroName: "Ubuntu 22.04.5 LTS",
		Codename: "jammy", Arch: "x64",
	}
	d := v.Describe()
	for _, want := range []string{"Ubuntu 22.04.5 LTS", "jammy", "apt", "x64"} {
		if !strings.Contains(d, want) {
			t.Errorf("描述 %q 缺少 %q", d, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 测试工具
// ---------------------------------------------------------------------------

// fakeLookPath 构造一个只认识给定可执行文件名的 LookPath。
func fakeLookPath(names ...string) func(string) (string, error) {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(name string) (string, error) {
		if set[name] {
			return "/usr/bin/" + name, nil
		}
		return "", os.ErrNotExist
	}
}

// writeFile 写测试用文件（失败直接 fatal）。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写测试文件失败: %v", err)
	}
}
