package store

import (
	"strings"
	"testing"
)

// ============================================================================
// 白名单校验测试（计划要求："版本校验"测试）
// ============================================================================

// TestValidSoftwareID 穷举软件 ID 的白名单边界。
func TestValidSoftwareID(t *testing.T) {
	valid := []string{"php", "nginx", "nodejs", "mysql", "a1", "php8", "my-sql", "my_sql", "a.b"}
	for _, id := range valid {
		if err := ValidSoftwareID(id); err != nil {
			t.Errorf("ValidSoftwareID(%q) 应通过，实际: %v", id, err)
		}
	}
	invalid := []string{
		"", "PHP", "Php", // 空、大写
		"1php",                 // 数字开头
		"-php", ".php", "_php", // 符号开头
		"php..extra",                 // 连续点
		"php/../etc",                 // 路径穿越
		"php;id", "php|id", "php&id", // shell 元字符
		"php id", "php\nid", "php`id`", // 空白、换行、反引号
		"php$(id)", "php>out", "php<in",
		"php'", "php\"", "php*", "php?",
		strings.Repeat("a", 40), // 超长
	}
	for _, id := range invalid {
		if err := ValidSoftwareID(id); err == nil {
			t.Errorf("ValidSoftwareID(%q) 应被拒绝", id)
		}
	}
}

// TestValidVersionID 穷举版本号白名单。
func TestValidVersionID(t *testing.T) {
	valid := []string{"8.3", "22", "1.26", "8.10.2", "0.1"}
	for _, v := range valid {
		if err := ValidVersionID(v); err != nil {
			t.Errorf("ValidVersionID(%q) 应通过，实际: %v", v, err)
		}
	}
	invalid := []string{
		"", "v8.3", "8.3.1.2", "8..3", ".8", "8.", "8.3-rc1", "8.3beta",
		"8.3; id", "8.3 && id", "8.3|id", "8.3`id`", "8.3$(id)",
		"8.3/../etc", "8.3\n", " 8.3", "8.3 ",
		"1234", strings.Repeat("9", 20),
	}
	for _, v := range invalid {
		if err := ValidVersionID(v); err == nil {
			t.Errorf("ValidVersionID(%q) 应被拒绝", v)
		}
	}
}

// TestValidPackageNameItem 穷举包名白名单。
func TestValidPackageNameItem(t *testing.T) {
	valid := []string{"php8.3-fpm", "nginx", "mysql-community-server", "redis-server", "php83-php-fpm", "libc++1", "g++"}
	for _, p := range valid {
		if err := ValidPackageNameItem(p); err != nil {
			t.Errorf("ValidPackageNameItem(%q) 应通过，实际: %v", p, err)
		}
	}
	invalid := []string{
		"", "-nginx", "--force-yes", "--allow-unauthenticated",
		"nginx;id", "nginx && id", "nginx|id", "nginx`id`", "nginx$(id)",
		"../../etc/passwd", "nginx/../shadow", "nginx..extra",
		"nginx id", "nginx\nid", "nginx'id'", "nginx\"id\"",
		"NGINX", "nginx*", "nginx?", "nginx>out",
		strings.Repeat("a", 70),
	}
	for _, p := range invalid {
		if err := ValidPackageNameItem(p); err == nil {
			t.Errorf("ValidPackageNameItem(%q) 应被拒绝", p)
		}
	}
}

// TestValidCodename 穷举发行版代号。
func TestValidCodename(t *testing.T) {
	for _, c := range []string{"jammy", "bookworm", "noble", "9", "40", "el9"} {
		if err := ValidCodename(c); err != nil {
			t.Errorf("ValidCodename(%q) 应通过: %v", c, err)
		}
	}
	for _, c := range []string{"", "jammy main", "jammy\n", "jammy;id", "../etc", "-jammy"} {
		if err := ValidCodename(c); err == nil {
			t.Errorf("ValidCodename(%q) 应被拒绝", c)
		}
	}
}

// TestValidBinaryName 穷举可执行文件名。
func TestValidBinaryName(t *testing.T) {
	for _, n := range []string{"node", "npm", "npx", "redis-server", "php-fpm8.3", "Node"} {
		if err := ValidBinaryName(n); err != nil {
			t.Errorf("ValidBinaryName(%q) 应通过: %v", n, err)
		}
	}
	for _, n := range []string{"", "-node", ".hidden", "a/b", "a\\b", "node;id", "node id", "..", "node..x"} {
		if err := ValidBinaryName(n); err == nil {
			t.Errorf("ValidBinaryName(%q) 应被拒绝", n)
		}
	}
}

// TestValidHTTPSURL 穷举 URL 白名单（清单数据的第一道闸门）。
func TestValidHTTPSURL(t *testing.T) {
	valid := []string{
		"https://deb.nodesource.com/setup_22.x",
		"https://nginx.org/keys/nginx_signing.key",
		"https://packages.sury.org/php/apt.gpg",
		"https://nodejs.org/dist/latest-v22.x/node-v22.14.0-linux-x64.tar.gz",
		"https://repo.mysql.com/apt/ubuntu/",
		"https://rpms.remirepo.net/enterprise/remi-release-9.rpm",
	}
	for _, u := range valid {
		if err := validHTTPSURL(u); err != nil {
			t.Errorf("validHTTPSURL(%q) 应通过: %v", u, err)
		}
	}
	invalid := []string{
		"", "http://example.com/k.gpg", // 非 https
		"https://",                         // 无主机
		"https://ex ample.com/a",           // 空格
		"https://example.com/$(id)",        // 命令注入
		"https://example.com/`id`",         // 反引号
		"https://example.com/a;id",         // 分号
		"https://example.com/a|id",         // 管道
		"https://example.com/a\nb",         // 换行
		"https://example.com/'a'",          // 引号
		"https://example.com/a&b",          // 与号
		"file:///etc/passwd",               // 本地文件
		"https://example.com/../../etc",    // 路径穿越（含 .. 段）
		"https://example.com/%2e%2e/etc",   // 编码后的上级目录段
		"https://example.com/a/%2e%2e%2fb", // 段内编码的穿越（解码后含 /../）
	}
	for _, u := range invalid {
		if err := validHTTPSURL(u); err == nil {
			t.Errorf("validHTTPSURL(%q) 应被拒绝", u)
		}
	}
}

// TestValidRepoContent 穷举 yum 仓库内容校验。
func TestValidRepoContent(t *testing.T) {
	ok := []string{
		"[nginx]\nname=nginx\nbaseurl=https://nginx.org/packages/mainline/centos/9/$basearch/\ngpgcheck=1",
		"[a]\nenabled=1\ngpgkey=file:///etc/pki/rpm-gpg/k.gpg",
		"[a]\nbaseurl=https://x.test/{distro}/",
	}
	for _, c := range ok {
		if err := validRepoContent(c); err != nil {
			t.Errorf("validRepoContent 应通过: %v（内容 %q）", err, c)
		}
	}
	bad := []string{
		"[a]\nbaseurl=https://x.test/$(whoami)", // 命令替换
		"[a]\nname=`id`",                        // 反引号
		"[a]\nname=\"quoted\"",                  // 引号
		"[a]\nbaseurl=https://x.test/a;id",      // 分号
		"[a]\nbaseurl=https://x.test/$releasever/$basearch/$(id)",
		strings.Repeat("a", 3000), // 超长
	}
	for _, c := range bad {
		if err := validRepoContent(c); err == nil {
			t.Errorf("validRepoContent 应拒绝 %q", c)
		}
	}
}

// TestRenderSourceTemplate 验证模板渲染与残留占位符检测。
func TestRenderSourceTemplate(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		version string
		distro  string
		arch    string
		want    string
		wantErr bool
	}{
		{
			name: "全部占位符", tmpl: "https://x.test/{version}/{distro}/{arch}",
			version: "22", distro: "jammy", arch: "x64",
			want: "https://x.test/22/jammy/x64",
		},
		{
			name: "无占位符", tmpl: "https://x.test/stable",
			want: "https://x.test/stable",
		},
		{
			name: "残留未知占位符", tmpl: "https://x.test/{disro}",
			distro: "jammy", wantErr: true,
		},
		{
			name: "版本号非法", tmpl: "https://x.test/{version}",
			version: "22;id", wantErr: true,
		},
		{
			name: "代号非法", tmpl: "https://x.test/{distro}",
			distro: "jammy main", wantErr: true,
		},
		{
			name: "架构非法", tmpl: "https://x.test/{arch}",
			arch: "x64;id", wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderSourceTemplate(tc.tmpl, tc.version, tc.distro, tc.arch)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("预期失败，实际得到 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("预期成功，实际: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildAptSourceLine 验证源条目渲染与二次字符集校验。
func TestBuildAptSourceLine(t *testing.T) {
	o := OfficialSource{
		Kind:               OfficialAptKeySource,
		KeyURL:             "https://packages.sury.org/php/apt.gpg",
		KeyringPath:        "/usr/share/keyrings/lipanel-sury-php.gpg",
		ListFile:           "lipanel-sury-php.list",
		SourceLineTemplate: "deb [signed-by=/usr/share/keyrings/lipanel-sury-php.gpg] https://packages.sury.org/php/ {distro} main",
	}
	line, err := BuildAptSourceLine(o, "8.3", "jammy")
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	want := "deb [signed-by=/usr/share/keyrings/lipanel-sury-php.gpg] https://packages.sury.org/php/ jammy main"
	if line != want {
		t.Fatalf("got %q, want %q", line, want)
	}
	// 代号非法必须在渲染阶段就被挡住（否则会被写进 sources.list）。
	if _, err := BuildAptSourceLine(o, "8.3", "jammy main"); err == nil {
		t.Fatal("非法代号应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// ValidPinnedPackage（钉版本的包条目）
// ---------------------------------------------------------------------------

// TestValidPinnedPackage 验证「包名=版本」的校验规则。
//
// 这个校验器守的是"从外部命令输出里取回来的版本号"：
// apt-cache policy 的输出受软件源控制，一个被污染的源
// 可以让候选版本里带上任意字符。因此规则必须**既放行真实版本号、
// 又挡住参数注入**。
func TestValidPinnedPackage(t *testing.T) {
	valid := []string{
		"nginx=1.26.2-1~jammy",                            // Debian 版本串（含 ~）
		"nginx=1.18.0-6ubuntu14",                          // 发行版版本
		"php8.3-fpm=8.3.2-1+ubuntu22.04.1+deb.sury.org+1", // 第三方源
		"redis=5:7.0.15-1~deb12u1",                        // epoch（含 :）
		"mysql-community-server=8.0.36-1.el9",             // rpm 风格
		"nodejs=22.14.0-1nodesource1",
	}
	for _, p := range valid {
		if err := ValidPinnedPackage(p); err != nil {
			t.Errorf("应放行 %q: %v", p, err)
		}
	}

	invalid := []string{
		"",
		"nginx",           // 没有 = 版本
		"=1.26",           // 包名为空
		"nginx=",          // 版本为空
		"nginx=1.26=2",    // 多个 =
		"nginx=1.26 1.24", // 空格 → 可拆出第二个参数
		"nginx=1.26;id",   // 命令分隔符
		"nginx=1.26&&id",
		"nginx=$(id)",
		"nginx=`id`",
		"nginx=1.26|id",
		"nginx=../etc/passwd", // 路径
		"nginx=1.26\nid",      // 换行
		"-nginx=1.26",         // 以 - 开头（会被当选项）
		"nginx=1.26'",         // 引号
		"nginx=1.26\"",
		"NGINX=1.26", // 大写包名
	}
	for _, p := range invalid {
		if err := ValidPinnedPackage(p); err == nil {
			t.Errorf("应拒绝 %q", p)
		}
	}
}

// TestValidInstallItems 验证安装条目按形态分流校验。
//
// 含 = 的走钉版本规则，不含的走包名规则——
// 由**结构**决定，而不是看调用方怎么说。
func TestValidInstallItems(t *testing.T) {
	if err := ValidInstallItems([]string{"nginx", "nginx=1.26.2-1~jammy"}); err != nil {
		t.Errorf("混合列表应放行: %v", err)
	}
	if err := ValidInstallItems([]string{"nginx=1.26;id"}); err == nil {
		t.Error("注入载荷应被拒绝")
	}
	if err := ValidInstallItems([]string{"NGINX"}); err == nil {
		t.Error("大写包名应被拒绝")
	}
	if err := ValidInstallItems(nil); err != nil {
		t.Errorf("空列表应放行（由调用方判断是否为空）: %v", err)
	}
}

// TestUninstallRejectsPinnedSyntax 验证卸载不接受钉版本写法。
//
// `apt-get remove nginx=1.26` 不是"卸载 1.26"，而是一个
// 语法错误（apt 会报找不到该版本）——把卸载写成那样会让用户
// 看到一个莫名其妙的失败。卸载永远不带版本约束。
func TestUninstallRejectsPinnedSyntax(t *testing.T) {
	if _, err := BuildAptRemove("/usr/bin/apt-get", []string{"nginx=1.26.2-1~jammy"}); err == nil {
		t.Error("apt 卸载不应接受 pkg=version 写法")
	}
	if _, err := BuildRPMRemove("/usr/bin/dnf", []string{"nginx=1.26.2"}); err == nil {
		t.Error("rpm 卸载不应接受 pkg=version 写法")
	}
}

// TestBuildAptInstallAcceptsPinned 验证安装命令接受钉版本写法。
func TestBuildAptInstallAcceptsPinned(t *testing.T) {
	cmd, err := BuildAptInstall("/usr/bin/apt-get", []string{"nginx=1.26.2-1~jammy"})
	if err != nil {
		t.Fatalf("应接受钉版本写法: %v", err)
	}
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "nginx=1.26.2-1~jammy") {
		t.Errorf("参数里应带钉住的版本: %s", args)
	}
	// 版本约束里的 = 不能让命令退化成 shell 拼接。
	if strings.Contains(args, ";") || strings.Contains(args, "&&") {
		t.Errorf("不应出现 shell 元字符: %s", args)
	}
}
