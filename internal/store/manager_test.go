package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 安装策略测试：多源回退（4.5 的核心要求）
//
//	系统源 → 官方源 → 预编译包
//
// 这些分支的真实触发条件是"某台机器上恰好没有某个版本"，
// 测试环境无法也不该去满足；因此全部通过 fake_test.go 里的
// 假包管理器在**内存**中制造这些状态，被测代码走的仍是生产路径。
// ============================================================================

// TestInstallSystemSourceHits 验证"系统源里有目标版本"时只用系统源。
//
// 锁死的行为是"不要越权"：系统源能装上就到此为止，
// 绝不去碰 /etc/apt 下的任何东西。
func TestInstallSystemSourceHits(t *testing.T) {
	h := newTestHarness(t, nil)
	// 注意：这里**只**设置候选版本，不预置"已安装"。
	// 预置已安装会走幂等分支，测不到真正的安装链路。
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategySystem {
		t.Errorf("策略应为 system，实际 %q", task.Strategy)
	}
	if task.Progress != 100 {
		t.Errorf("Progress = %d", task.Progress)
	}
	// 系统源命中时，官方源那一步根本不该存在（而不是"存在但跳过"）。
	if stepStatus(task) != "system:succeeded" {
		t.Errorf("步骤摘要 = %s", stepStatus(task))
	}
	if len(h.sys.snapshotDownloads()) != 0 {
		t.Errorf("系统源命中时不应下载任何文件: %v", h.sys.snapshotDownloads())
	}
	if _, err := os.Stat(filepath.Join(h.listDir, "lipanel-nginx.list")); !os.IsNotExist(err) {
		t.Error("系统源命中时不应写源条目文件")
	}
	if len(task.Packages) != 1 || task.Packages[0] != "nginx" {
		t.Errorf("Packages = %v", task.Packages)
	}
	// 命令必须是"先查版本、再安装"。
	cmds := strings.Join(h.sys.snapshotCommands(), "\n")
	if !strings.Contains(cmds, "apt-cache policy nginx") {
		t.Errorf("安装前必须确认系统源里的版本: %v", h.sys.snapshotCommands())
	}
}

// TestInstallFallsBackToOfficialSource 验证"系统源没有该版本 → 追加官方源"。
//
// 这是本模块最容易出错、也最容易被误报成功的一条路径：
// Ubuntu 22.04 的系统源里有 php8.1，用户要装 8.3，
// 若不判断版本就会实装 8.1 却报告成功。
func TestInstallFallsBackToOfficialSource(t *testing.T) {
	h := newTestHarness(t, nil)

	// php 依赖 nginx。本用例聚焦 php 的回退链路，
	// 因此先让依赖处于"已装好"状态（依赖行为另有专门用例）。
	h.sys.setInstalled("nginx", "1.26.2-1~jammy")
	// 系统源里的 php 只有 8.1。
	h.sys.candidates["php8.1-fpm"] = "8.1.2-1+ubuntu22.04.1+deb.sury.org+1"

	// 模拟真实语义：追加 sury 源并刷新索引之后，8.3 才查得到。
	h.sys.afterDownload = func(url string) {
		if !strings.Contains(url, "sury") {
			return
		}
		h.sys.mu.Lock()
		defer h.sys.mu.Unlock()
		for _, pkg := range []string{
			"php8.3-fpm", "php8.3-cli", "php8.3-mysql", "php8.3-curl",
			"php8.3-mbstring", "php8.3-xml", "php8.3-zip", "php8.3-gd",
		} {
			h.sys.candidates[pkg] = "8.3.13-1+ubuntu22.04.1+deb.sury.org+1"
		}
	}

	task := h.installAndWait("php", "8.3")
	if task.Status != TaskSucceeded {
		t.Fatalf("应走官方源成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategyOfficial {
		t.Errorf("策略应为 official，实际 %q", task.Strategy)
	}
	if stepStatus(task) != "system:failed,official:succeeded" {
		t.Errorf("步骤摘要 = %s", stepStatus(task))
	}

	// 顺序必须是 查版本 → 刷新索引 → 安装。
	cmds := h.sys.snapshotCommands()
	policyIdx, updateIdx, installIdx := -1, -1, -1
	for i, c := range cmds {
		switch {
		case policyIdx < 0 && strings.Contains(c, "apt-cache policy"):
			policyIdx = i
		case updateIdx < 0 && strings.Contains(c, "update"):
			updateIdx = i
		case installIdx < 0 && strings.Contains(c, " install "):
			installIdx = i
		}
	}
	if policyIdx < 0 || updateIdx < 0 || installIdx < 0 {
		t.Fatalf("命令序列缺少关键步骤: %v", cmds)
	}
	if !(policyIdx < updateIdx && updateIdx < installIdx) {
		t.Errorf("必须按 查版本 → 刷新索引 → 安装 的顺序执行: %v", cmds)
	}

	// 源条目必须写在**隔离目录**里，且内容可复核。
	data, err := os.ReadFile(filepath.Join(h.listDir, "lipanel-sury-php.list"))
	if err != nil {
		t.Fatalf("源条目未写入: %v", err)
	}
	if !strings.Contains(string(data), "https://packages.sury.org/php/ jammy main") {
		t.Errorf("源条目内容 = %q", string(data))
	}
	if strings.ContainsAny(string(data), "$`;|&") {
		t.Errorf("源条目含可疑字符: %q", string(data))
	}
	// GPG 公钥必须落在隔离的 keyring 目录。
	if _, err := os.Stat(filepath.Join(h.keyringDir, "lipanel-sury-php.gpg")); err != nil {
		t.Errorf("GPG 公钥未下载: %v", err)
	}
	// 声明的 8 个扩展都要装上。
	if len(task.Packages) != 8 {
		t.Errorf("应安装 8 个包，实际 %v", task.Packages)
	}
}

// TestInstallOfficialSourceThenStillNoCandidate 验证官方源接好了但版本仍不可用。
//
// 这是"源加上了、包没有"的真实故障（官方删了旧版本分支），
// 必须继续往下走而不是报告成功。
func TestInstallOfficialSourceThenStillNoCandidate(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		// 预编译不可用，让失败原因不含糊。
		o.Vars.Tools.Tar = ""
	})
	h.sys.candidates["nginx"] = "1.18.0-6ubuntu14" // 系统源只有旧版
	// afterDownload 不加钩子：官方源接好之后版本依然查不到。

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskFailed {
		t.Fatalf("版本不可用时必须失败，实际 %s（策略 %s）", task.Status, task.Strategy)
	}
	if !strings.Contains(task.Error, "策略均失败") {
		t.Errorf("错误应说明三条路都试过，实际 %q", task.Error)
	}
	// 官方源确实被接入过（这一步不是被跳过）。
	if _, err := os.Stat(filepath.Join(h.listDir, "lipanel-nginx.list")); err != nil {
		t.Errorf("官方源配置应已写入（佐证确实尝试过）: %v", err)
	}
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, "apt-get install") && strings.Contains(c, " nginx=1.26.2-1~jammy") {
			t.Errorf("版本不可用时不应盲目安装: %v", h.sys.snapshotCommands())
			break
		}
	}
}

// TestInstallUsesAlternativePackages 验证备选包名回退。
//
// 场景：官方源的主包名在当前发行版上不存在，
// 但发行版仓库里有等价的替代包（RHEL 上的 php83-* 就是这种形态）。
func TestInstallUsesAlternativePackages(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		o.Vars = rockyVars(PackageManagerDNF)
	})
	h.sys.setInstalled("nginx", "1.26.2-1.el9")
	// 主包名 php8.3-fpm 在 RHEL 上不存在；remi 的等价包名为 php83-php-fpm。
	h.sys.available["php83-php-fpm"] = []string{"0:8.1.0-1.el9", "0:8.3.13-1.el9"}
	h.sys.available["php83-php-cli"] = []string{"0:8.1.0-1.el9", "0:8.3.13-1.el9"}

	task := h.installAndWait("php", "8.3")
	if task.Status != TaskSucceeded {
		t.Fatalf("应通过替代包名成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategySystem {
		t.Errorf("替代包名属于系统源，策略应为 system，实际 %q", task.Strategy)
	}
	if _, ok := h.sys.installed["php83-php-fpm"]; !ok {
		t.Errorf("应装上替代包 php83-php-fpm，数据库 = %v", h.sys.installed)
	}
	if _, ok := h.sys.installed["php8.3-fpm"]; ok {
		t.Error("不应装上不存在的主包名")
	}
}

// TestInstallFallsBackToPrebuilt 验证"系统源与官方源都不行 → 预编译兜底"。
func TestInstallFallsBackToPrebuilt(t *testing.T) {
	root := t.TempDir()
	h := newTestHarness(t, func(o *Options) {
		// 预编译路径指向临时目录，避免测试真的写 /usr/local。
		o.PrebuiltRootOverride = root
	})
	// 经典陷阱：Ubuntu 22.04 系统源里的 nodejs 是 12.x，用户要 22。
	h.sys.candidates["nodejs"] = "12.22.9~dfsg-1ubuntu3.2"

	task := h.installAndWait("nodejs", "22")
	if task.Status != TaskSucceeded {
		t.Fatalf("应走预编译成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategyPrebuilt {
		t.Errorf("策略应为 prebuilt，实际 %q", task.Strategy)
	}
	if !strings.Contains(stepStatus(task), "prebuilt:succeeded") {
		t.Errorf("步骤摘要 = %s", stepStatus(task))
	}
	// 绝不能把发行版的 12.x 当成 22 报告成功。
	if _, ok := h.sys.installed["nodejs"]; ok {
		t.Errorf("预编译路径不应通过包管理器装任何东西: %v", h.sys.installed)
	}

	// 下载的必须是官方索引 + 从索引里解析出的归档，而不是凭空拼的 URL。
	dl := h.sys.snapshotDownloads()
	if len(dl) < 2 {
		t.Fatalf("应至少下载索引与归档，实际 %v", dl)
	}
	if !strings.Contains(dl[0], "SHASUMS256.txt") {
		t.Errorf("第一次应下载官方索引: %v", dl)
	}
	if !strings.Contains(dl[1], "node-v22.14.0-linux-x64.tar.gz") {
		t.Errorf("归档名应来自索引解析: %v", dl)
	}
	if task.PrebuiltURL != dl[1] {
		t.Errorf("任务的 PrebuiltURL = %q", task.PrebuiltURL)
	}

	// 解包、软链接、状态记录都必须真实发生。
	bin := filepath.Join(root, "usr/local/lib/lipanel/nodejs-22/bin/node")
	if _, err := os.Stat(bin); err != nil {
		t.Errorf("二进制未解包到预期位置: %v", err)
	}
	// strip-components=1 的意义：顶层目录必须已被剥掉。
	if _, err := os.Stat(filepath.Join(root, "usr/local/lib/lipanel/nodejs-22/node-v22.14.0-linux-x64")); !os.IsNotExist(err) {
		t.Error("归档顶层目录未被剥离（--strip-components 失效）")
	}
	link := filepath.Join(root, "usr/local/bin/node")
	if target, err := os.Readlink(link); err != nil {
		t.Errorf("软链接未建立: %v", err)
	} else if target != bin {
		t.Errorf("软链接指向 %q，应为 %q", target, bin)
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, "prebuilt.json")); err != nil {
		t.Errorf("预编译安装记录未落盘: %v", err)
	}
}

// TestInstallRejectsWrongSystemVersion 单独锁死最危险的失败：
//
//	用户选 22，系统源只有 12 —— 必须失败，不能"装上 12 并报告成功"。
func TestInstallRejectsWrongSystemVersion(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		// 预编译不可用，使失败只可能来自版本判定。
		o.Vars.Tools.Tar = ""
	})
	h.sys.candidates["nodejs"] = "12.22.9~dfsg-1ubuntu3.2"

	task := h.installAndWait("nodejs", "22")
	if task.Status != TaskFailed {
		t.Fatalf("版本不符时必须失败，实际 %s（策略 %s）", task.Status, task.Strategy)
	}
	if !strings.Contains(task.Error, "策略均失败") {
		t.Errorf("错误信息 = %q", task.Error)
	}
	// 关键断言：12.x 从未被安装。
	if v, ok := h.sys.installed["nodejs"]; ok {
		t.Errorf("错误的版本被安装了（%s）：系统源就绪判定失效", v)
	}
}

// TestInstallVersionMismatchAfterInstall 验证"命令成功但版本不符"被复验抓住。
//
// 这是防"假成功"的最后一道闸门：包管理器退出码为 0 不等于装对了。
func TestInstallVersionMismatchAfterInstall(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.18.0-6ubuntu14"
	// 装完之后数据库里是另一个版本。
	h.sys.installVersion = func(string) string { return "1.20.0-fake" }

	task := h.installAndWait("nginx", "1.18")
	if task.Status != TaskFailed {
		t.Fatalf("版本不符必须失败，实际 %s", task.Status)
	}
	// 顶层错误是三条策略的汇总，具体原因在步骤详情与日志里。
	var systemStep *StepState
	for i := range task.Steps {
		if task.Steps[i].Key == "system" {
			systemStep = &task.Steps[i]
		}
	}
	if systemStep == nil {
		t.Fatalf("应存在系统源步骤: %+v", task.Steps)
	}
	if systemStep.Status != StepFailed {
		t.Errorf("系统源步骤应失败，实际 %s", systemStep.Status)
	}
	logs := logsText(t, h.mgr, task.ID)
	if !strings.Contains(logs, "版本不符") {
		t.Errorf("日志应说明版本不符：\n%s", logs)
	}
	if !strings.Contains(logs, "1.20.0-fake") {
		t.Error("日志里应出现实际版本，便于用户判断")
	}
}

// TestInstallOfficialScriptFamily 验证 NodeSource 的脚本形态官方源。
//
// 这是整个模块里唯一执行 shell 的地方，因此单独验证其形态。
func TestInstallOfficialScriptFamily(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nodejs"] = "12.22.9"
	// 脚本执行后，NodeSource 源里的 22 才可用。
	h.sys.afterScript = func(string) {
		h.sys.mu.Lock()
		defer h.sys.mu.Unlock()
		h.sys.candidates["nodejs"] = "22.14.0-1nodesource1"
	}

	task := h.installAndWait("nodejs", "22")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategyOfficial {
		t.Errorf("策略应为 official，实际 %q", task.Strategy)
	}
	scripts := h.sys.snapshotScripts()
	if len(scripts) != 1 {
		t.Fatalf("应恰好执行一次官方脚本，实际 %v", scripts)
	}
	s := scripts[0]
	if !strings.Contains(s, "https://deb.nodesource.com/setup_22.x") {
		t.Errorf("脚本 URL = %q", s)
	}
	// 形态必须固定：右侧是 sh，URL 被单引号包裹。
	if !strings.HasSuffix(s, "| sh") || !strings.Contains(s, "'https://") {
		t.Errorf("脚本形态不安全: %q", s)
	}
}

// TestInstallRPMFamilyFallback 验证 rpm 系同样走 系统源 → 官方源 的回退。
func TestInstallRPMFamilyFallback(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		o.Vars = rockyVars(PackageManagerDNF)
	})
	h.sys.setInstalled("nginx", "1.26.2-1.el9")
	// 系统源里只有 remi 的 8.1。
	h.sys.available["php83-php-fpm"] = []string{"0:8.1.0-1.el9"}
	h.sys.available["php83-php-cli"] = []string{"0:8.1.0-1.el9"}
	// 接入 remi 官方源之后 8.3 才可用。
	// rpm 系的官方源是"安装 release 包"，走的是 install 而非下载，
	// 因此钩子挂在 install 的 URL 上（钩子在解锁后执行，可安全改状态）。
	h.sys.afterRPMRepoInstall = func(url string) {
		if !strings.Contains(url, "remirepo") {
			return
		}
		h.sys.available["php83-php-fpm"] = []string{"0:8.1.0-1.el9", "0:8.3.13-1.el9"}
		h.sys.available["php83-php-cli"] = []string{"0:8.1.0-1.el9", "0:8.3.13-1.el9"}
	}

	task := h.installAndWait("php", "8.3")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if task.Strategy != StrategyOfficial {
		t.Errorf("策略应为 official，实际 %q", task.Strategy)
	}
	joined := strings.Join(h.sys.snapshotCommands(), "\n")
	if !strings.Contains(joined, "--showduplicates list available") {
		t.Errorf("rpm 系必须用 --showduplicates 查可用版本: %v", h.sys.snapshotCommands())
	}
	if !strings.Contains(joined, "makecache") {
		t.Errorf("追加官方源后应刷新元数据: %v", h.sys.snapshotCommands())
	}
	// 官方源是 remi 的 release 包，且 {distro} 必须渲染成裸大版本号 9。
	if !strings.Contains(joined, "remi-release-9.rpm") {
		t.Errorf("remi release 包 URL 渲染错误: %v", h.sys.snapshotCommands())
	}
	if !strings.Contains(joined, "--setopt=install_weak_deps=False") {
		t.Errorf("rpm 安装应禁用弱依赖: %v", h.sys.snapshotCommands())
	}
}

// TestInstallRPMNoOfficialSource 验证 rpm 系缺官方源时如实失败。
func TestInstallRPMNoOfficialSource(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		v := rockyVars(PackageManagerYUM)
		v.Codename = "7"
		o.Vars = v
	})
	// redis 在清单里只有 debian 系的官方源，rpm 系没有。
	task := h.installAndWait("redis", "7.2")
	if task.Status != TaskFailed {
		t.Fatalf("无可用源时必须失败，实际 %s", task.Status)
	}
	if !strings.Contains(stepStatus(task), "official:skipped") {
		t.Errorf("官方源步骤应标记为 skipped：%s", stepStatus(task))
	}
	if !strings.Contains(logsText(t, h.mgr, task.ID), "未提供官方源") {
		t.Error("日志应说明该系列没有官方源")
	}
	if len(h.sys.installed) != 0 {
		t.Errorf("不应安装任何东西: %v", h.sys.installed)
	}
}

// TestInstallDependencyInstalledAutomatically 验证依赖被自动补齐且顺序正确。
func TestInstallDependencyInstalledAutomatically(t *testing.T) {
	h := newTestHarness(t, nil)
	// php 依赖 nginx；两者都在 8.1 版本上可用。
	php81 := []string{
		"php8.1-fpm", "php8.1-cli", "php8.1-mysql", "php8.1-curl",
		"php8.1-mbstring", "php8.1-xml", "php8.1-zip", "php8.1-gd",
	}
	for _, p := range php81 {
		h.sys.candidates[p] = "8.1.2-1+ubuntu22.04.1+deb.sury.org+1"
	}
	// nginx 的默认版本是 1.26，依赖安装会请求该软件的默认版本。
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("php", "8.1")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if len(task.Dependencies) != 1 || task.Dependencies[0] != "nginx" {
		t.Errorf("Dependencies = %v", task.Dependencies)
	}
	if _, ok := h.sys.installed["nginx"]; !ok {
		t.Errorf("依赖 nginx 应被装上，数据库 = %v", h.sys.installed)
	}
	// 依赖必须先于主软件安装，否则 PHP 的 postinst 可能起不来。
	cmds := h.sys.snapshotCommands()
	nginxAt, phpAt := -1, -1
	for i, c := range cmds {
		if !strings.Contains(c, " install ") {
			continue
		}
		if nginxAt < 0 && strings.Contains(c, "nginx=1.26.2-1~jammy") {
			nginxAt = i
		}
		if phpAt < 0 && strings.Contains(c, "php8.1-fpm") {
			phpAt = i
		}
	}
	if nginxAt < 0 || phpAt < 0 {
		t.Fatalf("应分别安装依赖与主软件: %v", cmds)
	}
	if nginxAt > phpAt {
		t.Errorf("依赖必须先装: nginx@%d php@%d", nginxAt, phpAt)
	}
}

// TestInstallSkipDependencies 验证可以显式跳过依赖。
func TestInstallSkipDependencies(t *testing.T) {
	h := newTestHarness(t, nil)
	for _, p := range []string{
		"php8.1-fpm", "php8.1-cli", "php8.1-mysql", "php8.1-curl",
		"php8.1-mbstring", "php8.1-xml", "php8.1-zip", "php8.1-gd",
	} {
		h.sys.candidates[p] = "8.1.2"
	}

	task, err := h.mgr.StartInstall(context.Background(), InstallRequest{
		Software: "php", Version: "8.1", SkipDependencies: true,
	})
	if err != nil {
		t.Fatalf("StartInstall 失败: %v", err)
	}
	got := waitTask(t, h.mgr, task.ID)
	if got.Status != TaskSucceeded {
		t.Fatalf("应成功: %s", got.Error)
	}
	if len(got.Dependencies) != 0 {
		t.Errorf("跳过依赖时 Dependencies 应为空: %v", got.Dependencies)
	}
	if len(h.sys.installed) != 8 {
		t.Errorf("只应安装 php 自身的包，实际 %v", h.sys.installed)
	}
}

// TestInstallAlreadyInstalled 验证幂等：重复点"安装"不会重跑命令。
func TestInstallAlreadyInstalled(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.26.2-1~jammy")

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s", task.Status)
	}
	if stepStatus(task) != "system:skipped" {
		t.Errorf("步骤摘要 = %s", stepStatus(task))
	}
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, " install ") {
			t.Errorf("已安装时不应再执行安装命令: %v", h.sys.snapshotCommands())
		}
	}
	if !strings.Contains(logsText(t, h.mgr, task.ID), "无需重复安装") {
		t.Error("日志应说明无需重复安装")
	}
}

// TestInstallVersionConflict 验证"已装别的版本"时明确拒绝。
//
// 自动"先卸载再装"会在用户不知情时拆掉生产环境依赖的版本，
// 因此"不自动"是被测试锁死的行为。
func TestInstallVersionConflict(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.18.0-6ubuntu14")

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskFailed {
		t.Fatalf("必须拒绝，实际 %s", task.Status)
	}
	if !strings.Contains(task.Error, "已安装") {
		t.Errorf("错误应说明已安装其它版本: %q", task.Error)
	}
	if !strings.Contains(task.Hint, "卸载") {
		t.Errorf("提示应引导用户先卸载: %q", task.Hint)
	}
	// 必须零变更命令。
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, " remove") || strings.Contains(c, " install ") {
			t.Errorf("冲突时不得执行任何变更命令: %v", h.sys.snapshotCommands())
			break
		}
	}
	// 冲突时已装的版本必须**原样保留**。
	//
	// 这里不能断言 "nginx 不在数据库里"：测试一开始就装好了 1.18，
	// 冲突拒绝的正确表现是"它仍然是 1.18"，而不是"它消失了"。
	// （早先的断言之所以能过，是因为当时 1.24/1.18 用了不同的
	//  假包名，冲突检查压根没生效——修好冲突检查后它才暴露出来。）
	if got := h.sys.installed["nginx"]; got != "1.18.0-6ubuntu14" {
		t.Errorf("冲突时已安装版本应保持不变，实际 %q", got)
	}
}

// TestInstallUnavailableEnvironment 验证无包管理器时直接拒绝。
//
// 与 4.1（无 systemd）、4.3（无 nginx）一致：能力缺失要如实上报，
// 而不是让用户点下去才失败。
func TestInstallUnavailableEnvironment(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		o.Vars = Vars{Family: FamilyUnknown, Arch: "x64"}
	})
	if h.mgr.Available() {
		t.Fatal("不应报告可用")
	}
	if h.mgr.UnavailableReason() == "" {
		t.Error("不可用时应给出原因")
	}
	if _, err := h.install("nginx", "1.26"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("应返回 ErrUnavailable，实际 %v", err)
	}
	if len(h.sys.snapshotCommands()) != 0 {
		t.Error("不可用时不应执行任何命令")
	}
}

// TestInstallRejectsInjection 穷举注入载荷（软件 ID 与版本 ID）。
//
// 断言重点不只是"被拒绝"，还有**零命令执行**。
func TestInstallRejectsInjection(t *testing.T) {
	h := newTestHarness(t, nil)
	cases := []struct{ sw, version string }{
		{"nginx; id", "1.26"},
		{"nginx|id", "1.26"},
		{"$(whoami)", "1.26"},
		{"../etc/passwd", "1.26"},
		{"NGINX", "1.26"},
		{"nginx ", "1.26"},
		{"nginx", "1.26; id"},
		{"nginx", "$(id)"},
		{"nginx", "1.26 && touch /tmp/pwned"},
		{"nginx", "`id`"},
		{"nginx", "1.26/../etc"},
		{"nginx", "not-a-version"},
		{"nonexistent", "1.26"}, // 形态合法但清单里没有
		{"nginx", "9.99"},       // 形态合法但该软件没有这个版本
	}
	for _, tc := range cases {
		_, err := h.install(tc.sw, tc.version)
		if err == nil {
			t.Errorf("install(%q, %q) 应被拒绝", tc.sw, tc.version)
			continue
		}
		if !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrNotFound) {
			t.Errorf("install(%q, %q) 应是参数非法或不存在，实际 %v", tc.sw, tc.version, err)
		}
	}
	if len(h.sys.snapshotCommands()) != 0 {
		t.Errorf("非法输入必须零命令执行，实际: %v", h.sys.snapshotCommands())
	}
	if _, err := os.Stat(h.stateDir); err == nil {
		// 状态目录可能被 NewManager 创建，这里只要求没有任务产物。
		if _, err := os.Stat(filepath.Join(h.stateDir, "prebuilt.json")); err == nil {
			t.Error("非法输入不应产生安装记录")
		}
	}
}

// TestInstallEmptyVersionUsesDefault 验证空版本等于"用默认版本"。
//
// 这是 API 契约的一部分（前端下拉框初始值就是默认版本），
// 因此单独锁死：空值必须被解析为清单里的 default_version，
// 而不是被当成错误或被随意拼进命令。
func TestInstallEmptyVersionUsesDefault(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task, err := h.mgr.StartInstall(context.Background(), InstallRequest{Software: "nginx"})
	if err != nil {
		t.Fatalf("空版本应回落到默认版本: %v", err)
	}
	got := waitTask(t, h.mgr, task.ID)
	if got.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s", got.Status, got.Error)
	}
	sw, _ := h.mgr.Catalog().Get("nginx")
	if got.Version != sw.DefaultVersion {
		t.Errorf("Version = %q，应为默认版本 %q", got.Version, sw.DefaultVersion)
	}
	if !strings.Contains(strings.Join(h.sys.snapshotCommands(), "\n"), sw.DefaultVersion) {
		t.Errorf("安装命令应针对默认版本: %v", h.sys.snapshotCommands())
	}
}

// TestInstallBusySerialized 验证并发安装被拒绝。
//
// apt/dpkg 与 rpm 都有全局锁，两个安装并行只会互相破坏；
// 这里把"一次只跑一个"锁死，并且要求错误里带上占用者。
func TestInstallBusySerialized(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.block = make(chan struct{})
	h.sys.blockOn = "aptget-install-block"
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	// 让 install 命令阻塞：把包名换成一个永远不会真的出现的匹配串。
	h.sys.blockOn = "nginx"

	first, err := h.install("nginx", "1.26")
	if err != nil {
		t.Fatalf("第一个任务应被接受: %v", err)
	}
	// 等第一个任务真正开始执行命令。
	deadline := time.Now().Add(3 * time.Second)
	for len(h.sys.snapshotCommands()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("第一个任务没有开始执行")
		}
		time.Sleep(2 * time.Millisecond)
	}

	second, err := h.install("php", "8.3")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("第二个任务应被拒绝（ErrBusy），实际 %v", err)
	}
	if second.ID != "" {
		t.Error("被拒绝的请求不应返回任务快照")
	}
	if !strings.Contains(err.Error(), first.ID) {
		t.Errorf("错误里应带上占用中的任务 ID: %v", err)
	}
	// 运行中的任务应能在状态里看到。
	st, err := h.mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if st.Running == nil || st.Running.ID != first.ID {
		t.Errorf("Running = %+v", st.Running)
	}

	close(h.sys.block)
	done := waitTask(t, h.mgr, first.ID)
	if done.Status != TaskSucceeded {
		t.Fatalf("第一个任务应最终成功: %s", done.Error)
	}
	// 结束后应能再次提交（锁被正确释放）。
	task, err := h.install("nginx", "1.26")
	if err != nil {
		t.Fatalf("任务结束后应能再次提交: %v", err)
	}
	waitTask(t, h.mgr, task.ID)
}

// TestInstallTimeoutReportsActionableHint 验证超时提示"不要立即重试"。
//
// 超时时包管理器可能仍在后台跑，立即重试会抢 apt/dpkg 的全局锁 ——
// 提示必须点出这一点。
func TestInstallTimeoutReportsActionableHint(t *testing.T) {
	h := newTestHarness(t, func(o *Options) {
		o.StepTimeout = 80 * time.Millisecond
	})
	h.sys.block = make(chan struct{})
	h.sys.blockOn = "install"
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"
	defer close(h.sys.block)

	task, err := h.install("nginx", "1.26")
	if err != nil {
		t.Fatalf("StartInstall 失败: %v", err)
	}
	got := waitTask(t, h.mgr, task.ID)
	if got.Status != TaskFailed {
		t.Fatalf("超时应失败，实际 %s", got.Status)
	}
	if !strings.Contains(got.Error, "超时") {
		t.Errorf("错误应包含超时，实际 %q", got.Error)
	}
	if !strings.Contains(got.Hint, "不要立即重试") {
		t.Errorf("提示必须引导用户不要立即重试，实际 %q", got.Hint)
	}
}

// TestDryRunTouchesNothing 验证试运行模式零副作用。
//
// "试运行"若还会写系统文件、还会下载，那它就只是"换个说法的真安装"。
func TestDryRunTouchesNothing(t *testing.T) {
	root := t.TempDir()
	h := newTestHarness(t, func(o *Options) {
		o.DryRun = true
		o.PrebuiltRootOverride = root
	})
	// 系统源里没有 22 → 会一路走到官方源与预编译。
	h.sys.candidates["nodejs"] = "12.22.9~dfsg-1ubuntu3.2"

	task := h.installAndWait("nodejs", "22")
	if task.Status != TaskSucceeded {
		t.Fatalf("试运行应报告成功，实际 %s: %s", task.Status, task.Error)
	}
	if !task.Simulated {
		t.Error("任务快照必须标记为模拟执行")
	}
	if len(h.sys.snapshotCommands()) != 0 {
		t.Errorf("试运行不得执行任何命令: %v", h.sys.snapshotCommands())
	}
	if len(h.sys.snapshotScripts()) != 0 {
		t.Errorf("试运行不得执行脚本: %v", h.sys.snapshotScripts())
	}
	if len(h.sys.snapshotDownloads()) != 0 {
		t.Errorf("试运行不得下载: %v", h.sys.snapshotDownloads())
	}
	// 磁盘上不能留下源条目、公钥、解包目录或安装记录。
	for _, p := range []string{
		filepath.Join(h.listDir, "lipanel-nodesource.list"),
		filepath.Join(h.keyringDir),
		filepath.Join(root, "usr/local/lib/lipanel/nodejs-22"),
		filepath.Join(root, "usr/local/bin/node"),
		filepath.Join(h.stateDir, "prebuilt.json"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("试运行不应创建 %s", p)
		}
	}
	// 但日志要说明**将会**做什么，否则试运行没有意义。
	logs := logsText(t, h.mgr, task.ID)
	if !strings.Contains(logs, "试运行") {
		t.Error("日志应说明这是试运行")
	}
	// ########## 试运行不"假装探测" ##########
	//
	// 探测靠解析 apt-cache policy 的真实输出，而试运行下命令根本不执行，
	// 解析必然为空。若照常解析，每条策略都会被判成"源里没有该版本"，
	// 最后报"所有策略均失败"——而事实恰恰相反（我们并不知道源里有没有）。
	// 因此试运行下按"假设源里有"继续推演，让用户看到**计划的命令序列**。
	if !strings.Contains(logs, "跳过") || !strings.Contains(logs, "假设") {
		t.Errorf("试运行应说明探测被跳过、按假设推演：\n%s", logs)
	}
	if task.Strategy != StrategySystem {
		t.Errorf("试运行应在第一条策略（系统源）成功收尾，实际 %q", task.Strategy)
	}
	// 试运行下没有真实版本号可查，因此**不能**钉版本
	// （硬钉一个猜出来的版本号会得到一条永远不会成功的命令）。
	if strings.Contains(logs, "钉住版本") {
		t.Errorf("试运行不应钉版本（完整版本号只能查源得知）：\n%s", logs)
	}
}

// TestDryRunShowsPrebuiltPlan 验证试运行能展示预编译兜底的计划命令。
//
// 直接调用 prebuiltFallback 而不是走完整安装流程：试运行下
// 系统源被假定可行（探测被跳过），因此完整流程**永远**在第一条
// 策略就成功收尾，走不到预编译那一段。而预编译的计划展开
// （"将下载 X、解包到 Y、建立软链接 Z"）本身是要验证的行为，
// 所以按单元来测它，而不是绕一圈去构造一个不自然的输入。
func TestDryRunShowsPrebuiltPlan(t *testing.T) {
	root := t.TempDir()
	h := newTestHarness(t, func(o *Options) {
		o.DryRun = true
		o.PrebuiltRootOverride = root
		// 架构要有对应产物，否则会因为"没有该架构的包"提前跳过。
		o.Vars.Arch = "x64"
		o.Vars.Tools.Curl = "/usr/bin/curl"
		o.Vars.Tools.Tar = "/usr/bin/tar"
	})

	sw, ok := h.mgr.Catalog().Get("nodejs")
	if !ok {
		t.Fatal("清单里应有 nodejs")
	}
	_, ver, ok := h.mgr.Catalog().FindVersion("nodejs", "22")
	if !ok {
		t.Fatal("应有 nodejs 22")
	}
	if ver.Prebuilt == nil {
		t.Fatal("nodejs 22 应提供预编译兜底")
	}

	// 用管理器自己的 newTask 建任务状态：日志环形缓冲、
	// 日志上限、步骤表都由它初始化，手搓一个会漏掉这些。
	ts := h.mgr.newTask(TaskInstall, sw.ID, sw.Name, ver.ID, "tester", "127.0.0.1")
	if err := h.mgr.prebuiltFallback(context.Background(), ts, sw, ver); err != nil {
		t.Fatalf("试运行下预编译兜底应成功: %v\n日志:\n%s", err,
			logsText(t, h.mgr, ts.t.ID))
	}

	logs := logsText(t, h.mgr, ts.t.ID)
	// 试运行不能去读官方索引（读索引要先下载），因此按规则合成文件名：
	// 前缀 + 版本 ID + 后缀。补丁号只有真读索引才知道。
	if !strings.Contains(logs, "node-v22-linux-x64.tar.gz") {
		t.Errorf("日志应展示将要下载的归档名：\n%s", logs)
	}
	if !strings.Contains(logs, "--strip-components=1") {
		t.Errorf("日志应展示解包命令：\n%s", logs)
	}
	// 零副作用：不下载、不建目录、不建软链接、不写安装记录。
	if len(h.sys.snapshotDownloads()) != 0 {
		t.Errorf("试运行不得下载: %v", h.sys.snapshotDownloads())
	}
	for _, p := range []string{
		filepath.Join(root, "usr/local/lib/lipanel/nodejs-22"),
		filepath.Join(root, "usr/local/bin/node"),
		filepath.Join(h.stateDir, "prebuilt.json"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("试运行不应创建 %s", p)
		}
	}
}

// TestUninstallRemovesPackages 验证卸载链路。
func TestUninstallRemovesPackages(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.26.2-1~jammy")

	task := h.uninstallAndWait("nginx", "1.26")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if _, ok := h.sys.installed["nginx"]; ok {
		t.Errorf("包应被移除: %v", h.sys.installed)
	}
	joined := strings.Join(h.sys.snapshotCommands(), "\n")
	// 卸载**不带**版本约束（apt-get remove nginx=1.26 是错的写法）。
	if !strings.Contains(joined, "apt-get remove -y") || !strings.Contains(joined, " nginx") {
		t.Errorf("应调用包管理器卸载: %v", h.sys.snapshotCommands())
	}
	if !strings.Contains(joined, "autoremove") {
		t.Errorf("应清理不再需要的依赖: %v", h.sys.snapshotCommands())
	}
	// 复验：卸载后必须确认真的没了。
	if !strings.Contains(joined, "dpkg-query") {
		t.Errorf("卸载后应复验: %v", h.sys.snapshotCommands())
	}
}

// TestUninstallNotInstalled 验证"本来就没装"时如实说明而不是报错。
func TestUninstallNotInstalled(t *testing.T) {
	h := newTestHarness(t, nil)

	task := h.uninstallAndWait("nginx", "1.26")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功（无事可做），实际 %s: %s", task.Status, task.Error)
	}
	// 关键：不能拿着"清单里声明的包名"去调包管理器。
	// 那些包多半根本没装，apt 对"没有可卸载的包"会返回非 0，
	// 于是"本来就没装"会被报告成"卸载失败"。
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, "remove") {
			t.Errorf("未安装时不应执行卸载命令: %v", h.sys.snapshotCommands())
		}
	}
	if !strings.Contains(logsText(t, h.mgr, task.ID), "未检测到") {
		t.Error("日志应说明未检测到已安装的包")
	}
	if stepStatus(task) != "system:skipped" {
		t.Errorf("步骤摘要 = %s", stepStatus(task))
	}
}

// TestUninstallPrebuiltRemovesFilesAndRecord 验证预编译安装的卸载。
//
// 预编译安装没有包管理器记录，卸载必须靠我们自己清理：
// 软链接、安装目录、状态文件三样都不能剩。
func TestUninstallPrebuiltRemovesFilesAndRecord(t *testing.T) {
	root := t.TempDir()
	h := newTestHarness(t, func(o *Options) {
		o.PrebuiltRootOverride = root
	})
	// 先真的装一遍（走预编译）。
	h.sys.candidates["nodejs"] = "12.22.9~dfsg-1ubuntu3.2"
	if task := h.installAndWait("nodejs", "22"); task.Status != TaskSucceeded {
		t.Fatalf("预编译安装应成功: %s", task.Error)
	}
	link := filepath.Join(root, "usr/local/bin/node")
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("前置条件不成立，软链接不存在: %v", err)
	}

	task := h.uninstallAndWait("nodejs", "22")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("软链接未清理")
	}
	if _, err := os.Stat(filepath.Join(root, "usr/local/lib/lipanel/nodejs-22")); !os.IsNotExist(err) {
		t.Error("安装目录未清理")
	}
	data, err := os.ReadFile(filepath.Join(h.stateDir, "prebuilt.json"))
	if err == nil && strings.Contains(string(data), "nodejs") {
		t.Errorf("安装记录未清理: %s", string(data))
	}
	// 卸载后状态应回到"未安装"。
	st, err := h.mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	for _, sw := range st.Software {
		if sw.ID != "nodejs" {
			continue
		}
		if sw.Installed {
			t.Errorf("卸载后仍报告已安装: %+v", sw)
		}
	}
}

// TestStatusReflectsInstallation 验证状态聚合。
//
// 关键点：系统里装着一个**清单里没有**的版本时（比如发行版自带的 1.18
// 而我们清单里也有，但这里用 1.20 制造差异），必须如实显示
// "已安装但不在可选列表里"，而不是假装没装。
func TestStatusReflectsInstallation(t *testing.T) {
	h := newTestHarness(t, nil)
	// 1.20 不在 nginx 的可选版本里（清单为 1.26/1.24/1.18）。
	h.sys.setInstalled("nginx", "1.20.0-custom")

	st, err := h.mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	var nginx SoftwareStatus
	for _, sw := range st.Software {
		if sw.ID == "nginx" {
			nginx = sw
		}
	}
	if !nginx.Installed {
		t.Fatalf("应报告已安装: %+v", nginx)
	}
	if nginx.DetectedVersion != "1.20.0-custom" {
		t.Errorf("DetectedVersion = %q，应回显系统里的真实版本", nginx.DetectedVersion)
	}
	if len(nginx.InstalledVersions) != 0 {
		t.Errorf("1.20 不在清单里，InstalledVersions 应为空: %v", nginx.InstalledVersions)
	}
	if st.Counts.Installed < 1 {
		t.Errorf("Counts = %+v", st.Counts)
	}
	// 未安装的软件也要如实出现。
	if len(st.Software) != len(h.mgr.Catalog().Software) {
		t.Errorf("状态应覆盖全部软件: %d != %d", len(st.Software), len(h.mgr.Catalog().Software))
	}
}

// TestTaskLogsCursor 验证日志游标增量拉取（前端轮询依赖它）。
func TestTaskLogsCursor(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("nginx", "1.26")
	all, ok := h.mgr.TaskLogs(task.ID, 0)
	if !ok {
		t.Fatal("任务不存在")
	}
	if len(all) == 0 {
		t.Fatal("应有日志")
	}
	// 游标语义：序号必须严格递增，便于前端去重。
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatalf("日志序号必须递增: %d 后出现 %d", all[i-1].Seq, all[i].Seq)
		}
	}
	// 从中间追加，只能拿到之后的行。
	mid := all[len(all)/2].Seq
	rest, _ := h.mgr.TaskLogs(task.ID, mid)
	if len(rest) == 0 {
		t.Fatal("增量拉取应返回后续日志")
	}
	if rest[0].Seq <= mid {
		t.Errorf("增量拉取返回了旧日志: since=%d 首条=%d", mid, rest[0].Seq)
	}
	if len(rest) >= len(all) {
		t.Errorf("增量拉取不应返回全部日志: %d", len(rest))
	}
	// 越界游标返回空而不是报错。
	if tail, _ := h.mgr.TaskLogs(task.ID, 1<<30); len(tail) != 0 {
		t.Errorf("越界游标应返回空: %v", tail)
	}
}

// TestTaskProgressMonotonic 验证进度只增不减（前端进度条依赖它）。
func TestTaskProgressMonotonic(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task, err := h.install("nginx", "1.26")
	if err != nil {
		t.Fatalf("StartInstall 失败: %v", err)
	}
	last := -1
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := h.mgr.Task(task.ID)
		if !ok {
			t.Fatal("任务消失")
		}
		if task.Progress < last {
			t.Fatalf("进度回退: %d → %d", last, task.Progress)
		}
		last = task.Progress
		if task.Status == TaskSucceeded || task.Status == TaskFailed {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	final, _ := h.mgr.Task(task.ID)
	if final.Status != TaskSucceeded {
		t.Fatalf("应成功: %s", final.Error)
	}
	if final.Progress != 100 {
		t.Errorf("成功后进度应为 100，实际 %d", final.Progress)
	}
}

// TestManagerShutdown 验证关停行为。
//
// 没有任务在跑时应当立刻返回；有任务时不能"杀掉 dpkg"，
// 只能是等待或超时返回。
func TestManagerShutdown(t *testing.T) {
	h := newTestHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.mgr.Shutdown(ctx); err != nil {
		t.Fatalf("空闲时关停应立即成功: %v", err)
	}

	// 有任务在跑：关停应在 ctx 超时后返回错误，而不是强杀。
	h.sys.block = make(chan struct{})
	h.sys.blockOn = "install"
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"
	defer close(h.sys.block)
	task, err := h.install("nginx", "1.26")
	if err != nil {
		t.Fatalf("StartInstall 失败: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(h.sys.snapshotCommands()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("任务没有开始执行")
		}
		time.Sleep(2 * time.Millisecond)
	}
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelShort()
	start := time.Now()
	err = h.mgr.Shutdown(shortCtx)
	if err == nil {
		t.Error("有任务在跑且超时，应返回错误提示仍在进行")
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("关停应等待而不是立即放弃，耗时 %v", elapsed)
	}
	// 任务必须还在（不能因为我们关停就把它标记成失败）。
	if got, _ := h.mgr.Task(task.ID); got.Status != TaskRunning {
		t.Errorf("关停不应改变运行中任务的状态: %s", got.Status)
	}
}

// TestAuditRecordsInstall 验证审计落库（4.5 的最高风险操作必须可追溯）。
func TestAuditRecordsInstall(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("nginx", "1.26")
	events := h.audit.Query(AuditFilter{Action: ActionInstall, Limit: 100})
	if len(events) == 0 {
		t.Fatal("应有审计事件")
	}
	var found *AuditEvent
	for i := range events {
		if events[i].TaskID == task.ID {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatalf("未找到任务 %s 的审计事件: %+v", task.ID, events)
	}
	if found.Outcome != AuditAllowed {
		t.Errorf("Outcome = %q", found.Outcome)
	}
	if found.Action != ActionInstall {
		t.Errorf("Action = %q", found.Action)
	}
	if found.Source != SourceCore {
		t.Errorf("Source = %q（核心模块不得伪装成插件）", found.Source)
	}
	if found.Strategy != StrategySystem {
		t.Errorf("Strategy = %q", found.Strategy)
	}
	if found.User != "admin" || found.ClientIP != "127.0.0.1" {
		t.Errorf("审计应记录操作者: %+v", found)
	}
	if !found.SystemChange {
		t.Error("软件安装必须标记为系统变更")
	}
}

// TestAuditRecordsFailure 验证失败也要留痕。
func TestAuditRecordsFailure(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.18.0-6ubuntu14")

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskFailed {
		t.Fatalf("前置条件不成立: %s", task.Status)
	}
	events := h.audit.Query(AuditFilter{Action: ActionInstall, Limit: 100})
	if len(events) == 0 {
		t.Fatal("失败也必须有审计事件")
	}
	last := events[len(events)-1]
	if last.TaskID != task.ID {
		t.Errorf("审计事件应指向该任务: %+v", last)
	}
	if last.Outcome != AuditFailed {
		t.Errorf("Outcome = %q，失败应记为 failed", last.Outcome)
	}
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

// rockyVars 返回一套 RHEL 系（Rocky 9）的环境描述。
func rockyVars(manager string) Vars {
	path := "/usr/bin/dnf"
	if manager == PackageManagerYUM {
		path = "/usr/bin/yum"
	}
	return Vars{
		Manager: manager, ManagerPath: path,
		Family: FamilyRHEL, DistroID: "rocky", DistroName: "Rocky Linux 9.4",
		VersionID: "9.4", Codename: "9", Arch: "x64",
		Tools: Tools{
			DpkgQuery: "/usr/bin/dpkg-query", RPM: "/usr/bin/rpm",
			Curl: "/usr/bin/curl", Tar: "/usr/bin/tar",
		},
		DistroSupported: true,
	}
}

// ---------------------------------------------------------------------------
// 钉版本（Version.PinSystemVersion）
// ---------------------------------------------------------------------------

// TestInstallPinsSystemVersion 验证共用包名的版本会钉住具体版本号。
//
// ########## 这个测试锁住的是一个真实踩过的坑 ##########
//
// nginx 1.26/1.24/1.18 在源里是**同一个包名 nginx**，
// 只能靠 `apt-get install nginx=<完整版本>` 区分。早先的实现
// 把版本编进包名（nginx1.26），造出了一个不存在的包，
// 于是"选 1.26"永远装不上——而日志看起来只是"源里没有"，
// 极难定位。
func TestInstallPinsSystemVersion(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskSucceeded {
		t.Fatalf("应成功，实际 %s: %s\n日志:\n%s", task.Status, task.Error,
			logsText(t, h.mgr, task.ID))
	}

	// 安装命令必须带 = 版本（钉住），而不是把版本拼进包名。
	cmds := h.sys.snapshotCommands()
	var install string
	for _, c := range cmds {
		if strings.Contains(c, " install ") {
			install = c
			break
		}
	}
	if install == "" {
		t.Fatalf("未执行安装命令: %v", cmds)
	}
	if !strings.Contains(install, "nginx=1.26.2-1~jammy") {
		t.Errorf("安装命令应钉住源里的完整版本号: %s", install)
	}
	if strings.Contains(install, "nginx1.26") {
		t.Errorf("不应把版本编进包名（该包不存在）: %s", install)
	}

	// 上报的包名是**裸名**：审计与界面看的是"装了哪些包"，
	// 而版本号随后续源更新会变。
	if len(task.Packages) != 1 || task.Packages[0] != "nginx" {
		t.Errorf("Packages = %v，应为裸包名 [nginx]", task.Packages)
	}

	// 复验必须用裸包名查到（dpkg-query 不认识 pkg=ver 语法）。
	// 若这里写错，会出现"明明装上了却报未安装"。
	if got := h.sys.installed["nginx"]; got != "1.26.2-1~jammy" {
		t.Errorf("已安装版本 = %q", got)
	}
	if task.Progress != 100 {
		t.Errorf("Progress = %d", task.Progress)
	}
}

// TestInstallPinNotAppliedWhenVersionHasNoCandidate 验证查不到候选时不硬钉。
//
// 查不到完整版本号却硬钉，会造出一个不存在的版本约束而必然失败；
// 此时应退化为"不钉"并**如实告警**，而不是静默地装任意版本。
func TestInstallPinFallsBackWithoutCandidate(t *testing.T) {
	h := newTestHarness(t, nil)
	// 候选为空 → ready 判定为不可用 → 不会走到钉版本那一步。
	h.sys.candidates["nginx"] = ""

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskFailed {
		t.Fatalf("无候选版本时应失败，实际 %s", task.Status)
	}
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, " install ") {
			t.Errorf("不应执行安装命令: %s", c)
		}
	}
}

// TestInstallVersionMismatchDoesNotRetryOtherPackageNames 验证版本不符时不换包名重试。
//
// 包装上了但版本不对时再试 nginx-core 毫无意义，还会把真正的原因
// （期望 1.26，实际 1.20）埋在一堆无用重试里。
//
// 注意用 **1.18**（不钉版本的档位）：钉版本的档位（1.26/1.24）
// 会把版本约束写进命令，装错版本这件事从根上就不会发生——
// 那正是钉版本的意义。这里要测的是"钉不住时怎么办"，
// 也就是发行版自带档位的行为。
func TestInstallVersionMismatchDoesNotRetryOtherPackageNames(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.candidates["nginx"] = "1.18.0-6ubuntu14"
	h.sys.installVersion = func(string) string { return "1.20.0-wrong" }

	task := h.installAndWait("nginx", "1.18")
	if task.Status != TaskFailed {
		t.Fatalf("版本不符必须失败，实际 %s", task.Status)
	}
	// 关键：不得再去试**安装**备选包名。
	//
	// 只检查 install，不能笼统地找 "nginx-core"：冲突预检会
	// 用一条 dpkg-query 同时查 nginx 与 nginx-core（**只读**，
	// 是正确行为），把它算成"重试"会误报。
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, " install ") && strings.Contains(c, "nginx-core") {
			t.Errorf("版本不符后不应换包名重试安装: %s", c)
		}
	}
	logs := logsText(t, h.mgr, task.ID)
	if !strings.Contains(logs, "版本不符") {
		t.Errorf("日志应说明版本不符：\n%s", logs)
	}
	if !strings.Contains(logs, "1.20.0-wrong") {
		t.Errorf("日志里应出现实际版本：\n%s", logs)
	}
	// 顶层错误也要能看出是版本问题，而不是"源不可用"。
	if !strings.Contains(task.Error, "版本不符") {
		t.Errorf("顶层错误应说明版本不符: %q", task.Error)
	}
}

// TestInstallSharedPackageNameConflictDetected 验证共用包名时冲突仍被检出。
//
// nginx 的三个版本共用包名 nginx，因此"包在不在数据库里"
// 不能用来判断装了哪个版本；必须拿**实际版本串**去比对。
func TestInstallSharedPackageNameConflictDetected(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.18.0-6ubuntu14")
	h.sys.candidates["nginx"] = "1.26.2-1~jammy"

	task := h.installAndWait("nginx", "1.26")
	if task.Status != TaskFailed {
		t.Fatalf("应拒绝，实际 %s", task.Status)
	}
	if !strings.Contains(task.Error, "已安装") {
		t.Errorf("错误应说明已安装其它版本: %q", task.Error)
	}
	// 已装的 1.18 必须原样保留。
	if got := h.sys.installed["nginx"]; got != "1.18.0-6ubuntu14" {
		t.Errorf("已安装版本不应被改动，实际 %q", got)
	}
}

// TestInstallSamePackageNameSameVersionIsIdempotent 验证已装目标版本时幂等。
//
// 与上一条配套：共用包名时"装的是 1.18、要装 1.18"必须识别为
// **已安装**（跳过），而不是误判成冲突而拒绝。
func TestInstallSamePackageNameSameVersionIsIdempotent(t *testing.T) {
	h := newTestHarness(t, nil)
	h.sys.setInstalled("nginx", "1.18.0-6ubuntu14")

	task := h.installAndWait("nginx", "1.18")
	if task.Status != TaskSucceeded {
		t.Fatalf("已是目标版本应幂等成功，实际 %s: %s", task.Status, task.Error)
	}
	for _, c := range h.sys.snapshotCommands() {
		if strings.Contains(c, " install ") {
			t.Errorf("无需重复安装，却执行了: %s", c)
		}
	}
}
