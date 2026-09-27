package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// 假系统：一个内存里的包管理器
// ============================================================================
//
// 安装链路的每一条策略分支都必须能被测试穷举，而这些分支的
// 真实触发条件是"某台 Debian 机器上恰好没有 php8.3"——
// 测试环境不可能也不该去满足这些条件。
//
// 因此这里实现一个**语义级**的假包管理器：它理解 apt-cache policy /
// dpkg-query / apt-get install / dnf list 这几条命令的含义，
// 维护一个内存包数据库，并按数据库回答问题。
// 被测代码走的是与生产完全相同的代码路径（同样的 argv 组装、
// 同样的输出解析），只有最后一步"碰操作系统"被替换掉了。

type fakeSystem struct {
	mu sync.Mutex

	// installed 是"已安装"包数据库（包名 → 版本串）。
	installed map[string]string
	// candidates 是 apt-cache policy 的候选版本。
	candidates map[string]string
	// available 是 dnf --showduplicates list available 的输出。
	available map[string][]string

	// commands 记录执行过的命令（供断言"到底调了哪几条"）。
	commands []string
	// scripts 记录经由 sh 执行的脚本命令。
	scripts []string
	// downloads 记录下载过的 URL（顺序保留）。
	downloads []string

	// failOn 可注入失败：返回 (退出码, stderr)。
	failOn func(name string, args []string) (int, string)
	// block 非 nil 时，匹配到的命令会阻塞直到该 channel 关闭（测并发锁）。
	block chan struct{}
	// blockOn 是触发阻塞的命令子串。
	blockOn string

	// archiveTopDir 决定预编译归档解包后的顶层目录名。
	archiveTopDir string

	// afterDownload / afterScript 是"副作用钩子"。
	//
	// ########## 为什么需要钩子而不是简单的失败注入 ##########
	//
	// 多级回退策略真正要测的是**状态转移**：
	// "追加官方源之前，apt-cache 查不到这个版本；追加之后就查得到"。
	// 只注入失败无法表达这种语义。钩子让测试可以定义
	// "哪条命令执行之后，系统状态发生变化"，
	// 从而把回退链路当成一台真实的机器来跑。
	afterDownload func(url string)
	afterScript   func(cmd string)

	// afterRPMRepoInstall 在 `dnf install <release-rpm-url>` 之后触发，
	// 对应"装了 remi-release 之后仓库里才有新版本"。
	afterRPMRepoInstall func(url string)

	// installVersion 决定"假安装"之后写进数据库的版本。
	// 默认取候选版本；覆盖它可以模拟
	// "包管理器装了另一个版本"——那正是安装后复验要抓的情况。
	installVersion func(pkg string) string
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		installed:     map[string]string{},
		candidates:    map[string]string{},
		available:     map[string][]string{},
		archiveTopDir: "node-v22.14.0-linux-x64",
	}
}

func (f *fakeSystem) Run(ctx context.Context, name string, args []string) (ExecResult, error) {
	base := filepath.Base(name)
	f.mu.Lock()
	f.commands = append(f.commands, RenderCommand(name, args))

	if f.blockOn != "" && f.block != nil && strings.Contains(strings.Join(args, " "), f.blockOn) {
		f.mu.Unlock()
		// 尊重 ctx：真实的 exec.CommandContext 在超时时会杀掉子进程并返回，
		// 假执行器必须复现这个语义，否则超时分支无法被测试。
		select {
		case <-ctx.Done():
			return ExecResult{}, fmt.Errorf("%w: %s 未在超时时间内返回", ErrTimeout, base)
		case <-f.block:
		}
		f.mu.Lock()
	}

	var code int
	var stderr string
	var post func()
	if f.failOn != nil {
		code, stderr = f.failOn(base, args)
	}
	if code == 0 {
		code, stderr, post = f.dispatchLocked(base, args)
	}
	stdout := ""
	if code == 0 {
		stdout = f.stdoutOf(base, args)
	}
	f.mu.Unlock()
	// 状态变更钩子在解锁后执行，避免持锁回调自锁。
	if post != nil {
		post()
	}

	res := ExecResult{Stdout: stdout, Stderr: stderr, ExitCode: code}
	if code != 0 {
		return res, fmt.Errorf("%w: %s 退出码 %d", errExitNonZero, base, code)
	}
	return res, nil
}

func (f *fakeSystem) RunScript(_ context.Context, cmd string) (ExecResult, error) {
	f.mu.Lock()
	f.scripts = append(f.scripts, cmd)
	var code int
	var stderr string
	if f.failOn != nil {
		code, stderr = f.failOn("sh", []string{"-c", cmd})
	}
	hook := f.afterScript
	f.mu.Unlock()
	if code == 0 && hook != nil {
		hook(cmd)
	}
	res := ExecResult{Stdout: "[fake script ok] " + cmd, Stderr: stderr, ExitCode: code}
	if code != 0 {
		return res, fmt.Errorf("%w: sh 退出码 %d", errExitNonZero, code)
	}
	return res, nil
}

// dispatchLocked 模拟命令的真实副作用（更新包数据库、写下载文件）。
// 返回 (退出码, stderr)。stdout 由 stdoutOf 单独计算，便于保持结构清晰。
func (f *fakeSystem) dispatchLocked(base string, args []string) (int, string, func()) {
	// 子命令：apt-get 的参数以 "install" 开头，dnf 的则以 "-y" 开头，
	// 因此统一取"第一个不是选项的参数"。
	sub := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			sub = a
			break
		}
	}

	switch {
	case base == "curl":
		// -o <dest> -- <url>
		dest, url := "", ""
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				dest = args[i+1]
			}
			if a == "--" && i+1 < len(args) {
				url = args[i+1]
			}
		}
		if url == "" || dest == "" {
			return 22, "curl: 缺少参数", nil
		}
		f.downloads = append(f.downloads, url)
		if err := f.writeDownloadedFile(dest, url); err != nil {
			return 23, err.Error(), nil
		}
		// 钩子必须**解锁之后**再调用：它会回头修改这个假系统的状态
		// （模拟"加上了官方源，版本才可用"），持锁回调会自锁。
		hook := f.afterDownload
		return 0, "", func() {
			if hook != nil {
				hook(url)
			}
		}

	case base == "apt-get" && sub == "install":
		for _, a := range args {
			if isPackageArg(a) {
				// `pkg=version` 是 apt 的钉版本语法：包数据库里记的是
				// **包名**，版本取 = 右边的值。假系统必须复现这一点，
				// 否则复验（dpkg-query pkg）会查不到——
				// 而那正好会掩盖"钉版本写错了"这类真实 bug。
				name, wantVer := splitPinned(a)
				if wantVer != "" {
					f.installed[name] = wantVer
					continue
				}
				f.installed[name] = f.candidateOf(name)
				if f.installVersion != nil {
					f.installed[name] = f.installVersion(name)
				}
			}
		}
		return 0, "", nil

	case base == "apt-get" && sub == "remove":
		for _, a := range args {
			if isPackageArg(a) {
				name, _ := splitPinned(a)
				delete(f.installed, name)
			}
		}
		return 0, "", nil

	case base == "dnf" || base == "yum":
		if sub == "install" {
			var repoURL string
			for _, a := range args {
				if strings.HasPrefix(a, "https://") {
					repoURL = a // release 包安装，不改包数据库
					continue
				}
				if isPackageArg(a) {
					name, wantVer := splitPinned(a)
					if wantVer != "" {
						f.installed[name] = wantVer
						continue
					}
					f.installed[name] = f.firstAvailable(name)
					if f.installVersion != nil {
						f.installed[name] = f.installVersion(name)
					}
				}
			}
			if repoURL != "" && f.afterRPMRepoInstall != nil {
				hook := f.afterRPMRepoInstall
				return 0, "", func() { hook(repoURL) }
			}
		}
		if sub == "remove" {
			for _, a := range args {
				if isPackageArg(a) {
					delete(f.installed, a)
				}
			}
		}
		return 0, "", nil

	case base == "tar":
		code, msg := f.extract(args)
		return code, msg, nil
	}
	return 0, "", nil
}

// splitPinned 拆开 apt 的 `pkg=version` 语法。
//
// 返回 (包名, 版本)；不含 = 时版本为空串。
func splitPinned(a string) (string, string) {
	if i := strings.Index(a, "="); i >= 0 {
		return a[:i], a[i+1:]
	}
	return a, ""
}

// stdoutOf 生成命令的标准输出。
func (f *fakeSystem) stdoutOf(base string, args []string) string {
	joined := strings.Join(args, " ")
	switch {
	case base == "apt-cache" && strings.Contains(joined, "policy"):
		pkg := lastPackageArg(args)
		cand := f.candidates[pkg]
		if cand == "" {
			cand = "(none)"
		}
		return fmt.Sprintf("%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n",
			pkg, orNone(f.installed[pkg]), cand)

	case base == "dpkg-query":
		var b strings.Builder
		for _, a := range args {
			if isPackageArg(a) {
				if v, ok := f.installed[a]; ok {
					fmt.Fprintf(&b, "%s|%s|ii \n", a, v)
				}
			}
		}
		return b.String()

	case base == "rpm" && strings.Contains(joined, "-q"):
		var b strings.Builder
		for _, a := range args {
			if isPackageArg(a) {
				if v, ok := f.installed[a]; ok {
					fmt.Fprintf(&b, "%s|%s\n", a, v)
				} else {
					b.WriteString("package " + a + " is not installed\n")
				}
			}
		}
		return b.String()

	case (base == "dnf" || base == "yum") && strings.Contains(joined, " list available"):
		pkg := lastPackageArg(args)
		var b strings.Builder
		b.WriteString("Available Packages\n")
		for _, v := range f.available[pkg] {
			fmt.Fprintf(&b, "%s.x86_64    %s    fake-repo\n", pkg, v)
		}
		return b.String()

	default:
		return ""
	}
}

// writeDownloadedFile 为下载请求生成一个可信的文件内容。
//
// 归档请求生成**真实的 tar.gz**（含一个顶层目录与 bin/ 下的可执行文件），
// 这样解包、软链接、验证三步都能按真实语义被测试。
func (f *fakeSystem) writeDownloadedFile(dest, url string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if strings.HasSuffix(url, ".tar.gz") {
		return writeFakeTarGz(dest, f.archiveTopDir)
	}
	if strings.Contains(filepath.Base(url), "SHASUMS") {
		// 一个真的官方索引长什么样，这里就给什么样。
		content := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2  node-v22.14.0-linux-x64.tar.gz\n" +
			"0000000000000000000000000000000000000000000000000000000000000000  node-v22.14.0-headers.tar.gz\n"
		return os.WriteFile(dest, []byte(content), 0o644)
	}
	return os.WriteFile(dest, []byte("-----FAKE GPG KEY-----\n"), 0o644)
}

// writeFakeTarGz 写一个含顶层目录与 bin/ 可执行文件的 tar.gz。
func writeFakeTarGz(path, topDir string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz := gzip.NewWriter(f)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	for _, bin := range []string{"node", "npm", "npx"} {
		body := "#!/bin/sh\necho v22.14.0\n"
		hdr := &tar.Header{
			Name: topDir + "/bin/" + bin,
			Mode: 0o755,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			return err
		}
	}
	return nil
}

// extract 模拟 tar -xzf archive -C dest --strip-components=1。
func (f *fakeSystem) extract(args []string) (int, string) {
	archive, dest, strip := "", "", false
	for i, a := range args {
		switch {
		case a == "-C" && i+1 < len(args):
			dest = args[i+1]
		case a == "--strip-components=1":
			strip = true
		case strings.HasSuffix(a, ".tar.gz"):
			archive = a
		}
	}
	if archive == "" || dest == "" {
		return 2, "tar: 参数不足"
	}
	src, err := os.Open(archive)
	if err != nil {
		return 2, "tar: " + err.Error()
	}
	defer func() { _ = src.Close() }()
	gz, err := gzip.NewReader(src)
	if err != nil {
		return 2, "tar: 不是合法的 gzip"
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		name := hdr.Name
		if strip {
			if i := strings.Index(name, "/"); i >= 0 {
				name = name[i+1:]
			}
		}
		if name == "" {
			continue
		}
		out := filepath.Join(dest, name)
		if !strings.HasPrefix(out, filepath.Clean(dest)+string(os.PathSeparator)) {
			return 2, "tar: 归档含越界路径 " + hdr.Name
		}
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return 2, err.Error()
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return 2, err.Error()
		}
		data, err := readAllTar(tr)
		if err != nil {
			return 2, err.Error()
		}
		if err := os.WriteFile(out, data, os.FileMode(hdr.Mode)); err != nil {
			return 2, err.Error()
		}
	}
	return 0, ""
}

func readAllTar(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if n == 0 {
				return out, nil
			}
			return out, nil
		}
		if len(out) > 1<<20 {
			return out, nil
		}
	}
}

// candidateOf 返回包名在假数据库里的候选版本（默认给一个"最新"版本）。
func (f *fakeSystem) candidateOf(pkg string) string {
	if v, ok := f.candidates[pkg]; ok && v != "" {
		return v
	}
	return "9.9.9-1fake"
}

func (f *fakeSystem) firstAvailable(pkg string) string {
	if vs := f.available[pkg]; len(vs) > 0 {
		return vs[len(vs)-1]
	}
	return "9.9.9-1fake"
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// isPackageArg 判断参数是否可能是包名（过滤掉选项与 -o 的值）。
func isPackageArg(a string) bool {
	if a == "" || strings.HasPrefix(a, "-") {
		return false
	}
	switch a {
	case "install", "remove", "update", "autoremove", "policy", "list",
		"available", "makecache", "--showduplicates", "-y",
		"--no-install-recommends", "--", "Dpkg::Options::=--force-confdef",
		"Dpkg::Options::=--force-confold", "--setopt=install_weak_deps=False":
		return false
	}
	// -o <kv> 的 kv 形态（如 Dpkg::Options::=--force-confdef）。
	//
	// 注意不能简单地"含 = 就不是包名"：apt 的钉版本语法
	// （nginx=1.26.2-1~jammy）也含 =，而那是**包条目**。
	// 两者靠形态区分：选项值里 = 左边含 `::` 或以 `-` 开头。
	if i := strings.Index(a, "="); i >= 0 {
		left := a[:i]
		if strings.Contains(left, "::") || strings.HasPrefix(left, "-") {
			return false
		}
	}
	// 排除选项值（紧跟 -o 的值由 "=" 判断已覆盖）
	return strings.IndexFunc(a, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
	}) == 0
}

func lastPackageArg(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if isPackageArg(args[i]) {
			return args[i]
		}
	}
	return ""
}

// snapshotCommands 返回执行过的命令（供断言）。
func (f *fakeSystem) snapshotCommands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func (f *fakeSystem) snapshotScripts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scripts...)
}

func (f *fakeSystem) snapshotDownloads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.downloads...)
}

func (f *fakeSystem) setInstalled(pkg, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed[pkg] = version
}

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

// testManager 构造一个完全隔离的 Manager：临时状态目录、假执行器、
// 假包数据库，并返回可用于断言的句柄。
type testHarness struct {
	t          *testing.T
	mgr        *Manager
	sys        *fakeSystem
	audit      *Auditor
	stateDir   string
	listDir    string
	keyringDir string
	yumRepoDir string
	vars       Vars
}

func newTestHarness(t *testing.T, mut func(*Options)) *testHarness {
	t.Helper()
	dir := t.TempDir()
	sys := newFakeSystem()

	vars := Vars{
		Manager:     PackageManagerAPT,
		ManagerPath: "/usr/bin/apt-get",
		Family:      FamilyDebian,
		DistroID:    "ubuntu",
		DistroName:  "Ubuntu 22.04.5 LTS",
		VersionID:   "22.04",
		Codename:    "jammy",
		Arch:        "x64",
		Tools: Tools{
			AptGet: "/usr/bin/apt-get", AptCache: "/usr/bin/apt-cache",
			DpkgQuery: "/usr/bin/dpkg-query", RPM: "/usr/bin/rpm",
			Curl: "/usr/bin/curl", Tar: "/usr/bin/tar",
		},
		DistroSupported: true,
	}

	opts := Options{
		Logger: discardLogger(),
		// 环境由测试显式给出（含"没有包管理器"这种结果）。
		// 不让 NewManager 去重探本机：重探只会得到"这台机器上有 apt"，
		// 无法表达"确定不可用"这个必须被覆盖的分支。
		SkipDetect:           true,
		Executor:             sys,
		Vars:                 vars,
		StateDir:             filepath.Join(dir, "state"),
		ListDirOverride:      filepath.Join(dir, "apt-sources"),
		KeyringDirOverride:   filepath.Join(dir, "keyrings"),
		YumRepoDirOverride:   filepath.Join(dir, "yum-repos"),
		PrebuiltRootOverride: filepath.Join(dir, "prebuilt-root"),
		StepTimeout:          10 * time.Second,
		TaskTimeout:          30 * time.Second,
	}
	if mut != nil {
		mut(&opts)
	}
	m, err := NewManager(opts)
	if err != nil {
		t.Fatalf("构造 Manager 失败: %v", err)
	}
	return &testHarness{
		t: t, mgr: m, sys: sys, audit: m.Auditor(),
		stateDir: opts.StateDir, listDir: opts.ListDirOverride,
		keyringDir: opts.KeyringDirOverride, yumRepoDir: opts.YumRepoDirOverride,
		vars: m.Vars(),
	}
}

// discardLogger 返回一个丢弃全部输出的 logger（测试不污染终端）。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitTask 等待任务进入终态（超时即失败）。
func waitTask(t *testing.T, m *Manager, id string) Task {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := m.Task(id)
		if !ok {
			t.Fatalf("任务 %s 不存在", id)
		}
		if task.Status == TaskSucceeded || task.Status == TaskFailed {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	task, _ := m.Task(id)
	t.Fatalf("任务 %s 超时未结束，当前状态 %s / 阶段 %s", id, task.Status, task.Stage)
	return Task{}
}

// installAndWait 触发安装并等待结束。
func (h *testHarness) installAndWait(sw, version string) Task {
	h.t.Helper()
	task, err := h.mgr.StartInstall(context.Background(), InstallRequest{
		Software: sw, Version: version, User: "admin", ClientIP: "127.0.0.1",
	})
	if err != nil {
		h.t.Fatalf("StartInstall(%s %s) 失败: %v", sw, version, err)
	}
	return waitTask(h.t, h.mgr, task.ID)
}

// install 触发安装但不等待（用于断言参数校验与并发锁）。
func (h *testHarness) install(sw, version string) (Task, error) {
	return h.mgr.StartInstall(context.Background(), InstallRequest{
		Software: sw, Version: version, User: "admin", ClientIP: "127.0.0.1",
	})
}

func (h *testHarness) uninstallAndWait(sw, version string) Task {
	h.t.Helper()
	task, err := h.mgr.StartUninstall(context.Background(), InstallRequest{
		Software: sw, Version: version, User: "admin", ClientIP: "127.0.0.1",
	})
	if err != nil {
		h.t.Fatalf("StartUninstall(%s) 失败: %v", sw, err)
	}
	return waitTask(h.t, h.mgr, task.ID)
}

// stepStatus 返回 "key:status" 形式的步骤摘要。
func stepStatus(t Task) string {
	parts := make([]string, 0, len(t.Steps))
	for _, s := range t.Steps {
		parts = append(parts, s.Key+":"+s.Status)
	}
	return strings.Join(parts, ",")
}

// logsText 返回任务日志的纯文本（断言用）。
func logsText(t *testing.T, m *Manager, id string) string {
	t.Helper()
	lines, ok := m.TaskLogs(id, 0)
	if !ok {
		t.Fatalf("任务 %s 不存在", id)
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Level)
		b.WriteString(" ")
		b.WriteString(l.Text)
		b.WriteString("\n")
	}
	return b.String()
}
