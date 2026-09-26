// 本文件验证「真实进程 + 真实 Unix socket」的完整链路。
//
// 与 builtin_test.go 的区别：那里只测插件实现本身（httptest 直接打 mux），
// 这里测的是 process.go / manager.go / proxy.go 的实际行为——
// fork/exec、socket 就绪等待、转发、优雅停止、崩溃检测。
//
// 这些用例会真的拉起子进程，因此必须用「主程序自身」作为可执行文件。
// go test 会把测试二进制编译到临时目录，进程被拉起后
// os.Args[1] 会是 "__plugin_sysinfo"，此时子进程会走 main 的插件分支吗？
// 不会——这是测试二进制，不是 cmd/lipanel。
// 因此这些用例先编译出真正的 lipanel 二进制再跑（见 buildTestBinary），
// 否则「用测试二进制当插件宿主」会直接失败。
package plugin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"lipanel/internal/plugin"
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// buildTestBinary 编译一次真实的 lipanel 二进制并缓存路径。
// 插件进程必须是真实的主程序，否则 __plugin_sysinfo 子命令无人处理。
func buildTestBinary(t *testing.T) string {
	t.Helper()

	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "lipanel-testbin-")
		if err != nil {
			binErr = fmt.Errorf("创建临时目录失败: %w", err)
			return
		}
		out := filepath.Join(dir, "lipanel-test")

		// 从本测试文件所在目录回溯到模块根（internal/plugin → ../..）。
		cmd := exec.Command("go", "build", "-o", out, "./cmd/lipanel")
		cmd.Dir = moduleRoot()
		// 沙箱内 HOME 不可写，必须显式指定缓存目录（见开发计划坑位 6）。
		cmd.Env = append(os.Environ(),
			"GOMODCACHE=/tmp/gocache/mod",
			"GOPATH=/tmp/gocache",
			"GOCACHE=/tmp/gocache/build",
			"GOPROXY=https://goproxy.cn,direct",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("编译测试用 lipanel 失败: %w\n%s", err, output)
			return
		}
		binPath = out
	})

	if binErr != nil {
		t.Fatalf("%v", binErr)
	}
	return binPath
}

// moduleRoot 返回模块根目录。
func moduleRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	// 当前目录是 <root>/internal/plugin。
	return filepath.Dir(filepath.Dir(wd))
}

// newLiveManager 构造一个使用真实二进制的管理器。
// watcher 开启（默认行为），因为要验证崩溃检测。
func newLiveManager(t *testing.T) *plugin.Manager {
	t.Helper()

	m, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		ExecutablePath: buildTestBinary(t),
		Logger:         testLogger(),
		StartTimeout:   15 * time.Second,
		StopTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	if err := m.RegisterAllBuiltins(); err != nil {
		t.Fatalf("注册内置插件失败: %v", err)
	}
	// 测试结束务必回收子进程，避免污染后续用例。
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	return m
}

// TestLivePluginStartStop 是本次任务的核心用例：
// 真拉起进程 → 等 socket 就绪 → 转发请求拿到真实数据 → 优雅停止 → 进程与 socket 都被回收。
func TestLivePluginStartStop(t *testing.T) {
	m := newLiveManager(t)

	// --- 启动 ---
	st, err := m.Start(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("启动插件失败: %v", err)
	}
	if st.State != plugin.StateRunning {
		t.Fatalf("启动后状态 = %q, 期望 %q", st.State, plugin.StateRunning)
	}
	if st.PID <= 0 {
		t.Fatalf("托管模式启动后应有 PID，实际 = %d", st.PID)
	}
	// socket 必须真实存在且是 socket 类型。
	info, err := os.Stat(st.SocketPath)
	if err != nil {
		t.Fatalf("socket 文件不存在: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket 路径不是 socket 类型: %v", info.Mode())
	}
	// 权限必须是 0600：这是 Unix socket 方案的核心安全属性。
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket 权限 = %04o, 期望 0600", perm)
	}

	pid := st.PID

	// --- 通过 Manager 直接拨号，确认插件真的在响应 ---
	conn, err := m.Dial(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	_ = conn.Close()

	// --- 健康探测 ---
	hst, err := m.Health(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("Health 失败: %v", err)
	}
	if hst.Healthy == nil || !*hst.Healthy {
		t.Errorf("健康探测结果 = %v, 期望 true", hst.Healthy)
	}

	// --- 重复启动必须被拒绝 ---
	if _, err := m.Start(context.Background(), "sysinfo"); err == nil {
		t.Error("重复启动应当报错")
	}

	// --- 停止 ---
	stopped, err := m.Stop("sysinfo")
	if err != nil {
		t.Fatalf("停止插件失败: %v", err)
	}
	if stopped.State != plugin.StateStopped {
		t.Errorf("停止后状态 = %q, 期望 %q", stopped.State, plugin.StateStopped)
	}
	if stopped.PID != 0 {
		t.Errorf("停止后 PID 应为 0，实际 = %d", stopped.PID)
	}

	// 进程必须真的没了（这是「优雅停止」与「只是改了个状态」的区别）。
	if processExists(pid) {
		t.Errorf("插件进程 %d 在停止后仍然存在", pid)
	}
	// socket 文件也必须被清理，否则下次启动会 bind 失败。
	if _, err := os.Stat(stopped.SocketPath); !os.IsNotExist(err) {
		t.Errorf("停止后 socket 文件仍然存在: %v", err)
	}

	// 停止后转发必须失败。
	if _, err := m.Dial(context.Background(), "sysinfo"); err == nil {
		t.Error("停止后 Dial 应当失败")
	}
}

// TestLivePluginRestart 验证重启会换一个新的 PID。
func TestLivePluginRestart(t *testing.T) {
	m := newLiveManager(t)

	first, err := m.Start(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	second, err := m.Restart(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("重启失败: %v", err)
	}
	if second.State != plugin.StateRunning {
		t.Fatalf("重启后状态 = %q, 期望 %q", second.State, plugin.StateRunning)
	}
	if second.PID == first.PID {
		t.Errorf("重启后 PID 未变化（%d），说明进程没有被真的重启", first.PID)
	}
	if processExists(first.PID) {
		t.Errorf("重启后旧进程 %d 仍然存在", first.PID)
	}
}

// TestLivePluginCrashDetected 验证插件崩溃后核心能感知并标记为 failed。
//
// 这是「查询插件状态」这个需求里最关键的一条：
// 如果崩溃后状态还是 running，管理页就在撒谎。
func TestLivePluginCrashDetected(t *testing.T) {
	m := newLiveManager(t)

	st, err := m.Start(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	// 模拟插件崩溃。
	proc, err := os.FindProcess(st.PID)
	if err != nil {
		t.Fatalf("定位进程失败: %v", err)
	}
	if err := proc.Kill(); err != nil {
		t.Fatalf("杀死插件进程失败: %v", err)
	}

	// 等崩溃回调把状态改掉（异步，需要轮询）。
	deadline := time.Now().Add(5 * time.Second)
	var got plugin.Status
	for time.Now().Before(deadline) {
		got, err = m.Get("sysinfo")
		if err != nil {
			t.Fatalf("Get 失败: %v", err)
		}
		if got.State == plugin.StateFailed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if got.State != plugin.StateFailed {
		t.Fatalf("崩溃后状态 = %q, 期望 %q", got.State, plugin.StateFailed)
	}
	if got.LastError == "" {
		t.Error("崩溃后应记录 LastError，便于前端提示")
	}
	if got.PID != 0 {
		t.Errorf("崩溃后 PID 应为 0，实际 = %d", got.PID)
	}
}

// TestLivePluginCrashDoesNotAffectIntentionalStop 验证「用户主动停止」不会被误判为崩溃。
//
// 这是 intendedRunning 标志存在的意义：
// 停止流程与崩溃检测都在改同一个状态，若不加区分，
// 每次正常停止后插件列表都会显示为「失败」。
func TestLivePluginCrashDoesNotAffectIntentionalStop(t *testing.T) {
	m := newLiveManager(t)

	if _, err := m.Start(context.Background(), "sysinfo"); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if _, err := m.Stop("sysinfo"); err != nil {
		t.Fatalf("停止失败: %v", err)
	}

	// 留足时间让（可能存在的）崩溃回调触发。
	time.Sleep(500 * time.Millisecond)

	st, err := m.Get("sysinfo")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if st.State != plugin.StateStopped {
		t.Errorf("主动停止后状态 = %q, 期望 %q（不应被误判为崩溃）", st.State, plugin.StateStopped)
	}
	if st.LastError != "" {
		t.Errorf("主动停止不应记录错误，实际: %q", st.LastError)
	}
	if st.Restarts != 0 {
		t.Errorf("主动停止不应计入重启次数，实际 = %d", st.Restarts)
	}
}

// TestLiveShutdownStopsAllPlugins 验证核心退出时会回收插件进程。
// 否则主程序走了、插件还在，下次启动会连到一个「上辈子的」插件上。
func TestLiveShutdownStopsAllPlugins(t *testing.T) {
	m := newLiveManager(t)

	st, err := m.Start(context.Background(), "sysinfo")
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	pid := st.PID

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 失败: %v", err)
	}

	if processExists(pid) {
		t.Errorf("Shutdown 后插件进程 %d 仍存在", pid)
	}

	after, err := m.Get("sysinfo")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if after.State != plugin.StateStopped {
		t.Errorf("Shutdown 后状态 = %q, 期望 %q", after.State, plugin.StateStopped)
	}
}

// TestLiveProxyForwardsRequest 验证代理层能通过 Unix socket 拿到插件响应，
// 并且不把核心的凭据带过去。
func TestLiveProxyForwardsRequest(t *testing.T) {
	m := newLiveManager(t)

	if _, err := m.Start(context.Background(), "sysinfo"); err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	proxy := plugin.NewProxy(m)

	// 用 httptest 之外的方式构造响应记录（复用 builtin_test.go 的 recorder）。
	req, err := http.NewRequest(http.MethodGet, "/api/plugins/sysinfo/echo?probe=1", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	// 故意带上核心凭据，验证它们不会到达插件。
	req.Header.Set("Cookie", "lipanel_session=SHOULD_NOT_LEAK")
	req.Header.Set("Authorization", "Bearer SHOULD_NOT_LEAK")

	rec := newRecorder()
	proxy.ServeHTTP(rec, req, "sysinfo", "/echo")

	if rec.status != http.StatusOK {
		t.Fatalf("转发状态码 = %d, 期望 200, body=%s", rec.status, rec.body)
	}

	var payload struct {
		Plugin       string            `json:"plugin"`
		Query        string            `json:"query"`
		Path         string            `json:"path"`
		Headers      map[string]string `json:"headers"`
		CookieStripp bool              `json:"cookie_stripped"`
		AuthStripp   bool              `json:"authorization_stripped"`
	}
	if err := json.Unmarshal([]byte(rec.body), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v, body=%s", err, rec.body)
	}

	if payload.Plugin != "sysinfo" {
		t.Errorf("插件自报 ID = %q, 期望 sysinfo", payload.Plugin)
	}
	// 子路径与查询串必须正确透传。
	if payload.Path != "/echo" {
		t.Errorf("插件收到的 path = %q, 期望 /echo", payload.Path)
	}
	if payload.Query != "probe=1" {
		t.Errorf("插件收到的 query = %q, 期望 probe=1", payload.Query)
	}
	// 安全关键：核心的会话凭据绝不能被转发给插件。
	if !payload.CookieStripp {
		t.Errorf("Cookie 未被剥离，插件看到了: %q", payload.Headers["Cookie"])
	}
	if !payload.AuthStripp {
		t.Errorf("Authorization 未被剥离，插件看到了: %q", payload.Headers["Authorization"])
	}
	// 应带上来源标记头，插件可据此区分面板代理与直接访问。
	if payload.Headers["X-Lipanel-Plugin-Proxy"] != "1" {
		t.Error("缺少 X-Lipanel-Plugin-Proxy 标记头")
	}
}

// TestLiveProxyRejectsWhenStopped 验证未运行的插件返回 503 而不是超时。
func TestLiveProxyRejectsWhenStopped(t *testing.T) {
	m := newLiveManager(t)
	proxy := plugin.NewProxy(m)

	rec := newRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/plugins/sysinfo/info", nil)
	proxy.ServeHTTP(rec, req, "sysinfo", "/info")

	if rec.status != http.StatusServiceUnavailable {
		t.Errorf("未运行时状态码 = %d, 期望 503", rec.status)
	}
	if !strings.Contains(rec.body, "未运行") {
		t.Errorf("响应应说明插件未运行，实际: %s", rec.body)
	}
}

// TestLiveProxyPathTraversalBlocked 验证路径穿越在代理层被拦截。
func TestLiveProxyPathTraversalBlocked(t *testing.T) {
	m := newLiveManager(t)
	if _, err := m.Start(context.Background(), "sysinfo"); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	proxy := plugin.NewProxy(m)

	cases := []struct {
		name    string
		id      string
		subPath string
		want    int
	}{
		{"非法 ID 含上跳", "../etc", "/passwd", http.StatusBadRequest},
		{"非法 ID 大写", "SYSINFO", "/info", http.StatusBadRequest},
		{"子路径不以斜杠开头", "sysinfo", "info", http.StatusBadRequest},
		{"子路径为空", "sysinfo", "", http.StatusBadRequest},
		{"不存在的插件", "ghost", "/info", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			proxy.ServeHTTP(rec, req, tc.id, tc.subPath)

			if rec.status != tc.want {
				t.Errorf("状态码 = %d, 期望 %d, body=%s", rec.status, tc.want, rec.body)
			}
		})
	}
}

// ---------- 辅助 ----------

// processExists 判断进程是否仍然存在。
// 信号 0 不发送任何信号，只做存在性与权限检查（POSIX 语义）。
// 若进程已变成僵尸（尚未被父进程回收），Signal(0) 仍会成功，
// 但本测试的场景下父进程就是核心/管理器本身，会及时 Wait，
// 因此这里能可靠地区分「活着」与「已回收」。
func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
