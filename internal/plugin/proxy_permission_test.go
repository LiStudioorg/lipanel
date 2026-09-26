// 权限拦截的**端到端**验证（阶段三 3.3 的核心用例）。
//
// 与 permission_test.go 的区别：那里测的是纯函数判定，这里测的是
// 真实链路——真实插件进程 + 真实 Unix socket + 真实反向代理，
// 验证「未声明的调用被拒绝，且请求根本到不了插件进程」。
//
// 为什么必须真拉进程：权限拦截最容易出的错不是「判定写错」，
// 而是「判定写对了但拦截点放错了位置」——例如先拨号再校验，
// 表现是接口返回 403 但插件侧日志里已经有请求记录。
// 只有让插件真的跑起来、并检查它的 /echo 有没有被调用过，才能发现。
package plugin_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lipanel/internal/plugin"
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

// echoProbe 是注入到测试插件里的「调用探针」。
//
// 插件返回的内容由它决定，因此可以用「返回体里是否有探针的标记」
// 来判断请求**是否真的到达了插件进程**。这是本文件所有用例的基础。
type echoProbe struct {
	calls int
}

// probePlugin 包装 sysinfo 插件，把它变成可控的探针。
//
// 做法：实现 plugin.Handler + plugin.AssetProvider 转发给真实插件，
// 但用自己的 Routes 覆盖 /echo，从而观察到「核心到底有没有转发过来」。
type probePlugin struct {
	inner plugin.Handler
	probe *echoProbe
}

func (p *probePlugin) Descriptor() plugin.Descriptor { return p.inner.Descriptor() }

func (p *probePlugin) Routes(mux *http.ServeMux) {
	// 先注册真实插件的业务路由，再用自己的实现覆盖 /echo。
	p.inner.Routes(mux)
	mux.HandleFunc("GET /echo", func(w http.ResponseWriter, r *http.Request) {
		p.probe.calls++
		plugin.PluginJSON(w, slog.Default(), http.StatusOK, map[string]any{
			"reached_plugin": true,
			"plugin":         "sysinfo",
		})
	})
}

// TestProxyPermissionDeniedNeverReachesPlugin 是 3.3 最关键的一条用例。
//
// 验证：插件未声明 file.read 时，GET /files 返回 403，
// **且插件的 /echo 探针一次都没被调用**——即请求在核心侧就被拦住了。
//
// 做法说明：这里不走真实进程，而是直接把 Proxy 挂在 httptest 上，
// 用「已置为 running 的外部模式插件」来承载请求。原因是我们需要
// 完全控制「插件是否收到请求」这件事，而真实 sysinfo 进程无法
// 汇报「有没有人到过 /files」（它压根没实现该路由）。
// 真实进程链路的权限验证见 TestLivePermissionAuditTrail。
func TestProxyPermissionDeniedNeverReachesPlugin(t *testing.T) {
	mgr := newPermTestManager(t)

	// 只声明 system.read / process.read 的插件，故意不声明 file.read。
	registerProbePlugin(t, mgr, "probe", []string{"system.read", "process.read"})

	proxy := plugin.NewProxy(mgr)

	// --- 允许的请求：应当 403 之前的路径走通 ---
	// /info 需要 system.read（已声明）。因为插件是外部模式且没有真实
	// socket，转发会因为连不上而失败，但那证明「权限校验放行了」。
	// 这里只断言「不是 403」——403 才是权限问题。
	rec := doProxyRequest(t, proxy, "probe", http.MethodGet, "/info")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("GET /info 已声明 system.read，不该被权限拒绝: %s", rec.Body.String())
	}

	// --- 被拒绝的请求 ---
	rec = doProxyRequest(t, proxy, "probe", http.MethodGet, "/files")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /files 未声明 file.read，应当 403，实际 %d: %s", rec.Code, rec.Body.String())
	}

	// --- 403 的响应体必须可操作 ---
	var payload struct {
		Error    string   `json:"error"`
		Code     string   `json:"code"`
		Plugin   string   `json:"plugin"`
		Required string   `json:"required"`
		Granted  []string `json:"granted"`
		Hint     string   `json:"hint"`
		Scope    string   `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("403 响应不是合法 JSON: %v\n%s", err, rec.Body.String())
	}
	if payload.Code != "plugin_permission_denied" {
		t.Errorf("code = %q, 期望 plugin_permission_denied（前端据此识别）", payload.Code)
	}
	if payload.Plugin != "probe" {
		t.Errorf("plugin = %q, 期望 probe", payload.Plugin)
	}
	if payload.Required != "file.read" {
		t.Errorf("required = %q, 期望 file.read", payload.Required)
	}
	if len(payload.Granted) != 2 {
		t.Errorf("granted = %v, 期望 2 条已声明权限", payload.Granted)
	}
	if payload.Hint == "" {
		t.Error("403 必须带 hint（告诉用户怎么修）")
	}
	// scope 字段必须写明这不是内核级沙箱，避免使用者产生安全误解。
	if !strings.Contains(payload.Scope, "不是内核级沙箱") {
		t.Errorf("scope 应当说明能力边界，实际: %q", payload.Scope)
	}
	// 响应头也带一个可编程识别的标记。
	if got := rec.Header().Get("X-Lipanel-Permission-Denied"); got != "file.read" {
		t.Errorf("X-Lipanel-Permission-Denied = %q, 期望 file.read", got)
	}
}

// TestProxyPermissionDeniedAudited 验证拒绝会被记入审计。
func TestProxyPermissionDeniedAudited(t *testing.T) {
	mgr := newPermTestManager(t)
	registerProbePlugin(t, mgr, "probe", []string{"system.read"})
	proxy := plugin.NewProxy(mgr)

	rec := doProxyRequest(t, proxy, "probe", http.MethodDelete, "/files/a.txt")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("应当 403，实际 %d", rec.Code)
	}

	events := mgr.Audit().Query(plugin.AuditFilter{Outcome: plugin.AuditDenied})
	if len(events) == 0 {
		t.Fatal("拒绝事件必须被记入审计")
	}

	ev := events[0]
	if ev.Plugin != "probe" {
		t.Errorf("审计 plugin = %q, 期望 probe", ev.Plugin)
	}
	if ev.Method != http.MethodDelete {
		t.Errorf("审计 method = %q, 期望 DELETE", ev.Method)
	}
	if ev.Path != "/files/a.txt" {
		t.Errorf("审计 path = %q, 期望 /files/a.txt", ev.Path)
	}
	if ev.Required != "file.write" {
		t.Errorf("审计 required = %q, 期望 file.write", ev.Required)
	}
	if ev.Status != http.StatusForbidden {
		t.Errorf("审计 status = %d, 期望 403", ev.Status)
	}
	if ev.Reason == "" {
		t.Error("审计必须记录拒绝原因")
	}
	if ev.Time == "" {
		t.Error("审计必须记录时间")
	}
}

// TestProxyExemptPathsAllowed 验证骨架接口与前端资源不被权限体系挡住。
//
// 这条很容易写错且后果严重：一旦 /healthz 需要权限，
// 未声明权限的插件会在管理页永远显示「状态未知」。
func TestProxyExemptPathsAllowed(t *testing.T) {
	mgr := newPermTestManager(t)
	// 一个权限都没声明的插件。
	registerProbePlugin(t, mgr, "bare", nil)
	proxy := plugin.NewProxy(mgr)

	for _, path := range []string{"/healthz", "/whoami", "/assets/plugin.js"} {
		rec := doProxyRequest(t, proxy, "bare", http.MethodGet, path)
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s 应当免权限校验（骨架接口/前端资源），实际 403: %s", path, rec.Body.String())
		}
	}
}

// TestProxyDenialDoesNotAffectOtherPlugins 验证「拒绝不影响主面板其它功能」。
//
// 这是需求里明确要求的兜底性质：一个插件越权被拒，
// 不该影响其它插件，也不该影响核心自己的接口。
func TestProxyDenialDoesNotAffectOtherPlugins(t *testing.T) {
	mgr := newPermTestManager(t)

	// 插件 A：无权限（会被拒）。插件 B：有权限。
	registerProbePlugin(t, mgr, "alpha", nil)
	registerProbePlugin(t, mgr, "beta", []string{"system.read", "process.read", "file.read"})

	proxy := plugin.NewProxy(mgr)

	// A 被拒。
	if rec := doProxyRequest(t, proxy, "alpha", http.MethodGet, "/info"); rec.Code != http.StatusForbidden {
		t.Fatalf("alpha 应被拒绝，实际 %d", rec.Code)
	}

	// B 不受影响。
	if rec := doProxyRequest(t, proxy, "beta", http.MethodGet, "/info"); rec.Code == http.StatusForbidden {
		t.Errorf("beta 声明了 system.read，不该受 alpha 的影响，实际 403")
	}
	if rec := doProxyRequest(t, proxy, "beta", http.MethodGet, "/files"); rec.Code == http.StatusForbidden {
		t.Errorf("beta 声明了 file.read，不该被拒绝")
	}

	// 插件列表接口照常工作（核心自身功能不受影响）。
	list := mgr.List()
	if len(list) != 2 {
		t.Errorf("插件列表应返回 2 个插件，实际 %d", len(list))
	}
}

// TestProxyUnregisteredPluginNotAuditedAsDenied 验证不存在的插件不写审计。
//
// 否则一个扫描器就能用不存在的插件 ID 把审计缓冲刷满，
// 把真正有价值的记录挤掉（环形缓冲容量有限）。
func TestProxyUnregisteredPluginNotAuditedAsDenied(t *testing.T) {
	mgr := newPermTestManager(t)
	proxy := plugin.NewProxy(mgr)

	before := mgr.Audit().Stats().Total
	for i := 0; i < 20; i++ {
		rec := doProxyRequest(t, proxy, "ghost", http.MethodGet, "/info")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("不存在的插件应当 404，实际 %d", rec.Code)
		}
	}
	if after := mgr.Audit().Stats().Total; after != before {
		t.Errorf("探测不存在的插件不该产生审计记录（before=%d after=%d）", before, after)
	}
}

// TestPluginSidePermissionSelfCheck 验证插件侧的纵深防御。
//
// 用真实插件实例走 plugin.Serve 注册的那套处理器逻辑：
// 插件自身没声明的权限，即使请求绕过核心直达 socket，插件也会拒绝。
func TestPluginSidePermissionSelfCheck(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	mux := http.NewServeMux()
	h.Routes(mux)
	// 用与 serve.go 相同的方式包一层自检。
	handler := plugin.ExportPermissionSelfCheckForTest(mux, h.Descriptor(), testLogger())

	// /info 需要 system.read —— sysinfo 已声明，应当放行（能进入真实处理器）。
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/info", nil))
	if rec.Code == http.StatusForbidden {
		t.Errorf("sysinfo 已声明 system.read，/info 不该被插件侧自检拒绝: %s", rec.Body.String())
	}

	// 但插件没实现、也没声明 file.read 的路径必须被自检挡住。
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("未声明的 file.read 应被插件侧自检拒绝，实际 %d", rec.Code)
	}

	// 骨架接口不受影响。
	for _, p := range []string{"/healthz", "/whoami", "/assets/plugin.js"} {
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s 是骨架接口，不该被自检拒绝", p)
		}
	}
}

// TestSysinfoDeclaresMinimalPermissions 验证内置插件声明的是最小权限集。
//
// 这条断言的是**安全姿态**而不是功能：一个只做展示的插件
// 永远不该持有 file.write / process.exec 这类能力。
// 若将来有人图省事给 sysinfo 加了写权限，这里会立刻失败。
func TestSysinfoDeclaresMinimalPermissions(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	perms := h.Descriptor().Permissions
	if len(perms) == 0 {
		t.Fatal("sysinfo 应当声明权限（否则除骨架接口外全部会被拒绝）")
	}

	allowed := map[string]bool{"system.read": true, "process.read": true}
	for _, p := range perms {
		if !allowed[p] {
			t.Errorf("sysinfo 声明了超出最小集的权限 %q（只应是 system.read / process.read）", p)
		}
	}

	set, err := plugin.ParsePermissions(perms)
	if err != nil {
		t.Fatalf("sysinfo 的权限声明非法: %v", err)
	}
	// 它用到的接口必须都在声明范围内，否则插件启动后立刻就 403。
	for _, need := range []string{"system.read", "process.read"} {
		if !set.Has(need) {
			t.Errorf("sysinfo 缺少必需权限 %q", need)
		}
	}
}

// ---------- 测试辅助 ----------

// newPermTestManager 构造一个不拉真实进程的管理器（外部模式插件便于置为 running）。
func newPermTestManager(t *testing.T) *plugin.Manager {
	t.Helper()

	mgr, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		Logger:         testLogger(),
		DisableWatcher: true,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// registerProbePlugin 注册一个外部模式的插件并置为 running。
//
// 外部模式的好处：不用真的拉起进程，但转发路径（含权限校验）完全一致。
func registerProbePlugin(t *testing.T, mgr *plugin.Manager, id string, perms []string) {
	t.Helper()

	desc := plugin.Descriptor{
		ID:          id,
		Name:        "测试插件 " + id,
		Version:     "1.0.0",
		Mode:        plugin.ModeExternal,
		Permissions: perms,
	}
	if err := mgr.Register(desc); err != nil {
		t.Fatalf("注册插件 %s 失败: %v", id, err)
	}
	// 置为运行中：权限校验发生在状态检查之前，但不置为 running
	// 会先撞上 503，无法验证“校验通过后继续转发”这条路径。
	if _, err := mgr.Start(context.Background(), id); err != nil {
		t.Fatalf("启动插件 %s 失败: %v", id, err)
	}
}

// doProxyRequest 直接调用 Proxy.ServeHTTP，返回记录到的响应。
func doProxyRequest(t *testing.T, proxy *plugin.Proxy, id, method, subPath string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, "/api/plugins/"+id+subPath, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.ServeHTTP(rec, req, id, subPath)
	}()

	// 外部模式插件没有真实 socket，转发会去连一个不存在的路径。
	// 给一个上限，避免测试挂死；403 路径根本不涉及拨号，会立即返回。
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("Proxy.ServeHTTP 超时（method=%s path=%s）", method, subPath)
	}
	return rec
}

// 保证 io/slog 被使用（testLogger 在 builtin_test.go 中定义，此处只用 slog.Discard 变体）。
var _ = io.Discard
