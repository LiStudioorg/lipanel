// Package plugin_test 从外部验证「内置插件注册表 + 真实进程生命周期」。
//
// 为什么必须用外部测试包（plugin_test 而非 plugin）：
// builtin/sysinfo 需要 import internal/plugin 来实现 Handler 接口，
// 因此 plugin 包自身不能反过来 import 它——那会形成循环依赖。
// 只有外部测试包可以同时引用两者。
package plugin_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"lipanel/internal/plugin"
	// 匿名导入内置插件：触发其 init 中的 RegisterBuiltin。
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBuiltinSysinfoRegistered 验证内置插件确实完成了自我登记。
func TestBuiltinSysinfoRegistered(t *testing.T) {
	ids := plugin.BuiltinIDs()
	if len(ids) == 0 {
		t.Fatal("内置插件注册表为空，sysinfo 应当已注册")
	}

	found := false
	for _, id := range ids {
		if id == "sysinfo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("注册表中未找到 sysinfo，实际: %v", ids)
	}

	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	desc := h.Descriptor()
	if desc.ID != "sysinfo" {
		t.Errorf("描述符 ID = %q, 期望 %q", desc.ID, "sysinfo")
	}
	if desc.Mode != plugin.ModeManaged {
		t.Errorf("Mode = %q, 期望 %q", desc.Mode, plugin.ModeManaged)
	}
	if !desc.Builtin {
		t.Error("sysinfo 应当是内置插件")
	}
	// 前端插槽元数据必须完整，否则菜单里不会出现该插件。
	if !desc.Frontend.Valid() {
		t.Errorf("Frontend 元数据不完整: %+v（entry/nav_title 都必填）", desc.Frontend)
	}

	if _, err := plugin.Build("no-such-plugin", testLogger()); err == nil {
		t.Error("构造不存在的内置插件应当报错")
	}
}

// TestSysinfoRoutesRegistered 验证插件的业务路由已注册。
// 用 httptest 直接打插件的 mux，不经过进程与 socket——
// 这一层验证「插件实现是否正确」，与进程链路解耦。
func TestSysinfoRoutesRegistered(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	mux := http.NewServeMux()
	h.Routes(mux)

	for _, route := range []string{"/info", "/echo", "/runtime"} {
		req, err := http.NewRequest(http.MethodGet, route, nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		rec := newRecorder()
		mux.ServeHTTP(rec, req)

		if rec.status != http.StatusOK {
			t.Errorf("GET %s 状态码 = %d, 期望 200", route, rec.status)
		}
		if !strings.Contains(rec.body, "sysinfo") {
			t.Errorf("GET %s 响应未包含插件 ID: %s", route, rec.body)
		}
	}
}

// TestManagerRegistersAllBuiltins 验证 main 启动时走的注册路径可用。
func TestManagerRegistersAllBuiltins(t *testing.T) {
	m, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		Logger:         testLogger(),
		DisableWatcher: true,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	if err := m.RegisterAllBuiltins(); err != nil {
		t.Fatalf("注册全部内置插件失败: %v", err)
	}

	list := m.List()
	if len(list) != len(plugin.BuiltinIDs()) {
		t.Fatalf("注册数量 = %d, 期望 %d", len(list), len(plugin.BuiltinIDs()))
	}

	// 未启动时应为 stopped，且带完整的描述符（前端据此渲染菜单）。
	st, err := m.Get("sysinfo")
	if err != nil {
		t.Fatalf("Get(sysinfo) 失败: %v", err)
	}
	if st.State != plugin.StateStopped {
		t.Errorf("初始状态 = %q, 期望 %q", st.State, plugin.StateStopped)
	}
	if !st.Frontend.Valid() {
		t.Error("列表项应携带可用的 Frontend 元数据")
	}

	// 重复调用必须失败（ID 冲突），防止 main 里不小心注册两遍。
	if err := m.RegisterAllBuiltins(); err == nil {
		t.Error("重复注册全部内置插件应当报错")
	}
}

// TestPluginShutdownOnEmptyManager 验证没有任何插件运行时 Shutdown 是安全的。
func TestPluginShutdownOnEmptyManager(t *testing.T) {
	m, err := plugin.NewManager(plugin.Options{
		SocketDir:      t.TempDir(),
		Logger:         testLogger(),
		DisableWatcher: true,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := m.Shutdown(ctx); err != nil {
		t.Errorf("空管理器的 Shutdown 应当无错误，实际: %v", err)
	}
}

// ---------- 测试辅助 ----------

// recorder 是一个极简的 http.ResponseWriter 实现，
// 避免为三行断言引入 httptest 之外的依赖。
type recorder struct {
	header http.Header
	status int
	body   string
}

func newRecorder() *recorder {
	return &recorder{header: http.Header{}, status: http.StatusOK}
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) Write(b []byte) (int, error) {
	r.body += string(b)
	return len(b), nil
}

func (r *recorder) WriteHeader(code int) { r.status = code }
