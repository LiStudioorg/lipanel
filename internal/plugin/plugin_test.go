package plugin

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// testLogger 返回一个丢弃输出的日志器，避免测试输出被日志淹没。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestManager 构造一个 socket 目录位于 t.TempDir() 的管理器。
// DisableWatcher 默认为 true：崩溃回调是异步的，
// 会在测试结束时与 t.TempDir() 的清理打架（进程在目录删掉后才退出）。
// 需要验证崩溃语义的用例会显式开启它并自行等待。
func newTestManager(t *testing.T, mutate ...func(*Options)) *Manager {
	t.Helper()

	opts := Options{
		SocketDir:      t.TempDir(),
		Logger:         testLogger(),
		DisableWatcher: true,
		StartTimeout:   5 * time.Second,
		StopTimeout:    2 * time.Second,
	}
	for _, fn := range mutate {
		fn(&opts)
	}

	m, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

// testDescriptor 返回一个合法的托管模式描述符。
func testDescriptor(id string) Descriptor {
	return Descriptor{
		ID:      id,
		Name:    "测试插件 " + id,
		Version: "1.0.0",
		Builtin: true,
		Mode:    ModeManaged,
	}
}

// ---------- ID 与描述符校验 ----------

func TestValidID(t *testing.T) {
	valid := []string{"sysinfo", "a1", "my-plugin", "abc-def-123", strings.Repeat("a", 32)}
	for _, id := range valid {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, 期望 true", id)
		}
	}

	// 这些都是安全边界用例：任一条被放行，
	// 插件 ID 就会变成 socket 文件路径的一部分，产生目录穿越。
	invalid := []string{
		"", "a", "-abc", "abc-", "ABC", "sys info", "sys.info",
		"../etc/passwd", "..", ".", "a/b", "a\\b", "sys\x00info",
		strings.Repeat("a", 33), "插件", "sys_info", "sys info",
	}
	for _, id := range invalid {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, 期望 false（安全边界）", id)
		}
	}
}

func TestDescriptorValidate(t *testing.T) {
	tests := []struct {
		name    string
		desc    Descriptor
		wantErr bool
	}{
		{"合法", testDescriptor("ok"), false},
		{"非法 ID", Descriptor{ID: "../x", Name: "n", Version: "1", Mode: ModeManaged}, true},
		{"缺 Name", Descriptor{ID: "ok", Version: "1", Mode: ModeManaged}, true},
		{"空 Name", Descriptor{ID: "ok", Name: "   ", Version: "1", Mode: ModeManaged}, true},
		{"缺 Version", Descriptor{ID: "ok", Name: "n", Mode: ModeManaged}, true},
		{"缺 Mode", Descriptor{ID: "ok", Name: "n", Version: "1"}, true},
		{"非法 Mode", Descriptor{ID: "ok", Name: "n", Version: "1", Mode: "wasm"}, true},
		{"external 模式合法", Descriptor{ID: "ok", Name: "n", Version: "1", Mode: ModeExternal}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.desc.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// ---------- 注册 ----------

func TestRegisterRejectsInvalidAndDuplicate(t *testing.T) {
	m := newTestManager(t)

	if err := m.Register(testDescriptor("good")); err != nil {
		t.Fatalf("注册合法插件失败: %v", err)
	}

	// 重复注册必须报错：否则同一 ID 会被静默覆盖，
	// 排查起来像是「插件行为莫名其妙变了」。
	if err := m.Register(testDescriptor("good")); err == nil {
		t.Error("重复注册同一 ID 应当报错，实际通过了")
	}

	bad := testDescriptor("bad id")
	if err := m.Register(bad); err == nil {
		t.Error("注册非法 ID 应当报错，实际通过了")
	}
}

// List 必须保持注册顺序：map 遍历顺序随机，
// 若直接返回 map 内容，前端菜单每次刷新都会换位置。
func TestListKeepsRegistrationOrder(t *testing.T) {
	m := newTestManager(t)
	ids := []string{"alpha", "bravo", "charlie", "delta"}
	for _, id := range ids {
		if err := m.Register(testDescriptor(id)); err != nil {
			t.Fatalf("注册 %s 失败: %v", id, err)
		}
	}

	// 多跑几次以暴露随机顺序问题。
	for i := 0; i < 20; i++ {
		got := m.List()
		if len(got) != len(ids) {
			t.Fatalf("List() 长度 = %d, 期望 %d", len(got), len(ids))
		}
		for j, st := range got {
			if st.ID != ids[j] {
				t.Fatalf("第 %d 次 List() 顺序 = %v, 期望 %v", i, idsOf(got), ids)
			}
		}
	}
}

func idsOf(list []Status) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

func TestGetUnknownPlugin(t *testing.T) {
	m := newTestManager(t)

	_, err := m.Get("ghost")
	if err == nil {
		t.Fatal("查询不存在的插件应当报错")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("错误信息应包含插件 ID，实际: %v", err)
	}

	if _, err := m.Start(context.Background(), "ghost"); err == nil {
		t.Error("启动不存在的插件应当报错")
	}
	if _, err := m.Stop("ghost"); err == nil {
		t.Error("停止不存在的插件应当报错")
	}
}

// ---------- external 模式 ----------

// external 模式的插件不由核心拉起，核心也不应假装能停止它。
func TestExternalModeLifecycle(t *testing.T) {
	m := newTestManager(t)

	desc := testDescriptor("ext")
	desc.Mode = ModeExternal
	if err := m.Register(desc); err != nil {
		t.Fatalf("注册 external 插件失败: %v", err)
	}

	// 初始为 stopped。
	st, err := m.Get("ext")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if st.State != StateStopped {
		t.Errorf("初始状态 = %q, 期望 %q", st.State, StateStopped)
	}

	// Start 只标记启用，不产生真实进程。
	st, err = m.Start(context.Background(), "ext")
	if err != nil {
		t.Fatalf("Start(external) 失败: %v", err)
	}
	if st.State != StateRunning {
		t.Errorf("启动后状态 = %q, 期望 %q", st.State, StateRunning)
	}
	if st.PID != 0 {
		t.Errorf("external 模式不应有 PID，实际 = %d", st.PID)
	}

	// Stop 必须明确告知「无法结束别人的进程」，而不是假装停掉了。
	_, err = m.Stop("ext")
	if err == nil {
		t.Fatal("停止 external 插件应返回错误（说明进程不由核心托管）")
	}
	if !strings.Contains(err.Error(), "外部") {
		t.Errorf("错误信息应说明原因，实际: %v", err)
	}

	// 即使报错，状态也必须已经切换为 stopped（核心不再转发）。
	st, err = m.Get("ext")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if st.State != StateStopped {
		t.Errorf("停止后状态 = %q, 期望 %q", st.State, StateStopped)
	}
}

// ---------- 内置插件注册表 ----------

// 说明：内置插件注册表（sysinfo）的验证放在 builtin_test.go。
// 原因是本包不能 import builtin/sysinfo——那会形成循环依赖
// （sysinfo 需要 import 本包才能实现 Handler 接口）。
// 因此那条用例放在 plugin_test 外部包中，由它同时引用两边。

func TestRegisterBuiltinRejectsBadInput(t *testing.T) {
	// 非法 ID 必须 panic：这是开发期就该炸掉的编程错误。
	defer func() {
		if recover() == nil {
			t.Error("注册非法 ID 应当 panic")
		}
	}()
	RegisterBuiltin("Bad ID", func(*slog.Logger) Handler { return nil })
}

func TestRegisterBuiltinRejectsNilFactory(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("注册 nil 工厂应当 panic")
		}
	}()
	RegisterBuiltin("nilfactory", nil)
}

// ---------- 幂等性 ----------

// 对已停止的插件重复调用 Stop 不应报错：
// 前端重复点击「停止」是很常见的操作。
func TestStopIsIdempotent(t *testing.T) {
	m := newTestManager(t)
	if err := m.Register(testDescriptor("idem")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	for i := 0; i < 3; i++ {
		st, err := m.Stop("idem")
		if err != nil {
			t.Fatalf("第 %d 次 Stop 报错: %v", i+1, err)
		}
		if st.State != StateStopped {
			t.Errorf("第 %d 次 Stop 后状态 = %q, 期望 %q", i+1, st.State, StateStopped)
		}
	}
}

// 未运行的插件不应能通过 Dial 连接（转发层据此返回 503）。
func TestDialNotRunning(t *testing.T) {
	m := newTestManager(t)
	if err := m.Register(testDescriptor("idle")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	if _, err := m.Dial(context.Background(), "idle"); err == nil {
		t.Error("对未运行的插件 Dial 应当失败")
	}

	if _, err := m.Dial(context.Background(), "ghost"); err == nil {
		t.Error("对不存在的插件 Dial 应当失败")
	}
}

// 状态快照必须是副本：外部拿到后修改不应影响管理器内部状态。
func TestStatusSnapshotIsCopy(t *testing.T) {
	m := newTestManager(t)
	desc := testDescriptor("snap")
	if err := m.Register(desc); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	st, err := m.Get("snap")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	st.State = "tampered"
	st.Frontend.Entry = "tampered"

	again, err := m.Get("snap")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if again.State != StateStopped {
		t.Errorf("外部修改快照影响了内部状态: %q", again.State)
	}
	if again.Frontend.Entry != "" {
		t.Errorf("外部修改快照影响了 Frontend: %q", again.Frontend.Entry)
	}
}
