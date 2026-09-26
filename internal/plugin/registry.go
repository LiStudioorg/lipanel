package plugin

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// Factory 是内置插件的构造函数。
//
// 内置插件在包初始化时通过 RegisterBuiltin 登记自己，
// cmd/lipanel 再用 Build 统一构造——这样主程序的插件入口
// 不需要 import 每个具体插件包，新增插件只改插件的 init。
type Factory func(logger *slog.Logger) Handler

var (
	builtinMu   sync.RWMutex
	builtinRegs = map[string]Factory{}
)

// RegisterBuiltin 登记一个内置插件工厂。
//
// 只能在包的 init 中调用（进程启动阶段），因此这里不做复杂的并发设计，
// 但依然加锁：将来若有插件按需延迟注册，行为也不会退化。
//
// 重复注册同一个 ID 会 panic：这是编程错误（两个插件包定义了同一个 ID），
// 属于必须在开发期立刻炸掉、而不是上线后发现「插件莫名其妙不对」的问题。
func RegisterBuiltin(id string, factory Factory) {
	if !ValidID(id) {
		panic(fmt.Sprintf("plugin: 内置插件 ID %q 非法", id))
	}
	if factory == nil {
		panic(fmt.Sprintf("plugin: 内置插件 %q 的工厂函数为 nil", id))
	}

	builtinMu.Lock()
	defer builtinMu.Unlock()

	if _, dup := builtinRegs[id]; dup {
		panic(fmt.Sprintf("plugin: 内置插件 ID %q 被重复注册", id))
	}
	builtinRegs[id] = factory
}

// BuiltinIDs 返回所有已登记的内置插件 ID（按字典序，便于稳定输出）。
func BuiltinIDs() []string {
	builtinMu.RLock()
	defer builtinMu.RUnlock()

	ids := make([]string, 0, len(builtinRegs))
	for id := range builtinRegs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Build 构造指定 ID 的内置插件实例。
func Build(id string, logger *slog.Logger) (Handler, error) {
	builtinMu.RLock()
	factory, ok := builtinRegs[id]
	builtinMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("plugin: 未找到内置插件 %q（已注册: %v）", id, BuiltinIDs())
	}
	h := factory(logger)
	if h == nil {
		return nil, fmt.Errorf("plugin: 内置插件 %q 的工厂返回了 nil", id)
	}
	return h, nil
}

// RegisterAllBuiltins 把所有已登记的内置插件注册进管理器。
//
// 由 main 在启动时调用。任一插件注册失败都会返回错误并终止启动：
// 内置插件是编译进本程序的，它注册不上说明代码有问题，
// 静默跳过只会让用户对着一个「少了个插件」的面板困惑。
func (m *Manager) RegisterAllBuiltins() error {
	for _, id := range BuiltinIDs() {
		h, err := Build(id, m.logger)
		if err != nil {
			return fmt.Errorf("plugin: 构造内置插件失败: %w", err)
		}
		if err := m.Register(h.Descriptor()); err != nil {
			return fmt.Errorf("plugin: 注册内置插件失败: %w", err)
		}
	}
	return nil
}
