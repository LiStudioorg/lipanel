package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 命令执行器（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 与 4.1 service.Executor、4.3 site.Executor、4.4 ssl.Executor、
// 4.5 store.Executor 同构：name 与 args 分开传递，**不经 shell**。
//
// 抽成接口的理由在本模块尤其重要：
//
//	防火墙命令会**真实改变这台机器的网络可达性**。
//	若测试直接跑真实 iptables，一次写错的用例就可能把开发机的
//	SSH 关掉（`iptables -A INPUT -j DROP` 之后连不上去，
//	只能去机房或控制台救）。
//
//	因此全部测试与端到端验证都注入假执行器；
//	真实执行只发生在用户实际点击操作时（以及一次
//	unshare -n 隔离环境下的验证，见 .e2e/ 脚本）。

// ExecResult 是一次命令执行的结果。
type ExecResult struct {
	// Stdout / Stderr 是标准输出与错误。
	Stdout string
	Stderr string
	// ExitCode 是退出码（正常退出为 0）。
	ExitCode int
	// DurationMS 是耗时（毫秒）。
	DurationMS int64
}

// Combined 返回合并后的输出（stdout 在前）。
//
// 与 4.5 同样的理由：ufw 把错误信息写 stderr，
// 但"防火墙未启用"这类关键状态可能出现在任一流里。
// 分开处理只会让每个调用点各写一遍合并逻辑。
func (r ExecResult) Combined() string {
	out := strings.TrimSpace(r.Stdout)
	errOut := strings.TrimSpace(r.Stderr)
	switch {
	case out == "":
		return errOut
	case errOut == "":
		return out
	default:
		return out + "\n" + errOut
	}
}

// Executor 执行外部命令。
type Executor interface {
	// Run 执行 argv 命令（name 与 args 分开，绝不经过 shell）。
	Run(ctx context.Context, name string, args []string) (ExecResult, error)
	// LookPath 判断命令是否存在。
	//
	// 单独一个方法而不是让调用方用 os/exec 直接找：
	// 假执行器需要能模拟"这个后端没装"，
	// 否则"四个后端都探测得到"这条分支在测试里无法穷举。
	LookPath(name string) (string, error)
}

// ============================================================================
// 真实执行器
// ============================================================================

// execExecutor 是默认执行器，基于 os/exec。
type execExecutor struct{}

// NewExecExecutor 返回基于 os/exec 的真实执行器。
func NewExecExecutor() Executor { return execExecutor{} }

// errExitNonZero 在命令非零退出时返回（携带退出码）。
var errExitNonZero = errors.New("firewall: 命令非零退出")

// Run 执行 argv 命令。
//
// ########## 关键的纪律：绝不经过 shell ##########
//
// 用 exec.CommandContext(ctx, name, args...) 而不是
// exec.CommandContext(ctx, "sh", "-c", strings.Join(...))。
// 前者把每个参数作为独立的 argv 元素传给内核，
// 内核不做任何解释，因此参数里的 `;`、`$(...)`、
// 反引号都只是普通字符。
//
// 这也意味着**本模块不可能存在命令注入**——
// 不是"过滤掉了"，而是结构上无法构造。
func (execExecutor) Run(ctx context.Context, name string, args []string) (ExecResult, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)

	// ########## 环境变量：固定语言 ##########
	//
	// 我们要解析输出（ufw status、iptables -S、nft list），
	// 而本地化输出会让解析在所有非 C locale 的机器上失效。
	// 与 4.1/4.3/4.4/4.5 同样的纪律。
	//
	// 不设置 PATH：防火墙命令由调用方给出确定的命令名，
	// 而 LookPath 已在探测阶段确认过它存在。
	cmd.Env = append(cmd.Environ(), "LANG=C", "LC_ALL=C")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := ExecResult{
		Stdout:     truncateRunes(stdout.String(), maxCapturedOutput),
		Stderr:     truncateRunes(stderr.String(), maxCapturedOutput),
		DurationMS: time.Since(start).Milliseconds(),
	}

	if err == nil {
		return res, nil
	}
	// ctx 超时/取消：单独返回 ErrTimeout。
	//
	// 对本模块而言这个区分很重要：防火墙命令几乎都是瞬时完成的
	// （不像 apt 要跑几分钟），超时说明的是**环境问题**
	// （如 iptables 在等 xtables lock），而不是"规则写错了"。
	// 提示用户"可能有另一个进程正在操作防火墙"比
	// "命令失败"有用得多。
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("%w: %s 未在超时时间内返回（可能有另一个进程正持有防火墙锁，如 xtables lock）",
			ErrTimeout, name)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return res, fmt.Errorf("%w: %s 被取消", ErrTimeout, name)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, fmt.Errorf("%w: %s 退出码 %d", errExitNonZero, name, res.ExitCode)
	}
	if errors.Is(err, exec.ErrNotFound) {
		return res, fmt.Errorf("firewall: 找不到可执行文件 %s", name)
	}
	return res, fmt.Errorf("firewall: 执行 %s 失败: %w", name, err)
}

// LookPath 判断命令是否存在。
func (execExecutor) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// maxCapturedOutput 是单条命令保留的输出上限（字符数）。
//
// 一条有几千条规则的 iptables -S 输出可能上百 KB；
// 前端只需要展示若干条，但解析需要完整数据，
// 因此上限给到 1 MiB 字符，远超正常规模。
const maxCapturedOutput = 1 << 20

// ============================================================================
// 假执行器（测试与端到端验证使用）
// ============================================================================

// MockResponse 是假执行器对某条命令的预置响应。
type MockResponse struct {
	// Stdout / Stderr 是输出。
	Stdout string
	Stderr string
	// ExitCode 非零时模拟失败（0 视为成功）。
	ExitCode int
	// Err 非空时模拟执行层面的错误（如超时）。
	Err error
}

// MockCall 记录一次被调用的命令。
type MockCall struct {
	// Name 是可执行文件名。
	Name string
	// Args 是参数切片（**原样保存**，便于断言）。
	Args []string
	// At 是调用时间。
	At time.Time
	// Command 是展示用的命令串。
	Command string
}

// MockExecutor 是假执行器。
//
// ########## 它同时是"零真实执行"的证据 ##########
//
// 端到端脚本注入本执行器后，可以断言：
//
//	① 面板的所有接口都正常工作（说明命令组装正确）；
//	② Calls() 里有完整记录（说明逻辑真的走了执行路径）；
//	③ 真实防火墙命令一次都没被执行（因为所有请求都被本执行器拦下）。
//
// 第 ③ 点无法"直接"证明，但可以反证：把真实命令换成
// 会立刻失败的分发路径（production 执行器已被完全替换），
// 并在脚本里核对宿主机真实规则在操作前后**逐字节不变**。
type MockExecutor struct {
	mu sync.Mutex
	// responses 按 "name arg0 arg1 ..." 的键匹配预置响应。
	responses map[string]MockResponse
	// prefixes 按 "name arg0" 前缀匹配（用于一个后端多条命令共用响应）。
	prefixes []mockPrefix
	// calls 记录全部调用。
	calls []MockCall
	// missing 是要模拟"命令不存在"的命令名集合。
	missing map[string]bool
	// fallback 是未匹配到预置响应时的默认响应。
	fallback MockResponse
}

type mockPrefix struct {
	key      string
	response MockResponse
}

// NewMockExecutor 构造假执行器。
//
// 默认行为：未匹配到任何预置响应时返回空输出 + 退出码 0。
// 这样"忘了配某条命令的响应"不会静默变成失败，
// 而是留下一条可被断言的空结果（测试通常用 ExactCallArgs
// 检查调用序列，因此忘记配置不会漏过）。
func NewMockExecutor() *MockExecutor {
	return &MockExecutor{
		responses: map[string]MockResponse{},
		missing:   map[string]bool{},
	}
}

// mockKey 生成精确匹配键。
func mockKey(name string, args []string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

// When 为一条精确命令预置响应。
func (m *MockExecutor) When(name string, args []string, resp MockResponse) *MockExecutor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[mockKey(name, args)] = resp
	return m
}

// WhenPrefix 为某命令的前缀预置响应（用于同一后端的多条命令）。
//
// 例如 WhenPrefix("iptables", []string{"-S"}) 会匹配所有
// `iptables -S ...` 调用。
func (m *MockExecutor) WhenPrefix(name string, args []string, resp MockResponse) *MockExecutor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prefixes = append(m.prefixes, mockPrefix{key: mockKey(name, args), response: resp})
	return m
}

// Missing 声明某个命令"不存在"（模拟未安装该后端）。
func (m *MockExecutor) Missing(name string) *MockExecutor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.missing[name] = true
	return m
}

// SetFallback 设置未匹配时的默认响应。
func (m *MockExecutor) SetFallback(resp MockResponse) *MockExecutor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fallback = resp
	return m
}

// Run 记录调用并返回预置响应。
func (m *MockExecutor) Run(_ context.Context, name string, args []string) (ExecResult, error) {
	m.mu.Lock()
	m.calls = append(m.calls, MockCall{
		Name:    name,
		Args:    append([]string(nil), args...),
		At:      time.Now(),
		Command: mockKey(name, args),
	})
	resp, ok := m.responses[mockKey(name, args)]
	if !ok {
		// 前缀匹配：取最长匹配的前缀（更具体者优先）。
		best := -1
		for i, p := range m.prefixes {
			if strings.HasPrefix(mockKey(name, args), p.key) {
				if best < 0 || len(p.key) > len(m.prefixes[best].key) {
					best = i
				}
			}
		}
		if best >= 0 {
			resp, ok = m.prefixes[best].response, true
		}
	}
	if !ok {
		resp = m.fallback
	}
	m.mu.Unlock()

	res := ExecResult{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode}
	if resp.Err != nil {
		return res, resp.Err
	}
	if resp.ExitCode != 0 {
		return res, fmt.Errorf("%w: %s 退出码 %d", errExitNonZero, name, resp.ExitCode)
	}
	return res, nil
}

// LookPath 按 Missing 声明判断命令是否存在。
func (m *MockExecutor) LookPath(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missing[name] {
		return "", fmt.Errorf("firewall: 未找到可执行文件 %s", name)
	}
	return "/usr/sbin/" + name, nil
}

// Calls 返回全部调用记录的快照。
func (m *MockExecutor) Calls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MockCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// Reset 清空调用记录（保留预置响应）。
//
// 端到端脚本常用它做"操作前后"的对比：
// 记录一次 Calls()，执行操作，再记录一次，
// 两者之差就是这次操作实际执行的命令。
func (m *MockExecutor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

// CallNames 返回被调用过的命令名集合（去重，保持首次出现顺序）。
func (m *MockExecutor) CallNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, c := range m.calls {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, c.Name)
	}
	return out
}

// ExactCallArgs 查找是否存在一次完全匹配的调用（用于断言"某条命令被执行过"）。
func (m *MockExecutor) ExactCallArgs(name string, args []string) bool {
	want := mockKey(name, args)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if c.Command == want {
			return true
		}
	}
	return false
}

// CallsContaining 返回所有命令串中包含某子串的调用。
//
// 端到端脚本用它做**安全断言**，例如：
//
//	if len(mock.CallsContaining("flush")) > 0 { 失败 }
func (m *MockExecutor) CallsContaining(substr string) []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MockCall
	for _, c := range m.calls {
		if strings.Contains(c.Command, substr) {
			out = append(out, c)
		}
	}
	return out
}
