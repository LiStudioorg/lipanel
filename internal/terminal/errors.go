package terminal

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/creack/pty"
)

// ============================================================================
// 平台能力判定与优雅降级（阶段五 5.1）
// ============================================================================
//
// #################### 为什么需要这个文件 ####################
//
// 本项目的发布矩阵包含 windows/386、windows/amd64、windows/arm64 三个目标。
// 而 Web 终端依赖 PTY，Windows 上没有 POSIX 伪终端，因此终端功能
// **在该平台上必然不可用**。
//
// ########## Windows 上"不可用"有两种表达方式，我们选后者 ##########
//
// 方式一（硬失败）：让构建在 Windows 上失败，把这个模块排除出发布矩阵。
//   问题是：整个二进制都发不出去，而 Windows 用户其实能用面板的
//   其它全部功能（服务/文件/网站/SSL/商店），只差一个终端。
//   为了一个功能砍掉整个平台的发布，代价与收益完全不成比例。
//
// 方式二（优雅降级）：编译通过，运行时明确报告"本平台不支持"。
//   这就是本文件的目的。
//
// ########## creack/pty 已经帮我们做了一半 ##########
//
// 该库自带平台 stub：
//
//	start_windows.go         //go:build windows
//	  func StartWithSize(...) (*os.File, error) { return nil, ErrUnsupported }
//	pty_unsupported.go       //go:build !linux && !darwin && ...
//	  func open() (...) { return nil, nil, ErrUnsupported }
//
// 因此 Windows 上 `pty.Start` **编译通过**，只是运行时返回 `"unsupported"`。
// 所以本模块**不需要**用 //go:build 拆分 session_unix.go / session_windows.go：
// 拆分不会修复任何现存故障（编译本来就是过的），只会把一个
// 已经跑通的模块拆成两份需要同步维护的代码。
//
// 本文件补上的是库**没有**做的那一半：
// 把库的裸错误 `"unsupported"` 翻译成**上层与前端能理解**的语义。

// ErrUnsupported 表示当前平台不支持 Web 终端。
//
// ########## 为什么要定义自己的错误，而不是直接用 pty.ErrUnsupported ##########
//
// `pty.ErrUnsupported` 的文本只有一个单词：`"unsupported"`。
// 若直接把它透到 API 层，前端拿到的会是：
//
//	{"error":"terminal: 启动 shell /bin/bash 失败: unsupported"}
//
// 这句话对用户几乎没有信息量：他既不知道**为什么**不支持，
// 也不知道**换台机器能不能用**，更不知道这是不是自己操作错了。
//
// 定义本模块自己的 ErrUnsupported 之后，上层可以用 errors.Is 精确判定，
// 并给出「Windows 没有 POSIX 伪终端，请在 Linux 服务器上使用本功能」
// 这样的可行动提示。**同时**用 %w 保留底层错误链，排查时仍能看到
// 真正的来源（pty 库）。
var ErrUnsupported = errors.New("terminal: 当前平台不支持 Web 终端")

// 其它语义错误。
//
// 这些错误与 permission.go 的 Decision 一起构成了 server 层
// 状态码映射的完整输入面（见 server/terminal_api.go 的
// terminalErrorStatus）。**每个错误都必须有一个明确的 HTTP 状态码**，
// 否则会落到默认的 500——而"裸奔 500"是本项目在 4.2 就明确禁止的
// 反模式（它把"用户输入错"和"面板内部炸了"混为一谈）。
var (
	// ErrConfirmRequired 表示破坏性操作缺少二次确认。
	ErrConfirmRequired = errors.New("terminal: 该操作需要二次确认（confirm=true）")
	// ErrInvalidSize 表示 cols/rows 非法或请求体不是合法 JSON。
	ErrInvalidSize = errors.New("terminal: 终端尺寸非法")
	// ErrPermission 表示权限不足。
	ErrPermission = errors.New("terminal: 权限不足")
	// ErrUnavailable 表示终端功能不可用。
	ErrUnavailable = errors.New("terminal: 终端功能不可用")
)

// Supported 报告当前平台是否支持 Web 终端。
//
// 判据是**编译期**的平台，而不是"能不能启动某个 shell"：
// 终端的前提是 PTY，而 PTY 是内核能力，与用户装了哪个 shell 无关。
//
// 用 runtime.GOOS 而不是 build tag：build tag 会让这个判断
// 在编译期固化，从而**无法被测试覆盖**（在 Linux 上永远看不到
// Windows 分支）。用运行时判断则可以在任意平台断言两个分支的行为，
// 这正是「优雅降级」这种"平时走不到"的代码最需要的。
func Supported() bool {
	return supportedFor(runtime.GOOS)
}

// supportedFor 是 Supported 的纯函数内核。
//
// ########## 为什么要拆出这个函数 ##########
//
// Supported() 读 runtime.GOOS，那是一个**进程级常量**：
// 在 Linux 上跑测试永远看到 Linux 分支，Windows 分支的代码
// （也就是"优雅降级"本身）**一行都不会被执行**。
//
// 拆成接收 goos 参数的纯函数后，测试可以穷举所有平台字符串，
// 断言 Windows 确实走降级、Linux 确实走正常路径。
// 否则这个模块最容易出错的部分恰好是唯一无法被测试的部分。
func supportedFor(goos string) bool {
	switch goos {
	// creack/pty 有真实实现的平台（与 pty_unsupported.go 的
	// 构建约束一一对应，改一处必须改另一处）。
	case "linux", "darwin", "freebsd", "dragonfly", "netbsd", "openbsd", "solaris", "zos":
		return true
	default:
		return false
	}
}

// UnsupportedReason 返回"为什么不支持"的可读说明。
//
// supported 为 true 时返回空字符串：调用方据此直接省略该字段
// （omitempty），避免在正常平台上给前端塞一句无意义的提示。
func UnsupportedReason() string {
	return unsupportedReasonFor(runtime.GOOS)
}

// unsupportedReasonFor 是 UnsupportedReason 的纯函数内核（理由同上）。
//
// 文案要求：既要说明**技术原因**（用户能据此判断换台机器行不行），
// 也要说明**哪些功能不受影响**（避免用户以为整个面板在 Windows 上是残废的）。
func unsupportedReasonFor(goos string) string {
	if supportedFor(goos) {
		return ""
	}
	switch goos {
	case "windows":
		return "Windows 没有 POSIX 伪终端（PTY），无法提供交互式 shell。" +
			"面板的其它功能（服务、文件、网站、SSL、软件商店）不受影响。" +
			"如需 Web 终端，请在 Linux 服务器上部署面板。"
	default:
		return fmt.Sprintf(
			"当前系统 %s 没有本模块可用的伪终端实现。"+
				"如需 Web 终端，请在 Linux 服务器上部署面板。", goos)
	}
}

// wrapUnsupported 把底层库的 ErrUnsupported 包装为本模块的错误。
//
// 返回 nil 表示"这不是不支持导致的失败"，调用方应原样返回原错误。
//
// ########## 为什么必须用 errors.Is 判定而不是比较字符串 ##########
//
// 比较 `err.Error() == "unsupported"` 会在下面任一情况下静默失效：
//
//	· 库在错误外面包了一层（`fmt.Errorf("pty: %w", ErrUnsupported)`）；
//	· 库改了错误文本（补丁版本升级就会发生）；
//	· 文本被本地化或加了上下文。
//
// 这三种情况下，Windows 用户会重新看到那个原始的、无法理解的
// `"unsupported"`——而这正是本文件要消除的问题。
// errors.Is 走的是错误链，对包装免疫。
func wrapUnsupported(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pty.ErrUnsupported) {
		// %w 保留两条链：上面是 ErrUnsupported（供上层判定），
		// 下面是原始的库错误（供排查时看到真正来源）。
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	return nil
}

// Capability 描述终端的平台能力，供 /api/terminal/status 返回。
//
// 单独一个结构体而不是裸 bool：前端要渲染的是一个**带原因的提示**，
// 而原因（为什么不支持、还能用什么）是用户真正需要的信息。
type Capability struct {
	// Supported 表示当前平台是否支持 Web 终端。
	Supported bool `json:"supported"`
	// OS 是运行时平台（便于用户/支持人员确认环境）。
	OS string `json:"os"`
	// Reason 是不支持时的可读原因（支持时省略）。
	Reason string `json:"reason,omitempty"`
	// Hint 是"那我该怎么办"（支持时省略）。
	Hint string `json:"hint,omitempty"`
}

// CurrentCapability 返回当前平台的终端能力快照。
func CurrentCapability() Capability {
	cap := Capability{
		Supported: Supported(),
		OS:        runtime.GOOS,
	}
	if !cap.Supported {
		cap.Reason = UnsupportedReason()
		cap.Hint = "Web 终端依赖伪终端（PTY），这是类 Unix 系统的内核能力。" +
			"Windows 上请改用 SSH 客户端连接服务器。"
	}
	return cap
}
