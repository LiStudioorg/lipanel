// Package ssl 提供 Let's Encrypt 证书的申请、查询与自动续期能力
// （阶段四 4.4，核心自带）。
//
// ############################################################
// 安全设计（必读）：本包会**调用外部 ACME 客户端**并**改写 nginx 配置**
//
// 与 4.1（systemctl argv）、4.2（文件路径）、4.3（nginx 配置注入）相比，
// 本包的攻击面是**前两者的并集**：
//
//	① 参数注入：域名会被交给 certbot，而 certbot 自己会把它拼进
//	   ACME 请求与 nginx 配置。因此域名必须过 4.3 的白名单校验，
//	   并且**显式拒绝通配符**（`*` 属于 DNS-01 能力，本期不做）。
//	② 配置写入：申请成功后要把 ssl_certificate 写进站点配置。
//	   写坏 nginx 配置 = **全站中断**，因此本包**绝不自己写配置文件**，
//	   一律经 4.3 site.Manager 已验证过的
//	   「快照 → 写盘 → nginx -t → reload → 失败自动回滚」链路。
//
// ############################################################
//
// 与其它核心模块的边界：
//
//	internal/site   —— 复用其 SystemAdapter（目录布局/命令组装）与
//	                   Manager 的配置写入、校验、回滚能力。
//	                   通过 main.go 注入 ConfigRewriter 闭包衔接，
//	                   避免 ssl → site 的包依赖（与 4.3 用 RootChecker
//	                   闭包避免 site → file 依赖环是同一个手法）。
//	internal/service/file/plugin —— 同构的权限判定与审计风格。
package ssl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// ACME 客户端探测
// ============================================================================
//
// 计划要求：「检测 acme.sh 或 certbot 是否安装（优先用 certbot，没有就 503）」。
//
// 这里做两件事，缺一不可：
//
//	① LookPath 找可执行文件  —— 回答「装没装」；
//	② 跑一次 <client> --version —— 回答「装的那个能不能用」。
//
// 为什么必须有第 ② 步：LookPath 只能证明「PATH 里有个同名文件」。
// 实际运维中常见的情况是——文件存在但缺执行位、架构不匹配（静态链接
// 二进制被丢到别的架构上）、或依赖的动态库缺失。这些情况下
// LookPath 全部返回成功，而真正的申请会在几十秒后才以一个
// 难以理解的方式失败。启动时就跑一次 --version，把这类问题
// 提前暴露成一句「certbot 不可用：xxx」。
//
// 探测结果**缓存**在 Detector 里：--version 是进程外调用，
// 每个 HTTP 请求都跑一次毫无必要（且会让状态接口变慢）。

// 支持的 ACME 客户端种类。
const (
	// ClientCertbot 表示使用 certbot。
	ClientCertbot = "certbot"
	// ClientAcmeSh 表示使用 acme.sh。
	ClientAcmeSh = "acme.sh"
	// ClientNone 表示未探测到任何可用的 ACME 客户端。
	ClientNone = "none"
)

// 默认可执行文件名（按 PATH 查找）。
const (
	DefaultCertbotName = "certbot"
	DefaultAcmeShName  = "acme.sh"
)

// ErrClientUnavailable 表示没有可用的 ACME 客户端。
//
// 调用方（server 层）据此返回 **503**（与 4.1 无 systemd 的降级策略一致）：
// 这是「环境不具备该能力」，不是「请求写错了」，因此不是 4xx。
var ErrClientUnavailable = errors.New("ssl: 未检测到可用的 ACME 客户端")

// ClientInfo 描述一个探测到的 ACME 客户端。
type ClientInfo struct {
	// Kind 见 ClientCertbot / ClientAcmeSh / ClientNone。
	Kind string `json:"kind"`
	// Path 是可执行文件的绝对路径。
	Path string `json:"path,omitempty"`
	// Version 是 `--version` 输出的首行（已 TrimSpace）。
	Version string `json:"version,omitempty"`
	// Available 表示该客户端能否真正使用。
	Available bool `json:"available"`
	// Reason 是不可用原因（Available 为 false 时才有值）。
	Reason string `json:"reason,omitempty"`
	// Source 说明路径来源："显式指定"（-certbot-path）或 "PATH"。
	//
	// 单独一个字段而不是混进 Reason 文本：用户排查「为什么用了
	// 一个我不认识的 certbot」时，需要一眼看出是不是自己的
	// -certbot-path 在生效。这在测试（指向 mock 脚本）时尤其重要。
	Source string `json:"source,omitempty"`
}

// DetectorOptions 是构造 Detector 的配置。
type DetectorOptions struct {
	// CertbotPath 是显式指定的 certbot 路径；为空则按 PATH 查找。
	CertbotPath string
	// AcmeShPath 是显式指定的 acme.sh 路径；为空则按 PATH 查找。
	AcmeShPath string
	// Timeout 是 `--version` 探测的超时；<=0 时用 DefaultDetectTimeout。
	Timeout time.Duration
	// Executor 用于执行 `--version`；为 nil 时用默认实现。
	//
	// 抽出来是为了**可测**：探测逻辑要覆盖「文件存在但执行失败」
	// 这类分支，而真实环境里很难构造一个"存在但不能跑"的 certbot。
	Executor Executor
	// Logger 为 nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// DefaultDetectTimeout 是版本探测的超时。
//
// 5s：`certbot --version` 正常在百毫秒级返回（它是 Python 程序，
// 冷启动可能要 1~2s）。给 5s 既够用，又不会在客户端卡死时
// 让面板启动被拖住。
const DefaultDetectTimeout = 5 * time.Second

// Detector 探测并缓存 ACME 客户端的可用性。
type Detector struct {
	opts DetectorOptions

	// 探测结果缓存。
	//
	// 用 sync.Once 而不是「普通字段 + 注释约定」：
	// 探测会被多个 HTTP 请求并发触发（前端同时打开 SSL 页与能力接口），
	// 没有同步手段的话会并发跑多次 `--version`，而写入 cached/err
	// 的竞争正是坑位 16「不加锁 + 注释约定一定会漏」的同一类问题。
	once   sync.Once
	cached ClientInfo
	err    error
}

// NewDetector 构造探测器。
//
// 注意：**构造时不执行任何外部命令**。探测延迟到首次 Detect()，
// 理由是启动阶段不应被一个可能卡住的 certbot 拖慢；而 once 保证
// 整个进程生命周期内只探测一次。
func NewDetector(opts DetectorOptions) *Detector {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultDetectTimeout
	}
	if opts.Executor == nil {
		opts.Executor = execExecutor{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Detector{opts: opts}
}

// Detect 返回探测结果（首次调用执行真实探测，之后返回缓存）。
//
// 返回的 error 仅在**完全没有可用客户端**时非 nil（ErrClientUnavailable）。
// 「certbot 可用但 acme.sh 不可用」是正常情况，不算错误。
//
// ctx 参数当前不参与控制（探测自带独立超时）：它保留在签名里是为了
// 让调用方不必在「有 ctx」和「没有 ctx」两种 API 之间做选择，
// 将来若要支持按请求取消也有位置可接。
func (d *Detector) Detect(ctx context.Context) (ClientInfo, error) {
	_ = ctx
	d.once.Do(func() {
		d.cached, d.err = d.detect()
	})
	return d.cached, d.err
}

// detect 是真实的探测流程。
//
// 顺序固定：**先 certbot，后 acme.sh**（计划明确要求优先 certbot）。
// 用户用 -certbot-path 显式指定时，只认指定的那个——
// 显式配置优先于自动发现，否则用户无法用「指向一个坏的 certbot」
// 来验证错误提示是否清晰。
func (d *Detector) detect() (ClientInfo, error) {
	certbot := d.probe(ClientCertbot, d.opts.CertbotPath)
	if certbot.Available {
		return certbot, nil
	}

	acmeSh := d.probe(ClientAcmeSh, d.opts.AcmeShPath)
	if acmeSh.Available {
		return acmeSh, nil
	}

	// 两者都不可用：返回一个合并了原因的 ClientInfo，
	// 让前端能显示「certbot 为什么不行、acme.sh 为什么不行」，
	// 而不是笼统一句「未检测到 ACME 客户端」。
	info := ClientInfo{
		Kind:      ClientNone,
		Available: false,
		Reason: fmt.Sprintf("certbot: %s；acme.sh: %s",
			strings.TrimPrefix(certbot.Reason, "certbot: "),
			strings.TrimPrefix(acmeSh.Reason, "acme.sh: ")),
	}
	return info, fmt.Errorf("%w: %s", ErrClientUnavailable, info.Reason)
}

// probe 探测单个客户端。
func (d *Detector) probe(kind, explicitPath string) ClientInfo {
	info := ClientInfo{Kind: kind}

	// ---------- ① 定位可执行文件 ----------
	path := explicitPath
	source := "显式指定"
	if path == "" {
		name := DefaultCertbotName
		if kind == ClientAcmeSh {
			name = DefaultAcmeShName
		}
		found, err := exec.LookPath(name)
		if err != nil {
			info.Reason = fmt.Sprintf("%s: PATH 中未找到 %s", kind, name)
			return info
		}
		path = found
		source = "PATH"
	}
	// 显式指定的路径必须校验：用户可以传相对路径或目录进来，
	// 让 exec 在几十秒后报一句含糊的错，不如现在就说清楚。
	abs, err := filepath.Abs(path)
	if err != nil {
		info.Reason = fmt.Sprintf("%s: 路径 %q 无法解析: %v", kind, path, err)
		return info
	}
	stat, err := os.Stat(abs)
	if err != nil {
		info.Reason = fmt.Sprintf("%s: 路径 %q 不可用: %v", kind, path, err)
		return info
	}
	if stat.IsDir() {
		info.Reason = fmt.Sprintf("%s: 路径 %q 是目录，不是可执行文件", kind, path)
		return info
	}
	info.Path = abs
	info.Source = source

	// ---------- ② 执行 --version 确认真的能用 ----------
	ctx, cancel := context.WithTimeout(context.Background(), d.opts.Timeout)
	defer cancel()

	stdout, stderr, err := d.opts.Executor.Run(ctx, abs, []string{"--version"})
	combined := strings.TrimSpace(stdout + stderr)
	if err != nil {
		info.Reason = fmt.Sprintf("%s: 执行 %s --version 失败: %v（输出: %s）",
			kind, abs, err, firstLine(combined))
		return info
	}

	info.Version = firstLine(combined)
	info.Available = true
	d.opts.Logger.Info("检测到 ACME 客户端",
		"kind", kind, "path", abs, "version", info.Version, "source", source)
	return info
}

// firstLine 取输出的第一行非空内容。
//
// 为什么要取一行：acme.sh --version 会输出多行（版本 + 升级提示 +
// 捐赠链接），整段塞进日志与 API 响应会让界面很难看。
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// ClientKind 返回探测到的客户端种类（不触发探测，仅返回缓存）。
//
// 供审计与日志使用：它们不该为了拿一个标识而触发进程外调用。
func (d *Detector) ClientKind() string {
	if d.cached.Kind == "" {
		return ClientNone
	}
	return d.cached.Kind
}
