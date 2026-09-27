package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ============================================================================
// 端到端验证用的假执行器（阶段四 4.6）
// ============================================================================
//
// ########## 为什么生产代码里会有"假执行器" ##########
//
// 本模块的写操作会**真实修改系统防火墙**。要在"完整跑一遍 HTTP →
// 权限 → 审计 → 命令组装 → 执行"的端到端链路上验证，就必须有一个
// 不会碰真防火墙的执行器——否则每次跑端到端测试都会拿本机的
// 连通性做实验（一条写错的规则就能让 SSH 断开，且无法远程修复）。
//
// 4.5 软件商店用的是"把假 apt-get 放进 PATH"的办法，
// 但防火墙不行：ufw / firewall-cmd / nft / iptables 的调用路径
// 由探测逻辑决定，而且 nft 需要**有状态**（添加后能读回句柄），
// PATH 里放一个无状态脚本无法模拟"加一条规则，再按句柄删掉它"。
//
// 因此这里提供一个由环境变量开启的、**有状态**的假执行器：
//
//	LIPANEL_FIREWALL_FAKE=1        开启
//	LIPANEL_FIREWALL_FAKE_BACKEND  指定模拟哪个后端（默认 ufw）
//	LIPANEL_FIREWALL_FAKE_LOG      把每次调用追加写入该文件（供测试断言）
//
// ########## 安全约束：绝不能在正常运行时被启用 ##########
//
// 它只在环境变量显式设置时生效，且：
//   · main.go 在启用时会打印醒目的 WARN 日志；
//   · 端到端脚本在启动前把该变量限制在自己的进程里；
//   · 生产部署不会设置这个变量（它不在任何配置文件里）。
//
// 换句话说：要误开它，必须有人主动往环境里塞一个名字很长的变量。
// 这比"默认假执行器、需要显式关掉"安全得多——后者的默认状态
// 会让生产环境悄悄失去防火墙管理能力（而用户以为在生效）。

// FakeExecutorEnv 是开启假执行器的环境变量名。
const FakeExecutorEnv = "LIPANEL_FIREWALL_FAKE"

// FakeExecutorBackendEnv 指定模拟的后端。
const FakeExecutorBackendEnv = "LIPANEL_FIREWALL_FAKE_BACKEND"

// FakeExecutorLogEnv 指定调用日志路径。
const FakeExecutorLogEnv = "LIPANEL_FIREWALL_FAKE_LOG"

// FakeExecutorFromEnv 按环境变量决定是否构造假执行器。
//
// 返回 (executor, true) 表示应当使用假执行器。
func FakeExecutorFromEnv() (Executor, bool) {
	if os.Getenv(FakeExecutorEnv) == "" {
		return nil, false
	}
	return NewFakeExecutor(FakeOptions{
		Backend: firstNonEmptyString(os.Getenv(FakeExecutorBackendEnv), BackendUFW),
		LogPath: os.Getenv(FakeExecutorLogEnv),
	}), true
}

// firstNonEmptyString 返回第一个非空串。
func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// FakeOptions 配置假执行器。
type FakeOptions struct {
	// Backend 是要模拟的后端（ufw / firewalld / nftables / iptables）。
	Backend string
	// LogPath 非空时把每次调用追加写入该文件。
	LogPath string
	// SSHConfig 非空时用该路径作为 sshd 配置（保护判定用）。
	SSHConfig string
}

// FakeExecutor 是一个**有状态**的假防火墙。
//
// ########## 为什么必须有状态 ##########
//
// 无状态的假执行器（任何命令都返回成功）无法验证本模块最核心的
// 那条链路："添加规则 → 读回规则（拿到句柄/规格）→ 按句柄删除"。
// 面板的删除逻辑强依赖回读结果，假执行器必须能记住自己加过什么。
type FakeExecutor struct {
	opts FakeOptions
	mu   sync.Mutex
	// rules 按后端存储已添加的规则。
	ufwRules  []string
	nftRules  []fakeNFTRule
	iptRules  []string
	fwRules   []string
	nextNftID int
	// calls 记录全部调用。
	calls []string
}

// fakeNFTRule 是假 nft 表里的一条规则。
type fakeNFTRule struct {
	// Handle 是句柄（从 2 开始，模拟真实 nft 的编号方式）。
	Handle int
	// Expr 是规则表达式（如 "tcp dport 8080 accept"）。
	Expr string
	// Comment 是规则备注（若有）。
	Comment string
}

// NewFakeExecutor 构造假执行器。
func NewFakeExecutor(opts FakeOptions) *FakeExecutor {
	if opts.Backend == "" {
		opts.Backend = BackendUFW
	}
	// 句柄从 2 开始：真实 nft 里 table 与 chain 各占一个句柄，
	// 规则通常从 2 起。这样端到端测试能复现"误取 table 的句柄"
	// 这个真实存在的坑。
	return &FakeExecutor{opts: opts, nextNftID: 2}
}

// Calls 返回全部调用记录（形如 "ufw allow proto tcp ..."）。
func (f *FakeExecutor) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// LookPath 报告命令是否存在。
//
// 只让"当前模拟的后端"存在，其它后端一律缺失——
// 这样探测逻辑会选中我们想要的后端，端到端测试才有确定性。
func (f *FakeExecutor) LookPath(name string) (string, error) {
	base := filepath.Base(name)
	if base == commandNameOf(f.opts.Backend) {
		return "/usr/bin/" + base, nil
	}
	return "", exec.ErrNotFound
}

// Run 执行一条（假的）命令。
func (f *FakeExecutor) Run(ctx context.Context, name string, args []string) (ExecResult, error) {
	base := filepath.Base(name)
	joined := base + " " + strings.Join(args, " ")

	f.mu.Lock()
	f.calls = append(f.calls, joined)
	logPath := f.opts.LogPath
	f.mu.Unlock()

	if logPath != "" {
		if fh, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_, _ = fh.WriteString(joined + "\n")
			_ = fh.Close()
		}
	}

	// ########## 绝不允许 flush ##########
	//
	// 这里也拦一道：端到端测试要能证明"整条链路上没有任何
	// 清空规则集的命令"。若放过去，测试的断言就失去意义了。
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), "flush") {
			return ExecResult{Stderr: "fake: 拒绝执行 flush", ExitCode: 1},
				fmt.Errorf("%w: 假执行器拒绝 flush", ErrCommandFailed)
		}
	}

	if base != commandNameOf(f.opts.Backend) {
		return ExecResult{Stderr: "command not found", ExitCode: 127},
			fmt.Errorf("%w: 命令不存在: %s", ErrUnavailable, base)
	}

	switch f.opts.Backend {
	case BackendUFW:
		return f.runUFW(args)
	case BackendFirewalld:
		return f.runFirewalld(args)
	case BackendNFTables:
		return f.runNFT(args)
	case BackendIPTables:
		return f.runIPTables(args)
	}
	return ExecResult{Stdout: ""}, nil
}

// ---------------------------------------------------------------------------
// ufw
// ---------------------------------------------------------------------------

func (f *FakeExecutor) runUFW(args []string) (ExecResult, error) {
	if len(args) >= 2 && args[0] == "status" && args[1] == "verbose" {
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		b.WriteString("Status: active\n")
		b.WriteString("Logging: on (low)\n")
		b.WriteString("Default: deny (incoming), allow (outgoing), disabled (routed)\n")
		b.WriteString("New profiles: skip\n")
		return ExecResult{Stdout: b.String()}, nil
	}
	if len(args) >= 2 && args[0] == "status" && args[1] == "numbered" {
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		b.WriteString("Status: active\n")
		if len(f.ufwRules) > 0 {
			b.WriteString("\n     To                         Action      From\n")
			b.WriteString("     --                         ------      ----\n")
			for i, r := range f.ufwRules {
				b.WriteString(fmt.Sprintf("[%2d] %s\n", i+1, r))
			}
		}
		return ExecResult{Stdout: b.String()}, nil
	}

	verb := args[0]
	switch verb {
	case "allow", "deny", "reject", "limit":
		spec, err := ufwRuleLine(verb, args[1:])
		if err != nil {
			return ExecResult{Stderr: err.Error(), ExitCode: 1}, err
		}
		f.mu.Lock()
		f.ufwRules = append(f.ufwRules, spec)
		f.mu.Unlock()
		return ExecResult{Stdout: "Rule added\n"}, nil
	case "delete":
		if len(args) < 2 {
			return ExecResult{Stderr: "ERROR: wrong number of arguments", ExitCode: 1},
				fmt.Errorf("delete 缺少参数")
		}
		spec, err := ufwRuleLine(args[1], args[2:])
		if err != nil {
			return ExecResult{Stderr: err.Error(), ExitCode: 1}, err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, r := range f.ufwRules {
			if normalizeSpace(r) == normalizeSpace(spec) {
				f.ufwRules = append(f.ufwRules[:i], f.ufwRules[i+1:]...)
				return ExecResult{Stdout: "Rule deleted\n"}, nil
			}
		}
		return ExecResult{Stderr: "ERROR: Could not delete non-existent rule", ExitCode: 1},
			fmt.Errorf("规则不存在")
	}
	return ExecResult{Stdout: ""}, nil
}

// ufwRuleLine 把 ufw 参数还原成 `ufw status numbered` 里的一行。
//
// ########## 这个函数模拟的是真实 ufw 的输出格式 ##########
//
// 真实 ufw 会把我们加的长格式参数**规范化**后再显示：
//
//	ufw allow proto tcp to any port 8080 comment "[lipanel] web"
//	→ 显示为 8080/tcp  ALLOW  Anywhere  # [lipanel] web
//
// 端到端验证的价值正在于此：面板的删除逻辑必须能解析这种
// **经过规范化**的输出，而不是"回显自己刚写的参数"。
func ufwRuleLine(verb string, rest []string) (string, error) {
	var port, proto, from, comment string
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "proto":
			if i+1 < len(rest) {
				proto = rest[i+1]
				i++
			}
		case "from":
			if i+1 < len(rest) {
				from = rest[i+1]
				i++
			}
		case "port":
			if i+1 < len(rest) {
				port = rest[i+1]
				i++
			}
		case "to":
			// "to any" —— 跳过目标描述。
			if i+1 < len(rest) {
				i++
			}
		case "comment":
			if i+1 < len(rest) {
				comment = rest[i+1]
				i++
			}
		}
	}
	if port == "" && from == "" {
		return "", fmt.Errorf("ufw: 缺少端口或来源")
	}

	action := strings.ToUpper(verb)
	target := "Anywhere"
	src := "Anywhere"
	if from != "" {
		src = from
	}
	if port != "" {
		// ufw 的端口范围显示为冒号形式。
		display := port
		if proto != "" {
			display = port + "/" + proto
		}
		target = display
	}
	line := fmt.Sprintf("%-26s %-11s %s", target, action+" IN", src)
	if comment != "" {
		line += "  # " + comment
	}
	return line, nil
}

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ---------------------------------------------------------------------------
// firewalld
// ---------------------------------------------------------------------------

func (f *FakeExecutor) runFirewalld(args []string) (ExecResult, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--state") && !strings.Contains(joined, "--add") {
		return ExecResult{Stdout: "running\n"}, nil
	}
	if strings.Contains(joined, "--list-all") {
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		b.WriteString("public (active)\n")
		b.WriteString("  target: default\n")
		b.WriteString("  interfaces: eth0\n")
		ports := []string{}
		for _, r := range f.fwRules {
			if strings.HasPrefix(r, "port:") {
				ports = append(ports, strings.TrimPrefix(r, "port:"))
			}
		}
		b.WriteString("  ports: " + strings.Join(ports, " ") + "\n")
		b.WriteString("  rich rules:\n")
		for _, r := range f.fwRules {
			if strings.HasPrefix(r, "rich:") {
				b.WriteString("    rule " + strings.TrimPrefix(r, "rich:") + "\n")
			}
		}
		return ExecResult{Stdout: b.String()}, nil
	}
	if strings.Contains(joined, "--reload") {
		return ExecResult{Stdout: "success\n"}, nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(joined, "--add-port="):
		for _, a := range args {
			if strings.HasPrefix(a, "--add-port=") {
				f.fwRules = append(f.fwRules, "port:"+strings.TrimPrefix(a, "--add-port="))
			}
		}
	case strings.Contains(joined, "--remove-port="):
		for _, a := range args {
			if strings.HasPrefix(a, "--remove-port=") {
				want := "port:" + strings.TrimPrefix(a, "--remove-port=")
				for i, r := range f.fwRules {
					if r == want {
						f.fwRules = append(f.fwRules[:i], f.fwRules[i+1:]...)
						break
					}
				}
			}
		}
	case strings.Contains(joined, "--add-rich-rule="):
		for _, a := range args {
			if strings.HasPrefix(a, "--add-rich-rule=") {
				f.fwRules = append(f.fwRules, "rich:"+strings.TrimPrefix(a, "--add-rich-rule="))
			}
		}
	case strings.Contains(joined, "--remove-rich-rule="):
		for _, a := range args {
			if strings.HasPrefix(a, "--remove-rich-rule=") {
				want := "rich:" + strings.TrimPrefix(a, "--remove-rich-rule=")
				for i, r := range f.fwRules {
					if normalizeSpace(r) == normalizeSpace(want) {
						f.fwRules = append(f.fwRules[:i], f.fwRules[i+1:]...)
						break
					}
				}
			}
		}
	}
	return ExecResult{Stdout: "success\n"}, nil
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

func (f *FakeExecutor) runNFT(args []string) (ExecResult, error) {
	joined := strings.Join(args, " ")

	switch {
	case strings.Contains(joined, "list ruleset") || strings.Contains(joined, "list table"):
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		// 注意句柄分配：table 与 chain 各占一个，
		// 规则从 2 起 —— 复现真实的句柄分布。
		b.WriteString("table inet filter { # handle 1\n")
		b.WriteString("\tchain input { # handle 1\n")
		b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
		for _, r := range f.nftRules {
			line := "\t\t" + r.Expr
			if r.Comment != "" {
				line += fmt.Sprintf(" comment %q", r.Comment)
			}
			line += fmt.Sprintf(" # handle %d\n", r.Handle)
			b.WriteString(line)
		}
		b.WriteString("\t}\n}\n")
		return ExecResult{Stdout: b.String()}, nil
	}

	if len(args) >= 3 && args[0] == "delete" && args[1] == "rule" {
		// nft delete rule inet filter input handle N
		handleIdx := -1
		for i, a := range args {
			if a == "handle" && i+1 < len(args) {
				handleIdx = i + 1
			}
		}
		if handleIdx < 0 {
			return ExecResult{Stderr: "Error: syntax error", ExitCode: 1},
				fmt.Errorf("delete rule 缺少 handle")
		}
		var handle int
		_, _ = fmt.Sscanf(args[handleIdx], "%d", &handle)

		f.mu.Lock()
		defer f.mu.Unlock()
		for i, r := range f.nftRules {
			if r.Handle == handle {
				f.nftRules = append(f.nftRules[:i], f.nftRules[i+1:]...)
				return ExecResult{}, nil
			}
		}
		// 真实的 nft 在句柄不存在时报这个错。
		return ExecResult{
				Stderr:   "Error: Could not process rule: No such file or directory",
				ExitCode: 1,
			},
			fmt.Errorf("handle %d 不存在", handle)
	}

	if len(args) >= 3 && args[0] == "add" && args[1] == "rule" {
		// 去掉前面的 "add rule inet filter input"，取规则表达式。
		expr := strings.Join(args[3:], " ")
		comment := ""
		if idx := strings.Index(expr, " comment "); idx >= 0 {
			comment = strings.Trim(expr[idx+len(" comment "):], `"`)
			expr = strings.TrimSpace(expr[:idx])
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nftRules = append(f.nftRules, fakeNFTRule{
			Handle: f.nextNftID, Expr: expr, Comment: comment,
		})
		f.nextNftID++
		return ExecResult{}, nil
	}

	return ExecResult{}, nil
}

// ---------------------------------------------------------------------------
// iptables
// ---------------------------------------------------------------------------

func (f *FakeExecutor) runIPTables(args []string) (ExecResult, error) {
	joined := strings.Join(args, " ")

	if strings.HasPrefix(joined, "-S") {
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		b.WriteString("-P INPUT ACCEPT\n")
		for _, r := range f.iptRules {
			b.WriteString(r + "\n")
		}
		return ExecResult{Stdout: b.String()}, nil
	}

	if len(args) >= 2 && (args[0] == "-A" || args[0] == "-I") {
		spec := fakeIPTablesSpec(args[1:])
		f.mu.Lock()
		f.iptRules = append(f.iptRules, spec)
		f.mu.Unlock()
		return ExecResult{}, nil
	}

	if len(args) >= 2 && args[0] == "-D" {
		want := normalizeSpace("-A " + fakeIPTablesSpec(args[1:]))
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, r := range f.iptRules {
			if normalizeSpace(r) == want {
				f.iptRules = append(f.iptRules[:i], f.iptRules[i+1:]...)
				return ExecResult{}, nil
			}
		}
		// 真实的 iptables 在规格不完全一致时报这个错。
		return ExecResult{
				Stderr:   "iptables: Bad rule (does a matching rule exist in that chain?).",
				ExitCode: 1,
			},
			fmt.Errorf("规格不匹配")
	}

	return ExecResult{}, nil
}

// fakeIPTablesSpec 把 iptables 的追加参数规范化成 `-S` 的输出形态。
//
// ########## 关键：补上内核会补的匹配器 ##########
//
// 真实 iptables 里，`-p tcp --dport 8080` 被 `-S` 读回时是
// `-p tcp -m tcp --dport 8080`——内核自动插入了 `-m tcp`。
// 这个行为正是"面板必须回读规格再删除"的原因，假执行器
// 必须复现它，否则端到端测试就验证不到这条关键路径。
func fakeIPTablesSpec(args []string) string {
	chain := args[0]
	rest := args[1:]

	var b strings.Builder
	b.WriteString("-A " + chain)

	hasProtoTCP := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		b.WriteString(" " + a)
		if a == "-p" && i+1 < len(rest) {
			b.WriteString(" " + rest[i+1])
			if rest[i+1] == "tcp" || rest[i+1] == "udp" {
				hasProtoTCP = true
			}
			i++
		} else if a == "-m" && i+1 < len(rest) {
			b.WriteString(" " + rest[i+1])
			i++
		} else if a == "--comment" && i+1 < len(rest) {
			b.WriteString(" " + rest[i+1])
			i++
		} else if (a == "--dport" || a == "--sport" || a == "--dports") && i+1 < len(rest) {
			b.WriteString(" " + rest[i+1])
			i++
		} else if a == "-s" || a == "-d" || a == "-j" {
			if i+1 < len(rest) {
				b.WriteString(" " + rest[i+1])
				i++
			}
		}
	}

	spec := b.String()
	// 模拟内核补 -m tcp / -m udp。
	if hasProtoTCP && !strings.Contains(spec, "-m tcp") && !strings.Contains(spec, "-m udp") {
		proto := "tcp"
		if strings.Contains(spec, "-p udp") {
			proto = "udp"
		}
		spec = strings.Replace(spec, "-p "+proto, "-p "+proto+" -m "+proto, 1)
	}
	return spec
}

// FakeExecutorJSON 把调用记录导出为 JSON（便于端到端脚本断言）。
func (f *FakeExecutor) FakeExecutorJSON() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := json.MarshalIndent(map[string]any{
		"backend": f.opts.Backend,
		"calls":   f.calls,
		"ufw":     f.ufwRules,
		"nft":     f.nftRules,
		"ipt":     f.iptRules,
	}, "", "  ")
	return string(data)
}
