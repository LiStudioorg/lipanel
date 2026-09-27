package firewall

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================================
// 端口保护（阶段四 4.6 防火墙与端口管理，核心自带）
// ============================================================================
//
// 本文件回答一个问题：**哪些端口不能随便关**。
//
// 防火墙模块与面板的其它模块有一处本质区别：它的操作对象是
// "网络可达性"，而面板本身就是通过网络被访问的。
// 一次误操作可以造成**不可逆的失联**——
// 用户关掉 22 端口后，SSH 断掉，如果面板端口也一起关了，
// 他就只剩物理控制台这一条路（云主机则要开工单）。
// 这与"删错一个文件"完全不同：后者可以重传，
// 前者会让人**再也连不上这台机器**。
//
// 因此本模块对两类端口施加保护：
//
//	① 面板自身的监听端口 —— 关了就连不上面板
//	② SSH 端口          —— 关了就连不上服务器
//
// #################### 核心纪律：探测不到就不猜 ####################
//
// 保护功能最大的风险不是"漏保护"，而是**错误保护**：
//
//	若我们猜 SSH 是 22（而实际上是 2222），会有两个后果：
//	  · 真正的 2222 没被保护，用户关掉它 → 失联
//	  · 无关的 22 被"保护"，用户被拦下来、开始怀疑面板的判定
//	第一条是安全事故，第二条是信任损失，
//	而两者都源于同一个错误：**用猜测代替探测**。
//
// 因此本文件的 Getenv 兜底、sshd_config 解析、监听端口探测
// 三条路径**都拿不到结论时，返回空集合**，
// 由前端如实显示"未能确定 SSH 端口"，而不是填一个 22。

// PortProtection 描述一个受保护的端口。
type PortProtection struct {
	// Port 是端口号。
	Port int `json:"port"`
	// Reason 是受保护的原因（面向用户，要具体）。
	Reason string `json:"reason"`
	// Source 说明这个端口是怎么确定的（探测来源）。
	//
	// ########## 为什么要把来源暴露出来 ##########
	//
	// 用户看到"22 被保护"时，第一个疑问是"你凭什么认为 22 是 SSH"。
	// 把来源（"读自 /etc/ssh/sshd_config" 或 "来自监听进程"）
	// 一并展示，用户就能自己判断这个结论可不可信，
	// 而不是只能选择"相信面板"或"完全不信"。
	Source string `json:"source"`
	// Kind 是保护类别：panel / ssh。
	Kind string `json:"kind"`
}

// 保护类别。
const (
	// ProtectPanel 表示面板自身的监听端口。
	ProtectPanel = "panel"
	// ProtectSSH 表示 SSH 端口。
	ProtectSSH = "ssh"
)

// Protection 是整个保护判定的结论。
type Protection struct {
	// Ports 是全部受保护的端口（按端口号排序）。
	Ports []PortProtection `json:"ports"`
	// SSHDetected 表示是否成功探测到 SSH 端口。
	//
	// ########## 为 false 时前端必须如实说明 ##########
	//
	// false 意味着"我们不知道 SSH 在哪个端口"，因此
	// **任何端口都可能是 SSH 端口**。前端应提示用户
	// "未能确定 SSH 端口，操作时请自行确认不会关闭 SSH"，
	// 而不是假装一切正常。
	SSHDetected bool `json:"ssh_detected"`
	// SSHSource 是 SSH 端口的探测来源（未探测到时为空）。
	SSHSource string `json:"ssh_source,omitempty"`
	// Notes 是探测过程中的说明与告警。
	Notes []string `json:"notes,omitempty"`
}

// ProtectOptions 是构造保护判定的配置。
type ProtectOptions struct {
	// PanelPort 是面板自身的监听端口（0 表示未知）。
	//
	// 由调用方从 -addr 解析后传入，而不是在本包再解析一遍：
	// 监听地址的真相只有 main 知道（它还可能是 unix socket、
	// 或者被 systemd socket activation 接管）。
	PanelPort int
	// SSHConfigPaths 是 sshd 配置的候选路径。
	//
	// 做成可配置是为了**可测**：测试用工作区里的临时文件，
	// 而生产用系统路径。若写死 /etc/ssh/sshd_config，
	// 本模块的测试就会依赖开发机上的真实 sshd 配置，
	// 那既不隔离也不可重复。
	SSHConfigPaths []string
	// SSHListenProbe 是一个"探测 SSH 监听端口"的回调。
	//
	// 由调用方注入（通常是读 /proc/net/tcp 或跑 ss），
	// 本包不自己执行命令：探测手段与平台相关，
	// 而保护判定本身是纯逻辑，两者分开才能各自被测试。
	SSHListenProbe func(ctx context.Context) []int
	// SSHConnectionEnv 是 SSH_CONNECTION 环境变量的值
	// （形如 "10.0.0.1 51234 10.0.0.2 22"）。
	//
	// 显式传入而不是直接 os.Getenv：让测试可以构造这一路径。
	SSHConnectionEnv string
	// ExtraPorts 是用户显式指定的受保护端口（-firewall-protected-ports）。
	ExtraPorts []int
}

// DefaultSSHConfigPaths 是 sshd 配置的默认候选路径。
var DefaultSSHConfigPaths = []string{
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d",
}

// Protector 判定受保护端口。
type Protector struct {
	panelPort   int
	configPaths []string
	listenProbe func(ctx context.Context) []int
	sshEnv      string
	extra       []int
}

// NewProtector 构造保护判定器。
func NewProtector(opts ProtectOptions) *Protector {
	paths := opts.SSHConfigPaths
	if len(paths) == 0 {
		paths = DefaultSSHConfigPaths
	}
	return &Protector{
		panelPort:   opts.PanelPort,
		configPaths: paths,
		listenProbe: opts.SSHListenProbe,
		sshEnv:      opts.SSHConnectionEnv,
		extra:       opts.ExtraPorts,
	}
}

// PanelPort 返回面板端口（0 表示未知）。
func (p *Protector) PanelPort() int { return p.panelPort }

// Evaluate 执行保护判定。
//
// 返回的 Protection.Ports 是全部受保护端口；
// 每个端口带具体的保护原因与探测来源。
func (p *Protector) Evaluate(ctx context.Context) Protection {
	var out Protection
	seen := map[int]bool{}

	add := func(port int, kind, reason, source string) {
		if port <= 0 || port > MaxPort {
			return
		}
		// 同一端口可能同时是面板端口与显式指定端口，
		// 保留先到的那条（面板端口优先，它的原因更有信息量）。
		if seen[port] {
			return
		}
		seen[port] = true
		out.Ports = append(out.Ports, PortProtection{
			Port:   port,
			Kind:   kind,
			Reason: reason,
			Source: source,
		})
	}

	// ① 面板自身的监听端口。
	if p.panelPort > 0 {
		add(p.panelPort, ProtectPanel,
			fmt.Sprintf("这是面板自身的监听端口（%d）。关闭它你将无法再访问面板，"+
				"若同时关闭 SSH 端口则只能通过物理控制台或云服务商的控制台恢复。", p.panelPort),
			"来自面板启动参数 -addr")
	}

	// ② 用户显式指定的受保护端口。
	for _, port := range p.extra {
		add(port, ProtectPanel,
			fmt.Sprintf("端口 %d 由 -firewall-protected-ports 显式声明为受保护。", port),
			"来自启动参数 -firewall-protected-ports")
	}

	// ③ SSH 端口：三条探测路径，按可靠性排序。
	sshPorts, source, notes := p.detectSSH(ctx)
	out.Notes = append(out.Notes, notes...)
	if len(sshPorts) > 0 {
		out.SSHDetected = true
		out.SSHSource = source
		for _, port := range sshPorts {
			add(port, ProtectSSH,
				fmt.Sprintf("这是 SSH 服务端口（%d）。关闭它你将失去远程登录能力，"+
					"只能通过物理控制台或云服务商的控制台恢复。", port),
				source)
		}
	} else {
		// ########## 探测不到时的处理：如实说明，绝不猜 ##########
		out.Notes = append(out.Notes,
			"未能确定 SSH 服务端口（未找到 sshd 配置、未能读取监听端口，"+
				"且当前会话不是通过 SSH 建立的）。因此面板无法对 SSH 端口施加保护——"+
				"请自行确认你所删除的端口不是 SSH 端口。")
	}

	sortProtection(out.Ports)
	return out
}

// detectSSH 按可靠性顺序探测 SSH 端口。
//
// 三条路径的顺序依据是"结论的确定程度"：
//
//	① sshd_config 的 Port 指令  —— 最准（就是 sshd 读的配置）。
//	   注意配置里可能有多个 Port 指令（监听多个端口），全部收集。
//	② 监听端口探测（ss/listen） —— 准（sshd 进程实际在听哪个端口），
//	   但需要能读到进程信息（/proc，且同权限）。
//	③ SSH_CONNECTION 环境变量   —— 最准但**最窄**：
//	   它只反映"当前这个连接"用的端口，若用户是通过
//	   非 SSH 方式（本地控制台、Web 终端）访问面板则不存在。
//	   作为兜底正合适：有它说明确实在 SSH 会话里，
//	   没有也不能推断"没有 SSH"。
//
// 三条都拿不到 -> 返回空 + 说明（绝不返回 22）。
func (p *Protector) detectSSH(ctx context.Context) (ports []int, source string, notes []string) {
	seen := map[int]bool{}
	push := func(all []int) []int {
		var out []int
		for _, v := range all {
			if v > 0 && v <= MaxPort && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}

	// ① sshd 配置。
	cfgPorts, cfgNotes := readSSHDPorts(p.configPaths)
	notes = append(notes, cfgNotes...)
	if len(cfgPorts) > 0 {
		return push(cfgPorts), "读自 sshd 配置（Port 指令）", notes
	}

	// ② 监听端口探测。
	if p.listenProbe != nil {
		listenPorts := p.listenProbe(ctx)
		if len(listenPorts) > 0 {
			return push(listenPorts), "来自 SSH 服务的实际监听端口", notes
		}
	}

	// ③ SSH_CONNECTION 兜底。
	if port, ok := sshPortFromConnectionEnv(p.sshEnv); ok {
		return push([]int{port}), "来自当前 SSH 连接（SSH_CONNECTION 环境变量）", notes
	}

	return nil, "", notes
}

// sshPortFromConnectionEnv 从 SSH_CONNECTION 解析出服务端端口。
//
// ########## 格式与"取哪一段" ##########
//
// SSH_CONNECTION 的格式是四段：
//
//	<客户端IP> <客户端端口> <服务端IP> <服务端端口>
//
// 我们要的是**服务端端口**（第 4 段）——那是 sshd 在听的端口。
// 取错成第 2 段（客户端端口）会得到一个随机的高位端口，
// 于是面板会"保护"一个毫不相干的端口，而真正的 22 毫无保护。
//
// 这个错误极其隐蔽：客户端端口通常也在 1-65535 内，
// 因此任何"看起来解析成功"的检查都发现不了它，
// 只有对照真实值才能发现（因此本函数有专门的测试）。
func sshPortFromConnectionEnv(env string) (int, bool) {
	fields := strings.Fields(env)
	if len(fields) != 4 {
		return 0, false
	}
	// 第 4 段是服务端端口。
	port, err := strconv.Atoi(fields[3])
	if err != nil || port < MinPort || port > MaxPort {
		return 0, false
	}
	return port, true
}

// sshPortDirectiveRe 匹配 sshd_config 里的 Port 指令。
//
// ########## 必须处理的行形态 ##########
//
//	Port 22              —— 正常
//	Port 22 # 注释        —— 行尾注释
//	port 22              —— 关键字大小写不敏感
//	#Port 2222           —— **被注释掉的**，必须忽略
//	Port 22 23 24        —— 部分版本支持一行多个端口
//
// 被注释掉的那一条最容易出错：若不处理，
// 面板会"保护"一个 sshd 实际不听的端口。
var sshPortDirectiveRe = regexp.MustCompile(`(?i)^\s*port\s+(.+)$`)

// readSSHDPorts 从 sshd 配置里读取 Port 指令。
//
// 支持两种路径形态：文件（直接解析）与目录（解析其下的 *.conf，
// 这是 Debian/Ubuntu 的 sshd_config.d 与 RHEL 的 conf.d 做法）。
func readSSHDPorts(paths []string) ([]int, []string) {
	var (
		ports []int
		notes []string
		seen  = map[int]bool{}
	)

	addPorts := func(found []int, from string) {
		var added []int
		for _, p := range found {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
				added = append(added, p)
			}
		}
		if len(added) > 0 {
			notes = append(notes, fmt.Sprintf("从 %s 读到 SSH 端口: %v", from, added))
		}
	}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			// 路径不存在是正常情况（不同发行版布局不同），
			// 不记 note 以免噪音。
			continue
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				notes = append(notes, fmt.Sprintf("无法读取 SSH 配置目录 %s: %v", path, err))
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
					continue
				}
				full := filepath.Join(path, e.Name())
				if found, err := parseSSHDConfigFile(full); err == nil && len(found) > 0 {
					addPorts(found, full)
				}
			}
			continue
		}
		found, err := parseSSHDConfigFile(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("读取 SSH 配置 %s 失败: %v", path, err))
			continue
		}
		addPorts(found, path)
	}
	return ports, notes
}

// parseSSHDConfigFile 解析单个 sshd 配置文件。
func parseSSHDConfigFile(path string) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ports []int
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)

		// 跳过注释行与空行。
		//
		// ########## 这一条是关键 ##########
		//
		// "#Port 2222" 是被注释掉的配置，sshd 不会读它。
		// 若不跳过，面板会保护一个 sshd 实际不听的端口，
		// 而真正的端口毫无保护。
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// 去掉行尾注释（Port 22 # main）。
		if i := strings.Index(trimmed, "#"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		m := sshPortDirectiveRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		// 一行可能有多个端口。
		for _, tok := range strings.Fields(m[1]) {
			p, err := strconv.Atoi(tok)
			if err != nil || p < MinPort || p > MaxPort {
				continue
			}
			ports = append(ports, p)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ports, nil
}

// sortProtection 按端口号升序排列保护列表。
func sortProtection(ports []PortProtection) {
	// 用简单插入排序：受保护端口通常只有个位数，
	// 引入 sort 包只是为这点数据没必要（且本包要保持零依赖纯粹性）。
	for i := 1; i < len(ports); i++ {
		cur := ports[i]
		j := i - 1
		for j >= 0 && ports[j].Port > cur.Port {
			ports[j+1] = ports[j]
			j--
		}
		ports[j+1] = cur
	}
}

// ============================================================================
// 保护判定
// ============================================================================

// ProtectionLookup 是保护判定的查询索引（由 Protection 构造）。
type ProtectionLookup struct {
	byPort map[int]PortProtection
}

// Lookup 从 Protection 构造查询索引。
func (p Protection) Lookup() ProtectionLookup {
	m := make(map[int]PortProtection, len(p.Ports))
	for _, pp := range p.Ports {
		m[pp.Port] = pp
	}
	return ProtectionLookup{byPort: m}
}

// Find 返回某端口的保护信息。
//
// ########## 端口范围的处理 ##########
//
// 范围规则（如 8000-9000）若覆盖了受保护端口，
// 应当判定为"涉及受保护端口"——关掉这个范围同样会关掉 SSH。
// 因此本函数对范围会检查区间内是否有任何受保护端口。
func (l ProtectionLookup) Find(port PortSpec) (PortProtection, bool) {
	if port.Start <= 0 {
		return PortProtection{}, false
	}
	// 精确命中优先。
	if pp, ok := l.byPort[port.Start]; ok && !port.IsRange() {
		return pp, true
	}
	// 范围：返回区间内第一个受保护端口。
	for p := port.Start; p <= port.End; p++ {
		if pp, ok := l.byPort[p]; ok {
			return pp, true
		}
	}
	return PortProtection{}, false
}

// Ports 返回全部受保护端口号（升序）。
func (l ProtectionLookup) Ports() []int {
	out := make([]int, 0, len(l.byPort))
	for p := range l.byPort {
		out = append(out, p)
	}
	// 插入排序保持与 sortProtection 一致的有序性。
	for i := 1; i < len(out); i++ {
		cur := out[i]
		j := i - 1
		for j >= 0 && out[j] > cur {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = cur
	}
	return out
}

// IsProtected 判断某端口是否受保护。
func (l ProtectionLookup) IsProtected(port PortSpec) bool {
	_, ok := l.Find(port)
	return ok
}

// ProtectPortError 构造"端口受保护"的错误。
//
// 错误信息里带上保护原因与来源，让用户能自己判断"要不要强删"。
func ProtectPortError(pp PortProtection) error {
	return fmt.Errorf("%w: 端口 %d —— %s（依据：%s）",
		ErrProtectedPort, pp.Port, pp.Reason, pp.Source)
}
