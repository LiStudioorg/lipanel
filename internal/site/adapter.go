package site

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ============================================================================
// SystemAdapter：发行版自适应的 nginx 目录布局
// ============================================================================
//
// nginx 本身没有"站点"这个概念，只有"配置文件"。不同发行版把
// "一个站点一个文件"这件事落在了不同的目录约定上：
//
//	Debian / Ubuntu：  /etc/nginx/sites-available/<name>.conf  （所有站点）
//	                   /etc/nginx/sites-enabled/<name>.conf    （符号链接 → available）
//	                   启用 = 建链接，禁用 = 删链接（**保留** available 里的原文）
//
//	RHEL / CentOS：    /etc/nginx/conf.d/<name>.conf
//	                   启用 = 文件就在 conf.d 里，禁用 = 改名或删除
//
// 两套约定的**语义差别是实质性的**：Debian 的"禁用"是可逆的（配置还在），
// 而 conf.d 的"禁用"若直接删除就不可逆了。因此这里不能只做一层
// "路径映射"，而要把 Enable/Disable 的行为差异也抽象进来。
//
// 探测策略（重要）：**看 nginx.conf 里真实存在的 include 行**，
// 而不是猜发行版名字。理由是：
//   - 用户完全可以自定义 nginx.conf（把 sites-enabled 换成别的目录）；
//   - 容器镜像里常见"Ubuntu 的 /etc/os-release + 自写的 nginx.conf"这种组合；
//   - 猜发行版名需要读 /etc/os-release，多一个失败点，且它回答的是
//     "这是什么系统"而不是"nginx 会加载哪些目录"——后者才是我们真正要知道的。
//
// 探测失败（既没有 sites-enabled 也没有 conf.d）时**不报错**，
// 而是标记为不可用并给出可读原因，与 4.1 的 systemd 降级策略一致：
// 面板其它功能必须照常可用。

// 布局模式。
const (
	// ModeSites 是 Debian/Ubuntu 的 sites-available + sites-enabled 布局。
	ModeSites = "sites"
	// ModeConfD 是 RHEL/CentOS 的 conf.d 布局。
	ModeConfD = "conf.d"
	// ModeUnavailable 表示没有探测到可用的站点目录。
	ModeUnavailable = "unavailable"
)

// 目录名常量。抽出来是因为测试与文档都要引用它们。
const (
	dirSitesAvailable = "sites-available"
	dirSitesEnabled   = "sites-enabled"
	dirConfD          = "conf.d"
)

// confSuffix 是本站点配置文件的固定后缀。
//
// 为什么强制加后缀：nginx 的 include 指令用的是通配（`sites-enabled/*`），
// 目录里任何文件都会被加载。一次"另存为 .conf.bak"的备份操作，
// 若备份文件没有后缀区分，就会被 nginx 当成正式配置加载，
// 于是"旧配置"与"新配置"同时生效、互相抢同一个 server_name。
// 统一用 .conf 后缀 + 禁用时显式改名，是避免这类事故的最低成本做法。
const confSuffix = ".conf"

// disabledSuffix 是 conf.d 模式下"禁用"用的后缀。
//
// 用 `.disabled` 而不是 `.bak`：语义明确（这是被面板禁用的），
// 且不会与 include 的 `*.conf` 通配匹配，因此禁用后真的不会被加载。
const disabledSuffix = ".conf.disabled"

// nginxExecPattern 匹配 nginx.conf 里的 include 行，提取被加载的目录。
var nginxExecInclude = regexp.MustCompile(`(?m)^\s*include\s+([^;]+);`)

// UnavailableError 表示站点目录不可用。
var (
	// ErrNginxUnavailable 表示系统没有可用的 nginx。
	ErrNginxUnavailable = errors.New("site: 系统未提供可用的 nginx")
	// ErrAdapterUnavailable 表示没有探测到可用的站点目录布局。
	ErrAdapterUnavailable = errors.New("site: 未找到可用的 nginx 站点目录")
)

// AdapterOptions 是构造 SystemAdapter 的配置。
type AdapterOptions struct {
	// Prefix 是 nginx 的 prefix 目录；为空时用 DefaultNginxPrefix。
	//
	// 这个字段存在的主要目的是**可测与可验证**：
	//   - 测试可以指向一个临时目录，不碰真实系统的 /etc/nginx；
	//   - 验证时可以 `nginx -p <dir>` 起一个真实实例，完整跑通
	//     "生成配置 → nginx -t → reload"链路而不影响系统 nginx。
	Prefix string
	// ConfPath 是 nginx.conf 的路径；为空时用 <Prefix>/nginx.conf。
	//
	// 之所以允许单独覆盖：有些发行版把主配置放在 /etc/nginx/nginx.conf，
	// 而 include 的目标目录却通过 -c 参数或 conf.d 里的另一层 include 引入。
	ConfPath string
	// LogDir 是 nginx 日志目录；为空时用 <Prefix>/logs。
	LogDir string
	// Executable 是 nginx 可执行文件路径；为空时用 exec.LookPath("nginx")。
	//
	// 抽成字段的唯一目的是**可测**：回滚逻辑这类安全性质必须能用单测
	// 穷举（断言"nginx -t 失败后配置真的回到原样"），
	// 而真实的 nginx 无法在测试里被安全地随意调用。
	Executable string
	// LookPath 用于探测 nginx 可执行文件；为 nil 时用 exec.LookPath。
	LookPath func(string) (string, error)
}

// SystemAdapter 把「发行版的站点目录约定」抽象为统一操作。
type SystemAdapter struct {
	mode         string
	prefix       string
	confPath     string
	availableDir string // sites-available 或 conf.d
	enabledDir   string // sites-enabled 或 conf.d（与 availableDir 相同）
	executable   string
	probeErr     error

	// enableIsSymlink 表示"启用"是否需要建立符号链接（Debian 布局为 true）。
	enableIsSymlink bool

	// mu 保护目录的惰性创建。
	//
	// 为什么需要：sites-available 在某些精简镜像里可能不存在，
	// 而"首次创建站点"会去 MkdirAll 它。并发创建两个站点时
	// 两个 goroutine 会同时 MkdirAll——MkdirAll 本身是幂等的，
	// 但紧随其后的写入与链接建立需要串行化，否则可能出现
	// "A 刚写完文件、B 就把目录状态读走"的中间态。
	mu sync.Mutex
}

// DefaultNginxPrefix 是 nginx 的默认 prefix 目录。
const DefaultNginxPrefix = "/etc/nginx"

// NewSystemAdapter 探测并构造适配器。
//
// 探测失败**不返回错误**：调用方（main）应打印告警并继续启动，
// 让用户仍能使用面板的其它功能。可用性用 Available() 查询。
func NewSystemAdapter(opts AdapterOptions) *SystemAdapter {
	executable := opts.Executable
	var probeErr error
	if executable == "" {
		lookPath := opts.LookPath
		if lookPath == nil {
			lookPath = exec.LookPath
		}
		path, err := lookPath("nginx")
		if err != nil {
			probeErr = err
		} else {
			executable = path
		}
	}

	prefix := opts.Prefix
	if prefix == "" {
		prefix = DefaultNginxPrefix
	}
	confPath := opts.ConfPath
	if confPath == "" {
		confPath = filepath.Join(prefix, "nginx.conf")
	}

	a := &SystemAdapter{
		mode:       ModeUnavailable,
		prefix:     prefix,
		confPath:   confPath,
		executable: executable,
		probeErr:   probeErr,
	}

	// 没有 nginx 可执行文件时仍然继续探测目录：
	// 用户可能装好了配置目录但 nginx 不在 PATH 里（例如用绝对路径启动的
	// 第三方 nginx）。目录信息对"为什么不可用"的提示有价值。
	available, enabled, isSymlink := a.detectLayout()
	a.availableDir = available
	a.enabledDir = enabled
	a.enableIsSymlink = isSymlink
	if available != "" {
		if isSymlink {
			a.mode = ModeSites
		} else {
			a.mode = ModeConfD
		}
	}

	if executable == "" && probeErr != nil {
		a.probeErr = probeErr
	}
	return a
}

// detectLayout 探测站点目录布局，返回 (availableDir, enabledDir, enableIsSymlink)。
//
// 顺序很重要：**优先 Debian 布局**。原因是两种布局可能同时存在
// （本机实测：Ubuntu 的 nginx.conf 同时 include 了 conf.d/*.conf
// 与 sites-enabled/*），此时若选 conf.d，面板建的站点会出现在
// conf.d 而不是用户预期的 sites-available 里，且"禁用"语义会从
// "删链接"变成"改名"——与用户在 Debian 系统上的直觉不符。
func (a *SystemAdapter) detectLayout() (string, string, bool) {
	// 先从 nginx.conf 的 include 行里读真实被加载的目录。
	// 读不到时退回"按惯例猜"（见下方），但读得到时**一定**以它为准。
	includes := a.readIncludes()

	sitesAvailable := a.resolveIncludeDir(includes, dirSitesAvailable, filepath.Join(a.prefix, dirSitesAvailable))
	sitesEnabled := a.resolveIncludeDir(includes, dirSitesEnabled, filepath.Join(a.prefix, dirSitesEnabled))
	confD := a.resolveIncludeDir(includes, dirConfD, filepath.Join(a.prefix, dirConfD))

	// ① Debian 布局：sites-available 与 sites-enabled 都存在。
	if dirExists(sitesAvailable) && dirExists(sitesEnabled) {
		return sitesAvailable, sitesEnabled, true
	}
	// ② 只有 sites-enabled 被 include 且存在：仍按 Debian 语义处理，
	//    available 目录先记为约定路径（首次建站时会按需创建）。
	if dirExists(sitesEnabled) && a.includesDir(includes, dirSitesEnabled) {
		return sitesAvailable, sitesEnabled, true
	}
	// ③ conf.d：写进去即生效。
	if dirExists(confD) {
		return confD, confD, false
	}
	// ④ 都没有：不可用。这时候**不猜**——猜错目录会让配置写到
	//    一个 nginx 根本不加载的地方，用户会看到"保存成功但站点不生效"
	//    这种最糟糕的失败模式。宁可明确报"不可用"。
	return "", "", false
}

// readIncludes 解析 nginx.conf 里的 include 目标。
//
// 主配置读不到不是错误（自定义 -c、权限受限等），返回空集合，
// detectLayout 会退回按惯例探测。
func (a *SystemAdapter) readIncludes() []string {
	f, err := os.Open(a.confPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []string
	scanner := bufio.NewScanner(f)
	// 加大单行上限：nginx.conf 里可以有很长的 include 通配行。
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		// 跳过注释行：被注释掉的 include 不代表目录被加载。
		// 这个判定必须有，否则 `# include /etc/nginx/sites-enabled/*;`
		// 会让面板以为该目录生效，而实际它根本没被加载。
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := nginxExecInclude.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

// includeParent 把一个 include 目标规约为它所在的目录（绝对路径）。
//
// #################### 为什么必须处理相对路径 ####################
//
// nginx 的 include 目标**可以是相对路径**，此时它相对于 nginx 的
// prefix（更准确地说是 `-p` 指定的 prefix）解析。例如：
//
//	include sites-enabled/*.conf;
//
// 在 prefix=/etc/nginx 时实际加载的是 /etc/nginx/sites-enabled/*.conf。
//
// 初版实现直接对目标做 filepath.Dir，得到的是**相对路径** "sites-enabled"，
// 它既不是绝对路径、也 stat 不到，于是"目录是否存在"的判定必然失败，
// 适配器把明明可用的布局报成 unavailable。
//
// 这不是理论问题：本项目自己的端到端验证用的就是 `include sites-enabled/*.conf`
// 这种相对写法（见 .e2e/nginx-prefix/nginx.conf），测试直接把该缺陷抓了出来。
//
// 处理方式与 nginx 保持一致：相对路径一律拼到 prefix 上。
func (a *SystemAdapter) includeParent(inc string) string {
	parent := filepath.Dir(inc)
	if filepath.IsAbs(parent) {
		return filepath.Clean(parent)
	}
	return filepath.Join(a.prefix, parent)
}

// resolveIncludeDir 在 include 目标里找与 dirName 匹配的目录。
//
// 匹配方式：include 目标所在目录的**最后一段**等于 dirName。
// 这样 `sites-enabled/*.conf`（相对）、`/etc/nginx/sites-enabled/*`
// （绝对）都能命中。
func (a *SystemAdapter) resolveIncludeDir(includes []string, dirName, fallback string) string {
	for _, inc := range includes {
		parent := a.includeParent(inc)
		if filepath.Base(parent) == dirName {
			return parent
		}
	}
	return fallback
}

// includesDir 判断某个目录名是否出现在 include 目标里。
func (a *SystemAdapter) includesDir(includes []string, dirName string) bool {
	for _, inc := range includes {
		if filepath.Base(a.includeParent(inc)) == dirName {
			return true
		}
	}
	return false
}

// dirExists 判断路径是否存在且是目录。
func dirExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// ---------------------------------------------------------------------------
// 查询接口
// ---------------------------------------------------------------------------

// Available 表示站点管理是否可用（有 nginx 可执行文件且探测到站点目录）。
func (a *SystemAdapter) Available() bool {
	return a != nil && a.executable != "" && a.availableDir != ""
}

// Mode 返回探测到的布局模式。
func (a *SystemAdapter) Mode() string {
	if a == nil {
		return ModeUnavailable
	}
	return a.mode
}

// Prefix 返回 nginx 的 prefix 目录。
func (a *SystemAdapter) Prefix() string {
	if a == nil {
		return ""
	}
	return a.prefix
}

// Executable 返回 nginx 可执行文件路径。
func (a *SystemAdapter) Executable() string {
	if a == nil {
		return ""
	}
	return a.executable
}

// AvailableDir 返回"站点定义文件"所在目录。
//
// Debian 布局下是 sites-available（禁用后配置仍保留在这里），
// conf.d 布局下就是 conf.d 自身。
func (a *SystemAdapter) AvailableDir() string {
	if a == nil {
		return ""
	}
	return a.availableDir
}

// EnabledDir 返回"被 nginx 加载"的目录。
func (a *SystemAdapter) EnabledDir() string {
	if a == nil {
		return ""
	}
	return a.enabledDir
}

// UnavailableReason 返回不可用的原因（可用时为空字符串）。
//
// 提示必须**可操作**：用户看到的应当是"装 nginx"或"改 -nginx-prefix"，
// 而不是一句内部错误。
func (a *SystemAdapter) UnavailableReason() string {
	if a == nil {
		return "站点管理未初始化。"
	}
	var parts []string
	if a.executable == "" {
		detail := ""
		if a.probeErr != nil {
			detail = ": " + a.probeErr.Error()
		}
		parts = append(parts, "系统中未找到 nginx 可执行文件"+detail)
	}
	if a.availableDir == "" {
		parts = append(parts,
			fmt.Sprintf("在 %s 下未找到 nginx 站点目录"+
				"（既没有 %s/%s 与 %s/%s，也没有 %s/%s 被 nginx.conf 加载）",
				a.prefix, a.prefix, dirSitesAvailable, a.prefix, dirSitesEnabled,
				a.prefix, dirConfD))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；") +
		"。站点管理需要 nginx 环境；若 nginx 装在非标准位置，" +
		"可用启动参数 -nginx-prefix 指定其 prefix 目录。面板其它功能不受影响。"
}

// ---------------------------------------------------------------------------
// 站点文件路径
// ---------------------------------------------------------------------------

// SiteFilePath 返回某站点定义文件的路径（AvailableDir 下）。
//
// 调用方必须已经通过 ValidSiteName 校验过 name——本函数不做校验，
// 因为它是纯粹的路径拼装；把校验混进来会让人误以为
// "只要调用了它就安全"，而真正的强制点应当是入口处显式的校验调用。
func (a *SystemAdapter) SiteFilePath(name string) string {
	return filepath.Join(a.availableDir, name+confSuffix)
}

// EnabledPath 返回某站点"启用入口"的路径。
//
// Debian 布局下是 sites-enabled 里的符号链接；conf.d 布局下与
// SiteFilePath 相同（文件本身就在生效目录里）。
func (a *SystemAdapter) EnabledPath(name string) string {
	return filepath.Join(a.enabledDir, name+confSuffix)
}

// DisabledPath 返回 conf.d 布局下被禁用站点的路径。
func (a *SystemAdapter) DisabledPath(name string) string {
	return filepath.Join(a.availableDir, name+disabledSuffix)
}

// ---------------------------------------------------------------------------
// 启用 / 禁用
// ---------------------------------------------------------------------------

// Enable 让站点进入"被 nginx 加载"的状态。
//
// Debian 布局：建立 sites-enabled/<name>.conf → sites-available/<name>.conf
// 的**相对**符号链接。
//
// 为什么用相对链接而不是绝对链接：Debian 自带的 default 站点用的就是
// `default -> /etc/nginx/sites-available/default`（绝对），两者都能工作。
// 选相对的理由是**可迁移**：把整个 /etc/nginx 目录打包搬到另一台机器
// （换个 prefix）时，绝对链接会全部失效，相对链接依然有效。
//
// conf.d 布局：把 <name>.conf.disabled 改回 <name>.conf（若存在），
// 否则说明文件本来就在生效位置，无需操作。
func (a *SystemAdapter) Enable(name string) error {
	if !a.Available() {
		return fmt.Errorf("%w: %s", ErrAdapterUnavailable, a.UnavailableReason())
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enableIsSymlink {
		return a.enableConfD(name)
	}

	// 确保两个目录都存在。
	if err := os.MkdirAll(a.availableDir, 0o755); err != nil {
		return fmt.Errorf("site: 创建站点目录 %s 失败: %w", a.availableDir, err)
	}
	if err := os.MkdirAll(a.enabledDir, 0o755); err != nil {
		return fmt.Errorf("site: 创建启用目录 %s 失败: %w", a.enabledDir, err)
	}

	src := a.SiteFilePath(name)
	if !fileExists(src) {
		return fmt.Errorf("site: 站点 %s 的配置文件不存在: %s", name, src)
	}
	link := a.EnabledPath(name)

	// 已经存在就视为成功（幂等）：重复点"启用"不该报错。
	//
	// 但必须区分"存在且指向本文件"与"存在却指向别处"：
	// 后者说明有人手工改过链接，直接当成成功会让用户以为
	// "启用生效了"，而实际加载的是另一份配置。
	if target, err := os.Readlink(link); err == nil {
		if target == src || target == name+confSuffix {
			return nil
		}
		return fmt.Errorf("site: 启用链接 %s 已存在且指向 %s，"+
			"与预期不符。请先手工确认该链接后重试", link, target)
	} else if !errors.Is(err, os.ErrNotExist) {
		// 存在但不是符号链接（有人放了一个同名普通文件）：
		// 拒绝覆盖，因为那可能是用户自己的配置。
		return fmt.Errorf("site: %s 已存在且不是符号链接，拒绝覆盖", link)
	}

	// 相对链接：目标相对于链接所在目录。
	rel := filepath.Join("..", dirSitesAvailable, name+confSuffix)
	if err := os.Symlink(rel, link); err != nil {
		return fmt.Errorf("site: 创建启用链接 %s 失败: %w", link, err)
	}
	return nil
}

// enableConfD 在 conf.d 布局下启用站点。
func (a *SystemAdapter) enableConfD(name string) error {
	disabled := a.DisabledPath(name)
	active := a.SiteFilePath(name)

	if fileExists(disabled) {
		if fileExists(active) {
			// 两个文件同时存在说明状态不一致（多半是手工操作留下的）。
			// 静默挑一个会让用户看到不确定的结果，直接报错要求人工确认。
			return fmt.Errorf("site: %s 与 %s 同时存在，状态不一致，请手工清理后重试",
				active, disabled)
		}
		if err := os.Rename(disabled, active); err != nil {
			return fmt.Errorf("site: 启用 %s 失败（改名 %s → %s）: %w",
				name, disabled, active, err)
		}
	}
	return nil
}

// Disable 让站点退出"被 nginx 加载"的状态，但**保留配置内容**。
//
// Debian 布局：删除 sites-enabled 里的符号链接。
// 这是 Debian 布局的核心价值——sites-available 里的原文一字不动，
// 用户随时可以再启用，配置不会因为一次"禁用"而丢失。
//
// conf.d 布局：把 <name>.conf 改名为 <name>.conf.disabled。
//   - 为什么**不能只删文件**：删除是不可逆的。用户点"禁用"时的预期是
//     "先停一下"，而不是"永久删除配置"。真正的删除有单独的 Delete 操作。
//   - 为什么**不能只改内容加注释**：注释掉整个 server 块需要逐行处理，
//     容易改坏，且用户再编辑时看到的是一堆注释。
//   - 为什么后缀是 `.conf.disabled` 而不是 `.disabled`：nginx 的 include
//     是 `conf.d/*.conf`，只要文件名不再以 .conf 结尾就不会被加载。
//     保留 .conf 前缀是为了让用户一眼看出"这是一份 nginx 配置，只是被禁用了"。
func (a *SystemAdapter) Disable(name string) error {
	if !a.Available() {
		return fmt.Errorf("%w: %s", ErrAdapterUnavailable, a.UnavailableReason())
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enableIsSymlink {
		return a.disableConfD(name)
	}

	link := a.EnabledPath(name)
	info, err := os.Lstat(link)
	if errors.Is(err, os.ErrNotExist) {
		// 已经禁用（幂等）。
		return nil
	}
	if err != nil {
		return fmt.Errorf("site: 读取启用链接 %s 失败: %w", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		// 不是符号链接：多半是用户在 sites-enabled 里放了一份真实配置。
		// 删除它等于销毁用户的文件，不做。
		return fmt.Errorf("site: %s 不是符号链接，"+
			"为避免误删用户文件，请手工处理", link)
	}
	if err := os.Remove(link); err != nil {
		return fmt.Errorf("site: 禁用 %s 失败（删除链接 %s）: %w", name, link, err)
	}
	return nil
}

// disableConfD 在 conf.d 布局下禁用站点。
func (a *SystemAdapter) disableConfD(name string) error {
	active := a.SiteFilePath(name)
	disabled := a.DisabledPath(name)

	if !fileExists(active) {
		if fileExists(disabled) {
			return nil // 已经禁用（幂等）。
		}
		return fmt.Errorf("site: 站点 %s 的配置文件不存在", name)
	}
	if fileExists(disabled) {
		return fmt.Errorf("site: %s 已存在，无法把 %s 改名为它，请手工清理",
			disabled, active)
	}
	if err := os.Rename(active, disabled); err != nil {
		return fmt.Errorf("site: 禁用 %s 失败（改名 %s → %s）: %w",
			name, active, disabled, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 状态查询
// ---------------------------------------------------------------------------

// Enabled 判断站点当前是否处于启用状态。
func (a *SystemAdapter) Enabled(name string) bool {
	if !a.Available() {
		return false
	}
	if a.enableIsSymlink {
		// Debian 布局：sites-enabled 里的链接存在即启用。
		_, err := os.Lstat(a.EnabledPath(name))
		return err == nil
	}
	// conf.d 布局：<name>.conf 存在即启用。
	return fileExists(a.SiteFilePath(name))
}

// Defined 判断站点定义文件是否存在（无论是否启用）。
func (a *SystemAdapter) Defined(name string) bool {
	if !a.Available() {
		return false
	}
	return fileExists(a.SiteFilePath(name)) || fileExists(a.DisabledPath(name))
}

// fileExists 判断路径存在且是普通文件（跟随符号链接）。
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// ---------------------------------------------------------------------------
// 兼容 helper
// ---------------------------------------------------------------------------

// command 是执行 nginx 子命令的 argv 前缀。
//
// 所有 nginx 调用都必须经过这里，好处是：
// ① 统一注入 `-p <prefix>` 与 `-c <confPath>`，保证测试与真实实例
// 用的是同一份配置（而不是"测试用临时目录、线上用 /etc/nginx"的偏差）；
// ② 统一走 argv 切片，绝不拼 shell 字符串（与 4.1 的纪律一致）。
//
// 注意 t 命令要放在最前：`nginx -t -p X -c Y` 与 `nginx -p X -c Y -t`
// 都能工作，但把 `-t` 放前面更贴近所有文档里的写法，也更不容易
// 被某个版本的参数解析顺序影响。
func (a *SystemAdapter) command(args ...string) (string, []string) {
	full := []string{}
	if a.confPath != "" {
		full = append(full, "-c", a.confPath)
	}
	if a.prefix != "" {
		full = append(full, "-p", a.prefix)
	}
	full = append(full, args...)
	return a.executable, full
}
