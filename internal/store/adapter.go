package store

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ============================================================================
// 发行版与包管理器自适应（阶段四 4.5）
// ============================================================================
//
// 与 4.3 site.SystemAdapter 同一思路，但探测对象不同：
//
//	4.3 探测的是 "nginx 会加载哪些目录"   —— 读 nginx.conf 的 include 行；
//	4.5 探测的是 "这台机器用什么装软件"   —— 看 /etc/os-release + PATH 里的包管理器。
//
// 为什么**不**从 os-release 推断包管理器，而是以 PATH 为准：
//
//	os-release 回答的是"这是什么发行版"，而我们要回答的是
//	"哪条命令真的能装上软件"。容器镜像里常见
//	"Ubuntu 的 os-release + 只装了 apt"、也常见 Debian 上装了 dnf 的场景，
//	而且用户完全可以把面板放在一个 chroot/自定义 PATH 里跑。
//	以可执行文件是否存在为准，才是"能不能装"的准确答案。
//
// os-release 仍然要读，但它只用来回答**另一个问题**：
// 官方源条目里的发行版代号（Ubuntu 的 jammy / Debian 的 bookworm /
// RHEL 的 el9）。这两个信息不能互相替代：
// 代号可以由发行版名推出，而"用哪个包管理器"不能。

// 包管理器种类。
const (
	// PackageManagerAPT 是 Debian/Ubuntu 的 apt。
	PackageManagerAPT = "apt"
	// PackageManagerDNF 是 RHEL 8+/Fedora 的 dnf。
	PackageManagerDNF = "dnf"
	// PackageManagerYUM 是 CentOS 7 时代的 yum。
	PackageManagerYUM = "yum"
	// PackageManagerNone 表示没有探测到可用的包管理器。
	PackageManagerNone = ""
)

// 发行版家族。
const (
	// FamilyDebian 是 apt 系（Debian/Ubuntu/Deepin/…）。
	FamilyDebian = "debian"
	// FamilyRHEL 是 rpm 系（RHEL/CentOS/Rocky/Alma/Fedora/…）。
	FamilyRHEL = "rhel"
	// FamilyUnknown 表示没认出来（此时仍可能装得动软件，只是官方源不可用）。
	FamilyUnknown = "unknown"
)

// Vars 是一次探测得到的"运行环境事实"。
//
// 全部字段都是**探测结果**而不是配置：命令组装所需的一切环境相关
// 信息都收敛在这里，测试可以用一个手写的 Vars 跑通全部链路，
// 不需要真的准备一台 Debian 或 Rocky。
type Vars struct {
	// Manager 见 PackageManager* 常量。
	Manager string
	// ManagerPath 是包管理器可执行文件的绝对路径。
	ManagerPath string
	// Tools 是本次探测到的辅助可执行文件路径（缺一个就少一条策略分支）。
	Tools Tools
	// Family 见 Family* 常量。
	Family string
	// DistroID 是 os-release 的 ID（如 ubuntu、debian、centos）。
	DistroID string
	// DistroName 是 PRETTY_NAME（展示用）。
	DistroName string
	// VersionID 是 os-release 的 VERSION_ID（如 22.04、9）。
	VersionID string
	// Codename 是官方源条目要用的发行版标识。
	//
	// 取值规则（apt 系用代号，rpm 系用大版本号）：
	//	Ubuntu 22.04 → jammy（来自 VERSION_CODENAME 或 UBUNTU_CODENAME）
	//	Debian 12    → bookworm
	//	RHEL 9       → 9
	//	Fedora 40    → 40
	//
	// ########## 为什么 rpm 系存的是裸大版本号 ##########
	//
	// 官方仓库的 URL 形态并不统一：remi 是
	// `remi-release-9.rpm`（裸版本号），MySQL 是
	// `mysql84-community-release-el9-1.noarch.rpm`（带 el 前缀）。
	// 把 `el` 放进代号里会让 remi 需要额外去掉前缀（多一次字符串手术），
	// 因此这里统一存裸版本号，由清单模板自己决定要不要写 `el`。
	//
	// 取不到时为空——为空则**官方源步骤直接不可用**，
	// 而不是猜一个代号（猜错会把源条目写成一个不存在的发行版，
	// apt update 会报 404，用户完全看不懂发生了什么）。
	Codename string
	// Arch 是预编译包要用的架构标识（x64 / arm64 / armv7l）。
	Arch string
	// DistroSupported 表示该发行版被本模块的安装策略覆盖。
	DistroSupported bool
	// ProbeNotes 是探测过程中的说明（进 capabilities 与日志）。
	ProbeNotes []string
}

// Tools 是探测到的辅助工具路径。
//
// 每一个都可能为空——**为空即那条策略不可用**，而不是拼一个命令
// 出去撞运气。安装链路的每一步都必须能在"工具缺失"时给出
// 可读的降级原因，否则用户看到的是一个语焉不详的失败。
type Tools struct {
	// AptGet 是 apt-get 路径（apt 系的安装/卸载/刷新）。
	AptGet string
	// AptCache 是 apt-cache 路径（查询候选版本）。
	AptCache string
	// DpkgQuery 是 dpkg-query 路径（查询已安装版本）。
	DpkgQuery string
	// RPM 是 rpm 路径（rpm 系查询已安装版本）。
	RPM string
	// Curl 是 curl 路径（下载 GPG key 与预编译包、执行官方脚本）。
	Curl string
	// Tar 是 tar 路径（解压预编译包）。
	Tar string
}

// AdapterOptions 是构造适配器的配置。
type AdapterOptions struct {
	// OSReleasePath 是 os-release 的路径；为空时用 /etc/os-release。
	//
	// 可覆盖的唯一目的是**可测**：测试指向一个临时文件即可穷举
	// Ubuntu/Debian/Rocky/未知发行版等分支，不依赖运行测试的机器。
	OSReleasePath string
	// LookPath 探测可执行文件；为 nil 时用 exec.LookPath。
	LookPath func(string) (string, error)
	// GOARCH 覆盖运行架构；为空时用 runtime.GOARCH。
	GOARCH string
	// ForceManager 强制指定包管理器（apt/dnf/yum）。
	//
	// 真实用途：用户明确知道自己要哪套（例如系统里同时装了 apt 与 dnf）。
	// 它是**启动参数**而不是请求参数——请求参数可以伪造，
	// 而包管理器一旦被请求指定，就等于把"执行哪个程序"交给了调用方。
	ForceManager string
}

// DetectVars 探测运行环境（纯函数式：所有外部依赖都可注入）。
//
// 探测失败不返回错误：与 4.1 无 systemd、4.3 无 nginx 的降级策略一致，
// 面板其它功能必须照常可用，软件商店自身只标记为不可用并给出原因。
func DetectVars(opts AdapterOptions) Vars {
	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	arch := opts.GOARCH
	if arch == "" {
		arch = runtime.GOARCH
	}
	path := opts.OSReleasePath
	if path == "" {
		path = DefaultOSReleasePath
	}

	v := Vars{Arch: normalizeArch(arch)}
	release, notes := ParseOSRelease(path)
	v.ProbeNotes = notes
	v.DistroID = release["ID"]
	v.DistroName = release["PRETTY_NAME"]
	v.VersionID = release["VERSION_ID"]
	v.Family = familyOf(release)

	// 包管理器探测顺序：强制指定 > 家族默认 > 有什么用什么。
	//
	// 注意 apt 系优先 apt-get 而不是 apt：apt 命令会打印
	// "apt does not have a stable CLI interface" 警告到 stderr，
	// 而我们要解析输出。apt-get 是稳定接口。
	switch {
	case opts.ForceManager != "":
		// ########## ForceManager 是**种类**，不是命令名 ##########
		//
		// 这里曾经直接 lookPath(ForceManager)，于是 `-store-package-manager apt`
		// 会解析到 **/usr/bin/apt** —— 那是给人用的交互式前端，
		// 而不是稳定接口：它会往 stderr 打
		// "apt does not have a stable CLI interface"，
		// 且在非 tty 环境下行为与 apt-get 有差异。
		//
		// 我们始终要的是 apt-get，因此把种类映射到**规范命令**，
		// 再做探测。这样 -store-package-manager apt 与
		// -store-package-manager apt-get 都落到同一条命令上。
		cands := map[string][]string{
			PackageManagerAPT: {"apt-get"},
			PackageManagerDNF: {"dnf"},
			PackageManagerYUM: {"yum"},
		}
		names, ok := cands[opts.ForceManager]
		if !ok {
			v.ProbeNotes = append(v.ProbeNotes,
				fmt.Sprintf("未知的包管理器种类 %q（可用：apt、dnf、yum）", opts.ForceManager))
			break
		}
		if _, p := firstPresent(lookPath, names...); p != "" {
			v.Manager = opts.ForceManager
			v.ManagerPath = p
		} else {
			v.ProbeNotes = append(v.ProbeNotes,
				fmt.Sprintf("指定的包管理器 %s（命令 %s）不存在于 PATH 中",
					opts.ForceManager, names[0]))
		}
	case v.Family == FamilyDebian:
		v.Manager, v.ManagerPath = firstPresent(lookPath, PackageManagerAPT+"-get")
		if v.Manager != "" {
			v.Manager = PackageManagerAPT
		}
	case v.Family == FamilyRHEL:
		if m, p := firstPresent(lookPath, PackageManagerDNF); m != "" {
			v.Manager, v.ManagerPath = PackageManagerDNF, p
		} else if m, p := firstPresent(lookPath, PackageManagerYUM); m != "" {
			v.Manager, v.ManagerPath = PackageManagerYUM, p
		}
	}

	// 家族没认出来（或指定家族的管理器缺失）时退到"有什么用什么"：
	// 能装上软件比"发行版名字对得上"重要得多。
	if v.Manager == "" {
		for _, cand := range []struct{ cmd, kind string }{
			{"apt-get", PackageManagerAPT},
			{PackageManagerDNF, PackageManagerDNF},
			{PackageManagerYUM, PackageManagerYUM},
		} {
			if p, err := lookPath(cand.cmd); err == nil {
				v.Manager, v.ManagerPath = cand.kind, p
				v.ProbeNotes = append(v.ProbeNotes,
					fmt.Sprintf("发行版未识别（ID=%q），按 PATH 探测到 %s", v.DistroID, cand.cmd))
				break
			}
		}
	}

	// 辅助工具探测：查版本、下载、解包。缺哪一个就少一条策略分支，
	// 因此结论要能被上层看见（capabilities 里逐项列出）。
	v.Tools = Tools{}
	if p, err := lookPath("apt-get"); err == nil {
		v.Tools.AptGet = p
	}
	if p, err := lookPath("apt-cache"); err == nil {
		v.Tools.AptCache = p
	}
	if p, err := lookPath("dpkg-query"); err == nil {
		v.Tools.DpkgQuery = p
	}
	if p, err := lookPath("rpm"); err == nil {
		v.Tools.RPM = p
	}
	if p, err := lookPath("curl"); err == nil {
		v.Tools.Curl = p
	}
	if p, err := lookPath("tar"); err == nil {
		v.Tools.Tar = p
	}

	v.Codename = codenameOf(v, release)
	v.DistroSupported = v.Manager != "" && v.Codename != ""
	if v.Manager == "" {
		v.ProbeNotes = append(v.ProbeNotes, "PATH 中未找到 apt-get / dnf / yum")
	}
	if v.Codename == "" && v.Manager != "" {
		v.ProbeNotes = append(v.ProbeNotes,
			"未能从 os-release 得到发行版代号，官方源（ondrej/php、NodeSource 等）不可用")
	}
	return v
}

// DefaultOSReleasePath 是 os-release 的标准位置。
const DefaultOSReleasePath = "/etc/os-release"

// ParseOSRelease 解析 os-release（key=value，值可带引号）。
//
// 只做标准允许的极简解析：忽略注释与空行，值两侧引号去掉。
// 不做 shell 变量展开——os-release 允许 `$VAR` 引用，但我们
// 只关心 ID/VERSION_ID/PRETTY_NAME/CODENAME 这几个**永远字面量**的键，
// 实现展开反而引入一层可被操纵的解析语义。
func ParseOSRelease(path string) (map[string]string, []string) {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out, []string{fmt.Sprintf("无法读取 %s: %v", path, err)}
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		out[k] = val
	}
	if err := scanner.Err(); err != nil {
		return out, []string{fmt.Sprintf("读取 %s 出错: %v", path, err)}
	}
	return out, nil
}

// familyOf 依据 ID / ID_LIKE 判断发行版家族。
func familyOf(release map[string]string) string {
	id := strings.ToLower(release["ID"])
	like := strings.Fields(strings.ToLower(release["ID_LIKE"]))
	match := func(set []string) bool {
		for _, s := range set {
			if s == id {
				return true
			}
		}
		return false
	}
	debianIDs := []string{"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "deepin", "devuan", "elementary", "zorin", "neon", "proxmox"}
	rhelIDs := []string{"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "oracle", "amzn", "cloudlinux", "virtuozzo", "scientific", "springdale", "eurolinux"}
	if match(debianIDs) {
		return FamilyDebian
	}
	if match(rhelIDs) {
		return FamilyRHEL
	}
	// ID_LIKE 是发行版自报的"我像谁"，优先级低于精确 ID 但高于放弃。
	for _, l := range like {
		for _, d := range debianIDs {
			if l == d {
				return FamilyDebian
			}
		}
		for _, r := range rhelIDs {
			if l == r {
				return FamilyRHEL
			}
		}
	}
	return FamilyUnknown
}

// codenameOf 推导官方源条目要用的发行版标识。
func codenameOf(v Vars, release map[string]string) string {
	// apt 系：优先 VERSION_CODENAME，其次 UBUNTU_CODENAME、DEBIAN_CODENAME。
	for _, key := range []string{"VERSION_CODENAME", "UBUNTU_CODENAME", "DEBIAN_CODENAME"} {
		if c := strings.ToLower(strings.TrimSpace(release[key])); c != "" {
			if err := ValidCodename(c); err == nil {
				return c
			}
		}
	}
	// rpm 系：裸大版本号（"9"、"8"、"40"），由清单模板自行决定加不加 el 前缀。
	if v.Manager == PackageManagerDNF || v.Manager == PackageManagerYUM {
		ver := strings.TrimSpace(release["VERSION_ID"])
		if ver == "" {
			return ""
		}
		major := ver
		if i := strings.IndexByte(ver, '.'); i > 0 {
			major = ver[:i]
		}
		if _, ok := allDigits(major); !ok {
			return ""
		}
		return major
	}
	return ""
}

// normalizeArch 把 GOARCH 映射为官方预编译包的架构标识。
//
// 只映射本模块清单里真实存在产物的架构；未知架构返回空字符串，
// 预编译步骤据此**跳过**而不是拼出一个下载不到的 URL。
func normalizeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7l"
	default:
		return ""
	}
}

// firstPresent 返回第一个存在于 PATH 中的可执行文件。
func firstPresent(lookPath func(string) (string, error), cands ...string) (string, string) {
	for _, c := range cands {
		if p, err := lookPath(c); err == nil {
			return c, p
		}
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// 运行环境上的查询方法
// ---------------------------------------------------------------------------

// Available 表示软件商店的装/卸能力是否可用。
func (v Vars) Available() bool { return v.Manager != "" }

// UnavailableReason 返回不可用的可读原因（可用时为空）。
func (v Vars) UnavailableReason() string {
	if v.Available() {
		return ""
	}
	detail := ""
	if len(v.ProbeNotes) > 0 {
		detail = "（" + strings.Join(v.ProbeNotes, "；") + "）"
	}
	return "未在系统中找到可用的包管理器（apt-get / dnf / yum）" + detail +
		"。软件商店需要其中之一才能安装运行环境；面板其它功能不受影响。"
}

// SupportsOfficialSource 表示能否走"追加官方源"这条策略。
//
// 判据是**同时**具备包管理器与发行版代号：没有代号就写不出
// 合法的源条目（见 Vars.Codename 的说明）。
func (v Vars) SupportsOfficialSource() bool {
	return v.Manager != "" && v.Codename != ""
}

// Describe 返回一行人类可读的环境描述（启动日志用）。
func (v Vars) Describe() string {
	name := v.DistroName
	if name == "" {
		name = v.DistroID
	}
	if name == "" {
		name = "未知发行版"
	}
	parts := []string{name}
	if v.Codename != "" {
		parts = append(parts, "codename="+v.Codename)
	}
	if v.Manager != "" {
		parts = append(parts, "pkg="+v.Manager)
	} else {
		parts = append(parts, "pkg=无")
	}
	if v.Arch != "" {
		parts = append(parts, "arch="+v.Arch)
	}
	return strings.Join(parts, " ")
}

// keyringDir 返回 GPG keyring 的落盘目录。
//
// 固定为 /usr/share/keyrings：它是 Debian 与 Ubuntu 共同约定的
// "第三方公钥"目录，且**不需要 root 之外的额外权限**即可被 apt 读取。
// 刻意**不用** /etc/apt/keyrings：Ubuntu 22.04 之前该目录不存在，
// 且 Debian 的 apt-key 会告警；也不用已废弃的 trusted.gpg.d
// （key 混在一起后无法定点移除，轮换密钥时会互相踩）。
const keyringDir = "/usr/share/keyrings"

// listDir 返回 apt 源条目的落盘目录。
const listDir = "/etc/apt/sources.list.d"

// yumRepoDir 返回 yum/dnf 仓库配置的落盘目录。
const yumRepoDir = "/etc/yum.repos.d"

// KeyringDir / ListDir / YumRepoDir 导出供上层展示"会写到哪里"。
func KeyringDir() string { return keyringDir }
func ListDir() string    { return listDir }
func YumRepoDir() string { return yumRepoDir }

// filepathJoin 是 filepath.Join 的包内别名，便于统一处理路径拼装。
func filepathJoin(parts ...string) string { return filepath.Join(parts...) }
