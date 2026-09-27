// Package store 实现软件商店（阶段四 4.5，核心自带）。
//
// 职责：内置软件清单（可安装哪些软件、哪些版本）、安装/卸载的
// 多源回退策略（系统源 → 官方源 → 预编译包）、异步任务与进度查询。
//
// 安全底线（与 4.1 systemctl / 4.3 nginx / 4.4 certbot 同一纪律）：
//   - 一切外部命令走 argv 切片，绝不拼 shell 字符串；
//   - 软件 ID 与版本号在进入任何命令之前经过严格白名单校验；
//   - 包名与源地址只允许来自**内置清单**，用户输入永远到不了命令里。
package store

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ============================================================================
// 软件清单（内置 JSON）
// ============================================================================
//
// 清单刻意用 JSON 而不是 Go map 字面量：
//
//	① 计划要求「新增软件清单解析测试」——JSON 需要一个真实的解析器，
//	   解析器能被测试穷举（重复 ID、非法版本、空版本表……），
//	   Go map 字面量没有"解析"可言，测试也就无从写起；
//	② 清单是一份**数据**，评审时读 JSON 比读嵌套 struct 字面量快得多；
//	③ go:embed 打进单二进制，零运行时文件依赖，仍然满足"单二进制"约束。
//
// 清单是唯一可信的包名/源地址来源：**用户提交的只有软件 ID 与版本号**，
// 二者都先过白名单校验，再从清单里查条目；真正的包名、源 key、
// GPG key URL、安装脚本 URL 全部来自这份内置清单。
// 也就是说：即便未来放宽校验，攻击面也不包含"任意的包名或 URL"。

// catalogJSON 是内置软件清单。
//
//go:embed catalog.json
var catalogJSON []byte

// ---------------------------------------------------------------------------
// 数据类型
// ---------------------------------------------------------------------------

// OfficialSourceType 是官方源的接入方式。
const (
	// OfficialAptKeySource 走 "GPG key + sources.list.d 条目"（apt 系）。
	// key 一律下载到 keyrings 专用目录并以 [signed-by=] 绑定，
	// 绝不把 key 塞进全局 trusted.gpg.d（那会让 key 失效后
	// 无法定点移除）。
	OfficialAptKeySource = "apt-key-source"
	// OfficialScript 走官方安装脚本（NodeSource 的 deb 源也由它代管）。
	// 脚本经 curl | sh 执行是本模块**唯一**一处 shell 形态的执行，
	// 且管道右侧固定是 `sh`、左侧只有一个经白名单校验的内置 URL；
	// 为此显式拆出 ScriptName/ScriptArgs（见 Command），
	// 让"哪些命令是 argv 直跑、哪些经由 sh -c"在类型上可区分、可测试。
	OfficialScript = "script"
	// OfficialDnfRepo 走 dnf 的 release 包（rpm 系装 Node.js/remi 的标准做法）。
	OfficialDnfRepo = "dnf-release-package"
	// OfficialYumRepo 走"自己写 .repo 文件 + rpm --import 公钥"。
	//
	// 用途：官方只提供"手工创建仓库文件"的接入方式时
	// （nginx.org 对 RHEL 就是如此，它给的是文档里的一段 .repo 内容）。
	// 与 apt 的 apt-key-source 对称：公钥落盘 + 仓库条目落盘。
	OfficialYumRepo = "yum-repo-file"
)

// PrebuiltKind 是预编译包的形态。
const (
	// PrebuiltTarGz 是 .tar.gz 归档（PHP 官方源缺失时的兜底形态）。
	PrebuiltTarGz = "tar.gz"
)

// OfficialSource 描述"系统源里没有这个版本"时的官方源接入方式。
type OfficialSource struct {
	// Kind 见 Official* 常量。
	Kind string `json:"kind"`
	// KeyURL 是 GPG 公钥下载地址（OfficialAptKeySource）。
	KeyURL string `json:"key_url,omitempty"`
	// KeyringPath 是公钥落盘的固定路径（keyrings 专用目录）。
	// 它是**固定文件名**，不含任何版本/软件名插值——避免成为注入面。
	KeyringPath string `json:"keyring_path,omitempty"`
	// ListFile 是 sources.list.d 下的条目文件名（固定名，同上）。
	ListFile string `json:"list_file,omitempty"`
	// SourceLineTemplate 是源条目模板。`{codename}` 会被替换为
	// **OS-release 解析出的**发行版代号（不是用户输入），
	// 替换前经过代号白名单校验。除此之外的文本原样落盘。
	SourceLineTemplate string `json:"source_line_template,omitempty"`
	// ScriptURL 是官方安装脚本地址模板（OfficialScript）。
	// 支持 `{version}` 占位符（如 NodeSource 的 setup_{version}.x）。
	ScriptURL string `json:"script_url,omitempty"`
	// ScriptArgs 是传给脚本的固定参数（来自清单常量，非用户输入）。
	ScriptArgs []string `json:"script_args,omitempty"`
	// RepoURLTemplate 是 release 包/rpm 仓库的地址模板（OfficialDnfRepo）。
	// 支持 `{version}` 与 `{distro}` 占位符。
	RepoURLTemplate string `json:"repo_url_template,omitempty"`
	// KeyPath / RepoFile / RepoContentTemplate 用于 OfficialYumRepo：
	// 公钥落盘位置、仓库文件名、仓库文件内容模板（支持 {distro}）。
	KeyPath             string `json:"key_path,omitempty"`
	RepoFile            string `json:"repo_file,omitempty"`
	RepoContentTemplate string `json:"repo_content_template,omitempty"`
}

// Validate 校验一个官方源条目自身的完整性（清单在加载时全量校验）。
//
// 这一步不是防御用户——用户根本改不了内置清单——而是防御**编辑错误**：
// 清单里写错一个字段（比如 apt-key-source 少了 key_url），
// 后果是安装进行到一半时命令组装失败。清单解析期就要拒绝。
func (o OfficialSource) Validate() error {
	switch o.Kind {
	case OfficialAptKeySource:
		if err := validHTTPSURL(o.KeyURL); err != nil {
			return fmt.Errorf("official.key_url: %w", err)
		}
		if err := validFixedPath(o.KeyringPath); err != nil {
			return fmt.Errorf("official.keyring_path: %w", err)
		}
		if err := validFixedName(o.ListFile); err != nil {
			return fmt.Errorf("official.list_file: %w", err)
		}
		if !strings.Contains(o.SourceLineTemplate, "{distro}") {
			return fmt.Errorf("official.source_line_template: 缺少 {distro} 占位符")
		}
		if err := validSourceLine(o.SourceLineTemplate); err != nil {
			return fmt.Errorf("official.source_line_template: %w", err)
		}
	case OfficialScript:
		if err := validHTTPSURLTemplate(o.ScriptURL); err != nil {
			return fmt.Errorf("official.script_url: %w", err)
		}
		for _, a := range o.ScriptArgs {
			if err := ValidToken(a); err != nil {
				return fmt.Errorf("official.script_args: %w", err)
			}
		}
	case OfficialDnfRepo:
		if err := validHTTPSURLTemplate(o.RepoURLTemplate); err != nil {
			return fmt.Errorf("official.repo_url_template: %w", err)
		}
		if !strings.Contains(o.RepoURLTemplate, "{distro}") &&
			!strings.Contains(o.RepoURLTemplate, "{version}") {
			return fmt.Errorf("official.repo_url_template: 至少要有一个占位符")
		}
	case OfficialYumRepo:
		if err := validHTTPSURL(o.KeyURL); err != nil {
			return fmt.Errorf("official.key_url: %w", err)
		}
		if err := validFixedPath(o.KeyPath); err != nil {
			return fmt.Errorf("official.key_path: %w", err)
		}
		if err := validFixedPath(o.RepoFile); err != nil {
			return fmt.Errorf("official.repo_file: %w", err)
		}
		if !strings.HasSuffix(o.RepoFile, ".repo") {
			return fmt.Errorf("official.repo_file: 必须以 .repo 结尾（否则 dnf 不会加载）")
		}
		if !strings.Contains(o.RepoContentTemplate, "{distro}") {
			return fmt.Errorf("official.repo_content_template: 缺少 {distro} 占位符")
		}
		// 仓库文件内容是多行 INI，用**比 apt 源条目更严**的字符集：
		// 只允许字母数字、常见标点与换行，且逐行校验（见函数内注释）。
		if err := validRepoContent(o.RepoContentTemplate); err != nil {
			return fmt.Errorf("official.repo_content_template: %w", err)
		}
	default:
		return fmt.Errorf("official.kind 未知: %q", o.Kind)
	}
	return nil
}

// validRepoContent 校验 yum .repo 文件内容模板。
//
// 比 apt 源条目多允许换行，但仍拒绝 `$`、反引号、引号与 shell 元字符——
// 除了两个**白名单内的 dnf 变量**：`$basearch` 与 `$releasever`。
//
// ########## 为什么只放行这两个 `$` ################
//
// dnf 的 .repo 文件支持变量替换，而 `$basearch` 是写仓库地址的
// 标准做法（同一份文件要在 x86_64 与 aarch64 上通用）。
// 但"支持变量替换"也意味着：一旦模板里出现别的 `$`，
// 我们写下的字面文本就变成了 dnf 会解释的配置语言。
// 因此这里只把这两个已知变量当字面量放行，其余 `$` 一律拒绝。
func validRepoContent(tmpl string) error {
	if len(tmpl) > 2048 {
		return fmt.Errorf("内容过长（%d > 2048）", len(tmpl))
	}
	for _, line := range strings.Split(tmpl, "\n") {
		probe := strings.ReplaceAll(line, "$basearch", "BASESEARCH")
		probe = strings.ReplaceAll(probe, "$releasever", "RELEASEVER")
		if !repoContentPattern.MatchString(probe) {
			return fmt.Errorf("第 %q 行含非法字符", line)
		}
	}
	return nil
}

// validHTTPSURLTemplate 校验带占位符的 https URL 模板。
//
// 做法：把占位符替换成**合法的样例值**再跑一遍 urL 白名单。
// 这样"模板本身字符集合法、占位符拼出来的结果也合法"两件事
// 一次校验完成，且不需要为"带花括号的 URL"另写一套宽松正则。
func validHTTPSURLTemplate(tmpl string) error {
	if !strings.Contains(tmpl, "{version}") && !strings.Contains(tmpl, "{distro}") {
		return validHTTPSURL(tmpl)
	}
	for _, v := range []string{"1.2.3", "22", "9", "jammy", "x64", "arm64"} {
		probe := strings.ReplaceAll(tmpl, "{version}", v)
		probe = strings.ReplaceAll(probe, "{distro}", v)
		probe = strings.ReplaceAll(probe, "{arch}", v)
		if strings.ContainsAny(probe, "{}") {
			return fmt.Errorf("模板含未知占位符: %q", tmpl)
		}
		if err := validHTTPSURL(probe); err != nil {
			return err
		}
	}
	return nil
}

// VersionPrebuilt 是版本级的预编译包兜底信息。
//
// ########## 只接受第一方产物 ##########
//
// 清单里允许出现的预编译包**只有软件官方发布的归档**
// （如 nodejs.org 的官方 tarball）。第三方"静态构建站"一律不收录：
// 安装路径上我们已经把信任交给了发行版仓库（有签名与审核），
// 再引入一个无签名的第三方二进制分发点，等于把 root 权限
// 交给一个没人审计的站点。宁可让这条兜底路径只覆盖少数软件。
//
// ########## 两种取 URL 的方式 ##########
//
//	① URLTemplate        —— 文件名固定的场景，直接下载；
//	② IndexURLTemplate   —— 文件名含**补丁号**的场景（Node.js 就是），
//	                       先下载索引（SHASUMS256.txt），
//	                       按前后缀匹配出真实文件名，再下载。
//
// 方式 ② 是必需的：`node-v22-linux-x64.tar.gz` 这个 URL **不存在**，
// 官方文件名是 `node-v22.14.0-linux-x64.tar.gz`。若把补丁号写死进清单，
// 清单会以"每几周失效一次"的速度腐化；而把"最新补丁号"的解析
// 交给官方索引，是唯一不需要人工跟版的写法。
type VersionPrebuilt struct {
	// Kind 见 Prebuilt* 常量。
	Kind string `json:"kind"`
	// URLTemplate 是固定下载地址模板 {version} / {arch}，二选一。
	URLTemplate string `json:"url_template,omitempty"`
	// IndexURLTemplate 是索引文件地址模板（如 SHASUMS256.txt）。
	IndexURLTemplate string `json:"index_url_template,omitempty"`
	// FilePrefix / FileSuffix 是在索引里匹配文件名用的前后缀，
	// 支持 `{arch}` 占位符（如 "node-v" / "-linux-{arch}.tar.gz"）。
	FilePrefix string `json:"file_prefix,omitempty"`
	FileSuffix string `json:"file_suffix,omitempty"`
	// InstallDir 是解包目标目录（固定路径）。
	InstallDir string `json:"install_dir,omitempty"`
	// LinkDir 是软链接目录（固定路径，通常 /usr/local/bin）。
	//
	// 预编译包解包后不会自动进 PATH，必须建软链接才"能直接用"。
	// 这一步是必要的：否则用户装完 node 敲 `node -v` 会得到
	// command not found，而面板显示"安装成功"。
	LinkDir string `json:"link_dir,omitempty"`
	// Binaries 是要建软链接的可执行文件名（相对 InstallDir/bin）。
	Binaries []string `json:"binaries,omitempty"`
	// VerifyArgs 是验证命令的参数（默认 `--version`）。
	VerifyArgs []string `json:"verify_args,omitempty"`
	// Notes 是兜底路径的已知限制（进任务日志与列表，让用户知道差异）。
	Notes []string `json:"notes,omitempty"`
}

// Version 是软件的一个可安装版本。
type Version struct {
	// ID 是版本字符串（如 "8.3"、"22"），同时用作包名后缀/替代名基准。
	ID string `json:"id"`
	// Label 是展示名（如 "PHP 8.3"）。
	Label string `json:"label,omitempty"`
	// SystemPackages 是该版本在**系统源**里对应的包名列表
	// （存在系统源时优先使用；可能为空表示系统源根本没有该版本，
	// 直接走官方源）。
	SystemPackages []string `json:"system_packages,omitempty"`
	// AlternativePackages 是系统源尝试失败后**在同源内**再试的包名
	// （Debian 与 Ubuntu 对同一软件的命名不同，如
	// php8.3-fpm vs php8.3-fpm8.3）。仍是内置常量，非用户输入。
	AlternativePackages []string `json:"alternative_packages,omitempty"`
	// PinSystemVersion 表示安装时要**钉住具体版本**
	// （apt 的 `pkg=1.26.2-1~jammy`、rpm 的 `pkg-1.26.2-1` 形态）。
	//
	// ########## 为什么必须有这个开关 ##########
	//
	// Debian/Ubuntu 的官方仓库里同一个包只有一个候选版本，
	// 因此「装 nginx」与「装 nginx 1.26」在不钉版本时是同一条命令。
	// nginx.org 的仓库就是这种情况：包名恒为 nginx，
	// 想装 1.26 只能用 `apt-get install nginx=1.26.2-1~jammy`。
	//
	// 没有这个开关时只有两条错路可走：
	//   ① 把版本编进包名（nginx1.26）—— 这个包不存在，永远装不上；
	//   ② 用包名 nginx —— 装上的可能是源里的任意版本，
	//      而"选了 1.26 却装上 1.24"会以**成功**上报，是最坏的结果。
	//
	// 钉住的值不是清单里写的，而是**源里查到的候选版本**：
	// 清单只知道"1.26"，完整版本号（1.26.2-1~jammy）
	// 只有 apt-cache policy / dnf list 才知道。
	PinSystemVersion bool `json:"pin_system_version,omitempty"`
	// Prebuilt 是最后的兜底（官方源也没有该版本时）。
	Prebuilt *VersionPrebuilt `json:"prebuilt,omitempty"`
	// Notes 是版本级提示（前端直接展示）。
	Notes []string `json:"notes,omitempty"`
}

// Software 是一个可安装软件（一个"卡片"）。
type Software struct {
	// ID 是稳定标识（白名单字符集，同时用于命令与展示）。
	ID string `json:"id"`
	// Name 是展示名（如 "PHP"）。
	Name string `json:"name"`
	// Category 是分组（Web 服务器 / 数据库 / 语言运行时 / 缓存）。
	Category string `json:"category"`
	// Description 是一句话说明。
	Description string `json:"description"`
	// DefaultVersion 是默认版本 ID（前端高亮）。
	DefaultVersion string `json:"default_version"`
	// Depends 是依赖的其他软件 ID（安装前自动补齐，见 Dependencies）。
	Depends []string `json:"depends,omitempty"`
	// Official 是按发行版家族分的官方源接入方式（key 为 debian / rhel）。
	//
	// ########## 为什么按家族分而不是一个字段 ##########
	//
	// 同一个软件的官方源在两大体系里**做法完全不同**：
	//
	//	PHP  Debian/Ubuntu → deb.sury.org（deb 源 + GPG key）
	//	     RHEL/Rocky    → remi-release rpm
	//	Node.js 两家都用官方安装脚本，但 RPM 侧是 release rpm
	//
	// 若只留一个字段，就得在运行期"按家族改行为"——那等于把
	// 清单数据写成了代码。分家族后，某个家族没写就是对它
	// **明确不支持官方源**，运行期直接走预编译或给出可读失败。
	Official map[string]OfficialSource `json:"official,omitempty"`
	// Versions 是可安装版本列表。
	Versions []Version `json:"versions"`
}

// Catalog 是解析后的完整清单。
type Catalog struct {
	Software []Software
	byID     map[string]*Software
}

// ---------------------------------------------------------------------------
// 解析与校验
// ---------------------------------------------------------------------------

// LoadCatalog 解析内置清单并在失败时返回错误（启动期即失败，不带着
// 坏清单运行——坏清单意味着命令组装会引用到不存在的包名）。
func LoadCatalog() (*Catalog, error) {
	return parseCatalog(catalogJSON)
}

// parseCatalog 解析并全量校验清单。
//
// 校验在加载期做而不是在使用期做：清单是内置数据，它的错误
// 属于构建缺陷，应当在启动/测试阶段全量暴露，而不是等某个
// 用户恰好点了那个软件时才炸出来。
func parseCatalog(data []byte) (*Catalog, error) {
	var parsed struct {
		Software []Software `json:"software"`
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("store: 解析软件清单失败: %w", err)
	}
	c := &Catalog{
		Software: parsed.Software,
		byID:     make(map[string]*Software, len(parsed.Software)),
	}
	for i := range c.Software {
		s := &c.Software[i]
		if err := validateSoftware(*s); err != nil {
			return nil, fmt.Errorf("store: 软件条目 %q 非法: %w", s.ID, err)
		}
		if _, dup := c.byID[s.ID]; dup {
			return nil, fmt.Errorf("store: 软件清单存在重复 ID: %q", s.ID)
		}
		c.byID[s.ID] = s
	}
	// 依赖引用的 ID 必须存在于清单里（悬空依赖会让安装前置步骤失败）。
	for _, s := range c.Software {
		for _, dep := range s.Depends {
			if _, ok := c.byID[dep]; !ok {
				return nil, fmt.Errorf("store: 软件 %q 的依赖 %q 不在清单中", s.ID, dep)
			}
			if dep == s.ID {
				return nil, fmt.Errorf("store: 软件 %q 依赖自身", s.ID)
			}
		}
	}
	return c, nil
}

// validateSoftware 校验单个软件条目。
func validateSoftware(s Software) error {
	if err := ValidSoftwareID(s.ID); err != nil {
		return err
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name 不能为空")
	}
	if len(s.Versions) == 0 {
		return fmt.Errorf("versions 不能为空")
	}
	seen := map[string]bool{}
	for _, v := range s.Versions {
		if err := ValidVersionID(v.ID); err != nil {
			return fmt.Errorf("版本 %q: %w", v.ID, err)
		}
		if seen[v.ID] {
			return fmt.Errorf("版本 %q 重复", v.ID)
		}
		seen[v.ID] = true
		for _, p := range append(append([]string{}, v.SystemPackages...), v.AlternativePackages...) {
			if err := ValidPackageNameItem(p); err != nil {
				return fmt.Errorf("版本 %q 的包名: %w", v.ID, err)
			}
		}
		if v.Prebuilt != nil {
			if v.Prebuilt.Kind != PrebuiltTarGz {
				return fmt.Errorf("版本 %q 的预编译类型未知: %q", v.ID, v.Prebuilt.Kind)
			}
			if len(v.Prebuilt.Binaries) == 0 {
				return fmt.Errorf("版本 %q 的预编译未声明 binaries（装完无法使用）", v.ID)
			}
			// 两种取 URL 的方式必须**恰好**选一种。
			switch {
			case v.Prebuilt.URLTemplate != "" && v.Prebuilt.IndexURLTemplate != "":
				return fmt.Errorf("版本 %q 的预编译同时给了 url_template 与 index_url_template", v.ID)
			case v.Prebuilt.URLTemplate == "" && v.Prebuilt.IndexURLTemplate == "":
				return fmt.Errorf("版本 %q 的预编译缺少 url_template 或 index_url_template", v.ID)
			case v.Prebuilt.IndexURLTemplate != "":
				if err := validHTTPSURLTemplate(v.Prebuilt.IndexURLTemplate); err != nil {
					return fmt.Errorf("版本 %q 的预编译索引 URL: %w", v.ID, err)
				}
				if v.Prebuilt.FilePrefix == "" || v.Prebuilt.FileSuffix == "" {
					return fmt.Errorf("版本 %q 的预编译索引方式缺少 file_prefix/file_suffix", v.ID)
				}
				if !strings.Contains(v.Prebuilt.FileSuffix, "{arch}") {
					return fmt.Errorf("版本 %q 的 file_suffix 缺少 {arch} 占位符", v.ID)
				}
			default:
				if err := validHTTPSURLTemplate(v.Prebuilt.URLTemplate); err != nil {
					return fmt.Errorf("版本 %q 的预编译 URL: %w", v.ID, err)
				}
				if !strings.Contains(v.Prebuilt.URLTemplate, "{arch}") {
					return fmt.Errorf("版本 %q 的预编译 URL 缺少 {arch} 占位符", v.ID)
				}
			}
			if err := validFixedPath(v.Prebuilt.InstallDir); err != nil {
				return fmt.Errorf("版本 %q 的预编译目录: %w", v.ID, err)
			}
			if err := validFixedPath(v.Prebuilt.LinkDir); err != nil {
				return fmt.Errorf("版本 %q 的软链接目录: %w", v.ID, err)
			}
			for _, b := range v.Prebuilt.Binaries {
				if err := ValidBinaryName(b); err != nil {
					return fmt.Errorf("版本 %q 的可执行文件名: %w", v.ID, err)
				}
			}
			for _, a := range v.Prebuilt.VerifyArgs {
				if err := ValidVerifyArg(a); err != nil {
					return fmt.Errorf("版本 %q 的验证参数: %w", v.ID, err)
				}
			}
		}
	}
	if !seen[s.DefaultVersion] {
		return fmt.Errorf("默认版本 %q 不在 versions 中", s.DefaultVersion)
	}
	for family, official := range s.Official {
		if family != FamilyDebian && family != FamilyRHEL {
			return fmt.Errorf("official 的家族键 %q 未知（只支持 %s / %s）",
				family, FamilyDebian, FamilyRHEL)
		}
		if err := official.Validate(); err != nil {
			return fmt.Errorf("official[%s]: %w", family, err)
		}
	}
	return nil
}

// validHTTPSURL 校验必须是 https:// 开头、字符集安全的 URL。
//
// https 是硬性要求：我们要下载的是**软件包与 GPG key**，
// http 下载等于把供应链完整性交给路径上的任何人。
func validHTTPSURL(u string) error {
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("URL 必须是 https: %q", u)
	}
	if !urlPattern.MatchString(u) {
		return fmt.Errorf("URL 含非法字符: %q", u)
	}
	// 拒绝 `..` 路径段（判据是 path segment，不是子串：
	// `node..x.tar.gz` 这类合法文件名不会被误杀）。
	//
	// ########## 为什么 URL 里也要管这个 ##########
	//
	// 清单里的 URL 决定"从哪下载要装进系统的文件"。带 `..` 的路径
	// 经过服务器或中间代理的规范化后，可能落到与书写意图完全不同的
	// 资源上——这是"看似从官方站下载、实际拿到别的文件"的经典入口。
	// 内置清单不该出现这种形态，出现即是编辑错误。
	for _, seg := range strings.Split(u, "/") {
		if seg == ".." {
			return fmt.Errorf("URL 含 .. 路径段: %q", u)
		}
		// 百分号编码的 `..`（`%2e%2e`）同样要拒：
		// 字符集校验放行了 `%`（URL 编码本身合法），
		// 但**解码后**的 `..` 在服务端会被当作上级目录。
		// 只针对点号做解码，不做完整 URL 解码——完整解码会把
		// `%2f` 也变成 `/`，从而引入新的路径语义。
		if strings.Contains(strings.ToLower(seg), "%2e") || strings.Contains(strings.ToLower(seg), "%2f") {
			decoded := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
			decoded = strings.ReplaceAll(decoded, "%2f", "/")
			if decoded == ".." || strings.HasPrefix(decoded, "../") ||
				strings.Contains(decoded, "/../") || strings.HasSuffix(decoded, "/..") {
				return fmt.Errorf("URL 含编码后的上级目录段: %q", u)
			}
		}
	}
	return nil
}

// validFixedPath 校验清单里的固定路径（keyring/list 文件/解包目录）。
func validFixedPath(p string) error {
	if !fixedPathPattern.MatchString(p) {
		return fmt.Errorf("固定路径非法: %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("固定路径含 .. 段: %q", p)
		}
	}
	return nil
}

// validFixedName 校验 sources.list.d 下的固定文件名。
func validFixedName(n string) error {
	if !fixedNamePattern.MatchString(n) {
		return fmt.Errorf("固定文件名非法: %q", n)
	}
	return nil
}

// validSourceLine 校验源条目模板的字符集（不含换行与 shell 元字符）。
// 模板在运行期只有 `{codename}` 一个插值点，插值前另行校验代号。
func validSourceLine(t string) error {
	if !sourceLinePattern.MatchString(t) {
		return fmt.Errorf("源条目模板含非法字符: %q", t)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

// Get 按 ID 返回软件条目。
func (c *Catalog) Get(id string) (Software, bool) {
	if c == nil {
		return Software{}, false
	}
	s, ok := c.byID[id]
	if !ok {
		return Software{}, false
	}
	return *s, true
}

// FindVersion 返回软件的具体版本。
func (c *Catalog) FindVersion(id, versionID string) (Software, Version, bool) {
	s, ok := c.Get(id)
	if !ok {
		return Software{}, Version{}, false
	}
	for _, v := range s.Versions {
		if v.ID == versionID {
			return s, v, true
		}
	}
	return Software{}, Version{}, false
}

// DependencyOrder 返回安装 id 之前需要先装好的依赖 ID（拓扑序）。
//
// 只做一层展平 + 去重 + 拓扑排序；清单里的依赖图很小（个位数节点），
// 不需要更重的算法。检出环时报错——环会让安装永远等待前一个完成。
func (c *Catalog) DependencyOrder(id string) ([]string, error) {
	if _, ok := c.Get(id); !ok {
		return nil, fmt.Errorf("store: 软件 %q 不在清单中", id)
	}
	// DFS 后序即拓扑序（依赖先于依赖者）。
	var (
		out      []string
		seen     = map[string]int{} // 0 未访问 1 访问中 2 完成
		visit    func(string) error
		errCycle error
	)
	visit = func(cur string) error {
		switch seen[cur] {
		case 1:
			errCycle = fmt.Errorf("store: 依赖存在环（涉及 %q）", cur)
			return errCycle
		case 2:
			return nil
		}
		seen[cur] = 1
		s, _ := c.Get(cur)
		for _, dep := range s.Depends {
			if err := visit(dep); err != nil {
				return err
			}
		}
		seen[cur] = 2
		out = append(out, cur)
		return nil
	}
	if err := visit(id); err != nil {
		return nil, err
	}
	// out 含 id 自身且依赖在前；调用方只需要依赖部分。
	if len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out, nil
}

// SortVersionsDesc 返回按语义版本降序排列的版本 ID（新的在前）。
// 前端下拉框的稳定顺序，避免依赖清单里的书写顺序。
func SortVersionsDesc(versions []Version) []string {
	ids := make([]string, 0, len(versions))
	for _, v := range versions {
		ids = append(ids, v.ID)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		return compareVersionIDs(ids[i], ids[j]) > 0
	})
	return ids
}

// compareVersionIDs 按数字段逐段比较版本字符串。
//
// "8.4" > "8.3" > "8.10"?? ——不对，逐段数字比较保证 8.10 > 8.4。
// 简单 split-by-dot 数字比较对本清单的版本格式（"8.3"、"22"、"3.3"）
// 已经足够；非数字段（如 "3.0z"）按字符串兜底比较，保持稳定。
func compareVersionIDs(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi string
		if i < len(as) {
			ai = as[i]
		}
		if i < len(bs) {
			bi = bs[i]
		}
		an, aNum := allDigits(ai)
		bn, bNum := allDigits(bi)
		if aNum && bNum {
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
			continue
		}
		if ai != bi {
			return strings.Compare(ai, bi)
		}
	}
	return 0
}

// allDigits 判断字符串是否全为数字并返回其整数值。
func allDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	return n, true
}

// ---------------------------------------------------------------------------
// 清单自检（供启动日志与 capabilities 使用）
// ---------------------------------------------------------------------------

// Summary 返回清单概要（启动日志用）。
func (c *Catalog) Summary() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Software))
	for _, s := range c.Software {
		out = append(out, fmt.Sprintf("%s(%d 版本)", s.ID, len(s.Versions)))
	}
	return out
}

// 清单解析的并发安全：Catalog 构造完成后**只读**，
// 因此无需任何锁——这也是把校验全部前置到解析期的另一个收益。
var catalogOnce struct {
	sync.Once
	cat *Catalog
	err error
}

// MustCatalog 返回进程级唯一清单实例（解析失败直接 panic）。
//
// 用 panic 而不是把 error 一路传给 main：清单是编译进二进制的内置数据，
// 解析失败等价于构建产物损坏，任何调用点都不具备"降级继续"的可能。
// 常规启动路径应先用 LoadCatalog 显式处理错误（main.go 就是这么做的），
// 本函数只服务于测试与不可能失败的展示路径。
func MustCatalog() *Catalog {
	catalogOnce.Do(func() {
		catalogOnce.cat, catalogOnce.err = LoadCatalog()
	})
	if catalogOnce.err != nil {
		panic(catalogOnce.err)
	}
	return catalogOnce.cat
}
