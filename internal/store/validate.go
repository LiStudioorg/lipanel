package store

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ============================================================================
// 输入白名单校验（阶段四 4.5 的安全底线）
// ============================================================================
//
// 计划要求："软件名、版本号严格白名单校验"。
//
// 本模块与 4.1/4.3/4.4 的校验层有一个**结构性的区别**，
// 这个区别决定了这里必须收得更紧：
//
//	4.1 systemctl start <name>   —— name 是用户体系里"已存在的东西"，
//	                                注入载荷最多吃一次 400；
//	4.5 apt install <pkg>        —— 若包名校验被绕过，后果不是"执行了
//	                                一条恶意命令"（argv 保证不会），
//	                                而是"安装了一个攻击者指定的软件包"。
//
// 也就是说：对本模块而言，**包名本身就是一种能力**。
// 因此本模块的输入面被切成两层：
//
//	第一层（用户可控）：软件 ID、版本 ID。
//	  —— 只用来在内置清单里**查表**，永远不直接进命令。
//	第二层（内置常量）：包名、源地址、key URL、脚本 URL、源条目。
//	  —— 全部来自 go:embed 的清单，且解析期全量校验（catalog.go）。
//
// 用户输入与命令之间隔着一次查表。哪怕第一层的校验将来被放宽，
// 攻击者也最多"选到清单里另一个合法版本"，而拼不出任意包名/URL。
//
// 沿用 4.3 的教训：**校验函数只回答能不能用，绝不悄悄改写输入**
// （TrimSpace 后再校验会让 "php\n" 被静默接受）。

// 校验相关的哨兵错误（server 层据此映射 400，并写 denied 审计）。
var (
	// ErrInvalidSoftwareID 表示软件 ID 未通过白名单校验。
	ErrInvalidSoftwareID = errors.New("store: 软件 ID 非法")
	// ErrInvalidVersion 表示版本号未通过白名单校验。
	ErrInvalidVersion = errors.New("store: 版本号非法")
	// ErrInvalidPackageName 表示包名未通过白名单校验。
	ErrInvalidPackageName = errors.New("store: 包名非法")
	// ErrInvalidToken 表示通用安全 token 未通过校验。
	ErrInvalidToken = errors.New("store: 参数含非法字符")
)

// softwareIDPattern 限定软件 ID：小写字母开头，允许数字与 - .。
//
// 刻意比站点名更紧（大写都不收）：ID 同时是清单主键、
// 任务标识与 API 路径分量，字符集越小，跨层约定越难出错。
var softwareIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// ValidSoftwareID 校验软件 ID。
func ValidSoftwareID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: 为空", ErrInvalidSoftwareID)
	}
	if !softwareIDPattern.MatchString(id) {
		return fmt.Errorf("%w: %q 只允许小写字母开头，后接小写字母、数字、. _ -，长度 2~32",
			ErrInvalidSoftwareID, id)
	}
	// `..` 是路径分量的经典逃逸（软件 ID 会作为任务文件名参与展示路径）。
	if strings.Contains(id, "..") {
		return fmt.Errorf("%w: %q 不能含连续的 . ", ErrInvalidSoftwareID, id)
	}
	return nil
}

// versionIDPattern 限定版本 ID：数字与点组成（"8.3"、"22"、"3.10"）。
//
// 为什么不允许字母后缀（如 "8.3rc1"）：本清单里所有版本都是纯数字点分。
// 白名单只能覆盖**清单实际使用的格式**——多放行一个字符类就多一类载荷。
// 将来真要支持 rc 版本，应当先改清单格式约定，再同步放宽这里，
// 而不是反过来为了兼容放宽在先。
var versionIDPattern = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$`)

// ValidVersionID 校验版本号。
func ValidVersionID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: 为空", ErrInvalidVersion)
	}
	if !versionIDPattern.MatchString(v) {
		return fmt.Errorf("%w: %q 只允许数字与点（如 8.3、22、3.10.2）", ErrInvalidVersion, v)
	}
	// 校验"形状"之外的语义：`1..2` 已被正则挡住（段间必须恰好一个点），
	// 但 "0.0.0.0" 这类形状合法、语义荒谬的值挡住没有意义——
	// 版本是否**存在**由清单决定（查不到就报"不支持该版本"），
	// 校验层只负责"这不是注入载荷"。
	return nil
}

// packageNamePattern 限定 apt/yum 包名条目的字符集。
//
// apt 允许的字符集很宽（历史遗留有 `+`、`:` 的包），
// 但本清单用到的生态（php*/mysql-server/nginx/redis/...）全部落在
// `[a-z0-9][a-z0-9+._-]*` 内。**按清单的实际需要收紧**，
// 而不是照抄 apt 的宽容上限——宽容上限里包含会干扰某些
// 工具解析行为的字符。
//
// 注意：包名允许 `.`（php8.3-fpm）但不允许 `/`，
// 于是它天然不可能构成路径。
var packageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,62}$`)

// ValidPackageNameItem 校验单个包名。
func ValidPackageNameItem(p string) error {
	if p == "" {
		return fmt.Errorf("%w: 为空", ErrInvalidPackageName)
	}
	if !packageNamePattern.MatchString(p) {
		return fmt.Errorf("%w: %q 只允许小写字母、数字与 + . _ -，且不能以符号开头",
			ErrInvalidPackageName, p)
	}
	// 拒绝以 - 开头的"选项注入"载荷（如 `--flag`）：
	// 包名永远出现在 `--` 分隔符之后，但纵深防御不因已有防线而省略
	// ——与 4.1 拒绝以 - 开头的服务名同理。
	if strings.HasPrefix(p, "-") {
		return fmt.Errorf("%w: %q 不能以 - 开头（会被当作命令选项）", ErrInvalidPackageName, p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("%w: %q 不能含连续的 . ", ErrInvalidPackageName, p)
	}
	return nil
}

// ValidPackageList 校验包名列表（逗号分隔的清单字段用）。
func ValidPackageList(items []string) error {
	for _, p := range items {
		if err := ValidPackageNameItem(p); err != nil {
			return err
		}
	}
	return nil
}

// pinnedPackagePattern 限定"钉住版本的包名"（`名字=版本`）。
//
// ########## 为什么不能复用 packageNamePattern ##########
//
// 版本号的字符集与包名**不同**：Debian 版本串里 `~`（1.26.2-1~jammy）
// 与 `:`（epoch，1:2.4.57-2）都是合法的，而 rpm 还用 `-` 分段。
// 若把版本硬塞进包名校验，`nginx=1.26.2-1~jammy` 会被拒——
// 于是钉版本这个功能在最重要的场景（官方源）下直接不可用。
//
// 但放宽字符集必须同时收紧结构，否则就是把命令注入的口子
// 从"包名"挪到"版本"。因此这里的规则是：
//
//	① 必须恰好一个 `=`：`名=版本`（多一个 = 就拒）；
//	② 名字部分仍走 packageNamePattern（不含 = 与 ~）；
//	③ 版本部分只允许版本号用得上的字符，且**不允许空格**；
//	④ 两侧都不能为空。
//
// 于是它既不可能构成路径（无 /），也不可能构成选项（不以 - 开头），
// 更不可能用空格拆出第二个参数——而这三点正是全部风险所在。
var pinnedPackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,62}=[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}$`)

// ValidPinnedPackage 校验"钉住版本的包名"（apt 的 `pkg=version`）。
//
// 只在校验**内部生成**的钉版本串时使用：名字来自清单常量，
// 版本号来自 `apt-cache policy` / `dnf list` 的输出。
// 后者是外部命令的输出，因此必须校验而不是信任——
// 一个被污染的源可以让候选版本里带上任意字符。
func ValidPinnedPackage(p string) error {
	if p == "" {
		return fmt.Errorf("%w: 为空", ErrInvalidPackageName)
	}
	if !pinnedPackagePattern.MatchString(p) {
		return fmt.Errorf("%w: %q 不是合法的「包名=版本」形式"+
			"（版本部分只允许字母数字与 + . : ~ _ -，且不能含空格）",
			ErrInvalidPackageName, p)
	}
	return nil
}

// tokenPattern 是"通用安全 token"字符集：字母数字与 . _ - / :。
// 用于清单里的小常量（脚本参数、代号占位以外的固定值）。
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:+-]*$`)

// ValidToken 校验通用安全 token。
func ValidToken(s string) error {
	if s == "" {
		return fmt.Errorf("%w: 为空", ErrInvalidToken)
	}
	if !tokenPattern.MatchString(s) {
		return fmt.Errorf("%w: %q 只允许字母、数字与 . _ / : + -", ErrInvalidToken, s)
	}
	return nil
}

// codenamePattern 限定发行版代号（来自 /etc/os-release，非用户输入，
// 但它会被**写进** sources.list.d 文件与 RPM 仓库 URL，因此同样过白名单）。
//
// 允许数字开头：RHEL 系用的是裸大版本号（"9"、"40"）。
var codenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// ValidCodename 校验发行版代号。
func ValidCodename(c string) error {
	if c == "" {
		return fmt.Errorf("%w: 发行版代号为空", ErrInvalidToken)
	}
	if !codenamePattern.MatchString(c) {
		return fmt.Errorf("%w: 发行版代号 %q 含非法字符", ErrInvalidToken, c)
	}
	return nil
}

// urlPattern 限定 https URL 的字符集（清单加载与运行期共用）。
//
// 刻意比 RFC 3986 允许的更窄：URL 会被传给 curl，也可能被写进
// 展示与审计文本，`$`、反引号、引号、`;` 等字符即使经 argv 执行
// 不构成注入，也会在"复制到终端复现"这类二次消费场景里出问题。
// 本清单用到的 URL（deb.sury.org / nodesource / pkgs.example 等）
// 全部落在收窄字符集内。
var urlPattern = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~%/:@!+,=-]*)*$`)

// fixedPathPattern 限定清单里的固定绝对路径。
var fixedPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// fixedNamePattern 限定 sources.list.d 下的固定文件名。
var fixedNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.list$`)

// binaryNamePattern 限定可执行文件名（预编译包的 binaries 字段）。
//
// 允许大写（有些软件的可执行文件带大写，如 `Node`），
// 但拒绝 `/` 与 `\`（防路径）、拒绝以 `.` 或 `-` 开头
// （`.` 开头在 ls 里是隐藏文件、`-` 开头会被当作命令选项）。
// `..` 这种纯点组合也被下面的显式判断挡住。
var binaryNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]*$`)

// verifyArgPattern 限定验证命令的参数（如 --version、-v、--version --json）。
//
// 与 ValidToken 的区别：**允许以 - 开头**。这里的参数是给
// 我们自己的二进制用的选项，而不是会被包管理器解析的包名——
// 前者本来就该是 --version 这种形态。
var verifyArgPattern = regexp.MustCompile(`^-{0,2}[A-Za-z0-9][A-Za-z0-9._=-]*$`)

// ValidVerifyArg 校验验证命令的参数。
func ValidVerifyArg(a string) error {
	if !verifyArgPattern.MatchString(a) {
		return fmt.Errorf("%w: 验证参数 %q 只允许字母、数字与 . _ = -（可带 1~2 个前导 -）",
			ErrInvalidToken, a)
	}
	return nil
}

// archiveNamePattern 限定归档文件名（索引里挑出来的文件名）。
var archiveNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]*$`)

// ValidArchiveName 校验归档文件名。
//
// 与 ValidBinaryName 同样的字符集，但单独一个函数：
// 两者将来可能分化（归档要允许 `~` 之类的版本符号），
// 共用一个函数会让"放宽归档名"顺手放宽可执行文件名。
func ValidArchiveName(n string) error {
	if !archiveNamePattern.MatchString(n) {
		return fmt.Errorf("%w: 归档文件名 %q 只允许字母、数字与 . _ + -", ErrInvalidToken, n)
	}
	if strings.Contains(n, "..") {
		return fmt.Errorf("%w: 归档文件名 %q 不能含连续的 . ", ErrInvalidToken, n)
	}
	return nil
}

// taskIDPattern 限定任务 ID 形态（t1、t42）。
var taskIDPattern = regexp.MustCompile(`^t[0-9]{1,9}$`)

// ValidTaskID 校验任务 ID。
//
// 任务 ID 会出现在响应回显与日志里，是**用户输入**
// （从 URL 路径拿），因此必须过白名单，不能原样反射回去。
func ValidTaskID(id string) error {
	if !taskIDPattern.MatchString(id) {
		return fmt.Errorf("%w: 任务 ID %q 形态非法（形如 t1）", ErrInvalidInput, id)
	}
	return nil
}

// ValidBinaryName 校验可执行文件名。
func ValidBinaryName(n string) error {
	if !binaryNamePattern.MatchString(n) {
		return fmt.Errorf("%w: 可执行文件名 %q 只允许字母、数字与 . _ + -", ErrInvalidToken, n)
	}
	if strings.Contains(n, "..") {
		return fmt.Errorf("%w: 可执行文件名 %q 不能含连续的 . ", ErrInvalidToken, n)
	}
	return nil
}

// sourceLinePattern 限定 apt 源条目模板的字符集。
//
// apt 的 sources.list 行会由 apt 自己解析（apt-config / apt-get），
// 它的语法里有变量展开（`deb $DIST` 会被 apt 展开），
// 因此模板里绝不允许出现 `$`、反引号、换行。
// 允许 `[signed-by=...]` 所需的方括号与 `{codename}` 占位符的花括号。
var sourceLinePattern = regexp.MustCompile(`^[A-Za-z0-9 \t./:_=+\[\]{}-]*$`)

// repoContentPattern 限定 yum .repo 文件单行的字符集。
//
// 允许 `[` `]`（段名）、`=`（键值）、`/` `.` `:` `-` `_`（URL 与名字）、
// `+` `~`（nginx 版本号里会出现），以及 `{distro}` 的花括号。
// 拒绝 `$`：dnf 的 .repo 支持 `$releasever` 这类变量展开，
// 放行 `$` 就等于把"我们写下的字面文本"变成了"dnf 会解释的配置语言"。
var repoContentPattern = regexp.MustCompile(`^[A-Za-z0-9 \t./:_=+~\[\]{}-]*$`)
