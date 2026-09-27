package store

import (
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// 命令组装（纯函数，可穷举测试）
// ============================================================================
//
// 与 4.1 systemctl、4.3 nginx、4.4 certbot 完全一致的纪律：
//
//	**argv 切片，绝不拼 shell 字符串。**
//
// 本文件的函数不执行任何命令、不碰文件系统，只回答
// "给定这些输入，应该执行哪个程序、argv 是什么"。
// 因此它们可以被单测穷举——计划要求的
// 「命令组装测试」与「apt/yum 适配测试」的落点就在这里。
//
// #################### 唯一的例外：官方安装脚本 ####################
//
// NodeSource 只提供 `curl -fsSL https://deb.nodesource.com/setup_22.x | bash -`
// 这一种接入方式（没有可直接下载的 .list 文件）。因此本模块**存在**
// 一处经由 `sh` 的执行，它被显式建模为一个独立字段（ScriptPipeline）
// 而不是混在 argv 里，好让"哪些命令是 argv 直跑、哪些经由 sh"
// 在类型与测试上都是显式的：
//
//	ScriptPipeline.Cmd 只由**内置清单**里的常量拼成，
//	插值只有两个白名单校验过的占位符（{distro} / {version}），
//	用户输入永远到不了这里（用户只能选软件 ID 与版本 ID，
//	两者先查清单，值来自清单）。
//
// 这条例外的存在被记录在 capabilities 的 notes 里，
// 并在前端确认弹窗中如实告知用户。

// Command 是一条待执行的命令（argv 形态）。
type Command struct {
	// Name 是可执行文件路径。
	Name string
	// Args 是参数切片（不含 Name）。
	Args []string
	// Label 是人类可读的用途（日志与审计展示，不参与执行）。
	Label string
	// Redacted 是可用于展示的命令文本（已按需引号包裹）。
	Redacted string
}

// String 返回可用于日志的命令文本。
func (c Command) String() string { return c.Redacted }

// ScriptPipeline 是一条"经由 sh 执行"的管道命令。
//
// 它是本模块唯一的 shell 形态执行，字段设计刻意收得很死：
// Cmd 是**完整的命令行文本**，由内置常量拼成，不经任何用户输入。
type ScriptPipeline struct {
	// Cmd 是交给 `sh -c` 的命令行文本。
	Cmd string
	// Label 见 Command.Label。
	Label string
	// Redacted 见 Command.Redacted。
	Redacted string
}

// String 返回可用于日志的命令文本。
func (s ScriptPipeline) String() string { return s.Redacted }

// Step 是一条待执行命令的联合类型：要么是 argv 命令，要么是脚本管道。
//
// 用联合类型而不是"给 Command 加一个 Shell 布尔"：
// 布尔标志位很容易在某个调用点被漏判，而联合类型让
// "这条命令走不走 shell"在**编译期**就必须被显式选择一次。
type Step struct {
	// Command 非 nil 时按 argv 执行。
	Command *Command
	// Script 非 nil 时经 `sh -c` 执行。
	Script *ScriptPipeline
	// IgnoreFailure 为 true 时该命令失败不中断步骤。
	//
	// 用途：`apt-get update` 这类"失败也可继续"的命令
	// （某个无关的第三方源 404 会让 update 非零退出，
	// 但我们真正要装的包可能已经在缓存里）。
	IgnoreFailure bool
}

// Label 返回该命令的用途。
func (s Step) Label() string {
	switch {
	case s.Command != nil:
		return s.Command.Label
	case s.Script != nil:
		return s.Script.Label
	}
	return ""
}

// Redacted 返回可用于展示的完整命令文本。
func (s Step) Redacted() string {
	switch {
	case s.Command != nil:
		return s.Command.Redacted
	case s.Script != nil:
		return s.Script.Redacted
	}
	return ""
}

// ---------------------------------------------------------------------------
// 命令构造 helper
// ---------------------------------------------------------------------------

// newCommand 构造一条 argv 命令并生成展示文本。
func newCommand(name string, args []string, label string) Command {
	return Command{
		Name:     name,
		Args:     args,
		Label:    label,
		Redacted: RenderCommand(name, args),
	}
}

// RenderCommand 把命令渲染成可安全展示的字符串。
//
// 拼接规则与 4.4 的 RedactCommand 一致：含空格或特殊字符的参数
// 加单引号，让用户可以直接复制到终端复现。
func RenderCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(name))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// quoteArg 在必要时给参数加引号。
func quoteArg(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n'\"\\$`;|&<>(){}[]*?!#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// ---------------------------------------------------------------------------
// apt 系命令
// ---------------------------------------------------------------------------

// AptOptions 是构造 apt 命令的输入。
type AptOptions struct {
	// ManagerPath 是 apt-get 的绝对路径。
	ManagerPath string
}

// aptInstallArgs 组装安装参数。
//
// 逐项说明：
//
//	install -y           非交互确认（面板是无终端的后台进程，
//	                     不加 -y 会挂到超时）
//	--no-install-recommends
//	                     不装推荐包。对面板场景是刻意的取舍：
//	                     推荐包会把一个 PHP 安装从几十 MB 拉到几百 MB，
//	                     而面板用户要的是"能跑起来的最小环境"。
//	                     代价是某些可选扩展缺失，已在清单 notes 里说明。
//	-o Dpkg::Options::=--force-confdef / --force-confold
//	                     配置文件冲突时的默认动作：**保留现有配置**。
//	                     这一条对本模块特别重要——面板自己管理的
//	                     nginx 站点配置在 sites-available 下，
//	                     但包的 conffile 冲突若走了交互询问，
//	                     非交互模式下 dpkg 会直接失败。
//	                     选择 confold（保留旧配置）而不是 confnew：
//	                     用户机器上的现有配置优先级高于包里的新默认值。
func aptInstallArgs(pkgs []string) []string {
	args := []string{
		"install",
		"-y",
		"--no-install-recommends",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
	}
	return append(args, pkgs...)
}

// ValidInstallItems 校验"安装用的包条目"。
//
// 安装条目比卸载条目多一种形态：钉住版本的 `pkg=version`
// （见 Version.PinSystemVersion）。卸载永远不带版本约束，
// 因此两者共用同一个校验器是错的——那会让卸载也能带上 `=版本`，
// 而 `apt-get remove nginx=1.26` 会把"卸载"变成"卸载失败"。
func ValidInstallItems(items []string) error {
	for _, item := range items {
		// 含 = 的按"钉版本"校验；不含的走普通包名校验。
		// 由**结构**决定走哪条规则，而不是看调用方怎么说。
		if strings.Contains(item, "=") {
			if err := ValidPinnedPackage(item); err != nil {
				return err
			}
			continue
		}
		if err := ValidPackageNameItem(item); err != nil {
			return err
		}
	}
	return nil
}

// BuildAptInstall 组装 apt 安装命令。
func BuildAptInstall(aptPath string, pkgs []string) (Command, error) {
	if err := ValidInstallItems(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	if aptPath == "" {
		return Command{}, errors.New("store: apt-get 路径为空")
	}
	// `--` 分隔符在这里**刻意不用**：apt-get 并不定义该分隔符
	// （4.1 的 systemctl 定义），加了反而会被当作待安装的包名。
	// 由于包名已过白名单（小写字母数字与 + . _ -，且不以 - 开头），
	// 不存在被解析成选项的可能。
	return newCommand(aptPath, aptInstallArgs(pkgs), "apt 安装 "+strings.Join(pkgs, " ")), nil
}

// BuildAptRemove 组装 apt 卸载命令。
//
// 用 remove 而不是 purge：purge 会一并删除**配置文件**。
// 用户点"卸载 PHP"时的预期是"这个软件不要了"，
// 而不是"顺便帮我清掉所有配置"——尤其当配置里还有
// 手工调过的 php.ini。真要清干净，apt purge 是用户自己的事。
func BuildAptRemove(aptPath string, pkgs []string) (Command, error) {
	if err := ValidPackageList(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	if aptPath == "" {
		return Command{}, errors.New("store: apt-get 路径为空")
	}
	args := append([]string{"remove", "-y", "--no-install-recommends"}, pkgs...)
	return newCommand(aptPath, args, "apt 卸载 "+strings.Join(pkgs, " ")), nil
}

// BuildAptUpdate 组装 apt 索引刷新命令。
func BuildAptUpdate(aptPath string) Command {
	return newCommand(aptPath, []string{"update", "-y"}, "刷新 apt 索引")
}

// BuildAptAutoRemove 组装自动清理命令（卸载后的孤儿依赖）。
func BuildAptAutoRemove(aptPath string) Command {
	return newCommand(aptPath, []string{"autoremove", "-y"}, "清理孤儿依赖")
}

// BuildAptCandidate 组装"查询候选版本"命令。
//
// 为什么用 apt-cache policy 而不是 `apt-cache madison`：
// policy 的信息更全（候选版本 + 各来源的优先级），
// 且输出格式在 Debian/Ubuntu 上多年未变，解析风险最低。
func BuildAptCandidate(aptCachePath, pkg string) (Command, error) {
	if err := ValidPackageNameItem(pkg); err != nil {
		return Command{}, err
	}
	return newCommand(aptCachePath, []string{"policy", pkg}, "查询 "+pkg+" 的候选版本"), nil
}

// BuildDpkgQuery 组装已安装版本查询命令。
//
// 格式串用 ${db:Status-Abbrev} 判断"是否真的装好了"：
// 只查 ${Version} 会把"配置未完成（iF）"或"已卸载但残留配置（rc）"
// 的包也算成已安装，从而让面板显示"已安装"而用户实际用不了。
func BuildDpkgQuery(dpkgQueryPath string, pkgs []string) (Command, error) {
	if err := ValidPackageList(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	args := []string{"-W", "-f", "${Package}|${Version}|${db:Status-Abbrev}\\n"}
	args = append(args, pkgs...)
	return newCommand(dpkgQueryPath, args, "查询已安装版本"), nil
}

// ---------------------------------------------------------------------------
// rpm 系命令（dnf / yum）
// ---------------------------------------------------------------------------

// BuildRPMInstall 组装 dnf/yum 安装命令。
//
// --setopt=install_weak_deps=False 对应 apt 的 --no-install-recommends：
// 不装弱依赖，动机相同（面板要的是最小可用环境）。
func BuildRPMInstall(managerPath string, pkgs []string) (Command, error) {
	if err := ValidInstallItems(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	if managerPath == "" {
		return Command{}, errors.New("store: 包管理器路径为空")
	}
	args := append([]string{"-y", "--setopt=install_weak_deps=False", "install"}, pkgs...)
	return newCommand(managerPath, args, "rpm 安装 "+strings.Join(pkgs, " ")), nil
}

// BuildRPMRemove 组装 dnf/yum 卸载命令。
func BuildRPMRemove(managerPath string, pkgs []string) (Command, error) {
	if err := ValidPackageList(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	if managerPath == "" {
		return Command{}, errors.New("store: 包管理器路径为空")
	}
	args := append([]string{"-y", "remove"}, pkgs...)
	return newCommand(managerPath, args, "rpm 卸载 "+strings.Join(pkgs, " ")), nil
}

// BuildRPMRefresh 组装元数据刷新命令。
func BuildRPMRefresh(managerPath string) Command {
	return newCommand(managerPath, []string{"-y", "makecache"}, "刷新 rpm 元数据")
}

// BuildRPMAvailable 组装"查询可安装版本"命令。
//
// `--showduplicates` 必须加：不加时 dnf 只列最新版本，
// 而我们要确认的是"这个**指定版本**在源里有没有"。
func BuildRPMAvailable(managerPath, pkg string) (Command, error) {
	if err := ValidPackageNameItem(pkg); err != nil {
		return Command{}, err
	}
	return newCommand(managerPath,
		[]string{"--showduplicates", "list", "available", pkg},
		"查询 "+pkg+" 的可用版本"), nil
}

// BuildRPMQuery 组装已安装版本查询命令。
func BuildRPMQuery(rpmPath string, pkgs []string) (Command, error) {
	if err := ValidPackageList(pkgs); err != nil {
		return Command{}, err
	}
	if len(pkgs) == 0 {
		return Command{}, fmt.Errorf("%w: 包列表为空", ErrInvalidPackageName)
	}
	args := []string{"-q", "--qf", "%{NAME}|%{VERSION}\\n"}
	args = append(args, pkgs...)
	return newCommand(rpmPath, args, "查询已安装版本"), nil
}

// BuildRPMInstallLocal 组装"安装仓库发布包"命令（dnf install <url>）。
//
// 用途：RHEL 系接入 NodeSource / MySQL / remi 官方源的标准做法是
// 安装它们提供的 release rpm。URL 来自内置清单并经 https 白名单校验。
func BuildRPMInstallLocal(managerPath, repoURL string) (Command, error) {
	if err := validHTTPSURL(repoURL); err != nil {
		return Command{}, err
	}
	return newCommand(managerPath, []string{"-y", "install", repoURL},
		"安装官方源发布包"), nil
}

// BuildRPMImportKey 组装"导入 GPG 公钥"命令（rpm --import <file>）。
//
// 与 apt 的 [signed-by=] 等价：公钥先落盘（BuildCurlKeyDownload），
// 再由包管理器导入。分两步而不是 `rpm --import <url>`：
// 落盘后可以核对文件内容，也让"导入失败"与"下载失败"是两种可区分的错误。
func BuildRPMImportKey(rpmPath, keyPath string) (Command, error) {
	if err := validFixedPath(keyPath); err != nil {
		return Command{}, err
	}
	return newCommand(rpmPath, []string{"--import", keyPath}, "导入官方源 GPG 公钥"), nil
}

// PickIndexedFile 从索引文件内容里挑出匹配前后缀的文件名。
//
// ########## 为什么需要它 ##########
//
// Node.js 的官方归档名带**补丁号**（node-v22.14.0-linux-x64.tar.gz），
// 而面板只知道主版本（22）。把补丁号写死进清单会让清单每几周就失效；
// 正确做法是读官方索引（SHASUMS256.txt 之类），按前后缀匹配出
// 当前真实文件名。
//
// 索引行的形态是 `<sha256>  <文件名>`，因此只取**最后一列**作为
// 候选文件名（下载 URL 里不能出现校验和）。
//
// 返回空字符串表示没匹配到（调用方据此给出可读的失败原因，
// 而不是拼一个必然 404 的 URL 出去）。
func PickIndexedFile(index, prefix, suffix string) string {
	best := ""
	for _, raw := range strings.Split(index, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 2 {
			continue
		}
		// 兼容 `sha  file` 与 `sha *file`（二进制模式标记）两种写法。
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		// 只接受裸文件名：索引里若出现路径，说明格式变了，
		// 此时宁可匹配失败也不要拼出带子目录的 URL。
		if strings.ContainsAny(name, "/\\") {
			continue
		}
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		// 取版本最大的那个（索引里通常只有一个匹配，但多版本共存时
		// "最大的那个"才是 latest 的语义）。
		if best == "" || compareVersionIDs(extractVersion(name, prefix, suffix), extractVersion(best, prefix, suffix)) > 0 {
			best = name
		}
	}
	return best
}

// extractVersion 从文件名里抠出前后缀之间的部分（用于比较大小）。
func extractVersion(name, prefix, suffix string) string {
	s := strings.TrimPrefix(name, prefix)
	s = strings.TrimSuffix(s, suffix)
	// node-v22.14.0-linux-x64.tar.gz 的前缀是 "node-v"，
	// 抠出来的是 "22.14.0"，正好是版本号。
	return s
}

// JoinURLFile 把索引 URL 的目录与文件名拼成下载地址。
//
// 只做字符串拼接而不引入 net/url：索引 URL 与文件名都已过字符集校验，
// 拼接结果还会再走一次 validHTTPSURL。
func JoinURLFile(indexURL, file string) (string, error) {
	if err := ValidArchiveName(file); err != nil {
		return "", fmt.Errorf("索引中的文件名非法: %w", err)
	}
	idx := strings.LastIndexByte(indexURL, '/')
	if idx <= len("https://") {
		return "", fmt.Errorf("store: 索引 URL 形态异常: %q", indexURL)
	}
	out := indexURL[:idx+1] + file
	if err := validHTTPSURL(out); err != nil {
		return "", err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// 下载与解包（预编译兜底）
// ---------------------------------------------------------------------------

// BuildDownload 组装下载命令。
//
// 参数说明：
//
//	-fail   HTTP 错误码直接失败（否则会把 404 页面存成"压缩包"，
//	        直到解包时才报一个看不懂的错误）
//	--retry 网络抖动重试；大文件下载中断后重来一次的代价可接受
//	-- 结束选项，后面一定是 URL 与输出路径两个位置参数
//
// 输出路径由**我们**指定为固定目录下的固定名，未取自清单里的
// URL 内容，因此不存在"服务端 Content-Disposition 改写落点"的问题。
func BuildDownload(curlPath, url, dest string) (Command, error) {
	if err := validHTTPSURL(url); err != nil {
		return Command{}, err
	}
	if err := validFixedPath(dest); err != nil {
		return Command{}, err
	}
	args := []string{"-fsSL", "--retry", "2", "--connect-timeout", "15", "-o", dest, "--", url}
	return newCommand(curlPath, args, "下载预编译包"), nil
}

// BuildExtract 组装解包命令。
//
// dest 一定是内置清单里的固定目录（validFixedPath 校验过），
// tar 的 `-C` 因此不可能指向用户可控的位置。
//
// ########## 为什么要 --strip-components=1 ##########
//
// 官方 tarball 都带**单一顶层目录**（node-v22.14.0-linux-x64/），
// 不解掉这一层的话，二进制会落在
// `<InstallDir>/node-v22.14.0-linux-x64/bin/node`，
// 而清单与验证命令找的是 `<InstallDir>/bin/node` —— 结果是
// "解压成功、验证失败"，而用户看到的是一个说不清的失败。
//
// 这也构成对清单的一条约定：**预编译归档必须只有一个顶层目录**。
// 清单里收录的产物（nodejs.org 官方 tarball）满足这个约定。
func BuildExtract(tarPath, archive, dest string) (Command, error) {
	if err := validFixedPath(archive); err != nil {
		return Command{}, err
	}
	if err := validFixedPath(dest); err != nil {
		return Command{}, err
	}
	return newCommand(tarPath,
		[]string{"-xzf", archive, "-C", dest, "--strip-components=1"},
		"解压预编译包"), nil
}

// BuildVerifyBinary 组装"验证解包结果"命令。
func BuildVerifyBinary(binPath string, args ...string) (Command, error) {
	if err := validFixedPath(binPath); err != nil {
		return Command{}, err
	}
	return newCommand(binPath, args, "验证预编译二进制"), nil
}

// ---------------------------------------------------------------------------
// 官方源接入
// ---------------------------------------------------------------------------

// RenderSourceTemplate 渲染模板里的占位符。
//
// 占位符只有三个，且都在渲染**之前**经过白名单校验：
//
//	{version} —— 版本 ID（数字与点，来自清单且经用户选择）
//	{distro}  —— 发行版代号（来自 os-release 解析）
//	{arch}    —— 架构标识（x64 / arm64 / armv7l，运行期探测）
//
// 渲染后还会再断言一次"结果里不再含 { 或 }"：占位符写错名
// （例如 {distro} 写成 {disro}）会让残留的花括号被写进
// sources.list 或下载 URL，apt 会报一句难以理解的解析错误。
// 这里提前失败并说清是哪个模板写错了。
func RenderSourceTemplate(tmpl, version, distro, arch string) (string, error) {
	if version != "" {
		if err := ValidVersionID(version); err != nil {
			return "", err
		}
	}
	if distro != "" {
		if err := ValidCodename(distro); err != nil {
			return "", err
		}
	}
	if arch != "" {
		if err := ValidToken(arch); err != nil {
			return "", err
		}
	}
	out := strings.ReplaceAll(tmpl, "{version}", version)
	out = strings.ReplaceAll(out, "{distro}", distro)
	out = strings.ReplaceAll(out, "{arch}", arch)
	if strings.ContainsAny(out, "{}") {
		return "", fmt.Errorf("store: 模板渲染后仍残留占位符: %q", tmpl)
	}
	return out, nil
}

// BuildAptSourceLine 渲染 apt 源条目文本（写入 .list 文件的内容）。
func BuildAptSourceLine(o OfficialSource, version, distro string) (string, error) {
	line, err := RenderSourceTemplate(o.SourceLineTemplate, version, distro, "")
	if err != nil {
		return "", err
	}
	// 渲染后再校验一次字符集：`{version}` 的取值已被校验，
	// 但"模板 + 取值"的组合结果才是真正落盘的东西。
	if err := validSourceLine(line); err != nil {
		return "", err
	}
	return line, nil
}

// BuildCurlKeyDownload 组装 GPG 公钥下载命令。
//
// `-o` 的目标是清单里的固定路径（validFixedPath 校验过）。
// 刻意**不**走 apt-key（已废弃且会把 key 混进全局 keyring，
// 无法定点轮换），也**不**用 `curl | gpg` 管道：
// 先落盘再让 apt 通过 [signed-by=] 引用，链路每一步都可检查。
func BuildCurlKeyDownload(curlPath, keyURL, keyPath string) (Command, error) {
	if err := validHTTPSURL(keyURL); err != nil {
		return Command{}, err
	}
	if err := validFixedPath(keyPath); err != nil {
		return Command{}, err
	}
	args := []string{"-fsSL", "--retry", "2", "--connect-timeout", "15", "-o", keyPath, "--", keyURL}
	return newCommand(curlPath, args, "下载官方源 GPG 公钥"), nil
}

// BuildOfficialScript 组装官方安装脚本的执行步骤。
//
// ########## 本模块唯一的 shell 形态执行 ##########
//
// 形状固定为：`curl -fsSL --retry 2 --connect-timeout 15 -- '<url>' | sh`
//
// 两个组成部分都不是用户输入：
//   - URL 来自内置清单，经 validHTTPSURL 校验（字符集里不含单引号、
//     空格、`$`、反引号，因此单引号包裹后不可能逃逸）；
//   - 管道右侧固定为 `sh`，不可由清单指定（清单只能给 URL 与参数）。
//
// 为什么不"下载到文件再执行"：NodeSource 的脚本本身会写
// sources.list 并调用 apt-key/gpg，行为与官方文档一致才最可预测；
// 多一步落盘只是把同样的信任从管道换成文件，安全性没有实质变化，
// 却容易与官方文档产生行为差异。
func BuildOfficialScript(curlPath, scriptURL string) (ScriptPipeline, error) {
	if err := validHTTPSURL(scriptURL); err != nil {
		return ScriptPipeline{}, err
	}
	// curl 路径我们也做一次白名单（它是本机可执行文件路径）。
	if err := validFixedPath(curlPath); err != nil {
		return ScriptPipeline{}, fmt.Errorf("curl 路径: %w", err)
	}
	cmd := fmt.Sprintf("curl -fsSL --retry 2 --connect-timeout 15 -- '%s' | sh", scriptURL)
	return ScriptPipeline{
		Cmd:      cmd,
		Label:    "执行官方安装脚本（追加软件源）",
		Redacted: cmd,
	}, nil
}

// ---------------------------------------------------------------------------
// 版本匹配
// ---------------------------------------------------------------------------

// VersionMatches 判断"已安装/候选的版本串"是否属于目标版本 ID。
//
// ########## 为什么必须有这一步 ##########
//
// 包管理器里的版本串与用户看到的版本 ID 不是一个东西：
//
//	目标 "8.3"  ←→  dpkg 版本 "8.3.13-1+ubuntu22.04.1+deb.sury.org+1"
//	目标 "7.0"  ←→  rpm  版本 "5:7.0.15-1rl1"
//	目标 "22"   ←→  版本 "22.14.0-1nodesource1"
//
// 而系统源自带的旧版本是**同一套包名**：
// Ubuntu 22.04 的 `nodejs` 是 12.22，`redis` 是 6.0——
// 若不做这一步比较，"系统源优先"会安装一个与用户选择
// 完全不符的版本，而面板还会显示"安装成功"。
//
// 匹配规则：
//
//	① 去掉 epoch（`5:`）与 revision（`-1rl1`、`~dfsg`）等后缀噪声；
//	② 目标 ID 的每一个数字段必须与版本串对应段完全相等。
//
// 目标段数与版本串的段数不要求相等（"22" 匹配 "22.14.0"），
// 但**不匹配前缀纠缠**："2" 不会匹配 "22.14.0"（段是 "22" ≠ "2"）。
func VersionMatches(have, want string) bool {
	if have == "" || want == "" {
		return false
	}
	have = strings.TrimSpace(have)
	want = strings.TrimSpace(want)

	// 去掉 epoch：apt 的 "5:7.0.15"、rpm 的 "1:8.0.36"。
	if i := strings.IndexByte(have, ':'); i >= 0 {
		have = have[i+1:]
	}
	// 去掉 revision 与发行版后缀：在 `-`、`~`、`+` 处截断。
	// 这三者都是 Debian/RPM 版本语法里的"本地/修订部分"分隔符。
	if i := strings.IndexAny(have, "-~+"); i >= 0 {
		have = have[:i]
	}

	haveSegs := strings.Split(have, ".")
	wantSegs := strings.Split(want, ".")
	if len(wantSegs) > len(haveSegs) {
		return false
	}
	for i, w := range wantSegs {
		if i >= len(haveSegs) {
			return false
		}
		// 段级比较：数字段按数值比较（"08" == "8"），
		// 非数字段按字面比较（"1a" 这类罕见形态）。
		wn, wNum := allDigits(w)
		hn, hNum := allDigits(haveSegs[i])
		if wNum && hNum {
			if wn != hn {
				return false
			}
			continue
		}
		if !strings.EqualFold(w, haveSegs[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 输出解析（纯函数）
// ---------------------------------------------------------------------------

// ParseAptPolicyCandidate 从 `apt-cache policy <pkg>` 输出里取候选版本。
//
// 典型输出：
//
//	nginx:
//	  Installed: (none)
//	  Candidate: 1.26.2-1~jammy
//	  Version table:
//	     ...
//
// 没有候选版本时 apt 输出 `Candidate: (none)`，返回空字符串。
// 找不到 Candidate 行也返回空字符串（**不猜**）：
// 猜错会让"版本校验"这层保护失效。
func ParseAptPolicyCandidate(out string) string {
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "Candidate:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
		if val == "" || strings.EqualFold(val, "(none)") {
			return ""
		}
		return val
	}
	return ""
}

// ParseDpkgQuery 解析 `dpkg-query -W -f '${Package}|${Version}|${db:Status-Abbrev}\n'` 输出。
//
// 返回 包名 → 已安装版本（只收 `ii` —— 状态已安装且配置完成）。
//
// `dpkg-query` 在某个包不存在时会把错误写到 stderr 并对其余包正常输出，
// 因此调用方必须**先解析 stdout、再看退出码**，不能因为退出码非零
// 就丢弃输出（那会把"装了 3 个包、1 个没装"误判成"什么都没装"）。
func ParseDpkgQuery(out string) map[string]string {
	res := map[string]string{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		status := strings.TrimSpace(parts[2])
		// db:Status-Abbrev 形如 "ii "（第三个字符是空格）或 "ii"。
		// 只看前两位：i = desired install，i = status installed。
		if len(status) < 2 || status[0] != 'i' || status[1] != 'i' {
			continue
		}
		if name == "" || version == "" {
			continue
		}
		res[name] = version
	}
	return res
}

// ParseRPMQuery 解析 `rpm -q --qf '%{NAME}|%{VERSION}\n'` 输出。
//
// 未安装的包会让 rpm 输出 `package X is not installed`（stdout！）
// 并以非零退出，因此这里必须过滤掉非 `name|version` 形态的行。
func ParseRPMQuery(out string) map[string]string {
	res := map[string]string{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, "|") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" || version == "" {
			continue
		}
		res[name] = version
	}
	return res
}

// ParseRPMAvailable 解析 `dnf --showduplicates list available <pkg>` 输出。
//
// 典型输出：
//
//	Available Packages
//	nodejs.x86_64    1:18.20.4-1.el9    nodesource-nodejs
//	nodejs.x86_64    1:20.17.0-1.el9    nodesource-nodejs
//
// 返回版本串列表（未排序，调用方用 VersionMatches 自行筛选）。
func ParseRPMAvailable(out string) []string {
	var versions []string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "Available Packages") ||
			strings.HasPrefix(line, "Installed Packages") ||
			strings.HasPrefix(line, "Last metadata") {
			continue
		}
		fields := strings.Fields(line)
		// 需要至少 3 列：包名.架构、版本、仓库。
		if len(fields) < 3 || !strings.Contains(fields[0], ".") {
			continue
		}
		versions = append(versions, fields[1])
	}
	return versions
}

// ParseAptUpdateFailure 从 apt 输出里提取一行可读的失败原因（失败展示用）。
//
// apt 失败时输出动辄上百行（每个源的 Get/Hit/Ign 各一行），
// 真正的原因通常是 `E:` 开头的行。这里优先取 E: 行，
// 没有则退回首行，避免把整段输出塞进前端的错误提示。
func ParseAptUpdateFailure(out string) string {
	var firstLine string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if firstLine == "" {
			firstLine = line
		}
		if strings.HasPrefix(line, "E:") || strings.HasPrefix(line, "W:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "E:"), "W:"))
		}
	}
	return firstLine
}
