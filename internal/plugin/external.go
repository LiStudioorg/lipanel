package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ============================================================================
// 外部插件：descriptor.json 的解析与校验
// ============================================================================
//
// ########## 为什么元数据是 JSON 文件而不是 Go 代码 ##########
//
// 内置插件的元数据是 Go 代码里的 Descriptor 字面量（见 plugin.go），
// 因为内置插件本来就要编译进主程序。
//
// 而外部插件的**全部意义**就是「不重新编译面板」，
// 因此它不可能用 Go 代码声明元数据——那个文件必须先被编译。
// descriptor.json 是唯一可行的形态：它能在运行期被读取与校验。
//
// ########## 名字沿用 descriptor.json 而不是 manifest.json ##########
//
// 两套命名会让插件作者困惑（"到底该写哪个文件"）。
// 这里统一叫 descriptor.json，字段与 plugin.Descriptor **逐一对齐**，
// 不引入第二套规范：
//
//	descriptor.json 字段         →  Descriptor 字段
//	────────────────────────────────────────────────
//	id                          →  ID
//	name                        →  Name
//	version                     →  Version
//	description                 →  Description
//	mode                        →  Mode
//	permissions                 →  Permissions
//	frontend.entry              →  Frontend.Entry
//	frontend.assets             →  Frontend.Assets
//	frontend.type               →  Frontend.Type
//	frontend.nav_title          →  Frontend.NavTitle
//	frontend.nav_icon           →  Frontend.NavIcon
//
// 外部特有的字段只有三个，且都加了 external_ 前缀或单独的段，
// 让"这是外部插件扩展"一目了然：
//
//	apiVersion                  →  与主程序的兼容性声明（外部插件必需）
//	backend.exec                →  自带可执行文件（可选）
//	frontend.path               →  前端资源在插件目录内的子目录（可选）

// DescriptorFileName 是外部插件元数据文件名。
const DescriptorFileName = "descriptor.json"

// CurrentAPIVersion 是当前主程序支持的插件 API 版本。
//
// ########## 为什么版本兼容按「主版本」判断 ##########
//
// 插件 API 的演进遵循语义化版本：主版本号变化表示**不兼容变更**
// （字段被删、语义被改），次版本号变化表示**向下兼容的新增**
// （加了新字段、新权限域）。
//
// 因此判断规则是「主版本相同即兼容」：
//
//	apiVersion "1"     → 兼容（缺省次版本视为 1.0）
//	apiVersion "1.2"   → 兼容（1.x 都兼容，多余的能力它自己会探测）
//	apiVersion "2"     → **拒绝**（可能用了被删除的字段）
//
// 若要求完全相等，那么主程序每加一个可选字段都会让**全部**已装插件
// 失效——用户会看到一堆"版本不兼容"，而实际上那些插件完全能跑。
const CurrentAPIVersion = "1"

// apiVersionPattern 限定 apiVersion 的形态：主版本号 + 可选次版本号。
var apiVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// externalIDPattern 是外部插件 ID 的合法形态。
//
// ########## 为什么与内置插件的 idPattern 不同 ##########
//
// 内置插件的 idPattern 允许 2~32 位；外部插件的规范是
// `^[a-z][a-z0-9-]{1,62}$`（首位必须是字母，总长 2~63）。
//
// 两者都**只放行小写字母、数字、连字符**，这是相同的安全边界：
// ID 会出现在 URL 路径、socket 文件名与磁盘目录名上，
// 允许 `.` 或 `/` 就等于允许 `../../etc/passwd` 做目录穿越。
//
// 外部插件的规则略严（首字符必须是字母）：它的 ID 同时是
// **它自己目录的名字**，以字母开头可以避免 "0"、"1" 这类
// 看起来像序号、且在排序时容易与其它条目混淆的目录名。
// ########## 末尾的 [a-z0-9] 不是多余的 ##########
//
// 若写成 `^[a-z][a-z0-9-]{1,62}$`，会**允许结尾是连字符**
// （例如 "abc-"）——规范里那 62 位的字符类包含 "-"，而结尾没有额外约束。
//
// 本实现额外要求末位必须是字母或数字。理由是连字符是"连接符"，
// 以它结尾的 ID 几乎总是笔误（"my-plugin" 打成了 "my-plugin-"）。
// 而这类笔误的后果不小：ID 同时是磁盘目录名，改一次要同步
// 目录、descriptor.json 与前端 entry 三处引用。
// 在**加载时**就拒绝，比让用户装好之后才发现对不上要友好得多。
//
// （内置插件的 idPattern 同样不允许首尾是连字符，此处保持一致。）
var externalIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ValidExternalID 判断外部插件 ID 是否合法。
func ValidExternalID(id string) bool { return externalIDPattern.MatchString(id) }

// semverPattern 是语义化版本的正则（允许可选的 v 前缀与预发布/构建元数据）。
//
//	1.0.0        ✅
//	0.1.0        ✅
//	v1.2.3       ✅（容忍 v 前缀：git tag 里很常见）
//	1.0.0-beta.1 ✅
//	1.0          ❌（必须是三段）
//	latest       ❌
var semverPattern = regexp.MustCompile(
	`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ValidSemver 判断是否为合法 semver。
func ValidSemver(v string) bool { return semverPattern.MatchString(strings.TrimSpace(v)) }

// Backend 描述外部插件自带的后端可执行文件。
//
// ########## 安全模型：默认不自动启动 ##########
//
// 面板通常以 root 运行。**exec 一个用户上传的二进制 = 直接给它 root**。
// 因此即便声明了 backend.exec，核心也**不会在启动时自动拉起它**，
// 只在插件管理页里注册为 stopped 状态，需要管理员手动点击启动。
//
// 这不是"多此一举的确认"，而是把「安装插件」与「运行插件代码」
// 分成两个独立的动作：用户可以放心地先安装、审查插件内容，
// 再决定是否让它跑起来。
type Backend struct {
	// Exec 是可执行文件路径，**相对于插件目录**。
	//
	// 必须是相对路径：允许绝对路径就等于允许插件指向 /bin/sh，
	// 一个「插件」就能直接拿到一个 shell。这里是硬性拒绝。
	Exec string `json:"exec,omitempty"`
	// Args 是传给可执行文件的额外参数（可选）。
	Args []string `json:"args,omitempty"`
	// AutoStart 表示是否在面板启动时自动拉起。
	//
	// ########## 这个字段存在，但当前被强制忽略 ##########
	//
	// 保留它是为了让 descriptor.json 的 schema 稳定（将来若要放开，
	// 不必改格式），但**当前实现一律不自动启动**，
	// 并且在检测到 auto_start=true 时给出明确的 WARN，
	// 让用户知道他的声明没有被采纳、原因是什么。
	//
	// 静默忽略是最糟的处理方式：用户会以为插件已经在跑了。
	AutoStart bool `json:"auto_start,omitempty"`
}

// ExternalDescriptor 是外部插件 descriptor.json 的完整结构。
type ExternalDescriptor struct {
	// APIVersion 声明插件针对的插件 API 版本，必需。
	APIVersion string `json:"apiVersion"`

	// ------ 以下字段与 plugin.Descriptor 逐一对齐 ------
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description,omitempty"`
	Mode        string     `json:"mode,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	Frontend    Frontend   `json:"frontend"`
	Backend     *Backend   `json:"backend,omitempty"`
	Extra       *ExtraInfo `json:"extra,omitempty"`

	// ########## 作者信息同时接受**顶层平铺**写法 ##########
	//
	// 这三个字段是纯展示信息，不参与任何逻辑判断。它们既可以被
	// 写在 "extra" 段里，也可以直接写在顶层：
	//
	//	{ "id": "x", "author": "张三", "license": "MIT" }        ← 顶层
	//	{ "id": "x", "extra": { "author": "张三" } }             ← 分段
	//
	// 两种写法等价，解析时合并（"extra" 段优先）。
	//
	// ########## 为什么值得为这点便利让步 ##########
	//
	// 本结构体用 DisallowUnknownFields 严格解析，因为字段拼错若被静默忽略，
	// 插件会以一种极难排查的方式失效（权限为空 → 所有调用 403）。
	// 但这条严格性用在 author 上是**纯粹的敌意**：
	//
	//	· 顶层写 author 是几乎所有插件作者的第一直觉；
	//	· 被拒绝时的报错是 `unknown field "author"`——
	//	  作者根本猜不到正确写法是把它塞进 "extra"；
	//	· 而它错了也不会有任何安全或功能后果（就是个署名）。
	//
	// 本项目的文档（docs/plugin-api.md）与示例包都曾因为这一条而加载失败，
	// 因此改为接受两种写法。真正需要严格的是 id / version / permissions /
	// frontend.entry 这些会变成路径、URL 与权限的字段——那些仍然严查。
	Author   string `json:"author,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	License  string `json:"license,omitempty"`
}

// ExtraInfo 是插件作者填写的展示信息（不参与任何逻辑判断）。
//
// 推荐用 "extra" 段承载这些信息，这样一眼能看出
// "面板不解析这些字段"。但顶层平铺写法同样被接受
// （见 ExternalDescriptor 里的说明）。
type ExtraInfo struct {
	Author   string `json:"author,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	License  string `json:"license,omitempty"`
}

// normalizeAuthorInfo 把"顶层平铺"的作者信息归并到 Extra 段里。
//
// 两种写法等价，规则是 **"extra" 段优先**：
//
//	{ "author": "张三", "extra": { "author": "李四" } }  →  李四
//
// 之所以让 "extra" 段优先：那是**更明确**的写法，
// 作者既然专门写了 extra 段，说明他清楚这些字段的归属，
// 此时顶层那个值多半是复制粘贴残留。
func (e *ExternalDescriptor) normalizeAuthorInfo() {
	if e.Author == "" && e.Homepage == "" && e.License == "" {
		return
	}
	if e.Extra == nil {
		e.Extra = &ExtraInfo{}
	}
	if e.Extra.Author == "" {
		e.Extra.Author = e.Author
	}
	if e.Extra.Homepage == "" {
		e.Extra.Homepage = e.Homepage
	}
	if e.Extra.License == "" {
		e.Extra.License = e.License
	}
}

// ParseExternalDescriptor 解析并**严格校验** descriptor.json。
//
// ########## 为什么校验这么严 ##########
//
// 这个文件来自用户上传的压缩包，是**不可信输入**。
// 它的每一个字段最终都会变成：一个磁盘目录名、一个 URL 路径、
// 一个 socket 文件名、或者一条权限声明。
// 因此宁可拒绝得啰嗦，也不能让可疑的输入进到注册表里。
//
// 所有校验都在**注册之前**完成：一个字段非法的插件
// 绝不能先注册再报错（那会在列表里留下一个半残的条目）。
func ParseExternalDescriptor(data []byte, dirName string) (*Descriptor, error) {
	var ext ExternalDescriptor
	// DisallowUnknownFields：拼错的字段名会被拒绝，而不是被静默忽略。
	//
	// ########## 为什么这个选择很重要 ##########
	//
	// 插件作者把 "permissions" 拼成 "permission" 时：
	//
	//	静默忽略 → 插件注册成功、权限为**空**、所有调用 403。
	//	           作者会去查路由、查代理、查网络，唯独不会怀疑拼写。
	//	拒绝     → 启动时直接报 "unknown field \"permission\""，
	//	           一眼就能定位。
	//
	// 对本文件而言，"启动即失败"远比"运行期行为诡异"友好。
	if err := strictUnmarshal(data, &ext); err != nil {
		return nil, fmt.Errorf("plugin: %s 解析失败: %w", DescriptorFileName, err)
	}
	// 合并两种写法的作者信息（顶层平铺 ↔ "extra" 段）。
	ext.normalizeAuthorInfo()

	// ---------- apiVersion ----------
	if strings.TrimSpace(ext.APIVersion) == "" {
		return nil, fmt.Errorf("plugin: %s 缺少 apiVersion 字段"+
			"（必须声明插件针对的插件 API 版本，当前为 %q）", DescriptorFileName, CurrentAPIVersion)
	}
	if !apiVersionPattern.MatchString(ext.APIVersion) {
		return nil, fmt.Errorf("plugin: apiVersion = %q 非法（期望形如 %q 或 %q）",
			ext.APIVersion, CurrentAPIVersion, CurrentAPIVersion+".0")
	}
	if !apiVersionCompatible(ext.APIVersion) {
		return nil, fmt.Errorf("%w: 插件声明 apiVersion %q，本面板支持 %q 主版本。"+
			"该插件可能使用了本版本不具备的能力，请升级面板或联系插件作者",
			ErrIncompatibleAPIVersion, ext.APIVersion, CurrentAPIVersion)
	}

	// ---------- id ----------
	if !ValidExternalID(ext.ID) {
		return nil, fmt.Errorf("plugin: 非法插件 ID %q（只允许小写字母/数字/连字符，"+
			"首位必须是字母，总长 2~63 位）", ext.ID)
	}
	// 目录名必须与 ID 一致。
	//
	// ########## 为什么要检查这个 ##########
	//
	// 插件的资源目录、socket 名都由 ID 派生。若目录叫 evil 而
	// descriptor.json 里的 id 是 sysinfo，那么"加载 evil 目录"
	// 得到的效果是注册一个叫 sysinfo 的插件——
	// 用户看着目录名以为装的是 A，实际跑的是 B。
	// 这种不一致没有任何正当用途，一律拒绝。
	if dirName != "" && dirName != ext.ID {
		return nil, fmt.Errorf("plugin: 目录名 %q 与 %s 里的 id %q 不一致"+
			"（目录名必须与插件 ID 相同）", dirName, DescriptorFileName, ext.ID)
	}

	// ---------- name / version ----------
	if strings.TrimSpace(ext.Name) == "" {
		return nil, fmt.Errorf("plugin: %s 缺少 name 字段", ext.ID)
	}
	if strings.TrimSpace(ext.Version) == "" {
		return nil, fmt.Errorf("plugin: %s 缺少 version 字段", ext.ID)
	}
	if !ValidSemver(ext.Version) {
		return nil, fmt.Errorf("plugin: %s 的 version = %q 不是合法的语义化版本"+
			"（期望形如 1.0.0）", ext.ID, ext.Version)
	}

	// ---------- mode ----------
	// 外部插件的 mode 只能由「是否有 backend.exec」决定，
	// 不接受 descriptor.json 自己声明。
	//
	// ########## 为什么不允许自己声明 mode ##########
	//
	// ModeExternal 的语义是"核心不拉起进程，只按地址拨号"。
	// 若外部插件能声明 ModeExternal，它就能让核心不去启动进程，
	// 却仍然把 /api/plugins/<id>/* 的请求转发到一个它自己
	// 指定的 socket 路径上——等于让插件劫持核心的转发目标。
	//
	// 因此 mode 由核心推导：
	//	有 backend.exec → ModeManaged（核心拉起，但需手动启动）
	//	无 backend.exec → 前端-only（核心不拉进程，只注册与转发静态资源）
	if ext.Mode != "" && ext.Mode != ModeManaged && ext.Mode != ModeExternal {
		return nil, fmt.Errorf("plugin: %s 的 mode = %q 非法，可选 %s|%s",
			ext.ID, ext.Mode, ModeManaged, ModeExternal)
	}

	// ---------- permissions ----------
	// 复用内置插件那套解析器：外部插件与内置插件**走同一条权限链路**，
	// 不存在"外部插件用另一套规则"的情况。
	if _, err := ParsePermissions(ext.Permissions); err != nil {
		return nil, fmt.Errorf("plugin: %s 的权限声明非法: %w", ext.ID, err)
	}

	// ---------- frontend ----------
	if err := validateExternalFrontend(ext.ID, ext.Frontend); err != nil {
		return nil, err
	}

	// ---------- backend ----------
	if err := validateExternalBackend(ext.ID, ext.Backend); err != nil {
		return nil, err
	}

	// 构造与内置插件完全相同的 Descriptor。
	// 从这里开始，外部插件在 Manager 眼里与内置插件没有区别。
	desc := &Descriptor{
		ID:          ext.ID,
		Name:        ext.Name,
		Version:     ext.Version,
		Description: ext.Description,
		// Builtin=false：这是外部插件。前端的"可卸载/可更新"判断依赖它。
		Builtin:     false,
		Mode:        ModeManaged,
		Permissions: ext.Permissions,
		Frontend:    ext.Frontend,
		External:    true,
	}
	if ext.Backend == nil || ext.Backend.Exec == "" {
		// 前端-only 插件：核心不拉起任何进程。
		desc.Mode = ModeExternal
	}
	return desc, nil
}

// apiVersionCompatible 判断插件声明的 apiVersion 是否与当前主程序兼容。
//
// 规则：**主版本号相同即兼容**（理由见 CurrentAPIVersion 的说明）。
func apiVersionCompatible(v string) bool {
	want := majorOf(CurrentAPIVersion)
	got := majorOf(v)
	return want != "" && want == got
}

// majorOf 取出 "1.2" 的主版本 "1"。
func majorOf(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// validateExternalFrontend 校验外部插件的前端声明。
//
// ########## entry 必须落在本插件自己的资源目录下 ##########
//
// 前端入口是核心会**原样返回给浏览器**、由 iframe 去动态 import 的地址。
// 若允许任意路径，插件就能把入口指向站点上的**其它资源**：
//
//	"entry": "/plugin-assets/sysinfo/plugin.js"   ← 指向别人的前端
//	"entry": "/assets/index-abc123.js"            ← 指向主程序产物
//	"entry": "https://evil.example.com/x.js"      ← 指向站外
//
// 第一种会让插件劫持/冒充另一个插件的界面（用户以为在看 sysinfo，
// 实际是攻击者的代码）；后两种更是直接的越界加载。
//
// 因此强制要求：entry 必须以 `/plugin-assets/<本插件id>/` 开头。
// 这是**唯一**被允许的前缀形式——不接受相对路径、不接受绝对 URL、
// 不接受 ../ 绕行。
func validateExternalFrontend(id string, f Frontend) error {
	entry := strings.TrimSpace(f.Entry)

	// 允许完全没有前端（纯后端插件）。
	if entry == "" && strings.TrimSpace(f.NavTitle) == "" {
		return nil
	}
	if entry == "" {
		return fmt.Errorf("plugin: %s 声明了 nav_title 但缺少 frontend.entry", id)
	}

	wantPrefix := "/plugin-assets/" + id + "/"
	if !strings.HasPrefix(entry, wantPrefix) {
		return fmt.Errorf("plugin: %s 的 frontend.entry = %q 非法。"+
			"必须以 %q 开头（插件只能引用自己的前端资源，"+
			"不能指向其它插件或主程序的资源）", id, entry, wantPrefix)
	}
	// 前缀之后必须还有实际文件名，且不能再用 .. 往回跳。
	rest := strings.TrimPrefix(entry, wantPrefix)
	if rest == "" {
		return fmt.Errorf("plugin: %s 的 frontend.entry 只给了目录 %q，缺少文件名",
			id, entry)
	}
	if err := checkNoTraversal(rest); err != nil {
		return fmt.Errorf("plugin: %s 的 frontend.entry %q 非法: %w", id, entry, err)
	}

	// assets 若声明，必须是 entry 所在目录（或它的前缀）。
	if assets := strings.TrimSpace(f.Assets); assets != "" {
		if !strings.HasPrefix(assets, "/plugin-assets/"+id+"/") {
			return fmt.Errorf("plugin: %s 的 frontend.assets = %q 非法，"+
				"必须以 %q 开头", id, assets, wantPrefix)
		}
	}

	// type 只支持 esm（与内置插件一致）。
	if t := strings.TrimSpace(f.Type); t != "" && t != FrontendTypeESM {
		return fmt.Errorf("plugin: %s 的 frontend.type = %q 不受支持（当前只支持 %q）",
			id, t, FrontendTypeESM)
	}
	return nil
}

// validateExternalBackend 校验后端声明。
func validateExternalBackend(id string, b *Backend) error {
	if b == nil || strings.TrimSpace(b.Exec) == "" {
		return nil // 前端-only 插件
	}

	exec := strings.TrimSpace(b.Exec)

	// ########## 必须是相对路径 ##########
	//
	// 绝对路径等于允许插件声明 "exec": "/bin/sh"，
	// 那样一个"插件"就直接拿到了一个 shell——完全绕过了
	// 「安装」与「运行」之间的那道人工确认。
	if filepath.IsAbs(exec) {
		return fmt.Errorf("plugin: %s 的 backend.exec = %q 非法："+
			"必须是**相对于插件目录**的路径，不能是绝对路径", id, exec)
	}
	// Windows 盘符形态（C:\...）同样拒绝。
	if len(exec) >= 2 && exec[1] == ':' {
		return fmt.Errorf("plugin: %s 的 backend.exec = %q 非法：不能是绝对路径", id, exec)
	}
	if err := checkNoTraversal(exec); err != nil {
		return fmt.Errorf("plugin: %s 的 backend.exec = %q 非法: %w", id, exec, err)
	}

	// 参数不允许包含空字节（execve 会拒绝，但提前给出更清楚的错误）。
	for i, a := range b.Args {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("plugin: %s 的 backend.args[%d] 含空字节", id, i)
		}
	}
	return nil
}

// checkNoTraversal 拒绝一切可能跳出插件目录的相对路径。
//
// 与 archive.go 的 zip 解压校验共用同一套判断标准：
// "解压时不许穿越"与"运行期不许穿越"必须是同一个规则，
// 否则会出现"装进来了但跑不起来"或更糟的"装的时候拦住了、
// 运行时却绕过去了"。
func checkNoTraversal(p string) error {
	if p == "" {
		return fmt.Errorf("路径为空")
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("路径含空字节")
	}
	// 统一分隔符后再判断：Windows 上传的包可能用反斜杠。
	norm := strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(norm, "/") {
		return fmt.Errorf("不允许绝对路径")
	}
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return fmt.Errorf("不允许包含 .. 路径段")
		}
	}
	// clean 之后仍必须落在原相对位置（防 "a/./../../b" 这类变体）。
	clean := filepath.ToSlash(filepath.Clean(norm))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("清理后仍跳出目录: %q", clean)
	}
	return nil
}

// ReadExternalDescriptor 从插件目录读取并解析 descriptor.json。
//
// 它会校验「目录名与插件 ID 一致」——这是**扫描磁盘时**的约束。
// 安装流程中的暂存目录名是随机的，那条路径要用
// ReadExternalDescriptorNoDirCheck。
func ReadExternalDescriptor(dir string) (*Descriptor, error) {
	return readExternalDescriptor(dir, filepath.Base(dir))
}

// ReadExternalDescriptorNoDirCheck 读取并解析 descriptor.json，
// 但**跳过**目录名与 ID 一致性的检查。
//
// ########## 为什么需要两条路径 ##########
//
// 「目录名与 ID 一致」在本项目里对应两个语义完全不同的场景：
//
//	扫描磁盘：  <pluginDir>/hello/descriptor.json
//	            → 目录名 "hello" 必须等于 id，否则用户看到的目录名
//	              与实际注册的插件对不上（以为装的是 A，跑的是 B）
//
//	安装过程中：<pluginDir>/.install-1234567/descriptor.json
//	            → 暂存目录名是随机生成的，此刻**还没**被命名成插件 ID，
//	              要求它等于 id 是不可能的
//
// 安装流程在通过校验后用 desc.ID 自己命名最终目录，
// 因此「目录名 == ID」这条约束由安装流程保证，
// 不需要在解析阶段重复检查。
func ReadExternalDescriptorNoDirCheck(dir string) (*Descriptor, error) {
	return readExternalDescriptor(dir, "")
}

// readExternalDescriptor 是两条路径的公共实现。
func readExternalDescriptor(dir, dirName string) (*Descriptor, error) {
	path := filepath.Join(dir, DescriptorFileName)

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 读取 %s 失败: %w", path, err)
	}
	// ########## 拒绝超大文件 ##########
	//
	// descriptor.json 是元数据，几 KB 足够。若是个几百 MB 的"JSON"，
	// 读进内存就成了一次拒绝服务。这个上限与 zip 解压的上限是
	// 同一条思路：**任何来自用户的输入都要有大小上限**。
	if info.Size() > maxDescriptorBytes {
		return nil, fmt.Errorf("plugin: %s 过大（%d 字节，上限 %d）",
			path, info.Size(), maxDescriptorBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 读取 %s 失败: %w", path, err)
	}
	return ParseExternalDescriptor(data, dirName)
}

// maxDescriptorBytes 是 descriptor.json 的大小上限。
const maxDescriptorBytes = 1 << 20 // 1 MiB

// strictUnmarshal 解析 JSON 并拒绝未知字段。
//
// ########## 为什么全项目统一用严格模式 ##########
//
// 见 ParseExternalDescriptor 里对 "permission"（漏了 s）的分析：
// 静默忽略拼错的字段，会让插件"注册成功但行为诡异"，
// 而严格模式把它变成一条启动时的明确错误。
//
// 单独抽成函数是为了让"读 descriptor.json 的两条路径"
// （完整校验 / 只取 backend 段）用**完全相同**的解析规则——
// 否则可能出现"完整校验通过了，但重新读取时解析出别的东西"。
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
