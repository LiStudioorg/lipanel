package plugin

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ============================================================================
// 插件权限模型（阶段三 3.3）
// ============================================================================
//
// #################### 能力边界声明（必读，防止安全误解）####################
//
// 本文件实现的是【面板转发通道】上的权限拦截，**不是内核级沙箱**。
//
// 核心能真正管住的只有「面板给了插件什么」：浏览器能不能经核心转发去调用
// 插件的某个接口、能不能取到插件的前端资源。核心**无法**阻止插件进程直接
// 调用 open(2)/read(2) 去读任意文件、或 fork/exec 去执行任意命令——那是内核
// 的职责，需要 seccomp / namespace / cgroup 或降权运行才能做到，而本项目
// 的工程约束是「单二进制 + 零依赖 + CGO_ENABLED=0」，不引入这类机制。
//
// 因此 `file.read:/etc/nginx` 这类声明**不会被强制为「插件只能读这个目录」**，
// 它的真实语义是：
//
//  1. 插件向用户**如实申报**自己需要什么能力（可展示、可审计的能力清单）；
//  2. 核心据此**拒绝**未经声明的面板转发调用（越权请求根本到不了插件进程）；
//  3. 为将来引入真正的进程沙箱（外部插件、降权运行、seccomp）预留统一接口。
//
// **绝不可**把它当作「插件被沙箱住了」来理解。若要运行不信任的插件，
// 必须另行使用操作系统级隔离（独立用户 + 只读挂载 + seccomp 等）。
//
// ###########################################################################
//
// 权限语法：`<域>.<动作>[:<资源>]`
//
//	system.read              读取系统信息
//	process.read             读取进程信息
//	process.exec:/usr/bin/x  执行指定程序（资源是白名单路径）
//	file.read:/etc/nginx     读取指定目录/文件
//	file.write:/var/log/x    写入指定路径
//	http.call                发起外部 HTTP 调用
//
// 资源段可选。带资源时，资源必须是非空的绝对路径形态或标识符，
// 由 [ParsePermission] 校验；当前核心只做「域.动作」级别的拦截，
// 资源段用于申报与展示，并为将来的细粒度校验保留。

// permissionPattern 限定权限的整体形态。
//
// 安全考量：权限串会被写进日志与审计记录，也可能出现在配置文件中。
// 严格限定字符集（小写字母、数字、点、连字符、下划线、冒号、斜杠）
// 可以避免控制字符、换行等注入到日志行里（日志注入会让审计记录失真）。
var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+(:[A-Za-z0-9._/\-]+)?$`)

// 内置权限域。域必须是已知的，否则很可能是拼写错误
// （例如 "system:read" 写成了 "sytem.read"），静默接受会掩盖真实问题。
var knownPermissionDomains = map[string]bool{
	"system":  true,
	"process": true,
	"file":    true,
	"network": true,
	"http":    true,
	"service": true,
}

// Permission 是一条已解析的权限声明。
type Permission struct {
	// Raw 是原始声明串，用于展示与审计（用户看到的就是它）。
	Raw string `json:"raw"`
	// Domain 是权限域，例如 system / process / file。
	Domain string `json:"domain"`
	// Action 是动作，例如 read / write / exec / call。
	Action string `json:"action"`
	// Resource 是可选资源限定，例如 /etc/nginx。为空表示不限资源。
	Resource string `json:"resource,omitempty"`
}

// String 返回权限的规范串。
func (p Permission) String() string { return p.Raw }

// Key 返回「域.动作」形式，用于粗粒度匹配。
//
// 资源段刻意不参与匹配：当前核心无法验证插件是否真的只用了资源段里的路径
// （见文件头的能力边界说明），把它并入匹配只会制造「校验很细」的假象。
// 资源仅用于申报与展示。
func (p Permission) Key() string { return p.Domain + "." + p.Action }

// ParsePermission 解析并校验一条权限声明。
func ParsePermission(raw string) (Permission, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Permission{}, fmt.Errorf("权限声明不能为空")
	}
	if len(s) > 128 {
		return Permission{}, fmt.Errorf("权限声明过长（上限 128 字符）: %q", s)
	}
	if !permissionPattern.MatchString(s) {
		return Permission{}, fmt.Errorf(
			"权限声明 %q 格式非法：期望 <域>.<动作>[:<资源>]，例如 system.read、file.read:/etc/nginx", s)
	}

	body, resource := s, ""
	if i := strings.IndexByte(s, ':'); i >= 0 {
		body, resource = s[:i], s[i+1:]
		if resource == "" {
			return Permission{}, fmt.Errorf("权限声明 %q 的资源段为空（要么去掉冒号，要么写上资源）", s)
		}
	}

	i := strings.IndexByte(body, '.')
	if i <= 0 || i == len(body)-1 {
		return Permission{}, fmt.Errorf("权限声明 %q 缺少「域.动作」结构", s)
	}
	domain, action := body[:i], body[i+1:]

	if !knownPermissionDomains[domain] {
		return Permission{}, fmt.Errorf(
			"权限声明 %q 的域 %q 未知（可用域：%s）", s, domain, strings.Join(knownDomains(), "|"))
	}
	// 动作段里不允许再出现点：多级动作会让匹配规则变得含糊。
	if strings.ContainsRune(action, '.') {
		return Permission{}, fmt.Errorf("权限声明 %q 的动作段不允许多级（只支持 <域>.<动作>）", s)
	}

	return Permission{Raw: s, Domain: domain, Action: action, Resource: resource}, nil
}

// knownDomains 返回排序后的已知域列表（用于错误提示的稳定输出）。
func knownDomains() []string {
	out := make([]string, 0, len(knownPermissionDomains))
	for d := range knownPermissionDomains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// PermissionSet 是一个插件已声明的权限集合。
//
// 零值可用（表示「未声明任何权限」），其 Check 一律拒绝——
// 这是有意的默认拒绝（fail-closed）。
type PermissionSet struct {
	// byKey 是「域.动作」→ 权限 的索引。
	byKey map[string]Permission
	// list 保留声明顺序，用于展示与审计（map 遍历顺序随机）。
	list []Permission
}

// ParsePermissions 解析一组权限声明。
//
// 重复声明同一「域.动作」会报错而不是静默去重：那通常是插件作者复制粘贴
// 时忘了改，静默去重会让"我明明声明了"这类排查变得困难。
func ParsePermissions(raws []string) (PermissionSet, error) {
	set := PermissionSet{byKey: make(map[string]Permission, len(raws))}
	for _, raw := range raws {
		// 允许用逗号分隔的简写：manifest 里写成一行更省事。
		for _, part := range strings.Split(raw, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			p, err := ParsePermission(part)
			if err != nil {
				return PermissionSet{}, err
			}
			if prev, dup := set.byKey[p.Key()]; dup {
				return PermissionSet{}, fmt.Errorf(
					"权限 %q 与已声明的 %q 重复（同一「域.动作」只能声明一次）", p.Raw, prev.Raw)
			}
			set.byKey[p.Key()] = p
			set.list = append(set.list, p)
		}
	}
	return set, nil
}

// Has 判断集合中是否包含指定权限（粗粒度，忽略资源段）。
func (s PermissionSet) Has(perm string) bool {
	key := perm
	if i := strings.IndexByte(perm, ':'); i >= 0 {
		key = perm[:i]
	}
	_, ok := s.byKey[key]
	return ok
}

// HasAny 判断集合中是否至少包含给定权限之一。
func (s PermissionSet) HasAny(perms ...string) bool {
	for _, p := range perms {
		if s.Has(p) {
			return true
		}
	}
	return false
}

// Empty 表示未声明任何权限。
func (s PermissionSet) Empty() bool { return len(s.list) == 0 }

// Len 返回权限条数。
func (s PermissionSet) Len() int { return len(s.list) }

// List 返回声明顺序的权限列表（副本，调用方可安全修改）。
func (s PermissionSet) List() []Permission {
	out := make([]Permission, len(s.list))
	copy(out, s.list)
	return out
}

// Strings 返回原始声明串列表，用于 JSON 输出与审计。
func (s PermissionSet) Strings() []string {
	out := make([]string, 0, len(s.list))
	for _, p := range s.list {
		out = append(out, p.Raw)
	}
	return out
}

// ============================================================================
// 权限规则表：（HTTP 方法 + 插件子路径）→ 所需权限
// ============================================================================

// publicPrefixes 是无需任何权限的路径前缀。
//
// 这些是**骨架接口**（由 plugin.Serve 统一提供，插件作者没有实现权），
// 核心的健康探测与身份确认依赖它们；把它们纳入权限体系只会让
// 「插件因为没声明权限而无法被探测健康」这种荒唐情况发生。
//
// /assets/ 同样免声明：它是宿主对插件的固定调用（取插件自带的前端资源），
// 请求由核心自己发起，不来自插件对面板的越权企图。
var publicPrefixes = []string{
	"/healthz",
	"/whoami",
	"/assets/",
}

// permissionRules 是「路径前缀 → 所需权限」的规则表。
//
// 匹配规则：按声明的顺序**最长前缀优先**（不是表里第一条命中），
// 因此更具体的路径可以覆盖更宽泛的前缀。
//
// 设计原则：**默认拒绝**。表中没有命中的路径会回落到
// fallbackPermission（见 RequiredPermission），而不是放行。
var permissionRules = []struct {
	// Prefix 是插件子路径前缀（不含 /api/plugins/<id>）。
	Prefix string
	// Method 为空表示匹配任意方法。
	Method string
	// Perm 是所需权限（「域.动作」）。
	Perm string
}{
	// 骨架级只读信息：运行时长、PID、内存占用等进程自身信息。
	{Prefix: "/runtime", Method: "GET", Perm: "process.read"},

	// sysinfo 类只读系统信息接口。
	{Prefix: "/info", Method: "GET", Perm: "system.read"},
	{Prefix: "/echo", Method: "GET", Perm: "system.read"},
	{Prefix: "/metrics", Method: "GET", Perm: "system.read"},

	// 服务管理类接口（第四阶段用得上，此处先把规则钉死，
	// 免得将来新增接口时忘记声明权限，默认拒绝会立刻暴露它）。
	{Prefix: "/services", Method: "GET", Perm: "service.read"},
	{Prefix: "/services", Method: "POST", Perm: "service.write"},

	// 文件类接口。
	{Prefix: "/files", Method: "GET", Perm: "file.read"},
	{Prefix: "/files", Method: "POST", Perm: "file.write"},
	{Prefix: "/files", Method: "PUT", Perm: "file.write"},
	{Prefix: "/files", Method: "DELETE", Perm: "file.write"},
}

// fallbackPermission 是规则表未命中时要求的权限。
//
// 选一个「最无害但仍然显式」的权限作为兜底：它保证默认拒绝的同时，
// 让只做只读查询的插件不必为每个新接口改规则表。
// 需要更强能力的插件必须自己把它写进 Permissions 并保持规则表同步。
const fallbackPermission = "system.read"

// RequiredPermission 推断访问某个插件子路径所需的权限。
//
// 返回值 ok=false 表示该路径**免权限校验**（骨架接口或前端资源）。
// 这是权限体系的唯一判定入口：规则集中在此处，便于审计与测试。
func RequiredPermission(method, subPath string) (perm string, ok bool) {
	for _, p := range publicPrefixes {
		if subPath == p || strings.HasPrefix(subPath, p) {
			return "", false
		}
	}

	best := ""
	bestPerm := ""
	for _, r := range permissionRules {
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		if !strings.HasPrefix(subPath, r.Prefix) {
			continue
		}
		// 最长前缀优先：/services/1/log 应当命中 /services 的规则，
		// 但 /files 与 /files-x 这类前缀不能互相误伤，因此要求
		// 前缀命中处必须是路径边界（结尾或下一个字符是 /）。
		if len(subPath) > len(r.Prefix) && !strings.HasSuffix(r.Prefix, "/") &&
			subPath[len(r.Prefix)] != '/' {
			continue
		}
		if len(r.Prefix) > len(best) {
			best, bestPerm = r.Prefix, r.Perm
		}
	}
	if bestPerm != "" {
		return bestPerm, true
	}
	return fallbackPermission, true
}

// PermissionDecision 是权限校验的结论。
type PermissionDecision struct {
	// Allowed 表示是否放行。
	Allowed bool `json:"allowed"`
	// Required 是本次请求所需的权限（免校验时为空）。
	Required string `json:"required,omitempty"`
	// Exempt 表示该路径免权限校验（骨架接口 / 前端资源）。
	Exempt bool `json:"exempt,omitempty"`
	// Reason 是拒绝原因的简短描述，用于审计与前端提示。
	Reason string `json:"reason,omitempty"`
	// Hint 是「怎么办」的提示，前端直接展示给用户。
	Hint string `json:"hint,omitempty"`
}

// CheckPermission 判断给定插件是否可以用「已声明的权限集合」访问某路径。
//
// 纯函数，无副作用，便于单测穷举。调用方（Proxy）负责记审计。
func CheckPermission(pluginID string, granted PermissionSet, method, subPath string) PermissionDecision {
	required, needCheck := RequiredPermission(method, subPath)
	if !needCheck {
		return PermissionDecision{Allowed: true, Exempt: true}
	}

	if granted.Has(required) {
		return PermissionDecision{Allowed: true, Required: required}
	}

	reason := fmt.Sprintf("插件 %s 未声明权限 %s", pluginID, required)
	hint := fmt.Sprintf(
		"请在插件描述符的 Permissions 中补充 %q 后重启插件。"+
			"注意：权限声明约束的是「核心转发给插件的调用」，不是内核级沙箱——"+
			"它无法阻止插件进程直接访问系统资源。", required)
	if granted.Empty() {
		reason = fmt.Sprintf("插件 %s 未声明任何权限", pluginID)
		hint = "该插件没有声明任何权限，因此除骨架接口外的一切转发调用都会被拒绝。" + hint
	}

	return PermissionDecision{
		Allowed:  false,
		Required: required,
		Reason:   reason,
		Hint:     hint,
	}
}
