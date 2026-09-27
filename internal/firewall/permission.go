package firewall

import (
	"fmt"
	"strings"
)

// ============================================================================
// 防火墙操作的权限判定（阶段四 4.6）
// ============================================================================
//
// 与 internal/service（4.1）、internal/file（4.2）、internal/site（4.3）、
// internal/ssl（4.4）、internal/store（4.5）的 permission.go 同构，理由相同：
//
//	RequireAuth 保证的是「登录了」，权限判定保证的是「有权限改防火墙」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——
//	将来引入只读用户时，这条路径就是补不上的洞。
//
// #################### 防火墙权限的语义 ####################
//
// 防火墙操作改变的是**网络可达性**，这与其它模块有本质区别：
//
//	4.1 启停服务   —— 影响一个服务的可用性
//	4.2 读写文件   —— 影响若干文件的内容
//	4.3 改站点配置 —— 影响 nginx 的加载行为
//	4.4 申请证书   —— 影响 HTTPS 与 CA 配额
//	4.5 安装软件   —— 影响系统软件构成
//	4.6 改防火墙   —— **影响这台机器能否被访问到**
//
// 最后一条的后果是不可逆的：一条错误的规则可以让 SSH 与面板
// **同时失联**，用户只能通过物理控制台或云服务商控制台恢复。
// 其它模块的误操作大多可以重传文件、重装软件来修复，
// 而"连不上机器"这件事无法通过网络修好。
//
// 因此 firewall.write 的语义是"允许改变这台机器的网络可达性"。
// 刻意**不复用** service.write：形状相同但风险等级完全不同
// （"能重启 nginx"与"能让整台机器断网"不是一回事）。

// 防火墙相关权限常量。
const (
	// PermRead 允许查看防火墙状态、规则列表与审计。
	PermRead = "firewall.read"
	// PermWrite 允许增删防火墙规则（放行/关闭端口、管理 IP 黑白名单）。
	PermWrite = "firewall.write"
)

// 防火墙操作动作（用于审计与日志的稳定标识）。
const (
	// ActionStatus 查询防火墙状态与后端。
	ActionStatus = "status"
	// ActionListRules 查询规则列表。
	ActionListRules = "list_rules"
	// ActionAudit 查询审计。
	ActionAudit = "audit"
	// ActionCapabilities 能力探测。
	ActionCapabilities = "capabilities"
	// ActionAddPort 放行/拒绝端口。
	ActionAddPort = "add_port"
	// ActionDeletePort 删除端口规则。
	ActionDeletePort = "delete_port"
	// ActionAddIP 添加 IP 黑白名单。
	ActionAddIP = "add_ip"
	// ActionDeleteIP 删除 IP 黑白名单。
	ActionDeleteIP = "delete_ip"
	// ActionEnable 启用防火墙。
	ActionEnable = "enable"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 读操作（status/list_rules/audit/capabilities）要 firewall.read；
// 其余（增删规则、启用防火墙）一律要 firewall.write。
//
// ########## 为什么 enable 也算写操作 ##########
//
// 启用防火墙会立刻让所有未放行的端口不可达。
// 若把 SSH 端口漏在规则外，**启用的一瞬间**当前 SSH 连接就断了。
// 因此它是彻头彻尾的写操作，且是所有写操作里最危险的一个。
func RequiredPermission(action string) string {
	switch action {
	case ActionStatus, ActionListRules, ActionAudit, ActionCapabilities:
		return PermRead
	}
	return PermWrite
}

// WritesSystem 表示该动作会改变系统状态（用于审计的醒目标记）。
func WritesSystem(action string) bool {
	switch action {
	case ActionAddPort, ActionDeletePort, ActionAddIP, ActionDeleteIP, ActionEnable:
		return true
	}
	return false
}

// DeletionAction 表示该动作是"删除类"操作（需要二次确认）。
//
// ########## 为什么需要这个判定 ##########
//
// 计划明确要求"删除规则前必须二次确认，避免把 SSH 端口误关导致失联"。
// 把"哪些动作需要确认"做成一个**集中判定**而不是散落在
// 各个 handler 里的 if，有两个好处：
//
//	① 新增删除类动作时不会漏加确认（漏了就是失联风险）；
//	② 测试可以穷举所有动作，断言删除类的都在集合里。
func DeletionAction(action string) bool {
	return action == ActionDeletePort || action == ActionDeleteIP
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的防火墙权限集合。
	//
	// 当前实现：登录用户即管理员，Granted 为 [PermRead, PermWrite]。
	// 保留显式集合而不是"永远返回 true"，是为了让判定+留痕的链路
	// 在引入多用户时**不需要改动调用方**。
	Granted []string
}

// Has 判断是否被授予了某权限（大小写不敏感）。
func (g Grantee) Has(perm string) bool {
	for _, p := range g.Granted {
		if strings.EqualFold(strings.TrimSpace(p), perm) {
			return true
		}
	}
	return false
}

// Decision 是权限校验的结论。
type Decision struct {
	// Allowed 表示是否放行。
	Allowed bool `json:"allowed"`
	// Required 是本次操作所需的权限。
	Required string `json:"required,omitempty"`
	// Granted 是当前用户已授予的权限，便于直接对照"为什么被拒"。
	Granted []string `json:"granted,omitempty"`
	// Reason 是拒绝原因。
	Reason string `json:"reason,omitempty"`
	// Hint 是"怎么办"的提示，前端直接展示给用户。
	Hint string `json:"hint,omitempty"`
}

// AdminGrantee 返回「登录用户即管理员」这一当前策略下的授予集合。
//
// 单用户面板阶段：能登录进来就是管理员，因此授予全部防火墙权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// ReadOnlyGrantee 返回只读授予集合（供测试与将来的只读角色使用）。
func ReadOnlyGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead}}
}

// CheckFirewallPermission 判断某用户能否执行某防火墙操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckFirewallPermission(g Grantee, action string) Decision {
	required := RequiredPermission(action)

	if g.Has(required) {
		return Decision{
			Allowed:  true,
			Required: required,
			Granted:  append([]string(nil), g.Granted...),
		}
	}

	user := g.User
	if user == "" {
		user = "当前用户"
	}
	return Decision{
		Allowed:  false,
		Required: required,
		Granted:  append([]string(nil), g.Granted...),
		Reason:   fmt.Sprintf("%s 未被授予权限 %s", user, required),
		Hint: fmt.Sprintf(
			"该操作需要权限 %s。当前面板为单管理员模式，登录用户默认拥有全部"+
				"防火墙权限；若你看到此提示，说明账号权限已被收窄。"+
				"注意：修改防火墙规则会改变这台机器的网络可达性，"+
				"一条错误的规则可能同时切断 SSH 与面板的访问，"+
				"因此该权限被单独管控，且删除类操作需要二次确认。",
			required),
	}
}
