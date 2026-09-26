package ssl

import (
	"fmt"
	"strings"
)

// ============================================================================
// SSL 操作的权限判定（阶段四 4.4）
// ============================================================================
//
// 与 internal/service（4.1）、internal/file（4.2）、internal/site（4.3）
// 的 permission.go 同构，理由也完全相同：
//
//	RequireAuth 保证的是「**登录了**」，权限判定保证的是「**有权限动证书**」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——将来引入只读用户时，
//	这条路径就是补不上的洞。因此核心自带的写操作也统一走一次判定并留痕。
//
// #################### SSL 为什么比 4.1~4.3 更该有权限判定 ####################
//
// 本模块的写操作有两个别处没有的后果：
//
//	① **消耗外部配额**：Let's Encrypt 对同一组域名有"每周 5 次重复签发"
//	   的速率限制。一个越权的申请请求不只是"改了一个文件"，
//	   它可能让这台服务器**整整一周都无法为这个域名签发证书**——
//	   包括正常的紧急续期。这类破坏是不可逆且有时效的。
//	② **使全站 HTTPS 中断**：证书写进 nginx 后，若证书文件损坏或路径错，
//	   reload 后 HTTPS 全部失效（HTTP 仍可用，但浏览器会报证书错误）。
//
// 因此 `ssl.write` 在本模块的语义是"允许消耗 CA 配额并改写 HTTPS 配置"，
// 而不是一个普通的写权限。
//
// 权限命名沿用同一套语法（<域>.<动作>）：
//
//	ssl.read    查看证书状态、到期时间、能力探测
//	ssl.write   申请、续期证书（会消耗 CA 配额并改写 nginx 配置）
//
// 刻意**不复用** site.Grantee：形状相同但语义不同
// （一个描述"能改哪些站点"，一个描述"能申请哪些证书"）。
// 复用会让将来加入"只能为某几个域名申请"这类资源级权限时无从下手。

// SSL 相关权限常量。
const (
	// PermRead 允许查看证书状态与到期时间。
	PermRead = "ssl.read"
	// PermWrite 允许申请与续期证书。
	PermWrite = "ssl.write"
)

// SSL 操作动作（用于审计与日志的稳定标识）。
const (
	// ActionList 列出证书状态。
	ActionList = "list"
	// ActionView 查看单个站点的证书状态。
	ActionView = "view"
	// ActionCapabilities 能力探测。
	ActionCapabilities = "capabilities"
	// ActionIssue 申请证书。
	ActionIssue = "issue"
	// ActionRenew 手动续期。
	ActionRenew = "renew"
	// ActionAutoRenew 自动续期（定时任务触发）。
	ActionAutoRenew = "auto_renew"
	// ActionAudit 查看审计。
	ActionAudit = "audit"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 读操作（list/view/capabilities/audit）要 ssl.read；
// 其余（issue/renew/auto_renew）一律要 ssl.write。
func RequiredPermission(action string) string {
	switch action {
	case ActionList, ActionView, ActionCapabilities, ActionAudit:
		return PermRead
	}
	return PermWrite
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的 SSL 权限集合。
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
// 单用户面板阶段：能登录进来就是管理员，因此授予全部 SSL 权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// AutomationGrantee 返回内部定时任务使用的授予集合。
//
// ########## 为什么自动续期也要走权限判定 ##########
//
// 自动续期没有"登录用户"，但它同样是一个会消耗 CA 配额、
// 会改写 nginx 配置的写操作。若给它开一条"内部调用免检"的后门，
// 那么"权限判定是唯一强制点"这句话就不成立了——
// 将来收窄策略时（例如"只允许为特定域名续期"），
// 定时任务会成为一个绕过它的静默通道。
//
// 因此这里显式构造一个系统身份，让它和用户请求走**完全同一条**
// 判定与审计路径（审计里 User 记为 "system:auto-renew"，
// 事后能一眼看出"这次续期不是我点的"）。
func AutomationGrantee() Grantee {
	return Grantee{
		User:    AutomationUser,
		Granted: []string{PermRead, PermWrite},
	}
}

// AutomationUser 是自动续期在审计中的操作者标识。
//
// 用 "system:" 前缀与真实用户名区分开：审计查询按 user 过滤时，
// `user=system:auto-renew` 能精确筛出全部自动续期记录。
// 若记成空字符串或某个真实用户名，事后就无法区分
// "证书是定时任务续的" 还是 "有人手工续的"——而这在排查
// "为什么证书在半夜被换掉了" 时是第一个要回答的问题。
const AutomationUser = "system:auto-renew"

// CheckSSLPermission 判断某用户能否执行某 SSL 操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckSSLPermission(g Grantee, action string) Decision {
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
			"该操作需要权限 %s。当前面板为单管理员模式，"+
				"登录用户默认拥有全部 SSL 权限；若你看到此提示，说明账号权限已被收窄。"+
				"注意：申请与续期会消耗 Let's Encrypt 的签发配额，因此被单独管控。",
			required),
	}
}
