package service

import (
	"fmt"
	"strings"
)

// ============================================================================
// 服务操作的权限判定（阶段四 4.1）
// ============================================================================
//
// #################### 为什么面板自身的写操作也要过权限判定 ####################
//
// RequireAuth 保证的是「**登录了**」，权限判定保证的是「**有权限操作服务**」，
// 这是两件不同的事。若面板自己的写操作绕过权限判定，就会出现一条
// 「特权路径」：插件调同一个能力要申报 service.write，面板自己却不用。
// 一旦将来引入多用户与角色（只读用户、仅日志用户），
// 这条特权路径就是权限模型上补不上的洞。因此这里统一走一次判定并留痕。
//
// ##########################################################################
//
// 与插件权限的关系：复用同一套权限**语法与命名**
// （internal/plugin 的 <域>.<动作> 形式），保持概念一致：
//
//	service.read    查看服务列表与状态
//	service.write   启动/停止/重启服务
//
// 但**不复用 plugin.PermissionSet**：插件那套模型回答的是
// 「某个插件声明了哪些权限」，而面板自身没有「声明」这一步——
// 它的权限来自「当前登录用户被授予了什么」。
// 两者输入不同，共用类型只会制造「面板假装自己是个插件」的混乱。

// 服务相关权限常量（与 internal/plugin 的规则表保持同名）。
const (
	// PermRead 允许查看服务列表与状态。
	PermRead = "service.read"
	// PermWrite 允许启停/重启服务。
	PermWrite = "service.write"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 读操作只要 service.read；三个写操作一律要求 service.write。
// 注意 start/stop/restart 之间不做区分：能停服务的人当然也能启动它，
// 再细分（例如「只能重启不能停止」）在运维上没有实际意义，
// 却会让权限模型复杂到没人愿意配置。
func RequiredPermission(action Action) string {
	switch action {
	case ActionStart, ActionStop, ActionRestart:
		return PermWrite
	}
	return PermRead
}

// Grantee 表示「谁在被校验」，用于生成可读的拒绝原因。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的权限集合。
	//
	// 当前实现：登录用户即管理员，Granted 为 [PermRead, PermWrite]。
	// 这里保留显式集合而不是「永远返回 true」，是为了让
	// 「判定 + 留痕」的链路在引入多用户时**不需要改动调用方**——
	// 届时只需换掉这一个来源（从配置/数据库读取角色）。
	Granted []string
}

// Has 判断是否被授予了某权限。
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
	// Granted 是当前用户已授予的权限，便于直接对照「为什么被拒」。
	Granted []string `json:"granted,omitempty"`
	// Reason 是拒绝原因。
	Reason string `json:"reason,omitempty"`
	// Hint 是「怎么办」的提示，前端直接展示给用户。
	Hint string `json:"hint,omitempty"`
}

// AdminGrantee 返回「登录用户即管理员」这一当前策略下的授予集合。
//
// 单用户面板阶段：能登录进来就是管理员，因此授予全部服务权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckServicePermission 判断某用户能否对服务执行某操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckServicePermission(g Grantee, action Action) Decision {
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
				"登录用户默认拥有全部服务权限；若你看到此提示，说明账号权限已被收窄。",
			required),
	}
}
