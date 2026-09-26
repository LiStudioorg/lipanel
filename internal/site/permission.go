package site

import (
	"fmt"
	"strings"
)

// ============================================================================
// 站点操作的权限判定（阶段四 4.3）
// ============================================================================
//
// 与 internal/service（4.1）、internal/file（4.2）的 permission.go 同构，
// 理由也完全相同：
//
//	RequireAuth 保证的是「**登录了**」，权限判定保证的是「**有权限改站点**」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——将来引入只读用户时，
//	这条路径就是补不上的洞。因此核心自带的写操作也统一走一次判定并留痕。
//
// 权限命名沿用同一套语法（<域>.<动作>）：
//
//	site.read    查看站点列表与配置
//	site.write   创建、编辑、删除、启用、禁用站点
//
// 刻意**不复用** service.Grantee / file.Grantee：三者的形状相同，
// 但语义不同（一个描述"能操作哪些服务"，一个描述"能碰哪些文件"，
// 一个描述"能改哪些站点"）。复用会让将来加入
// "只能管理某个域名的站点"这类资源级权限时无从下手。
//
// ⚠️ 权限判定与站点名校验是**两道独立的闸门**，谁也替代不了谁：
//   - 站点名校验回答「这个名字会不会破坏 nginx 配置」（与用户无关）；
//   - 权限判定回答「这个用户能不能改站点」（与名字无关，是账号策略）。

// 站点相关权限常量。
const (
	// PermRead 允许查看站点列表与配置内容。
	PermRead = "site.read"
	// PermWrite 允许创建、编辑、删除、启用、禁用站点。
	PermWrite = "site.write"
)

// 站点操作动作（用于审计与日志的稳定标识）。
const (
	// ActionList 列出站点。
	ActionList = "list"
	// ActionView 查看单个站点。
	ActionView = "view"
	// ActionCreate 创建站点。
	ActionCreate = "create"
	// ActionUpdate 编辑站点。
	ActionUpdate = "update"
	// ActionDelete 删除站点。
	ActionDelete = "delete"
	// ActionEnable 启用站点。
	ActionEnable = "enable"
	// ActionDisable 禁用站点。
	ActionDisable = "disable"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 只有 list/view 是读；其余五个写操作一律要求 site.write。
// 不做更细的区分（例如"只能禁用不能删除"）：在运维上没有实际意义，
// 却会让权限模型复杂到没人愿意配置（与 4.1 同样的取舍）。
func RequiredPermission(action string) string {
	switch action {
	case ActionList, ActionView:
		return PermRead
	}
	return PermWrite
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的站点权限集合。
	//
	// 当前实现：登录用户即管理员，Granted 为 [PermRead, PermWrite]。
	// 保留显式集合而不是"永远返回 true"，是为了让判定+留痕的链路
	// 在引入多用户时**不需要改动调用方**——届时只需换掉这一个来源。
	Granted []string
}

// Has 判断是否被授予了某权限（大小写不敏感，允许配置里写成 Site.Write）。
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
// 单用户面板阶段：能登录进来就是管理员，因此授予全部站点权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckSitePermission 判断某用户能否对站点执行某操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckSitePermission(g Grantee, action string) Decision {
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
				"登录用户默认拥有全部站点权限；若你看到此提示，说明账号权限已被收窄。",
			required),
	}
}
