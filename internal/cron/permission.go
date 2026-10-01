package cron

import (
	"fmt"
	"strings"
)

// ============================================================================
// 权限判定（阶段五 5.2）
// ============================================================================
//
// 与 4.1 service / 4.2 file / 4.6 firewall 完全同构：
//
//	cron.read    查看任务列表与执行日志
//	cron.write   新增 / 编辑 / 删除任务
//
// ########## 为什么核心自带的功能也要过权限判定 ##########
//
// RequireAuth 保证「登录了」，权限判定保证「有权限改 crontab」，
// 这是两件事。若面板自己的写操作绕过判定，就留下一条特权路径：
// 插件调同类能力要申报权限、面板自己却不用。将来引入多用户时
// 这条路径是补不上的洞。因此这里统一走一次判定并留痕。
//
// 不复用 plugin.PermissionSet：那套模型回答的是「某插件声明了哪些权限」，
// 面板没有「声明」这一步——它的权限来自「当前用户被授予了什么」。

// 权限常量。
const (
	// PermRead 允许查看任务列表与日志。
	PermRead = "cron.read"
	// PermWrite 允许增删改任务。
	PermWrite = "cron.write"
)

// Action 是操作类型。
type Action string

const (
	ActionList   Action = "list"
	ActionLogs   Action = "logs"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// RequiredPermission 返回操作所需权限：读操作 read，写操作 write。
func RequiredPermission(a Action) string {
	switch a {
	case ActionCreate, ActionUpdate, ActionDelete:
		return PermWrite
	}
	return PermRead
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	User    string
	Granted []string
}

// Has 判断是否被授予某权限。
func (g Grantee) Has(perm string) bool {
	for _, p := range g.Granted {
		if strings.EqualFold(strings.TrimSpace(p), perm) {
			return true
		}
	}
	return false
}

// Decision 是权限校验结论。
type Decision struct {
	Allowed  bool     `json:"allowed"`
	Required string   `json:"required,omitempty"`
	Granted  []string `json:"granted,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// AdminGrantee：当前单管理员策略——能登录即拥有全部计划任务权限。
// 这是将来接入多用户时唯一需要替换的函数。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckCronPermission 纯函数判定，调用方（server 层）负责记审计。
func CheckCronPermission(g Grantee, a Action) Decision {
	required := RequiredPermission(a)
	if g.Has(required) {
		return Decision{Allowed: true, Required: required,
			Granted: append([]string(nil), g.Granted...)}
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
				"登录用户默认拥有全部计划任务权限；若看到此提示，说明账号权限已被收窄。",
			required),
	}
}
