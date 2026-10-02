package logs

import (
	"fmt"
	"strings"
)

// ============================================================================
// 日志查看的权限判定（阶段五 5.4.1）
// ============================================================================
//
// 与 4.1~4.6、5.1~5.3 的核心自带模块完全一致的模型（见 internal/service/
// permission.go 的详细论证）：
//
//   - 权限命名复用 internal/plugin 的 `<域>.<动作>` 语法与语义；
//   - 面板自身同样走一次判定并留痕，绝不留下"特权路径"；
//   - 判定是纯函数无副作用，留痕由调用方（server 层）负责。

// 日志相关权限常量。
const (
	// PermRead 允许查看日志源与查询日志。
	PermRead = "log.read"
)

// Grantee 表示"谁在被校验"。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是授予的权限集合。当前单管理员模式为 AdminGrantee 的全部。
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

// Action 表示一次日志操作。
type Action string

const (
	// ActionList 是列出日志源。
	ActionList Action = "list"
	// ActionQuery 是查询日志。
	ActionQuery Action = "query"
)

// RequiredPermission 返回某操作所需权限。
func RequiredPermission(action Action) string {
	return PermRead
}

// AdminGrantee 返回当前单管理员策略下的授予集合。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead}}
}

// CheckLogPermission 判断能否对日志执行某操作。
func CheckLogPermission(g Grantee, action Action) Decision {
	required := RequiredPermission(action)
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
		Hint: "该操作需要权限 log.read。当前面板为单管理员模式，" +
			"登录用户默认拥有该权限；若你看到此提示，说明账号权限已被收窄。",
	}
}
