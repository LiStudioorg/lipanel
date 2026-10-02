package notify

import (
	"fmt"
	"strings"
)

// ============================================================================
// 通知渠道的权限判定（阶段五 5.4.2）
// ============================================================================
//
// 与其它核心模块完全一致的模型：权限命名复用 internal/plugin 的
// `<域>.<动作>` 语法；面板自身走一次判定并留痕；判定是纯函数无副作用。

// 通知相关权限常量。
const (
	// PermRead 允许查看渠道（脱敏视图）。
	PermRead = "notify.read"
	// PermWrite 允许增删改渠道、测试发送。
	PermWrite = "notify.write"
)

// Grantee 表示"谁在被校验"。
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

// Action 表示一次通知操作。
type Action string

const (
	ActionList   Action = "list"
	ActionQuery  Action = "query"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionTest   Action = "test"
	ActionSend   Action = "send"
)

// RequiredPermission 返回某操作所需权限。
func RequiredPermission(action Action) string {
	switch action {
	case ActionCreate, ActionUpdate, ActionDelete, ActionTest, ActionSend:
		return PermWrite
	}
	return PermRead
}

// AdminGrantee 返回当前单管理员策略下的授予集合。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckNotifyPermission 判断能否执行某通知操作。
func CheckNotifyPermission(g Grantee, action Action) Decision {
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
		Hint: "该操作需要的权限与当前授予不符。当前面板为单管理员模式，" +
			"登录用户默认拥有全部通知权限；若你看到此提示，说明账号权限已被收窄。",
	}
}
