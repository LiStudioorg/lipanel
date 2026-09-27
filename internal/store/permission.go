package store

import (
	"fmt"
	"strings"
)

// ============================================================================
// 软件商店操作的权限判定（阶段四 4.5）
// ============================================================================
//
// 与 internal/service（4.1）、internal/file（4.2）、internal/site（4.3）、
// internal/ssl（4.4）的 permission.go 同构，理由相同：
//
//	RequireAuth 保证的是「登录了」，权限判定保证的是「有权限装软件」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——
//	将来引入只读用户时，这条路径就是补不上的洞。
//
// #################### 装软件为什么是**最高危**的核心能力 ####################
//
// 本模块与其它四个模块有一个量级上的差别：
//
//	4.1 启停服务   —— 影响一个服务
//	4.2 读写文件   —— 影响若干文件
//	4.3 改站点配置 —— 影响 nginx 的加载行为
//	4.4 申请证书   —— 影响 HTTPS 与 CA 配额
//	4.5 安装软件   —— **以 root 身份运行发行版包管理器的安装脚本**
//
// 最后一条是本质区别：包的 postinst 脚本以 root 运行、可以改动
// 系统里的任何东西（这也是它能装上服务、创建用户、写 systemd unit 的原因）。
// 换句话说，"允许安装软件"等价于"允许在这台机器上以 root 执行
// 发行版仓库里的任意安装逻辑"。因此 store.write 的语义是
// "允许改变这台机器的软件构成"，而不是一个普通的写权限。
//
// 权限命名沿用同一套语法（<域>.<动作>）：
//
//	store.read    查看软件清单、版本列表、安装状态、任务进度、能力探测
//	store.write   安装 / 卸载软件（以 root 运行包管理器）
//
// 刻意**不复用** service.write：形状相同但语义不同
// （"能启停服务"和"能安装软件"是两种完全不同的授权，
// 后者能装上新的服务）。复用会让将来做细粒度授权时无从下手。

// 软件商店相关权限常量。
const (
	// PermRead 允许查看软件清单与安装状态。
	PermRead = "store.read"
	// PermWrite 允许安装与卸载软件。
	PermWrite = "store.write"
)

// 软件商店操作动作（用于审计与日志的稳定标识）。
const (
	// ActionList 查看软件清单（含每个软件的安装状态）。
	ActionList = "list"
	// ActionView 查看单个软件。
	ActionView = "view"
	// ActionCapabilities 环境能力探测（包管理器、发行版、官方源可用性）。
	ActionCapabilities = "capabilities"
	// ActionAudit 查看审计。
	ActionAudit = "audit"
	// ActionInstall 安装软件。
	ActionInstall = "install"
	// ActionUninstall 卸载软件。
	ActionUninstall = "uninstall"
	// ActionTask 查询任务进度。
	ActionTask = "task"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 读操作（list/view/capabilities/audit/task）要 store.read；
// 其余（install/uninstall）一律要 store.write。
func RequiredPermission(action string) string {
	switch action {
	case ActionList, ActionView, ActionCapabilities, ActionAudit, ActionTask:
		return PermRead
	}
	return PermWrite
}

// WritesSystem 表示该动作会改变系统状态（用于审计的醒目标记）。
func WritesSystem(action string) bool {
	return action == ActionInstall || action == ActionUninstall
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的软件商店权限集合。
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
// 单用户面板阶段：能登录进来就是管理员，因此授予全部软件商店权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckStorePermission 判断某用户能否执行某软件商店操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckStorePermission(g Grantee, action string) Decision {
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
				"软件商店权限；若你看到此提示，说明账号权限已被收窄。"+
				"注意：安装与卸载会以 root 身份运行发行版包管理器，"+
				"因此被单独管控。",
			required),
	}
}
