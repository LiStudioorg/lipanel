package terminal

import (
	"fmt"
	"strings"
)

// ============================================================================
// 终端操作的权限判定（阶段五 5.1）
// ============================================================================
//
// 与 internal/service（4.1）、internal/file（4.2）、internal/site（4.3）、
// internal/ssl（4.4）、internal/store（4.5）、internal/firewall（4.6）
// 的 permission.go 同构，理由相同：
//
//	RequireAuth 保证的是「登录了」，权限判定保证的是「有权限开终端」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——
//	将来引入只读用户时，这条路径就是补不上的洞。
//
// #################### 终端权限的语义 ####################
//
// 终端权限的能量等级是本面板中**唯一**与 4.5 商店、
// 4.6 防火墙并列的量级，但性质不同：
//
//	4.1 启停服务   —— 影响一个服务的可用性
//	4.2 读写文件   —— 影响若干文件的内容
//	4.3 改站点配置 —— 影响 nginx 的加载行为
//	4.4 申请证书   —— 影响 HTTPS 与 CA 配额
//	4.5 安装软件   —— 影响系统软件构成
//	4.6 改防火墙   —— 影响这台机器能否被访问到
//	5.1 开终端     —— **无任何限制地以服务账号身份执行任意命令**
//
// 最后一条的特殊性在于：**它是前面所有能力的超集**。
// 拿到终端的人可以用 `apt install` 装软件（等价 4.5）、
// 可以用 `iptables` 改防火墙（等价 4.6）、可以用 `cat`
// 读任意文件（等价 4.2，且不受白名单根目录约束）。
//
// 也就是说：4.1~4.6 的每一次权限判定，本质上都是在
// 「终端能力」之上切出的**受限子集**。而终端本身没有任何子集。
//
// #################### 由此得出的两个设计决定 ####################
//
// 1. **不复用任何已有权限**。
//    terminal.write 刻意**不**复用 store.write 或 firewall.write：
//    虽然它们都是高危，但"允许改防火墙"的授权意图
//    与"允许在这台机器上以 root 身份执行任意命令"完全不同。
//    复用的后果是：将来管理员想收回终端能力时，
//    会发现收回它等于同时收回了防火墙管理——授权变得不可细分。
//
// 2. **read 与 write 的分界线是"能不能拿到 shell"，而不是"看没看到东西"**。
//    列出会话 ID（read）不泄露任何能力：attach 会被
//    "会话绑定 owner"这一层拦住。因此读操作只需要 terminal.read。

// 终端相关权限常量。
const (
	// PermRead 允许查看终端状态、会话列表与审计。
	PermRead = "terminal.read"
	// PermWrite 允许创建与关闭终端会话（即取得一个 shell）。
	PermWrite = "terminal.write"
)

// 终端操作动作（用于审计与日志的稳定标识）。
const (
	// ActionStatus 查询终端服务状态。
	ActionStatus = "status"
	// ActionListSessions 查询会话列表。
	ActionListSessions = "list_sessions"
	// ActionAudit 查询审计。
	ActionAudit = "audit"
	// ActionConnect 建立 WebSocket 终端连接（attach 到一个会话）。
	ActionConnect = "connect"
	// ActionDisconnect 断开 WebSocket 连接。
	ActionDisconnect = "disconnect"
	// ActionCreate 创建会话。
	ActionCreate = "create_session"
	// ActionClose 关闭会话。
	ActionClose = "close_session"
)

// RequiredPermission 返回执行某操作所需的权限。
//
// 读操作（status/list_sessions/audit）要 terminal.read；
// 其余（创建、连接、断开、关闭）一律要 terminal.write。
//
// ########## 为什么 connect 是高危写操作 ##########
//
// 看起来 connect 只是"连上一个已经存在的会话"，
// 但 attach 成功后客户端就获得了该 shell 的**完整控制权**。
// 把它当读操作会导致：一个只有 terminal.read 的用户
// 可以 attach 到任何会话并执行任意命令——
// 那么 terminal.write 就形同虚设了。
func RequiredPermission(action string) string {
	switch action {
	case ActionStatus, ActionListSessions, ActionAudit:
		return PermRead
	}
	return PermWrite
}

// WritesSystem 表示该动作会改变系统状态（用于审计的醒目标记）。
//
// ########## 为什么 connect 不算"改变系统" ##########
//
// 这个标记回答的是"这一条审计记录是否意味着机器被改了"。
// connect 本身不改任何东西——**但它之后的每一条命令都会**。
// 因此这里如实返回 false，同时在审计里把 connect
// 记成一条**独立的、显眼的事件**（见 audit.go 的 SessionEvent），
// 让事后排查能定位到"这个时间点有一个 shell 被建立"。
func WritesSystem(action string) bool {
	switch action {
	case ActionCreate, ActionClose:
		return true
	}
	return false
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的终端权限集合。
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
	Allowed  bool     `json:"allowed"`
	Required string   `json:"required,omitempty"`
	Granted  []string `json:"granted,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// AdminGrantee 返回「登录用户即管理员」这一当前策略下的授予集合。
//
// 单用户面板阶段：能登录进来就是管理员，因此授予全部终端权限。
// 这个函数是**将来接入多用户时唯一需要替换的地方**。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// ReadOnlyGrantee 返回只读授予集合（供测试与将来的只读角色使用）。
func ReadOnlyGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead}}
}

// CanAttach 判断某用户能否 attach 到某会话。
//
// ########## 这是"会话不能被共享"的授权层 ##########
//
// 与防火墙的受保护端口判定一样，这条规则有**两个独立的执行点**：
//
//	授权层（本函数）：会话属于创建者，别人不能接管；
//	连接层（Session.Attach）：一个会话只能被 attach 一次。
//
// 两者防的是不同的东西，缺一不可：
//
//	授权层防"另一个用户接管我的会话"——即使他拿到了 ID；
//	连接层防"同一个用户开两个标签页"——这时授权层是放行的。
//
// 第二个场景看起来无害（都是同一个人），但它是真实的风险：
// 两个标签页同时向一个 shell 发输入，会交错成
// 谁也无法理解的命令（见 ErrSessionBusy 的注释）。
//
// 纯函数、无副作用，便于单测穷举。
func CanAttach(g Grantee, sessionOwner string) error {
	if !g.Has(PermWrite) {
		return fmt.Errorf("用户 %s 未被授予权限 %s", g.User, PermWrite)
	}
	if sessionOwner == "" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(g.User), strings.TrimSpace(sessionOwner)) {
		return fmt.Errorf("会话属于用户 %s，%s 不能接管他人的终端会话",
			sessionOwner, g.User)
	}
	return nil
}

// CheckTerminalPermission 判断某用户能否执行某终端操作。
//
// 纯函数、无副作用，便于单测穷举；调用方（server 层）负责记审计。
func CheckTerminalPermission(g Grantee, action string) Decision {
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
				"终端权限；若你看到此提示，说明账号权限已被收窄。"+
				"注意：Web 终端提供一个**无限制的命令行**，"+
				"它等价于以服务账号身份登录服务器，"+
				"能力覆盖文件管理、软件安装、防火墙等全部模块，"+
				"因此该权限被单独管控。", required),
	}
}
