package file

import (
	"fmt"
	"strings"
)

// ============================================================================
// 文件操作的权限判定（阶段四 4.2）
// ============================================================================
//
// 与 internal/service 的 permission.go 同构，理由也完全相同：
//
//	RequireAuth 保证的是「**登录了**」，权限判定保证的是「**有权限碰文件**」。
//	若面板自身的写操作绕过判定，就会出现一条特权路径——将来引入只读用户时，
//	这条路径就是补不上的洞。因此核心自带的写操作也统一走一次判定并留痕。
//
// 权限命名沿用同一套语法（<域>.<动作>）：
//
//	file.read    查看目录、下载、读取文本内容
//	file.write   新建目录、上传、保存、重命名、删除
//
// 刻意**不复用** service.Grantee：两者现在形状相同，但语义不同
// （一个描述"能操作哪些服务"，一个描述"能操作哪些文件"）。
// 直接复用会让将来加入「限制在某个根目录内」这类资源级权限时无从下手。
//
// 注意：路径白名单（Resolver）与权限判定是**两道独立的闸门**，
// 谁也替代不了谁：
//   - 白名单回答「这个路径能不能碰」（与用户无关，是部署策略）；
//   - 权限判定回答「这个用户能不能碰文件」（与路径无关，是账号策略）。
// 只有两道闸门都放行，操作才会真正落到文件系统上。

// 文件相关权限常量。
const (
	// PermRead 允许浏览目录、下载与读取文件内容。
	PermRead = "file.read"
	// PermWrite 允许新建目录、上传、保存、重命名、删除。
	PermWrite = "file.write"
)

// 文件操作动作（用于审计与日志的稳定标识）。
const (
	// ActionList 列出目录。
	ActionList = "list"
	// ActionRead 读取文件内容。
	ActionRead = "read"
	// ActionDownload 下载文件。
	ActionDownload = "download"
	// ActionWrite 保存文件内容。
	ActionWrite = "write"
	// ActionMkdir 新建目录。
	ActionMkdir = "mkdir"
	// ActionUpload 上传文件。
	ActionUpload = "upload"
	// ActionRename 重命名。
	ActionRename = "rename"
	// ActionDelete 删除。
	ActionDelete = "delete"
)

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的文件权限集合。
	Granted []string
}

// Has 判断是否被授予了某权限（大小写不敏感，允许配置里写成 File.Write）。
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

// RequiredPermission 返回某动作所需的权限。
//
// 读类动作（列目录/读/下载）只要 file.read；其余一律 file.write。
// 与服务的口径一致：删除与"新建"不再细分——能删文件的人当然也能建文件，
// 再切一刀只会让权限模型复杂到没人愿意配。
func RequiredPermission(action string) string {
	switch action {
	case ActionList, ActionRead, ActionDownload:
		return PermRead
	}
	return PermWrite
}

// AdminGrantee 返回「登录用户即管理员」这一当前策略下的授予集合。
//
// 这是**将来接入多用户/只读角色时唯一需要替换的地方**：
// 届时改为从配置或数据库读取角色即可，调用方一行都不用动。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// IsWriteAction 判断某动作是否属于写操作（需要记入审计）。
func IsWriteAction(action string) bool {
	return RequiredPermission(action) == PermWrite
}

// CheckFilePermission 判断某用户能否执行某文件动作。
//
// 纯函数、无副作用，便于单测穷举；审计由 server 层负责。
func CheckFilePermission(g Grantee, action string) Decision {
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
			"该操作需要权限 %s。当前面板为单管理员模式，登录用户默认拥有"+
				"全部文件权限；若你看到此提示，说明账号权限已被收窄。",
			required),
	}
}
