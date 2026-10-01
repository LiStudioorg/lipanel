package backup

import (
	"fmt"
	"strings"
)

// ============================================================================
// 权限判定（阶段五 5.3）
// ============================================================================
//
// 与 4.1 service / 4.2 file / 4.6 firewall / 5.2 cron 完全同构：
//
//	backup.read    查看任务、备份清单、历史、下载、预览恢复内容
//	backup.write   增删改任务与存储配置、立即执行、恢复、删除备份
//
// ########## 为什么核心自带的功能也要过权限判定 ##########
//
// RequireAuth 保证「登录了」，权限判定保证「有权限做这件事」，这是两件事。
// 若面板自己的写操作绕过判定，就留下一条特权路径：插件调同类能力要申报
// 权限、面板自己却不用。将来引入只读用户时这条路径是补不上的洞。
// 因此这里统一走一次判定并留痕。
//
// 不复用 cron.Grantee：两者现在形状相同，但语义不同（一个描述「能改哪些
// 定时任务」，一个描述「能碰哪些备份」）。直接复用会让将来加入
// 「只能恢复、不能删除备份」这类资源级权限时无从下手。
//
// ########## 权限判定与路径白名单是两道独立的闸门 ##########
//
// 权限判定回答「这个用户能不能做备份操作」，与路径无关；
// file.Resolver 白名单回答「这个源路径/恢复目标能不能碰」，与用户无关。
// 只有两道闸门都放行，操作才会真正落到文件系统或远端存储上。

// 备份相关权限常量。
const (
	// PermRead 允许查看任务、备份清单、执行历史、下载与预览恢复内容。
	PermRead = "backup.read"
	// PermWrite 允许增删改任务与存储配置、立即执行、删除备份、恢复。
	PermWrite = "backup.write"
)

// Action 是操作类型（用于审计与日志的稳定标识）。
type Action string

const (
	// ActionList 查看任务列表 / 备份清单 / 状态。
	ActionList Action = "list"
	// ActionHistory 查看某任务的执行历史。
	ActionHistory Action = "history"
	// ActionCreate 新增任务。
	ActionCreate Action = "create"
	// ActionUpdate 编辑任务。
	ActionUpdate Action = "update"
	// ActionDelete 删除任务。
	ActionDelete Action = "delete"
	// ActionRun 立即执行一次备份。
	ActionRun Action = "run"
	// ActionDownload 下载一个备份文件。
	ActionDownload Action = "download"
	// ActionDeleteFile 删除一个备份文件。
	ActionDeleteFile Action = "delete_file"
	// ActionPreview 预览恢复内容（只读，不落盘）。
	ActionPreview Action = "restore_preview"
	// ActionRestore 执行恢复（**本模块唯一不可逆的动作**）。
	ActionRestore Action = "restore"
	// ActionStorageCreate 新增存储配置。
	ActionStorageCreate Action = "storage_create"
	// ActionStorageUpdate 编辑存储配置。
	ActionStorageUpdate Action = "storage_update"
	// ActionStorageDelete 删除存储配置。
	ActionStorageDelete Action = "storage_delete"
	// ActionStorageTest 测试存储连通性（会写入并删除一个探针对象）。
	ActionStorageTest Action = "storage_test"
)

// RequiredPermission 返回操作所需权限：只读动作 read，其余 write。
func RequiredPermission(a Action) string {
	switch a {
	case ActionList, ActionHistory, ActionPreview:
		return PermRead
	}
	return PermWrite
}

// Grantee 表示「谁在被校验」。
type Grantee struct {
	// User 是登录用户名。
	User string
	// Granted 是该用户被授予的备份权限集合。
	Granted []string
}

// Has 判断是否被授予某权限（大小写不敏感，容忍配置里写成 Backup.Write）。
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

// AdminGrantee：当前单管理员策略——能登录即拥有全部备份权限。
// 这是将来接入多用户时唯一需要替换的函数。
func AdminGrantee(user string) Grantee {
	return Grantee{User: user, Granted: []string{PermRead, PermWrite}}
}

// CheckBackupPermission 纯函数判定，调用方（server 层）负责记审计。
func CheckBackupPermission(g Grantee, a Action) Decision {
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
				"登录用户默认拥有全部备份权限；若看到此提示，说明账号权限已被收窄。",
			required),
	}
}
