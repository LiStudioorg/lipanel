package backup

import (
	"strings"
	"time"
)

// ============================================================================
// 数据模型（阶段五 5.3）
// ============================================================================

// 备份任务类型。
const (
	// TypeFull 是完整备份（本模块只做完整备份，增量/快照明确不做）。
	TypeFull = "full"
)

// 源类型。
const (
	// SourceDir 备份一个目录。
	SourceDir = "dir"
	// SourceFile 备份单个文件。
	SourceFile = "file"
)

// 存储类型。
const (
	// StorageLocal 本地目录。
	StorageLocal = "local"
	// StorageS3 S3 兼容对象存储（含 MinIO 等自建实现）。
	StorageS3 = "s3"
	// StorageWebDAV WebDAV 服务端。
	StorageWebDAV = "webdav"
)

// 保留策略模式。
const (
	// KeepNone 不清理（用户自己管）。
	KeepNone = "none"
	// KeepCount 按份数保留最近 N 份。
	KeepCount = "count"
	// KeepDays 按天数保留最近 N 天内的备份。
	KeepDays = "days"
)

// 执行触发来源。
const (
	// TriggerManual 面板上的「立即执行」。
	TriggerManual = "manual"
	// TriggerCron 由 crontab 拉起的自调用子进程。
	TriggerCron = "cron"
	// TriggerTest 存储连通性测试（不产生备份）。
	TriggerTest = "test"
)

// Task 是一个备份任务。
//
// ########## 为什么 CronJobID 要存下来 ##########
//
// 备份任务在 crontab 上的落地形式是 5.2 的一条普通计划任务。
// 二者是**两份数据**（一份在 tasks.json，一份在 crontab），
// 必须记下对面那一半的 id，否则「改一个备份任务」只能靠命令文本
// 反查 crontab——而命令文本在用户面前是不可见的实现细节，
// 一旦格式调整，历史任务就再也对不上号了。
type Task struct {
	// ID 是 12 位 hex 的任务标识（与 5.2 的任务 id 同形态）。
	ID string `json:"id"`
	// Name 是任务名。恢复时必须逐字输入它才能继续（二次确认）。
	Name string `json:"name"`
	// Type 固定为 TypeFull（留字段是为了将来扩展时不改存储格式）。
	Type string `json:"type"`
	// SourceType 是 dir 或 file。
	SourceType string `json:"source_type"`
	// SourcePath 是要备份的绝对路径。
	SourcePath string `json:"source_path"`
	// StorageID 指向 Storage.ID。
	StorageID string `json:"storage_id"`
	// Prefix 是存储上的对象名前缀（可空，默认为任务 id）。
	Prefix string `json:"prefix,omitempty"`
	// Expr 是 cron 表达式（5 段式或 @ 别名）。
	Expr string `json:"expr"`
	// Comment 是备注。
	Comment string `json:"comment,omitempty"`
	// KeepPolicy 是保留策略：none / count / days。
	KeepPolicy string `json:"keep_policy"`
	// KeepCount 是保留份数（KeepPolicy=count 时生效）。
	KeepCount int `json:"keep_count,omitempty"`
	// KeepDays 是保留天数（KeepPolicy=days 时生效）。
	KeepDays int `json:"keep_days,omitempty"`
	// Enabled 为 false 时任务仍保留配置，但不挂到 crontab 上（只能手动执行）。
	Enabled bool `json:"enabled"`
	// CronJobID 是该任务在 crontab 上的 id（空表示未挂上）。
	CronJobID string `json:"cron_job_id,omitempty"`
	// CreatedAt / UpdatedAt 是 RFC3339 时间戳。
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// TaskView 是任务列表返回的元素：任务本体 + 派生字段。
//
// 派生字段由 Manager 每次列表时现算，**绝不落盘**：
// 「下次执行时间」与「上次执行结果」是随时间变化的事实，
// 存进配置文件就会立刻变成一份会说谎的缓存。
type TaskView struct {
	*Task
	// StorageName / StorageType 是目标存储的展示信息。
	StorageName string `json:"storage_name,omitempty"`
	StorageType string `json:"storage_type,omitempty"`
	// StorageMissing 表示引用的存储配置已不存在（此时任务必然执行失败）。
	StorageMissing bool `json:"storage_missing"`
	// SourceExists 表示源路径当前是否存在（不存在时执行必然失败）。
	SourceExists bool `json:"source_exists"`
	// SourceReason 是源路径不可用的原因。
	SourceReason string `json:"source_reason,omitempty"`
	// Valid / InvalidReason 是表达式的合法性。
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalid_reason,omitempty"`
	// Human 是表达式的中文描述（空表示不在常见模式里）。
	Human string `json:"human,omitempty"`
	// Reboot 表示 @reboot（没有日历意义上的下次执行时间）。
	Reboot bool `json:"reboot"`
	// NextRun / NextRunHas 是下次执行时间。
	NextRun    string `json:"next_run,omitempty"`
	NextRunHas bool   `json:"next_run_has"`
	// CronManaged 表示这条任务是否已挂到 crontab 上。
	CronManaged bool `json:"cron_managed"`
	// CronReason 说明为什么没挂上（cron 不可用 / 任务被停用 / 表达式非法）。
	CronReason string `json:"cron_reason,omitempty"`
	// Last 是最近一次执行记录（可能为空）。
	Last *HistoryEntry `json:"last,omitempty"`
	// LastStatus 是最近一次执行的状态（无记录时为空）。
	LastStatus string `json:"last_status,omitempty"`
	// Running 表示此刻是否有一次执行正在进行（锁被占）。
	Running bool `json:"running"`
	// BackupCount 是该任务在存储上的备份份数（列不出来时为 -1）。
	BackupCount int `json:"backup_count"`
}

// TaskInput 是新增/编辑任务的输入。
type TaskInput struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	SourceType string `json:"source_type"`
	SourcePath string `json:"source_path"`
	StorageID  string `json:"storage_id"`
	Prefix     string `json:"prefix"`
	Expr       string `json:"expr"`
	Comment    string `json:"comment"`
	KeepPolicy string `json:"keep_policy"`
	KeepCount  int    `json:"keep_count"`
	KeepDays   int    `json:"keep_days"`
	// Enabled 为 false 时任务仍保留配置，但不挂到 crontab 上（只能手动执行）。
	//
	// ########## 为什么新建任务必须显式传 true ##########
	//
	// Go 的零值是 false，于是"没传 enabled"会被默默当成"停用"。
	// 后果是用户建完一条备份任务、看到它躺在列表里，
	// 以为从此有备份了——而它从第一天起就没跑过。
	// 备份这类功能的失败周期以月计，等到需要恢复时才发现，
	// 那时数据已经没了。
	//
	// 接口层因此用 *bool 承接 JSON（见 server/backup_api.go 的
	// backupTaskRequest.toInput）：省略 = 启用，显式 false = 停用。
	// 这里再做一道防线：调用方若忘了设，ValidateTask 会把零值
	// 归一化成"启用"。要停用必须**显式**调用 Disabled 语义的输入。
	Enabled bool `json:"enabled"`
	// DisableExplicit 为 true 时，Enabled=false 才会被当成"停用"。
	// 它让"忘了设"与"明确要停用"在类型上区分得开。
	DisableExplicit bool `json:"-"`
	// ExpectedIDs 是乐观并发断言用的 id 集合（与 5.2 同一手法）。
	ExpectedIDs []string `json:"expected_ids"`
}

// Storage 是一个存储配置。
//
// ########## 凭证的存放与回显 ##########
//
// SecretKey / Password 以明文存在 <data>/tasks.json（权限 0600），
// 这与绝大多数面板的做法一致：面板必须以这些凭证自动执行备份，
// 因此它必须是**可还原的**——加密存储需要另一个密钥，而那个密钥
// 又得放在同一台机器上，除了制造"看起来加密了"的错觉之外没有收益。
//
// 真正的防线有三条，缺一不可：
//
//	① 文件权限 0600、目录 0700；
//	② **接口永不回显凭证**（Redacted 只给 "已设置" 与尾 4 位）；
//	③ 审计里也只记存储 id 与类型，绝不记凭证。
type Storage struct {
	// ID 是 12 位 hex 标识。
	ID string `json:"id"`
	// Name 是展示名。
	Name string `json:"name"`
	// Type 是 local / s3 / webdav。
	Type string `json:"type"`
	// Path 是本地存储的目录（Type=local）。
	Path string `json:"path,omitempty"`
	// Endpoint 是 S3/WebDAV 的服务地址。
	Endpoint string `json:"endpoint,omitempty"`
	// Bucket 是 S3 的桶名。
	Bucket string `json:"bucket,omitempty"`
	// Region 是 S3 区域（SigV4 签名需要；留空按 us-east-1）。
	Region string `json:"region,omitempty"`
	// AccessKey 是 S3 的 Access Key ID。
	AccessKey string `json:"access_key,omitempty"`
	// SecretKey 是 S3 的 Secret Access Key（**永不回显**）。
	SecretKey string `json:"secret_key,omitempty"`
	// PathStyle 为 true 时用 path-style 寻址（MinIO 等自建实现通常需要）。
	PathStyle bool `json:"path_style,omitempty"`
	// BasePath 是 WebDAV/本地存储下的基础路径。
	BasePath string `json:"base_path,omitempty"`
	// Username / Password 是 WebDAV 的 Basic 认证（**Password 永不回显**）。
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// InsecureSkipVerify 允许自签证书（自建 MinIO/WebDAV 常见）。
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// CreatedAt / UpdatedAt 是 RFC3339 时间戳。
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Redacted 返回凭证脱敏后的副本，**专供接口回显**。
//
// 它返回的是一个新结构（不是就地改），因此调用方绝无可能
// 因为"忘了复制"而把明文凭证写进 HTTP 响应。
// 尾 4 位刻意保留：用户要靠它确认「我填的是不是那一把钥匙」，
// 而这 4 位不足以推出完整凭证。
func (s Storage) Redacted() Storage {
	out := s
	out.SecretKey = ""
	out.Password = ""
	return out
}

// HasSecret 表示是否已设置 SecretKey。
func (s Storage) HasSecret() bool { return strings.TrimSpace(s.SecretKey) != "" }

// HasPassword 表示是否已设置 Password。
func (s Storage) HasPassword() bool { return strings.TrimSpace(s.Password) != "" }

// SecretTail 返回 SecretKey 的尾 4 位（用于「是不是那一把」的确认）。
func (s Storage) SecretTail() string { return tail4(s.SecretKey) }

// PasswordTail 返回 Password 的尾 4 位。
func (s Storage) PasswordTail() string { return tail4(s.Password) }

func tail4(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 4 {
		// 太短就整体不给：给出来等于把钥匙交出去。
		return ""
	}
	return v[len(v)-4:]
}

// StorageInput 是新增/编辑存储配置的输入。
//
// ########## 密钥字段为什么要区分「没传」与「传了空串」 ##########
//
// 编辑存储时前端拿不到原密钥（接口不回显），因此它提交的密钥字段
// 要么为空（= 我不改）、要么是新值。若把空串当成"清空密钥"，
// 用户改一下名字就会把密钥抹掉，下一次备份直接失败。
// 因此用 *string：nil = 不改动，非 nil = 采纳（含显式清空）。
type StorageInput struct {
	Name               string  `json:"name"`
	Type               string  `json:"type"`
	Path               string  `json:"path"`
	Endpoint           string  `json:"endpoint"`
	Bucket             string  `json:"bucket"`
	Region             string  `json:"region"`
	AccessKey          string  `json:"access_key"`
	SecretKey          *string `json:"secret_key"`
	PathStyle          bool    `json:"path_style"`
	BasePath           string  `json:"base_path"`
	Username           string  `json:"username"`
	Password           *string `json:"password"`
	InsecureSkipVerify bool    `json:"insecure_skip_verify"`
	// Confirm 用于删除存储配置（428 强制）。
	Confirm bool `json:"confirm"`
}

// HistoryStatus 是执行结果的状态。
const (
	// StatusOK 执行成功。
	StatusOK = "ok"
	// StatusFailed 执行失败。
	StatusFailed = "failed"
	// StatusRunning 已开始但未见结束（进程被 kill / 机器断电）。
	StatusRunning = "running"
	// StatusSkipped 因锁被占用等原因跳过（不是失败，但也没有备份产出）。
	StatusSkipped = "skipped"
)

// HistoryEntry 是一次执行记录。
type HistoryEntry struct {
	// ID 是本次执行的 12 位 hex 标识。
	ID string `json:"id"`
	// TaskID / TaskName 是任务标识与名字（名字冗余存一份：
	// 任务被删掉后历史仍然要能读懂"这是什么备份"）。
	TaskID   string `json:"task_id"`
	TaskName string `json:"task_name,omitempty"`
	// Trigger 是 manual / cron。
	Trigger string `json:"trigger"`
	// Status 是 ok / failed / running / skipped。
	Status string `json:"status"`
	// StartedAt / FinishedAt 是 RFC3339 时间戳。
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	// DurationMS 是耗时毫秒。
	DurationMS int64 `json:"duration_ms"`
	// StorageID / StorageType 是目标存储。
	StorageID   string `json:"storage_id,omitempty"`
	StorageType string `json:"storage_type,omitempty"`
	// ArchiveKey 是产出的对象名（失败时为空）。
	ArchiveKey string `json:"archive_key,omitempty"`
	// ArchiveBytes 是归档体积。
	ArchiveBytes int64 `json:"archive_bytes,omitempty"`
	// FileCount / TotalBytes 是打包的条目数与原始总字节数。
	FileCount  int   `json:"file_count,omitempty"`
	TotalBytes int64 `json:"total_bytes,omitempty"`
	// Skipped 是被跳过的条目数（符号链接、设备、读不了的文件）。
	Skipped int `json:"skipped,omitempty"`
	// Warnings 是打包过程中的告警（逐条给人看）。
	Warnings []string `json:"warnings,omitempty"`
	// Pruned 是本次保留策略清理掉的份数。
	Pruned int `json:"pruned,omitempty"`
	// PruneErrors 是清理失败的原因（清理失败不影响备份本身成功）。
	PruneErrors []string `json:"prune_errors,omitempty"`
	// Error 是失败原因（Status=failed 时必填）。
	Error string `json:"error,omitempty"`
	// User 是发起人（cron 触发时为空，如实留白而不是写个假的"系统"）。
	User string `json:"user,omitempty"`
}

// ArchiveEntry 是归档内的一个条目（预览用）。
type ArchiveEntry struct {
	// Name 是归档内的相对路径。
	Name string `json:"name"`
	// Size 是解压后的字节数。
	Size int64 `json:"size"`
	// Mode 是权限位的八进制展示。
	Mode string `json:"mode,omitempty"`
	// IsDir 表示目录条目。
	IsDir bool `json:"is_dir"`
	// Type 是 tar 条目类型（file/dir/symlink/...）。
	Type string `json:"type"`
	// Unsafe 为 true 表示该条目**不被允许恢复**（绝对路径、.. 段、
	// 符号链接、设备等）。预览必须把它显眼列出——用户有权知道
	// "这个包里有什么东西是我恢复不了的"。
	Unsafe  bool   `json:"unsafe"`
	Reason  string `json:"reason,omitempty"`
	Convert bool   `json:"convert,omitempty"`
}

// RestorePreview 是恢复预览的结果。
type RestorePreview struct {
	// Key 是被预览的归档。
	Key string `json:"key"`
	// TargetDir 是恢复目标目录。
	TargetDir string `json:"target_dir"`
	// Entries 是归档内容。
	Entries []ArchiveEntry `json:"entries"`
	// Total 是条目总数（可能大于 Entries 的长度，见 Truncated）。
	Total int `json:"total"`
	// Truncated 表示条目过多，只返回了前若干条。
	Truncated bool `json:"truncated"`
	// SafeCount / UnsafeCount 是可恢复 / 不可恢复的条目数。
	SafeCount   int `json:"safe_count"`
	UnsafeCount int `json:"unsafe_count"`
	// Conflicts 是与目标目录里已存在文件的冲突清单（会被覆盖）。
	Conflicts []string `json:"conflicts"`
	// ConflictCount 是冲突总数（Conflicts 可能被截断）。
	ConflictCount int `json:"conflict_count"`
	// TotalBytes 是归档内文件的总字节数。
	TotalBytes int64 `json:"total_bytes"`
	// ConfirmText 是恢复时必须逐字输入的文字（= 任务名）。
	ConfirmText string `json:"confirm_text"`
	// Danger 是给用户看的危险说明（后端生成，前端直接展示，
	// 避免"前端提示与后端实际行为不一致"）。
	Danger []string `json:"danger"`
	// Warnings 是归档自身的问题（跳过条目等）。
	Warnings []string `json:"warnings,omitempty"`
}

// RestoreResult 是恢复的执行结果。
type RestoreResult struct {
	Key         string   `json:"key"`
	TargetDir   string   `json:"target_dir"`
	Restored    int      `json:"restored"`
	Dirs        int      `json:"dirs"`
	Overwritten int      `json:"overwritten"`
	Skipped     int      `json:"skipped"`
	Bytes       int64    `json:"bytes"`
	Warnings    []string `json:"warnings,omitempty"`
	DurationMS  int64    `json:"duration_ms"`
}

// FileEntry 是备份清单里的一项（存储上的一个归档）。
type FileEntry struct {
	// Key 是对象名。
	Key string `json:"key"`
	// Name 是展示用的文件名。
	Name string `json:"name"`
	// Size 是字节数（未知时为 0 且 SizeKnown=false）。
	Size      int64 `json:"size"`
	SizeKnown bool  `json:"size_known"`
	// ModTime 是最后修改时间（RFC3339，未知时为空）。
	ModTime string `json:"mod_time,omitempty"`
	// TaskID / TaskName 是归属（能从 key 前缀反查出时填写）。
	TaskID   string `json:"task_id,omitempty"`
	TaskName string `json:"task_name,omitempty"`
	// StorageID / StorageType 是所在存储。
	StorageID   string `json:"storage_id"`
	StorageType string `json:"storage_type"`
	// LocalPath 是本地存储时的绝对路径（远端存储为空）。
	// 它由面板自己拼出来，**不接受任何外部输入**。
	LocalPath string `json:"local_path,omitempty"`
}

// Status 是模块运行状态（供 UI 说明「面板在往哪写备份」）。
type Status struct {
	// DataDir 是配置与历史所在目录。
	DataDir string `json:"data_dir"`
	// StorePath 是任务/存储配置文件路径。
	StorePath string `json:"store_path"`
	// SourceRoots 是允许作为备份源的白名单根目录。
	SourceRoots []string `json:"source_roots"`
	// RestoreRoots 是允许作为恢复目标的白名单根目录。
	RestoreRoots []string `json:"restore_roots"`
	// RestoreRootNarrow 为 true 表示恢复根是**收紧的默认值**
	// （不是管理员显式放开的），前端据此给出更醒目的说明。
	RestoreRootNarrow bool `json:"restore_root_narrow"`
	// TaskCount / StorageCount 是配置规模。
	TaskCount    int `json:"task_count"`
	StorageCount int `json:"storage_count"`
	// CronAvailable 表示 crontab 当前是否可读写。
	CronAvailable bool `json:"cron_available"`
	// CronReason 是 crontab 不可用的原因。
	CronReason string `json:"cron_reason,omitempty"`
	// CronMode 是 cron 模块的存取模式（crontab / file）。
	CronMode string `json:"cron_mode,omitempty"`
	// CronTarget 是 cron 模块的读写目标描述。
	CronTarget string `json:"cron_target,omitempty"`
	// Limits 是运行限制（前端据此提前提示）。
	Limits Limits `json:"limits"`
	// Audit 是审计统计。
	Audit AuditStats `json:"audit"`
}

// Limits 是模块的运行限制。
type Limits struct {
	ExecTimeoutSeconds int   `json:"exec_timeout_seconds"`
	HTTPTimeoutSeconds int   `json:"http_timeout_seconds"`
	MaxArchiveBytes    int64 `json:"max_archive_bytes"`
	MaxSourceBytes     int64 `json:"max_source_bytes"`
	MaxEntries         int   `json:"max_entries"`
	MaxHistoryEntries  int   `json:"max_history_entries"`
	PreviewMaxEntries  int   `json:"preview_max_entries"`
}

// nowRFC3339 返回当前时间的 RFC3339 表示。
func nowRFC3339(now func() time.Time) string {
	return now().Format(time.RFC3339)
}

// StorageTypeInfo 描述一种存储类型（供前端动态渲染表单）。
type StorageTypeInfo struct {
	// Type 是类型标识。
	Type string `json:"type"`
	// Label 是中文名。
	Label string `json:"label"`
	// Description 是一句话说明。
	Description string `json:"description"`
	// Fields 是该类型需要填写的字段名（前端据此动态显隐）。
	Fields []string `json:"fields"`
	// Builtin 表示无需额外依赖即可使用（本地存储）。
	Builtin bool `json:"builtin"`
	// DocsHint 是配置要点（例如 MinIO 需要 path-style）。
	DocsHint string `json:"docs_hint,omitempty"`
}

// StorageTypes 返回支持的存储类型清单。
//
// 由后端给出而不是前端写死：加一种存储时，前端的表单
// 会自动多出一个选项——这正是"新增能力不改前端"这条纪律。
func StorageTypes() []StorageTypeInfo {
	return []StorageTypeInfo{
		{
			Type:        StorageLocal,
			Label:       "本地目录",
			Description: "把归档写进本机的一个目录，不需要任何外部依赖。",
			Fields:      []string{"path", "base_path"},
			Builtin:     true,
			DocsHint: "请确保该目录所在分区有足够空间；归档会先写到 staging 目录再落地，因此两者都需要空间。",
		},
		{
			Type:        StorageS3,
			Label:       "S3 兼容对象存储",
			Description: "AWS S3、MinIO、Ceph 等一切兼容 S3 协议的对象存储。",
			Fields: []string{"endpoint", "bucket", "region", "access_key", "secret_key",
				"base_path", "path_style", "insecure_skip_verify"},
			DocsHint: "自建 MinIO 请勾选 path-style 寻址；区域留空按 us-east-1 处理。",
		},
		{
			Type:        StorageWebDAV,
			Label:       "WebDAV",
			Description: "Nextcloud、坚果云、群晖等 WebDAV 服务端。",
			Fields: []string{"endpoint", "base_path", "username", "password",
				"insecure_skip_verify"},
			DocsHint: "地址填到 WebDAV 根（例如 https://dav.example.com/remote.php/dav/files/user），不要带查询串。",
		},
	}
}

// KeepPolicyInfo 描述一种保留策略。
type KeepPolicyInfo struct {
	Policy      string `json:"policy"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// NeedsValue 表示需要额外填一个数字。
	NeedsValue bool   `json:"needs_value"`
	ValueField string `json:"value_field,omitempty"`
	MaxValue   int    `json:"max_value,omitempty"`
}

// KeepPolicies 返回保留策略清单（同样由后端给出，前端不写死）。
func KeepPolicies() []KeepPolicyInfo {
	return []KeepPolicyInfo{
		{
			Policy:      KeepNone,
			Label:       "不自动清理",
			Description: "所有备份都保留。**磁盘会被慢慢吃满**，需要你自己定期清理。",
		},
		{
			Policy:      KeepCount,
			Label:       "按份数保留",
			Description: "每次备份成功后，只保留最近 N 份，更早的自动删除。",
			NeedsValue:  true,
			ValueField:  "keep_count",
			MaxValue:    MaxKeepCount,
		},
		{
			Policy:      KeepDays,
			Label:       "按天数保留",
			Description: "保留最近 N 天内的备份，更早的自动删除（按归档名里的时间戳判定）。",
			NeedsValue:  true,
			ValueField:  "keep_days",
			MaxValue:    MaxKeepDays,
		},
	}
}
