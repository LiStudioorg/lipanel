package backup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"lipanel/internal/cron"
)

// ============================================================================
// 字段校验（阶段五 5.3）
// ============================================================================
//
// 与 5.2 的 internal/cron/validate.go 同构：所有拒绝都带字段名与原因，
// 接口层据此返回 400 + field，前端能把错误挂到具体表单项上。

// 字段上限（字节）。
const (
	// MaxNameLen 是任务名 / 存储名的字节上限。
	MaxNameLen = 100
	// MaxPathLen 是源路径 / 目标路径的字节上限。
	MaxPathLen = 500
	// MaxCommentLen 是备注的字节上限。
	MaxCommentLen = 200
	// MaxExprLen 是 cron 表达式的字节上限（与 cron.MaxExprLen 一致）。
	MaxExprLen = 200
	// MaxPrefixLen 是对象名前缀的字节上限。
	MaxPrefixLen = 120
	// MaxEndpointLen 是服务地址的字节上限。
	MaxEndpointLen = 300
	// MaxBucketLen 是桶名的字节上限。
	MaxBucketLen = 200
	// MaxSecretLen 是凭证字段的字节上限。
	MaxSecretLen = 500
)

// 保留策略的取值上限。
const (
	// MaxKeepCount 是保留份数上限。
	//
	// 不是"多多益善"：份数上限直接决定清理时要在远端列出多少个对象。
	// 给到 10000 而用户真填了，一次清理就会发出上万个 DELETE 请求。
	MaxKeepCount = 1000
	// MaxKeepDays 是保留天数上限（10 年）。
	MaxKeepDays = 3650
)

// 校验用的哨兵错误。
var (
	// ErrTaskNotFound 表示任务不存在。
	ErrTaskNotFound = errors.New("backup: 备份任务不存在")
	// ErrStorageNotFound 表示存储配置不存在。
	ErrStorageNotFound = errors.New("backup: 存储配置不存在")
	// ErrStorageInUse 表示存储配置仍被任务引用，不能删除。
	ErrStorageInUse = errors.New("backup: 存储配置仍被任务引用")
	// ErrConfirmRequired 表示缺少二次确认（接口层 → 428）。
	ErrConfirmRequired = errors.New("backup: 该操作需要二次确认")
	// ErrConfirmTextMismatch 表示确认文字不匹配（接口层 → 428）。
	ErrConfirmTextMismatch = errors.New("backup: 确认文字不匹配")
	// ErrEditConflict 表示乐观并发冲突（接口层 → 409）。
	ErrEditConflict = errors.New("backup: 配置已被外部修改")
	// ErrRunning 表示该任务此刻已有一次执行在进行（接口层 → 409）。
	ErrRunning = errors.New("backup: 该任务已有一次备份正在执行")
	// ErrTooLarge 表示超出体积/条目数上限。
	ErrTooLarge = errors.New("backup: 超出备份体积或条目数上限")
	// ErrCronUnavailable 表示无法把任务挂到 crontab 上。
	ErrCronUnavailable = errors.New("backup: 计划任务（crontab）当前不可用")
	// ErrArchiveUnsafe 表示归档含有不被允许恢复的条目（tar slip 等）。
	ErrArchiveUnsafe = errors.New("backup: 备份归档含有不安全条目")
	// ErrSourceUnavailable 表示源路径不可用。
	ErrSourceUnavailable = errors.New("backup: 备份源路径不可用")
)

// ValidationError 是字段级校验错误。
//
// 单独一个类型（而不是 fmt.Errorf 一个字符串）的原因：接口层需要
// 把 Field 塞进 JSON，前端才能把错误挂到对应输入框上。
type ValidationError struct {
	// Field 是出错的字段名（与 JSON 字段同名）。
	Field string `json:"field"`
	// Reason 是给用户看的原因。
	Reason string `json:"reason"`
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return "backup: " + e.Reason
	}
	return fmt.Sprintf("backup: 字段 %s 非法: %s", e.Field, e.Reason)
}

// invalid 构造一个字段级校验错误。
func invalid(field, format string, args ...any) *ValidationError {
	return &ValidationError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// ErrArchiveEntryUnsafe 描述归档里一个不可恢复的条目。
type ErrArchiveEntryUnsafe struct {
	Name   string
	Reason string
}

func (e *ErrArchiveEntryUnsafe) Error() string {
	return fmt.Sprintf("backup: 归档条目 %q 不安全: %s", e.Name, e.Reason)
}

// taskIDRe 是任务 / 存储 / 历史 id 的形态：12 位小写 hex。
//
// 严格限定形态的意义：id 会被拼进对象名与锁文件名，
// 一旦允许任意字符，"任务 id"就成了一个可以穿越路径的输入。
var taskIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// NewID 生成一个 12 位 hex 标识（与 5.2 的 NewJobID 同形态同来源）。
func NewID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("backup: 生成标识失败: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidateTaskID 校验任务 id 形态。
func ValidateTaskID(id string) error {
	if !taskIDRe.MatchString(id) {
		return invalid("id", "应为 12 位小写十六进制，实际收到 %q", id)
	}
	return nil
}

// MaxNameRunes 是任务名的字符数上限（用于提示，判定仍按字节）。
const MaxNameRunes = 60

// ValidateTask 校验任务输入，并返回规范化后的副本。
//
// expr 的**语义**校验不在这里：cron 表达式只有 internal/cron 那份解析器
// 说了算（前端也一样，绝不写第二份）。这里只做形态与字段级检查。
func ValidateTask(in TaskInput) (TaskInput, error) {
	out := in

	// ########## 零值归一化：没设 enabled 等于"启用" ##########
	//
	// Go 的零值是 false，若原样透传，"调用方忘了设"就变成
	// "任务被停用"——用户建完任务看到它躺在列表里，以为从此有备份，
	// 而它从第一天起就没跑过。备份的失败周期以月计。
	// 要真的停用，必须同时给出 DisableExplicit=true（接口层用
	// *bool 承接 JSON，省略即启用）。
	if !out.Enabled && !out.DisableExplicit {
		out.Enabled = true
	}

	out.Name = strings.TrimSpace(in.Name)
	if out.Name == "" {
		return out, invalid("name", "任务名不能为空（恢复时需要逐字输入它来确认）")
	}
	if len(out.Name) > MaxNameLen {
		return out, invalid("name", "任务名超过 %d 字节", MaxNameLen)
	}
	if strings.ContainsAny(out.Name, "\r\n\t") {
		return out, invalid("name", "任务名不能包含换行或制表符")
	}

	out.Type = strings.TrimSpace(in.Type)
	if out.Type == "" {
		out.Type = TypeFull
	}
	if out.Type != TypeFull {
		return out, invalid("type", "只支持 %q（本模块不做增量备份与快照）", TypeFull)
	}

	out.SourceType = strings.TrimSpace(in.SourceType)
	if out.SourceType == "" {
		out.SourceType = SourceDir
	}
	if out.SourceType != SourceDir && out.SourceType != SourceFile {
		return out, invalid("source_type", "只支持 dir 或 file，实际收到 %q", in.SourceType)
	}

	out.SourcePath = strings.TrimSpace(in.SourcePath)
	if out.SourcePath == "" {
		return out, invalid("source_path", "源路径不能为空")
	}
	if len(out.SourcePath) > MaxPathLen {
		return out, invalid("source_path", "源路径超过 %d 字节", MaxPathLen)
	}
	if strings.ContainsRune(out.SourcePath, 0) {
		return out, invalid("source_path", "源路径含 NUL 字节")
	}
	if !filepath.IsAbs(out.SourcePath) {
		// 刻意不支持相对路径：相对谁？面板的当前目录、还是用户的意图？
		// 路径校验最怕真相不止一个（与 4.2 同一理由）。
		return out, invalid("source_path", "源路径必须是绝对路径（以 / 开头）")
	}

	out.StorageID = strings.TrimSpace(in.StorageID)
	if out.StorageID == "" {
		return out, invalid("storage_id", "请选择目标存储")
	}
	if err := ValidateTaskID(out.StorageID); err != nil {
		return out, invalid("storage_id", "存储标识形态非法: %q", out.StorageID)
	}

	out.Prefix = strings.TrimSpace(in.Prefix)
	if len(out.Prefix) > MaxPrefixLen {
		return out, invalid("prefix", "前缀超过 %d 字节", MaxPrefixLen)
	}
	if err := validateKeyPrefix(out.Prefix); err != nil {
		return out, invalid("prefix", "%s", err.Error())
	}

	out.Expr = strings.TrimSpace(in.Expr)
	if out.Expr == "" {
		return out, invalid("expr", "请填写 cron 表达式")
	}
	if len(out.Expr) > MaxExprLen {
		return out, invalid("expr", "表达式超过 %d 字节", MaxExprLen)
	}
	if strings.ContainsAny(out.Expr, "\r\n\t") {
		return out, invalid("expr", "表达式不能包含换行或制表符")
	}
	// ########## 语义校验必须交给 cron 包，不能只查形态 ##########
	//
	// 只查"非空、不太长、没有换行"的话，"not a cron" 这种输入会被
	// 保存成功。后果不是一条报错，而是**一个永远不执行的备份任务**：
	// 用户在列表里看到它、以为数据有备份，直到需要恢复的那天才发现
	// 从第一天起就没跑过。备份这类功能的失败周期是以月计的。
	//
	// 用 cron 包那份解析器（而不是在这里再写一遍）还有第二个好处：
	// 界面上"下次执行时间"与保存时的判定永远一致。
	if _, err := cron.ValidateExpr(out.Expr); err != nil {
		return out, invalid("expr", "%s", strings.TrimPrefix(err.Error(), "cron: "))
	}

	out.Comment = strings.TrimSpace(in.Comment)
	if len(out.Comment) > MaxCommentLen {
		return out, invalid("comment", "备注超过 %d 字节", MaxCommentLen)
	}
	if strings.ContainsAny(out.Comment, "\r\n") {
		return out, invalid("comment", "备注不能包含换行")
	}

	out.KeepPolicy = strings.TrimSpace(in.KeepPolicy)
	if out.KeepPolicy == "" {
		out.KeepPolicy = KeepNone
	}
	switch out.KeepPolicy {
	case KeepNone:
		out.KeepCount, out.KeepDays = 0, 0
	case KeepCount:
		if out.KeepCount <= 0 {
			return out, invalid("keep_count", "按份数保留时必须填写大于 0 的份数")
		}
		if out.KeepCount > MaxKeepCount {
			return out, invalid("keep_count", "份数上限为 %d", MaxKeepCount)
		}
		out.KeepDays = 0
	case KeepDays:
		if out.KeepDays <= 0 {
			return out, invalid("keep_days", "按天数保留时必须填写大于 0 的天数")
		}
		if out.KeepDays > MaxKeepDays {
			return out, invalid("keep_days", "天数上限为 %d", MaxKeepDays)
		}
		out.KeepCount = 0
	default:
		return out, invalid("keep_policy", "只支持 none / count / days，实际收到 %q", in.KeepPolicy)
	}

	return out, nil
}

// validateKeyPrefix 校验对象名前缀。
//
// 前缀会被拼进对象名，因此它必须**结构上无法越界**：
// 允许的字符集足够宽（路径分段、字母数字、- _ .），但拒绝
// 绝对路径、`..` 段与反斜杠——与外部插件安装的 zip slip 同一纪律。
func validateKeyPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.ContainsRune(prefix, 0) {
		return errors.New("前缀含 NUL 字节")
	}
	if strings.Contains(prefix, "\\") {
		return errors.New("前缀不能包含反斜杠")
	}
	if strings.HasPrefix(prefix, "/") {
		return errors.New("前缀不能以 / 开头（它是相对存储根的位置）")
	}
	for _, seg := range strings.Split(prefix, "/") {
		if seg == ".." {
			return errors.New("前缀不能包含 .. 路径段")
		}
	}
	if prefix == "." {
		return errors.New("前缀不能是 .")
	}
	return nil
}

// ValidateStorage 校验存储配置输入。
//
// 不做网络连通性检查：那是 /api/backup/storages/test 的事。
// 保存配置与"这个配置此刻能不能连上"是两件事——把二者绑在一起，
// 用户就没法先把配置存下来、等网络恢复了再用。
func ValidateStorage(in StorageInput) (StorageInput, error) {
	out := in

	out.Name = strings.TrimSpace(in.Name)
	if out.Name == "" {
		return out, invalid("name", "存储名不能为空")
	}
	if len(out.Name) > MaxNameLen {
		return out, invalid("name", "存储名超过 %d 字节", MaxNameLen)
	}
	if strings.ContainsAny(out.Name, "\r\n\t") {
		return out, invalid("name", "存储名不能包含换行或制表符")
	}

	out.Type = strings.TrimSpace(in.Type)
	switch out.Type {
	case StorageLocal:
		out.Path = strings.TrimSpace(in.Path)
		if out.Path == "" {
			return out, invalid("path", "本地存储必须填写目录路径")
		}
		if len(out.Path) > MaxPathLen {
			return out, invalid("path", "路径超过 %d 字节", MaxPathLen)
		}
		if !filepath.IsAbs(out.Path) {
			return out, invalid("path", "本地存储路径必须是绝对路径")
		}
		if strings.ContainsRune(out.Path, 0) {
			return out, invalid("path", "路径含 NUL 字节")
		}
		// 本地存储的其它字段一律清空：留着只会让配置文件里
		// 出现一堆"看起来配了、其实没用"的字段，误导后来的人。
		out.Endpoint, out.Bucket, out.Region = "", "", ""
		out.AccessKey, out.Username, out.BasePath = "", "", ""
		out.PathStyle, out.InsecureSkipVerify = false, false
		if in.SecretKey != nil {
			empty := ""
			out.SecretKey = &empty
		}
		if in.Password != nil {
			empty := ""
			out.Password = &empty
		}
		return out, nil

	case StorageS3:
		out.Endpoint = strings.TrimSpace(in.Endpoint)
		out.Bucket = strings.TrimSpace(in.Bucket)
		out.Region = strings.TrimSpace(in.Region)
		out.AccessKey = strings.TrimSpace(in.AccessKey)
		out.BasePath = strings.Trim(strings.TrimSpace(in.BasePath), "/")

		if out.Endpoint == "" {
			return out, invalid("endpoint", "S3 必须填写服务地址（自建 MinIO 也要填）")
		}
		if len(out.Endpoint) > MaxEndpointLen {
			return out, invalid("endpoint", "服务地址超过 %d 字节", MaxEndpointLen)
		}
		if err := validateHTTPURL(out.Endpoint); err != nil {
			return out, invalid("endpoint", "%s", err.Error())
		}
		if out.Bucket == "" {
			return out, invalid("bucket", "S3 必须填写桶名")
		}
		if len(out.Bucket) > MaxBucketLen {
			return out, invalid("bucket", "桶名超过 %d 字节", MaxBucketLen)
		}
		if err := validateBucket(out.Bucket); err != nil {
			return out, invalid("bucket", "%s", err.Error())
		}
		if out.Region != "" && len(out.Region) > 64 {
			return out, invalid("region", "区域名过长")
		}
		if out.AccessKey == "" {
			return out, invalid("access_key", "S3 必须填写 Access Key ID")
		}
		if err := validateKeyPrefix(out.BasePath); err != nil {
			return out, invalid("base_path", "%s", err.Error())
		}
		out.Path, out.Username = "", ""
		if in.Password != nil {
			empty := ""
			out.Password = &empty
		}
		if in.SecretKey != nil {
			if len(*in.SecretKey) > MaxSecretLen {
				return out, invalid("secret_key", "凭证超过 %d 字节", MaxSecretLen)
			}
		}
		return out, nil

	case StorageWebDAV:
		out.Endpoint = strings.TrimSpace(in.Endpoint)
		out.Username = strings.TrimSpace(in.Username)
		out.BasePath = strings.Trim(strings.TrimSpace(in.BasePath), "/")

		if out.Endpoint == "" {
			return out, invalid("endpoint", "WebDAV 必须填写服务地址")
		}
		if len(out.Endpoint) > MaxEndpointLen {
			return out, invalid("endpoint", "服务地址超过 %d 字节", MaxEndpointLen)
		}
		if err := validateHTTPURL(out.Endpoint); err != nil {
			return out, invalid("endpoint", "%s", err.Error())
		}
		if err := validateKeyPrefix(out.BasePath); err != nil {
			return out, invalid("base_path", "%s", err.Error())
		}
		if out.Username == "" {
			return out, invalid("username", "WebDAV 必须填写用户名")
		}
		out.Path, out.Bucket, out.Region, out.AccessKey = "", "", "", ""
		out.PathStyle = false
		if in.SecretKey != nil {
			empty := ""
			out.SecretKey = &empty
		}
		if in.Password != nil {
			if len(*in.Password) > MaxSecretLen {
				return out, invalid("password", "凭证超过 %d 字节", MaxSecretLen)
			}
		}
		return out, nil

	default:
		return out, invalid("type", "只支持 local / s3 / webdav，实际收到 %q", in.Type)
	}
}

// validateHTTPURL 校验服务地址是 http/https 且没有查询串与片段。
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("服务地址无法解析: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("服务地址必须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return errors.New("服务地址缺少主机名")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		// 带查询串的 endpoint 只在少数 S3 兼容实现上"能用"，
		// 但会让签名与路径拼接的语义变得含混，不如明确拒绝。
		return errors.New("服务地址不能带查询串或片段")
	}
	return nil
}

// validateBucket 校验 S3 桶名形态（DNS 兼容规则的一个宽松子集）。
func validateBucket(bucket string) error {
	if strings.ContainsAny(bucket, "/\\ \t\r\n") {
		return errors.New("桶名不能包含斜杠、空格或空白字符")
	}
	if strings.Contains(bucket, "..") {
		return errors.New("桶名不能包含 ..")
	}
	if strings.HasPrefix(bucket, ".") || strings.HasSuffix(bucket, ".") {
		return errors.New("桶名不能以 . 开头或结尾")
	}
	return nil
}

// ValidateArchiveKey 校验对象名形态。
//
// 这是**远端删除/下载的唯一入口**校验：key 会直接拼进 URL 与
// 本地路径，因此必须是相对形态、不含 .. 段、不含控制字符。
// 与 4.2 的路径白名单同一思路——白名单之外一律拒绝，
// 而不是"过滤掉危险片段"。
func ValidateArchiveKey(key string) error {
	k := strings.TrimSpace(key)
	if k == "" {
		return invalid("key", "对象名不能为空")
	}
	if len(k) > MaxPathLen {
		return invalid("key", "对象名超过 %d 字节", MaxPathLen)
	}
	if strings.ContainsRune(k, 0) {
		return invalid("key", "对象名含 NUL 字节")
	}
	if strings.Contains(k, "\\") {
		return invalid("key", "对象名不能包含反斜杠")
	}
	if strings.HasPrefix(k, "/") {
		return invalid("key", "对象名不能以 / 开头")
	}
	for _, seg := range strings.Split(k, "/") {
		switch seg {
		case "":
			return invalid("key", "对象名不能包含空路径段")
		case ".", "..":
			return invalid("key", "对象名不能包含 %q 路径段", seg)
		}
	}
	return nil
}

// ArchiveName 生成一个归档对象名。
//
// ########## 名字里为什么内嵌时间戳且定长 ##########
//
// 它同时承担三件事：可读、**字典序即时间序**（保留策略因此不必
// 依赖远端 mtime——那在各家 S3 实现上并不一致）、以及可反查归属。
// 前缀里的任务 id 由面板生成，时间戳定长，因此整串名字
// 在结构上不可能被任务名里的字符改形状。
func ArchiveName(prefix, taskID string, t interface{ Format(string) string }) string {
	base := strings.Trim(prefix, "/")
	if base == "" {
		base = "lipanel"
	}
	return fmt.Sprintf("%s/%s-%s.tar.gz", base, taskID, t.Format("20060102-150405"))
}

// contains 判断 real 是否等于 base 或位于 base 之下。
//
// 与 internal/file 的 contains 同一实现与同一理由：
// 用 HasPrefix 会把 /home/us 误判为在 /home/user 之下。
func contains(base, real string) bool {
	rel, err := filepath.Rel(base, real)
	if err != nil {
		return false // 出错按"不包含"处理，方向是安全的
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// cleanArchiveEntryName 规范化归档条目的名字（仅用于展示与判定）。
func cleanArchiveEntryName(name string) string {
	return path.Clean(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
}
