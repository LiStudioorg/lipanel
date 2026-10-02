package logs

import (
	"regexp"
	"strings"
)

// ============================================================================
// 日志行过滤（纯函数，便于单测穷举）
// ============================================================================
//
// 过滤发生在读取与截断之后、返回给前端之前：
//   读取原始行 → 截断到 Lines 上限 → 逐行过滤 → 返回
//
// 顺序很重要：先截断再过滤，保证「不管日志多大、过滤条件多宽，
// 最终只在最近 Lines 行里过滤」，从而把扫描量限制在请求行数内
// （否则一个大 access.log 全量扫一遍会拖死查询）。

// levelPriorities 把级别映射到数字优先级，用于级别过滤的"不低于某级别"语义。
// journald 的 -p 参数也是同一套数字（emerg=0..debug=7），此处保持一致，
// 便于「我们过滤器看到的」与「journalctl 底部限制的」概念一致。
var levelPriorities = map[string]int{
	"emerg": 0, "alert": 1, "crit": 2,
	"error": 3, "warn": 4, "warning": 4,
	"notice": 5, "info": 6, "debug": 7,
}

// normalizeLevel 把用户输入的级别映射为规范级别（error/warn/info/debug），
// 返回空串表示该输入不构成有效级别（调用方应视为不想过滤）。
// 未知级别（如 "verbose"）返回空串——宁可不过滤也不误判。
func normalizeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "crit", "err", "emergency", "emerg", "alert", "fatal", "error":
		return "error"
	case "warning", "warn":
		return "warn"
	case "notice", "info":
		return "info"
	case "debug", "trace":
		return "debug"
	}
	return ""
}

// journaldLevelFlag 返回传给 journalctl -p 的级别标志。
// 用的正是 normalizeLevel 的结果；空串返回空（不加 flag）。
func journaldLevelFlag(level string) string {
	return normalizeLevel(level)
}

// ValidLevel 判断一个级别是否被本模块支持（用于接口参数校验）。
func ValidLevel(level string) bool {
	return normalizeLevel(level) != ""
}

// logLevelPattern 匹配日志行里的级别关键字（[ERROR] 之类的方括号前缀）。
// 只用于纯文本的方式做"该行体现的严重程度"的粗判，
// 并不追求完美 —— 这是为了在**非 journald 且不支持级别过滤**的源上，
// 提供一个"看起来像 error 的行"的能力；精确的级别信息只来自 journald 的 -p。
var logLevelPattern = regexp.MustCompile(`(?i)\b(error|warn(ing)?|info|debug|critical|fatal)\b`)

// lineLevelPriority 估算一行日志的级别优先级（越低越严重）。
// 返回 -1 表示识别不出级别（等于没过滤）。
func lineLevelPriority(line string) int {
	// 方括号级别最常见：`[ERROR]`、`2024 E ...`。优先在行首 40 字符内匹配。
	head := line
	if len(head) > 48 {
		head = head[:48]
	}
	m := logLevelPattern.FindStringSubmatch(head)
	if len(m) > 1 {
		word := strings.ToLower(m[1])
		if word == "warning" || word == "warn" {
			word = "warn"
		}
		if p, ok := levelPriorities[word]; ok {
			return p
		}
	}
	return -1
}

// filterOptions 是一次过滤的约束。
type filterOptions struct {
	// Keyword 是大小写不敏感的子串过滤；空串表示不过滤。
	Keyword string
	// MinPriority 是非负时才生效：只保留"级别严重程度不低于该值"的行
	// （错误越严重数值越小）。仅对能识别出级别的行生效；
	// 识别不出级别的行行为由 KeepUnknown 决定。
	MinPriority int
	// KeepUnknown 为 true 时，识别不出级别的行**保留**（否则丢弃）。
	// 仅在请求了级别过滤时才有意义。
	KeepUnknown bool
	// HasLevelFilter 标记"请求了级别过滤"。区分"用户没开级别过滤"
	// 与"用户开了但同一条设置 KeepUnknown 有默认值"两件事。
	HasLevelFilter bool
}

// matches 判断一行是否通过过滤。
func (o filterOptions) matches(line string) bool {
	if o.Keyword != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(o.Keyword)) {
		return false
	}
	if o.HasLevelFilter && o.MinPriority >= 0 {
		p := lineLevelPriority(line)
		if p < 0 {
			return o.KeepUnknown
		}
		if p > o.MinPriority {
			return false
		}
	}
	return true
}

// defaultMaxLines / defaultMinLines 是行数参数的界限。
const (
	DefaultLines = 100
	MaxLines     = 2000
)

// clampLines 把用户请求的 Lines 收敛到 [1, MaxLines]。
func clampLines(lines int) int {
	if lines <= 0 {
		return DefaultLines
	}
	if lines > MaxLines {
		return MaxLines
	}
	return lines
}
