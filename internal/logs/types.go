// Package logs 提供日志查看能力（阶段五 5.4.1，核心自带）。
//
// 本模块读取**系统日志**（journalctl，备选 /var/log/syslog、/var/log/messages）
// 与**应用日志**（Nginx access/error，路径来自 site 模块的 nginx prefix），
// 支持按关键词、级别、行数过滤。
//
// #################### 安全底线（本模块的重中之重） ####################
//
// 日志读取是「以面板身份读任意日志文件」能力。若开一个 ?path= 参数，
// 它就是「登录即可读这台机器上任何可读文件」的入口。
// 因此本模块**绝不允许外部传入任意路径**：
//
//   - 所有日志源都在一个**白名单**里登记（见 sources.go）；
//   - journalctl 一律用 `exec.CommandContext("journalctl", argv...)` 传
//     **argv 切片**，绝不拼 shell 字符串、绝不经 shell；
//   - Nginx 应用日志只允许 `<nginx logs 目录>/{access,error}.log` 两个
//     固定文件名，目录在构造时注入并校验、运行时不再接受输入。
//
// 行内容由后端原样返回（可含任意字符，**不做转义**——转义是渲染层
// 的职责，前端用 <pre> + 文本节点展示，禁止 v-html）：
// 若后端在返回前转义，"&lt;" 会以双重转义的形式展现在面板上，
// 既不美观也偏离"原样"语义。真实的安全边界在前端不使用 v-html。
package logs

import "time"

// SourceType 是日志源的类型。
type SourceType string

const (
	// SourceSystem 是系统日志源（journalctl，备选 syslog/messages）。
	SourceSystem SourceType = "system"
	// SourceApp 是应用日志源（Nginx access/error）。
	SourceApp SourceType = "app"
)

// Capability 描述一个日志源支持的能力，供前端据此渲染过滤控件。
type Capability struct {
	// Search 是否支持关键词过滤。
	Search bool `json:"search"`
	// Level 是否支持按级别过滤。
	Level bool `json:"level"`
	// InitialLines 是前端默认请求的行数。
	InitialLines int `json:"initial_lines"`
}

// Source 是一个可用的日志源。
type Source struct {
	// ID 是日志源标识，前端用它来查日志（system / nginx-access / nginx-error）。
	ID string `json:"id"`
	// Type 是日志源类型（system / app）。
	Type SourceType `json:"type"`
	// Name 是人类可读的名称（如「系统日志 (journald)」）。
	Name string `json:"name"`
	// Description 是来源说明，前端展示给用户。
	Description string `json:"description"`
	// Available 表示该源当前是否可读。不可读时不代表面板坏了
	// （可能是没装 journald / 没有 nginx），接口仍返回 200，由它如实说明。
	Available bool `json:"available"`
	// UnavailableReason 是 Available 为 false 时的具体原因与修复指引。
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Capability 是能力声明，指导前端渲染过滤控件。
	Capability Capability `json:"capability"`
}

// Entry 是一条日志记录。
type Entry struct {
	// Line 是日志原文（尾部换行已去掉）。
	Line string `json:"line"`
	// Timestamp 是提取到的时间戳（RFC3339，解析不到则为空）。
	// 仅用于前端可选展示，过滤与排序均不依赖它。
	Timestamp string `json:"timestamp,omitempty"`
}

// Query 是一次日志查询的参数。
type Query struct {
	// SourceID 是日志源 ID（白名单内）。
	SourceID string
	// Lines 是要读取的最大行数（读取端实际行数可能更多，返回端截断）。
	Lines int
	// Filter 是关键词过滤（大小写不敏感的子串匹配，空串不过滤）。
	Filter string
	// Level 是级别过滤，仅 system 源生效（error/warn/info/debug，空串不过滤）。
	Level string
	// Since 是相对时间过滤（仅 system 源生效，如 15m、1h）。
	Since time.Duration
}

// Result 是一次日志查询的结果。
type Result struct {
	// SourceID 是请求的日志源 ID。
	SourceID string `json:"source_id"`
	// Entries 是过滤后的日志条目，按时间先后排列，总数不超过请求的行数。
	Entries []Entry `json:"entries"`
	// Truncated 表示原始读取出的行数超过了请求的 Line 上限，
	// 已被截断（返回给了最新 Lines 行）。
	Truncated bool `json:"truncated"`
	// Scanned 是读取到的原始行数（过滤后返回给调用方必然是其中一部分）。
	Scanned int `json:"scanned"`
}
