package cron

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ============================================================================
// crontab 文本 ↔ 结构化任务（阶段五 5.2）
// ============================================================================
//
// crontab 是一个**行式文本文件**，里面常有面板之外的内容
// （用户手写的任务、MAILTO/PATH 等全局设置）。解析器的第一原则：
//
//	**任何不认识的原样保留，保存时逐行写回。**
//
// 所有增删改都是行级操作（替换某几行 / 删除某几行 / 追加两行），
// 而不是「解析成结构 → 重新序列化整个文件」。后者必然丢失注释、
// 空行与写法差异，等于面板悄悄改写了用户自己的 crontab。
//
// 面板管理的任务通过**标记注释**与任务行关联：
//
//	# lipanel:<12位hex id> <用户备注>
//	*/5 * * * * /bin/sh '/var/lib/lipanel/cron/jobs/<id>.sh'
//
// 为什么用注释：crontab 没有任何字段可以放元数据，注释是唯一
// 既保留信息又不影响 cron 执行的位置（也是各类面板的通行做法）。
// 非面板添加的行照常展示（managed=false），编辑它即「收编」
// （补标记注释并换成日志包装脚本），删除按行删除。
//
// 续行（行尾反斜杠）按 Vixie cron 语义折叠成一个逻辑行，
// 否则删除任务会留下半截续行——那会让 crontab 出现语法错误。

// markerRe 匹配面板标记注释：# lipanel:<id> [备注]
// id 只允许小写 hex（新增任务由 Manager 用 crypto/rand 生成）。
// 外部内容即使伪造标记，也过不了 Manager 的表达式校验与整文件回滚，
// 且文件名拼接前 id 必须先经过本正则的形态约束（见 scriptPathFor）。
var markerRe = regexp.MustCompile(`^#\s*lipanel:([0-9a-f]{6,32})(?:\s+(.*))?$`)

// managedIDRe 是面板生成 id 的形态（API 入参必须先过它再碰任何路径拼接）。
var managedIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// derivedIDRe 是非面板任务的派生 id 形态（见 deriveID）。
var derivedIDRe = regexp.MustCompile(`^u-[0-9a-f]{12}$`)

// envRe 匹配 crontab 的全局设置行（Vixie 语义：name=value，值到行尾）。
var envRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// Job 是一条面板视角的 crontab 任务。
type Job struct {
	// ID：面板任务用标记注释里的 id；非面板任务用「u-」前缀的派生 id
	// （由行号 + 行内容哈希得到）。派生 id 在增删行后会变化——
	// 这正是它「未被面板接管」的如实反映（接管后即换用稳定 id）。
	ID string `json:"id"`
	// Expression 是 cron 表达式（原样）。
	Expression string `json:"expression"`
	// Command 是命令原文：面板任务读自包装脚本（真实命令），
	// 非面板任务是 crontab 行里表达式之后的原文。
	Command string `json:"command"`
	// Comment 是备注（仅面板任务有；来自标记注释）。
	Comment string `json:"comment"`
	// Managed 表示该任务是否由面板生成/接管。
	Managed bool `json:"managed"`
	// Raw 是 crontab 原始行（续行已折叠；审计与 UI 展示实际内容）。
	Raw string `json:"raw"`
	// LineNo 是 1 起的起始行号（仅供展示；操作一律按 ID）。
	LineNo int `json:"line_no"`
	// Valid / InvalidReason / Human / NextRun* / Reboot 由 Manager 填充
	// （需要表达式解析与时钟），解析器本身只负责文本结构。
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalid_reason,omitempty"`
	Human         string `json:"human,omitempty"`
	NextRun       string `json:"next_run,omitempty"`
	NextRunHas    bool   `json:"next_run_has"`
	Reboot        bool   `json:"reboot"`
	// ScriptPath / LogPath 仅面板任务非空。
	ScriptPath string `json:"script_path,omitempty"`
	LogPath    string `json:"log_path,omitempty"`
	// CommandMissing 表示包装脚本丢失（数据目录被动过）：
	// 如实标出，而不是悄悄显示成一条空命令的任务。
	CommandMissing bool `json:"command_missing"`

	// startLine / endLine：该任务占据的物理行区间（0 起，含标记注释行）。
	// 行级改写全靠它，因此不导出、不进 JSON。
	startLine int
	endLine   int
}

// Setting 是一条 crontab 全局设置（MAILTO=... 等），只读展示。
type Setting struct {
	Raw    string `json:"raw"`
	LineNo int    `json:"line_no"`
}

// tab 是解析后的 crontab：物理行 + 任务视图 + 全局设置。
type tab struct {
	// lines 是逐行原文（改写时按区间替换，未触碰的行原样输出）。
	lines []string
	// jobs 按出现顺序排列。
	jobs []*Job
	// settings 是 ENV=值 行（只读，面板不碰）。
	settings []Setting
}

// parseTab 把 crontab 文本解析为 tab。永不失败——
// 单行的问题体现为该任务表达式非法（Valid=false 由 Manager 标注），
// 绝不让整个列表打不开。
//
// jobsDir/logsDir 用于给面板任务填 ScriptPath/LogPath；
// readScript 读取包装脚本内容（不存在时 ok=false）。
func parseTab(content string, jobsDir, logsDir string, readScript func(path string) (string, bool)) *tab {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	var lines []string
	if content != "" {
		lines = strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	}
	t := &tab{lines: lines}

	// pendingMarker：紧邻上一行若是面板标记则记下它。
	// 只认「紧邻」：中间隔了任何的行都不算（面板生成时保证紧邻）。
	type marker struct {
		id      string
		comment string
		idx     int
	}
	var pm *marker
	// unmanagedSeen 记录「同样内容的非面板行已经出现过几次」，
	// 用于给完全相同的重复行分配不同 id（否则删除其一无法定位是哪一行）。
	//
	// ########## 为什么 id 里不含行号 ##########
	//
	// 派生 id 会参与乐观并发断言（ExpectedJobIDs）。若把行号混进哈希，
	// 用户在列表**上方**新增一条任务就会让下面所有非面板行的 id 变化，
	// 于是「编辑一条没人动过的任务」也会报并发冲突——
	// 假冲突会让用户不敢用面板，比没这个功能更糟。
	// 用「内容 + 同内容序号」则只在**该行的内容真的变了**时才变，
	// 恰好就是并发断言想表达的语义。
	unmanagedSeen := map[string]int{}

	for i := 0; i < len(t.lines); i++ {
		raw := t.lines[i]
		trimmed := strings.TrimSpace(raw)

		switch {
		case trimmed == "":
			pm = nil

		case strings.HasPrefix(trimmed, "#"):
			if m := markerRe.FindStringSubmatch(trimmed); m != nil {
				pm = &marker{id: strings.ToLower(m[1]), comment: strings.TrimSpace(m[2]), idx: i}
			} else {
				pm = nil
			}

		case envRe.MatchString(trimmed):
			// Vixie 语义：赋值行的值延伸到行尾，不是命令。
			t.settings = append(t.settings, Setting{Raw: raw, LineNo: i + 1})
			pm = nil

		default:
			// 折叠续行：行尾 '\' 与后续行属于同一个逻辑任务（Vixie 语义）。
			// 不折叠的后果是删除任务时留下半截续行——crontab 会直接语法错误。
			start := i
			end := i
			joined := trimmed
			for strings.HasSuffix(joined, `\`) && end+1 < len(t.lines) {
				end++
				joined = strings.TrimSuffix(joined, `\`) + " " + strings.TrimSpace(t.lines[end])
			}
			i = end

			expr, cmd, ok := splitJobLine(joined)
			if !ok {
				pm = nil
				continue
			}
			job := &Job{
				Expression: expr,
				Command:    cmd,
				Raw:        joined,
				startLine:  start,
				endLine:    end,
			}
			// 标记必须紧邻任务块的首行才算关联。
			if pm != nil && pm.idx == start-1 {
				job.ID = pm.id
				job.Comment = pm.comment
				job.Managed = true
				job.startLine = pm.idx
				job.ScriptPath = scriptPathFor(jobsDir, pm.id)
				job.LogPath = logPathFor(logsDir, pm.id)
				if script, ok2 := readScript(job.ScriptPath); ok2 {
					job.Command = script
				} else {
					job.CommandMissing = true
				}
			} else {
				job.ID = deriveID(joined, unmanagedSeen[joined])
				unmanagedSeen[joined]++
			}
			job.LineNo = job.startLine + 1
			t.jobs = append(t.jobs, job)
			pm = nil
		}
	}
	return t
}

// splitJobLine 把一个逻辑任务行切成（表达式, 命令原文, ok）。
//
// 判定刻意宽松：真正的合法性判断交给 ValidateExpr，
// 这里只回答「它长得像不像一条任务行」——
// 不像的行（比如用户随手写的散文）原样保留、不出现在任务列表里。
//
// 逐字节扫描而不是 strings.Fields 后按下标切片：Fields 会把制表符也算
// 分隔符，用 len(field) 推算偏移在「空格/制表符混用」的行上会切错位置，
// 把命令开头切掉几个字符——一个静默的、内容级的错误。
func splitJobLine(line string) (expr, cmd string, ok bool) {
	if strings.HasPrefix(line, "@") {
		// @reboot / @daily / Go-cron 的 @every 等：1 段表达式。
		at := strings.Fields(line)[0]
		rest := strings.TrimSpace(line[len(at):])
		if rest == "" {
			return "", "", false
		}
		return at, rest, true
	}
	pos := 0
	var fields []string
	for n := 0; n < 5; n++ {
		for pos < len(line) && isSpaceByte(line[pos]) {
			pos++
		}
		start := pos
		for pos < len(line) && !isSpaceByte(line[pos]) {
			pos++
		}
		if pos == start {
			return "", "", false // 不足 5 段
		}
		fields = append(fields, line[start:pos])
	}
	cmd = strings.TrimSpace(line[pos:])
	if cmd == "" {
		return "", "", false // 5 段但没命令：crontab 里本就是语法错误
	}
	return strings.Join(fields, " "), cmd, true
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\v' || b == '\f'
}

// deriveID 给非面板任务生成展示与定位用的 id：行内容 + 同内容序号取哈希。
// 稳定性语义见 parseTab 里的注释（**不**含行号）。
func deriveID(raw string, ordinal int) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%d\x00%s", ordinal, raw)))
	return "u-" + hex.EncodeToString(h[:6])
}

// NewJobID 生成一个新的面板任务 id（12 位小写 hex）。
func NewJobID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cron: 生成任务 ID 失败: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// scriptPathFor / logPathFor 拼接面板任务文件路径。
//
// ⚠️ id 必须先通过 managedIDRe 形态校验——这两个函数是**唯一**把
// id 拼进文件名的地方，形态校验在这里兜底（调用方理论上已校验过），
// 双保险的原因：crontab 里的伪造标记注释也能决定这里的 id。
func scriptPathFor(jobsDir, id string) string {
	if !managedIDRe.MatchString(id) {
		return ""
	}
	return filepath.Join(filepath.Clean(jobsDir), id+".sh")
}

func logPathFor(logsDir, id string) string {
	if !managedIDRe.MatchString(id) {
		return ""
	}
	return filepath.Join(filepath.Clean(logsDir), id+".log")
}

// findJob 按 id 查找任务。
func (t *tab) findJob(id string) *Job {
	for _, j := range t.jobs {
		if j.ID == id {
			return j
		}
	}
	return nil
}

// renderContent 把行切片渲染回 crontab 文本（非空时保证结尾换行——
// crontab 最后一行没有换行符时部分实现会丢弃该行）。
func renderContent(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
