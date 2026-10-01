// Package cron 提供计划任务（crontab）的读取、解析、校验与增删改查
// （阶段五 5.2，核心自带）。
//
// 设计约束：
//   - 零新增依赖：表达式解析与下次执行时间计算全部手写（纯标准库）。
//   - 表达式解析器是纯函数，供后端校验、下次执行计算与（未来的）前端复用，
//     保证「面板上显示的下次执行时间」与「面板拒绝一个表达式的依据」
//     来自同一份语义，不会出现「校验放行、计算却算错」的漂移。
//   - 所有对 crontab 的读写都必须经过 Manager：先备份、失败回滚。
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// cron 表达式校验与下次执行时间计算
// ============================================================================
//
// 支持范围与 Vixie cron（Debian/Ubuntu 与 cronie 使用的实现）对齐：
//
//   - 5 段式：分(0-59) 时(0-23) 日(1-31) 月(1-12) 周(0-7，0 与 7 都是周日)；
//   - 字段形式：*、a、a-b、a-b/n、*/n、a/n（step 等价 a-max/n）、逗号列表；
//   - 数字外的别名：jan..dec、sun..sat（大小写不敏感）；
//   - @ 别名：@reboot @yearly @annually @monthly @weekly @daily @midnight
//     @hourly @every <dur>（@every 是 Go cron 风格，仅面板展示用，
//     写回 crontab 前必须展开为等价 5 段式——见 Normalize，故不接受其入库）。
//
// ########## 日/周 的「或」语义（最容易算错的地方） ##########
//
// Vixie cron 的经典行为：当「日」和「周」都被显式限定（都不是 *）时，
// 匹配条件是 日命中 **或** 周命中。例：`0 0 13 * 5` = 每月 13 号 0 点
// **加上** 每周五 0 点。多数自研解析器把它实现成「与」，
// 于是面板显示的下次执行时间和实际执行对不上——这类偏差比报错更危险，
// 因为用户会信任面板显示的时间。本实现按「或」处理，并与
// `13 * fri` 这类显式写法保持一致。
//
// @reboot 没有下次执行时间（由 cron 守护进程在系统启动时执行），
// NextRun 如实返回 has=false，而不是编造一个时间。

// 字段下标。
const (
	fieldMinute = iota
	fieldHour
	fieldDayOfMonth
	fieldMonth
	fieldDayOfWeek
	fieldCount
)

// 各字段取值范围（dayOfWeek 的 7 会被归一化为 0）。
type fieldRange struct {
	min, max int
	name     string
}

var fieldRanges = [fieldCount]fieldRange{
	{0, 59, "分钟"},
	{0, 23, "小时"},
	{1, 31, "日"},
	{1, 12, "月"},
	{0, 7, "星期"},
}

var (
	monthNames = map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}
	weekdayNames = map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	}
)

// ErrExprEmpty 表示表达式为空。
var ErrExprEmpty = errors.New("cron: 表达式为空")

// ErrExprFormat 表示表达式不是合法的 5 段式或 @ 别名。
type ErrExprFormat struct {
	Expr   string
	Reason string
}

func (e *ErrExprFormat) Error() string {
	return fmt.Sprintf("cron: 表达式 %q 不合法：%s", e.Expr, e.Reason)
}

// ExprSpec 是一条已校验的 cron 表达式（不可变）。
type ExprSpec struct {
	// Text 是归一化后的表达式（@ 别名已展开为标准 5 段式；
	// 别名原样保留在 Alias 中，便于 UI 显示更友好的形式）。
	Text string
	// Alias 是原始的 @ 别名（非别名表达式为空串）。
	Alias string
	// IsReboot 表示 @reboot：仅在系统启动时执行，没有下次执行时间。
	IsReboot bool

	// 每个字段一个 64 位位集合（0..62 足够容纳所有取值）。
	fields [fieldCount]uint64
	// starDOM / starDOW 记录「日/周」是否为通配，决定「或」语义是否生效。
	starDOM bool
	starDOW bool
}

// minuteBits 等便捷访问器（供测试与展开逻辑使用）。
func (s *ExprSpec) bits(f int) uint64 { return s.fields[f] }

// describes 判断位集合是否覆盖字段全量程（即等价于 *）。
func describes(allVals, bits uint64) bool { return bits == allVals }

// allValuesOf 返回某字段的完整取值位集合。
func allValuesOf(f int) uint64 {
	r := fieldRanges[f]
	if f == fieldDayOfWeek {
		// 0-6（7 归一化为 0）。
		return (1 << 7) - 1
	}
	// [min,max] 全量程。
	var mask uint64
	for v := r.min; v <= r.max; v++ {
		mask |= 1 << uint(v)
	}
	return mask
}

// ValidateExpr 校验表达式并返回归一化的 ExprSpec。
func ValidateExpr(expr string) (*ExprSpec, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, ErrExprEmpty
	}
	// 拒绝任何不可见字符：crontab 按行解析，一个多余的换行/制表符
	// 就可能把一行任务变成两行（注入面），因此白名单只允许空格与可见字符。
	for _, r := range trimmed {
		if r == '\n' || r == '\r' || r == '\t' {
			return nil, &ErrExprFormat{Expr: expr, Reason: "含有换行或制表符（可能被解析成多条任务）"}
		}
		if r < 0x20 {
			return nil, &ErrExprFormat{Expr: expr, Reason: "含有控制字符"}
		}
	}

	if strings.HasPrefix(trimmed, "@") {
		return validateAlias(trimmed)
	}

	fields := strings.Fields(trimmed)
	if len(fields) != fieldCount {
		return nil, &ErrExprFormat{Expr: expr,
			Reason: fmt.Sprintf("应为 5 段（分 时 日 月 周），实际是 %d 段", len(fields))}
	}

	spec := &ExprSpec{Text: strings.Join(fields, " ")}
	var parsed [fieldCount]uint64
	for i, f := range fields {
		bits, _, err := parseField(f, i)
		if err != nil {
			return nil, &ErrExprFormat{Expr: expr,
				Reason: fmt.Sprintf("%s字段 %q %s", fieldRanges[i].name, f, err.Error())}
		}
		parsed[i] = bits
		// ########## star 判定必须按 Vixie 的字面规则 ##########
		//
		// Vixie cron（Debian cronie 同源）在 load_entry 里看的是
		// 「字段原文首字符是否为 *」，而不是「取值是否覆盖全量程」：
		// `*/2` 算星字段（不触发日/周「或」），`1-31` 算受限字段。
		// 若按位集合等价来判 star，`0 0 */2 * 5` 的面板预测会变成
		// 「偶数日 ∪ 周五」，而真实 cron 只跑周五——
		// 预测与执行不一致比报错更危险（用户会相信面板显示的时间）。
		switch i {
		case fieldDayOfMonth:
			spec.starDOM = strings.HasPrefix(f, "*")
		case fieldDayOfWeek:
			spec.starDOW = strings.HasPrefix(f, "*")
		}
	}
	spec.fields = parsed
	return spec, nil
}

// validateAlias 处理 @ 开头的别名表达式。
func validateAlias(expr string) (*ExprSpec, error) {
	lower := strings.ToLower(expr)
	switch lower {
	case "@reboot":
		return &ExprSpec{Text: lower, Alias: lower, IsReboot: true}, nil
	case "@yearly", "@annually":
		return expandAlias(lower, "0 0 1 1 *")
	case "@monthly":
		return expandAlias(lower, "0 0 1 * *")
	case "@weekly":
		return expandAlias(lower, "0 0 * * 0")
	case "@daily", "@midnight":
		return expandAlias(lower, "0 0 * * *")
	case "@hourly":
		return expandAlias(lower, "0 * * * *")
	}
	return nil, &ErrExprFormat{Expr: expr,
		Reason: "不支持的 @ 别名（支持 @reboot/@yearly/@annually/@monthly/@weekly/@daily/@midnight/@hourly）"}
}

func expandAlias(alias, std string) (*ExprSpec, error) {
	spec, err := ValidateExpr(std)
	if err != nil {
		return nil, err
	}
	spec.Alias = alias
	return spec, nil
}

// Normalize 返回可安全写回 crontab 的表达式（@ 别名展开为标准 5 段式）。
//
// @reboot 没有 5 段式等价形式，原样返回。
func (s *ExprSpec) Normalize() string {
	if s.Alias != "" && !s.IsReboot {
		return s.Text // Text 存的就是扩展开的标准式
	}
	return s.Text
}

// Humanize 给出一条表达式的简短中文描述（用于确认弹窗与列表提示）。
// 尽力而为，不追求穷尽所有组合；模式不在常见集合里时返回空串，
// 让 UI 回退到展示原始表达式——**猜测出来的错误描述比没有描述更糟**。
func (s *ExprSpec) Humanize() string {
	if s.IsReboot {
		return "仅在系统启动时执行一次"
	}
	mi := describes(allValuesOf(fieldMinute), s.fields[fieldMinute])
	ho := describes(allValuesOf(fieldHour), s.fields[fieldHour])
	switch {
	case mi && ho && s.starDOM && s.starDOW:
		return "每分钟执行一次"
	case !mi && ho && s.starDOM && s.starDOW:
		return "每小时执行一次"
	case !mi && !ho && s.starDOM && s.starDOW:
		return "每天定时执行"
	case !mi && !ho && s.starDOM && !s.starDOW:
		return "每周定时执行"
	case !mi && !ho && !s.starDOM && s.starDOW:
		return "每月定时执行"
	default:
		return ""
	}
}

// parseField 解析单个字段，返回（取值位集合, 是否等价于全量程, 错误原因）。
//
// 错误以 error 返回「原因短语」，由调用方组装字段上下文，
// 让报错读起来像「小时字段 "25" 超出范围 0-23」而不是一个裸的 invalid。
func parseField(f string, idx int) (uint64, bool, error) {
	r := fieldRanges[idx]
	var bits uint64
	full := allValuesOf(idx)

	for _, part := range strings.Split(f, ",") {
		if part == "" {
			return 0, false, errors.New("含空的逗号分段")
		}
		b, err := parseRangeStep(part, idx, r)
		if err != nil {
			return 0, false, err
		}
		bits |= b
	}
	return bits, bits == full, nil
}

// parseRangeStep 解析 `*`、`a`、`a-b`、`*/n`、`a-b/n`、`a/n`。
func parseRangeStep(part string, idx int, r fieldRange) (uint64, error) {
	base := part
	step := 1
	if i := strings.IndexByte(part, '/'); i >= 0 {
		base = part[:i]
		n, err := strconv.Atoi(part[i+1:])
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("步长 %q 不是正整数", part[i+1:])
		}
		if base == "" {
			return 0, errors.New("步长前缺少范围")
		}
		step = n
	}

	var lo, hi int
	switch {
	case base == "*":
		lo, hi = r.min, r.max
	default:
		// 先按 '-' 切成两端再各自解析：反过来（先整体解析再找 '-'）
		// 会让所有范围写法（1-5、mon-fri、0-30/2）在解析单个值时就失败。
		if j := strings.IndexByte(base, '-'); j >= 0 {
			a, err := parseValue(base[:j], idx, r)
			if err != nil {
				return 0, err
			}
			b, err := parseValue(base[j+1:], idx, r)
			if err != nil {
				return 0, err
			}
			lo, hi = a, b
		} else {
			a, err := parseValue(base, idx, r)
			if err != nil {
				return 0, err
			}
			lo, hi = a, a
		}
	}

	// Vixie cron 允许跨零回绕（如 fri-mon），跟随其语义避免误拒合法写法。
	var bits uint64
	if lo <= hi {
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(normDOW(idx, v))
		}
	} else {
		for v := lo; v <= r.max; v += step {
			bits |= 1 << uint(normDOW(idx, v))
		}
		for v := r.min; v <= hi; v += step {
			bits |= 1 << uint(normDOW(idx, v))
		}
	}
	if bits == 0 {
		return 0, fmt.Errorf("范围 %s 在步长 %d 下没有任何取值", base, step)
	}
	return bits, nil
}

func normDOW(idx, v int) int {
	if idx == fieldDayOfWeek && v == 7 {
		return 0
	}
	return v
}

// parseValue 解析单个数值或名称，越界时报出**本字段**的范围。
func parseValue(s string, idx int, r fieldRange) (int, error) {
	if idx == fieldMonth {
		if m, ok := monthNames[strings.ToLower(s)]; ok {
			return m, nil
		}
	}
	if idx == fieldDayOfWeek {
		if d, ok := weekdayNames[strings.ToLower(s)]; ok {
			return d, nil
		}
	}
	// 纯数字才接受（拒绝 "1a"、"+1"、"0x2" 等形式）。
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("%q 不是合法取值（应为 %d-%d 的数字或英文缩写）", s, r.min, r.max)
		}
	}
	if s == "" {
		return 0, fmt.Errorf("取值为空（应为 %d-%d）", r.min, r.max)
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q 不是数字", s)
	}
	if v < r.min || v > r.max {
		return 0, fmt.Errorf("超出范围 %d-%d", r.min, r.max)
	}
	return v, nil
}

// NextRun 计算从 after（不含）开始的下次执行时间（本地时区）。
//
// 采用逐分钟推进 + 粗剪枝：先对齐到下一个整分钟，若月份不匹配则直接
// 跳到下月 1 日 00:00、日不匹配则跳到次日 00:00，避免逐年逐分钟暴力扫描；
// 上限 5 年，防止像 `0 0 30 feb` 这种永不成立的表达式把调用方卡死。
//
// @reboot 返回 has=false（由系统启动触发，不在日历里）。
func (s *ExprSpec) NextRun(after time.Time, loc *time.Location) (next time.Time, has bool, err error) {
	if s.IsReboot {
		return time.Time{}, false, nil
	}
	if loc == nil {
		loc = time.Local
	}

	t := after.In(loc).Truncate(time.Minute).Add(time.Minute)
	limit := t.Add(5 * 365 * 24 * time.Hour)

	for t.Before(limit) {
		month := int(t.Month())
		if s.fields[fieldMonth]&(1<<uint(month)) == 0 {
			// 月份不匹配：跳到下个月 1 号 00:00。
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
			t = t.AddDate(0, 1, 0)
			continue
		}
		domHit := s.fields[fieldDayOfMonth]&(1<<uint(t.Day())) != 0
		dowHit := s.fields[fieldDayOfWeek]&(1<<uint(int(t.Weekday()))) != 0
		// Vixie cron 的日/周判定，三种情形缺一不可：
		//	两侧都受限 → 取「或」；
		//	只一侧受限 → **只看受限的那侧**（另一侧恒真）；
		//	两侧都通配 → 恒真。
		// 把「或」无条件套用会在 dow=* 时恒真，
		// 让 `0 0 1 * *` 预测出「每天 0 点」这种离谱结果。
		var dayOK bool
		switch {
		case !s.starDOM && !s.starDOW:
			dayOK = domHit || dowHit
		case !s.starDOM:
			dayOK = domHit
		case !s.starDOW:
			dayOK = dowHit
		default:
			dayOK = true
		}
		if !dayOK {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)
			continue
		}
		if s.fields[fieldHour]&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, loc).Add(time.Hour)
			continue
		}
		if s.fields[fieldMinute]&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t, true, nil
	}
	return time.Time{}, false, fmt.Errorf("cron: 表达式 %q 在 5 年内没有任何匹配时间", s.Text)
}
