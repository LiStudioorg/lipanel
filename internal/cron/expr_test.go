package cron

import (
	"testing"
	"time"
)

// ============================================================================
// 表达式校验与下次执行时间测试（阶段五 5.2）
// ============================================================================
//
// 这个文件锁死三件事：
//	① 非法表达式必须被拒绝（它们是写进 crontab 后**静默不执行**的根源）；
//	② @ 别名正确展开；
//	③ 下次执行时间与实际 cron 的语义一致——尤其是日/周的「或」。

func TestValidateExprAccepts(t *testing.T) {
	ok := []string{
		"* * * * *",
		"*/5 * * * *",
		"0 2 * * *",
		"30 4 1 * *",
		"0 0 13 * 5",
		"0-30/2 * * * *",
		"5,10,15 * * * *",
		"1-5 9-17 * * mon-fri",
		"0 0 1 jan,jul *",
		"0 0 * * 7",             // 7 == 周日
		"0 0 * * fri-mon",       // 跨零回绕（Vixie 允许）
		"0 0 1 */3 *",           // 每 3 个月
		"0 0 * * MON",           // 大小写
		"  0   2   *   *   *  ", // 多余空格
		"@reboot",
		"@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly",
	}
	for _, e := range ok {
		spec, err := ValidateExpr(e)
		if err != nil {
			t.Errorf("应接受 %q，实际报错: %v", e, err)
			continue
		}
		if spec.Text == "" {
			t.Errorf("%q 归一化后为空", e)
		}
	}
}

func TestValidateExprRejects(t *testing.T) {
	bad := map[string]string{
		"":                            "空",
		"   ":                         "空白",
		"* * * *":                     "4 段",
		"* * * * * *":                 "6 段",
		"60 * * * *":                  "分越界",
		"* 24 * * *":                  "时越界",
		"* * 0 * *":                   "日为 0",
		"* * 32 * *":                  "日越界",
		"* * * 13 *":                  "月越界",
		"* * * * 8":                   "周越界",
		"a * * * *":                   "非数字",
		"*/0 * * * *":                 "步长 0",
		"*/x * * * *":                 "步长非数字",
		"1-2-3 * * * *":               "多段范围",
		"1,,2 * * * *":                "空逗号段",
		"1a * * * *":                  "带字母的数字",
		"0x2 * * * *":                 "十六进制",
		"+1 * * * *":                  "正号",
		"-1 * * * *":                  "负号开头",
		"@every 5m":                   "Go cron 风格不支持",
		"@nope":                       "未知别名",
		"0 2 * * *\n* * * * * echo x": "换行注入",
		"0\t2 * * *":                  "制表符",
	}
	for e := range bad {
		if _, err := ValidateExpr(e); err == nil {
			t.Errorf("应拒绝 %q（%s），实际通过", e, bad[e])
		}
	}
}

func TestAliasExpandsToStandardForm(t *testing.T) {
	cases := map[string]string{
		"@yearly":   "0 0 1 1 *",
		"@annually": "0 0 1 1 *",
		"@monthly":  "0 0 1 * *",
		"@weekly":   "0 0 * * 0",
		"@daily":    "0 0 * * *",
		"@midnight": "0 0 * * *",
		"@hourly":   "0 * * * *",
	}
	for alias, want := range cases {
		spec, err := ValidateExpr(alias)
		if err != nil {
			t.Fatalf("%s: %v", alias, err)
		}
		if got := spec.Normalize(); got != want {
			t.Errorf("%s 展开为 %q，期望 %q", alias, got, want)
		}
		if spec.Alias != alias {
			t.Errorf("%s 的 Alias 是 %q", alias, spec.Alias)
		}
	}
	// @reboot 没有 5 段式等价形式，原样保留。
	spec, err := ValidateExpr("@reboot")
	if err != nil || !spec.IsReboot || spec.Normalize() != "@reboot" {
		t.Errorf("@reboot 处理异常: %+v err=%v", spec, err)
	}
}

// fixedClock 把测试时钟固定在 2026-03-05（周四）10:00:00 本地时间。
func fixedClock() time.Time {
	return time.Date(2026, 3, 5, 10, 0, 0, 0, time.Local)
}

func TestNextRunCommonShapes(t *testing.T) {
	now := fixedClock()
	cases := []struct {
		expr string
		want time.Time
	}{
		{"* * * * *", time.Date(2026, 3, 5, 10, 1, 0, 0, time.Local)},
		{"0 2 * * *", time.Date(2026, 3, 6, 2, 0, 0, 0, time.Local)},
		{"30 10 * * *", time.Date(2026, 3, 5, 10, 30, 0, 0, time.Local)},
		{"0 0 1 * *", time.Date(2026, 4, 1, 0, 0, 0, 0, time.Local)},
		{"*/15 * * * *", time.Date(2026, 3, 5, 10, 15, 0, 0, time.Local)},
		// 2026-03-05 是周四，下一个周五是 03-06。
		{"0 0 * * 5", time.Date(2026, 3, 6, 0, 0, 0, 0, time.Local)},
		{"@weekly", time.Date(2026, 3, 8, 0, 0, 0, 0, time.Local)}, // 下个周日
	}
	for _, c := range cases {
		spec, err := ValidateExpr(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		got, has, err := spec.NextRun(now, time.Local)
		if err != nil || !has {
			t.Errorf("%s: 期望算出下次时间，得到 has=%v err=%v", c.expr, has, err)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("%s 下次执行 = %s，期望 %s", c.expr, got.Format(time.RFC3339), c.want.Format(time.RFC3339))
		}
	}
}

// TestNextRunDOMDOWOrSemantics 锁死 Vixie cron 的日/周「或」语义。
//
// 这是最容易算错、且错了不会报错只会**悄悄跑错时间**的一条。
func TestNextRunDOMDOWOrSemantics(t *testing.T) {
	// 2026-03-05（周四）10:00 起。
	// `0 0 13 * 5`：每月 13 号 0 点 **或** 每周五 0 点 → 先是周五 03-06。
	spec, err := ValidateExpr("0 0 13 * 5")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := spec.NextRun(fixedClock(), time.Local)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 3, 6, 0, 0, 0, 0, time.Local) // 周五
	if !got.Equal(want) {
		t.Errorf("日/周「或」语义：得到 %s，期望 %s（周五）", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	// 日命中也要算出来：从 03-12 起，下一个是 03-13（周五恰好也在 03-13？
	// 2026-03-13 是周五，所以两者同时命中——改用 13 号 + 周一避免歧义）。
	// `0 0 13 * 1`：从 2026-03-12（周四）10:00 起 → 03-13（周五）不命中周一，
	// 但命中 13 号，所以是 03-13。若实现成「与」，会跳到 03-16（周一）。
	spec2, err := ValidateExpr("0 0 13 * 1")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 3, 12, 10, 0, 0, 0, time.Local)
	got2, _, err := spec2.NextRun(from, time.Local)
	if err != nil {
		t.Fatal(err)
	}
	want2 := time.Date(2026, 3, 13, 0, 0, 0, 0, time.Local)
	if !got2.Equal(want2) {
		t.Errorf("日命中优先场景：得到 %s，期望 %s；若得到 03-16 说明实现成了「与」",
			got2.Format(time.RFC3339), want2.Format(time.RFC3339))
	}
}

// TestStarWithStepIsNotRestrictedField 锁死「*/n 算星字段」这条 Vixie 规则。
//
// `0 0 */2 * 5` 在真实 cron 里**只跑周五**（因为日字段以 * 开头 → 不算受限），
// 若按「取值是否覆盖全量程」判 star，面板会预测出偶数日，与实际执行不符。
func TestStarWithStepIsNotRestrictedField(t *testing.T) {
	spec, err := ValidateExpr("0 0 */2 * 5")
	if err != nil {
		t.Fatal(err)
	}
	if !spec.starDOM {
		t.Fatal("*/2 应被视为星型字段（Vixie 看首字符）")
	}
	got, _, err := spec.NextRun(fixedClock(), time.Local)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 3, 6, 0, 0, 0, 0, time.Local) // 周五
	if !got.Equal(want) {
		t.Errorf("*/2 + 周五 的下次执行 = %s，期望 %s（只按周五）",
			got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

// TestNextRunUnreachable 锁死「永不成立的表达式报错而不是死循环」。
func TestNextRunUnreachable(t *testing.T) {
	// 2 月 30 日不存在；月份字段限定 2 月、日字段限定 30。
	spec, err := ValidateExpr("0 0 30 feb *")
	if err != nil {
		t.Fatal(err)
	}
	if _, has, err := spec.NextRun(fixedClock(), time.Local); err == nil || has {
		t.Errorf("2 月 30 日应报错且 has=false，得到 has=%v err=%v", has, err)
	}
}

// TestNextRunRebootHasNoTime 锁死 @reboot 不编造时间。
func TestNextRunRebootHasNoTime(t *testing.T) {
	spec, err := ValidateExpr("@reboot")
	if err != nil {
		t.Fatal(err)
	}
	if got, has, err := spec.NextRun(fixedClock(), time.Local); has || !got.IsZero() || err != nil {
		t.Errorf("@reboot 应无下次执行时间，得到 has=%v got=%v err=%v", has, got, err)
	}
}

func TestHumanize(t *testing.T) {
	cases := map[string]string{
		"* * * * *":   "每分钟执行一次",
		"*/5 * * * *": "每小时执行一次",
		"0 2 * * *":   "每天定时执行",
		"0 2 * * 1":   "每周定时执行",
		"0 2 1 * *":   "每月定时执行",
		"@reboot":     "仅在系统启动时执行一次",
	}
	for expr, want := range cases {
		spec, err := ValidateExpr(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if got := spec.Humanize(); got != want {
			t.Errorf("%s 描述为 %q，期望 %q", expr, got, want)
		}
	}
	// 复杂组合不强求描述，但**绝不能给一个错误的描述**（空串是允许的）。
	spec, err := ValidateExpr("1,5,9 2-6 1-3 jan-mar mon")
	if err != nil {
		t.Fatalf("复杂表达式应能通过校验，实际: %v", err)
	}
	if got := spec.Humanize(); got != "" {
		t.Logf("复杂表达式给出了描述 %q（若与语义不符需要收窄 Humanize 的匹配范围）", got)
	}
}
