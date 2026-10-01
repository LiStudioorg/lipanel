package cron

import (
	"strings"
	"testing"
)

// ============================================================================
// crontab 文本解析测试（阶段五 5.2）
// ============================================================================
//
// 核心断言不是「能解析出几条」，而是**往返无损**：
// 解析 → 增删改 → 渲染，面板不认识的所有内容必须一字不差地还在原位置。
// 用户的手写 crontab 是他的资产，面板只是代管；
// 一次「顺手重排整个文件」的行为等于篡改用户资产。

// noScript 用于非面板任务的测试（没有包装脚本可读）。
func noScript(string) (string, bool) { return "", false }

// fakeScripts 返回一个从 map 读脚本的 reader。
func fakeScripts(m map[string]string) func(string) (string, bool) {
	return func(p string) (string, bool) {
		v, ok := m[p]
		return v, ok
	}
}

func TestParseTabMixedContent(t *testing.T) {
	content := `# 系统级设置，面板必须原样保留
MAILTO=admin@example.com
PATH=/usr/local/bin:/usr/bin:/bin

# 用户手写的一条任务
0 3 * * * /usr/local/bin/backup.sh
*/10 * * * * curl -s https://example.com/hb

@reboot /opt/start.sh
`
	tab := parseTab(content, "/data/jobs", "/data/logs", noScript)

	if len(tab.jobs) != 3 {
		t.Fatalf("应解析出 3 条任务，实际 %d: %+v", len(tab.jobs), jobsSummary(tab))
	}
	if len(tab.settings) != 2 {
		t.Errorf("应识别 2 条 ENV 设置，实际 %d", len(tab.settings))
	}
	// 非面板任务：managed=false、id 是派生的、命令取自行内原文。
	for _, j := range tab.jobs {
		if j.Managed {
			t.Errorf("%q 被误判为面板管理", j.Raw)
		}
		if !strings.HasPrefix(j.ID, "u-") {
			t.Errorf("%q 的 id %q 不是派生 id", j.Raw, j.ID)
		}
	}
	if tab.jobs[0].Command != "/usr/local/bin/backup.sh" {
		t.Errorf("命令切分错误: %q", tab.jobs[0].Command)
	}
	if tab.jobs[1].Expression != "*/10 * * * *" {
		t.Errorf("表达式切分错误: %q", tab.jobs[1].Expression)
	}
	if tab.jobs[2].Expression != "@reboot" || tab.jobs[2].Command != "/opt/start.sh" {
		t.Errorf("@reboot 行解析错误: %+v", tab.jobs[2])
	}
}

// TestParseTabTabSeparatedCommand 锁死制表符分隔不会吃掉命令开头。
//
// 用 strings.Fields + len() 推算偏移时，这一条必然失败——
// 它是一个**内容级静默错误**（面板显示的命令与真实执行的不同）。
func TestParseTabTabSeparatedCommand(t *testing.T) {
	content := "0\t2\t*\t*\t*\techo\tfirst second\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	if len(tab.jobs) != 1 {
		t.Fatalf("应解析出 1 条，实际 %d", len(tab.jobs))
	}
	if tab.jobs[0].Expression != "0 2 * * *" {
		t.Errorf("表达式 = %q", tab.jobs[0].Expression)
	}
	if tab.jobs[0].Command != "echo\tfirst second" {
		t.Errorf("命令被切错了: %q", tab.jobs[0].Command)
	}
}

func TestParseTabManagedJobReadsScript(t *testing.T) {
	scripts := map[string]string{"/data/jobs/aabbccddeeff.sh": "rsync -az /srv/ /backup/"}
	content := "# 面板添加\n# lipanel:aabbccddeeff 每晚同步\n0 1 * * * /bin/sh '/data/jobs/aabbccddeeff.sh'\n"
	tab := parseTab(content, "/data/jobs", "/data/logs", fakeScripts(scripts))
	if len(tab.jobs) != 1 {
		t.Fatalf("任务数 = %d", len(tab.jobs))
	}
	j := tab.jobs[0]
	if !j.Managed || j.ID != "aabbccddeeff" || j.Comment != "每晚同步" {
		t.Fatalf("面板任务识别失败: %+v", j)
	}
	if j.Command != "rsync -az /srv/ /backup/" {
		t.Errorf("命令应读自包装脚本，实际 %q", j.Command)
	}
	if j.ScriptPath != "/data/jobs/aabbccddeeff.sh" || j.LogPath != "/data/logs/aabbccddeeff.log" {
		t.Errorf("路径拼装错误: %+v", j)
	}
}

func TestParseTabManagedJobMissingScript(t *testing.T) {
	content := "# lipanel:112233445566 备注\n0 1 * * * /bin/sh '/data/jobs/112233445566.sh'\n"
	tab := parseTab(content, "/data/jobs", "/data/logs", noScript)
	j := tab.jobs[0]
	if !j.Managed || !j.CommandMissing {
		t.Fatalf("脚本缺失应标 CommandMissing，实际 %+v", j)
	}
	// 回退到行内原文（那指向脚本文件本身，至少不是空的）。
	if !strings.Contains(j.Command, "112233445566.sh") {
		t.Errorf("脚本缺失时应回退行内原文: %q", j.Command)
	}
}

// TestParseTabMarkerMustBeAdjacent 锁死「标记必须紧邻任务行」。
func TestParseTabMarkerMustBeAdjacent(t *testing.T) {
	content := "# lipanel:aabbccddeeff 孤儿标记\n# 中间隔了一行注释\n0 1 * * * echo hi\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	if len(tab.jobs) != 1 {
		t.Fatalf("任务数 = %d", len(tab.jobs))
	}
	if tab.jobs[0].Managed {
		t.Error("隔了其它行的标记不应关联到任务（会把无关任务误当成面板的）")
	}
}

// TestParseTabIgnoresForgedMarkerWithBadID 锁死伪造 id 的标记不生效。
func TestParseTabIgnoresForgedMarkerWithBadID(t *testing.T) {
	content := "# lipanel:../../etc/passwd 伪造\n0 1 * * * echo hi\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	if tab.jobs[0].Managed {
		t.Error("非 hex 形态的 id 不应被当作面板任务")
	}
	if strings.Contains(tab.jobs[0].ScriptPath, "..") {
		t.Error("路径里出现了 ..")
	}
}

// TestParseTabEnvIsNotCommand 锁死 MAILTO= 不被当成任务。
func TestParseTabEnvIsNotCommand(t *testing.T) {
	tab := parseTab("MAILTO=\"\"\n", "/d/jobs", "/d/logs", noScript)
	if len(tab.jobs) != 0 {
		t.Errorf("ENV 行不应成为任务: %+v", jobsSummary(tab))
	}
	if len(tab.settings) != 1 {
		t.Errorf("应记为设置行，实际 %d", len(tab.settings))
	}
}

// TestParseTabContinuationLine 锁死续行折叠为一个逻辑任务。
func TestParseTabContinuationLine(t *testing.T) {
	content := "0 2 * * * long-command \\\n  --flag value \\\n  --more\n0 3 * * * next.sh\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	if len(tab.jobs) != 2 {
		t.Fatalf("应折叠为 2 条任务，实际 %d: %+v", len(tab.jobs), jobsSummary(tab))
	}
	if !strings.Contains(tab.jobs[0].Raw, "--more") {
		t.Errorf("续行没被折叠进第一条: %q", tab.jobs[0].Raw)
	}
	if tab.jobs[0].startLine != 0 || tab.jobs[0].endLine != 2 {
		t.Errorf("行区间错误: [%d,%d]", tab.jobs[0].startLine, tab.jobs[0].endLine)
	}
}

// TestParseTabDuplicateUnmanagedLinesHaveDistinctIDs 锁死同内容两行有不同 id。
func TestParseTabDuplicateUnmanagedLinesHaveDistinctIDs(t *testing.T) {
	content := "0 5 * * * dup.sh\n0 5 * * * dup.sh\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	if tab.jobs[0].ID == tab.jobs[1].ID {
		t.Error("同内容两行的 id 相同，删除其一将无法定位")
	}
}

// TestDeriveIDStableAcrossLineShifts 锁死派生 id **不含行号**。
//
// 若在列表上方新增一条任务就让下面所有行的 id 变化，
// 用户的编辑会撞上假的并发冲突——假冲突比没这功能更糟。
func TestDeriveIDStableAcrossLineShifts(t *testing.T) {
	a := parseTab("0 5 * * * dup.sh\n", "/d/jobs", "/d/logs", noScript)
	b := parseTab("# 新增的注释\nMAILTO=x\n\n0 5 * * * dup.sh\n", "/d/jobs", "/d/logs", noScript)
	if a.jobs[0].ID != b.jobs[0].ID {
		t.Errorf("行号变化导致 id 漂移: %s vs %s", a.jobs[0].ID, b.jobs[0].ID)
	}
}

// TestRenderContentKeepsEverything 是往返无损的兜底断言。
func TestRenderContentKeepsEverything(t *testing.T) {
	content := "MAILTO=x\n#c\n0 1 * * * a.sh\n\nweird line\n"
	tab := parseTab(content, "/d/jobs", "/d/logs", noScript)
	got := renderContent(tab.lines)
	if got != content {
		t.Errorf("未触碰的行必须逐字节一致：\n got=%q\nwant=%q", got, content)
	}
	// 非空内容必须保证结尾换行（部分实现会丢弃无换行的最后一行）。
	if renderContent([]string{"a"}) != "a\n" {
		t.Error("结尾换行缺失")
	}
	if renderContent(nil) != "" {
		t.Error("空行切片应渲染为空串")
	}
}

func jobsSummary(tab *tab) []string {
	out := make([]string, 0, len(tab.jobs))
	for _, j := range tab.jobs {
		out = append(out, j.Raw)
	}
	return out
}
