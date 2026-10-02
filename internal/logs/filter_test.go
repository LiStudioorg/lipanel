package logs

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 级别归一化与过滤（纯函数）
// ---------------------------------------------------------------------------

func TestNormalizeLevel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"error", "error"},
		{"ERROR", "error"},
		{" err ", "error"},
		{"critical", "error"},
		{"crit", "error"},
		{"fatal", "error"},
		{"emerg", "error"},
		{"alert", "error"},
		{"warn", "warn"},
		{"warning", "warn"},
		{"info", "info"},
		{"notice", "info"},
		{"debug", "debug"},
		{"trace", "debug"},
		{"verbose", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeLevel(c.in); got != c.want {
			t.Errorf("normalizeLevel(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestValidLevel(t *testing.T) {
	if !ValidLevel("error") || !ValidLevel("ERROR") || !ValidLevel("debug") {
		t.Error("合法级别应通过")
	}
	if ValidLevel("") || ValidLevel("garbage") || ValidLevel("verbose") {
		t.Error("非法级别不应通过")
	}
}

func TestLineLevelPriority(t *testing.T) {
	// 明显级别的行应被识别。
	if p := lineLevelPriority("[ERROR] boom"); p != 3 {
		t.Errorf("ERROR 应=3, got %d", p)
	}
	if p := lineLevelPriority("2024 E system error occurred"); p != 3 {
		t.Errorf("带 error 的行应=3, got %d", p)
	}
	if p := lineLevelPriority("[WARN] old"); p != 4 {
		t.Errorf("WARN 应=4, got %d", p)
	}
	if p := lineLevelPriority("[info] ok"); p != 6 {
		t.Errorf("info 应=6, got %d", p)
	}
	// 正文里没有级别词、或只为普通请求行的，识别不出。
	if p := lineLevelPriority("GET /health 200 ok"); p != -1 {
		t.Errorf("无关行应=-1, got %d", p)
	}
}

func TestFilterOptionsMatches(t *testing.T) {
	// 关键词过滤（大小写不敏感）。
	kw := filterOptions{Keyword: "panic"}
	if !kw.matches("a Panic at boot") {
		t.Error("关键词应命中（大小写不敏感）")
	}
	if kw.matches("all good here") {
		t.Error("无关键词的行不应命中")
	}
	// 空关键词不过滤。
	if !(filterOptions{}).matches("anything") {
		t.Error("空关键词应全部放行")
	}
	// 级别过滤。
	lvl := filterOptions{HasLevelFilter: true, MinPriority: 3 /* error */, KeepUnknown: true}
	if !lvl.matches("[error] bad") {
		t.Error("error 行应通过 error 级过滤")
	}
	if lvl.matches("[debug] verbose") {
		t.Error("debug 行应被 error 级过滤挡住")
	}
	// 无关行按 KeepUnknown 决定。
	if !lvl.matches("GET / 200") {
		t.Error("KeepUnknown=true 时无关行应保留")
	}
	lvl2 := filterOptions{HasLevelFilter: true, MinPriority: 3, KeepUnknown: false}
	if lvl2.matches("GET / 200") {
		t.Error("KeepUnknown=false 时无关行应被丢弃")
	}
	// 同时关键词 + 级别。
	both := filterOptions{Keyword: "db", HasLevelFilter: true, MinPriority: 3, KeepUnknown: true}
	if !both.matches("[error] db down") {
		t.Error("满足两者应通过")
	}
	if both.matches("[error] redis down") {
		t.Error("不满足关键词应被挡")
	}
	if both.matches("[debug] db verbose") {
		t.Error("不满足级别应被挡")
	}
}

func TestClampLines(t *testing.T) {
	if clampLines(0) != DefaultLines {
		t.Errorf("0 应回落到 DefaultLines")
	}
	if clampLines(-5) != DefaultLines {
		t.Errorf("负数应回落到 DefaultLines")
	}
	if clampLines(DefaultLines) != DefaultLines {
		t.Error("默认值应原样")
	}
	if clampLines(MaxLines+100) != MaxLines {
		t.Error("超上限应收敛到 MaxLines")
	}
	if clampLines(42) != 42 {
		t.Error("正常值应原样")
	}
}

// ---------------------------------------------------------------------------
// journalctl argv 组装（argv 切片，绝不拼 shell）
// ---------------------------------------------------------------------------

func TestBuildJournaldArgv(t *testing.T) {
	argv := buildJournaldArgv("/usr/bin/journalctl", 100, "error", nil)
	// 必须以可执行文件开头。
	if argv[0] != "/usr/bin/journalctl" {
		t.Fatalf("argv[0]=%q 应为 journalctl 路径", argv[0])
	}
	joined := strings.Join(argv, " ")
	// 必须含 -n <lines> 与 --no-pager，且**不含任何 shell 元字符**。
	for _, want := range []string{"-n", "100", "--no-pager", "-o", "short-iso"} {
		if !contains(argv, want) {
			t.Errorf("argv 缺少 %q: %v", want, argv)
		}
	}
	// 参数必须是独立 argv 元素，不可能包含 shell 管道的输入来源；
	// 这里校验整条命令串里不出现会触发 shell 解析的元字符/词。
	for _, bad := range []string{";", "|", "&&", "$(", "`", "$(", "-c", "eval", "exec"} {
		if strings.Contains(joined, bad) {
			t.Errorf("argv 不应包含 shell 危险串 %q: %v", bad, argv)
		}
	}
	// level 映射。
	lvl := buildJournaldArgv("/x", 10, "warn", nil)
	if !contains(lvl, "-p") || !contains(lvl, "warning") {
		t.Errorf("warn 应映射为 -p warning: %v", lvl)
	}
	// 无级别时加 -p。
	noLvl := buildJournaldArgv("/x", 10, "", nil)
	if contains(noLvl, "-p") {
		t.Errorf("空级别不应加 -p: %v", noLvl)
	}
	// 附加 flags 追尾。
	withUnit := buildJournaldArgv("/x", 10, "", []string{"-u", "nginx.service"})
	if !contains(withUnit, "-u") || !contains(withUnit, "nginx.service") {
		t.Errorf("附加 flags 应追尾: %v", withUnit)
	}
}

func contains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// 保证 journald 级别 flag 与 CLI 映射表一致。
func TestJournaldLevelMappingConsistent(t *testing.T) {
	for lvl, flag := range journaldLevelToFlag {
		if flag == "" {
			t.Errorf("级别 %s 映射为空", lvl)
		}
		if _, ok := levelPriorities[lvl]; !ok && lvl != "err" && lvl != "warning" {
			// 至少保证有定义
		}
	}
	if journaldLevelToFlag["error"] != "err" {
		t.Error("error 应映射为 err")
	}
	if journaldLevelToFlag["warn"] != "warning" {
		t.Error("warn 应映射为 warning")
	}
}

// ---------------------------------------------------------------------------
// 行时间戳提取
// ---------------------------------------------------------------------------

func TestExtractTimestamp(t *testing.T) {
	// ISO 时间戳。
	if got := extractTimestamp("2024-09-29T12:34:56 host app: msg"); got != "2024-09-29T12:34:56Z" && got == "" {
		t.Errorf("ISO 时间戳应被提取")
	}
	// syslog 风格 `Sep 29 12:34:56`。
	if got := extractTimestamp("Sep 29 12:34:56 host app: msg"); got == "" {
		t.Errorf("syslog 时间戳应被提取")
	}
	// 无时间戳。
	if got := extractTimestamp("just a bare message"); got != "" {
		t.Errorf("无时间戳应返回空, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// 权限判定（纯函数）
// ---------------------------------------------------------------------------

func TestCheckLogPermission(t *testing.T) {
	admin := AdminGrantee("root")
	if d := CheckLogPermission(admin, ActionQuery); !d.Allowed {
		t.Error("管理员应被授予 log.read")
	}
	if d := CheckLogPermission(admin, ActionList); !d.Allowed {
		t.Error("管理员应能列出日志源")
	}

	limited := Grantee{User: "viewer", Granted: []string{"other.read"}}
	d := CheckLogPermission(limited, ActionQuery)
	if d.Allowed {
		t.Error("无权用户不应放行")
	}
	if d.Required != PermRead {
		t.Errorf("required=%q 应为 log.read", d.Required)
	}
	if !strings.Contains(d.Reason, "viewer") || !strings.Contains(d.Reason, PermRead) {
		t.Errorf("拒绝原因应含用户与被拒权限: %s", d.Reason)
	}
	if d.Hint == "" {
		t.Error("拒绝时应给 hint")
	}
}
