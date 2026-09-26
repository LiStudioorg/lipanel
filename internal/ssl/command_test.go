package ssl

import (
	"strings"
	"testing"
)

// ============================================================================
// certbot 命令组装测试（阶段四 4.4）
// ============================================================================
//
// 计划明确要求「新增 ... certbot 命令组装测试」，本文件是那条要求的落点。
//
// 这里的测试重点不是"命令看起来对不对"，而是**安全性质**：
//
//	① 参数注入：恶意域名不能变成 shell 命令或额外的 certbot 参数
//	② argv 切片：命令与参数分开传递，绝不拼 shell 字符串
//	③ 通配符拒绝：`*.example.com` 必须被明确拒绝（本期不做 DNS-01）
//	④ 强制续期默认关闭：避免打满 Let's Encrypt 的速率限制

// TestValidIssueDomainAccepts 验证合法域名被接受。
func TestValidIssueDomainAccepts(t *testing.T) {
	valid := []string{
		"example.com",
		"www.example.com",
		"a.b.c.example.com",
		"my-site.example.com",
		"sub_domain.example.com", // 下划线在非最左标签是合法的（虽不常见）
		"xn--fiqs8s.example.com", // IDN punycode
		"a1.example.com",
		"123.example.com",
		strings.Repeat("a", 63) + ".example.com", // 单标签最长 63
	}
	for _, d := range valid {
		if err := ValidIssueDomain(d); err != nil {
			t.Errorf("ValidIssueDomain(%q) 应当通过，实际报错: %v", d, err)
		}
	}
}

// TestValidIssueDomainRejectsWildcard 验证通配符被**明确**拒绝。
//
// ########## 为什么这条测试很重要 ##########
//
// `*.example.com` 在 nginx 里完全合法（4.3 的 ValidDomain 就允许它），
// 用户会理所当然地把站点域名填成它，然后点「申请证书」。
//
// 如果这里放行，命令会被原样执行，certbot 用 HTTP-01 必然失败，
// 返回一段冗长的 ACME 报错（大意是"通配符需要 DNS-01"）。
// 用户要读完那段黑话才知道"原来这个功能不支持"。
//
// 因此必须在这里拦住，并给出「通配符需要 DNS 验证，本版本未支持」。
func TestValidIssueDomainRejectsWildcard(t *testing.T) {
	wildcards := []string{
		"*.example.com",
		"*.sub.example.com",
		"*",
		"foo.*.example.com",
		"example.*",
	}
	for _, d := range wildcards {
		err := ValidIssueDomain(d)
		if err == nil {
			t.Errorf("ValidIssueDomain(%q) 应当被拒绝（通配符需要 DNS-01）", d)
			continue
		}
		// 必须是专门的哨兵错误，而不是笼统的"域名非法"——
		// 调用方要据此给出"通配符不受支持"这个具体提示。
		if !strings.Contains(err.Error(), "通配符") {
			t.Errorf("ValidIssueDomain(%q) 的错误应说明通配符问题，实际: %v", d, err)
		}
	}
}

// TestValidIssueDomainRejectsInjection 穷举注入载荷。
//
// 这是本模块最重要的一条测试：域名会被交给 certbot，
// 而 certbot 内部会把它拼进 ACME 请求与（在 --nginx 模式下）nginx 配置。
// 任何一个漏网的字符都可能变成一条命令或一条 nginx 指令。
func TestValidIssueDomainRejectsInjection(t *testing.T) {
	payloads := []string{
		// shell 元字符
		"example.com;id",
		"example.com; reboot",
		"example.com && id",
		"example.com || id",
		"example.com | id",
		"example.com `id`",
		"example.com $(id)",
		"example.com ${HOME}",
		"example.com > /tmp/x",
		"example.com < /etc/passwd",
		"example.com & background",
		"example.com\nid",
		"example.com\r\nid",
		// certbot 参数注入：以 - 开头会被当成选项
		"--help",
		"-d",
		"--nginx",
		"--force-renewal",
		"example.com --nginx",
		// nginx 配置元字符
		"example.com{",
		"example.com}",
		"example.com;",
		"example.com#comment",
		`example.com"`,
		"example.com'",
		// 路径与遍历
		"../etc/passwd",
		"example.com/../../etc",
		"/etc/passwd",
		"example.com/",
		// 空白与空值
		"",
		" ",
		"example.com ",
		" example.com",
		"example.com\t",
		// 结构非法
		".example.com",
		"example..com",
		"example.com.",
		"localhost",
		"-example.com",
		"example-.com",
		"exa mple.com",
		// 控制字符
		"example.com\x00",
		"example.com\x1b[31m",
	}
	for _, p := range payloads {
		if err := ValidIssueDomain(p); err == nil {
			t.Errorf("注入载荷 %q 竟然通过了域名校验", p)
		}
	}
}

// TestValidIssueDomainLengthLimit 验证长度上限。
func TestValidIssueDomainLengthLimit(t *testing.T) {
	// 64 字符的单标签超限
	tooLong := strings.Repeat("a", 64) + ".example.com"
	if err := ValidIssueDomain(tooLong); err == nil {
		t.Error("超过 63 字符的域名段应当被拒绝")
	}
	// 整体超过 253
	huge := strings.Repeat("abcdefghij.", 30) + "com"
	if err := ValidIssueDomain(huge); err == nil {
		t.Error("超过 253 字符的域名应当被拒绝")
	}
}

// TestValidIssueDomainDoesNotMutateInput 验证校验不静默改写输入。
//
// 4.3 踩过的坑：normalize 里先 TrimSpace 再校验，
// 导致 `"site\n"` 被静默接受（末尾换行被无声丢弃）。
// 危害有两层：安全上"校验看到的不是用户真正提交的内容"；
// 可观测上用户提交了带换行的名字却得到一个正常结果，他不会知道输入被改过。
func TestValidIssueDomainDoesNotMutateInput(t *testing.T) {
	if err := ValidIssueDomain("example.com\n"); err == nil {
		t.Error("带尾随换行的域名必须被拒绝，而不是被静默 trim 后接受")
	}
	if err := ValidIssueDomain("\texample.com"); err == nil {
		t.Error("带前导制表符的域名必须被拒绝")
	}
}

// ---------------------------------------------------------------------------
// webroot 校验
// ---------------------------------------------------------------------------

// TestValidWebroot 验证 webroot 校验。
func TestValidWebroot(t *testing.T) {
	valid := []string{
		"/var/www/html",
		"/var/www/example.com",
		"/home/user/site",
		"/srv/www/my-site",
		"/opt/a.b.c",
		"/my..site", // `..` 只有作为**独立路径段**才危险
	}
	for _, d := range valid {
		if err := ValidWebroot(d); err != nil {
			t.Errorf("ValidWebroot(%q) 应当通过，实际: %v", d, err)
		}
	}

	invalid := []string{
		"",
		"var/www",         // 相对路径
		"./www",           // 相对路径
		"/var/www;id",     // shell 元字符
		"/var/www && id",  //
		"/var/www/../etc", // `..` 路径段
		"/../etc/passwd",  //
		"/var/www\n",      // 换行
		"/var/www html",   // 空格
		"/var/www$(id)",   //
		"/var/www`id`",    //
		"/var/www|id",     //
		"/var/www*/x",     //
		"/var/www\x00",    //
		" /var/www",       // 前导空格
		"/var/www/",       // 尾随斜杠是合法的，这里仅确认不 panic
	}
	for _, d := range invalid {
		if d == "/var/www/" {
			continue // 尾随斜杠合法，见上
		}
		if err := ValidWebroot(d); err == nil {
			t.Errorf("非法 webroot %q 竟然通过校验", d)
		}
	}
}

// TestValidWebrootTrailingSlashIsValid 单独验证尾随斜杠。
func TestValidWebrootTrailingSlashIsValid(t *testing.T) {
	if err := ValidWebroot("/var/www/html/"); err != nil {
		t.Errorf("尾随斜杠是合法的 webroot，实际报错: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 证书名校验
// ---------------------------------------------------------------------------

// TestValidCertName 验证证书名校验（它同时是路径分量）。
func TestValidCertName(t *testing.T) {
	valid := []string{
		"example.com",
		"my-site",
		"my_site",
		"site123",
		"a",
	}
	for _, n := range valid {
		if err := ValidCertName(n); err != nil {
			t.Errorf("ValidCertName(%q) 应当通过，实际: %v", n, err)
		}
	}

	invalid := []string{
		"",
		"../etc",
		"..",
		"a/../b",
		"/etc/passwd",
		"a/b",
		"-startdash",
		".startdot",
		"has space",
		"has;semico",
		"has$(id)",
		"name\n",
		strings.Repeat("a", 129), // 超长
	}
	for _, n := range invalid {
		if err := ValidCertName(n); err == nil {
			t.Errorf("非法证书名 %q 竟然通过校验", n)
		}
	}
}

// ---------------------------------------------------------------------------
// 邮箱校验
// ---------------------------------------------------------------------------

// TestValidEmail 验证邮箱校验（空值允许）。
func TestValidEmail(t *testing.T) {
	// 空邮箱允许：certbot 支持不提供邮箱
	if err := ValidEmail(""); err != nil {
		t.Errorf("空邮箱应当被允许，实际: %v", err)
	}

	valid := []string{
		"admin@example.com",
		"a.b+c@example.co.uk",
		"user_name@sub.example.com",
		"x@y.io",
	}
	for _, e := range valid {
		if err := ValidEmail(e); err != nil {
			t.Errorf("ValidEmail(%q) 应当通过，实际: %v", e, err)
		}
	}

	invalid := []string{
		"not-an-email",
		"@example.com",
		"user@",
		"user@example",       // 无顶级域
		"user name@x.com",    // 空格
		"user@x.com;id",      //
		"user@x.com\n",       //
		"admin@example.com ", // 尾随空格
		"a@b.c d",
	}
	for _, e := range invalid {
		if err := ValidEmail(e); err == nil {
			t.Errorf("非法邮箱 %q 竟然通过校验", e)
		}
	}
}

// ---------------------------------------------------------------------------
// 申请命令组装
// ---------------------------------------------------------------------------

// TestBuildIssueCommand 验证申请命令的完整形状。
func TestBuildIssueCommand(t *testing.T) {
	cmd, err := BuildIssueCommand("/usr/bin/certbot", IssueRequest{
		Domains:  []string{"example.com"},
		Webroot:  "/var/www/html",
		Email:    "admin@example.com",
		CertName: "my-site",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}

	if cmd.Name != "/usr/bin/certbot" {
		t.Errorf("Name = %q", cmd.Name)
	}

	// 断言关键参数存在且取值正确
	assertArgPair(t, cmd.Args, "-w", "/var/www/html")
	assertArgPair(t, cmd.Args, "-d", "example.com")
	assertArgPair(t, cmd.Args, "--cert-name", "my-site")
	assertArgPair(t, cmd.Args, "--email", "admin@example.com")

	// certonly 必须是第一个参数：它把 certbot 限制为"只发证书"，
	// 从而**不会**用 --nginx 插件改写 /etc/nginx 下的文件。
	// 这一点是本项目的红线（配置只能由 4.3 的 site.Manager 经回滚链路写）。
	if len(cmd.Args) == 0 || cmd.Args[0] != "certonly" {
		t.Errorf("第一个参数必须是 certonly（限制 certbot 不改 nginx 配置），实际 %v", cmd.Args)
	}

	// 非交互模式：没有它，certbot 在缺输入时会等待 stdin，
	// 而面板是无终端的后台进程 → 请求挂到超时
	assertHasArg(t, cmd.Args, "--non-interactive")
	assertHasArg(t, cmd.Args, "--agree-tos")
	assertHasArg(t, cmd.Args, "--no-eff-email")

	// HTTP-01：必须是 webroot 而不是 standalone
	assertHasArg(t, cmd.Args, "--webroot")
	assertLacksArg(t, cmd.Args, "--standalone")
	// 绝不能用 --nginx（它会自己改写 nginx 配置）
	assertLacksArg(t, cmd.Args, "--nginx")

	// 默认不加 --force-renewal（避免打满速率限制）
	assertLacksArg(t, cmd.Args, "--force-renewal")

	// 默认不是 dry-run
	assertLacksArg(t, cmd.Args, "--dry-run")
}

// TestBuildIssueCommandCertNameDefaultsToDomain 验证证书名缺省。
func TestBuildIssueCommandCertNameDefaultsToDomain(t *testing.T) {
	cmd, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertArgPair(t, cmd.Args, "--cert-name", "example.com")
}

// TestBuildIssueCommandWithoutEmail 验证无邮箱时的参数。
//
// 无邮箱时必须显式 --register-unsafely-without-email，
// 否则非交互模式下 certbot 会因"没有邮箱"而拒绝注册账号。
func TestBuildIssueCommandWithoutEmail(t *testing.T) {
	cmd, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertHasArg(t, cmd.Args, "--register-unsafely-without-email")
	assertLacksArg(t, cmd.Args, "--email")

	// 反之，有邮箱时不该出现这个参数
	cmd2, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
		Email:   "a@b.com",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertLacksArg(t, cmd2.Args, "--register-unsafely-without-email")
}

// TestBuildIssueCommandDryRunAndForce 验证两个开关。
func TestBuildIssueCommandDryRunAndForce(t *testing.T) {
	dry, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
		DryRun:  true,
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertHasArg(t, dry.Args, "--dry-run")

	force, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
		Force:   true,
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertHasArg(t, force.Args, "--force-renewal")
}

// TestBuildIssueCommandRejectsMultipleDomains 验证多域名被明确拒绝。
//
// 本版本一次只支持一个域名。**明确拒绝**而不是默默只用第一个：
// 用户提交了多个域名却只签了一个，他会以为都签好了。
func TestBuildIssueCommandRejectsMultipleDomains(t *testing.T) {
	_, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"a.example.com", "b.example.com"},
		Webroot: "/var/www/html",
	})
	if err == nil {
		t.Fatal("多域名应当被拒绝（本版本一次只支持一个）")
	}
	if !strings.Contains(err.Error(), "只能为一个域名") {
		t.Errorf("错误信息应当说明限制，实际: %v", err)
	}
}

// TestBuildIssueCommandRejectsBadInputs 验证各字段校验都会被触发。
func TestBuildIssueCommandRejectsBadInputs(t *testing.T) {
	base := IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
	}

	tests := []struct {
		name string
		req  IssueRequest
	}{
		{"无域名", IssueRequest{Webroot: "/var/www/html"}},
		{"通配符域名", IssueRequest{Domains: []string{"*.example.com"}, Webroot: "/var/www/html"}},
		{"注入域名", IssueRequest{Domains: []string{"example.com;id"}, Webroot: "/var/www/html"}},
		{"空 webroot", IssueRequest{Domains: []string{"example.com"}}},
		{"相对 webroot", IssueRequest{Domains: []string{"example.com"}, Webroot: "var/www"}},
		{"webroot 穿越", IssueRequest{Domains: []string{"example.com"}, Webroot: "/var/../etc"}},
		{"非法邮箱", IssueRequest{Domains: []string{"example.com"}, Webroot: "/var/www", Email: "not-email"}},
		{"非法证书名", IssueRequest{Domains: []string{"example.com"}, Webroot: "/var/www", CertName: "../evil"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildIssueCommand("certbot", tt.req); err == nil {
				t.Errorf("%s：应当被拒绝但通过了", tt.name)
			}
		})
	}
	_ = base
}

// TestBuildIssueCommandRejectsSpaceInWebroot 验证含空格的 webroot 被拒绝。
//
// 含空格的路径无法安全地作为单个参数传递：用户以为是一个路径、
// shell（或 argv 消费方）会看成两个。因此在校验层就拒绝，
// 而不是让它变成一个"看起来能用、实际指向别处"的配置。
func TestBuildIssueCommandRejectsSpaceInWebroot(t *testing.T) {
	if _, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/my site",
	}); err == nil {
		t.Error("含空格的 webroot 应当被拒绝")
	}
}

// TestBuildIssueCommandArgvIsSlice 验证参数是独立切片元素。
//
// 关键安全性质：`-d` 与域名是两个独立的 argv 元素，
// 而不是拼成 `-d example.com` 一个字符串交给 shell。
// 若实现改成拼字符串走 sh -c，恶意域名就能逃逸。
func TestBuildIssueCommandArgvIsSlice(t *testing.T) {
	cmd, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	// 每个参数都不应包含空格拼接的痕迹
	for i, a := range cmd.Args {
		if strings.Contains(a, " -d ") || strings.Contains(a, "-w /") {
			t.Errorf("参数 %d = %q 看起来是拼接过的字符串，应当分成独立元素", i, a)
		}
	}
	// `-d` 后面紧跟的必须是域名本身
	for i, a := range cmd.Args {
		if a == "-d" {
			if i+1 >= len(cmd.Args) || cmd.Args[i+1] != "example.com" {
				t.Errorf("-d 后面应当是独立的域名元素，实际 %v", cmd.Args)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 续期命令组装
// ---------------------------------------------------------------------------

// TestBuildRenewCommand 验证续期命令。
func TestBuildRenewCommand(t *testing.T) {
	cmd, err := BuildRenewCommand("/usr/bin/certbot", "my-site", false, false)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if cmd.Name != "/usr/bin/certbot" {
		t.Errorf("Name = %q", cmd.Name)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != "renew" {
		t.Errorf("第一个参数必须是 renew，实际 %v", cmd.Args)
	}
	assertArgPair(t, cmd.Args, "--cert-name", "my-site")
	assertHasArg(t, cmd.Args, "--non-interactive")

	// 默认**不加** force：certbot 自己会判断是否进入续期窗口。
	// 加上 force 会让每次点击"续期"都真的重新签发，
	// 几天内就会撞上 Let's Encrypt 的每周 5 次限制。
	assertLacksArg(t, cmd.Args, "--force-renewal")
	assertLacksArg(t, cmd.Args, "--dry-run")
}

// TestBuildRenewCommandDryRunAndForce 验证续期开关。
func TestBuildRenewCommandDryRunAndForce(t *testing.T) {
	dry, err := BuildRenewCommand("certbot", "site", true, false)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertHasArg(t, dry.Args, "--dry-run")

	force, err := BuildRenewCommand("certbot", "site", false, true)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	assertHasArg(t, force.Args, "--force-renewal")
}

// TestBuildRenewCommandRejectsBadCertName 验证证书名校验。
func TestBuildRenewCommandRejectsBadCertName(t *testing.T) {
	for _, n := range []string{"", "../evil", "a/b", "has space"} {
		if _, err := BuildRenewCommand("certbot", n, false, false); err == nil {
			t.Errorf("非法证书名 %q 应当被拒绝", n)
		}
	}
}

// TestBuildRenewAllCommand 验证批量续期命令。
//
// ⚠️ 这条命令**绝不能**带 --force-renewal：定时器每 12 小时跑一次，
// 加了 force 等于每天把全部证书重新签发一遍。
func TestBuildRenewAllCommand(t *testing.T) {
	cmd := BuildRenewAllCommand("certbot", false)
	if len(cmd.Args) == 0 || cmd.Args[0] != "renew" {
		t.Errorf("第一个参数必须是 renew，实际 %v", cmd.Args)
	}
	assertLacksArg(t, cmd.Args, "--force-renewal")
	assertLacksArg(t, cmd.Args, "--cert-name")
	assertHasArg(t, cmd.Args, "--non-interactive")

	dry := BuildRenewAllCommand("certbot", true)
	assertHasArg(t, dry.Args, "--dry-run")
}

// TestBuildListCommand 验证查询命令。
func TestBuildListCommand(t *testing.T) {
	cmd := BuildListCommand("certbot")
	if len(cmd.Args) != 1 || cmd.Args[0] != "certificates" {
		t.Errorf("查询命令应当是 certificates，实际 %v", cmd.Args)
	}
}

// ---------------------------------------------------------------------------
// 命令展示（脱敏）
// ---------------------------------------------------------------------------

// TestRedactCommandQuotesArgs 验证命令展示会正确加引号。
//
// 目的是让用户能把日志里的命令**直接复制到终端**执行以复现问题。
func TestRedactCommandQuotesArgs(t *testing.T) {
	got := RedactCommand("certbot", []string{"certonly", "-w", "/var/www/my site", "-d", "example.com"})
	if !strings.Contains(got, "'/var/www/my site'") {
		t.Errorf("含空格的参数应当被加引号，实际: %s", got)
	}
	if !strings.HasPrefix(got, "certbot ") {
		t.Errorf("命令应当以程序名开头，实际: %s", got)
	}
	// 不含特殊字符的参数不该被加引号（保持可读）
	if strings.Contains(got, "'example.com'") {
		t.Errorf("普通参数不该被加引号，实际: %s", got)
	}
}

// TestRedactCommandHandlesEmpty 验证空参数被正确表示。
func TestRedactCommandHandlesEmpty(t *testing.T) {
	got := RedactCommand("cmd", []string{"a", "", "b"})
	if !strings.Contains(got, "''") {
		t.Errorf("空参数应当显示为 ''，实际: %s", got)
	}
}

// TestCommandString 验证 Command.String 返回脱敏文本。
func TestCommandString(t *testing.T) {
	cmd, err := BuildIssueCommand("certbot", IssueRequest{
		Domains: []string{"example.com"},
		Webroot: "/var/www/html",
	})
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if cmd.String() != cmd.Redacted {
		t.Error("String() 应当返回 Redacted")
	}
	if cmd.Label == "" {
		t.Error("Label 不应当为空（审计与日志需要它）")
	}
}

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// assertHasArg 断言参数存在。
func assertHasArg(t *testing.T, args []string, want string) {
	t.Helper()
	for _, a := range args {
		if a == want {
			return
		}
	}
	t.Errorf("参数列表中缺少 %q，实际: %v", want, args)
}

// assertLacksArg 断言参数不存在。
func assertLacksArg(t *testing.T, args []string, unwanted string) {
	t.Helper()
	for _, a := range args {
		if a == unwanted {
			t.Errorf("参数列表中不应出现 %q，实际: %v", unwanted, args)
			return
		}
	}
}

// assertArgPair 断言 `key value` 成对出现。
func assertArgPair(t *testing.T, args []string, key, wantValue string) {
	t.Helper()
	for i, a := range args {
		if a != key {
			continue
		}
		if i+1 >= len(args) {
			t.Errorf("参数 %q 后面缺少取值，实际: %v", key, args)
			return
		}
		if args[i+1] != wantValue {
			t.Errorf("参数 %q 的取值 = %q，期望 %q", key, args[i+1], wantValue)
		}
		return
	}
	t.Errorf("参数列表中缺少 %q，实际: %v", key, args)
}
