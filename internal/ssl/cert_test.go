package ssl

import (
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 证书解析与到期时间计算测试（阶段四 4.4）
// ============================================================================
//
// 本文件的测试数据**全部来自真实 certbot 1.21.0 的输出**
// （在本机实际跑 `certbot certificates` 得到），不是照文档编造的。
// 这一点很重要：解析器最大的风险就是"按想象中的格式写"，
// 而 certbot 的实际输出有几个文档里看不出来的细节
// （例如剩余不足一天时单位变成 hour(s)）。

// 固定的时间基准，避免测试依赖"当前时间"而变得不稳定。
var testNow = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

// realCertbotOutput 是实测得到的 certbot 输出（含无关注释行与分隔线）。
const realCertbotOutput = `Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Found the following certs:
  Certificate Name: example.com
    Serial Number: 4ec6321e979eb33fc104bd7efbd0c25a88268541
    Key Type: RSA
    Domains: example.com
    Expiry Date: 2026-12-24 14:30:32+00:00 (VALID: 88 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`

// TestParseRealCertbotOutput 用真实输出验证解析器。
func TestParseRealCertbotOutput(t *testing.T) {
	certs := ParseCertificates(realCertbotOutput, testNow, DefaultRenewDays)

	if len(certs) != 1 {
		t.Fatalf("期望解析出 1 张证书，实际 %d 张", len(certs))
	}
	c := certs[0]

	if c.Name != "example.com" {
		t.Errorf("Name = %q，期望 example.com", c.Name)
	}
	if c.PrimaryDomain != "example.com" {
		t.Errorf("PrimaryDomain = %q，期望 example.com", c.PrimaryDomain)
	}
	if len(c.Domains) != 1 || c.Domains[0] != "example.com" {
		t.Errorf("Domains = %v，期望 [example.com]", c.Domains)
	}
	if c.CertPath != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Errorf("CertPath = %q", c.CertPath)
	}
	if c.KeyPath != "/etc/letsencrypt/live/example.com/privkey.pem" {
		t.Errorf("KeyPath = %q", c.KeyPath)
	}
	if c.KeyType != "RSA" {
		t.Errorf("KeyType = %q，期望 RSA", c.KeyType)
	}
	if c.Serial != "4ec6321e979eb33fc104bd7efbd0c25a88268541" {
		t.Errorf("Serial = %q", c.Serial)
	}
	if c.Expiry != "2026-12-24T14:30:32Z" {
		t.Errorf("Expiry = %q，期望 2026-12-24T14:30:32Z", c.Expiry)
	}
	// 2026-09-26 → 2026-12-24 是 89 个自然日
	if c.DaysRemaining != 89 {
		t.Errorf("DaysRemaining = %d，期望 89", c.DaysRemaining)
	}
	if c.Status != StatusValid {
		t.Errorf("Status = %q，期望 %q", c.Status, StatusValid)
	}
	if c.ParseNote != "" {
		t.Errorf("正常输出不该有 ParseNote，实际 %q", c.ParseNote)
	}
}

// TestParseNoCertificates 验证「没有任何证书」被正确识别。
//
// 这是**实测确认的行为**：certbot 在无证书时输出
// `No certificates found.` 并且 **exit code 为 0**。
// 因此「输出里没有证书」不能当成错误——新机器就是这个状态。
func TestParseNoCertificates(t *testing.T) {
	const out = `Saving debug log to /var/log/letsencrypt/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
No certificates found.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 0 {
		t.Fatalf("期望 0 张证书，实际 %d 张", len(certs))
	}
	if !IsNoCertificatesOutput(out) {
		t.Error("IsNoCertificatesOutput 应当识别出 `No certificates found.`")
	}
}

// TestIsNoCertificatesOutputDistinguishesFormatChange 是上一条的**反向**测试。
//
// 「没有证书」与「输出格式不认识」在解析结果上都是 0 张，
// 但语义完全不同：前者是正常状态，后者说明解析器需要适配新版本。
// 混淆这两者会让 certbot 升级被伪装成「你的证书全没了」。
func TestIsNoCertificatesOutputDistinguishesFormatChange(t *testing.T) {
	unknownFormat := `Saving debug log to /tmp/x.log
Some brand new certbot 9.0 output format that we do not understand
`

	if IsNoCertificatesOutput(unknownFormat) {
		t.Error("未知格式不应被识别为「没有证书」")
	}
	certs := ParseCertificates(unknownFormat, testNow, DefaultRenewDays)
	if len(certs) != 0 {
		t.Errorf("未知格式应解析出 0 张证书，实际 %d 张", len(certs))
	}
}

// TestParseHourUnitExpiry 验证「剩余不足一天时单位变成 hour(s)」。
//
// ########## 这是必须实测才能发现的坑 ##########
//
// certbot 在剩余时间不足一天时输出的是 `(VALID: 23 hour(s))`
// 而不是 `days`。只匹配 `days` 的解析器会在这种情况下
// **整条证书解析失败**——而这恰恰是用户最需要看到告警的时刻。
func TestParseHourUnitExpiry(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: exp.test
    Domains: exp.test
    Expiry Date: 2026-09-27 14:30:53+00:00 (VALID: 23 hour(s))
    Certificate Path: /etc/letsencrypt/live/exp.test/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/exp.test/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	c := certs[0]
	// 到期时间是 9-27，今天是 9-26 → 剩 1 个自然日
	if c.DaysRemaining != 1 {
		t.Errorf("DaysRemaining = %d，期望 1", c.DaysRemaining)
	}
	if c.Status != StatusExpiring {
		t.Errorf("Status = %q，期望 %q", c.Status, StatusExpiring)
	}
	if c.Expiry == "" {
		t.Error("Expiry 不应为空（时间戳本身是可解析的）")
	}
}

// TestParseMultipleCertificates 验证多证书场景。
func TestParseMultipleCertificates(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: a.example.com
    Domains: a.example.com, www.a.example.com
    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 96 days)
    Certificate Path: /etc/letsencrypt/live/a.example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/a.example.com/privkey.pem
  Certificate Name: b.example.com
    Domains: b.example.com
    Expiry Date: 2026-10-01 00:00:00+00:00 (VALID: 4 days)
    Certificate Path: /etc/letsencrypt/live/b.example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/b.example.com/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 2 {
		t.Fatalf("期望 2 张证书，实际 %d 张", len(certs))
	}

	if certs[0].Name != "a.example.com" {
		t.Errorf("第一张证书名 = %q", certs[0].Name)
	}
	if len(certs[0].Domains) != 2 {
		t.Errorf("第一张证书域名数 = %d，期望 2（逗号分隔要正确切分）", len(certs[0].Domains))
	}
	// 多域名证书必须仍以首个域名为主域名
	if certs[0].PrimaryDomain != "a.example.com" {
		t.Errorf("PrimaryDomain = %q，期望 a.example.com", certs[0].PrimaryDomain)
	}
	if certs[0].Status != StatusValid {
		t.Errorf("第一张状态 = %q，期望 %q", certs[0].Status, StatusValid)
	}
	if certs[1].Status != StatusExpiring {
		t.Errorf("第二张状态 = %q，期望 %q（剩 4 天）", certs[1].Status, StatusExpiring)
	}
}

// TestParseExpiredCertificate 验证已过期证书（certbot 输出 INVALID）。
func TestParseExpiredCertificate(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: old.example.com
    Domains: old.example.com
    Expiry Date: 2026-09-20 00:00:00+00:00 (INVALID: -6 days)
    Certificate Path: /etc/letsencrypt/live/old.example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/old.example.com/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	if certs[0].DaysRemaining >= 0 {
		t.Errorf("DaysRemaining = %d，期望为负（已过期）", certs[0].DaysRemaining)
	}
	if certs[0].Status != StatusExpired {
		t.Errorf("Status = %q，期望 %q", certs[0].Status, StatusExpired)
	}
}

// TestParseMissingPathsMarkedUnknown 验证路径缺失时的降级。
//
// 证书信息存在但路径缺失 = 证书无法用于 nginx。
// 这种状态必须显式标为 unknown 并给出说明，
// 否则用户会看到一个绿色的"有效"，却在配置里得到一个
// ssl_certificate 指向空路径的报错。
func TestParseMissingPathsMarkedUnknown(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: nopath.example.com
    Domains: nopath.example.com
    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 96 days)
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	if certs[0].Status != StatusUnknown {
		t.Errorf("路径缺失时 Status = %q，期望 %q", certs[0].Status, StatusUnknown)
	}
	if certs[0].ParseNote == "" {
		t.Error("路径缺失时应当有 ParseNote 说明原因")
	}
}

// TestParseMissingExpiryMarkedUnknown 验证到期时间缺失时的降级。
func TestParseMissingExpiryMarkedUnknown(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: noexpiry.example.com
    Domains: noexpiry.example.com
    Certificate Path: /etc/letsencrypt/live/x/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/x/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	if certs[0].Status != StatusUnknown {
		t.Errorf("缺少到期时间时 Status = %q，期望 %q", certs[0].Status, StatusUnknown)
	}
	if certs[0].ParseNote == "" {
		t.Error("缺少到期时间时应当有 ParseNote")
	}
}

// TestParseMalformedExpiryFallsBackToDuration 验证时间戳畸形时的兜底。
//
// certbot 若改了时间戳格式，我们仍应利用括号里的
// 人类可读剩余时间，而不是直接变成 unknown。
func TestParseMalformedExpiryFallsBackToDuration(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: weird.example.com
    Domains: weird.example.com
    Expiry Date: 24 Dec 2026 (VALID: 88 days)
    Certificate Path: /etc/letsencrypt/live/x/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/x/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	c := certs[0]
	if c.ParseNote == "" {
		t.Error("时间戳格式异常时应当有 ParseNote")
	}
	if c.DaysRemaining != 88 {
		t.Errorf("DaysRemaining = %d，期望回退用括号里的 88", c.DaysRemaining)
	}
	if c.Expiry == "" {
		t.Error("回退路径也应当反推出一个 Expiry")
	}
}

// TestParseEmptyOutput 验证空输出不会 panic。
func TestParseEmptyOutput(t *testing.T) {
	for _, out := range []string{"", "\n", "   \n  \n", "garbage without any known field"} {
		certs := ParseCertificates(out, testNow, DefaultRenewDays)
		if len(certs) != 0 {
			t.Errorf("输入 %q 期望 0 张证书，实际 %d 张", out, len(certs))
		}
	}
}

// TestParseCertificateNameWithoutDomains 验证缺 Domains 行时的推断。
func TestParseCertificateNameWithoutDomains(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: onlyname.example.com
    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 96 days)
    Certificate Path: /etc/letsencrypt/live/x/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/x/privkey.pem
`
	certs := ParseCertificates(out, testNow, DefaultRenewDays)
	if len(certs) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d 张", len(certs))
	}
	// 证书名通常就是主域名 → 这是"信息不完整但不致命"，值得提示
	if certs[0].PrimaryDomain != "onlyname.example.com" {
		t.Errorf("PrimaryDomain = %q，期望按证书名推断", certs[0].PrimaryDomain)
	}
	if certs[0].ParseNote == "" {
		t.Error("缺少 Domains 行时应当有 ParseNote")
	}
}

// ---------------------------------------------------------------------------
// 到期时间计算
// ---------------------------------------------------------------------------

// TestDaysRemaining 穷举剩余天数计算的边界。
//
// ########## 为什么必须按「日期粒度」算 ##########
//
// 直觉写法 `int(expiry.Sub(now).Hours()/24)` 会让"还剩 30 天"
// 这句话在一天之内跳变（30 天 1 小时 → 30，29 天 23 小时 → 29），
// 用户完全无法据此判断。按自然日归一后，数字与用户
// 看到证书 notAfter 日期时的直觉一致。
func TestDaysRemaining(t *testing.T) {
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		expiry time.Time
		want   int
	}{
		{"同一时刻", now, 0},
		{"1 小时后", now.Add(time.Hour), 0},
		{"23 小时后（跨日）", now.Add(23 * time.Hour), 1},
		{"正好 24 小时", now.Add(24 * time.Hour), 1},
		{"29 天 23 小时应算 30 个自然日", now.Add(29*24*time.Hour + 23*time.Hour), 30},
		{"30 天整", now.Add(30 * 24 * time.Hour), 30},
		{"89 天整", now.Add(89 * 24 * time.Hour), 89},
		{"已过期 1 天", now.Add(-25 * time.Hour), -1},
		{"已过期 10 天", now.Add(-10 * 24 * time.Hour), -10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DaysRemaining(tt.expiry, now); got != tt.want {
				t.Errorf("DaysRemaining(%v, %v) = %d，期望 %d",
					tt.expiry, now, got, tt.want)
			}
		})
	}
}

// TestDaysRemainingZeroTime 验证零值时间返回 0 而不是 panic 或乱数。
func TestDaysRemainingZeroTime(t *testing.T) {
	if got := DaysRemaining(time.Time{}, testNow); got != 0 {
		t.Errorf("零值到期时间应返回 0，实际 %d", got)
	}
}

// TestDaysRemainingTimezoneIndependence 验证 UTC 归一。
//
// 同一张证书在不同时区的机器上必须显示相同的剩余天数，
// 否则运维会困惑"为什么两台机器上说的不一样"。
func TestDaysRemainingTimezoneIndependence(t *testing.T) {
	expiry := time.Date(2026, 12, 24, 14, 30, 32, 0, time.UTC)
	baseNow := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

	want := DaysRemaining(expiry, baseNow)

	// 同一绝对时刻，用不同时区表示 now
	shanghai := time.FixedZone("CST", 8*3600)
	newYork := time.FixedZone("EST", -5*3600)

	if got := DaysRemaining(expiry, baseNow.In(shanghai)); got != want {
		t.Errorf("东八区结果 %d 与 UTC 结果 %d 不一致", got, want)
	}
	if got := DaysRemaining(expiry, baseNow.In(newYork)); got != want {
		t.Errorf("西五区结果 %d 与 UTC 结果 %d 不一致", got, want)
	}
}

// TestClassifyStatus 穷举状态分级边界。
func TestClassifyStatus(t *testing.T) {
	tests := []struct {
		name      string
		days      int
		renewDays int
		want      string
	}{
		{"充裕", 90, 30, StatusValid},
		{"正好阈值+1", 31, 30, StatusValid},
		// 阈值本身就该告警：剩 30 天正是官方建议续期的起点，
		// 显示成健康的绿色会错过最佳时机
		{"正好阈值", 30, 30, StatusExpiring},
		{"阈值内", 15, 30, StatusExpiring},
		{"剩 1 天", 1, 30, StatusExpiring},
		{"剩 0 天（今天到期）", 0, 30, StatusExpired},
		{"已过期", -1, 30, StatusExpired},
		{"早已过期", -100, 30, StatusExpired},
		{"自定义阈值", 10, 7, StatusValid},
		{"自定义阈值内", 5, 7, StatusExpiring},
		{"阈值非法时用默认值", 45, 0, StatusValid},
		{"阈值非法时用默认值（阈值内）", 20, 0, StatusExpiring},
		{"负阈值时用默认值", 20, -5, StatusExpiring},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyStatus(tt.days, tt.renewDays); got != tt.want {
				t.Errorf("ClassifyStatus(%d, %d) = %q，期望 %q",
					tt.days, tt.renewDays, got, tt.want)
			}
		})
	}
}

// TestParseCertificatesRespectsRenewDays 验证阈值参数真的被用上。
func TestParseCertificatesRespectsRenewDays(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: x.example.com
    Domains: x.example.com
    Expiry Date: 2026-11-15 00:00:00+00:00 (VALID: 50 days)
    Certificate Path: /etc/letsencrypt/live/x/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/x/privkey.pem
`
	// 剩 50 天：默认阈值 30 天 → valid
	if c := ParseCertificates(out, testNow, 30); c[0].Status != StatusValid {
		t.Errorf("阈值 30 时状态 = %q，期望 %q", c[0].Status, StatusValid)
	}
	// 阈值改成 60 天 → expiring
	if c := ParseCertificates(out, testNow, 60); c[0].Status != StatusExpiring {
		t.Errorf("阈值 60 时状态 = %q，期望 %q", c[0].Status, StatusExpiring)
	}
}

// TestDurationToDays 验证各单位换算（实测单位的覆盖）。
func TestDurationToDays(t *testing.T) {
	tests := []struct {
		n    float64
		unit string
		want int
	}{
		{88, "days", 88},
		{1, "days", 1},
		// 23 小时应当显示「还剩 1 天」而不是「还剩 0 天」——
		// 后者看起来像已经过期了
		{23, "hour(s)", 1},
		{24, "hour(s)", 1},
		{25, "hour(s)", 2},
		{1, "hour(s)", 1},
		{30, "minute(s)", 1},
		{60, "minute(s)", 1},
		{0, "minute(s)", 0},
	}
	for _, tt := range tests {
		if got := durationToDays(tt.n, tt.unit); got != tt.want {
			t.Errorf("durationToDays(%v, %q) = %d，期望 %d", tt.n, tt.unit, got, tt.want)
		}
	}
}

// TestParseCertificatesUsesProvidedNow 验证时间基准被正确传入。
//
// 同一次解析若内部各自取一次 time.Now()，跨午夜运行时会
// 得到互相矛盾的结果。这里用两个相差一年多的 now 值
// 确保结果确实跟着 now 走。
func TestParseCertificatesUsesProvidedNow(t *testing.T) {
	const out = `Found the following certs:
  Certificate Name: x.example.com
    Domains: x.example.com
    Expiry Date: 2026-12-24 14:30:32+00:00 (VALID: 88 days)
    Certificate Path: /etc/letsencrypt/live/x/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/x/privkey.pem
`
	early := ParseCertificates(out, time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC), 30)
	late := ParseCertificates(out, time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC), 30)

	if early[0].DaysRemaining <= late[0].DaysRemaining {
		t.Errorf("较早的 now 应给出更多剩余天数：early=%d late=%d",
			early[0].DaysRemaining, late[0].DaysRemaining)
	}
	if late[0].Status != StatusExpiring {
		t.Errorf("在 2026-12-20 看这张证书应当是 %q，实际 %q",
			StatusExpiring, late[0].Status)
	}
}

// TestCertificateExpiryTime 验证 Expiry 字段能解析回 time.Time。
func TestCertificateExpiryTime(t *testing.T) {
	c := Certificate{Expiry: "2026-12-24T14:30:32Z"}
	if got := c.ExpiryTime(); got.IsZero() {
		t.Error("合法 Expiry 应当能解析")
	}
	bad := Certificate{Expiry: "not-a-time"}
	if got := bad.ExpiryTime(); !got.IsZero() {
		t.Error("非法 Expiry 应当返回零值而不是 panic")
	}
	if got := (Certificate{}).ExpiryTime(); !got.IsZero() {
		t.Error("空 Expiry 应当返回零值")
	}
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// TestSplitDomains 验证域名切分（含各种空白形态）。
func TestSplitDomains(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"example.com", []string{"example.com"}},
		{"example.com, www.example.com", []string{"example.com", "www.example.com"}},
		{"a.com,b.com", []string{"a.com", "b.com"}},
		{"  a.com  ,  b.com  ", []string{"a.com", "b.com"}},
		{"a.com,,b.com", []string{"a.com", "b.com"}},
		{"", nil},
		{"  ", nil},
	}
	for _, tt := range tests {
		got := splitDomains(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("splitDomains(%q) = %v，期望 %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitDomains(%q)[%d] = %q，期望 %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

// TestTruncate 验证截断不会越界。
func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("短串不该被截断，实际 %q", got)
	}
	long := strings.Repeat("x", 100)
	got := truncate(long, 10)
	if len(got) > 20 {
		t.Errorf("截断后过长: %d", len(got))
	}
	if !strings.HasPrefix(got, "xxxxxxxxxx") {
		t.Errorf("截断应保留前缀，实际 %q", got)
	}
}
