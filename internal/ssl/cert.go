package ssl

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// 证书信息解析与到期时间计算
// ============================================================================
//
// 数据来源是 `certbot certificates` 的**人类可读输出**（不是 JSON——
// certbot 1.21 没有 `--format json` 这类选项）。因此解析器必须
// 针对「运维工具的输出格式」做防御，而不是假设它永远规整。
//
// #################### 实测得到的真实格式 ####################
//
// 以下输出是在本机 certbot 1.21.0 上**真实跑出来**的（不是抄文档）：
//
//	Saving debug log to /var/log/letsencrypt/letsencrypt.log
//
//	- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//	Found the following certs:
//	  Certificate Name: example.com
//	    Serial Number: 4ec6321e979eb33fc104bd7efbd0c25a88268541
//	    Key Type: RSA
//	    Domains: example.com
//	    Expiry Date: 2026-12-24 14:30:32+00:00 (VALID: 88 days)
//	    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
//	    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
//	- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
// 无证书时：
//
//	- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//	No certificates found.
//	- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
// #################### 两个必须处理的实际陷阱 ####################
//
// **陷阱一：`VALID` 的单位不固定。** 剩余时间不足一天时 certbot 输出的是
// `(VALID: 23 hour(s))` 而不是 `days`——这一点也是实测确认的。
// 只匹配 `days` 的解析器在这种情况会**整条证书解析失败**，
// 而那时恰恰是用户最需要看到「证书即将过期」的时刻。
// 因此下面同时支持 days / hour(s) / minute(s)。
//
// **陷阱二：`No certificates found.` 是成功而非失败。**
// 它伴随 **exit code 0**。若把「输出里没有 Certificate Name」当成错误，
// 那么「干净的新机器」这个最常见的状态会显示成红色报错。
// 正确语义是：命令成功 + 零张证书 = 每张证书都还没申请。

// ============================================================================
// 证书状态
// ============================================================================

// 证书状态（相对「现在」而言）。
const (
	// StatusValid 表示证书有效且距到期还有充足时间。
	StatusValid = "valid"
	// StatusExpiring 表示证书即将过期（剩余天数 <= 阈值）。
	StatusExpiring = "expiring"
	// StatusExpired 表示证书已过期。
	StatusExpired = "expired"
	// StatusNone 表示该域名尚未申请证书。
	StatusNone = "none"
	// StatusUnknown 表示解析失败或信息不完整（需要人工查看）。
	StatusUnknown = "unknown"
)

// DefaultRenewDays 是「即将过期」的默认阈值。
//
// 30 天：Let's Encrypt 证书有效期 90 天，官方建议在剩余 30 天时续期
// （ACME 也允许 30 天内续期）。这个数字同时用于
// ① 界面上的橙色告警；② 自动续期调度器的触发条件。
const DefaultRenewDays = 30

// Certificate 是一张证书的解析结果。
//
// 字段刻意保持扁平：它同时用于「内部判断」与「API 响应」。
type Certificate struct {
	// Name 是证书名（certbot 的 `Certificate Name`，通常等于主域名）。
	Name string `json:"name"`
	// Domains 是这张证书覆盖的全部域名（第一个视为主域名）。
	Domains []string `json:"domains"`
	// PrimaryDomain 是证书的主域名（Domains[0]）。
	//
	// 冗余一个字段而不是让前端自己取 [0]：前端要按它去匹配站点，
	// 而「站点域名 == 证书主域名」是本模块的关联键，
	// 应该在后端确定下来，避免多处各自实现一遍。
	PrimaryDomain string `json:"primary_domain"`
	// CertPath 是 fullchain.pem 的路径（供 nginx ssl_certificate 使用）。
	CertPath string `json:"cert_path"`
	// KeyPath 是 privkey.pem 的路径（供 nginx ssl_certificate_key 使用）。
	KeyPath string `json:"key_path"`
	// Expiry 是到期时间（RFC3339，UTC）。
	//
	// 序列化成 UTC 而不是本地时区：证书的 notAfter 本身是 UTC，
	// 界面上跨时区查看时用 UTC 才不会出现「同一张证书在不同
	// 机器上显示不同到期日」的困惑。
	Expiry string `json:"expiry,omitempty"`
	// DaysRemaining 是剩余天数（向上取整；已过期为负）。
	DaysRemaining int `json:"days_remaining"`
	// Status 见 StatusValid / StatusExpiring / StatusExpired / StatusUnknown。
	Status string `json:"status"`
	// KeyType 是密钥类型（RSA / ECDSA）。
	KeyType string `json:"key_type,omitempty"`
	// Serial 是证书序列号。
	Serial string `json:"serial,omitempty"`
	// ParseNote 记录解析过程中值得提示给用户的情况。
	//
	// 与 4.3 Site.ParseNote 同款取舍：解析异常**不让整张证书失败**
	// （那样会让列表接口整体报错），而是作为一条附着的说明。
	ParseNote string `json:"parse_note,omitempty"`
}

// ExpiryTime 把 Expiry 字段解析回 time.Time。
//
// 返回零值表示无到期时间（未申请或解析失败）。
func (c Certificate) ExpiryTime() time.Time {
	if c.Expiry == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, c.Expiry)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ============================================================================
// 到期时间计算
// ============================================================================

// DaysRemaining 计算从 now 到 expiry 的剩余天数。
//
// #################### 为什么必须按「日期粒度」而不是时长除法 ####################
//
// 直觉写法是 `int(expiry.Sub(now).Hours() / 24)`，但它会给出**误导性的数字**：
// 剩余 29 天 23 小时会被算成 29，而剩余 29 天 0 小时也算 29——
// 更糟的是剩余 30 天 0 小时算 30、剩余 29 天 23 小时算 29，
// 于是「还剩 30 天」这句话在一天之内会跳变，用户完全无法据此判断。
//
// 证书到期的语义是「哪一天到期」，因此这里把两端都归一到 UTC 日期
// 再相减，得到的是**自然日差**：
//
//	剩余 30 天 0 小时  → 30
//	剩余 29 天 23 小时 → 30   （因为按日期看确实跨了 30 个自然日）
//
// 这个口径与用户看到证书 notAfter 日期时的直觉一致。
//
// 用 UTC 归一而不是本地时区：证书时间本身是 UTC，
// 用本地时区会让同一张证书在 UTC+8 与 UTC-5 的机器上
// 显示出不同的剩余天数。
func DaysRemaining(expiry, now time.Time) int {
	if expiry.IsZero() {
		return 0
	}
	// 取两端的 UTC 日期零点，再相减。
	e := time.Date(expiry.UTC().Year(), expiry.UTC().Month(), expiry.UTC().Day(), 0, 0, 0, 0, time.UTC)
	n := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(e.Sub(n).Hours() / 24)
}

// ClassifyStatus 按剩余天数判定证书状态。
//
// renewDays 是「即将过期」的阈值；<=0 时用 DefaultRenewDays。
//
// 边界语义（有测试锁死）：
//
//	days >  renewDays  → valid
//	0 < days <= renewDays → expiring
//	days <= 0          → expired
//
// 注意 `days == renewDays` 判为 expiring 而不是 valid：
// 阈值本身就应该开始告警，否则「剩 30 天」这个官方建议的续期起点
// 会被显示成健康的绿色，正好错过最佳续期时机。
func ClassifyStatus(days, renewDays int) string {
	if renewDays <= 0 {
		renewDays = DefaultRenewDays
	}
	switch {
	case days <= 0:
		return StatusExpired
	case days <= renewDays:
		return StatusExpiring
	default:
		return StatusValid
	}
}

// ============================================================================
// certbot certificates 输出解析
// ============================================================================

// certbot 输出的字段前缀（实测确认，含前导空格）。
const (
	fieldCertName  = "Certificate Name:"
	fieldDomains   = "Domains:"
	fieldExpiry    = "Expiry Date:"
	fieldCertPath  = "Certificate Path:"
	fieldKeyPath   = "Private Key Path:"
	fieldKeyType   = "Key Type:"
	fieldSerial    = "Serial Number:"
	noCertsMarker  = "No certificates found."
	foundCertsMark = "Found the following certs:"
)

// expiryTimestampPattern 抽取 certbot 时间戳：`2026-12-24 14:30:32+00:00`。
//
// 与下面的括号部分**分开成两个正则**，而不是合成一个大的。
//
// ########## 为什么要拆开 ##########
//
// 合成一个 `^时间戳\s*\(状态: 数量 单位\)` 的正则时，
// 只要时间戳格式变了（certbot 换版本），整个正则就**完全不匹配**，
// 于是括号里那个仍然可用的 `88 days` 也被一起丢掉，
// 结果是一张好端端的证书变成 unknown。
//
// 拆开之后，两条信息各自独立成败：
//
//	时间戳能解析 → 用绝对值（首选，不受读取时机影响）
//	时间戳不能解析但括号能解析 → 回退用括号里的人类可读数字
//	两者都不能解析 → unknown + ParseNote
//
// 防线是分层的，而不是"全有或全无"。
var expiryTimestampPattern = regexp.MustCompile(
	`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})`)

// expiryParentheticalPattern 抽取括号部分：`(VALID: 88 days)`。
//
// 拆成四段捕获：
//
//	① 状态词 VALID / INVALID（INVALID 表示已过期）
//	② 数量：`-?` 前缀是必需的——已过期的证书 certbot 输出的是
//	   `(INVALID: -6 days)`，带**负号**。少了这个负号，
//	   正则对已过期证书整条不匹配，而"证书已过期"恰恰是最需要
//	   被正确识别、最不能静默失败的状态（测试已锁死这一点）。
//	③ 单位：days / hour(s) / minute(s)，实测确认单位**不固定**。
var expiryParentheticalPattern = regexp.MustCompile(
	`\(([A-Z]+):\s*(-?[\d.]+)\s*([a-z()]+)\)`)

// renewDurationPattern 解析 `(VALID: 88 days)` 里的数量与单位。
//
// 单位的实际形态（实测）：`days`、`hour(s)`、`minute(s)`。
// 注意 `hour(s)` 带括号，因此不能用 `\w+` 匹配。
var renewDurationPattern = regexp.MustCompile(`^([\d.]+)\s+(day|hour|minute)`)

// ParseCertificates 解析 `certbot certificates` 的输出。
//
// 返回的证书按 certbot 的输出顺序排列（certbot 本身按证书名排序，稳定）。
//
// **不返回 error**：这是刻意的。解析失败（格式变化、部分字段缺失）
// 不应让整个状态接口失败——那会让用户在一个格式不兼容的 certbot 上
// 完全看不到 SSL 页面。无法解析的内容会体现为：
//   - 完全解析不出任何证书条目 → 返回空列表 + 由调用方结合
//     命令是否成功来判断（见 Manager.Status）；
//   - 单张证书缺字段 → 该证书带 ParseNote，其余字段仍可用。
func ParseCertificates(output string, now time.Time, renewDays int) []Certificate {
	if renewDays <= 0 {
		renewDays = DefaultRenewDays
	}
	if now.IsZero() {
		now = time.Now()
	}

	var (
		certs   []Certificate
		current *Certificate
	)

	// flush 把累积中的证书收尾（计算剩余天数与状态）。
	flush := func() {
		if current == nil {
			return
		}
		finalizeCertificate(current, now, renewDays)
		certs = append(certs, *current)
		current = nil
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// 新证书条目开始：先收尾上一张。
		if v, ok := trimField(line, fieldCertName); ok {
			flush()
			current = &Certificate{Name: v}
			continue
		}

		// 还没进入任何条目：这些行（Saving debug log、分隔线、提示语）直接跳过。
		if current == nil {
			continue
		}

		switch {
		case hasField(line, fieldSerial):
			current.Serial = fieldValue(line, fieldSerial)
		case hasField(line, fieldKeyType):
			current.KeyType = fieldValue(line, fieldKeyType)
		case hasField(line, fieldDomains):
			current.Domains = splitDomains(fieldValue(line, fieldDomains))
		case hasField(line, fieldExpiry):
			parseExpiryLine(current, fieldValue(line, fieldExpiry), now)
		case hasField(line, fieldCertPath):
			current.CertPath = fieldValue(line, fieldCertPath)
		case hasField(line, fieldKeyPath):
			current.KeyPath = fieldValue(line, fieldKeyPath)
		}
	}
	flush()

	return certs
}

// finalizeCertificate 计算派生字段（主域名、剩余天数、状态）并补 ParseNote。
func finalizeCertificate(c *Certificate, now time.Time, renewDays int) {
	if len(c.Domains) > 0 {
		c.PrimaryDomain = c.Domains[0]
	} else {
		// 没有 Domains 行时退回证书名：certbot 的证书名通常就是主域名，
		// 因此这是**信息不完整但不致命**的情况，值得提示而非报错。
		c.PrimaryDomain = c.Name
		c.ParseNote = appendNote(c.ParseNote, "未能解析出域名列表，已按证书名推断主域名")
	}

	if c.Expiry == "" {
		c.Status = StatusUnknown
		c.ParseNote = appendNote(c.ParseNote, "未能解析出到期时间，无法判断证书状态")
		return
	}
	c.Status = ClassifyStatus(c.DaysRemaining, renewDays)

	// 字段完整性检查：缺证书或私钥路径时，证书"存在"但**无法用于 nginx**。
	// 这种状态必须显式告知，否则用户会看到一个绿色的「有效」，
	// 却在配置里得到一个 ssl_certificate 指向空路径的报错。
	if c.CertPath == "" || c.KeyPath == "" {
		c.Status = StatusUnknown
		c.ParseNote = appendNote(c.ParseNote, "证书或私钥路径缺失，无法写入 nginx 配置")
	}
}

// parseExpiryLine 解析 `Expiry Date:` 的值部分。
//
// 值形如：`2026-12-24 14:30:32+00:00 (VALID: 88 days)`
//
// 解析策略：**优先信任时间戳，用括号里的剩余时间兜底**。
//
// 为什么不直接用括号里的 `88 days` 算到期时间：那个数字是
// certbot 生成输出那一刻算出来的，而我们读到的可能是缓存的旧输出。
// 时间戳是绝对值，不受读取时机影响，因此以它为准。
//
// 括号部分仍然要解析，用途是——当时间戳解析失败时（格式变化）
// 还能拿到一个可用的剩余天数，而不是直接变成 unknown。
//
// now 由调用方传入（而不是内部取 time.Now）：单一时间基准是本模块
// 可测试性的前提——同一次解析里若有两处各自取 Now()，
// 跨午夜运行时会得到互相矛盾的结果。
func parseExpiryLine(c *Certificate, value string, now time.Time) {
	// ---------- ① 时间戳（主来源） ----------
	if m := expiryTimestampPattern.FindStringSubmatch(value); m != nil {
		if t, err := time.Parse("2006-01-02 15:04:05-07:00", m[1]); err == nil {
			c.Expiry = t.UTC().Format(time.RFC3339)
			c.DaysRemaining = DaysRemaining(t, now)
			return
		}
		// 时间戳形状对但解析不了（例如月份越界）：记一笔，
		// 继续尝试用括号里的信息兜底。
		c.ParseNote = appendNote(c.ParseNote,
			"到期时间戳 "+m[1]+" 无法解析")
	}

	// ---------- ② 括号里的剩余时间（兜底） ----------
	// 走到这里说明时间戳缺失或不可用。仍然把括号里的
	// 人类可读数字用起来，至少让界面能显示"还剩几天"。
	m := expiryParentheticalPattern.FindStringSubmatch(value)
	if m == nil {
		// 连括号都匹配不上：交给 finalizeCertificate 标为 unknown。
		c.ParseNote = appendNote(c.ParseNote,
			"到期时间格式无法识别: "+truncate(value, 60))
		return
	}

	count, unit := m[2], m[3]
	n, err := strconv.ParseFloat(count, 64)
	if err != nil {
		c.ParseNote = appendNote(c.ParseNote,
			"到期时间数量无法解析: "+truncate(count, 20))
		return
	}

	days := durationToDays(n, unit)
	c.DaysRemaining = days
	// 反推一个到期时间，让界面上的"到期时间"字段不至于为空。
	c.Expiry = now.AddDate(0, 0, days).UTC().Format(time.RFC3339)
	c.ParseNote = appendNote(c.ParseNote,
		fmt.Sprintf("已回退使用 certbot 报告的剩余时间 %s %s", count, unit))
}

// durationToDays 把 certbot 的「数量 + 单位」换算成天数。
//
// 单位来自实测：days / hour(s) / minute(s)。
// 向上取整（Ceil）而不是截断：剩余 23 小时应当显示「还剩 1 天」
// 而不是「还剩 0 天」——后者看起来像已经过期了。
func durationToDays(n float64, unit string) int {
	switch {
	case strings.HasPrefix(unit, "day"):
		return int(math.Ceil(n))
	case strings.HasPrefix(unit, "hour"):
		return int(math.Ceil(n / 24))
	case strings.HasPrefix(unit, "minute"):
		return int(math.Ceil(n / (24 * 60)))
	default:
		return int(math.Ceil(n))
	}
}

// splitDomains 切分 `Domains:` 的值。
//
// certbot 用逗号加空格分隔：`example.com, www.example.com`。
func splitDomains(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// hasField 判断一行是否以某个字段名开头（certbot 输出带缩进，已 TrimSpace）。
func hasField(line, field string) bool {
	return strings.HasPrefix(line, field)
}

// trimField 在行以 field 开头时返回去掉前缀的值；否则 ok 为 false。
func trimField(line, field string) (string, bool) {
	if !strings.HasPrefix(line, field) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, field)), true
}

// fieldValue 等价于 trimField 但不关心 ok（调用方已用 hasField 判断过）。
func fieldValue(line, field string) string {
	v, _ := trimField(line, field)
	return v
}

// appendNote 追加一条解析说明（多条之间用分号连接）。
func appendNote(existing, note string) string {
	if existing == "" {
		return note
	}
	return existing + "；" + note
}

// truncate 截断过长的字符串（用于把畸形输出塞进 ParseNote 时避免刷屏）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ErrNoCertificates 表示客户端明确报告「没有任何证书」。
//
// 注意：这**不是错误状态**，只是一个可判定的信号，
// 让调用方能把「零证书」与「解析失败」区分开。
var ErrNoCertificates = errors.New("ssl: 没有任何证书")

// IsNoCertificatesOutput 判断输出是否明确表示「没有证书」。
//
// 这个判断存在的意义：`No certificates found.` 与「解析出 0 张证书」
// 在结果上一样，但语义完全不同——
//   - 前者：命令成功了，机器上确实一张证书都没有（新机器）；
//   - 后者：命令成功了，但输出格式我们不认识（certbot 换版本了）。
//
// 前者应当安静地显示「未申请」，后者应当提示「输出格式无法识别」。
// 不区分这两者的话，certbot 升级导致的格式变化会被伪装成
// 「你的证书全没了」，足以让人白忙半天。
func IsNoCertificatesOutput(output string) bool {
	return strings.Contains(output, noCertsMarker)
}
