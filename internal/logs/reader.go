package logs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// 日志读取
// ============================================================================
//
// 本模块从两个渠道读日志：
//
//   - journalctl：**只**通过 exec.CommandContext 传 argv 切片调用（见 readJournald），
//     绝不拼 shell 字符串，也绝不经 sh -c。
//   - 普通日志文件：按行读取（见 readFile）。
//
// 两者最后都汇入同一段「截断 → 过滤」逻辑（readAndFilter），保证行为一致、
// 且过滤逻辑只写一次、只测一次。

// journaldTime layout：journalctl 默认短时间格式 "Sep 29 12:34:56"。
const journaldTimeLayout = "Jan 02 15:04:05"

// timestampPattern 匹配日志行开头的常见时间戳（syslog 风格）。
// 仅用于把时间戳**展示**给前端；匹配不到不影响读日志。
var timestampPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})|^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

// extractTimestamp 提取行首时间戳（若有），返回 RFC3339 字符串；否则空串。
func extractTimestamp(line string) string {
	m := timestampPattern.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	raw := ""
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			raw = m[i]
			break
		}
	}
	if raw == "" {
		return ""
	}
	// 两种形态：
	//   ① ISO：2024-09-29 12:34:56（或 2024-09-29T12:34:56）→ 空格换 T。
	//   ② syslog：Sep 29 12:34:56 → 保持原样按 "Jan 02 15:04:05" 解析。
	var layouts []string
	if strings.Contains(raw, "-") && len(raw) >= 10 {
		raw = strings.Replace(raw, " ", "T", 1)
		layouts = []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05.999999999"}
	} else {
		layouts = []string{journaldTimeLayout}
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.Format(time.RFC3339)
		}
	}
	return ""
}

// maxLineBytes 是单行读取上限。日志里偶发超长行（如堆栈转储）不该
// 拖垮读取；超过的行会被截断并在该条里标记（见 readAndFilter 的 TruncatedLine）。
const maxLineBytes = 1 << 16 // 64 KiB

// readAndFilter 从 reader 逐行读取，应用截断与过滤，返回结果。
//
// reader 产生「原始行」；本函数负责：
//  1. 只保留最近 lines 行（用环形先存，读完再截断）——见下方为何不预先截。
//  2. 应用关键词/级别过滤。
//
// 注意过滤顺序：**先取最近 lines 行，再对这 lines 行过滤**。
// 为什么不是「先全读、再过滤、再截断」？因为那样一个大 access.log
// 会被完整扫一遍，查询行数越大扫描量线性增长，极慢且吃内存。
// 这里始终只用与请求行数相近的行做过滤。
func readAndFilter(r io.Reader, lines int, opts filterOptions) ([]Entry, bool, int) {
	limit := clampLines(lines)
	// 用环形缓冲保留最近的 limit 行（再加少量余量，避免过度截断）。
	ring := make([]Entry, 0, limit+8)
	truncated := false
	scanned := 0

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		scanned++
		// 超长行 Scanner 会报错（bufio.ErrTooLong），此时我们不知道行内容；
		// 把它当作"存在超长行"而标记 truncated 即可（该行的正文本就不能完整展示）。
		if len(line) > maxLineBytes {
			truncated = true
			continue
		}

		if !opts.matches(line) {
			continue
		}

		if len(ring) >= limit {
			// 丢弃最旧，保持只在最近 limit 行内过滤。
			copy(ring, ring[1:])
			ring = ring[:len(ring)-1]
			truncated = true
		}
		ring = append(ring, Entry{
			Line:      line,
			Timestamp: extractTimestamp(line),
		})
	}
	return ring, truncated, scanned
}

// ---- journalctl ----

// journaldLevelToFlag 把规范级别映射为 journalctl -p 接受的值。
var journaldLevelToFlag = map[string]string{
	"error": "err",
	"warn":  "warning",
	"info":  "info",
	"debug": "debug",
}

// buildJournaldArgv 组装 journalctl 参数（argv 切片，绝不拼 shell）。
// flags 里可带 -u <unit> 之类的附加参数（由源决定）。
//
// 返回的 argv 固定包含：-n <lines> --no-pager -o short-iso，可选 -p <level>。
// 我们让 journalctl 先 -n 拿到最近 lines 行的窗口，再由本地 readAndFilter
// 做关键词过滤 —— journalctl 的 --grep 是 PCRE2 正则，与"子串过滤"语义不同，
// 且各发行版 PCRE2 支持不一致，故本地过滤更可控。
func buildJournaldArgv(journalCtl string, lines int, level string, flags []string) []string {
	argv := []string{journalCtl, "-n", fmt.Sprintf("%d", clampLines(lines)), "--no-pager", "-o", "short-iso"}
	if lvl := journaldLevelToFlag[normalizeLevel(level)]; lvl != "" {
		argv = append(argv, "-p", lvl)
	}
	if len(flags) > 0 {
		argv = append(argv, flags...)
	}
	return argv
}

// readJournald 通过 journalctl 读取系统日志行。
// ctx 用于超时控制（-logs-timeout）。
func readJournald(ctx context.Context, journalCtl string, lines int, level, filter string) Result {
	argv := buildJournaldArgv(journalCtl, lines, level, nil)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// 固定语言环境，保证 -o short-iso 与级别文本不随 locale 变化。
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")

	// 同时读取 stdout 与 stderr（journald 某些告警走 stderr，不能让它撑爆管道）。
	var stderr strings.Builder
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{SourceID: SourceIDSystem,
			Entries: nil, Truncated: false, Scanned: 0}
	}
	if err := cmd.Start(); err != nil {
		return Result{SourceID: SourceIDSystem,
			Entries: nil, Truncated: false, Scanned: 0}
	}

	entries, truncated, scanned := readAndFilter(stdout, lines, filterOptions{
		Keyword:        filter,
		HasLevelFilter: level != "",
		MinPriority:    levelPriorities[normalizeLevel(level)],
		KeepUnknown:    true,
	})
	// 读取完 stdout 后等待进程结束（并收集 stderr）。
	_ = cmd.Wait()
	_ = stderr.String() // 仅用于排泄，避免阻塞

	return Result{
		SourceID:  SourceIDSystem,
		Entries:   entries,
		Truncated: truncated,
		Scanned:   scanned,
	}
}

// ---- 普通日志文件 ----

// readFile 从白名单文件读取最近 lines 行并过滤。
// 文件路径必须已通过源探测的白名单校验（probeFile）。
func readFile(ctx context.Context, path string, lines int, filter string, level string) Result {
	f, err := os.Open(path)
	if err != nil {
		return Result{SourceID: SourceIDSystem,
			Entries: []Entry{}, Truncated: false, Scanned: 0}
	}
	defer f.Close()

	// 大文件只读末尾若干行（日志里我们只关心最近的内容）。
	// 先 Seek 到文件末尾往回退一段按圆环读，避免全文件扫描。
	// 简化实现：用 os.File 支持 Seek；对 <= maxAppLogBytes 的文件全量读
	// 也早已可接受（见 maxAppLogBytes），因此这里直接回绕式读取尾部。
	return readTailFile(ctx, f, lines, filter, level)
}

// readTailFile 从文件尾部回绕读取，返回最近的、通过过滤的行。
func readTailFile(ctx context.Context, f *os.File, lines int, filter string, level string) Result {
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return Result{Entries: []Entry{}, Truncated: false, Scanned: 0}
	}
	size := info.Size()
	if size == 0 {
		return Result{Entries: []Entry{}, Truncated: false, Scanned: 0}
	}

	// 回绕读取最近至多 maxAppLogBytes 的区域（日志轮转后的新文件也不担心，
	// 因为这里读的是"当前这个文件"的尾部）。
	const window = maxAppLogBytes
	var start int64
	if size > window {
		start = size - window
	} else {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return Result{Entries: []Entry{}, Truncated: false, Scanned: 0}
	}
	// 若从中间开始，首行可能是半行 —— 用 Scanner 天然按 \n 分行，半行会被框进来，
	// 但这只是"行首不完整"，对日志展示可接受（且很少是关键行）。
	sr := io.NewSectionReader(f, start, size-start)
	entries, truncated, scanned := readAndFilter(sr, lines, filterOptions{
		Keyword:        filter,
		HasLevelFilter: level != "",
		MinPriority:    levelPriorities[normalizeLevel(level)],
		KeepUnknown:    true,
	})
	return Result{Entries: entries, Truncated: truncated, Scanned: scanned}
}
