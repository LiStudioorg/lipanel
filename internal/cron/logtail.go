package cron

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ============================================================================
// 执行日志的包装脚本与读取（阶段五 5.2）
// ============================================================================
//
// ########## 为什么任务本身不产生日志，以及为什么选包装脚本 ##########
//
// cron 的唯一输出通道是「把 stdout/stderr 用邮件发给 MAILTO」，
// 而绝大多数机器没配本地 MTA —— 于是输出被静默丢弃，
// 用户唯一的感知是「任务好像没跑」。
//
// 两条出路：
//
//	① 行内重定向：`*/5 * * * * cmd >> /path/x.log 2>&1`
//	② 包装脚本：  `*/5 * * * * /bin/sh '/var/lib/lipanel/cron/jobs/<id>.sh'`
//	              脚本内部做重定向与退出码记录
//
// 选 ②，理由是可验证性与信息量：
//
//	· 行内重定向要把用户命令**塞进一个带引号的 shell 片段**，
//	  引号/重定向符/反引号的转义是经典的静默出错源
//	  （引号不配对时 crontab 行照样保存成功，永远不执行）。
//	· 脚本里可以先写一行分隔符与时间戳、执行完再写退出码，
//	  面板才能如实回答「上次跑得怎么样」；行内重定向只有裸输出，
//	  连失败都看不出来。
//	· 用户命令在脚本里**原样成行**，用户在面板上看到的命令
//	  与磁盘上真正执行的完全一致（读脚本即可，无需反向解析引号）。
//
// 代价如实说明：数据目录里会多出面板生成的脚本文件；
// 删除任务时一并清理（脚本、日志、备份各自独立处理）。

// LogTailLimit / MaxLogTailBytes 是日志读取的默认与上限。
const (
	// DefaultLogTailLines 是默认返回的行数。
	DefaultLogTailLines = 200
	// MaxLogTailLines 是单次能请求的最大行数。
	MaxLogTailLines = 2000
	// MaxLogTailBytes 是单次读取的字节上限（防一条巨型日志打死内存）。
	MaxLogTailBytes = 1 << 20 // 1 MiB
	// DefaultLogMaxBytes 是单个任务日志的体积上限，超出后原地截断。
	DefaultLogMaxBytes = 2 << 20 // 2 MiB
)

// scriptBody 生成包装脚本正文。
//
// 结构（刻意让用户的命令**独占一行**且不被任何语法包裹修改）：
//
//	#!/bin/sh
//	# lipanel 计划任务包装脚本（面板生成）
//	echo "==== lipanel cron run start ... ===="
//	{
//	<用户命令原文>
//	} >> '<log>' 2>&1
//	rc=$?
//	echo "==== lipanel cron run end ... exit=$rc ===="
//	exit $rc
//
// 关键取舍：
//
//	· 用 `/bin/sh` 而不是 bash：sh 在所有 POSIX 系统都在，
//	  且 cron 默认也是 sh。用户需要 bash 特性时自己写 `bash -c '...'`。
//	· 用户命令单独成行、**不做任何转义**——不转义正是最安全的做法：
//	  任何转义方案都有出错空间；命令的唯一硬约束（无换行）由校验保证。
//	· 日志路径由面板生成（不含单引号），用单引号包住。
//	· 记退出码：这是「任务跑了但失败了」的唯一证据。
//	· 不加 `set -e`：命令失败也要走到写退出码那一步。
func scriptBody(id, command, logPath string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# lipanel 计划任务包装脚本（面板生成，请勿手工编辑；删除任务时会一并移除）\n")
	b.WriteString("# 任务 ID: " + id + "\n")
	b.WriteString("# 命令输出与退出码写入: " + logPath + "\n")
	b.WriteString("echo \"==== lipanel cron run start $(date '+%Y-%m-%d %H:%M:%S %z') job=" + id + " ====\"\n")
	b.WriteString("{\n")
	b.WriteString(command + "\n")
	b.WriteString("} >> '" + logPath + "' 2>&1\n")
	b.WriteString("rc=$?\n")
	b.WriteString("echo \"==== lipanel cron run end $(date '+%Y-%m-%d %H:%M:%S %z') exit=$rc ====\"\n")
	b.WriteString("exit $rc\n")
	return b.String()
}

// LogEntry 是一次执行的日志块（以 start/end 分隔符切分）。
type LogEntry struct {
	// Raw 是该次执行的原文块。
	Raw string `json:"raw"`
	// Exit 是退出码；-1 表示没找到结束标记（任务仍在跑或被 kill）。
	Exit int `json:"exit"`
	// Status 是归一化结论：ok / failed / running。
	Status string `json:"status"`
}

// TailLog 读取任务日志尾部。
//
// 从**文件尾部向前**读固定字节窗口，而不是整个读进来再截尾：
// 一个刷屏的死循环任务能写出几百 MB 日志，
// 全量读取会让「看一下日志」这个只读操作把面板 OOM 掉。
//
// 文件不存在返回 found=false（任务从未执行过，不是错误）。
func TailLog(path string, lines int) (text string, found bool, truncated bool, err error) {
	if lines <= 0 {
		lines = DefaultLogTailLines
	}
	if lines > MaxLogTailLines {
		lines = MaxLogTailLines
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, false, nil
		}
		return "", false, false, fmt.Errorf("cron: 打开日志 %s 失败: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return "", false, false, fmt.Errorf("cron: 读取日志信息失败: %w", err)
	}
	size := st.Size()
	// 多取一些字节凑够行数，再按行裁。
	want := int64(lines+1) * 512
	if want > MaxLogTailBytes {
		want = MaxLogTailBytes
	}
	if size > want {
		if _, err := f.Seek(size-want, io.SeekStart); err != nil {
			return "", false, false, fmt.Errorf("cron: 定位日志尾部失败: %w", err)
		}
		truncated = true
	}
	buf, err := io.ReadAll(io.LimitReader(f, MaxLogTailBytes))
	if err != nil {
		return "", false, truncated, fmt.Errorf("cron: 读取日志失败: %w", err)
	}
	text = string(buf)
	// 截断点可能落在行中间：丢掉第一个不完整行。
	if truncated {
		if i := strings.IndexByte(text, '\n'); i >= 0 && i+1 < len(text) {
			text = text[i+1:]
		}
	}
	all := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
		truncated = true
	}
	return strings.Join(all, "\n"), true, truncated, nil
}

// ParseLogEntries 把日志文本切成执行块（按 start 标记）。
//
// 供接口层返回结构化历史；解析不出来时归入一个 unknown 块，
// 绝不丢弃原文——用户可能刚手工往日志里写了东西。
func ParseLogEntries(text string) []LogEntry {
	var out []LogEntry
	var cur []string
	inBlock := false
	for _, ln := range strings.Split(text, "\n") {
		if strings.Contains(ln, "lipanel cron run start") {
			if inBlock && len(cur) > 0 {
				out = append(out, buildEntry(cur))
			}
			cur = []string{ln}
			inBlock = true
			continue
		}
		if inBlock {
			cur = append(cur, ln)
			if strings.Contains(ln, "lipanel cron run end") {
				out = append(out, buildEntry(cur))
				cur = nil
				inBlock = false
			}
		} else if strings.TrimSpace(ln) != "" {
			out = append(out, LogEntry{Raw: ln, Exit: -1, Status: "unknown"})
		}
	}
	if inBlock && len(cur) > 0 {
		out = append(out, buildEntry(cur))
	}
	return out
}

func buildEntry(lines []string) LogEntry {
	raw := strings.Join(lines, "\n")
	exit := -1
	for _, ln := range lines {
		if i := strings.Index(ln, "exit="); i >= 0 && strings.Contains(ln, "lipanel cron run end") {
			var rc int
			if _, err := fmt.Sscanf(ln[i:], "exit=%d", &rc); err == nil {
				exit = rc
			}
		}
	}
	status := "running" // 没有结束标记：可能仍在执行，也可能被 kill
	if exit >= 0 {
		if exit == 0 {
			status = "ok"
		} else {
			status = "failed"
		}
	}
	return LogEntry{Raw: raw, Exit: exit, Status: status}
}

// RotateLogIfNeeded 在日志超过上限时原地截断（保留尾部一半）。
//
// 不做按天轮转：面板不提供日志归档功能（那属于系统 logrotate 的职责），
// 这里只需保证一件事——**跑疯了的任务不能把磁盘写满**。
// 截断而非清空：保留尾部才能看到出问题的现场。
func RotateLogIfNeeded(path string, maxBytes int64) (bool, error) {
	if maxBytes <= 0 {
		return false, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("cron: 检查日志体积失败: %w", err)
	}
	if st.Size() <= maxBytes {
		return false, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, fmt.Errorf("cron: 打开日志准备截断失败: %w", err)
	}
	defer func() { _ = f.Close() }()

	keep := maxBytes / 2
	off := st.Size() - keep
	buf := make([]byte, keep)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return false, fmt.Errorf("cron: 读取日志尾部失败: %w", err)
	}
	// 从第一个完整行开始，避免留下半行。
	if i := strings.IndexByte(string(buf), '\n'); i >= 0 && i+1 < len(buf) {
		buf = buf[i+1:]
	}
	head := fmt.Sprintf("==== lipanel 日志已截断（保留最近 %d 字节，原大小 %d 字节）%s ====\n",
		len(buf), st.Size(), time.Now().Format("2006-01-02 15:04:05"))
	if err := f.Truncate(0); err != nil {
		return false, fmt.Errorf("cron: 截断日志失败: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("cron: 回写日志失败: %w", err)
	}
	if _, err := f.WriteString(head + string(buf) + "\n"); err != nil {
		return false, fmt.Errorf("cron: 回写日志失败: %w", err)
	}
	return true, nil
}
