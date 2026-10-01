package backup

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ============================================================================
// 执行历史（阶段五 5.3）
// ============================================================================
//
// ########## 为什么是每任务一个 JSONL 文件 ##########
//
// 备份执行有两个进程：面板本体（手动执行）与 crontab 拉起的
// 自调用子进程（定时执行）。两者都要写历史，而它们**不共享内存**。
//
// 因此历史必须是"多个写者、只追加"的格式：
//
//	· JSONL 追加写（O_APPEND）在小块写入上是原子的（PIPE_BUF 以内），
//	  两个进程同时写不会互相撕裂对方的行；
//	· 每任务一个文件，把并发写降到"同一个任务同时被手动与定时触发"
//	  这一种情况——而那正是执行锁要拦住的；
//	· 一行一条记录，坏掉一行不影响其它行（JSON 文件坏一个字节就全废）。
//
// ########## 面板本体为什么只读不写这个文件 ##########
//
// 面板本体写历史走的是同一份 AppendHistory；而**配置**（tasks.json）
// 只有面板本体写。两个文件、两种写者，各管一摊，不存在
// "两个进程改同一个配置文件"的问题。

// historyFileName 返回某个任务的历史文件路径。
func (m *Manager) historyFileName(taskID string) string {
	return filepath.Join(m.historyDir, taskID+".jsonl")
}

// AppendHistory 追加一条执行记录。
//
// 写失败返回错误，但调用方（执行流程）**不应**因此判定备份失败：
// 备份本身已经成功产出了归档文件，此时把整次执行标成失败，
// 用户会重跑一次并在存储上得到两份备份。因此执行流程会
// 把这里的错误降级成警告。
func (m *Manager) AppendHistory(entry *HistoryEntry) error {
	if entry == nil {
		return errors.New("backup: 历史记录为空")
	}
	if entry.TaskID == "" {
		return errors.New("backup: 历史记录缺少任务 id")
	}
	if err := os.MkdirAll(m.historyDir, storeDirMode); err != nil {
		return fmt.Errorf("backup: 创建历史目录失败: %w", err)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("backup: 序列化历史记录失败: %w", err)
	}
	raw = append(raw, '\n')

	path := m.historyFileName(entry.TaskID)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, storeFileMode)
	if err != nil {
		return fmt.Errorf("backup: 打开历史文件失败: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("backup: 写入历史记录失败: %w", err)
	}
	return nil
}

// pruneHistory 在历史文件过长时截断，只保留最近若干条。
//
// 截断用"重写整个文件"而不是"从头部删"：文件系统没有"删头部"
// 这个操作，而重写一个几百 KB 的文件代价可以忽略。
// 为降低重写与追加撞车的概率，这里用独立的锁——两条执行路径
// （手动 / cron）可能同时在写。
func (m *Manager) pruneHistory(taskID string) error {
	m.histMu.Lock()
	defer m.histMu.Unlock()

	path := m.historyFileName(taskID)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("backup: 读取历史文件失败: %w", err)
	}
	lines := splitNonEmptyLines(string(data))
	if len(lines) <= m.maxHistory {
		return nil
	}
	keep := lines[len(lines)-m.maxHistory:]
	body := strings.Join(keep, "\n") + "\n"

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), storeFileMode); err != nil {
		return fmt.Errorf("backup: 写入历史临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: 截断历史文件失败: %w", err)
	}
	return nil
}

// splitNonEmptyLines 按行拆分并丢弃空行。
func splitNonEmptyLines(s string) []string {
	out := []string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	// 单条历史记录不大，但默认的 64KB 上限对"某条记录里带一长串
	// 告警文本"的情况可能不够，放大到 1MB。
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// ReadHistory 读取某个任务的历史（倒序，最新在前）。
func (m *Manager) ReadHistory(taskID string, limit int) ([]*HistoryEntry, error) {
	if err := ValidateTaskID(taskID); err != nil {
		return nil, err
	}
	// ########## 任务不存在必须报错，不能返回空列表 ##########
	//
	// 若这里直接读文件、读不到就返回 []，那么"id 打错了"与
	// "这条任务确实还没跑过"在接口上完全一样（都是 200 + 空数组）。
	// 用户会对着一个不存在的任务反复点刷新，而界面永远告诉他
	// "暂无执行记录"。
	//
	// 判定必须基于**配置里有没有这条任务**，而不是历史文件在不在：
	// 删除任务时我们刻意保留历史文件（留痕），因此文件存在
	// 并不能说明任务还在。
	if t, err := m.store.FindTask(taskID); err != nil {
		return nil, err
	} else if t == nil {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, taskID)
	}
	if limit <= 0 {
		limit = 50
	}
	m.histMu.Lock()
	data, err := os.ReadFile(m.historyFileName(taskID))
	m.histMu.Unlock()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []*HistoryEntry{}, nil
		}
		return nil, fmt.Errorf("backup: 读取历史文件失败: %w", err)
	}
	lines := splitNonEmptyLines(string(data))
	out := make([]*HistoryEntry, 0, limit)
	// 从后往前取：最新的在文件末尾。
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		var entry HistoryEntry
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			// 一行坏掉就跳过它，并在记录里标出来——
			// 宁可少一条历史，也不要因为一行的问题让整个页面打不开。
			continue
		}
		out = append(out, &entry)
	}
	return out, nil
}

// ReadAllHistory 汇总所有任务的历史（倒序，最新在前）。
//
// 用于「备份历史」页：它不是按任务分组的视图，而是"这台机器上
// 最近发生过什么备份"的时间线。
func (m *Manager) ReadAllHistory(limit int) ([]*HistoryEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(m.historyDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []*HistoryEntry{}, nil
		}
		return nil, fmt.Errorf("backup: 读取历史目录失败: %w", err)
	}
	out := []*HistoryEntry{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		taskID := strings.TrimSuffix(e.Name(), ".jsonl")
		list, err := m.ReadHistory(taskID, limit)
		if err != nil {
			continue
		}
		out = append(out, list...)
	}
	// 按开始时间倒序。字符串比较在这里是有效的：
	// 全是同一格式（RFC3339，同机同时区）。
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].StartedAt > out[j].StartedAt
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// LastEntry 返回某个任务最近一次执行记录（没有时返回 nil, nil）。
func (m *Manager) LastEntry(taskID string) (*HistoryEntry, error) {
	list, err := m.ReadHistory(taskID, 1)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}
