package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ============================================================================
// 执行互斥（阶段五 5.3）
// ============================================================================
//
// 同一个任务可能在两个进程里被同时触发：
//
//	面板本体的「立即执行」   → 进程 A
//	crontab 拉起的定时执行   → 进程 B
//
// 二者会往**同一个对象名**里写（对象名里的时间戳精确到秒），
// 于是出现"两个 tar.gz 写同一个文件"——最终存储上是哪一份取决于
// 谁后完成，而用户看到的可能是半截内容（本地后端 tmp+rename 能
// 保证不出现半截文件，但两个进程会互相覆盖，结果仍然不可预期）。
//
// ########## 为什么不用进程内锁 ##########
//
// sync.Mutex 只在同一个进程内有效，而这里的两个触发源本来就是
// **两个进程**。因此必须用文件系统层面的锁。
//
// ########## 为什么不用 flock ##########
//
// flock(2) 需要 golang.org/x/sys 或 syscall.Flock，而后者在
// Windows 上不可用（本项目的发布矩阵包含 Windows）。用
// O_CREATE|O_EXCL 创建锁文件是**跨平台**的，代价是需要自己处理
// "进程被 kill 后锁文件留在磁盘上"这件事。
//
// ########## 陈旧锁的接管 ##########
//
// 进程被 SIGKILL 或机器断电时锁文件不会被清理。因此锁文件里
// 记着**开始时间**，超过 ExecTimeout 之后视为陈旧并接管。
// 判定用"锁文件的 mtime"而不是文件内容里的时间戳：
// 前者不受系统时间被调整的影响，而且即便文件内容写坏了也依然可用。

// lockFileName 返回某个任务的锁文件路径。
func (m *Manager) lockFileName(taskID string) string {
	return filepath.Join(m.lockDir, taskID+".lock")
}

// lockInfo 是锁文件的内容（供排查"谁占着锁"）。
type lockInfo struct {
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	Trigger   string `json:"trigger,omitempty"`
}

// TryLock 尝试获取某个任务的执行锁。
//
// 成功返回 (true, 释放函数, nil)。失败返回 (false, nil, nil)——
// "已被占用"是一种**正常状态**而不是错误，调用方据此把这次执行
// 记成 skipped 并如实说明原因。
func (m *Manager) TryLock(taskID, trigger string) (bool, func(), error) {
	if err := ValidateTaskID(taskID); err != nil {
		return false, nil, err
	}
	if err := os.MkdirAll(m.lockDir, storeDirMode); err != nil {
		return false, nil, fmt.Errorf("backup: 创建锁目录失败: %w", err)
	}
	path := m.lockFileName(taskID)

	ok, err := m.acquireLock(path, trigger)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		// 已被占用：检查是不是陈旧锁。
		reclaimed, rerr := m.reclaimStale(path, trigger)
		if rerr != nil {
			return false, nil, rerr
		}
		if !reclaimed {
			return false, nil, nil
		}
	}
	release := func() {
		// 删除失败不改变"锁已被释放"这个事实对调用方的意义，
		// 但会让后续执行可能被一个不存在的进程挡住——
		// 陈旧判定会兜住，因此这里只尽力而为。
		_ = os.Remove(path)
	}
	return true, release, nil
}

// acquireLock 用 O_CREATE|O_EXCL 原子地创建锁文件。
func (m *Manager) acquireLock(path, trigger string) (bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, storeFileMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("backup: 创建锁文件失败: %w", err)
	}
	info, _ := json.Marshal(lockInfo{
		PID:       os.Getpid(),
		StartedAt: m.now().Format(time.RFC3339),
		Trigger:   trigger,
	})
	_, _ = f.Write(append(info, '\n'))
	_ = f.Close()
	return true, nil
}

// reclaimStale 尝试接管一个陈旧的锁。
func (m *Manager) reclaimStale(path, trigger string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// 锁在我们的检查期间被释放了：再抢一次。
			return m.acquireLock(path, trigger)
		}
		return false, fmt.Errorf("backup: 检查锁文件失败: %w", err)
	}
	timeout := m.execTimeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	// 留出 2 倍余量：一次合法但接近超时的执行不该被误判成陈旧，
	// 那会造成两个进程同时写同一份备份。
	if m.now().Sub(info.ModTime()) < timeout*2 {
		return false, nil
	}

	m.logger.Warn("发现陈旧的执行锁（持有它的进程可能已被强杀），将接管",
		"path", path, "age", m.now().Sub(info.ModTime()).String())

	// 先删再抢。中间存在一个极小的窗口，两个接管者可能同时删、
	// 再同时抢——但只有一个能成功（O_EXCL），另一个会走
	// "已被占用"分支并放弃，因此不会出现两个执行者。
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("backup: 清理陈旧锁失败: %w", err)
	}
	return m.acquireLock(path, trigger)
}

// LockHeld 报告某个任务此刻是否被占用（供列表展示"正在执行"）。
func (m *Manager) LockHeld(taskID string) bool {
	if err := ValidateTaskID(taskID); err != nil {
		return false
	}
	_, err := os.Stat(m.lockFileName(taskID))
	return err == nil
}
