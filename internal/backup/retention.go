package backup

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// 保留策略（阶段五 5.3）
// ============================================================================
//
// ########## 为什么清理要以存储上的实际清单为准 ##########
//
// 最直觉的做法是"读历史记录，把超出的那些删掉"。但历史记录
// 只是一个**日志**：它可能因为手工删过、面板重装过而丢失，
// 而存储上的文件还在那里占着空间。
//
// 反过来，如果按历史删，会出现两种坏情况：
//   · 历史丢了 → 旧备份永远不被清理，磁盘慢慢被吃满；
//   · 历史里有但存储上已被手工删掉 → 每次清理报一堆"删除失败"，
//     把真正的问题淹没。
//
// 因此清理的**依据是 backend.List 的真实结果**，历史只用来展示。
//
// ########## 为什么靠名字排序而不是 mtime ##########
//
// 归档名里内嵌了定长时间戳（<taskid>-20060102-150405.tar.gz），
// 因此字典序就是时间序。而 mtime 在各家 S3 实现与 WebDAV 服务端上
// 精度与语义并不一致（有的返回秒级、有的返回分钟级、有的干脆不返回），
// 依赖它就会出现"该删的没删、不该删的删了"——
// 后者对备份工具是不可接受的：删掉了还想留的那一份。

// RetentionResult 是清理结果。
type RetentionResult struct {
	// Deleted 是删掉的份数。
	Deleted int
	// Kept 是保留下来的份数。
	Kept int
	// Errors 是逐条失败原因（清理失败**不影响备份本身成功**）。
	Errors []string
}

// ApplyRetention 按策略清理某个任务的旧备份。
//
// 返回的 error 只用于"策略本身无法执行"（例如列不出对象）；
// 单份删除失败记进 Errors，因为那不影响刚做完的这次备份，
// 但必须让用户看到（否则磁盘会安静地涨）。
func ApplyRetention(ctx context.Context, be Backend, task *Task, now time.Time) (*RetentionResult, error) {
	res := &RetentionResult{Errors: []string{}}
	if task == nil {
		return res, nil
	}
	policy := task.KeepPolicy
	if policy == "" {
		policy = KeepNone
	}
	if policy == KeepNone {
		return res, nil
	}

	prefix := taskPrefix(task)
	objects, err := be.List(ctx, prefix)
	if err != nil {
		return res, fmt.Errorf("backup: 列出已有备份失败: %w", err)
	}
	if len(objects) == 0 {
		return res, nil
	}
	// List 的实现保证按 key 升序 —— 即时间升序。
	// 这里再排一次是防御性的：万一某个后端漏了排序，
	// 后果是删错文件（删掉最新的那份），代价太大，不值得省这一行。
	sortObjects(objects)

	keep := keepSet(task, objects, now)
	for _, obj := range objects {
		if keep[obj.Key] {
			res.Kept++
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := be.Delete(ctx, obj.Key); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", obj.Key, err))
			continue
		}
		res.Deleted++
	}
	return res, nil
}

// keepSet 计算哪些对象要保留。
func keepSet(task *Task, objects []Object, now time.Time) map[string]bool {
	keep := map[string]bool{}
	switch task.KeepPolicy {
	case KeepCount:
		n := task.KeepCount
		if n <= 0 {
			return keep // 策略非法：一份都不留（由校验层拦住，这里兜底）
		}
		// 保留**最新**的 n 份：从末尾往前数。
		for i := len(objects) - 1; i >= 0 && len(keep) < n; i-- {
			keep[objects[i].Key] = true
		}
	case KeepDays:
		days := task.KeepDays
		if days <= 0 {
			return keep
		}
		cutoff := now.AddDate(0, 0, -days)
		for _, obj := range objects {
			// 优先用对象名里的时间戳判定——那是**归档自己的时间**，
			// 与远端 mtime 无关（见文件头说明）。
			t, ok := archiveTime(obj.Key)
			if !ok {
				// 名字解析不出来的对象（用户手工放进来的文件）
				// 一律保留：我们不知道它是什么，就不该替用户删掉它。
				keep[obj.Key] = true
				continue
			}
			if !t.Before(cutoff) {
				keep[obj.Key] = true
			}
		}
	}
	return keep
}

// archiveTime 从归档名里解析出时间戳。
//
// 名字形态：<任意前缀>/<12位id>-20060102-150405.tar.gz
func archiveTime(key string) (time.Time, bool) {
	name := objectName(key)
	name = strings.TrimSuffix(name, ".tar.gz")
	if name == "" {
		return time.Time{}, false
	}
	// 时间戳固定在最后 15 个字符（20060102-150405）。
	const stampLen = 15
	if len(name) < stampLen+1 {
		return time.Time{}, false
	}
	stamp := name[len(name)-stampLen:]
	t, err := time.ParseInLocation("20060102-150405", stamp, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// taskPrefix 返回某个任务在存储上的对象名前缀。
//
// ########## 前缀必须带上任务 id，不能只用用户填的 prefix ##########
//
// 两个任务若填了同一个 prefix，清理时会把对方刚做的备份删掉——
// 这是"保留策略"最危险的形态：它删除的是**别人**的数据。
// 因此前缀始终以任务 id 结尾，用户填的 prefix 只是它前面的一段路径。
func taskPrefix(task *Task) string {
	if task.Prefix == "" {
		return task.ID + "/"
	}
	return strings.Trim(task.Prefix, "/") + "/" + task.ID + "/"
}

// ArchiveKeyFor 生成某个任务这一时刻的归档对象名。
func ArchiveKeyFor(task *Task, t time.Time) string {
	// 时间戳格式里的字面量 2006/01/02 是 Go 的参考时间，
	// 不是可配置项——它决定了"字典序即时间序"成立。
	return fmt.Sprintf("%s/%s-%s.tar.gz",
		strings.Trim(taskPrefix(task), "/"), task.ID, t.Format("20060102-150405"))
}

// RetentionSummary 生成保留策略的中文描述（前端与审计共用）。
func RetentionSummary(task *Task) string {
	if task == nil {
		return ""
	}
	switch task.KeepPolicy {
	case KeepCount:
		return fmt.Sprintf("保留最近 %d 份", task.KeepCount)
	case KeepDays:
		return fmt.Sprintf("保留最近 %d 天", task.KeepDays)
	default:
		return "不自动清理"
	}
}
