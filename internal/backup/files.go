package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ============================================================================
// 备份清单 / 下载 / 删除 / 恢复（阶段五 5.3）
// ============================================================================

// ListFiles 汇总各存储上的备份文件。
//
// taskID 非空时只列该任务的。返回的每一项都带 StorageID / Key，
// 而**下载与删除只接受从这里出现过的 key**（见 Manager.ResolveKey）。
func (m *Manager) ListFiles(ctx context.Context, taskID string, limit int) ([]FileEntry, error) {
	tasks, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	storages, err := m.store.Storages()
	if err != nil {
		return nil, err
	}
	if taskID != "" {
		if err := ValidateTaskID(taskID); err != nil {
			return nil, err
		}
		filtered := make([]*Task, 0, 1)
		for _, t := range tasks {
			if t.ID == taskID {
				filtered = append(filtered, t)
			}
		}
		tasks = filtered
	}
	if limit <= 0 {
		limit = 500
	}

	byStorage := map[string]*Storage{}
	for _, st := range storages {
		byStorage[st.ID] = st
	}
	// 按存储分组，避免同一个存储被多个任务重复连接多次。
	perStorage := map[string][]*Task{}
	for _, t := range tasks {
		perStorage[t.StorageID] = append(perStorage[t.StorageID], t)
	}

	out := []FileEntry{}
	for storageID, group := range perStorage {
		st := byStorage[storageID]
		if st == nil {
			// 存储配置已被删除：如实跳过（任务视图里会显示 storage_missing）。
			continue
		}
		be, err := m.backendFor(*st)
		if err != nil {
			// 单个存储连不上不该让整个清单页失败；
			// 返回空列表并在日志里说明。
			m.logger.Warn("列出备份时跳过不可用的存储",
				"storage", storageID, "type", st.Type, "err", err)
			continue
		}
		for _, t := range group {
			objects, lerr := be.List(ctx, taskPrefix(t))
			if lerr != nil {
				m.logger.Warn("列出某个任务的备份失败",
					"task", t.ID, "storage", storageID, "err", lerr)
				continue
			}
			for _, obj := range objects {
				out = append(out, fileEntryOf(t, st, obj))
			}
		}
		_ = be.Close()
	}

	// 按名字倒序（= 时间倒序，见 retention.go 的说明）。
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key > out[j].Key })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// fileEntryOf 把一个存储对象转成清单项。
func fileEntryOf(t *Task, st *Storage, obj Object) FileEntry {
	e := FileEntry{
		Key:         obj.Key,
		Name:        objectName(obj.Key),
		Size:        obj.Size,
		SizeKnown:   obj.SizeKnown,
		StorageID:   st.ID,
		StorageType: st.Type,
		TaskID:      t.ID,
		TaskName:    t.Name,
	}
	if !obj.ModTime.IsZero() {
		e.ModTime = obj.ModTime.Format("2006-01-02 15:04:05")
	}
	// 本地存储时给出磁盘路径（供"在文件管理页打开"用）。
	// 它是**面板自己拼出来的**，不接受任何外部输入。
	if st.Type == StorageLocal {
		full := filepath.Join(st.Path, filepath.FromSlash(joinKey(st.BasePath, obj.Key)))
		if contains(st.Path, full) {
			e.LocalPath = full
		}
	}
	return e
}

// ResolveKey 把一个对象名解析成 (存储, 任务, 对象)。
//
// ########## 为什么下载/删除必须先过这里 ##########
//
// 若接口直接接受一个对象名去存储上取，那它就是一个
// 「登录即可读取任意对象」的入口——运维面板上这个洞的后果是
// 用户能读到别处的数据（同桶里的其它文件）。
//
// 因此 key 必须能**反查回一个真实存在的任务**，且必须确实落在
// 该任务的前缀之下。这既是权限判定，也是存在性判定。
func (m *Manager) ResolveKey(ctx context.Context, storageID, key string) (*Task, *Storage, Object, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return nil, nil, Object{}, err
	}
	if err := ValidateTaskID(storageID); err != nil {
		return nil, nil, Object{}, invalid("storage_id", "存储标识形态非法")
	}
	st, err := m.store.FindStorage(storageID)
	if err != nil {
		return nil, nil, Object{}, err
	}
	if st == nil {
		return nil, nil, Object{}, fmt.Errorf("%w: %s", ErrStorageNotFound, storageID)
	}
	tasks, err := m.store.Tasks()
	if err != nil {
		return nil, nil, Object{}, err
	}
	// 找出 key 归属的任务：前缀匹配 + 必须落在某个任务的前缀下。
	var owner *Task
	for _, t := range tasks {
		if t.StorageID != storageID {
			continue
		}
		if strings.HasPrefix(key, taskPrefix(t)) {
			owner = t
			break
		}
	}
	if owner == nil {
		return nil, nil, Object{}, fmt.Errorf(
			"%w: 对象 %s 不属于该存储上的任何备份任务", ErrObjectNotFound, key)
	}

	be, err := m.backendFor(*st)
	if err != nil {
		return nil, nil, Object{}, err
	}
	defer func() { _ = be.Close() }()
	obj, err := be.Stat(ctx, key)
	if err != nil {
		return nil, nil, Object{}, err
	}
	return owner, st, obj, nil
}

// OpenFile 打开一个备份文件供下载。
//
// 返回的 ReadCloser 由调用方关闭；同时返回建议的文件名。
func (m *Manager) OpenFile(ctx context.Context, storageID, key string) (io.ReadCloser, int64, string, error) {
	_, st, _, err := m.ResolveKey(ctx, storageID, key)
	if err != nil {
		return nil, 0, "", err
	}
	be, err := m.backendFor(*st)
	if err != nil {
		return nil, 0, "", err
	}
	rc, size, err := be.Get(ctx, key)
	if err != nil {
		_ = be.Close()
		return nil, 0, "", err
	}
	// 包装一层：读完时把后端也关掉（本地后端是 no-op，
	// 但保持这个纪律，将来加连接池时不会漏）。
	return &backendReadCloser{rc: rc, be: be}, size, objectName(key), nil
}

// backendReadCloser 在关闭读取器的同时关闭后端。
type backendReadCloser struct {
	rc io.ReadCloser
	be Backend
}

func (b *backendReadCloser) Read(p []byte) (int, error) { return b.rc.Read(p) }

func (b *backendReadCloser) Close() error {
	err := b.rc.Close()
	if b.be != nil {
		_ = b.be.Close()
	}
	return err
}

// DeleteFile 删除一个备份文件（**只删存储上的对象，不删任务**）。
func (m *Manager) DeleteFile(ctx context.Context, storageID, key string, confirm bool) error {
	if !confirm {
		return ErrConfirmRequired
	}
	_, st, _, err := m.ResolveKey(ctx, storageID, key)
	if err != nil {
		return err
	}
	be, err := m.backendFor(*st)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()
	return be.Delete(ctx, key)
}

// PreviewRestoreFile 预览从某个备份恢复的影响面。
func (m *Manager) PreviewRestoreFile(ctx context.Context, storageID, key, targetDir string) (*RestorePreview, error) {
	task, st, _, err := m.ResolveKey(ctx, storageID, key)
	if err != nil {
		return nil, err
	}
	// 目标目录先过白名单并创建（预览时也要建：目标不存在意味着
	// "没有冲突"，而不是一个错误）。
	realTarget, err := m.CheckRestoreTarget(targetDir)
	if err != nil {
		return nil, err
	}
	open := func() (io.ReadCloser, error) {
		be, berr := m.backendFor(*st)
		if berr != nil {
			return nil, berr
		}
		rc, _, gerr := be.Get(ctx, key)
		if gerr != nil {
			_ = be.Close()
			return nil, gerr
		}
		return &backendReadCloser{rc: rc, be: be}, nil
	}
	prev, err := PreviewRestore(ctx, open, realTarget, task.Name, RestoreOptions{
		MaxEntries: m.maxEntries,
		MaxBytes:   m.maxArchive,
	})
	if err != nil {
		return nil, err
	}
	prev.Key = key
	return prev, nil
}

// RestoreFile 从某个备份恢复到目标目录。
//
// ########## 二次确认是服务端强制的 ##########
//
// confirm 必须为 true，**且 confirmText 必须逐字等于任务名**。
// 前端弹窗只是体验，服务端强制才是边界——恢复会覆盖目标目录里
// 同名的文件，那是本模块唯一不可逆的动作。
// 只比对"任务名"而不是让用户输入一长串目标路径的原因：
// 用户记得住的名字才是有效确认，而路径他会直接复制粘贴，
// 那样"确认"就退化成了回车。
func (m *Manager) RestoreFile(ctx context.Context, storageID, key, targetDir string,
	confirm bool, confirmText string) (*RestoreResult, error) {
	if !confirm {
		return nil, ErrConfirmRequired
	}
	task, st, _, err := m.ResolveKey(ctx, storageID, key)
	if err != nil {
		return nil, err
	}
	// ########## 逐字比对，不做任何归一化 ##########
	//
	// 不能 TrimSpace：那会让 " 任务名 " 也算通过。用户"顺手"粘贴一段
	// 带空白的文字就完成了确认，而这个门槛的全部意义就在于
	// "他必须亲手、准确地打出一个他在别处看到过的名字"。
	// 一个能被空白绕过的门槛等于没有门槛。
	//
	// 前端负责在提交前把输入框的空白去掉（见 backupLogic.js），
	// 因此正常用户永远不会撞到这个严格判定。
	if confirmText != task.Name {
		return nil, fmt.Errorf("%w: 需要逐字输入任务名 %q", ErrConfirmTextMismatch, task.Name)
	}
	realTarget, err := m.CheckRestoreTarget(targetDir)
	if err != nil {
		return nil, err
	}

	// 整次恢复也受执行超时约束：一个超大归档的解压同样可能很久。
	runCtx, cancel := context.WithTimeout(ctx, m.execTimeout)
	defer cancel()

	open := func() (io.ReadCloser, error) {
		be, berr := m.backendFor(*st)
		if berr != nil {
			return nil, berr
		}
		rc, _, gerr := be.Get(runCtx, key)
		if gerr != nil {
			_ = be.Close()
			return nil, gerr
		}
		return &backendReadCloser{rc: rc, be: be}, nil
	}
	res, err := Restore(runCtx, open, realTarget, RestoreOptions{
		MaxEntries: m.maxEntries,
		MaxBytes:   m.maxArchive,
	})
	if err != nil {
		return nil, err
	}
	res.Key = key
	return res, nil
}

// RestoreFromLocalFile 从 staging 之外的本地归档恢复（供 __backup_run 之外的工具使用）。
//
// 保留给测试与运维脚本：它跳过存储后端，直接从磁盘上的文件恢复。
func (m *Manager) RestoreFromLocalFile(ctx context.Context, archivePath, targetDir string,
	confirm bool, confirmText string) (*RestoreResult, error) {
	if !confirm {
		return nil, ErrConfirmRequired
	}
	if strings.TrimSpace(confirmText) == "" {
		return nil, fmt.Errorf("%w: 需要逐字输入任务名", ErrConfirmTextMismatch)
	}
	realTarget, err := m.CheckRestoreTarget(targetDir)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, m.execTimeout)
	defer cancel()
	open := func() (io.ReadCloser, error) {
		return os.Open(archivePath)
	}
	return Restore(runCtx, open, realTarget, RestoreOptions{
		MaxEntries: m.maxEntries,
		MaxBytes:   m.maxArchive,
	})
}

// FindTaskByName 按任务名精确查找（供确认文字比对与测试）。
func (m *Manager) FindTaskByName(name string) (*Task, error) {
	tasks, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	for _, t := range tasks {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, nil
}
