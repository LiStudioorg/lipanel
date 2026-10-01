package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lipanel/internal/cron"
)

// ============================================================================
// 管理器 / 存储 / 锁 / cron 挂接的测试（阶段五 5.3）
// ============================================================================

// newTestManager 造一个完全隔离的测试管理器。
//
// ########## 全程隔离是硬要求 ##########
//
// 数据目录、源白名单、恢复白名单全部指向 t.TempDir()。
// 绝不允许任何一个用例碰宿主机上真实的备份目录、crontab 或系统路径
// ——与 4.6 的假执行器、5.2 的 -cron-file 同一条纪律。
func newTestManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	dataDir := t.TempDir()
	if opts.DataDir == "" {
		opts.DataDir = dataDir
	}
	if len(opts.SourceRoots) == 0 {
		opts.SourceRoots = []string{dataDir}
	}
	if len(opts.RestoreRoots) == 0 {
		opts.RestoreRoots = []string{dataDir}
	}
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	m, err := NewManager(opts)
	if err != nil {
		t.Fatalf("构造管理器失败: %v", err)
	}
	return m
}

// seedTask 造一条可直接执行的任务（源目录已在白名单内）。
func seedTask(t *testing.T, m *Manager, files map[string]string) (*Task, *Storage) {
	t.Helper()
	srcRoot := m.srcResolver.Roots()[0].Path
	src := filepath.Join(srcRoot, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if files == nil {
		files = map[string]string{"data.txt": "content"}
	}
	writeTree(t, src, files)

	dst := filepath.Join(srcRoot, "store")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := m.CreateStorage(StorageInput{
		Name: "本地", Type: StorageLocal, Path: dst,
	})
	if err != nil {
		t.Fatalf("建存储失败: %v", err)
	}
	view, err := m.CreateTask(context.Background(), TaskInput{
		Name: "测试任务", Type: TypeFull, SourceType: SourceDir,
		SourcePath: src, StorageID: st.ID, Expr: "0 3 * * *",
		KeepPolicy: KeepCount, KeepCount: 3,
	})
	if err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	task, err := m.FindTaskByID(view.ID)
	if err != nil || task == nil {
		t.Fatalf("回读任务失败: %v", err)
	}
	return task, st
}

// ---------------------------------------------------------------------------
// 配置文件
// ---------------------------------------------------------------------------

func TestStoreRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tasks.json")

	st, err := NewStore(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); err != nil {
		t.Fatalf("首次加载（文件不存在）应成功: %v", err)
	}

	task := &Task{
		ID: "abcdef123456", Name: "备份 nginx", Type: TypeFull,
		SourceType: SourceDir, SourcePath: "/var/www",
		StorageID: "111111111111", Expr: "0 3 * * *", Enabled: true,
		KeepPolicy: KeepCount, KeepCount: 5,
	}
	if err := st.Mutate(func(d *storeData) error {
		d.Tasks = append(d.Tasks, task)
		return nil
	}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	// 权限必须是 0600：配置里有 S3 的 SecretKey 与 WebDAV 密码。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("配置文件权限 = %04o, 期望 0600（里面有存储凭证）", info.Mode().Perm())
	}

	// 重新加载（模拟重启）。
	st2, err := NewStore(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Load(); err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	tasks, err := st2.Tasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].Name != "备份 nginx" {
		t.Fatalf("重新加载后的任务不对: %+v", tasks)
	}
}

// 配置文件损坏时**必须报错**，绝不能悄悄重置成空配置。
//
// 静默重置的后果：用户装好面板重启一次，所有备份任务凭空消失，
// 而界面显示"一切正常，暂无任务"。
func TestStoreCorruptFileIsHardError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tasks.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); err == nil {
		t.Fatalf("损坏的配置文件竟然加载成功了（会静默丢掉所有任务）")
	}
	// 且不能覆盖原文件——用户还能手工修它。
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "not json") {
		t.Fatalf("损坏的配置被覆盖了，用户失去了手工修复的机会")
	}
}

// Redacted() 不能就地改内部状态。
func TestStoreStoragesRedactionDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "tasks.json"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Mutate(func(d *storeData) error {
		d.Storages = append(d.Storages, &Storage{
			ID: "111111111111", Name: "s3", Type: StorageS3,
			Bucket: "b", AccessKey: "a", SecretKey: "topsecret",
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	list, err := st.Storages()
	if err != nil {
		t.Fatal(err)
	}
	// 调用方（任务执行路径）拿到的必须是**含凭证**的原件。
	if list[0].SecretKey != "topsecret" {
		t.Fatalf("Storages() 返回了已脱敏的副本，执行时就没密钥可用了")
	}
	red := list[0].Redacted()
	if red.SecretKey != "" {
		t.Fatalf("脱敏副本仍有密钥")
	}
	// 再取一次，密钥必须还在（说明 Redacted 没改到内部）。
	again, _ := st.Storages()
	if again[0].SecretKey != "topsecret" {
		t.Fatalf("Redacted() 改动了内部状态，密钥被抹掉了")
	}
}

// Mutate 失败时必须回滚内存，不能让内存与磁盘不一致。
func TestStoreMutateRollbackOnFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "tasks.json"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Mutate(func(d *storeData) error {
		d.Tasks = append(d.Tasks, &Task{ID: "abcdef123456", Name: "one"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 一个会失败的变更：先加了东西再返回错误。
	wantErr := errors.New("模拟写入失败")
	err = st.Mutate(func(d *storeData) error {
		d.Tasks = append(d.Tasks, &Task{ID: "ffffffffffff", Name: "two"})
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("期望返回写入错误，实际 %v", err)
	}
	tasks, _ := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("失败的变更留在了内存里：%d 条任务（期望 1）", len(tasks))
	}
}

// ---------------------------------------------------------------------------
// 任务 CRUD
// ---------------------------------------------------------------------------

func TestCreateTaskValidates(t *testing.T) {
	m := newTestManager(t, Options{})
	st := createLocalStorage(t, m)

	cases := []struct {
		name  string
		input TaskInput
		field string
	}{
		{"空名字", TaskInput{Name: "", StorageID: st.ID, SourcePath: "/x", Expr: "0 3 * * *"}, "name"},
		{"空源路径", TaskInput{Name: "n", StorageID: st.ID, SourcePath: "", Expr: "0 3 * * *"}, "source_path"},
		{"空存储", TaskInput{Name: "n", SourcePath: "/x", Expr: "0 3 * * *"}, "storage_id"},
		{"非法表达式", TaskInput{Name: "n", StorageID: st.ID, SourcePath: "/x", Expr: "not a cron"}, "expr"},
		{"按份数但没给份数", TaskInput{Name: "n", StorageID: st.ID, SourcePath: "/x",
			Expr: "0 3 * * *", KeepPolicy: KeepCount}, "keep_count"},
		{"份数超上限", TaskInput{Name: "n", StorageID: st.ID, SourcePath: "/x",
			Expr: "0 3 * * *", KeepPolicy: KeepCount, KeepCount: MaxKeepCount + 1}, "keep_count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.CreateTask(context.Background(), tc.input)
			if err == nil {
				t.Fatalf("非法输入竟然创建成功了")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("期望 ValidationError，实际 %T: %v", err, err)
			}
			if ve.Field != tc.field {
				t.Fatalf("错误字段 = %q, 期望 %q（前端要据此高亮表单项）", ve.Field, tc.field)
			}
		})
	}
}

// 引用一个不存在的存储必须当场被拒。
func TestCreateTaskRejectsMissingStorage(t *testing.T) {
	m := newTestManager(t, Options{})
	_, err := m.CreateTask(context.Background(), TaskInput{
		Name: "n", SourceType: SourceDir, SourcePath: "/tmp",
		StorageID: "deadbeef0000", Expr: "0 3 * * *",
	})
	if err == nil {
		t.Fatalf("引用了不存在的存储竟然创建成功")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "storage_id" {
		t.Fatalf("期望 storage_id 字段错误，实际 %v", err)
	}
}

// 删除任务必须带 confirm。
func TestDeleteTaskRequiresConfirm(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)

	if _, err := m.DeleteTask(context.Background(), task.ID, false, nil); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("无确认删除：期望 ErrConfirmRequired，实际 %v", err)
	}
	tasks, _ := m.ListTasks(context.Background())
	if len(tasks) != 1 {
		t.Fatalf("被拒绝的删除竟然生效了")
	}
	if _, err := m.DeleteTask(context.Background(), task.ID, true, nil); err != nil {
		t.Fatalf("带确认的删除失败: %v", err)
	}
	tasks, _ = m.ListTasks(context.Background())
	if len(tasks) != 0 {
		t.Fatalf("删除后仍有 %d 条任务", len(tasks))
	}
}

// 乐观并发：expected_ids 与现状不符时必须 409，且**不做任何改动**。
func TestTaskEditConflict(t *testing.T) {
	m := newTestManager(t, Options{})
	createLocalStorage(t, m)
	task, _ := seedTask(t, m, nil)

	// 客户端以为有一个不存在的任务。
	_, err := m.UpdateTask(context.Background(), task.ID, TaskInput{
		Name: "改名", Type: TypeFull, SourceType: SourceDir, SourcePath: task.SourcePath,
		StorageID: task.StorageID, Expr: "0 4 * * *",
		ExpectedIDs: []string{task.ID, "999999999999"},
	})
	if !errors.Is(err, ErrEditConflict) {
		t.Fatalf("期望 ErrEditConflict，实际 %v", err)
	}
	var detail *ErrEditConflictDetail
	if !errors.As(err, &detail) {
		t.Fatalf("期望能拿到冲突详情，实际 %T", err)
	}
	if !detail.Current {
		t.Fatalf("冲突详情应说明「你以为有、其实没有」")
	}

	// 原任务必须原封不动。
	after, _ := m.FindTaskByID(task.ID)
	if after.Name != task.Name || after.Expr != task.Expr {
		t.Fatalf("被拒绝的编辑竟然改了任务: %+v", after)
	}
}

// ---------------------------------------------------------------------------
// 存储配置
// ---------------------------------------------------------------------------

func createLocalStorage(t *testing.T, m *Manager) *Storage {
	t.Helper()
	root := m.srcResolver.Roots()[0].Path
	dir := filepath.Join(root, "store-"+strings.ReplaceAll(t.Name(), "/", "_"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := m.CreateStorage(StorageInput{Name: "本地 " + t.Name(), Type: StorageLocal, Path: dir})
	if err != nil {
		t.Fatalf("建存储失败: %v", err)
	}
	return st
}

// 被任务引用的存储不能删（默默删掉会让任务在下一次执行时才失败）。
func TestDeleteStorageInUse(t *testing.T) {
	m := newTestManager(t, Options{})
	task, st := seedTask(t, m, nil)

	usedBy, err := m.DeleteStorage(context.Background(), st.ID, true)
	if !errors.Is(err, ErrStorageInUse) {
		t.Fatalf("期望 ErrStorageInUse，实际 %v", err)
	}
	if len(usedBy) != 1 || usedBy[0] != task.Name {
		t.Fatalf("应报出引用它的任务名，实际 %v", usedBy)
	}
	// 存储必须还在。
	if s, _ := m.FindStorageRaw(st.ID); s == nil {
		t.Fatalf("被拒绝的删除竟然生效了")
	}
}

func TestDeleteStorageRequiresConfirm(t *testing.T) {
	m := newTestManager(t, Options{})
	st := createLocalStorage(t, m)
	if _, err := m.DeleteStorage(context.Background(), st.ID, false); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("期望 ErrConfirmRequired，实际 %v", err)
	}
}

// 编辑存储时"没传密钥"必须表示**不改动**，而不是清空。
//
// 这是最容易造成退化的一处：接口不回显密钥，前端提交时字段为空。
// 若把空当成清空，用户改一下名字，下一次备份就直接失败。
func TestUpdateStorageKeepsSecretWhenOmitted(t *testing.T) {
	m := newTestManager(t, Options{})
	st, err := m.CreateStorage(StorageInput{
		Name: "s3", Type: StorageS3, Endpoint: "http://localhost:9000",
		Bucket: "b", Region: "us-east-1", AccessKey: "AKIA", SecretKey: strPtr("topsecret"),
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("建 S3 存储失败: %v", err)
	}

	// 只改名字，不带密钥字段。
	updated, err := m.UpdateStorage(st.ID, StorageInput{
		Name: "s3-改过名字", Type: StorageS3, Endpoint: "http://localhost:9000",
		Bucket: "b", Region: "us-east-1", AccessKey: "AKIA",
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if updated.Name != "s3-改过名字" {
		t.Fatalf("名字没改: %q", updated.Name)
	}
	raw, _ := m.FindStorageRaw(st.ID)
	if raw.SecretKey != "topsecret" {
		t.Fatalf("密钥被清空了（R=%q）——改个名字就把凭证抹掉", raw.SecretKey)
	}
}

// 类型切换时旧类型的凭证必须清掉。
func TestUpdateStorageClearsSecretOnTypeChange(t *testing.T) {
	m := newTestManager(t, Options{})
	st, err := m.CreateStorage(StorageInput{
		Name: "s3", Type: StorageS3, Endpoint: "http://x", Bucket: "b",
		AccessKey: "a", SecretKey: strPtr("s3secret"), PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := m.srcResolver.Roots()[0].Path
	dir := filepath.Join(root, "newlocal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateStorage(st.ID, StorageInput{
		Name: "改成本地", Type: StorageLocal, Path: dir,
	}); err != nil {
		t.Fatalf("切换类型失败: %v", err)
	}
	raw, _ := m.FindStorageRaw(st.ID)
	if raw.SecretKey != "" {
		t.Fatalf("切换成本地存储后仍留着 S3 密钥: %q", raw.SecretKey)
	}
}

// ---------------------------------------------------------------------------
// 执行
// ---------------------------------------------------------------------------

// 手动执行一遍：归档必须落到存储上、历史必须写下、状态必须是 ok。
func TestRunNowWritesArchiveAndHistory(t *testing.T) {
	m := newTestManager(t, Options{})
	task, st := seedTask(t, m, map[string]string{
		"a.txt": "hello", "sub/b.txt": "world",
	})

	res, err := m.RunNow(context.Background(), task.ID, "admin")
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.Skipped {
		t.Fatalf("第一次执行不该被跳过")
	}
	entry := res.Entry
	if entry.Status != StatusOK {
		t.Fatalf("状态 = %s, 错误 = %s", entry.Status, entry.Error)
	}
	if entry.ArchiveKey == "" {
		t.Fatalf("没有归档对象名")
	}
	if entry.ArchiveBytes <= 0 {
		t.Fatalf("归档体积 = %d", entry.ArchiveBytes)
	}
	if entry.FileCount != 2 {
		t.Fatalf("FileCount = %d, 期望 2", entry.FileCount)
	}

	// 存储上确实有一个对象。
	be, err := m.backendFor(*st)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()
	if _, err := be.Stat(context.Background(), entry.ArchiveKey); err != nil {
		t.Fatalf("存储上看不到归档: %v", err)
	}

	// 历史里有记录（且最新的那条是 ok）。
	entries, err := m.ReadHistory(task.ID, 10)
	if err != nil {
		t.Fatalf("读历史失败: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("历史为空")
	}
	if entries[0].Status != StatusOK {
		t.Fatalf("最新一条历史状态 = %s", entries[0].Status)
	}

	// staging 必须被清干净（失败的清理会安静地吃磁盘）。
	leftovers, _ := os.ReadDir(m.stagingDir)
	if len(leftovers) != 0 {
		t.Fatalf("staging 里残留了 %d 个文件", len(leftovers))
	}
}

// 源路径不存在时执行**失败但留痕**（而不是返回一个没有记录的错）。
func TestRunNowFailsWithHistoryOnBadSource(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)
	// 手动把源目录删掉，模拟"任务配好了但目录后来没了"。
	if err := os.RemoveAll(task.SourcePath); err != nil {
		t.Fatal(err)
	}

	res, err := m.RunNow(context.Background(), task.ID, "admin")
	if err != nil {
		t.Fatalf("执行本身应该成功返回（失败写在历史里）: %v", err)
	}
	if res.Entry.Status != StatusFailed {
		t.Fatalf("状态 = %s, 期望 failed", res.Entry.Status)
	}
	if res.Entry.Error == "" {
		t.Fatalf("失败必须给出原因")
	}
	entries, _ := m.ReadHistory(task.ID, 10)
	found := false
	for _, e := range entries {
		if e.Status == StatusFailed && e.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("失败没有写进历史（用户看不到为什么没备份成功）")
	}
}

// 存储被删掉后执行必须给出**可理解**的失败原因。
func TestRunNowFailsWhenStorageGone(t *testing.T) {
	m := newTestManager(t, Options{})
	task, st := seedTask(t, m, nil)
	// 直接改配置把存储抹掉（绕过"被引用不让删"的保护，模拟手工改文件）。
	if err := m.store.Mutate(func(d *storeData) error {
		d.Storages = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = st

	res, err := m.RunNow(context.Background(), task.ID, "admin")
	if err != nil {
		t.Fatalf("执行本身应成功返回: %v", err)
	}
	if res.Entry.Status != StatusFailed {
		t.Fatalf("状态 = %s, 期望 failed", res.Entry.Status)
	}
	if !strings.Contains(res.Entry.Error, "存储") {
		t.Fatalf("失败原因应提到存储配置: %q", res.Entry.Error)
	}
}

// 并发执行必须**互斥**：第二次被跳过，而不是两份任务同时写同一个对象。
func TestExecuteMutualExclusion(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)

	// 手工占住锁。
	locked, release, err := m.TryLock(task.ID, TriggerManual)
	if err != nil || !locked {
		t.Fatalf("取锁失败: %v", err)
	}
	defer release()

	// 此时再取一次必须失败（false, nil, nil —— 这是正常状态不是错误）。
	again, _, err := m.TryLock(task.ID, TriggerManual)
	if err != nil {
		t.Fatalf("重复取锁不该报错: %v", err)
	}
	if again {
		t.Fatalf("同一个任务同时取到了两把锁")
	}

	res, err := m.RunNow(context.Background(), task.ID, "admin")
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !res.Skipped {
		t.Fatalf("已有执行在跑时，本次应被跳过")
	}
	if res.Entry.Status != StatusSkipped {
		t.Fatalf("状态 = %s, 期望 skipped", res.Entry.Status)
	}
	if res.Entry.Error == "" {
		t.Fatalf("跳过必须说明原因")
	}
}

// 陈旧的锁必须能被接管（进程被 kill -9 后锁文件会留下）。
func TestStaleLockIsReclaimed(t *testing.T) {
	m := newTestManager(t, Options{ExecTimeout: 50 * time.Millisecond})
	task, _ := seedTask(t, m, nil)

	locked, release, err := m.TryLock(task.ID, TriggerManual)
	if err != nil || !locked {
		t.Fatalf("取锁失败: %v", err)
	}
	// 不调用 release：模拟进程被强杀。
	// 把锁文件的 mtime 改到很久以前（陈旧判据是 2×execTimeout）。
	lockPath := filepath.Join(m.lockDir, task.ID+".lock")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatalf("调整锁文件时间失败: %v", err)
	}

	locked2, release2, err := m.TryLock(task.ID, TriggerManual)
	if err != nil {
		t.Fatalf("接管陈旧锁时报错: %v", err)
	}
	if !locked2 {
		t.Fatalf("陈旧的锁没有被接管（面板重启后备份会永远跑不起来）")
	}
	release2()
	_ = release
}

// 锁文件里必须记下 PID 与触发方式，供人排查。
func TestLockFileContents(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)

	locked, release, err := m.TryLock(task.ID, TriggerCron)
	if err != nil || !locked {
		t.Fatalf("取锁失败: %v", err)
	}
	defer release()

	body, err := os.ReadFile(filepath.Join(m.lockDir, task.ID+".lock"))
	if err != nil {
		t.Fatalf("读锁文件失败: %v", err)
	}
	var info lockInfo
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("锁文件不是合法 JSON: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Fatalf("锁文件 PID = %d, 期望 %d", info.PID, os.Getpid())
	}
	if info.Trigger != TriggerCron {
		t.Fatalf("锁文件 Trigger = %q, 期望 %q", info.Trigger, TriggerCron)
	}
	if info.StartedAt == "" {
		t.Fatalf("锁文件缺少开始时间")
	}
}

// 执行时源白名单必须真的生效。
func TestExecuteRejectsSourceOutsideWhitelist(t *testing.T) {
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"x.txt": "1"})

	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)
	// 把任务的源改到白名单之外（模拟有人手工改了 tasks.json）。
	// 必须**落盘**：RunNow 会从配置里重新读任务，
	// 只改内存里的副本等于什么都没测。
	if err := m.store.Mutate(func(d *storeData) error {
		for _, t := range d.Tasks {
			if t.ID == task.ID {
				t.SourcePath = outside
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	res, err := m.RunNow(context.Background(), task.ID, "admin")
	if err != nil {
		t.Fatalf("执行本身应成功返回: %v", err)
	}
	if res.Entry.Status != StatusFailed {
		t.Fatalf("白名单外的源竟然备份成功了")
	}
	if !errors.Is(ErrSourceUnavailable, ErrSourceUnavailable) {
		// 只是确保哨兵错误本身可用（下面的字符串断言才是真检查）。
		t.Fatalf("哨兵错误不可用")
	}
	if !strings.Contains(res.Entry.Error, "不可用") && !strings.Contains(res.Entry.Error, "源") {
		t.Fatalf("失败原因应说明源路径问题: %q", res.Entry.Error)
	}
}

// ---------------------------------------------------------------------------
// 历史
// ---------------------------------------------------------------------------

// 历史条数超上限后必须截断，且保留**最新**的。
func TestHistoryPruning(t *testing.T) {
	m := newTestManager(t, Options{MaxHistoryEntries: 3})
	task, _ := seedTask(t, m, nil)

	base := time.Now()
	for i := 0; i < 7; i++ {
		e := &HistoryEntry{
			ID:        NewIDOrPanic(),
			TaskID:    task.ID,
			TaskName:  task.Name,
			Status:    StatusOK,
			StartedAt: base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Trigger:   TriggerManual,
		}
		if err := m.AppendHistory(e); err != nil {
			t.Fatalf("追加历史失败: %v", err)
		}
	}
	if err := m.pruneHistory(task.ID); err != nil {
		t.Fatalf("截断失败: %v", err)
	}

	entries, err := m.ReadHistory(task.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("截断后剩 %d 条，期望 3", len(entries))
	}
	// 最新的必须在（倒序返回的第一条）。
	if !strings.HasPrefix(entries[0].StartedAt, base.Add(6*time.Minute).Format("2006-01-02T15:04")) {
		t.Fatalf("截断把最新的记录删掉了: %s", entries[0].StartedAt)
	}
}

// 历史文件权限 0600（里面可能含源路径这类信息）。
func TestHistoryFilePermissions(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)
	if err := m.AppendHistory(&HistoryEntry{
		ID: NewIDOrPanic(), TaskID: task.ID, Status: StatusOK,
		StartedAt: time.Now().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(m.historyFileName(task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("历史文件权限 = %04o, 期望 0600", info.Mode().Perm())
	}
}

// 损坏的历史行必须被跳过，而不是让整个历史读不出来。
func TestHistorySkipsCorruptLines(t *testing.T) {
	m := newTestManager(t, Options{})
	task, _ := seedTask(t, m, nil)
	p := m.historyFileName(task.ID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	good := `{"id":"111111111111","task_id":"` + task.ID + `","status":"ok","started_at":"2026-03-01T03:00:00+08:00"}`
	content := good + "\n{ this is garbage\n" + good + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := m.ReadHistory(task.ID, 10)
	if err != nil {
		t.Fatalf("损坏行让整个历史读取都失败了: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("读到 %d 条，期望 2（跳过损坏行）", len(entries))
	}
}

// ---------------------------------------------------------------------------
// cron 挂接
// ---------------------------------------------------------------------------

// 新建任务时必须往 crontab（隔离文件）里挂一条，且那条行里
// **不能出现任何用户输入的文字**。
func TestCronLinkCreatesJob(t *testing.T) {
	cronFile := filepath.Join(t.TempDir(), "crontab")
	cronMgr := newIsolatedCronManager(t, cronFile)

	m := newTestManager(t, Options{Cron: cronMgr})
	task, _ := seedTask(t, m, nil)

	after, _ := m.FindTaskByID(task.ID)
	if after.CronJobID == "" {
		t.Fatalf("任务没有挂到 crontab 上（CronJobID 为空）")
	}

	// ########## 分两层看：crontab 行 与 包装脚本 ##########
	//
	// 5.2 的架构是：crontab 行只写 `0 3 * * * /bin/sh '<jobsDir>/<id>.sh'`，
	// 真正的命令在包装脚本里（它负责把输出与退出码落进任务日志）。
	// 备份只是往那条命令里放 `__backup_run`，因此断言要分别看这两层。

	body := readCronFile(t, cronFile)
	// crontab 里出现的是**计划任务自己的 id**（5.2 生成的），
	// 不是备份任务 id——两者是不同的标识，别把它们混在一起断言。
	if !strings.Contains(body, after.CronJobID) {
		t.Fatalf("crontab 里没有对应的计划任务 %s:\n%s", after.CronJobID, body)
	}
	if after.CronJobID == task.ID {
		t.Fatalf("计划任务 id 不该等于备份任务 id（两者是不同层的东西）")
	}
	// ⚠️ 任务名只允许出现在**注释行**里（给人看的），
	// 绝不能出现在**可执行的那一行**——它可能含空格、引号、中文，
	// 拼进命令里会带来解析与注入问题。
	// 5.2 的 jobLine 只把 spec 与脚本路径写进命令行，这里锁死这一点。
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // 注释行允许含任务名（它是给人看的标题）
		}
		if strings.Contains(trimmed, task.Name) {
			t.Fatalf("crontab 的**命令**行里出现了任务名（用户输入不该进命令）:\n%s", trimmed)
		}
		// 命令只该指向包装脚本，不该直接塞备份命令。
		if strings.Contains(trimmed, backupRunSubcommand) {
			t.Fatalf("crontab 命令里直接出现了备份命令（应由包装脚本承载）:\n%s", trimmed)
		}
	}

	// 包装脚本里必须是我们那条自调用命令。
	script := readCronJobScript(t, cronMgr, after.CronJobID)
	if !strings.Contains(script, backupRunSubcommand) {
		t.Fatalf("包装脚本里没有自调用子命令:\n%s", script)
	}
	if !strings.Contains(script, task.ID) {
		t.Fatalf("包装脚本里没有任务 id:\n%s", script)
	}
	// 必须把配置文件路径传下去：定时进程靠它找到任务定义。
	if !strings.Contains(script, m.StorePath()) {
		t.Fatalf("包装脚本里没有 -backup-store 配置路径（子进程会找不到任务）:\n%s", script)
	}
	// 任务名同样不该出现在脚本的命令行里。
	if strings.Contains(script, "-c") && strings.Contains(script, task.Name) {
		t.Fatalf("包装脚本里出现了任务名\n%s", script)
	}
}

// 删除任务时必须把 crontab 上那条一并删掉。
//
// 漏删的后果：crontab 上留下一条指向不存在任务的行，
// 它每天跑一次、每天失败一次，而面板上再也找不到它。
func TestCronLinkRemovesJobOnDelete(t *testing.T) {
	cronFile := filepath.Join(t.TempDir(), "crontab")
	cronMgr := newIsolatedCronManager(t, cronFile)
	m := newTestManager(t, Options{Cron: cronMgr})
	task, _ := seedTask(t, m, nil)

	before, _ := m.FindTaskByID(task.ID)
	if before == nil || before.CronJobID == "" {
		t.Fatalf("前置条件不成立：任务没挂上去")
	}
	jobID := before.CronJobID
	if !strings.Contains(readCronFile(t, cronFile), jobID) {
		t.Fatalf("前置条件不成立：crontab 里没有那条计划任务")
	}
	if _, err := m.DeleteTask(context.Background(), task.ID, true, nil); err != nil {
		t.Fatalf("删除任务失败: %v", err)
	}
	body := readCronFile(t, cronFile)
	if strings.Contains(body, jobID) {
		t.Fatalf("删除任务后 crontab 里还留着它的行:\n%s", body)
	}
	// 包装脚本也必须被清掉，否则 jobsDir 会越积越多。
	if _, err := os.Stat(filepath.Join(filepath.Dir(cronFile), "jobs", jobID+".sh")); err == nil {
		t.Fatalf("删除任务后包装脚本还在：jobs/%s.sh", jobID)
	}
}

// 表达式改掉之后，crontab 上的时间必须跟着变。
func TestCronLinkUpdatesExpression(t *testing.T) {
	cronFile := filepath.Join(t.TempDir(), "crontab")
	cronMgr := newIsolatedCronManager(t, cronFile)
	m := newTestManager(t, Options{Cron: cronMgr})
	task, _ := seedTask(t, m, nil)

	if _, err := m.UpdateTask(context.Background(), task.ID, TaskInput{
		Name: task.Name, Type: TypeFull, SourceType: SourceDir, SourcePath: task.SourcePath,
		StorageID: task.StorageID, Expr: "30 4 * * 1", KeepPolicy: KeepCount, KeepCount: 3,
	}); err != nil {
		t.Fatalf("改表达式失败: %v", err)
	}
	body := readCronFile(t, cronFile)
	if !strings.Contains(body, "30 4 * * 1") {
		t.Fatalf("crontab 里的时间没跟着改:\n%s", body)
	}
	if strings.Contains(body, "0 3 * * *") {
		t.Fatalf("crontab 里还留着旧的时间:\n%s", body)
	}
}

// 停用任务时，crontab 上的行必须被摘掉（否则"停用"是假的）。
func TestCronLinkRemovesJobWhenDisabled(t *testing.T) {
	cronFile := filepath.Join(t.TempDir(), "crontab")
	cronMgr := newIsolatedCronManager(t, cronFile)
	m := newTestManager(t, Options{Cron: cronMgr})
	task, _ := seedTask(t, m, nil)

	// 先记下挂上去的那条计划任务 id（停用之后 CronJobID 会被清空，
	// 那时就无从断言了）。
	before, _ := m.FindTaskByID(task.ID)
	if before == nil || before.CronJobID == "" {
		t.Fatalf("前置条件不成立：任务没挂上去")
	}
	jobID := before.CronJobID

	if _, err := m.UpdateTask(context.Background(), task.ID, TaskInput{
		Name: task.Name, Type: TypeFull, SourceType: SourceDir, SourcePath: task.SourcePath,
		StorageID: task.StorageID, Expr: "0 3 * * *", KeepPolicy: KeepCount, KeepCount: 3,
		Enabled: false, DisableExplicit: true,
	}); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	if body := readCronFile(t, cronFile); strings.Contains(body, jobID) {
		t.Fatalf("停用后 crontab 里还留着它的行（停用是假的）:\n%s", body)
	}
	// 任务本身必须还在（停用 ≠ 删除），只是不再定时执行。
	after, _ := m.FindTaskByID(task.ID)
	if after == nil {
		t.Fatalf("停用把任务删掉了（停用只该摘掉时间计划）")
	}
	if after.Enabled {
		t.Fatalf("任务仍标记为启用")
	}
	// 停用后仍然可以手动执行。
	if _, err := m.RunNow(context.Background(), task.ID, "admin"); err != nil {
		t.Fatalf("停用后手动执行失败: %v", err)
	}
}

// cron 不可用时，任务**仍然要保存成功**，只是带一个原因。
//
// 若这里返回错误，用户在没有 cron 的容器里就完全用不了备份功能。
func TestCronUnavailableStillSavesTask(t *testing.T) {
	m := newTestManager(t, Options{Cron: nil})
	view, err := func() (*TaskView, error) {
		root := m.srcResolver.Roots()[0].Path
		src := filepath.Join(root, "s")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		st := createLocalStorage(t, m)
		return m.CreateTask(context.Background(), TaskInput{
			Name: "无 cron 的任务", Type: TypeFull, SourceType: SourceDir,
			SourcePath: src, StorageID: st.ID, Expr: "0 3 * * *",
		})
	}()
	if err != nil {
		t.Fatalf("cron 不可用时任务竟然创建失败（用户会完全用不了备份）: %v", err)
	}
	if view.CronManaged {
		t.Fatalf("没有 cron 却报告已挂接")
	}
	if view.CronReason == "" {
		t.Fatalf("必须说明为什么没挂上时间计划")
	}
	// 但仍然要能手动执行。
	if _, err := m.RunNow(context.Background(), view.ID, "admin"); err != nil {
		t.Fatalf("无 cron 时手动执行失败: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 拒绝危险路径（打包与恢复的白名单）
// ---------------------------------------------------------------------------

func TestCheckRestoreTargetRejectsOutsideWhitelist(t *testing.T) {
	m := newTestManager(t, Options{})
	outside := t.TempDir() // 不在 m 的白名单里

	if _, err := m.CheckRestoreTarget(outside); err == nil {
		t.Fatalf("白名单外的恢复目标竟然通过了")
	}
}

func TestCheckRestoreTargetRejectsRelative(t *testing.T) {
	m := newTestManager(t, Options{})
	if _, err := m.CheckRestoreTarget("relative/path"); err == nil {
		t.Fatalf("相对路径的恢复目标竟然通过了")
	}
}

func TestCheckRestoreTargetCreatesDir(t *testing.T) {
	m := newTestManager(t, Options{})
	root := m.rstResolver.Roots()[0].Path
	target := filepath.Join(root, "deep", "nested", "target")

	real, err := m.CheckRestoreTarget(target)
	if err != nil {
		t.Fatalf("合法的恢复目标被拒绝了: %v", err)
	}
	if info, err := os.Stat(real); err != nil || !info.IsDir() {
		t.Fatalf("恢复目标目录没有被创建: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 证书/工具
// ---------------------------------------------------------------------------

// strPtr 返回字符串指针（StorageInput 的密钥字段是 *string，
// nil 表示"不改动"）。
func strPtr(v string) *string { return &v }

// NewIDOrPanic 是测试用的 id 生成（失败就直接 panic，测试里不该失败）。
func NewIDOrPanic() string {
	id, err := NewID()
	if err != nil {
		panic(err)
	}
	return id
}

// newIsolatedCronManager 造一个**只写隔离文件**的 cron 管理器。
//
// ⚠️ 绝不使用真实 crontab：那会改宿主机上别人的定时任务
// （与 5.2 的 -cron-file 同一条纪律）。
func newIsolatedCronManager(t *testing.T, file string) *cron.Manager {
	t.Helper()
	isolated := filepath.Dir(file)
	mgr, err := cron.NewManager(cron.Options{
		// 数据目录同样必须隔离：cron 的默认数据目录是
		// /var/lib/lipanel/cron，非 root 跑测试时直接 mkdir 失败。
		DataDir:  isolated,
		FilePath: file,
		Logger:   discardLogger(),
	})
	if err != nil {
		t.Fatalf("构造 cron 管理器失败: %v", err)
	}
	return mgr
}

// readCronJobScript 读出 5.2 为某个计划任务生成的包装脚本正文。
//
// 备份命令实际就在这里（crontab 行只负责 `/bin/sh <脚本>`）。
func readCronJobScript(t *testing.T, mgr *cron.Manager, jobID string) string {
	t.Helper()
	if jobID == "" {
		t.Fatalf("任务没有对应的计划任务 id")
	}
	res, err := mgr.List(context.Background())
	if err != nil || res == nil {
		t.Fatalf("查询计划任务失败: %v", err)
	}
	path := ""
	for _, job := range res.Jobs {
		if job.ID == jobID {
			path = job.ScriptPath
			break
		}
	}
	if path == "" {
		t.Fatalf("计划任务 %s 没有脚本路径（任务列表里找不到它？）", jobID)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读包装脚本 %s 失败: %v", path, err)
	}
	return string(body)
}

func readCronFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		t.Fatalf("读 crontab 隔离文件失败: %v", err)
	}
	return string(body)
}
