package cron

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ============================================================================
// crontab 命令模式测试（阶段五 5.2）
// ============================================================================
//
// ########## 为什么用工作区里的假 crontab 脚本而不是真命令 ##########
//
// 宿主机 /var/spool/cron 是**真实系统的资产**：本项目的安全红线明确要求
// 「写 crontab 测试必须用隔离目录或 mock，不要污染宿主机真实 crontab」。
// 因此这里在工作区生成一个 shell 脚本冒充 crontab 可执行文件
// （行为对齐真实实现：-l 读文件、写模式校验文件、无 crontab 时报
// "no crontab for"），把它传给 commandStore.bin。
//
// 这样既守住了红线，又真的跑到了 fork/exec、stderr 判读、
// 临时文件传递这条**真实代码路径**上——只用接口 mock 是验不到这些的。

// writeFakeCrontab 生成一个记录调用的假 crontab 可执行文件。
//
// 语义与 util-linux/Vixie crontab 对齐的部分：
//   - `crontab -l`：无文件时 stderr 输出 "no crontab for <user>" 且退出码 1；
//   - `crontab -u <u> -l`：同上但用指定用户名；
//   - `crontab <file>`：文件不存在时 stderr 报错并退出 1；
//     文件含语法错误时同样退出 1（这里用「含 BAD 字样」模拟）。
func writeFakeCrontab(t *testing.T, stateDir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("假 crontab 是 shell 脚本，Windows 上跳过")
	}
	path := filepath.Join(stateDir, "fake-crontab.sh")
	script := `#!/bin/sh
# 假 crontab：状态存在 $STATE 里，绝不碰系统目录。
STATE="__STATE__"
LOG="$STATE/calls.log"
echo "call: $*" >> "$LOG"

user="(current)"
args=""
while [ $# -gt 0 ]; do
  case "$1" in
    -u) user="$2"; shift 2 ;;
    -l) args="list"; shift ;;
    *) args="$1"; shift ;;
  esac
done

if [ "$args" = "list" ]; then
  if [ ! -f "$STATE/crontab-$user" ]; then
    echo "no crontab for $user" >&2
    exit 1
  fi
  cat "$STATE/crontab-$user"
  exit 0
fi

if [ ! -f "$args" ]; then
  echo "crontab: bad file: $args -- (No such file or directory)" >&2
  exit 1
fi
if grep -q "BAD" "$args"; then
  echo "crontab: installing new crontab: bad minute field" >&2
  exit 1
fi
cat "$args" > "$STATE/crontab-$user"
echo "crontab: installing new crontab" >&2
exit 0
`
	script = strings.ReplaceAll(script, "__STATE__", stateDir)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func newFakeCommandStore(t *testing.T, user string) (*commandStore, string) {
	t.Helper()
	state := t.TempDir()
	bin := writeFakeCrontab(t, state)
	st := newCommandStore(CommandStoreOptions{Bin: bin, User: user})
	st.lookPath = func(string) (string, error) { return bin, nil }
	return st, state
}

func TestCommandStoreReadNoCrontabIsEmpty(t *testing.T) {
	st, _ := newFakeCommandStore(t, "")
	got, err := st.Read(context.Background())
	if err != nil {
		t.Fatalf("「还没有 crontab」是正常状态，不应报错: %v", err)
	}
	if got != "" {
		t.Errorf("应为空内容，实际 %q", got)
	}
}

func TestCommandStoreRoundTrip(t *testing.T) {
	st, _ := newFakeCommandStore(t, "")
	want := "# 注释\nMAILTO=\"\"\n*/5 * * * * /bin/sh '/x/y.sh'\n"
	if err := st.Write(context.Background(), want); err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	got, err := st.Read(context.Background())
	if err != nil {
		t.Fatalf("Read 失败: %v", err)
	}
	if got != want {
		t.Errorf("往返不一致:\n got=%q\nwant=%q", got, want)
	}
}

func TestCommandStoreWriteErrorPropagates(t *testing.T) {
	st, _ := newFakeCommandStore(t, "")
	err := st.Write(context.Background(), "BAD line\n")
	if err == nil {
		t.Fatal("crontab 拒绝内容时必须报错")
	}
	// 报错要带 crontab 给出的真实原因，而不是只剩 exit status 1。
	if !strings.Contains(err.Error(), "bad minute field") {
		t.Errorf("应保留 stderr 原文，实际: %v", err)
	}
}

func TestCommandStoreUserFlag(t *testing.T) {
	st, state := newFakeCommandStore(t, "www-data")
	if err := st.Write(context.Background(), "@daily echo x\n"); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(state, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "-u www-data") {
		t.Errorf("指定用户时必须传 -u，实际调用:\n%s", calls)
	}
	if !strings.Contains(st.Target(), "www-data") {
		t.Errorf("Target 应写明在改谁的任务: %q", st.Target())
	}
}

func TestCommandStoreDefaultTargetsOwnUser(t *testing.T) {
	st, state := newFakeCommandStore(t, "")
	if err := st.Write(context.Background(), "@daily echo x\n"); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(filepath.Join(state, "calls.log"))
	// 默认**不加 -u**：面板改的是自己运行身份的任务，
	// 加 -u root 会让误操作直接命中系统级定时任务。
	if strings.Contains(string(calls), "-u ") {
		t.Errorf("默认不应带 -u:\n%s", calls)
	}
	if !strings.Contains(st.Target(), "面板运行身份") {
		t.Errorf("Target 应说明是面板自己的 crontab: %q", st.Target())
	}
}

func TestCommandStoreMissingBinary(t *testing.T) {
	st := newCommandStore(CommandStoreOptions{Bin: "definitely-not-here-xyz"})
	st.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if _, err := st.Read(context.Background()); err == nil {
		t.Fatal("缺 crontab 命令时应报错并给出指引")
	} else if !strings.Contains(err.Error(), "-cron-file") {
		t.Errorf("报错应提示隔离模式可用，实际: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 隔离文件模式
// ---------------------------------------------------------------------------

func TestFileStoreAtomicAndMissingIsOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "crontab")
	st := newFileStore(path)
	// 文件不存在 = 空 crontab，不是错误。
	if got, err := st.Read(context.Background()); err != nil || got != "" {
		t.Errorf("首次读取应为空且不报错: got=%q err=%v", got, err)
	}
	if err := st.Write(context.Background(), "0 1 * * * echo x\n"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "0 1 * * * echo x\n" {
		t.Errorf("内容不符: %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("crontab 隔离文件应 0600，实际 %v", fi.Mode())
	}
	// 目录里不应残留临时文件。
	for _, n := range listDir(t, filepath.Dir(path)) {
		if n != "crontab" {
			t.Errorf("残留临时文件: %s", n)
		}
	}
	// Target 必须让人一眼看出这**不是**系统 crontab。
	if !strings.Contains(st.Target(), "不是系统 crontab") {
		t.Errorf("Target=%q", st.Target())
	}
}

// TestFileStoreFailureLeavesContentIntact 锁死写失败不损坏原文件。
func TestFileStoreFailureLeavesContentIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	st := newFileStore(path)
	if err := st.Write(context.Background(), "original\n"); err != nil {
		t.Fatal(err)
	}
	st.failNextWrite = true
	if err := st.Write(context.Background(), "new\n"); err == nil {
		t.Fatal("应报错")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "original\n" {
		t.Errorf("写失败后原文件必须完好，实际 %q", b)
	}
}

// TestManagerWithFileStoreEndToEnd 用真实文件 store 走一遍 CRUD，
// 覆盖「Manager + 真实文件读写」这条组合路径（也是 curl 端到端的前置保障）。
func TestManagerWithFileStoreEndToEnd(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Options{
		FilePath: filepath.Join(dir, "isolated-crontab"),
		DataDir:  filepath.Join(dir, "data"),
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	ctx := context.Background()
	if m.Mode() != ModeFile {
		t.Errorf("mode=%s", m.Mode())
	}

	created, err := m.Create(ctx, JobInput{Expression: "*/10 * * * *", Command: "echo e2e", Comment: "端到端"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Jobs) != 1 || list.Jobs[0].ID != created.Job.ID {
		t.Fatalf("列表应含新建任务: %+v", list.Jobs)
	}
	if list.Jobs[0].Command != "echo e2e" {
		t.Errorf("命令应读自包装脚本: %q", list.Jobs[0].Command)
	}
	if _, err := m.Update(ctx, created.Job.ID, JobInput{
		Expression: "*/20 * * * *", Command: "echo edited", Comment: "改过",
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := m.List(ctx)
	if after.Jobs[0].Expression != "*/20 * * * *" || after.Jobs[0].Command != "echo edited" {
		t.Errorf("编辑未生效: %+v", after.Jobs[0])
	}
	if _, err := m.Delete(ctx, created.Job.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	final, _ := m.List(ctx)
	if len(final.Jobs) != 0 {
		t.Errorf("删除后应为空: %+v", final.Jobs)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "jobs", created.Job.ID+".sh")); !os.IsNotExist(err) {
		t.Error("删除后包装脚本应被清理")
	}
}
