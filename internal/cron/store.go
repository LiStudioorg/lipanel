package cron

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// crontab 存取层（阶段五 5.2）
// ============================================================================
//
// 两种实现，由 -cron-file 决定，接口一致：
//
//	① commandStore（默认）：调 `crontab -l` / `crontab <file>`，
//	   操作**当前运行用户**的 crontab。
//	② fileStore（-cron-file <path>）：读写一个普通文件。
//
// ########## fileStore 为什么是核心设计而不是测试补丁 ##########
//
// 计划的安全红线写着「写 crontab 测试必须用隔离目录或 mock，
// 不要污染宿主机真实 crontab」。要在**真实的 HTTP 链路**上验证
// 「列表 → 新增 → 编辑 → 删除」，就必须有一个能把全部读写重定向到
// 工作区文件的模式——只有单测里的 mock 是不够的：
// 那验不到序列化、原子写、回滚这一整条真实路径。
//
// 同一个动机也解释了 4.6 的假防火墙执行器（LIPANEL_FIREWALL_FAKE）
// 与 4.5 的 LIPANEL_STORE_* 目录重定向。
//
// 安全性：
//   - 命令一律 exec.CommandContext 传 argv，**绝不拼 shell**；
//   - 用户名为空表示「当前用户」（不加 -u），避免误操作他人 crontab；
//   - 写入走「临时文件 + fsync + rename」，crontab 命令也从一个
//     完整落盘的文件读取，不会出现半截输入。

// 存取模式常量（进审计与状态接口）。
const (
	ModeCrontab = "crontab"
	ModeFile    = "file"
)

// DefaultCommandTimeout 是单次 crontab 命令的超时。
// crontab 是瞬时完成的本地操作，超时说明磁盘或 PAM 出问题了，
// 等再久也不会变好，因此取短值。
const DefaultCommandTimeout = 10 * time.Second

// Store 抽象 crontab 的读写。
type Store interface {
	// Mode 返回 ModeCrontab / ModeFile。
	Mode() string
	// Target 是人类可读的读写目标（"root 的 crontab" / 文件路径），
	// 用于状态接口与启动日志——用户必须一眼看清面板在动谁的任务。
	Target() string
	// Read 返回 crontab 全文。无 crontab（首次使用）返回空串而非错误。
	Read(ctx context.Context) (string, error)
	// Write 全量写入。实现必须保证原子性（要么全成要么原样不动）。
	Write(ctx context.Context, content string) error
}

// ---------------------------------------------------------------------------
// ① 命令模式
// ---------------------------------------------------------------------------

// commandStore 通过 crontab 命令读写。
type commandStore struct {
	// bin 默认为 "crontab"，测试可替换成工作区里的假脚本。
	bin     string
	user    string
	timeout time.Duration
	// lookPath 便于测试注入。
	lookPath func(string) (string, error)
}

// CommandStoreOptions 是命令模式参数。
type CommandStoreOptions struct {
	// Bin 是 crontab 可执行文件（空则用 "crontab" 并做 lookPath）。
	Bin string
	// User 为空表示当前运行用户（不加 -u）。
	//
	// ########## 为什么默认是当前用户而不是 root ##########
	//
	// 面板通常以 root 运行。若默认操作 root 的 crontab，
	// 面板上任何一次误操作都直接命中系统的定时任务
	// （系统级 cron 往往承担日志轮转、备份等职责）。
	// 「面板改自己的任务、系统 cron 不受影响」才是安全的默认值；
	// 想管理别的用户必须显式传 -cron-user，且状态接口会写明。
	User    string
	Timeout time.Duration
}

func newCommandStore(opts CommandStoreOptions) *commandStore {
	bin := opts.Bin
	if bin == "" {
		bin = "crontab"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	return &commandStore{bin: bin, user: opts.User, timeout: timeout, lookPath: exec.LookPath}
}

func (s *commandStore) Mode() string { return ModeCrontab }

func (s *commandStore) Target() string {
	if s.user != "" {
		return fmt.Sprintf("用户 %s 的 crontab（crontab -u %s）", s.user, s.user)
	}
	name := currentUserName()
	if name == "" {
		name = "当前用户"
	}
	return fmt.Sprintf("用户 %s 的 crontab（面板运行身份）", name)
}

// args 组装 crontab 的参数：只在显式指定用户时加 -u。
func (s *commandStore) args(extra ...string) []string {
	var out []string
	if s.user != "" {
		out = append(out, "-u", s.user)
	}
	return append(out, extra...)
}

func (s *commandStore) Read(ctx context.Context) (string, error) {
	if _, err := s.lookPath(s.bin); err != nil {
		// 双 %w：既要让接口层用 errors.Is 认出「环境不具备能力」，
		// 又要把 lookPath 的原始原因留给日志（权限问题与真的没装
		// 是两种修法，只留一个就看不出区别）。
		return "", fmt.Errorf("cron: 找不到 crontab 命令（%s）：%w（%v）—— "+
			"请安装 cron，或用 -cron-file 指定隔离的 crontab 文件", s.bin, ErrStoreUnavailable, err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.bin, s.args("-l")...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		// 没有任何 crontab 是**正常状态**（新机器、新用户），
		// 不能当错误抛——否则全新环境下面板列表直接报错。
		// 判据只看 stderr 文案：`crontab -l` 在没有 crontab 时
		// 退出码非 0 且输出 "no crontab for <user>"。
		if isNoCrontabMessage(msg) {
			return "", nil
		}
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("cron: 读取 crontab 超时（%s）", s.timeout)
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("cron: 读取 crontab 失败: %s", msg)
	}
	return stdout.String(), nil
}

// Write 把内容写进**临时文件**再让 crontab 读取它。
//
// 不用 stdin 管道的原因：管道出问题时 crontab 可能已经清空了原条目
// 才读到 EOF（等于写失败反而删光了任务）。给一个完整文件，
// 失败时它连文件都不读，原有 crontab 分毫不动。
func (s *commandStore) Write(ctx context.Context, content string) error {
	if _, err := s.lookPath(s.bin); err != nil {
		return fmt.Errorf("cron: 找不到 crontab 命令（%s）：%w（%v）", s.bin, ErrStoreUnavailable, err)
	}
	tmp, err := os.CreateTemp("", "lipanel-crontab-*.txt")
	if err != nil {
		return fmt.Errorf("cron: 创建临时 crontab 失败: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if err := writeAllAndSync(tmp, content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cron: 写入临时 crontab 失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cron: 关闭临时 crontab 失败: %w", err)
	}
	// crontab 需要能以普通用户身份读这个文件（0600 对同用户足够）。
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("cron: 设置临时 crontab 权限失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.bin, s.args(name)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("cron: 写入 crontab 超时（%s）", s.timeout)
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("cron: 写入 crontab 失败: %s", msg)
	}
	return nil
}

// isNoCrontabMessage 判断 stderr 是否是「该用户还没有 crontab」。
//
// 只匹配语义片段而不是整句，因为该文案随 locale 变化
// （LC_ALL=C 下稳定，但我们无法保证调用环境）。
func isNoCrontabMessage(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "no crontab for") || strings.Contains(m, "no crontab of")
}

func currentUserName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// ---------------------------------------------------------------------------
// ② 隔离文件模式
// ---------------------------------------------------------------------------

// fileStore 读写一个普通文件（隔离环境 / 开发用）。
type fileStore struct {
	path string
	// failNextWrite 供测试注入写失败，验证回滚链路。
	failNextWrite bool
}

func newFileStore(path string) *fileStore { return &fileStore{path: path} }

func (s *fileStore) Mode() string   { return ModeFile }
func (s *fileStore) Target() string { return "隔离文件 " + s.path + "（不是系统 crontab）" }

func (s *fileStore) Read(_ context.Context) (string, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil // 还不存在 = 空 crontab
		}
		return "", fmt.Errorf("cron: 读取 %s 失败: %w", s.path, err)
	}
	return string(b), nil
}

// Write 原子写：同目录临时文件 + fsync + rename。
//
// 必须在**同目录**建临时文件：跨文件系统的 rename 不保证原子性。
func (s *fileStore) Write(_ context.Context, content string) error {
	if s.failNextWrite {
		s.failNextWrite = false
		return errors.New("cron: 注入的写入失败（测试用）")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cron: 创建目录 %s 失败: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".crontab-*.tmp")
	if err != nil {
		return fmt.Errorf("cron: 创建临时文件失败: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if err := writeAllAndSync(tmp, content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cron: 写入临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cron: 关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("cron: 设置权限失败: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("cron: 替换 %s 失败: %w", s.path, err)
	}
	// 目录 fsync：rename 本身也要落盘，否则掉电后可能只剩空文件。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// writeAllAndSync 写完并 fsync（供两种 store 复用）。
func writeAllAndSync(f *os.File, content string) error {
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	return f.Sync()
}

// ErrStoreUnavailable 表示「这台机器现在没法管理 crontab」——
// 典型原因是根本没装 cron（容器、精简镜像里非常常见）。
//
// ########## 为什么必须是哨兵错误而不是普通 error ##########
//
// 接口层要区分两件完全不同的事：
//
//	① 环境不具备这个能力 → **503 + 原因 + 安装指引**，前端渲染说明页；
//	② 面板自己的代码或配置出错 → 500，那才是我们的问题。
//
// 靠匹配「crontab」这类文案来判断既脆弱（locale 与发行版文案各异），
// 又会把 ① 误报成 ②。「没装 cron」不是 bug，报成 500 会让人
// 以为面板坏了，于是去重装面板。
var ErrStoreUnavailable = errors.New("cron: crontab 不可用")

// DefaultDataDir 是包装脚本与执行日志的默认目录。
const DefaultDataDir = "/var/lib/lipanel/cron"

// DefaultBackupKeep 是保留的历史备份份数。
const DefaultBackupKeep = 10
