package cron

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 计划任务管理器（阶段五 5.2）
// ============================================================================
//
// ########## 写操作的固定时序（顺序错了就会丢任务） ##########
//
//	① 读当前 crontab（拿到「改前的真相」）
//	② 解析 + 行级改写（纯内存，此时还没碰任何东西）
//	③ 落备份（改前内容；备份失败 = 拒绝写入）
//	④ 先写包装脚本，再写 crontab
//	⑤ crontab 写失败 → 回滚：把 ① 的内容写回去，并把脚本还原/清掉
//
// ③ 在 ④ 之前：备份是「能不能改」的前置条件。
// 备份写不下去（磁盘满、目录只读）却照样改 crontab，等于让用户失去
// 唯一的恢复手段——这是不可接受的交易。
//
// ④ 脚本先于 crontab：反过来会出现「crontab 已指向脚本、脚本还不存在」
// 的窗口，cron 一命中就往日志里写一条 No such file or directory。
//
// ⑤ 回滚尽力而为但**如实记录结果**：回滚也失败时，审计里
// rollback_ok=false + rollback_error 必须留痕，并把恢复用的备份路径
// 一并返回给用户——那行备份路径是用户此时的救命稻草。

// Options 是构造 Manager 的配置。
type Options struct {
	// Store 是 crontab 读写实现；为 nil 时按 Command/File 选项自建。
	Store Store
	// FilePath 非空时使用隔离文件模式（等价于 -cron-file）。
	FilePath string
	// CrontabBin 覆盖 crontab 可执行文件（测试用）。
	CrontabBin string
	// CrontabUser 非空时用 crontab -u <user> 管理指定用户。
	CrontabUser string
	// CommandTimeout 是单次 crontab 命令超时；<=0 用默认值。
	CommandTimeout time.Duration
	// DataDir 是包装脚本与日志的根目录（默认 DefaultDataDir）。
	DataDir string
	// LogMaxBytes 是单任务日志上限；<=0 用 DefaultLogMaxBytes。
	LogMaxBytes int64
	// BackupKeep 是保留备份份数；<=0 用 DefaultBackupKeep。
	BackupKeep int
	// Logger / Auditor 可为 nil（分用 slog.Default 与不落盘审计器）。
	Logger  *slog.Logger
	Auditor *Auditor
	// Now 用于注入时钟（测试可确定地断言下次执行时间）。
	Now func() time.Time
	// Location 为 nil 时用 time.Local。
	Location *time.Location
}

// Manager 提供计划任务的增删改查。
type Manager struct {
	store       Store
	dataDir     string
	jobsDir     string
	logsDir     string
	backupsDir  string
	logMaxBytes int64
	backupKeep  int
	commandTO   time.Duration
	logger      *slog.Logger
	auditor     *Auditor
	now         func() time.Time
	location    *time.Location

	// mu 串行化全部写操作，并保护「读-改-写」这条复合路径。
	//
	// 面板自身只有这一个写入者，但 crontab 是个**外部可变**的资源
	// （`crontab -e`、系统脚本都可能同时改它），
	// 因此每次写都以「刚读到的内容」为准做行级改写，
	// 再用 ExpectedJobIDs 断言没有别人在中间动过。
	mu sync.Mutex
}

// NewManager 构造管理器。
func NewManager(opts Options) (*Manager, error) {
	var err error
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	store := opts.Store
	if store == nil {
		if opts.FilePath != "" {
			store = newFileStore(opts.FilePath)
		} else {
			store = newCommandStore(CommandStoreOptions{
				Bin: opts.CrontabBin, User: opts.CrontabUser, Timeout: opts.CommandTimeout,
			})
		}
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	logMax := opts.LogMaxBytes
	if logMax <= 0 {
		logMax = DefaultLogMaxBytes
	}
	keep := opts.BackupKeep
	if keep <= 0 {
		keep = DefaultBackupKeep
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	loc := opts.Location
	if loc == nil {
		loc = time.Local
	}

	// Auditor 为 nil 时构造一个仅内存的审计器（与其它核心模块一致）：
	// 判定与留痕的链路不因「没配 -audit-log」而短路。
	auditor := opts.Auditor
	if auditor == nil {
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}

	m := &Manager{
		store:       store,
		dataDir:     dataDir,
		jobsDir:     filepath.Join(dataDir, "jobs"),
		logsDir:     filepath.Join(dataDir, "logs"),
		backupsDir:  filepath.Join(dataDir, "backups"),
		logMaxBytes: logMax,
		backupKeep:  keep,
		commandTO:   opts.CommandTimeout,
		logger:      logger,
		auditor:     auditor,
		now:         now,
		location:    loc,
	}
	// 目录提前建好：等到第一次写任务时才因为权限失败，
	// 用户看到的就是一句与「保存失败」相关的含糊报错。
	for _, d := range []string{m.dataDir, m.jobsDir, m.logsDir, m.backupsDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("cron: 创建数据目录 %s 失败: %w", d, err)
		}
	}
	return m, nil
}

// Mode 返回存取模式。
func (m *Manager) Mode() string { return m.store.Mode() }

// Target 返回读写目标描述。
func (m *Manager) Target() string { return m.store.Target() }

// DataDir 返回数据目录（状态接口与前端提示用）。
func (m *Manager) DataDir() string { return m.dataDir }

// Auditor 返回审计器，供 server 层查询记录与统计。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// LogMaxBytes 返回单任务日志体积上限（状态接口展示用）。
func (m *Manager) LogMaxBytes() int64 { return m.logMaxBytes }

// CommandTimeout 返回单次 crontab 命令超时（状态接口展示用）。
func (m *Manager) CommandTimeout() time.Duration {
	if m.commandTO <= 0 {
		return DefaultCommandTimeout
	}
	return m.commandTO
}

// LogResult 是日志查询结果。
type LogResult struct {
	JobID      string     `json:"job_id"`
	Expression string     `json:"expression,omitempty"`
	Command    string     `json:"command,omitempty"`
	LogPath    string     `json:"log_path,omitempty"`
	Found      bool       `json:"found"`
	Reason     string     `json:"reason,omitempty"`
	Truncated  bool       `json:"truncated"`
	Tail       string     `json:"tail"`
	Entries    []LogEntry `json:"entries"`
}

// Logs 返回某个任务的执行日志。
//
// ########## 日志路径只能由 id + 当前 crontab 内容推出 ##########
//
// 接口**绝不接受调用方传入的日志路径**：那等于开一个任意文件读取
// （`?path=/etc/shadow`），而本接口是认证后接口，一旦开洞就是
// 「登录即可读 root 的任意文件」。路径由 Manager 从 id 反查，
// id 又必须先过 managedIDRe 形态校验，两头都封死。
//
// 非面板任务没有包装脚本、也就没有面板日志，如实返回 found=false + 原因，
// 而不是返回一个空日志让人以为「跑了但没输出」。
func (m *Manager) Logs(ctx context.Context, id string, lines int) (*LogResult, error) {
	if err := ValidateJobID(id); err != nil {
		return nil, err
	}
	res := &LogResult{JobID: id, Entries: []LogEntry{}}
	if !managedIDRe.MatchString(id) {
		res.Reason = "该任务不是面板管理的任务，没有包装脚本，因此没有面板日志。" +
			"需要日志请先在面板里编辑一次（面板会接管该任务并启用日志包装）"
		return res, nil
	}

	content, err := m.store.Read(ctx)
	if err != nil {
		return nil, err
	}
	job := m.parse(content).findJob(id)
	if job == nil {
		return nil, fmt.Errorf("%w: %s", ErrJobNotFound, id)
	}
	res.Expression = job.Expression
	res.Command = job.Command
	if job.LogPath == "" {
		res.Reason = "无法确定该任务的日志路径"
		return res, nil
	}
	text, found, truncated, err := TailLog(job.LogPath, lines)
	if err != nil {
		return nil, err
	}
	res.Found = found
	res.LogPath = job.LogPath
	res.Truncated = truncated
	res.Tail = text
	if !found {
		res.Reason = "还没有执行记录（任务尚未被 cron 触发，或日志已被清理）"
		return res, nil
	}
	if entries := ParseLogEntries(text); entries != nil {
		res.Entries = entries
	}
	return res, nil
}

// Status 是模块运行状态（供 UI 说明「面板正在改谁的任务」）。
type Status struct {
	Mode    string `json:"mode"`
	Target  string `json:"target"`
	DataDir string `json:"data_dir"`
	User    string `json:"user,omitempty"`
	// Available 表示 crontab 当前是否可读写。
	Available bool       `json:"available"`
	Reason    string     `json:"reason,omitempty"`
	Audit     AuditStats `json:"audit"`
	Backups   []string   `json:"backups"`
}

// Status 探测 crontab 是否可读（读失败不报错，而是如实标 available=false）。
//
// 「机器上没装 cron」不是错误状态，而是一个需要向用户解释的运行状态：
// 接口返回 200 + available=false + 原因，前端才渲染得出带说明的页面，
// 而不是一个与真实原因无关的红色错误框（与 4.1~4.6 的降级策略一致）。
func (m *Manager) Status(ctx context.Context) Status {
	st := Status{
		Mode:    m.store.Mode(),
		Target:  m.store.Target(),
		DataDir: m.dataDir,
		User:    currentUserName(),
		Audit:   m.auditor.Stats(),
		Backups: m.listBackups(),
	}
	if st.Backups == nil {
		st.Backups = []string{}
	}
	if _, err := m.store.Read(ctx); err != nil {
		st.Available = false
		st.Reason = err.Error()
		return st
	}
	st.Available = true
	return st
}

// Jobs 是一次列表的结果。
type ListResult struct {
	Mode   string `json:"mode"`
	Target string `json:"target"`
	// User 是面板身份的用户名（crontab 模式）。
	User string `json:"user,omitempty"`
	// Jobs 是任务列表（含非面板添加的行）。
	Jobs []*Job `json:"jobs"`
	// Settings 是 crontab 里的全局设置行（只读）。
	Settings []Setting `json:"settings"`
	// Backups 是最近的备份文件名（供 UI 说明「改坏了去哪找」）。
	Backups []string `json:"backups"`
	// Status 是模块状态（列表已隐含「读成功」，但模式与目标要一起给，
	// 前端才不用为了显示一行说明再发一次请求）。
	Status Status `json:"status"`
}

// List 读取并解析当前 crontab。
func (m *Manager) List(ctx context.Context) (*ListResult, error) {
	content, err := m.store.Read(ctx)
	if err != nil {
		return nil, err
	}
	t := m.parse(content)
	// 列表已经成功读过了，状态直接复用这次读取的结论——
	// 再调一次 Status() 会对 crontab 多读一遍（多一次 fork/exec）。
	res := &ListResult{
		Mode:     m.store.Mode(),
		Target:   m.store.Target(),
		User:     currentUserName(),
		Jobs:     t.jobs,
		Settings: t.settings,
		Backups:  m.listBackups(),
		Status: Status{
			Mode:      m.store.Mode(),
			Target:    m.store.Target(),
			DataDir:   m.dataDir,
			User:      currentUserName(),
			Available: true,
			Audit:     m.auditor.Stats(),
			Backups:   m.listBackups(),
		},
	}
	if res.Jobs == nil {
		res.Jobs = []*Job{}
	}
	if res.Settings == nil {
		res.Settings = []Setting{}
	}
	if res.Status.Backups == nil {
		res.Status.Backups = []string{}
	}
	return res, nil
}

// MaxPreviewRuns 是单次预览返回的执行时间条数上限。
const MaxPreviewRuns = 10

// PreviewExpr 校验一条表达式并预测接下来若干次的执行时间。
//
// ########## 为什么这个方法挂在 Manager 上而不是让接口层直接用包级函数 ##########
//
// 「下次执行时间」依赖两个只有 Manager 才知道的东西：注入的时钟与时区。
// 接口层若自己调 ValidateExpr + NextRun，就会用 time.Now 与 time.Local，
// 于是**测试里**（Manager 注入了固定时钟）列表显示一个时间、
// 弹窗预览显示另一个时间；生产里若将来支持 -timezone，两者也会漂移。
// 同一个界面上出现两个互相矛盾的「下次执行时间」，比不显示更糟。
//
// 它**不读 crontab**：编辑弹窗里用户还没保存，此时读一次 crontab
// 纯属浪费（还要 fork 一个 crontab 进程）。
//
// 从 from（不含）开始逐个求解，最多 count 条：
// 表达式永不成立（`0 0 30 feb`）时 NextRun 会报错，
// 此时把已算出的部分连同错误一起返回，让用户看到「只匹配到这些」。
func (m *Manager) PreviewExpr(expr string, count int) (*PreviewResult, error) {
	if count <= 0 {
		count = 5
	}
	if count > MaxPreviewRuns {
		count = MaxPreviewRuns
	}
	spec, err := ValidateExpr(expr)
	if err != nil {
		return nil, err
	}
	res := &PreviewResult{
		Expression: spec.Normalize(),
		Original:   strings.TrimSpace(expr),
		Human:      spec.Humanize(),
		Reboot:     spec.IsReboot,
		Runs:       []string{},
	}
	if spec.IsReboot {
		res.Note = "@reboot 由 cron 守护进程在系统启动时执行，没有日历意义上的下次执行时间。"
		return res, nil
	}
	cur := m.now()
	for len(res.Runs) < count {
		next, has, err := spec.NextRun(cur, m.location)
		if err != nil {
			res.Reason = strings.TrimPrefix(err.Error(), "cron: ")
			break
		}
		if !has {
			break
		}
		res.Runs = append(res.Runs, next.Format(time.RFC3339))
		cur = next
	}
	return res, nil
}

// PreviewResult 是表达式预览的结果。
type PreviewResult struct {
	// Expression 是归一化后（@ 别名已展开）准备写入 crontab 的表达式。
	Expression string `json:"expression"`
	// Original 是用户提交的原文，便于 UI 对照展示。
	Original string `json:"original"`
	// Human 是中文描述（不在常见模式里时为空，UI 回退展示原文）。
	Human string `json:"human,omitempty"`
	// Reboot 表示 @reboot（无下次执行时间）。
	Reboot bool `json:"reboot"`
	// Runs 是接下来若干次执行时间（RFC3339，本地时区）。
	Runs []string `json:"runs"`
	// Note 是补充说明（@reboot 等）。
	Note string `json:"note,omitempty"`
	// Reason 是求解中断的原因（永不成立的表达式）。
	Reason string `json:"reason,omitempty"`
}

// parse 解析并填充表达式派生字段（合法性、下次执行时间）。
func (m *Manager) parse(content string) *tab {
	t := parseTab(content, m.jobsDir, m.logsDir, m.readScript)
	now := m.now()
	for _, j := range t.jobs {
		spec, err := ValidateExpr(j.Expression)
		if err != nil {
			j.Valid = false
			j.InvalidReason = strings.TrimPrefix(err.Error(), "cron: ")
			continue
		}
		j.Valid = true
		j.Reboot = spec.IsReboot
		j.Human = spec.Humanize()
		if next, has, err := spec.NextRun(now, m.location); err == nil && has {
			j.NextRun = next.Format(time.RFC3339)
			j.NextRunHas = true
		}
	}
	return t
}

// readScript 读取包装脚本里的真实命令。
func (m *Manager) readScript(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	cmd, ok := extractCommand(string(body))
	if !ok {
		return "", false
	}
	return cmd, true
}

// scriptOpen / scriptClose：scriptBody 里包裹用户命令的两行固定标记。
const (
	scriptOpen  = "{"
	scriptClose = "} >> '"
)

// extractCommand 从包装脚本正文里取回用户命令原文。
//
// 依赖 scriptBody 的固定结构：命令是「{」行的下一整行。
// 取不到时返回 ok=false，由调用方标成 CommandMissing——
// 宁可显示「命令不可读」，也不显示一个**猜出来的**命令。
func extractCommand(body string) (string, bool) {
	lines := strings.Split(body, "\n")
	for i := 0; i+2 < len(lines); i++ {
		if lines[i] != scriptOpen {
			continue
		}
		if !strings.HasPrefix(lines[i+2], scriptClose) {
			return "", false
		}
		cmd := lines[i+1]
		if strings.TrimSpace(cmd) == "" {
			return "", false
		}
		return cmd, true
	}
	return "", false
}

// WriteResult 是一次写操作的结果。
type WriteResult struct {
	// Job 是写入后的任务视图（删除时为被删掉的那条）。
	Job *Job `json:"job"`
	// Jobs 是写入后的完整列表，前端可直接替换表格。
	Jobs []*Job `json:"jobs"`
	// BackupPath 是本次改动的备份文件（绝对路径）。
	BackupPath string `json:"backup_path,omitempty"`
	// BeforeCount / AfterCount 是任务条数变化。
	BeforeCount int `json:"before_count"`
	AfterCount  int `json:"after_count"`
	// RolledBack 表示写失败后已回滚。
	RolledBack bool `json:"rolled_back"`
	// RollbackErr 是回滚本身失败的原因（此时用户需要手工恢复）。
	RollbackErr string `json:"rollback_error,omitempty"`
	// RestoredFrom 是回滚写回的内容来源描述。
	RestoredFrom string `json:"restored_from,omitempty"`
	// Warning 是「操作成功但有附加信息」的提示。
	Warning string `json:"warning,omitempty"`
}

// Create 新增任务。
func (m *Manager) Create(ctx context.Context, in JobInput) (*WriteResult, error) {
	spec, err := ValidateJobInput(in)
	if err != nil {
		return nil, err
	}
	return m.apply(ctx, ActionCreate, "", in, func(t *tab, lines []string) ([]string, *Job, error) {
		id, err := NewJobID()
		if err != nil {
			return nil, nil, err
		}
		raw := jobLine(spec, filepath.Join(m.jobsDir, id+".sh"))
		newLines := append([]string(nil), lines...)
		newLines = append(newLines, markerLine(id, strings.TrimSpace(in.Comment)), raw)
		job := &Job{
			ID:         id,
			Managed:    true,
			Expression: spec.Normalize(),
			Command:    in.Command,
			Comment:    strings.TrimSpace(in.Comment),
			Raw:        raw,
			startLine:  len(newLines) - 2,
			endLine:    len(newLines) - 1,
		}
		return newLines, job, nil
	})
}

// Update 编辑任务（非面板任务编辑即收编）。
func (m *Manager) Update(ctx context.Context, id string, in JobInput) (*WriteResult, error) {
	if err := ValidateJobID(id); err != nil {
		return nil, err
	}
	spec, err := ValidateJobInput(in)
	if err != nil {
		return nil, err
	}
	return m.apply(ctx, ActionUpdate, id, in, func(t *tab, lines []string) ([]string, *Job, error) {
		old := t.findJob(id)
		if old == nil {
			return nil, nil, fmt.Errorf("%w: %s", ErrJobNotFound, id)
		}
		// 收编一个面板不支持的表达式没有意义：用户改不动的东西
		// 却在面板里显示成「可编辑」，保存后只会破坏他的原文件。
		if !old.Valid {
			return nil, nil, &ErrJobInvalid{ID: id,
				Reason: "表达式不被面板支持（" + old.InvalidReason + "）"}
		}
		// 非面板任务收编时启用一个稳定新 id；已是面板任务则保持 id 不变
		// （否则用户收藏的日志与审计关联会断掉）。
		newID := old.ID
		if !old.Managed {
			newID, err = NewJobID()
			if err != nil {
				return nil, nil, err
			}
		}
		job := &Job{
			ID:         newID,
			Managed:    true,
			Expression: spec.Normalize(),
			Command:    in.Command,
			Comment:    strings.TrimSpace(in.Comment),
			Raw:        jobLine(spec, filepath.Join(m.jobsDir, newID+".sh")),
		}
		newLines := make([]string, 0, len(lines)+1)
		newLines = append(newLines, lines[:old.startLine]...)
		newLines = append(newLines, markerLine(newID, job.Comment), job.Raw)
		newLines = append(newLines, lines[old.endLine+1:]...)
		job.startLine = old.startLine
		job.endLine = job.startLine + 1
		return newLines, job, nil
	})
}

// Delete 删除任务。
//
// confirm=false 时返回 ErrConfirmRequired（接口层 → 428）：
// 与 4.6 防火墙同一纪律——前端弹窗只是体验，服务端强制才是边界。
// 删掉一条正在跑的生产定时任务（备份、证书续期）是不可逆的。
func (m *Manager) Delete(ctx context.Context, id string, confirm bool, expectedIDs []string) (*WriteResult, error) {
	if err := ValidateJobID(id); err != nil {
		return nil, err
	}
	if !confirm {
		return nil, ErrConfirmRequired
	}
	return m.apply(ctx, ActionDelete, id, JobInput{ExpectedJobIDs: expectedIDs},
		func(t *tab, lines []string) ([]string, *Job, error) {
			old := t.findJob(id)
			if old == nil {
				return nil, nil, fmt.Errorf("%w: %s", ErrJobNotFound, id)
			}
			newLines := make([]string, 0, len(lines))
			newLines = append(newLines, lines[:old.startLine]...)
			newLines = append(newLines, lines[old.endLine+1:]...)
			return newLines, old, nil
		})
}

// applyFunc 是在已解析的 tab 上产出新内容的函数。
type applyFunc func(t *tab, lines []string) ([]string, *Job, error)

// apply 是所有写操作的**唯一**实现（见文件头的固定时序）。
func (m *Manager) apply(ctx context.Context, action Action, id string, in JobInput, fn applyFunc) (*WriteResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 整个「读-备份-写-回滚」序列共用一个超时预算：
	// 只对其中某一步生效的超时会给用户虚假的安全感（4.1 的坑位 52）。
	if m.commandTO > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.commandTO*4)
		defer cancel()
	}

	// ① 读当前内容。
	before, err := m.store.Read(ctx)
	if err != nil {
		return nil, err
	}
	t := m.parse(before)

	// 乐观并发断言：客户端提交的 id 集合必须与现状一致。
	if err := checkExpected(t, in.ExpectedJobIDs); err != nil {
		return nil, err
	}
	beforeCount := len(t.jobs)

	// ② 行级改写。
	newLines, job, err := fn(t, t.lines)
	if err != nil {
		return nil, err
	}
	after := renderContent(newLines)

	// 脚本改动先落盘（同时记下如何撤销），失败时整体放弃。
	scriptPath := ""
	if job.Managed {
		scriptPath = filepath.Join(m.jobsDir, job.ID+".sh")
	}
	oldJob := t.findJob(id)
	oldScriptPath, oldScript, hadOldScript := "", "", false
	if oldJob != nil && oldJob.Managed && oldJob.ScriptPath != "" {
		oldScriptPath = oldJob.ScriptPath
		if b, err := os.ReadFile(oldScriptPath); err == nil {
			oldScript, hadOldScript = string(b), true
		}
	}
	// 日志截断只针对**本次操作涉及的任务**：在任何一次写操作里
	// 顺手遍历全部任务的日志，会让一次无关的编辑返回
	// 「任务 X 的日志被截断」这种与用户操作毫无关系的警告。
	var touchedLogs []string

	switch action {
	case ActionCreate, ActionUpdate:
		logPath := job.LogPath
		if logPath == "" {
			logPath = filepath.Join(m.logsDir, job.ID+".log")
		}
		if err := m.writeScript(scriptPath, scriptBody(job.ID, job.Command, logPath)); err != nil {
			return nil, err
		}
		touchedLogs = append(touchedLogs, logPath)
	case ActionDelete:
		if oldJob != nil && oldJob.ScriptPath != "" {
			if err := os.Remove(oldJob.ScriptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("cron: 删除包装脚本失败（未改动 crontab）: %w", err)
			}
		}
		if oldJob != nil && oldJob.LogPath != "" {
			touchedLogs = append(touchedLogs, oldJob.LogPath)
		}
	}

	// ③ 备份改前内容。备份失败 = 拒绝写入。
	backupPath, backupErr := m.backup(before)
	if backupErr != nil {
		m.undoScriptChange(action, scriptPath, oldScriptPath, oldScript, hadOldScript, id)
		return nil, backupErr
	}

	// ④ 写 crontab；⑤ 失败回滚。
	if err := m.store.Write(ctx, after); err != nil {
		res := &WriteResult{BackupPath: backupPath, BeforeCount: beforeCount, RolledBack: true}
		if rbErr := m.store.Write(ctx, before); rbErr != nil {
			// 回滚也失败：把备份路径交还给用户，并在审计里醒目标出。
			res.RollbackErr = rbErr.Error()
			res.RestoredFrom = "回滚失败：请手工执行 crontab " + backupPath
			m.logger.Error("写入 crontab 失败且回滚也失败，已保留备份",
				"write_err", err.Error(), "rollback_err", rbErr.Error(), "backup", backupPath)
		} else {
			res.RestoredFrom = "已成功回滚到改动前的内容"
		}
		// 脚本也恢复到改前状态（删除操作把脚本放回去）。
		m.undoScriptChange(action, scriptPath, oldScriptPath, oldScript, hadOldScript, id)
		return res, fmt.Errorf("cron: 保存 crontab 失败，已回滚: %w", err)
	}

	// 写成功后的收尾：
	//  · 收编换了 id 的面板任务，把旧脚本删掉（否则会留一个没人引用的可执行文件）；
	//  · 本次任务日志超限时截断。
	if action == ActionUpdate && hadOldScript && oldScriptPath != "" && oldScriptPath != scriptPath {
		_ = os.Remove(oldScriptPath)
	}
	afterTab := m.parse(after)
	var warnings []string
	for _, p := range touchedLogs {
		rotated, err := RotateLogIfNeeded(p, m.logMaxBytes)
		if err != nil {
			m.logger.Warn("计划任务日志截断失败（不影响任务本身）", "path", p, "err", err)
			continue
		}
		if rotated {
			warnings = append(warnings, "该任务的执行日志超出大小上限，已截断并保留最近部分")
		}
	}

	// 返回值以**写入后的真实视图**为准（派生字段按新内容重新算过）。
	// 找不到时用传入的 job 兜底（只可能出现在异常情形），
	// 但**不**用行区间去 newLines 里取 Raw —— 删除操作后该区间
	// 指向的是别的内容，取回来就是一个说谎的 Raw 字段。
	final := afterTab.findJob(job.ID)
	if final == nil {
		final = job
	}
	final.LineNo = final.startLine + 1
	if action == ActionDelete && final.LineNo < 1 {
		final.LineNo = 0
	}
	res := &WriteResult{
		Job:         final,
		Jobs:        afterTab.jobs,
		BackupPath:  backupPath,
		BeforeCount: beforeCount,
		AfterCount:  len(afterTab.jobs),
	}
	if len(warnings) > 0 {
		res.Warning = strings.Join(warnings, "；")
	}
	return res, nil
}

// checkExpected 校验客户端提交的 id 集合与现状一致（乐观并发）。
//
// 空集合表示「不做断言」（curl 直连、脚本调用等），此时仍安全：
// 行级改写基于刚读到的内容，只是可能覆盖别人同时加的任务。
// 前端一律带上集合，因为「面板上看着在、其实已被别人删掉」
// 是最容易让用户困惑的失败。
func checkExpected(t *tab, expected []string) error {
	if len(expected) == 0 {
		return nil
	}
	have := make(map[string]bool, len(t.jobs))
	for _, j := range t.jobs {
		have[j.ID] = true
	}
	want := make(map[string]bool, len(expected))
	for _, id := range expected {
		if !managedIDRe.MatchString(id) && !derivedIDRe.MatchString(id) {
			continue // 非法形态的 id 不参与比对（防御性：别让它干扰判断）
		}
		want[id] = true
	}
	for id := range have {
		if !want[id] {
			return &ErrEditConflict{ID: id}
		}
	}
	for id := range want {
		if !have[id] {
			return &ErrEditConflict{ID: id}
		}
	}
	return nil
}

// writeScript 原子写包装脚本（0700：里面有可执行命令，且属主可改）。
func (m *Manager) writeScript(path, body string) error {
	if path == "" {
		return errors.New("cron: 内部错误：包装脚本路径为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cron: 创建脚本目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".job-*.tmp")
	if err != nil {
		return fmt.Errorf("cron: 创建临时脚本失败: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := writeAllAndSync(tmp, body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cron: 写入临时脚本失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cron: 关闭临时脚本失败: %w", err)
	}
	if err := os.Chmod(name, 0o700); err != nil {
		return fmt.Errorf("cron: 设置脚本权限失败: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("cron: 替换脚本 %s 失败: %w", path, err)
	}
	return nil
}

// undoScriptChange 把脚本改动撤销回改前状态。
//
// 各操作对应的「改前状态」：
//
//	create：新脚本本来不存在 → 删掉它；
//	update：新脚本路径若与旧的不同 → 删新脚本，把旧内容放回旧路径；
//	delete：旧脚本被移走了 → 用改前读到的内容放回旧路径
//	        （内容早已读出，恢复是可靠的；万一没读到内容才降级为告警）。
func (m *Manager) undoScriptChange(action Action, scriptPath, oldPath, oldScript string, hadOld bool, id string) {
	switch action {
	case ActionCreate:
		if scriptPath != "" {
			_ = os.Remove(scriptPath)
		}
	case ActionUpdate:
		if scriptPath != "" && scriptPath != oldPath {
			_ = os.Remove(scriptPath)
		}
		if oldPath != "" && hadOld {
			_ = m.writeScript(oldPath, oldScript)
		}
	case ActionDelete:
		if oldPath == "" {
			return
		}
		if hadOld {
			_ = m.writeScript(oldPath, oldScript)
			return
		}
		m.logger.Warn("删除操作已回滚，但该任务的包装脚本无法自动恢复，"+
			"请在面板上重新保存该任务以重建脚本", "job", id, "path", oldPath)
	}
}

// backup 把改动前的内容写入备份目录，返回路径。
//
// 同时写一个**固定名**的 last 副本：出事后不必去一堆带时间戳的文件里
// 找最近那一个（时间戳文件名对人并不友好）。
func (m *Manager) backup(content string) (string, error) {
	if err := os.MkdirAll(m.backupsDir, 0o700); err != nil {
		return "", fmt.Errorf("cron: 创建备份目录失败: %w", err)
	}
	stamped := filepath.Join(m.backupsDir,
		"crontab."+m.now().Format("20060102-150405.000000")+".bak")
	if err := writeBackup(stamped, content); err != nil {
		return "", err
	}
	if err := writeBackup(filepath.Join(m.backupsDir, "crontab.last.bak"), content); err != nil {
		m.logger.Warn("写最近备份副本失败（带时间戳的备份仍然可用）", "path", stamped, "err", err)
	}
	m.pruneBackups()
	return stamped, nil
}

func writeBackup(path, content string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cron: 创建备份文件失败: %w", err)
	}
	if err := writeAllAndSync(f, content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cron: 写入备份失败: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cron: 关闭备份文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cron: 落地备份失败: %w", err)
	}
	return nil
}

// pruneBackups 只保留最近 backupKeep 份带时间戳的备份。
// 不清理的后果：面板每次改任务都留一份，一年下来目录里几万个文件。
func (m *Manager) pruneBackups() {
	entries, err := os.ReadDir(m.backupsDir)
	if err != nil {
		return
	}
	var baks []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "crontab.") ||
			!strings.HasSuffix(e.Name(), ".bak") || e.Name() == "crontab.last.bak" {
			continue
		}
		baks = append(baks, e.Name())
	}
	if len(baks) <= m.backupKeep {
		return
	}
	// 时间戳格式保证字典序即时间序。
	sort.Strings(baks)
	for _, name := range baks[:len(baks)-m.backupKeep] {
		_ = os.Remove(filepath.Join(m.backupsDir, name))
	}
}

// listBackups 返回最近的备份文件名（倒序）。
func (m *Manager) listBackups() []string {
	entries, err := os.ReadDir(m.backupsDir)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "crontab.") && strings.HasSuffix(e.Name(), ".bak") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	// 倒序 + 限量。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > m.backupKeep {
		out = out[:m.backupKeep]
	}
	return out
}

// markerLine 生成标记注释行。
func markerLine(id, comment string) string {
	if comment == "" {
		return "# lipanel:" + id
	}
	return "# lipanel:" + id + " " + comment
}

// jobLine 生成任务行：固定调用包装脚本，**不含任何用户输入**。
//
// ########## 这一行为什么是本模块安全设计的关键 ##########
//
// 用户命令永远不出现在 crontab 行里，而是待在数据目录的脚本文件中。
// 于是 crontab 行成了一个**由面板完全生成**的模板：
// 无论命令里有什么（引号、$()、反引号、分号、管道），
// 都不可能把 crontab 行本身改写成别的样子——
// 注入需要「改变行的结构」，而这一行的结构里没有任何用户可写的部分。
//
// 脚本路径用单引号包住：路径由面板生成（id 过 managedIDRe、
// 目录是启动期确定的绝对路径），不含单引号，因此不可能被闭合。
func jobLine(spec *ExprSpec, scriptPath string) string {
	return spec.Normalize() + ` /bin/sh '` + scriptPath + "'"
}
