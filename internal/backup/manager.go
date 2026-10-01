package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lipanel/internal/cron"
	"lipanel/internal/file"
)

// ============================================================================
// 备份管理器（阶段五 5.3）
// ============================================================================
//
// ########## 执行流程（唯一一份实现）##########
//
//	① 取执行锁（跨进程互斥，见 lock.go）
//	② 解析任务与存储配置（配置已变则如实失败）
//	③ 源路径过白名单（file.Resolver）
//	④ 打包到 staging/<taskid>-<时间>.tar.gz（见 archive.go）
//	⑤ 上传到目标存储（见 storage_*.go）
//	⑥ 应用保留策略（见 retention.go）
//	⑦ 写历史（见 history.go）
//	⑧ 清理 staging 文件
//
// 手动执行与 cron 子进程**走的是同一个 Execute**，只差一个 trigger 标签。
// 两条路径各写一份实现必然漂移，而漂移的后果是"手动执行成功、
// 定时执行悄悄失败"——用户要到需要恢复的那天才发现。
//
// ########## 超时预算 ##########
//
// 整条链路共用一个 ExecTimeout（默认 30 分钟），而不是每一步各给一个：
// 只对某一步生效的超时会给用户虚假的安全感（4.1 的坑位 52）。
//
// ########## staging 目录 ##########
//
// 归档先落在本地 staging 文件上，而不是"边打包边上传"：
//   · S3 的 SigV4 需要在发送前知道载荷的 SHA256，因此必须先有一个
//     可重放的来源；两遍 I/O 换来的是"永远不需要把归档放进内存"；
//   · 失败重试、体积统计、本地后端的原子 rename 都依赖它；
//   · 上传成功后立即删除（除非用户显式要求保留本地副本）。

// Options 是构造 Manager 的配置。
type Options struct {
	// DataDir 是数据目录（配置、历史、锁、staging 都在其下）。
	DataDir string
	// StorePath 是配置文件路径；为空时取 <DataDir>/tasks.json。
	StorePath string
	// SourceRoots 是允许作为备份源的白名单根目录。
	SourceRoots []string
	// RestoreRoots 是允许作为恢复目标的白名单根目录。
	RestoreRoots []string
	// RestoreRootExplicit 表示恢复根是管理员显式配的（不是默认值）。
	RestoreRootExplicit bool
	// ExecTimeout 是单次执行的总超时。
	ExecTimeout time.Duration
	// HTTPTimeout 是单次存储请求超时。
	HTTPTimeout time.Duration
	// MaxArchiveBytes 是归档体积上限。
	MaxArchiveBytes int64
	// MaxSourceBytes 是源数据总量上限。
	MaxSourceBytes int64
	// MaxEntries 是打包条目数上限。
	MaxEntries int
	// MaxHistoryEntries 是每任务历史条数上限。
	MaxHistoryEntries int
	// Cron 是计划任务管理器（可为 nil：此时任务只能手动执行）。
	Cron *cron.Manager
	// Logger / Auditor 可为 nil。
	Logger  *slog.Logger
	Auditor *Auditor
	// Now 注入时钟（测试用）。
	Now func() time.Time
}

// Manager 提供备份任务的增删改查与执行。
type Manager struct {
	dataDir             string
	storePath           string
	stagingDir          string
	historyDir          string
	lockDir             string
	srcResolver         *file.Resolver
	rstResolver         *file.Resolver
	restoreRootExplicit bool

	execTimeout time.Duration
	httpTimeout time.Duration
	maxArchive  int64
	maxSource   int64
	maxEntries  int
	maxHistory  int

	store    *Store
	cron     *cron.Manager
	cronOpts cronLinkOptions
	logger   *slog.Logger
	auditor  *Auditor
	now      func() time.Time

	// mu 串行化**配置写**（增删改任务与存储）。
	// 执行路径不走它：执行可能持续几十分钟，用它做互斥会让
	// 「列表」这类只读接口全部卡住。执行之间靠文件锁（lock.go）。
	mu sync.Mutex
	// histMu 保护历史文件的截断（见 history.go）。
	histMu sync.Mutex

	// httpClientFor 允许测试注入 HTTP 客户端（按存储类型）。
	//
	// 测试注入的不是"假客户端"，而是配置了正确超时的**真客户端**：
	// 要验证的正是真实的 HTTP 交互（签名、XML 解析、状态码处理），
	// 把 HTTP 层替换成替身等于把被测对象换成了替身。
	httpClientFor func(Storage) *http.Client
}

// NewManager 构造管理器。
func NewManager(opts Options) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析数据目录失败: %w", err)
	}
	storePath := opts.StorePath
	if storePath == "" {
		storePath = filepath.Join(absData, "tasks.json")
	}

	srcRoots := opts.SourceRoots
	if len(srcRoots) == 0 {
		srcRoots = []string{DefaultSourceRoot}
	}
	rstRoots := opts.RestoreRoots
	if len(rstRoots) == 0 {
		rstRoots = []string{DefaultRestoreRoot}
	}

	// 两类白名单都用 4.2 的同一份实现。恢复根目录可能还不存在
	// （默认值就是新建的），因此先建出来——Resolver 要求根必须已存在，
	// 而这个要求是对的：一个不存在的根只会在用户操作时报出
	// 令人困惑的 ENOENT。
	for _, r := range rstRoots {
		if err := os.MkdirAll(r, storeDirMode); err != nil {
			return nil, fmt.Errorf("backup: 创建恢复根目录 %s 失败: %w", r, err)
		}
	}

	srcResolver, err := file.NewResolver(srcRoots)
	if err != nil {
		return nil, fmt.Errorf("backup: 初始化源路径白名单失败: %w", err)
	}
	rstResolver, err := file.NewResolver(rstRoots)
	if err != nil {
		return nil, fmt.Errorf("backup: 初始化恢复目标白名单失败: %w", err)
	}

	execTimeout := opts.ExecTimeout
	if execTimeout <= 0 {
		execTimeout = DefaultExecTimeout
	}
	httpTimeout := opts.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = DefaultHTTPTimeout
	}
	maxArchive := opts.MaxArchiveBytes
	if maxArchive <= 0 {
		maxArchive = DefaultMaxArchiveBytes
	}
	maxSource := opts.MaxSourceBytes
	if maxSource <= 0 {
		maxSource = DefaultMaxSourceBytes
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	maxHistory := opts.MaxHistoryEntries
	if maxHistory <= 0 {
		maxHistory = DefaultMaxHistoryEntries
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	auditor := opts.Auditor
	if auditor == nil {
		// 与其它核心模块一致：Auditor 为 nil 时构造一个仅内存的审计器，
		// 判定与留痕的链路不因「没配 -audit-log」而短路。
		auditor, err = NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
	}

	store, err := NewStore(storePath, logger)
	if err != nil {
		return nil, err
	}
	if err := store.Load(); err != nil {
		return nil, err
	}

	m := &Manager{
		dataDir:             absData,
		storePath:           storePath,
		stagingDir:          filepath.Join(absData, "staging"),
		historyDir:          filepath.Join(absData, "history"),
		lockDir:             filepath.Join(absData, "locks"),
		srcResolver:         srcResolver,
		rstResolver:         rstResolver,
		restoreRootExplicit: opts.RestoreRootExplicit,
		execTimeout:         execTimeout,
		httpTimeout:         httpTimeout,
		maxArchive:          maxArchive,
		maxSource:           maxSource,
		maxEntries:          maxEntries,
		maxHistory:          maxHistory,
		store:               store,
		cron:                opts.Cron,
		logger:              logger,
		auditor:             auditor,
		now:                 now,
	}
	m.cronOpts = cronLinkOptions{
		Executable: executablePath(),
		StorePath:  storePath,
	}

	// 目录提前建好：等到第一次备份时才因为权限失败，
	// 用户看到的就是一句与「备份失败」相关的含糊报错。
	for _, d := range []string{m.dataDir, m.stagingDir, m.historyDir, m.lockDir} {
		if err := os.MkdirAll(d, storeDirMode); err != nil {
			return nil, fmt.Errorf("backup: 创建数据目录 %s 失败: %w", d, err)
		}
	}
	// staging 是中间产物：进程启动时里面的东西必然是上次异常退出
	// 留下的残骸，清掉它们（不清理会一直占着磁盘，而没人会想到
	// 去一个叫 staging 的目录里找空间）。
	m.cleanStaging()
	return m, nil
}

// cleanStaging 清理 staging 目录里的残留。
func (m *Manager) cleanStaging() {
	entries, err := os.ReadDir(m.stagingDir)
	if err != nil {
		return
	}
	removed := 0
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(m.stagingDir, e.Name())); err == nil {
			removed++
		}
	}
	if removed > 0 {
		m.logger.Warn("已清理上次异常退出留下的打包中间文件",
			"dir", m.stagingDir, "count", removed)
	}
}

// Auditor 返回审计器，供 server 层查询记录与统计。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// DataDir 返回数据目录。
func (m *Manager) DataDir() string { return m.dataDir }

// StorePath 返回配置文件路径。
func (m *Manager) StorePath() string { return m.storePath }

// ExecTimeout 返回单次执行超时。
func (m *Manager) ExecTimeout() time.Duration { return m.execTimeout }

// Limits 返回运行限制。
func (m *Manager) Limits() Limits {
	return Limits{
		ExecTimeoutSeconds: int(m.execTimeout.Seconds()),
		HTTPTimeoutSeconds: int(m.httpTimeout.Seconds()),
		MaxArchiveBytes:    m.maxArchive,
		MaxSourceBytes:     m.maxSource,
		MaxEntries:         m.maxEntries,
		MaxHistoryEntries:  m.maxHistory,
		PreviewMaxEntries:  DefaultPreviewMaxEntries,
	}
}

// Status 返回模块运行状态。
//
// 它**不做任何写操作**：面板启动不该改写系统上的任何东西。
func (m *Manager) Status(ctx context.Context) Status {
	tasks, _ := m.store.Tasks()
	storages, _ := m.store.Storages()

	st := Status{
		DataDir:           m.dataDir,
		StorePath:         m.storePath,
		SourceRoots:       rootPaths(m.srcResolver),
		RestoreRoots:      rootPaths(m.rstResolver),
		RestoreRootNarrow: !m.restoreRootExplicit,
		TaskCount:         len(tasks),
		StorageCount:      len(storages),
		Limits:            m.Limits(),
		Audit:             m.auditor.Stats(),
	}
	if m.cron != nil {
		cs := m.cron.Status(ctx)
		st.CronAvailable = cs.Available
		st.CronReason = cs.Reason
		st.CronMode = cs.Mode
		st.CronTarget = cs.Target
	} else {
		st.CronReason = "计划任务模块未启用（面板启动时未注入 cron 管理器）"
	}
	return st
}

// rootPaths 提取白名单根目录的路径列表。
func rootPaths(r *file.Resolver) []string {
	if r == nil {
		return []string{}
	}
	roots := r.Roots()
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		out = append(out, root.Path)
	}
	return out
}

// ---------------------------------------------------------------------------
// 任务 CRUD
// ---------------------------------------------------------------------------

// ListTasks 返回任务列表（含派生字段）。
func (m *Manager) ListTasks(ctx context.Context) ([]*TaskView, error) {
	tasks, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	storages, err := m.store.Storages()
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*Storage, len(storages))
	for _, st := range storages {
		byID[st.ID] = st
	}
	out := make([]*TaskView, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, m.viewOf(ctx, t, byID[t.StorageID]))
	}
	return out, nil
}

// GetTask 返回单个任务的视图。
func (m *Manager) GetTask(ctx context.Context, id string) (*TaskView, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	t, err := m.store.FindTask(id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, id)
	}
	var st *Storage
	if t.StorageID != "" {
		st, _ = m.store.FindStorage(t.StorageID)
	}
	return m.viewOf(ctx, t, st), nil
}

// viewOf 组装任务视图（派生字段现算，绝不落盘）。
func (m *Manager) viewOf(ctx context.Context, t *Task, st *Storage) *TaskView {
	v := &TaskView{Task: t, BackupCount: -1}
	if st != nil {
		v.StorageName = st.Name
		v.StorageType = st.Type
	} else {
		v.StorageMissing = true
	}

	// 源路径状态：用一个**只读**的探测告诉用户"这条任务现在跑会失败"，
	// 而不是等他点了执行才发现。探测失败也不影响列表返回。
	if info, err := os.Lstat(t.SourcePath); err != nil {
		v.SourceExists = false
		v.SourceReason = "源路径不存在或不可读：" + err.Error()
	} else if info.Mode()&os.ModeSymlink != 0 {
		v.SourceExists = false
		v.SourceReason = "源路径是符号链接，面板拒绝备份链接本身（它指向的内容不在你的预期内）"
	} else if t.SourceType == SourceDir && !info.IsDir() {
		v.SourceExists = false
		v.SourceReason = "任务配置为备份目录，但该路径不是目录"
	} else if t.SourceType == SourceFile && !info.Mode().IsRegular() {
		v.SourceExists = false
		v.SourceReason = "任务配置为备份文件，但该路径不是普通文件"
	} else {
		v.SourceExists = true
	}

	// 表达式派生字段：用 **cron 包** 的解析器，不是这里再写一份。
	// 同一界面上出现两个互相矛盾的「下次执行时间」比不显示更糟。
	if spec, err := cron.ValidateExpr(t.Expr); err != nil {
		v.Valid = false
		v.InvalidReason = strings.TrimPrefix(err.Error(), "cron: ")
	} else {
		v.Valid = true
		v.Reboot = spec.IsReboot
		v.Human = spec.Humanize()
		if next, has, nerr := spec.NextRun(m.now(), time.Local); nerr == nil && has {
			v.NextRun = next.Format(time.RFC3339)
			v.NextRunHas = true
		}
	}

	// crontab 挂接状态。
	switch {
	case !t.Enabled:
		v.CronManaged = false
		v.CronReason = "任务已停用（不会定时执行，可手动执行）"
	case t.CronJobID == "":
		v.CronManaged = false
		v.CronReason = "尚未挂到计划任务上（保存时同步失败或计划任务不可用）"
	default:
		v.CronManaged = true
	}

	v.Running = m.LockHeld(t.ID)

	// 最近一次执行记录。
	if last, err := m.LastEntry(t.ID); err == nil && last != nil {
		v.Last = last
		v.LastStatus = last.Status
	}
	return v
}

// CreateTask 新增任务。
func (m *Manager) CreateTask(ctx context.Context, in TaskInput) (*TaskView, error) {
	norm, err := ValidateTask(in)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// 并发断言：与 5.2 同一手法，防止"基于过期的列表做编辑"。
	current, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	if err := checkExpectedTasks(current, in.ExpectedIDs); err != nil {
		return nil, err
	}

	// 存储必须存在：允许引用一个不存在的存储，只会让任务在被执行时
	// 才炸掉，而那时用户已经忘了自己配过什么。
	st, err := m.store.FindStorage(norm.StorageID)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, invalid("storage_id", "所选存储配置不存在（可能已被删除）")
	}
	if err := m.validateSourceForSave(norm); err != nil {
		return nil, err
	}

	id, err := NewID()
	if err != nil {
		return nil, err
	}
	now := m.now()
	task := &Task{
		ID:         id,
		Name:       norm.Name,
		Type:       TypeFull,
		SourceType: norm.SourceType,
		SourcePath: norm.SourcePath,
		StorageID:  norm.StorageID,
		Prefix:     norm.Prefix,
		Expr:       norm.Expr,
		Comment:    norm.Comment,
		KeepPolicy: norm.KeepPolicy,
		KeepCount:  norm.KeepCount,
		KeepDays:   norm.KeepDays,
		// ⚠️ 必须用**归一化后**的 norm.Enabled，不是 in.Enabled：
		// in 里的零值 false 会被 ValidateTask 归一化成 true，
		// 而这里若读原值，归一化就等于没做——新建的任务全是停用的。
		Enabled: norm.Enabled,
		CreatedAt:  now.Format(time.RFC3339),
	}

	// 先挂 crontab 再落盘，还是反过来？
	//
	// 这里选**先落盘**：任务的定义才是真相，crontab 是它的一个投影。
	// 反过来（先挂 cron 再写配置）会出现"crontab 上有一条指向不存在
	// 任务的行"，那条行每天跑一次、每天失败一次。
	// 先落盘的代价是"配置里有任务但 crontab 上还没有"——
	// 那是可恢复的（用户再保存一次，或我们下次同步时补上），
	// 且 CronReason 会如实说明。
	if err := m.store.Mutate(func(d *storeData) error {
		d.Tasks = append(d.Tasks, task)
		return nil
	}); err != nil {
		return nil, err
	}

	cronJobID, cronReason, err := m.syncCron(ctx, task)
	if err != nil {
		// cron 同步出错不影响任务已保存这一事实，如实返回原因。
		cronReason = trimErr(err)
	}
	if cronJobID != "" {
		task.CronJobID = cronJobID
		if err := m.store.Mutate(func(d *storeData) error {
			for _, t := range d.Tasks {
				if t.ID == task.ID {
					t.CronJobID = cronJobID
					return nil
				}
			}
			return nil
		}); err != nil {
			m.logger.Warn("保存 crontab 任务 id 失败（任务本身已保存）", "task", task.ID, "err", err)
		}
	}

	view := m.viewOf(ctx, task, st)
	if cronReason != "" {
		view.CronReason = cronReason
	}
	return view, nil
}

// UpdateTask 编辑任务。
func (m *Manager) UpdateTask(ctx context.Context, id string, in TaskInput) (*TaskView, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	norm, err := ValidateTask(in)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	if err := checkExpectedTasks(current, in.ExpectedIDs); err != nil {
		return nil, err
	}
	var existing *Task
	for _, t := range current {
		if t.ID == id {
			existing = t
			break
		}
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, id)
	}
	st, err := m.store.FindStorage(norm.StorageID)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, invalid("storage_id", "所选存储配置不存在（可能已被删除）")
	}
	if err := m.validateSourceForSave(norm); err != nil {
		return nil, err
	}

	updated := *existing
	updated.Name = norm.Name
	updated.SourceType = norm.SourceType
	updated.SourcePath = norm.SourcePath
	updated.StorageID = norm.StorageID
	updated.Prefix = norm.Prefix
	updated.Expr = norm.Expr
	updated.Comment = norm.Comment
	updated.KeepPolicy = norm.KeepPolicy
	updated.KeepCount = norm.KeepCount
	updated.KeepDays = norm.KeepDays
	// 同上：读归一化后的值，否则"编辑一次任务"就会把它停用。
	updated.Enabled = norm.Enabled
	updated.UpdatedAt = m.now().Format(time.RFC3339)

	if err := m.store.Mutate(func(d *storeData) error {
		for i, t := range d.Tasks {
			if t.ID == id {
				d.Tasks[i] = &updated
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrTaskNotFound, id)
	}); err != nil {
		return nil, err
	}

	cronJobID, cronReason, cerr := m.syncCron(ctx, &updated)
	if cerr != nil {
		cronReason = trimErr(cerr)
	}
	if cronJobID != updated.CronJobID {
		updated.CronJobID = cronJobID
		_ = m.store.Mutate(func(d *storeData) error {
			for _, t := range d.Tasks {
				if t.ID == id {
					t.CronJobID = cronJobID
					return nil
				}
			}
			return nil
		})
	}

	view := m.viewOf(ctx, &updated, st)
	if cronReason != "" {
		view.CronReason = cronReason
	}
	return view, nil
}

// DeleteTask 删除任务。
//
// confirm 由调用方（接口层）强制要求：删掉一条备份任务意味着
// 从此不再有新的备份，而这件事往往要到需要恢复的那天才被发现。
func (m *Manager) DeleteTask(ctx context.Context, id string, confirm bool, expectedIDs []string) (*Task, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	if !confirm {
		return nil, ErrConfirmRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	if err := checkExpectedTasks(current, expectedIDs); err != nil {
		return nil, err
	}
	var target *Task
	for _, t := range current {
		if t.ID == id {
			target = t
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, id)
	}
	if err := m.removeCronJob(ctx, target.CronJobID); err != nil {
		// crontab 上删不掉时**不继续删配置**：留一条能对得上号的
		// 记录，用户还能在计划任务页看到并手工处理。
		// 反过来（先删配置）会留下一条指向不存在任务的行，
		// 它每天都会失败一次，而面板上再也找不到它。
		return nil, err
	}
	if err := m.store.Mutate(func(d *storeData) error {
		kept := make([]*Task, 0, len(d.Tasks))
		for _, t := range d.Tasks {
			if t.ID != id {
				kept = append(kept, t)
			}
		}
		d.Tasks = kept
		return nil
	}); err != nil {
		return nil, err
	}
	return target, nil
}

// checkExpectedTasks 校验客户端提交的 id 集合与现状一致（乐观并发）。
//
// 空集合表示不做断言（curl 直连、脚本调用），此时仍然安全：
// 改写基于刚读到的内容，只是可能覆盖别人同时做的改动。
// 前端一律带上集合，因为"面板上看着在、其实已被别人删掉"
// 是最容易让用户困惑的失败。
func checkExpectedTasks(current []*Task, expected []string) error {
	if len(expected) == 0 {
		return nil
	}
	have := make(map[string]bool, len(current))
	for _, t := range current {
		have[t.ID] = true
	}
	want := make(map[string]bool, len(expected))
	for _, id := range expected {
		if !taskIDRe.MatchString(id) {
			continue // 非法形态的 id 不参与比对（防御性）
		}
		want[id] = true
	}
	for id := range have {
		if !want[id] {
			return &ErrEditConflictDetail{ID: id, Current: false}
		}
	}
	for id := range want {
		if !have[id] {
			return &ErrEditConflictDetail{ID: id, Current: true}
		}
	}
	return nil
}

// ErrEditConflictDetail 说明冲突的具体形态。
type ErrEditConflictDetail struct {
	// ID 是发生冲突的任务 id。
	ID string
	// Current 表示这条任务是"你以为有、其实没有"（true）
	// 还是"你以为没有、其实有"（false）。
	Current bool
}

func (e *ErrEditConflictDetail) Error() string {
	if e.Current {
		return fmt.Sprintf("backup: 任务 %s 已被外部删除或从未存在，"+
			"请刷新列表后重试（**不要重复提交**）", e.ID)
	}
	return fmt.Sprintf("backup: 存在你未看到的新任务 %s（可能是别处刚创建的），"+
		"请刷新列表后重试（**不要重复提交**）", e.ID)
}

// Is 让 ErrEditConflictDetail 能被 errors.Is(ErrEditConflict) 命中。
func (e *ErrEditConflictDetail) Is(target error) bool {
	return target == ErrEditConflict
}

// ---------------------------------------------------------------------------
// 存储配置 CRUD
// ---------------------------------------------------------------------------

// ListStorages 返回存储配置（**凭证已脱敏**）。
//
// 这是接口层唯一能拿到存储列表的入口，且它返回的就已经是脱敏副本——
// 把脱敏的责任放在这里而不是 handler 里，是因为 handler 有十几个，
// 而"忘了调用 Redacted()"只需要发生一次。
func (m *Manager) ListStorages() ([]*Storage, error) {
	list, err := m.store.Storages()
	if err != nil {
		return nil, err
	}
	out := make([]*Storage, 0, len(list))
	for _, st := range list {
		red := st.Redacted()
		out = append(out, &red)
	}
	return out, nil
}

// FindTaskByID 按 id 查任务（不存在返回 nil, nil）。
//
// 与 GetTask 的区别：GetTask 会做派生字段计算与存储探测，
// 那是给**界面**用的；这里是给执行路径与子进程用的，
// 它们只要任务定义本身。
func (m *Manager) FindTaskByID(id string) (*Task, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	return m.store.FindTask(id)
}

// RawStorages 返回**含凭证**的存储配置列表。
//
// 名字里的 Raw 是刻意的警告：它返回的东西**不能直接序列化给前端**。
// 接口层需要它来回答"这个存储到底设没设密钥"（脱敏副本里
// 凭证已被清空，对副本调 HasSecret() 永远返回 false），
// 以及"测试连通性时用已保存的密钥"。
// 任何把它直接写进响应的代码都是 bug。
func (m *Manager) RawStorages() ([]*Storage, error) {
	return m.store.Storages()
}

// FindStorageRaw 返回**含凭证**的存储配置（仅供执行路径内部使用）。
func (m *Manager) FindStorageRaw(id string) (*Storage, error) {
	return m.store.FindStorage(id)
}

// CreateStorage 新增存储配置。
func (m *Manager) CreateStorage(in StorageInput) (*Storage, error) {
	norm, err := ValidateStorage(in)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id, err := NewID()
	if err != nil {
		return nil, err
	}
	now := m.now()
	st := &Storage{
		ID:                 id,
		Name:               norm.Name,
		Type:               norm.Type,
		Path:               norm.Path,
		Endpoint:           norm.Endpoint,
		Bucket:             norm.Bucket,
		Region:             norm.Region,
		AccessKey:          norm.AccessKey,
		PathStyle:          norm.PathStyle,
		BasePath:           norm.BasePath,
		Username:           norm.Username,
		InsecureSkipVerify: norm.InsecureSkipVerify,
		CreatedAt:          now.Format(time.RFC3339),
	}
	if norm.SecretKey != nil {
		st.SecretKey = *norm.SecretKey
	}
	if norm.Password != nil {
		st.Password = *norm.Password
	}
	if st.Type == StorageS3 && st.SecretKey == "" {
		return nil, invalid("secret_key", "S3 必须填写 Secret Access Key")
	}
	if st.Type == StorageWebDAV && st.Password == "" {
		return nil, invalid("password", "WebDAV 必须填写密码")
	}

	// 构造一次后端：把"配置本身不成立"（目录建不起来、地址非法）
	// 在保存的那一刻就报出来，而不是等第一次备份失败。
	if _, err := m.newBackend(*st); err != nil {
		return nil, err
	}

	if err := m.store.Mutate(func(d *storeData) error {
		d.Storages = append(d.Storages, st)
		return nil
	}); err != nil {
		return nil, err
	}
	red := st.Redacted()
	return &red, nil
}

// UpdateStorage 编辑存储配置。
//
// ########## 密钥字段的 nil 语义 ##########
//
// 接口不回显密钥，因此前端提交时密钥字段要么为空（我不改）、
// 要么是新值。若把"没传"当成"清空"，用户改一下名字就会
// 把密钥抹掉，下一次备份直接失败——这是最难排查的一类退化。
func (m *Manager) UpdateStorage(id string, in StorageInput) (*Storage, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	norm, err := ValidateStorage(in)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.store.FindStorage(id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageNotFound, id)
	}

	updated := *existing
	updated.Name = norm.Name
	updated.Type = norm.Type
	updated.Path = norm.Path
	updated.Endpoint = norm.Endpoint
	updated.Bucket = norm.Bucket
	updated.Region = norm.Region
	updated.AccessKey = norm.AccessKey
	updated.PathStyle = norm.PathStyle
	updated.BasePath = norm.BasePath
	updated.Username = norm.Username
	updated.InsecureSkipVerify = norm.InsecureSkipVerify
	updated.UpdatedAt = m.now().Format(time.RFC3339)
	// 类型切换时把上一类的凭证清掉：留着会让配置里出现
	// "看起来还配着 S3 密钥"的 WebDAV 存储。
	if existing.Type != norm.Type {
		updated.SecretKey, updated.Password = "", ""
	}
	if norm.SecretKey != nil {
		updated.SecretKey = *norm.SecretKey
	}
	if norm.Password != nil {
		updated.Password = *norm.Password
	}
	if updated.Type == StorageS3 && updated.SecretKey == "" {
		return nil, invalid("secret_key", "S3 必须填写 Secret Access Key")
	}
	if updated.Type == StorageWebDAV && updated.Password == "" {
		return nil, invalid("password", "WebDAV 必须填写密码")
	}

	if _, err := m.newBackend(updated); err != nil {
		return nil, err
	}

	if err := m.store.Mutate(func(d *storeData) error {
		for i, st := range d.Storages {
			if st.ID == id {
				d.Storages[i] = &updated
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrStorageNotFound, id)
	}); err != nil {
		return nil, err
	}
	red := updated.Redacted()
	return &red, nil
}

// DeleteStorage 删除存储配置。
//
// 被任何任务引用时拒绝（409）：默默删掉会让那些任务在下一次
// 执行时才失败，而失败的表现是"备份没了"——用户很难把
// "我上周删了一个存储配置"与"这周备份失败"联系起来。
func (m *Manager) DeleteStorage(ctx context.Context, id string, confirm bool) ([]string, error) {
	if err := ValidateTaskID(id); err != nil {
		return nil, err
	}
	if !confirm {
		return nil, ErrConfirmRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.store.FindStorage(id)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageNotFound, id)
	}
	tasks, err := m.store.Tasks()
	if err != nil {
		return nil, err
	}
	usedBy := []string{}
	for _, t := range tasks {
		if t.StorageID == id {
			usedBy = append(usedBy, t.Name)
		}
	}
	if len(usedBy) > 0 {
		return usedBy, fmt.Errorf("%w: 仍被 %d 个任务引用（%s）",
			ErrStorageInUse, len(usedBy), strings.Join(usedBy, "、"))
	}
	if err := m.store.Mutate(func(d *storeData) error {
		kept := make([]*Storage, 0, len(d.Storages))
		for _, s := range d.Storages {
			if s.ID != id {
				kept = append(kept, s)
			}
		}
		d.Storages = kept
		return nil
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

// TestStorage 对一个存储配置做连通性测试。
//
// 可以直接传一个尚未保存的配置（storages/test 接口的用法），
// 也可以传 id。未保存时密钥从输入里取（此时前端会带上）。
func (m *Manager) TestStorage(ctx context.Context, st Storage) error {
	be, err := m.newBackend(st)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	payload := []byte("lipanel connectivity probe " + m.now().UTC().Format(time.RFC3339))
	probeKey := ".lipanel-connectivity-probe"
	if err := be.Put(ctx, probeKey, strings.NewReader(string(payload)), int64(len(payload))); err != nil {
		return fmt.Errorf("写入测试对象失败（请检查目标是否存在、凭证是否有写权限）: %w", err)
	}
	if _, err := be.Stat(ctx, probeKey); err != nil {
		return fmt.Errorf("读取测试对象失败（写入似乎成功但读不回来）: %w", err)
	}
	if err := be.Delete(ctx, probeKey); err != nil {
		return fmt.Errorf("测试对象写入成功，但删除失败（请检查删除权限）: %w", err)
	}
	return nil
}

// newBackend 按存储配置构造后端（含测试注入点）。
func (m *Manager) newBackend(st Storage) (Backend, error) {
	return m.backendFor(st)
}

// backendFor 为一次执行构造后端（含测试注入点）。
func (m *Manager) backendFor(st Storage) (Backend, error) {
	opts := BackendOptions{Timeout: m.httpTimeout}
	if m.httpClientFor != nil {
		opts.HTTPClient = m.httpClientFor(st)
	}
	return NewBackend(st, opts)
}

// ---------------------------------------------------------------------------
// 源路径与恢复目标的校验
// ---------------------------------------------------------------------------

// checkSource 校验备份源路径。
func (m *Manager) checkSource(t *Task) (string, error) {
	if strings.TrimSpace(t.SourcePath) == "" {
		return "", invalid("source_path", "源路径为空")
	}
	real, err := m.srcResolver.ResolveExisting(t.SourcePath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	info, err := os.Lstat(real)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	if t.SourceType == SourceDir && !info.IsDir() {
		return "", fmt.Errorf("%w: %s 不是目录", ErrSourceUnavailable, real)
	}
	if t.SourceType == SourceFile && !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s 不是普通文件", ErrSourceUnavailable, real)
	}
	return real, nil
}

// validateSourceForSave 在**保存任务时**校验源路径。
//
// ########## 为什么保存时就要校验，而不是等执行 ##########
//
// 只在执行时校验的话，用户可以把 `/etc`、`/root` 这类白名单外的路径
// 保存成一条"看起来正常"的备份任务。此后：
//   · 列表里它显示得好好的，没有任何异常标记；
//   · 直到第一次执行才发现失败，而那时可能已经过了几天；
//   · 用户以为自己有备份，实际上一天都没备份过。
//
// 备份这类功能的失败周期以天/月计，必须**在用户还在屏幕前时**
// 就把问题说出来。这条规则与"存储必须存在"是同一个道理。
//
// 注意：这里只校验**能不能访问**与**类型对不对**，不要求它现在
// 一定有内容。空目录也是合法的备份源。
func (m *Manager) validateSourceForSave(norm TaskInput) error {
	real, err := m.srcResolver.ResolveExisting(norm.SourcePath)
	if err != nil {
		return invalid("source_path",
			"源路径不在允许备份的范围内（%v）。可用范围见「状态」接口的 source_roots", err)
	}
	info, err := os.Lstat(real)
	if err != nil {
		return invalid("source_path", "源路径不可访问：%v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// 符号链接会让"我备份的是 A"与"实际打进包的是 B"不一致。
		return invalid("source_path",
			"源路径是一个符号链接。请填它指向的真实路径——"+
				"否则你无法从任务配置上看出实际备份的是什么")
	}
	switch norm.SourceType {
	case SourceDir:
		if !info.IsDir() {
			return invalid("source_path", "任务类型是「备份目录」，但该路径不是目录")
		}
	case SourceFile:
		if !info.Mode().IsRegular() {
			return invalid("source_path", "任务类型是「备份单个文件」，但该路径不是普通文件")
		}
	}
	return nil
}

// CheckRestoreTarget 校验恢复目标目录（供接口层在预览前调用）。
//
// 它把目标目录解析到白名单之内，并**创建它**（预览时也要建：
// 用户想恢复到 /var/lib/lipanel/restore/mysql，那个目录多半还不存在，
// 而"目标目录不存在"不该是一个错误——它只是意味着没有冲突）。
func (m *Manager) CheckRestoreTarget(target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", invalid("target_dir", "请填写恢复目标目录")
	}
	if len(target) > MaxPathLen {
		return "", invalid("target_dir", "路径超过 %d 字节", MaxPathLen)
	}
	if strings.ContainsRune(target, 0) {
		return "", invalid("target_dir", "路径含 NUL 字节")
	}
	if !filepath.IsAbs(target) {
		return "", invalid("target_dir", "恢复目标必须是绝对路径（以 / 开头）")
	}
	// 先解析已被允许的祖先（目标可能还不存在），再创建，
	// 最后做一次完整解析确认它确实落在白名单内。
	if _, err := m.rstResolver.ResolveForCreate(target); err != nil {
		return "", invalid("target_dir", "目标目录不在允许恢复的范围内：%v", err)
	}
	if err := os.MkdirAll(target, storeDirMode); err != nil {
		return "", fmt.Errorf("backup: 创建恢复目标目录失败: %w", err)
	}
	real, err := m.rstResolver.ResolveExisting(target)
	if err != nil {
		return "", invalid("target_dir", "目标目录校验失败：%v", err)
	}
	return real, nil
}

// ---------------------------------------------------------------------------
// 执行
// ---------------------------------------------------------------------------

// RunResult 是一次执行的结果（供接口层返回）。
type RunResult struct {
	Entry *HistoryEntry `json:"entry"`
	// Skipped 表示因为已有一次执行在进行而跳过。
	Skipped bool `json:"skipped"`
}

// RunNow 立即执行一次备份（面板本体的入口）。
//
// user 只用于审计与历史（谁点的按钮）。
func (m *Manager) RunNow(ctx context.Context, taskID, user string) (*RunResult, error) {
	if err := ValidateTaskID(taskID); err != nil {
		return nil, err
	}
	task, err := m.store.FindTask(taskID)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, fmt.Errorf("%w: %s", ErrTaskNotFound, taskID)
	}
	entry, err := m.Execute(ctx, task, TriggerManual, user)
	if err != nil {
		if errors.Is(err, ErrRunning) {
			return &RunResult{Skipped: true}, nil
		}
		return nil, err
	}
	return &RunResult{Entry: entry, Skipped: entry.Status == StatusSkipped}, nil
}

// Execute 执行一次备份（**唯一一份实现**）。
//
// 它自己负责写历史与锁：调用方（面板接口 / cron 子进程）不需要
// 知道这些细节，也就不会出现"某条路径忘了写历史"。
//
// 返回的 error 只用于"任务根本没法开始"（找不到存储、取不到锁之外的
// 内部错误）；备份本身的失败已经写进返回的 HistoryEntry 里
// （Status=failed + Error），因为那是一次**有记录的执行**，
// 而不是一次"调用失败"。
func (m *Manager) Execute(ctx context.Context, task *Task, trigger, user string) (*HistoryEntry, error) {
	if task == nil {
		return nil, errors.New("backup: 任务为空")
	}
	// 整条链路共用一个超时预算（见文件头说明）。
	runCtx, cancel := context.WithTimeout(ctx, m.execTimeout)
	defer cancel()

	locked, release, err := m.TryLock(task.ID, trigger)
	if err != nil {
		return nil, err
	}
	if !locked {
		entry := m.newEntry(task, trigger, user)
		entry.Status = StatusSkipped
		entry.FinishedAt = m.now().Format(time.RFC3339)
		entry.Error = "该任务已有一次执行正在进行，本次已跳过（避免两次执行互相覆盖同一份备份）"
		_ = m.AppendHistory(entry)
		return entry, nil
	}
	defer release()

	entry := m.newEntry(task, trigger, user)
	start := m.now()
	entry.StartedAt = start.Format(time.RFC3339)

	// 立刻写一条 running 记录：备份可能跑几十分钟，中途进程被 kill
	// 时，用户需要看到"它开始过"，而不是一片空白。
	if err := m.AppendHistory(entry); err != nil {
		m.logger.Warn("写入开始记录失败（不影响备份）", "task", task.ID, "err", err)
	}

	res, execErr := m.runBackup(runCtx, task, entry)

	entry.FinishedAt = m.now().Format(time.RFC3339)
	entry.DurationMS = time.Since(start).Milliseconds()
	if execErr != nil {
		entry.Status = StatusFailed
		entry.Error = trimErr(execErr)
	} else {
		entry.Status = StatusOK
		entry.Error = ""
		entry.ArchiveKey = res.key
		entry.ArchiveBytes = res.bytes
		entry.FileCount = res.files
		entry.TotalBytes = res.totalBytes
		entry.Skipped = res.skipped
		entry.Warnings = res.warnings
		entry.Pruned = res.pruned
		entry.PruneErrors = res.pruneErrors
	}
	if err := m.AppendHistory(entry); err != nil {
		m.logger.Warn("写入完成记录失败（备份本身已按上述状态完成）",
			"task", task.ID, "status", entry.Status, "err", err)
	}
	// 历史截断尽力而为：它失败不该让一次成功的备份被标成失败。
	if err := m.pruneHistory(task.ID); err != nil {
		m.logger.Warn("截断历史文件失败", "task", task.ID, "err", err)
	}
	return entry, nil
}

// newEntry 构造一条历史记录。
func (m *Manager) newEntry(task *Task, trigger, user string) *HistoryEntry {
	id, err := NewID()
	if err != nil {
		id = fmt.Sprintf("%012x", m.now().UnixNano()&0xffffffffffff)
	}
	return &HistoryEntry{
		ID:          id,
		TaskID:      task.ID,
		TaskName:    task.Name,
		Trigger:     trigger,
		Status:      StatusRunning,
		StorageID:   task.StorageID,
		StartedAt:   m.now().Format(time.RFC3339),
		User:        user,
		Warnings:    []string{},
		PruneErrors: []string{},
	}
}

// backupOutcome 是执行成功后的产出描述。
type backupOutcome struct {
	key         string
	bytes       int64
	files       int
	totalBytes  int64
	skipped     int
	warnings    []string
	pruned      int
	pruneErrors []string
}

// runBackup 是执行的主体（打包 → 上传 → 清理）。
func (m *Manager) runBackup(ctx context.Context, task *Task, entry *HistoryEntry) (*backupOutcome, error) {
	st, err := m.store.FindStorage(task.StorageID)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("目标存储配置不存在（可能已被删除），请重新选择存储")
	}
	entry.StorageType = st.Type

	be, err := m.backendFor(*st)
	if err != nil {
		return nil, err
	}
	defer func() { _ = be.Close() }()

	src, err := m.checkSource(task)
	if err != nil {
		return nil, err
	}

	// staging 文件名用任务 id 而不是任务名：任务名可能含空格、
	// 中文、斜杠，用它做文件名会立刻踩到路径问题。
	stagingPath := filepath.Join(m.stagingDir,
		fmt.Sprintf("%s-%s.tar.gz", task.ID, m.now().Format("20060102-150405")))
	defer func() {
		// 无论成功失败都清理 staging：留下来只会安静地吃磁盘。
		if rmErr := os.Remove(stagingPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			m.logger.Warn("清理打包中间文件失败", "path", stagingPath, "err", rmErr)
		}
	}()

	arc, err := CreateArchive(ctx, src, stagingPath, ArchiveOptions{
		MaxBytes:   m.maxSource,
		MaxEntries: m.maxEntries,
	})
	if err != nil {
		return nil, err
	}
	entry.Warnings = append(entry.Warnings, arc.Warnings...)
	entry.Skipped = arc.Skipped
	entry.FileCount = arc.FileCount
	entry.TotalBytes = arc.TotalBytes

	if arc.Bytes > m.maxArchive {
		return nil, fmt.Errorf("%w: 归档体积 %s 超过上限 %s（请收窄源路径或提高 -backup-max-bytes）",
			ErrTooLarge, humanBytes(arc.Bytes), humanBytes(m.maxArchive))
	}

	key := ArchiveKeyFor(task, m.now())
	f, err := os.Open(stagingPath)
	if err != nil {
		return nil, fmt.Errorf("backup: 打开归档文件失败: %w", err)
	}
	putErr := be.Put(ctx, key, f, arc.Bytes)
	_ = f.Close()
	if putErr != nil {
		return nil, fmt.Errorf("上传到 %s 失败: %w", st.Type, putErr)
	}

	out := &backupOutcome{
		key: key, bytes: arc.Bytes, files: arc.FileCount,
		totalBytes: arc.TotalBytes, skipped: arc.Skipped,
		warnings: arc.Warnings,
	}

	// 保留策略：清理失败**不影响备份成功**（刚做完的这份是好端端的），
	// 但必须如实报告——不报的话磁盘会安静地涨到满。
	if ret, rerr := ApplyRetention(ctx, be, task, m.now()); rerr != nil {
		out.pruneErrors = append(out.pruneErrors,
			fmt.Sprintf("保留策略未执行：%v", rerr))
		m.logger.Warn("保留策略未执行", "task", task.ID, "err", rerr)
	} else {
		out.pruned = ret.Deleted
		out.pruneErrors = append(out.pruneErrors, ret.Errors...)
		if len(ret.Errors) > 0 {
			m.logger.Warn("部分旧备份清理失败", "task", task.ID, "failed", len(ret.Errors))
		}
	}
	return out, nil
}
