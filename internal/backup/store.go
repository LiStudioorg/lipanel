package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// ============================================================================
// 配置持久化（阶段五 5.3）
// ============================================================================
//
// ########## 为什么是一个 JSON 文件而不是一个数据库 ##########
//
// 本模块的配置规模是个位数的任务与个位数的存储，与 4.5 的软件商店、
// 5.2 的计划任务同一量级。JSON 文件的好处是：可以直接看、可以直接改、
// 备份/迁移就是复制一个文件——这正是一个"帮你做备份"的模块应有的样子。
//
// ########## 写入纪律 ##########
//
// 写配置走「tmp + fsync + rename」原子替换，权限 0600、目录 0700。
// 非原子写在这里的后果不是"数据丢了"这么简单：进程在写到一半时被
// 杀掉会留下一个**半截的 JSON**，下次启动直接解析失败——
// 用户所有的备份任务配置一起消失，而备份恰恰是他最不想丢的东西。
//
// 启动时解析失败的处置同样是刻意的：**明确报错，绝不静默重置为空**。
// 静默重置会让用户对着一个空列表以为"任务被删了"，
// 而他真正的配置其实还在那个文件里（只是我们不愿意说）。

// storeFileMode 是配置文件权限：只有属主可读写。
const storeFileMode os.FileMode = 0o600

// storeDirMode 是数据目录权限。
const storeDirMode os.FileMode = 0o700

// storeData 是配置文件的内存镜像（也是落盘格式）。
type storeData struct {
	// Version 是格式版本，为将来的迁移留出判据。
	Version int `json:"version"`
	// Tasks 是备份任务。
	Tasks []*Task `json:"tasks"`
	// Storages 是存储配置（**含明文凭证**，见 Storage 的说明）。
	Storages []*Storage `json:"storages"`
}

// storeVersion 是当前格式版本。
const storeVersion = 1

// Store 是配置的读写实现。
//
// 它把「读-改-写」整条路径放在自己的锁里，而不是把锁交给 Manager：
// 配置文件是**唯一**的真相来源，任何绕过它的写都会造成两份互相
// 矛盾的视图（面板显示任务 A 在，而 crontab 上挂着另一个版本）。
type Store struct {
	path   string
	logger *slog.Logger

	mu sync.Mutex
	// data 是内存镜像；为 nil 表示尚未加载。
	data *storeData
}

// NewStore 构造配置存储。
//
// 目录会在这里创建（不等到第一次写）：一个建不起来的目录
// （只读文件系统、权限不足）应该在启动阶段就报出来，
// 而不是等用户填完一整个表单点保存才失败。
func NewStore(path string, logger *slog.Logger) (*Store, error) {
	if path == "" {
		return nil, errors.New("backup: 配置文件路径不能为空")
	}
	if logger == nil {
		logger = slog.Default()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析配置文件路径失败: %w", err)
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, storeDirMode); err != nil {
		return nil, fmt.Errorf("backup: 创建数据目录 %s 失败: %w", dir, err)
	}
	return &Store{path: abs, logger: logger}, nil
}

// Path 返回配置文件绝对路径。
func (s *Store) Path() string { return s.path }

// Load 读取并缓存配置。
//
// 文件不存在**不是错误**（首次启动），返回空配置。
// 文件存在但解析失败是错误——且错误信息里带上路径与原始原因，
// 因为此时用户唯一能做的就是去看那个文件。
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.data = &storeData{Version: storeVersion, Tasks: []*Task{}, Storages: []*Storage{}}
			return nil
		}
		return fmt.Errorf("backup: 读取配置文件 %s 失败: %w", s.path, err)
	}
	if len(raw) == 0 {
		// 空文件按"没有配置"处理：手工 touch 出来的文件就是这样。
		s.data = &storeData{Version: storeVersion, Tasks: []*Task{}, Storages: []*Storage{}}
		return nil
	}
	var data storeData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf(
			"backup: 解析配置文件 %s 失败（请修复该文件后重启，面板不会自动重置它）: %w",
			s.path, err)
	}
	s.normalize(&data)
	s.data = &data
	return nil
}

// normalize 补齐缺省值，保证内存镜像里没有 nil 切片。
//
// 落盘格式是给人看的，"tasks": null 与 "tasks": [] 对用户是噪声差异，
// 但对代码是崩溃与不崩溃的差别（range nil 可以，写回时却会变成 null）。
func (s *Store) normalize(d *storeData) {
	if d.Version == 0 {
		d.Version = storeVersion
	}
	if d.Tasks == nil {
		d.Tasks = []*Task{}
	}
	if d.Storages == nil {
		d.Storages = []*Storage{}
	}
	d.Tasks = filterNilTasks(d.Tasks)
	d.Storages = filterNilStorages(d.Storages)
}

func filterNilTasks(in []*Task) []*Task {
	out := make([]*Task, 0, len(in))
	for _, t := range in {
		if t != nil {
			out = append(out, t)
		}
	}
	return out
}

func filterNilStorages(in []*Storage) []*Storage {
	out := make([]*Storage, 0, len(in))
	for _, st := range in {
		if st != nil {
			out = append(out, st)
		}
	}
	return out
}

// ensureLoaded 保证内存镜像存在（首次调用时惰性加载）。
func (s *Store) ensureLoaded() error {
	if s.data != nil {
		return nil
	}
	return s.loadLocked()
}

// Tasks 返回任务的副本（按名称排序，便于 UI 稳定展示）。
func (s *Store) Tasks() ([]*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}
	out := make([]*Task, 0, len(s.data.Tasks))
	for _, t := range s.data.Tasks {
		cp := *t
		out = append(out, &cp)
	}
	sortTasks(out)
	return out, nil
}

// Storages 返回存储配置的副本。
//
// 返回副本而不是内部指针：调用方（接口层）会把它脱敏后直接
// 序列化出去，若给的是同一个对象，"脱敏"就变成了"就地改写内部状态"——
// 一次列表请求会把内存里的凭证清空，下一次备份直接失败。
func (s *Store) Storages() ([]*Storage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}
	out := make([]*Storage, 0, len(s.data.Storages))
	for _, st := range s.data.Storages {
		cp := *st
		out = append(out, &cp)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// FindTask 按 id 查任务（不存在返回 nil, nil）。
func (s *Store) FindTask(id string) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}
	for _, t := range s.data.Tasks {
		if t.ID == id {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

// FindStorage 按 id 查存储（不存在返回 nil, nil）。
func (s *Store) FindStorage(id string) (*Storage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(); err != nil {
		return nil, err
	}
	for _, st := range s.data.Storages {
		if st.ID == id {
			cp := *st
			return &cp, nil
		}
	}
	return nil, nil
}

// Mutate 在锁内执行一次「读-改-写」，成功后原子落盘。
//
// fn 收到的 data 是**内存镜像本身**（不是副本）：它要在锁内直接改。
// 改完之后本方法负责规范化与落盘；落盘失败会把内存镜像回滚成
// 改动前的样子——否则会出现「磁盘上没写成功、内存里却生效了」，
// 面板显示任务存在而重启后它消失，这是最难排查的一类故障。
func (s *Store) Mutate(fn func(d *storeData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(); err != nil {
		return err
	}
	before := s.data
	// 深拷贝一份作为"改前快照"：fn 直接改 s.data，
	// 没有快照就没法在落盘失败时回滚。
	working := cloneStoreData(s.data)

	if err := fn(working); err != nil {
		return err
	}
	s.normalize(working)
	if err := s.writeLocked(working); err != nil {
		s.data = before
		return err
	}
	s.data = working
	return nil
}

// writeLocked 原子写出配置（调用方必须持有锁）。
func (s *Store) writeLocked(d *storeData) error {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: 序列化配置失败: %w", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".tasks-*.tmp")
	if err != nil {
		return fmt.Errorf("backup: 创建临时配置文件失败: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if err := writeAllSync(tmp, raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("backup: 写入临时配置文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("backup: 关闭临时配置文件失败: %w", err)
	}
	// 先 Chmod 再 Rename：CreateTemp 默认 0600，但显式设定一次
	// 可以不依赖 umask 与实现的默认值。
	if err := os.Chmod(name, storeFileMode); err != nil {
		return fmt.Errorf("backup: 设置配置文件权限失败: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("backup: 替换配置文件 %s 失败: %w", s.path, err)
	}
	return nil
}

// writeAllSync 写全部字节并 fsync。
//
// fsync 不能省：rename 只保证"名字指向新文件"这件事是原子的，
// 不保证内容已经落盘。断电后可能出现"文件在、内容是空的"——
// 对一个存着全部备份任务配置的文件来说，这个代价不可接受。
func writeAllSync(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// cloneStoreData 深拷贝配置（用于落盘失败时回滚内存镜像）。
func cloneStoreData(d *storeData) *storeData {
	out := &storeData{Version: d.Version,
		Tasks: make([]*Task, 0, len(d.Tasks)), Storages: make([]*Storage, 0, len(d.Storages))}
	for _, t := range d.Tasks {
		if t == nil {
			continue
		}
		cp := *t
		out.Tasks = append(out.Tasks, &cp)
	}
	for _, st := range d.Storages {
		if st == nil {
			continue
		}
		cp := *st
		out.Storages = append(out.Storages, &cp)
	}
	return out
}

// sortTasks 按名称、再按 id 稳定排序。
func sortTasks(list []*Task) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}
