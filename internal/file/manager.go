package file

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// ============================================================================
// 文件管理核心（阶段四 4.2，核心自带）
// ============================================================================
//
// 本文件实现全部文件操作。两条贯穿始终的纪律：
//
//  1. **任何文件系统调用都必须使用 Resolver 返回的真实路径**。
//     绝不把用户传来的字符串直接交给 os.*——"校验用一个路径、操作用另一个路径"
//     是路径校验里最经典、也最致命的写法。
//  2. **每一次失败都要能被翻译成有意义的 HTTP 状态码**。
//     计划明确要求写操作有明确的错误处理（不存在、权限不足、磁盘满……）。
//     因此这里统一用 os/filepath/io 的标准错误做包装，由 server 层用
//     errors.Is 翻译；绝不在这一层把错误吞掉或换成字符串。
//
// 权限位的保留、原子写入、大小上限等细节见各方法注释——它们不是"顺手加的"，
// 每一条都对应一类真实事故（写入一半就断电、上传把可执行文件变成 0600 等）。

// 默认限制。所有限制都可以通过 ManagerOptions 覆盖。
const (
	// DefaultMaxUploadBytes 是单次上传的大小上限（128 MiB）。
	//
	// 为什么要有上限：面板以 root 运行，没有上限意味着一次请求就能
	// 把服务器磁盘写满（典型后果是整个系统不可用，而不只是面板挂了）。
	DefaultMaxUploadBytes = 128 << 20
	// DefaultMaxEditBytes 是内置文本编辑器能打开的最大文件（2 MiB）。
	//
	// 这不是磁盘限制而是**交互限制**：几 MB 的文本塞进浏览器文本域会卡死页面。
	// 更大的文件应当用下载 + 本地编辑器 + 上传，这是刻意的产品取舍。
	DefaultMaxEditBytes = 2 << 20
	// DefaultMaxListEntries 是单次列目录返回的最大条目数。
	DefaultMaxListEntries = 5000
	// maxEditPathBytes 是路径字符串长度上限（防御性）。
	maxPathBytes = 4096
	// dirReadChunk 是 os.ReadDir 无法流式读取时的兜底粒度（保留语义清晰）。
	dirReadChunk = 1024
)

// ManagerOptions 是构造 Manager 的配置。
type ManagerOptions struct {
	// Roots 是允许操作的根目录（绝对路径），至少一个。
	Roots []string
	// MaxUploadBytes 是单次上传上限；<=0 时用 DefaultMaxUploadBytes。
	MaxUploadBytes int64
	// MaxEditBytes 是文本编辑器可打开的最大字节数；<=0 时用 DefaultMaxEditBytes。
	MaxEditBytes int64
	// MaxListEntries 是列目录返回上限；<=0 时用 DefaultMaxListEntries。
	MaxListEntries int
	// Logger 为 nil 时使用 slog.Default()。
	Logger Logger
	// Auditor 为 nil 时不记审计（测试可省）。
	Auditor *Auditor
}

// Logger 是本包依赖的最小日志接口。
//
// 为什么不用 *slog.Logger 直接写死：本包需要被 internal/server 注入，
// 而测试里常用一个记录型 logger 断言"拒绝时打了日志"。
// 接口只有两个方法，实现成本极低，却让依赖面小到不可能失控。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Entry 是目录中的一个条目（列目录接口的返回单元）。
type Entry struct {
	// Name 是文件名（不含路径），前端用它拼操作请求。
	Name string `json:"name"`
	// Path 是**绝对路径**，前端直接拿它做后续操作，
	// 避免前端自己拼路径拼出 `//`、`/./` 之类的形态差异。
	Path string `json:"path"`
	// IsDir 是否为目录（符号链接指向目录时为 true，因为按真实目标展示）。
	IsDir bool `json:"is_dir"`
	// Size 是文件大小（字节）；目录为 0。
	Size int64 `json:"size"`
	// Mode 是权限位的可读形式（如 "-rw-r--r--"）。
	Mode string `json:"mode"`
	// ModTime 是修改时间（RFC3339）。
	ModTime string `json:"mod_time"`
	// Type 是展示用的类型分类：dir / file / symlink / other。
	// symlink 是**独立类别**：用户必须一眼看出哪个条目是链接，
	// 否则"目录里莫名其妙出现一个能进却不在根内的入口"会难以排查。
	Type string `json:"type"`
	// Target 是符号链接指向的原始内容（非链接为空），用于界面提示。
	Target string `json:"target,omitempty"`
	// Editable 表示可否用内置编辑器打开（普通文件且不超过 MaxEditBytes）。
	Editable bool `json:"editable"`
	// Broken 表示符号链接已失效（指向的目标不存在）。
	Broken bool `json:"broken,omitempty"`
}

// DirListing 是一次列目录的结果。
type DirListing struct {
	// Path 是请求的目录绝对路径。
	Path string `json:"path"`
	// Parent 是上级目录；已到根目录时为**空字符串**（前端据此禁用"上级"按钮）。
	//
	// 不返回根目录之外的值：若父目录已在白名单之外，
	// 前端拿到它也没用（点了必然被拒），不如明确置空。
	Parent string `json:"parent"`
	// Root 是命中的白名单根目录。
	Root string `json:"root"`
	// Entries 是目录内容，已排序（目录优先，再按名称）。
	Entries []Entry `json:"entries"`
	// Total 是目录中的条目总数（可能大于 len(Entries)，见 Truncated）。
	Total int `json:"total"`
	// Truncated 表示因条数上限被截断。
	Truncated bool `json:"truncated"`
	// MaxListEntries 是生效的上限，便于前端解释 Truncated。
	MaxListEntries int `json:"max_list_entries"`
}

// FileContent 是读取文本文件的结果。
type FileContent struct {
	Path string `json:"path"`
	// Content 是文件内容（UTF-8 文本）。
	Content string `json:"content"`
	// Size / ModTime / Mode 供编辑页展示"正在改的是哪个版本"。
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	Mode    string `json:"mode"`
	// MaxEditBytes 是生效的上限，前端据此提示"太大请用下载"。
	MaxEditBytes int64 `json:"max_edit_bytes"`
}

// WriteResult 是写入文件的结果。
type WriteResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Created 表示是新建而非覆盖，便于前端给出不同文案。
	Created bool `json:"created"`
	// Mode 是写入后的权限位。
	Mode string `json:"mode"`
}

// Manager 提供受限目录内的文件操作。
//
// 所有方法都**不接受未经校验的路径**：它们内部第一件事就是调用 resolver，
// 调用方（server 层）无法"忘记校验"——这正是把 Resolver 嵌进 Manager
// 而不是让 server 层自己调的原因。
type Manager struct {
	resolver       *Resolver
	maxUploadBytes int64
	maxEditBytes   int64
	maxListEntries int
	logger         Logger
	auditor        *Auditor
}

// NewManager 构造文件管理器。
func NewManager(opts ManagerOptions) (*Manager, error) {
	resolver, err := NewResolver(opts.Roots)
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger{}
	}
	m := &Manager{
		resolver:       resolver,
		maxUploadBytes: opts.MaxUploadBytes,
		maxEditBytes:   opts.MaxEditBytes,
		maxListEntries: opts.MaxListEntries,
		logger:         logger,
		auditor:        opts.Auditor,
	}
	if m.maxUploadBytes <= 0 {
		m.maxUploadBytes = DefaultMaxUploadBytes
	}
	if m.maxEditBytes <= 0 {
		m.maxEditBytes = DefaultMaxEditBytes
	}
	if m.maxListEntries <= 0 {
		m.maxListEntries = DefaultMaxListEntries
	}
	return m, nil
}

// nopLogger 在未注入 logger 时静默丢弃日志（测试便利）。
type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// Resolver 暴露解析器，供 server 层做展示用途（如列出白名单根目录）。
func (m *Manager) Resolver() *Resolver { return m.resolver }

// Auditor 暴露审计器，供 server 层记录与查询。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// Limits 是生效的各项限制，供接口返回给前端做提示。
type Limits struct {
	MaxUploadBytes int64 `json:"max_upload_bytes"`
	MaxEditBytes   int64 `json:"max_edit_bytes"`
	MaxListEntries int   `json:"max_list_entries"`
}

// Limits 返回生效的限制。
func (m *Manager) Limits() Limits {
	return Limits{
		MaxUploadBytes: m.maxUploadBytes,
		MaxEditBytes:   m.maxEditBytes,
		MaxListEntries: m.maxListEntries,
	}
}

// ============================================================================
// 路径校验的公共入口
// ============================================================================

// resolveForRead 校验一个必须存在的路径。
func (m *Manager) resolveForRead(p string) (string, error) {
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("%w: 路径过长（>%d 字节）", ErrInvalidPath, maxPathBytes)
	}
	return m.resolver.ResolveExisting(p)
}

// resolveForCreate 校验一个将被创建的路径。
func (m *Manager) resolveForCreate(p string) (string, error) {
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("%w: 路径过长（>%d 字节）", ErrInvalidPath, maxPathBytes)
	}
	return m.resolver.ResolveForCreate(p)
}

// ============================================================================
// 列目录
// ============================================================================

// List 列出目录内容。
func (m *Manager) List(p string) (*DirListing, error) {
	real, err := m.resolveForRead(p)
	if err != nil {
		return nil, err
	}

	info, err := os.Lstat(real)
	if err != nil {
		return nil, fmt.Errorf("file: 读取 %s 失败: %w", real, err)
	}
	// Lstat（而非 Stat）是有意的：这里要判断"用户请求的这个路径本身"
	// 是不是目录。用 Stat 会把符号链接当成目标，从而放行
	// "对一个指向目录的链接执行 rmdir"之类的危险操作。
	if info.Mode()&os.ModeSymlink != 0 {
		target, statErr := os.Stat(real)
		if statErr != nil {
			return nil, fmt.Errorf("%w: %s 是失效的符号链接", ErrNotDirectory, real)
		}
		if !target.IsDir() {
			return nil, fmt.Errorf("%w: %s", ErrNotDirectory, real)
		}
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotDirectory, real)
	}

	// ReadDir 一次性读取：os.ReadDir 内部按 1024 分批，
	// 因此即便目录里有十万个文件也不会一次性吃掉大量内存；
	// 真正的内存占用由下面的上限兜住。
	//
	// 注意这里用的是 real（已解析符号链接）：
	// 若用户经链接进入目录，列出的必须是**链接目标**的内容，
	// 否则会出现"列的是 A、进去是 B"的错位。
	dir, err := os.Open(real)
	if err != nil {
		return nil, fmt.Errorf("file: 打开目录 %s 失败: %w", real, err)
	}
	defer func() { _ = dir.Close() }()

	names, err := dir.Readdirnames(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("file: 读取目录 %s 失败: %w", real, err)
	}

	listing := &DirListing{
		Path:           real,
		Root:           m.rootOf(real),
		Entries:        make([]Entry, 0, min(len(names), dirReadChunk)),
		Total:          len(names),
		MaxListEntries: m.maxListEntries,
	}
	listing.Truncated = len(names) > m.maxListEntries
	if listing.Truncated {
		names = names[:m.maxListEntries]
	}

	for _, name := range names {
		entry, ok := m.entryFor(real, name)
		if !ok {
			// 单个条目取不到元数据（例如刚刚被删除、或有竞态）：
			// 跳过而不是让整个列表失败——列目录是最常用的操作，
			// 因为一个文件消失就报 500 是不可接受的。
			continue
		}
		listing.Entries = append(listing.Entries, entry)
	}

	sortEntries(listing.Entries)

	// 上级目录只在**仍在白名单内**时才给出。
	parent := filepath.Dir(real)
	if parent != real {
		if _, err := m.resolver.ResolveExisting(parent); err == nil {
			listing.Parent = parent
		}
	}
	return listing, nil
}

// entryFor 构造单个目录条目的元数据。
func (m *Manager) entryFor(dir, name string) (Entry, bool) {
	full := filepath.Join(dir, name)
	info, err := os.Lstat(full)
	if err != nil {
		return Entry{}, false
	}

	e := Entry{
		Name:    name,
		Path:    full,
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
		Type:    "other",
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		e.Type = "symlink"
		if target, err := os.Readlink(full); err == nil {
			e.Target = target
		}
		// 解析链接以决定"进得去吗、能不能编辑"。
		// 解析失败（失效链接）或解析后跑到根外，都按不可操作处理：
		// 这既是安全要求，也让界面上的表现与点下去的结果一致
		// （否则用户会看到一个能点、但点进去必然 400 的条目）。
		resolved, err := m.resolver.Resolve(full)
		if err != nil {
			e.Broken = true
			return e, true
		}
		target, err := os.Stat(resolved)
		if err != nil {
			e.Broken = true
			return e, true
		}
		e.IsDir = target.IsDir()
		if e.IsDir {
			e.Type = "symlink"
			e.Size = 0
		} else {
			e.Size = target.Size()
			e.Editable = target.Mode().IsRegular() && target.Size() <= m.maxEditBytes
		}
	case info.IsDir():
		e.IsDir = true
		e.Type = "dir"
		e.Size = 0
	case info.Mode().IsRegular():
		e.Type = "file"
		e.Editable = info.Size() <= m.maxEditBytes
	default:
		// 设备文件、FIFO、socket 等：展示出来（用户有权知道存在），
		// 但不可编辑、不可下载。
		e.Type = "other"
	}
	return e, true
}

// sortEntries 排序：目录优先，再按名称（不区分大小写，与文件管理器一致）。
//
// 不做成可配置项：面板的使用场景是"快速找到某个文件"，
// 一个稳定且符合直觉的默认顺序胜过一堆排序选项。
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.IsDir != b.IsDir {
			return a.IsDir
		}
		la, lb := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if la != lb {
			return la < lb
		}
		return a.Name < b.Name
	})
}

// rootOf 返回路径命中的白名单根目录（展示用）。
func (m *Manager) rootOf(real string) string {
	for _, root := range m.resolver.Roots() {
		if r := m.resolver.Rel(real); r != "" {
			return root.Path
		}
	}
	return ""
}

// ============================================================================
// 读取
// ============================================================================

// ReadText 读取文本文件内容。
//
// 三类拒绝（都以哨兵错误暴露，由 server 层翻译成合适的状态码）：
//   - 不是普通文件            → ErrNotRegular
//   - 超过 MaxEditBytes       → ErrTooLarge
//   - 不是合法 UTF-8 或含 NUL → ErrBinaryFile
//
// 为什么要拦二进制：面板只提供**纯文本编辑器**。若把二进制塞进文本域，
// 浏览器与 Go 的字符串转换会各自做一轮替换，用户一保存就把文件彻底毁掉
// （且不可逆）。宁可明确拒绝并提示"请下载后用本地编辑器修改"。
func (m *Manager) ReadText(p string) (*FileContent, error) {
	real, err := m.resolveForRead(p)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(real)
	if err != nil {
		return nil, fmt.Errorf("file: 打开文件 %s 失败: %w", real, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("file: 读取文件状态 %s 失败: %w", real, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, real)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s 不是普通文件", ErrNotRegular, real)
	}
	if info.Size() > m.maxEditBytes {
		return nil, fmt.Errorf("%w: 文件 %d 字节，超过可编辑上限 %d 字节",
			ErrTooLarge, info.Size(), m.maxEditBytes)
	}

	// 多读一个字节：用于识别"刚好等于上限"与"其实更大但被截断"，
	// 避免 LimitReader 静默截断导致用户保存时丢掉尾部内容。
	data, err := io.ReadAll(io.LimitReader(f, m.maxEditBytes+1))
	if err != nil {
		return nil, fmt.Errorf("file: 读取文件 %s 失败: %w", real, err)
	}
	if int64(len(data)) > m.maxEditBytes {
		return nil, fmt.Errorf("%w: 文件超过可编辑上限 %d 字节", ErrTooLarge, m.maxEditBytes)
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: %s 不是 UTF-8 文本文件", ErrBinaryFile, real)
	}

	return &FileContent{
		Path:         real,
		Content:      string(data),
		Size:         info.Size(),
		ModTime:      info.ModTime().Format(time.RFC3339),
		Mode:         info.Mode().String(),
		MaxEditBytes: m.maxEditBytes,
	}, nil
}

// OpenForDownload 校验并打开一个可下载的文件，返回句柄与元数据。
//
// 返回 *os.File 而不是读进内存：下载动辄几百 MB，
// 交给 http.ServeContent 流式发送才是正确做法（它还顺便提供了
// Range 断点续传与 If-Modified-Since 支持）。
//
// 调用方**必须**关闭返回的句柄。
func (m *Manager) OpenForDownload(p string) (*os.File, os.FileInfo, error) {
	real, err := m.resolveForRead(p)
	if err != nil {
		return nil, nil, err
	}

	// 用 os.Open（跟随符号链接）而不是 O_NOFOLLOW：
	// 链接本身已经过 Resolve 校验，指向根内即可下载——
	// 这是常见部署形态（站点目录里大量指向共享资源的链接）。
	f, err := os.Open(real)
	if err != nil {
		return nil, nil, fmt.Errorf("file: 打开文件 %s 失败: %w", real, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("file: 读取文件状态 %s 失败: %w", real, err)
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: %s 是目录，请用打包方式下载", ErrNotRegular, real)
	}
	return f, info, nil
}

// ============================================================================
// 写入
// ============================================================================

// WriteText 写入文本文件内容。
//
// overwrite 为 false 且目标已存在时返回 ErrExists（由 server 层翻译成 409）。
// 这个默认值是刻意的：面板上"保存"按钮误触的代价是覆盖别人的配置，
// 必须由用户显式确认覆盖。
//
// 写入方式：**临时文件 + fsync + rename**（与 config.Save 同一口径）。
// 直接 os.WriteFile 覆盖时，一旦写到一半进程被杀/断电，用户就得到一个
// 被截断的配置文件——对 nginx.conf 这类文件意味着服务再也起不来。
func (m *Manager) WriteText(p string, content []byte, overwrite bool) (*WriteResult, error) {
	defer wipe(content)

	if int64(len(content)) > m.maxEditBytes {
		return nil, fmt.Errorf("%w: 内容 %d 字节，超过可写上限 %d 字节",
			ErrTooLarge, len(content), m.maxEditBytes)
	}
	// 保存的是文本：含 NUL 的载荷绝大多数是前端出错或攻击尝试，
	// 一律拒绝（否则会写出一堆"看起来正常、实际是二进制"的配置文件）。
	if bytes.IndexByte(content, 0) >= 0 {
		return nil, fmt.Errorf("%w: 内容含 NUL 字节，拒绝写为文本", ErrBinaryFile)
	}

	real, err := m.resolveForCreate(p)
	if err != nil {
		return nil, err
	}

	// 目标若已存在，必须是**普通文件**：不允许通过保存接口
	// 覆盖目录、设备文件或（指向别处的）符号链接。
	// 注意这里必须用 Lstat：Stat 会跟随符号链接，从而把
	// "覆盖链接"悄悄变成"覆盖链接指向的文件"。
	existed := false
	var keepMode os.FileMode
	if info, statErr := os.Lstat(real); statErr == nil {
		existed = true
		if info.Mode()&os.ModeSymlink != 0 {
			// 链接本身不覆盖，但若它指向根内的普通文件，允许写入目标。
			target, _, resolveErr := m.statFollowing(real)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if !target.Mode().IsRegular() {
				return nil, fmt.Errorf("%w: %s 指向的不是普通文件", ErrNotRegular, real)
			}
			keepMode = target.Mode().Perm()
		} else {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%w: %s 不是普通文件", ErrNotRegular, real)
			}
			keepMode = info.Mode().Perm()
		}
		if !overwrite {
			return nil, fmt.Errorf("%w: %s", ErrExists, real)
		}
	}

	if err := m.atomicWrite(real, content, keepMode); err != nil {
		return nil, err
	}

	final := int64(len(content))
	mode := keepMode
	if !existed {
		mode = 0o644
	}
	return &WriteResult{
		Path:    real,
		Size:    final,
		Created: !existed,
		Mode:    fs.FileMode(mode).String(),
	}, nil
}

// statFollowing 解析符号链接并返回目标的 FileInfo。
func (m *Manager) statFollowing(p string) (os.FileInfo, string, error) {
	resolved, err := m.resolver.Resolve(p)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("file: 读取 %s 失败: %w", resolved, err)
	}
	return info, resolved, nil
}

// atomicWrite 以「临时文件 + fsync + rename」方式写入。
//
// keepMode 为 0 时（新建）使用 0644 并按 umask 收敛：
// 上传/新建的文件不该继承 0600（用户多半要拿去给 web 服务器读），
// 也不该直接用 0666（等于把可执行位交给上传内容）。
func (m *Manager) atomicWrite(real string, content []byte, keepMode os.FileMode) error {
	dir := filepath.Dir(real)

	// 目标目录必须存在：这里**不做 MkdirAll**。
	// 自动创建父目录会让"路径打错一个字母"变成"在别处悄悄建出一棵树"，
	// 用户要的是明确的 ENOENT 提示。
	tmp, err := os.CreateTemp(dir, ".lipanel-*.tmp")
	if err != nil {
		return fmt.Errorf("file: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	mode := keepMode
	if mode == 0 {
		mode = 0o644
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: 设置文件权限失败: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: 写入临时文件失败: %w", err)
	}
	// fsync 后再 rename：保证掉电时不会出现"文件已改名、内容还在页缓存"。
	// 磁盘满（ENOSPC）通常就在这一步暴露，错误必须原样带 Wrapped 链上抛，
	// 由 server 层翻译成 507。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: 同步临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("file: 关闭临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, real); err != nil {
		return fmt.Errorf("file: 替换 %s 失败: %w", real, err)
	}
	tmpName = ""
	return nil
}

// wipe 尽力抹掉内存中的文件内容副本。
//
// 说清楚它的作用边界：Go 的 copy-on-write / GC 意味着**无法保证**
// 内存里不留残影，因此这不是"安全擦除"，只是缩短敏感内容在内存中
// 可被 heap dump 看到的窗口。写在这里是为了不让读者误以为
// "文件内容会一直留在堆上"。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ============================================================================
// 新建目录
// ============================================================================

// Mkdir 新建目录（只在已存在的父目录下创建，不递归建树）。
//
// all 参数为用户显式选择（界面上是"同时创建缺失的上级目录"勾选框）：
// 默认 false 时路径中任何一段不存在都会报 404，
// 避免用户把 /a/b/c 错打成 /a/b/c/d/e 却在别处悄悄建出一棵树。
func (m *Manager) Mkdir(p string, all bool) (*Entry, error) {
	real, err := m.resolveForCreate(p)
	if err != nil {
		return nil, err
	}
	if _, statErr := os.Lstat(real); statErr == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, real)
	}

	if all {
		if err := os.MkdirAll(real, 0o755); err != nil {
			return nil, fmt.Errorf("file: 创建目录 %s 失败: %w", real, err)
		}
	} else {
		if err := os.Mkdir(real, 0o755); err != nil {
			return nil, fmt.Errorf("file: 创建目录 %s 失败: %w", real, err)
		}
	}

	info, err := os.Lstat(real)
	if err != nil {
		return nil, fmt.Errorf("file: 读取新建目录 %s 失败: %w", real, err)
	}
	return &Entry{
		Name:    filepath.Base(real),
		Path:    real,
		IsDir:   true,
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
		Type:    "dir",
	}, nil
}

// ============================================================================
// 重命名
// ============================================================================

// Rename 把路径重命名为同一目录下的新名字。
//
// 只支持**同目录改名**（newName 是文件名，不能含路径分隔符）。
// 这与计划里"重命名"的语义一致，也把一整类边界问题挡在门外：
// 跨目录移动要处理"移进自己的子目录""跨白名单根""目标已存在"等情形，
// 每一条都是独立的边界，而它们对用户的价值远低于实现成本。
//
// 覆盖已有文件是允许的（POSIX rename 语义），但需要 overwrite 显式确认——
// 服务端不会替用户决定"要不要覆盖别人的文件"。
func (m *Manager) Rename(p, newName string, overwrite bool) (*Entry, error) {
	newName = strings.TrimSpace(newName)
	if err := validateName(newName); err != nil {
		return nil, err
	}

	src, err := m.resolveForRead(p)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(filepath.Dir(src), newName)
	if dst == src {
		// 新旧同名：直接返回当前状态，不报错。
		// 报错会让"我只想改个大小写但没改成"这类操作以失败告终，
		// 而用户的意图（文件叫这个名字）已经满足了。
		entry, ok := m.entryFor(filepath.Dir(src), newName)
		if !ok {
			return nil, fmt.Errorf("file: 读取 %s 失败: %w", src, os.ErrNotExist)
		}
		return &entry, nil
	}

	// 目标必须落在白名单内（父目录与源相同，理论上必然满足，
	// 但仍走一次校验：安全判定不做"理论上"的假设）。
	if _, err := m.resolveForCreate(dst); err != nil {
		return nil, err
	}

	if _, statErr := os.Lstat(dst); statErr == nil {
		if !overwrite {
			return nil, fmt.Errorf("%w: %s", ErrExists, dst)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("file: 检查目标 %s 失败: %w", dst, statErr)
	}

	if err := os.Rename(src, dst); err != nil {
		return nil, fmt.Errorf("file: 重命名 %s 为 %s 失败: %w", src, newName, err)
	}
	entry, ok := m.entryFor(filepath.Dir(dst), newName)
	if !ok {
		return nil, fmt.Errorf("file: 重命名成功但读取结果失败: %s", dst)
	}
	return &entry, nil
}

// validateName 校验单个文件/目录名。
//
// 拒绝的是"这个名字表达的是路径而非名字"的写法：
// 分隔符、. 与 ..、空字节。允许隐藏文件（.env）与中文、空格——
// 它们在 Linux 上完全合法，面板没有理由比内核更严格。
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: 名称不能为空", ErrInvalidPath)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: 名称不能是 %q", ErrInvalidPath, name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: 名称含 NUL 字节", ErrInvalidPath)
	}
	if strings.ContainsRune(name, '/') {
		return fmt.Errorf("%w: 名称不能包含路径分隔符 /", ErrInvalidPath)
	}
	// 用 system 分隔符再判一次：本包目前只跑在 Linux/Windows 上，
	// 在 Windows 上 '\' 同样是路径分隔符。
	if os.PathSeparator != '/' && strings.ContainsRune(name, os.PathSeparator) {
		return fmt.Errorf("%w: 名称不能包含路径分隔符 %c", ErrInvalidPath, os.PathSeparator)
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: 名称过长（>255 字节）", ErrInvalidPath)
	}
	return nil
}

// ============================================================================
// 删除
// ============================================================================

// Delete 删除文件或目录。
//
// 两道独立防线，缺一不可：
//
//  1. **非空目录必须先显式 recursive**——默认拒绝，返回 ErrNotEmpty（409）。
//     rm -rf 级别的操作不该能靠一次误点完成。
//  2. **符号链接一律只删链接本身**（os.Remove / unlinkat），绝不跟随。
//     跟随意味着"删掉 /home/www/data"可能实际删掉 /etc 里的东西，
//     即使用户有权这么做，那也不是他要删的东西。
//
// 注意这里判断类型必须用 **Lstat**：
// 用 os.Stat 会跟随链接，于是"指向 /etc/passwd 的链接"会被看成普通文件、
// "指向目录的链接"会被看成目录而走进 rmdir 分支（rmdir 对符号链接返回
// ENOTDIR，实测确认），最终表现为**用户永远删不掉一个链接**。
func (m *Manager) Delete(p string, recursive bool) error {
	// 用最短路径的解析：要删的是"路径指向的这个条目本身"，
	// 而不是它最终解析到的目标。
	//
	// 因此不能无条件调用 ResolveExisting（它会 EvalSymlinks）：
	// 对**失效链接**（指向不存在的目标）它会直接失败，而删除失效链接
	// 恰恰是用户最需要的能力——否则那些条目永远清理不掉。
	real, err := m.resolveForRemoval(p)
	if err != nil {
		return err
	}

	// 用 Lstat：要判断的是"这个路径本身"是什么。
	info, err := os.Lstat(real)
	if err != nil {
		return fmt.Errorf("file: 读取 %s 失败: %w", real, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		// 只删链接。os.Remove → unlink(2)，对符号链接就是删链接本身
		// （无论它指向文件还是目录、无论目标是否存在）。
		if err := os.Remove(real); err != nil {
			return fmt.Errorf("file: 删除符号链接 %s 失败: %w", real, err)
		}
		return nil
	}

	if info.IsDir() {
		if !recursive {
			// 先探一次是否为空：空目录可以直接删，
			// 非空目录返回 ErrNotEmpty 让前端弹出"递归删除"的二次确认。
			entries, readErr := os.ReadDir(real)
			if readErr != nil {
				return fmt.Errorf("file: 读取目录 %s 失败: %w", real, readErr)
			}
			if len(entries) > 0 {
				return fmt.Errorf("%w: %s 包含 %d 个条目", ErrNotEmpty, real, len(entries))
			}
		}
		// RemoveAll 内部先尝试 unlink、失败且为 EISDIR 才递归，
		// 因此它对路径本身的处理与上面的分支一致（不会跟随符号链接）。
		if err := os.RemoveAll(real); err != nil {
			return fmt.Errorf("file: 删除目录 %s 失败: %w", real, err)
		}
		return nil
	}

	if err := os.Remove(real); err != nil {
		return fmt.Errorf("file: 删除 %s 失败: %w", real, err)
	}
	return nil
}

// resolveForRemoval 校验一个**将被删除**的路径。
//
// 与 resolveForRead 的差别只在"失效符号链接"这一种情形：
//
//	Resolve（EvalSymlinks）遇到 link -> 不存在的目标 会失败，
//	而删除这种链接是完全合法且必要的操作。
//
// 判定规则仍然严格，不存在"因为解析不了就放行"的漏洞：
//
//   - Lstat 失败（路径真的不存在）→ 原样返回错误（上层翻译成 404）；
//   - Lstat 成功且不是符号链接 → 走完整 Resolve（词法 + 符号链接复核）；
//   - Lstat 成功且**是符号链接** → 链接本身必须落在白名单根内（词法判定），
//     且若它的目标存在，目标也必须落在白名单内。
//
// 最后一条是防"经链接删根外文件"的关键：链接指向根外时目标存在，
// 目标判定会拒绝；目标不存在时没有根外文件可删，删除链接本身是安全的。
func (m *Manager) resolveForRemoval(p string) (string, error) {
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("%w: 路径过长（>%d 字节）", ErrInvalidPath, maxPathBytes)
	}
	return m.resolver.ResolveForRemoval(p)
}

// ============================================================================
// 上传
// ============================================================================

// UploadOptions 是上传的选项。
type UploadOptions struct {
	// Path 是目标目录的**绝对路径**。
	Path string
	// Filename 是保存的文件名（客户端提供，必须经 validateName）。
	Filename string
	// Reader 是文件内容流。
	Reader io.Reader
	// Overwrite 为 false 时目标已存在即拒绝。
	Overwrite bool
	// MaxBytes 覆盖 Manager 的上限（<=0 时用 Manager 的值）。
	MaxBytes int64
}

// UploadResult 是上传结果。
type UploadResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Mode 是落盘后的权限位（固定 0644：上传的文件要能被 web 服务器读）。
	Mode string `json:"mode"`
}

// Upload 把一个流写到目标目录。
//
// ## 为什么先写临时文件、成功后再改名
//
// 上传是最容易中断的操作（网络断、用户关页面、磁盘满）。
// 直接写目标文件的话，中断会留下一个**半截文件**，
// 而它在面板上看起来与正常文件毫无区别——用户会以为上传成功了。
// 临时文件 + rename 保证目标文件要么不存在，要么完整。
//
// ## 为什么用 io.LimitReader 而不是信任 Content-Length
//
// 客户端可以谎报长度（甚至用 chunked 不报），因此真正的防线是
// 读取时的字节计数：超过上限立刻中断并删除临时文件。
// 调用方（server 层）还会再加一层 http.MaxBytesReader 兜住内存/磁盘。
func (m *Manager) Upload(opts UploadOptions) (*UploadResult, error) {
	if err := validateName(opts.Filename); err != nil {
		return nil, err
	}
	dir, err := m.resolveForRead(opts.Path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("file: 读取目录 %s 失败: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s 不是目录", ErrNotDirectory, dir)
	}

	dst, err := m.resolveForCreate(filepath.Join(dir, opts.Filename))
	if err != nil {
		return nil, err
	}

	limit := opts.MaxBytes
	if limit <= 0 {
		limit = m.maxUploadBytes
	}

	if _, statErr := os.Lstat(dst); statErr == nil {
		if !opts.Overwrite {
			return nil, fmt.Errorf("%w: %s", ErrExists, dst)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("file: 检查目标 %s 失败: %w", dst, statErr)
	}

	tmp, err := os.CreateTemp(dir, ".lipanel-upload-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("file: 创建上传临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	// 上传文件的权限固定 0644：既让 web 服务器读得到，
	// 又不把可执行位交给上传内容（用户真要执行，自己 chmod 更明确）。
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return nil, fmt.Errorf("file: 设置上传文件权限失败: %w", err)
	}

	written, err := io.Copy(tmp, io.LimitReader(opts.Reader, limit+1))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("file: 写入上传内容失败: %w", err)
	}
	if written > limit {
		cleanup()
		return nil, fmt.Errorf("%w: 上传内容超过上限 %d 字节", ErrTooLarge, limit)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		// ENOSPC（磁盘满）通常在这里暴露。
		return nil, fmt.Errorf("file: 同步上传文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, fmt.Errorf("file: 关闭上传临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return nil, fmt.Errorf("file: 保存上传文件到 %s 失败: %w", dst, err)
	}

	return &UploadResult{Path: dst, Size: written, Mode: "-rw-r--r--"}, nil
}

// ============================================================================
// 错误分类辅助
// ============================================================================

// 文件操作的哨兵错误。server 层用 errors.Is 把它们翻译成 HTTP 状态码。
var (
	// ErrNotDirectory 表示目标不是目录（列目录、上传目标处）。
	ErrNotDirectory = errors.New("file: 目标不是目录")
	// ErrNotRegular 表示目标不是普通文件（读、编辑、下载处）。
	ErrNotRegular = errors.New("file: 目标不是普通文件")
	// ErrExists 表示目标已存在且未允许覆盖。
	ErrExists = errors.New("file: 目标已存在")
	// ErrNotEmpty 表示目录非空且未允许递归删除。
	ErrNotEmpty = errors.New("file: 目录非空")
	// ErrTooLarge 表示内容超过配置的上限。
	ErrTooLarge = errors.New("file: 内容超过大小上限")
	// ErrBinaryFile 表示目标不是可处理的 UTF-8 文本。
	ErrBinaryFile = errors.New("file: 不是 UTF-8 文本文件")
	// ErrDiskFull 表示磁盘空间不足（由 ENOSPC 归一化而来）。
	ErrDiskFull = errors.New("file: 磁盘空间不足")
)

// ClassifyError 把底层错误归一化，供 server 层决定状态码与提示文案。
//
// 单独一个函数而不是让 server 层自己 switch 一串 errors.Is：
// 状态码映射是"这个模块的错误语义如何对外表达"的一部分，
// 它应当与错误的产生地放在一起，否则新增一类错误时极易漏改。
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}
	// ENOSPC：磁盘满。这是运维最需要立刻知道的一类失败，
	// 单独识别出来以便给出"清理磁盘"的可操作提示（507）。
	if errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("%w: %v", ErrDiskFull, err)
	}
	// EDQUOT：磁盘配额用尽，症状与 ENOSPC 相同。
	if errors.Is(err, syscall.EDQUOT) {
		return fmt.Errorf("%w: %v", ErrDiskFull, err)
	}
	return err
}
