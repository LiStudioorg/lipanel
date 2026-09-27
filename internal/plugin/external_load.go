package plugin

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ============================================================================
// 外部插件：目录扫描与加载
// ============================================================================
//
// ########## 目录布局 ##########
//
//	<pluginDir>/
//	  ├── hello/
//	  │     ├── descriptor.json     必需：元数据
//	  │     ├── backend             可选：自带可执行文件（backend.exec 指向它）
//	  │     └── assets/             可选：前端资源（frontend.entry 指向它）
//	  │           └── plugin.js
//	  └── another-plugin/
//	        └── descriptor.json
//
// ########## 加载是"尽力而为"的 ##########
//
// 一个插件加载失败**绝不能**阻止面板启动，也不能阻止其它插件加载。
//
// 理由是实际的：用户手工往目录里丢了个写错 descriptor.json 的插件，
// 若这会导致整个面板起不来，他就失去了修复它的手段（面板本身就是
// 他管理服务器的方式）。因此扫描时逐个隔离错误——
// 失败的记入 LoadError 列表，在插件管理页展示，其余照常加载。

// LoadError 描述一个加载失败的外部插件。
//
// 保留足够的信息让用户能自己修：是哪个目录、为什么失败。
// 只记一句"加载失败"会让用户完全无从下手。
type LoadError struct {
	// Dir 是插件目录名。
	Dir string `json:"dir"`
	// Path 是出问题的文件路径（可能为空）。
	Path string `json:"path,omitempty"`
	// Reason 是失败原因（已本地化，可直接展示给用户）。
	Reason string `json:"reason"`
}

// String 便于日志输出。
func (e LoadError) String() string {
	if e.Path != "" {
		return fmt.Sprintf("%s (%s): %s", e.Dir, e.Path, e.Reason)
	}
	return fmt.Sprintf("%s: %s", e.Dir, e.Reason)
}

// LoadExternalResult 是一次目录扫描的结果汇总。
type LoadExternalResult struct {
	// Loaded 是成功加载的插件 ID（按字典序）。
	Loaded []string
	// Failed 是加载失败的插件。
	Failed []LoadError
	// Skipped 是被跳过的目录名（非目录、隐藏目录等）。
	Skipped []string
}

// LoadExternal 扫描 pluginDir 并注册全部外部插件。
//
// ########## 设计要点 ##########
//
//  1. **目录不存在不是错误**。用户可能没建这个目录（默认路径
//     /opt/lipanel/plugins 在多数机器上不存在）。返回空结果即可，
//     让面板正常启动。把"没装任何外部插件"当成错误是荒谬的。
//
//  2. **单个插件失败不影响其它插件**。每个目录独立处理，
//     失败进 Failed 列表。
//
//  3. **注册前完成全部校验**。任何字段非法都在注册之前拒绝，
//     避免在注册表里留下半残条目。
//
//  4. **ID 冲突时拒绝加载外部插件**。见 registerExternal 的说明。
func (m *Manager) LoadExternal(pluginDir string) (*LoadExternalResult, error) {
	res := &LoadExternalResult{}

	pluginDir = strings.TrimSpace(pluginDir)
	if pluginDir == "" {
		return res, nil
	}

	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 目录不存在：正常情况，不是错误。
			m.logger.Info("外部插件目录不存在，跳过扫描", "dir", pluginDir)
			return res, nil
		}
		// 其它错误（权限不足等）值得让用户知道，但不阻止启动。
		m.logger.Warn("扫描外部插件目录失败，面板其它功能不受影响",
			"dir", pluginDir, "err", err)
		res.Failed = append(res.Failed, LoadError{
			Dir:    pluginDir,
			Reason: "无法读取插件目录: " + err.Error(),
		})
		return res, nil
	}

	for _, ent := range entries {
		name := ent.Name()

		// 跳过隐藏目录与常见噪音（.DS_Store、__MACOSX 等）。
		if strings.HasPrefix(name, ".") || name == "__MACOSX" {
			res.Skipped = append(res.Skipped, name)
			continue
		}
		// 只认目录：目录里可能同时放着 README、zip 包等文件。
		if !ent.IsDir() {
			res.Skipped = append(res.Skipped, name)
			continue
		}

		dir := filepath.Join(pluginDir, name)
		id, err := m.loadOneExternal(dir, name)
		if err != nil {
			var le LoadError
			if lerr, ok := err.(*loadError); ok {
				le = LoadError{Dir: name, Path: lerr.path, Reason: lerr.reason}
			} else {
				le = LoadError{Dir: name, Reason: err.Error()}
			}
			res.Failed = append(res.Failed, le)
			// 每个失败都记 WARN：用户排查时日志是第一现场。
			m.logger.Warn("外部插件加载失败，已跳过（不影响其它插件与面板）",
				"dir", dir, "path", le.Path, "reason", le.Reason)
			continue
		}
		res.Loaded = append(res.Loaded, id)
	}

	sort.Strings(res.Loaded)
	sort.Slice(res.Failed, func(i, j int) bool { return res.Failed[i].Dir < res.Failed[j].Dir })
	sort.Strings(res.Skipped)

	if len(res.Loaded) > 0 || len(res.Failed) > 0 {
		m.logger.Info("外部插件扫描完成",
			"dir", pluginDir,
			"loaded", res.Loaded,
			"failed_count", len(res.Failed))
	}
	return res, nil
}

// loadError 携带出问题的文件路径，便于用户定位。
type loadError struct {
	path   string
	reason string
}

func (e *loadError) Error() string { return e.reason }

// loadOneExternal 加载单个外部插件目录，返回插件 ID。
func (m *Manager) loadOneExternal(dir, dirName string) (string, error) {
	// ---------- 读 descriptor.json ----------
	descPath := filepath.Join(dir, DescriptorFileName)
	if _, err := os.Stat(descPath); err != nil {
		if os.IsNotExist(err) {
			return "", &loadError{
				path: descPath,
				reason: fmt.Sprintf("目录内没有 %s。"+
					"外部插件必须在自己的目录里放一个 %s", DescriptorFileName, DescriptorFileName),
			}
		}
		return "", &loadError{path: descPath, reason: err.Error()}
	}

	desc, err := ReadExternalDescriptor(dir)
	if err != nil {
		return "", &loadError{path: descPath, reason: err.Error()}
	}

	// 记录插件根目录：前端资源与后端可执行文件都从它派生。
	// 转成绝对路径，避免后续因工作目录变化而解析到别处。
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", &loadError{path: dir, reason: err.Error()}
	}
	desc.Dir = absDir

	// ---------- 校验后端可执行文件确实存在 ----------
	if err := m.checkBackendExecutable(desc); err != nil {
		return "", &loadError{path: descPath, reason: err.Error()}
	}

	// ---------- 注册 ----------
	if err := m.registerExternal(desc); err != nil {
		return "", &loadError{path: descPath, reason: err.Error()}
	}
	return desc.ID, nil
}

// checkBackendExecutable 校验 descriptor 声明的可执行文件真实存在。
//
// ########## 为什么在加载时就检查 ##########
//
// 启动插件时才发现文件不存在，用户看到的是"点击启动 → 失败"，
// 而真正的原因（打包时忘了带上二进制）要翻日志才知道。
// 在扫描阶段就说清楚，用户能立刻发现包有问题。
func (m *Manager) checkBackendExecutable(desc *Descriptor) error {
	execRel := m.externalExecRel(desc)
	if execRel == "" {
		return nil // 前端-only 插件
	}
	full := filepath.Join(desc.Dir, filepath.FromSlash(execRel))

	// 再次确认没有跳出插件目录。
	//
	// ########## 为什么这里要**再**查一次 ##########
	//
	// ParseExternalDescriptor 已经查过一遍了。这里重查不是冗余：
	// 那是"校验声明"，这是"校验将要打开的真实路径"。
	// 两者之间隔了一个 filepath.Join，而 Join 会静默地
	// 把 .. 应用掉。在真正使用路径的地方再验证一次，
	// 是防止"校验与使用不一致"这类漏洞的通用做法。
	rel, err := filepath.Rel(desc.Dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("plugin: %s 的 backend.exec 指向插件目录之外", desc.ID)
	}

	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("plugin: %s 声明的 backend.exec %q 不存在"+
				"（打包时是否忘了带上可执行文件？）", desc.ID, execRel)
		}
		return fmt.Errorf("plugin: %s 无法访问 backend.exec %q: %v", desc.ID, execRel, err)
	}
	if info.IsDir() {
		return fmt.Errorf("plugin: %s 的 backend.exec %q 是一个目录，不是可执行文件",
			desc.ID, execRel)
	}
	// ########## 只警告不拒绝：可执行位缺失 ##########
	//
	// 从 Windows 打包、或经某些文件系统传输后，可执行位常会丢失。
	// 这确实是"启动时才会发现"的问题，但它是**可修复**的
	// （chmod +x），比"整个插件加载不进来"更友好：
	// 至少用户能看到这个插件、看到这条提示，然后去修。
	if info.Mode().Perm()&0o111 == 0 {
		m.logger.Warn("外部插件的后端文件没有可执行权限，启动前请先 chmod +x",
			"plugin", desc.ID, "path", full)
	}
	return nil
}

// externalExecRel 返回外部插件后端可执行文件的相对路径（前端-only 插件为空）。
//
// ########## 为什么重新解析而不是把 Backend 存进 Descriptor ##########
//
// Descriptor 是**对外契约**（会序列化给前端），而 backend.exec
// 是外部插件的实现细节。把它塞进 Descriptor 会让前端看到一个
// 服务器上的相对路径——没有用处，还可能被误当成可访问的 URL。
//
// 这里的"重新读取一遍 descriptor.json"看起来有点浪费，
// 但它发生在**启动插件时**（低频、人手触发），
// 换来的是契约的干净与磁盘上的声明始终是唯一事实来源。
func (m *Manager) externalExecRel(desc *Descriptor) string {
	if desc == nil || desc.Dir == "" {
		return ""
	}
	ext, err := readExternalExtras(desc.Dir)
	if err != nil {
		return ""
	}
	if ext.Backend == nil {
		return ""
	}
	return strings.TrimSpace(ext.Backend.Exec)
}

// externalExecPath 返回外部插件后端可执行文件的绝对路径。
func (m *Manager) externalExecPath(desc *Descriptor) string {
	rel := m.externalExecRel(desc)
	if rel == "" {
		return ""
	}
	return filepath.Join(desc.Dir, filepath.FromSlash(rel))
}

// externalArgs 返回外部插件后端的附加参数。
func (m *Manager) externalArgs(desc *Descriptor) []string {
	if desc == nil || desc.Dir == "" {
		return nil
	}
	ext, err := readExternalExtras(desc.Dir)
	if err != nil || ext.Backend == nil {
		return nil
	}
	return ext.Backend.Args
}

// externalAutoStartWarn 检查插件是否声明了当前不支持的 auto_start。
//
// 静默忽略是最糟的处理：用户写了 auto_start: true，
// 面板却不启动它，用户会以为插件已经在跑了。
func (m *Manager) externalAutoStartWarn(desc *Descriptor) {
	if desc == nil || desc.Dir == "" {
		return
	}
	ext, err := readExternalExtras(desc.Dir)
	if err != nil || ext.Backend == nil || !ext.Backend.AutoStart {
		return
	}
	m.logger.Warn("外部插件声明了 backend.auto_start，但当前版本**不会自动启动**"+
		"（面板以高权限运行，exec 用户上传的二进制需要管理员显式确认）。"+
		"请在插件管理页手动启动它",
		"plugin", desc.ID)
}

// readExternalExtras 重新读取外部插件的 descriptor.json，
// 取出核心需要的实现细节（backend 段）。
func readExternalExtras(dir string) (*ExternalDescriptor, error) {
	path := filepath.Join(dir, DescriptorFileName)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxDescriptorBytes {
		return nil, fmt.Errorf("plugin: %s 过大", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ext ExternalDescriptor
	if err := strictUnmarshal(data, &ext); err != nil {
		return nil, err
	}
	return &ext, nil
}

// registerExternal 把外部插件注册进注册表。
//
// ########## ID 冲突：拒绝外部插件，绝不覆盖内置插件 ##########
//
// 这条规则是**单向**的，且方向至关重要：
//
//	外部插件与内置插件同 ID   → 拒绝外部插件（本函数）
//	外部插件与外部插件同 ID   → 拒绝后加载的那个
//
// 反过来（允许外部覆盖内置）会是一个严重漏洞：
//
//	攻击者只需往 /opt/lipanel/plugins 里丢一个 ID 为 "sysinfo" 的目录，
//	就能**替换掉内置插件的后端与前端**。用户界面上的菜单名还是
//	"系统信息（插件）"（因为他看的是内置插件的注册信息），
//	但点进去跑的已经是攻击者的代码。
//
// 内置插件是编译进主程序的、经过审查的；外部插件是任意来源的。
// 二者的信任级别不同，绝不能让低信任的一方覆盖高信任的一方。
func (m *Manager) registerExternal(desc *Descriptor) error {
	if !desc.External {
		return fmt.Errorf("plugin: registerExternal 收到了非外部插件 %s", desc.ID)
	}

	// 先检查冲突，再走通用注册。
	// 之所以在这里显式检查（而不是依赖 Register 的重复检测），
	// 是为了给出**针对外部插件场景**的明确提示：
	// 用户需要知道"是内置插件占了这个名字"，而不是一句干巴巴的"已注册"。
	m.mu.RLock()
	existing, conflict := m.registry[desc.ID]
	m.mu.RUnlock()

	if conflict {
		if existing.desc.Builtin {
			return fmt.Errorf("%w: 插件 ID %q 已被**内置插件**占用。"+
				"外部插件不能覆盖内置插件（内置插件编译在主程序内、经过审查），"+
				"请改用其它 ID",
				ErrIDConflict, desc.ID)
		}
		m.logger.Warn("外部插件 ID 重复，后加载的被拒绝",
			"plugin", desc.ID, "dir", desc.Dir)
		return fmt.Errorf("%w: 插件 ID %q 已由另一个外部插件注册", ErrIDConflict, desc.ID)
	}

	if err := m.Register(*desc); err != nil {
		return err
	}

	// 注册后补一条日志说明它是外部插件，便于与内置插件区分。
	m.logger.Info("外部插件已注册",
		"plugin", desc.ID,
		"version", desc.Version,
		"dir", desc.Dir,
		"frontend_only", desc.Mode == ModeExternal)

	// auto_start 声明了但不受支持：明确告知。
	m.externalAutoStartWarn(desc)

	// 带后端的插件**注册后保持 stopped**，等管理员手动启动。
	if desc.Mode == ModeManaged {
		m.logger.Info("外部插件已就绪但**未启动**（安全策略）",
			"plugin", desc.ID,
			"hint", "请在插件管理页确认插件内容后手动启动它")
	}
	return nil
}

// ExternalDirFS 返回外部插件前端资源的文件系统。
//
// ########## 复用现有转发链，零改动 ##########
//
// 内置插件通过 AssetProvider 接口返回一个 fs.FS（go:embed），
// 核心据此把 /api/plugins/<id>/assets/* 转发出去。
//
// 外部插件的前端资源在磁盘上，用 os.DirFS 就能满足**同一个接口**：
//
//	外部插件:  os.DirFS(<dir>/assets)
//	内置插件:  go:embed 的 fs.FS
//	                ↓ 同一个 AssetProvider 接口
//	          核心的转发逻辑完全不需要知道区别
//
// 这正是把 AssetProvider 设计成 fs.FS 而不是 []byte 的价值。
func ExternalDirFS(desc *Descriptor) (fs.FS, bool) {
	if desc == nil || desc.Dir == "" {
		return nil, false
	}
	// 前端资源目录固定为插件目录下的 assets/。
	//
	// ########## 为什么固定而不是让插件自己声明目录名 ##########
	//
	// 自由声明目录名会引入第三条路径（entry 前缀、目录名、实际文件
	// 三者可能互相矛盾）。固定为 assets/ 让"插件目录长什么样"
	// 有唯一答案，打包脚本与文档都只有一种写法。
	//
	// 注意 entry 里的 /plugin-assets/<id>/ 是**对外 URL 前缀**，
	// 与磁盘上的 assets/ 是两个不同的东西，由服务器做映射。
	root := filepath.Join(desc.Dir, "assets")
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, false
	}
	return os.DirFS(root), true
}

// AssetFSFor 返回某个插件的可选前端资源文件系统。
//
// 外部插件用磁盘目录，内置插件由各自的 AssetProvider 实现提供
// （那部分通过插件进程的 /assets/ 接口转发，不在这里处理）。
func (m *Manager) AssetFSFor(id string) (fs.FS, bool) {
	m.mu.RLock()
	e, ok := m.registry[id]
	m.mu.RUnlock()
	if !ok || !e.desc.External {
		return nil, false
	}
	return ExternalDirFS(&e.desc)
}

// ExternalPlugins 返回全部外部插件的描述符（按注册顺序）。
func (m *Manager) ExternalPlugins() []Descriptor {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Descriptor, 0)
	for _, id := range m.order {
		if e, ok := m.registry[id]; ok && e.desc.External {
			out = append(out, e.desc)
		}
	}
	return out
}

// DefaultExternalDir 是外部插件的默认目录。
//
// ########## 为什么用 /opt/lipanel/plugins ##########
//
//   - /opt 是 Linux 上放"附加软件包"的惯例位置，用户对这个路径
//     有直觉（不像 /var/lib 那样需要查文档才知道是干什么的）；
//   - lipanel 自身若装在 /opt/lipanel，插件放在它下面
//     便于整目录备份与迁移；
//   - 不放在 /var/lib：那里放的是**可变状态**（数据库、缓存），
//     而插件是用户主动放进去的"资产"，性质不同。
//
// 目录不存在时静默跳过——绝大多数用户不会用外部插件，
// 因为一个不存在的目录就报警或报错是没有道理的。
const DefaultExternalDir = "/opt/lipanel/plugins"
