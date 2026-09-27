package plugin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// 插件安装（上传 zip → 解压 → 校验 → 原子落盘）
// ============================================================================
//
// ########## 安装流程的六个阶段，顺序不可调换 ##########
//
//	① 写临时文件      上传的字节流落盘（带大小上限）
//	② 解压到暂存目录  在**目标目录内**，防跨设备 rename
//	③ 校验 descriptor 全部字段校验（ID / 版本 / 权限 / 路径）
//	④ 冲突检查        ID 不能与内置或已有外部插件重复
//	⑤ 原子 rename     同一文件系统内的 rename 是原子的
//	⑥ 注册            进注册表（但仍处于 stopped）
//
// ########## 为什么必须"先暂存再原子落地" ##########
//
// 若直接解压到 <pluginDir>/<id>/，那么任何一个中途失败
// （解压到一半磁盘满、descriptor.json 非法、ID 冲突）
// 都会在插件目录里留下一个**半成品目录**。后果是：
//
//	· 面板每次启动都会尝试加载它并再次失败（日志刷屏）
//	· 用户看到目录存在，以为装好了
//	· 想重装时还要先手工删掉它
//
// 暂存 + 原子 rename 让"安装成功"成为一个**全有或全无**的事件：
// 目标目录要么不存在，要么是完整可用的插件。

// InstallOptions 控制一次安装行为。
type InstallOptions struct {
	// PluginDir 是外部插件根目录。
	PluginDir string
	// ArchiveName 是上传文件的**原始文件名**，用于判断格式。
	//
	// 只用来判断扩展名（zip / tar.gz），不参与任何路径拼接——
	// 用户上传的文件名是**不可信输入**，绝不能拿它当磁盘路径。
	ArchiveName string
	// Overwrite 表示允许覆盖已存在的**外部**插件同名目录。
	//
	// ########## 这个开关绝不能影响内置插件的保护 ##########
	//
	// 即便 Overwrite=true，ID 与内置插件冲突时仍然拒绝（见 registerExternal）。
	// 覆盖只对"同名外部插件目录"生效——那是"重装/升级"的正常需求。
	Overwrite bool
}

// InstallResult 描述一次成功的安装。
type InstallResult struct {
	// ID 是安装好的插件 ID。
	ID string `json:"id"`
	// Dir 是插件目录的绝对路径。
	Dir string `json:"dir"`
	// Files 是解压出的文件数。
	Files int `json:"files"`
	// Bytes 是解压出的总字节数。
	Bytes int64 `json:"bytes"`
	// Mode 是插件运行模式（managed / external）。
	Mode string `json:"mode"`
	// Replaced 表示这是一次覆盖安装。
	Replaced bool `json:"replaced"`
}

// InstallError 是安装失败错误，带可供前端展示的结构化信息。
type InstallError struct {
	// Stage 是失败的阶段（中文，可直接展示）。
	Stage string `json:"stage"`
	// Reason 是失败原因。
	Reason string `json:"reason"`
	// Err 是底层错误（供 errors.Is 判断）。
	Err error
}

func (e *InstallError) Error() string {
	return fmt.Sprintf("插件安装失败（%s）：%s", e.Stage, e.Reason)
}

func (e *InstallError) Unwrap() error { return e.Err }

// newInstallError 构造一个安装错误。
func newInstallError(stage, reason string, err error) *InstallError {
	return &InstallError{Stage: stage, Reason: reason, Err: err}
}

// InstallFromStream 从字节流安装一个插件包。
//
// 这是上传接口的入口：它把"一个不可信的压缩包字节流"
// 安全地变成"插件目录里一个可加载的插件"。
//
// 所有失败路径都会清理临时文件与暂存目录，
// 保证不会在插件目录里留下垃圾。
func (m *Manager) InstallFromStream(r io.Reader, opts InstallOptions) (*InstallResult, error) {
	pluginDir := strings.TrimSpace(opts.PluginDir)
	if pluginDir == "" {
		return nil, newInstallError("检查配置",
			"未配置外部插件目录（请用 -plugin-dir 指定）", nil)
	}

	// 判断压缩包格式。**必须在写盘之前**判断：不支持的格式
	// 没必要先落一个几十 MB 的文件再报错。
	kind := ArchiveKindOf(opts.ArchiveName)
	if kind == "" {
		return nil, newInstallError("检查格式",
			fmt.Sprintf("不支持的文件类型 %q（支持 %s）",
				opts.ArchiveName, strings.Join(supportedArchiveExts, " / ")),
			ErrUnsupportedArchive)
	}

	// 插件目录必须存在（安装是显式动作，不像扫描那样"不存在就跳过"）。
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return nil, newInstallError("准备目录",
			fmt.Sprintf("无法创建插件目录 %s: %v", pluginDir, err), err)
	}

	// ---------- ① 写入临时文件 ----------
	//
	// 临时文件建在**插件目录内**：这样它与最终位置在同一文件系统上，
	// 第 ⑤ 步的 rename 才是原子的。
	//
	// 若用 os.TempDir()，在 /opt 是独立分区（很常见）的机器上，
	// rename 会以 EXDEV 失败——安装功能直接不可用。
	tmpFile, err := os.CreateTemp(pluginDir, ".upload-*.tmp")
	if err != nil {
		return nil, newInstallError("写入临时文件", err.Error(), err)
	}
	tmpPath := tmpFile.Name()
	// 无论成功失败都要删掉临时文件。
	defer func() { _ = os.Remove(tmpPath) }()

	// ########## 边写边限流，而不是先读完再检查 ##########
	//
	// 若先 io.ReadAll 再判断大小，一个 10 GB 的上传会先把
	// 内存或磁盘吃满，检查发生在"已经太晚"之后。
	// LimitReader 让超出上限的字节**根本不会被读取**。
	written, err := io.Copy(tmpFile, io.LimitReader(r, maxArchiveBytes+1))
	closeErr := tmpFile.Close()
	if err != nil {
		return nil, newInstallError("写入临时文件", err.Error(), err)
	}
	if closeErr != nil {
		return nil, newInstallError("写入临时文件", closeErr.Error(), closeErr)
	}
	if written > maxArchiveBytes {
		return nil, newInstallError("检查大小",
			fmt.Sprintf("压缩包超过上限（%d MiB）", maxArchiveBytes>>20),
			ErrUnsafeArchive)
	}
	if written == 0 {
		return nil, newInstallError("检查内容", "上传的文件是空的", nil)
	}

	// ---------- ② 解压到暂存目录 ----------
	staging, err := os.MkdirTemp(pluginDir, ".install-*")
	if err != nil {
		return nil, newInstallError("准备暂存目录", err.Error(), err)
	}
	// 失败时清理；成功时这个目录已经被 rename 走了，RemoveAll 是空操作。
	defer func() { _ = os.RemoveAll(staging) }()

	extracted, err := ExtractArchive(tmpPath, kind, staging)
	if err != nil {
		stage := "解压压缩包"
		if errors.Is(err, ErrUnsafeArchive) {
			stage = "安全检查"
		}
		return nil, newInstallError(stage, err.Error(), err)
	}

	// ---------- ③ 校验 descriptor.json ----------
	//
	// ########## 这里必须传 dirName="" ##########
	//
	// ParseExternalDescriptor 会校验"目录名与 ID 一致"。但暂存目录的名字是
	// 随机生成的（.install-<随机数>），与插件 ID 必然不同——
	// 那是**安装期的中间状态**，此刻目录还没被命名成插件 ID。
	//
	// 传空串表示"跳过目录名一致性检查"（该检查的语义是
	// "扫描磁盘时，目录名应当就是插件 ID"）。安装流程在后面
	// 用 desc.ID 自己命名最终目录，因此这条约束由本函数保证，
	// 不依赖 Parse 的检查。
	desc, err := ReadExternalDescriptorNoDirCheck(staging)
	if err != nil {
		return nil, newInstallError("校验 descriptor.json", err.Error(), err)
	}
	// ########## 顺序至关重要：必须先设置 Dir，再做后端检查 ##########
	//
	// checkBackendExecutable 依赖 desc.Dir 去解析 backend.exec 的完整路径
	// （见 externalExecRel：Dir 为空时直接返回 ""，即"没有后端"）。
	//
	// 本函数第一版把检查放在了赋值之前，结果**后端检查被静默跳过**：
	// Dir 还是空的，于是 externalExecRel 返回 ""、函数认为
	// "这是前端-only 插件"、直接返回 nil。
	// 症状是"声明了 backend.exec 但文件不存在的包也能装上"，
	// 直到用户点击启动才报错——正是这条注释想避免的情况。
	absDir, err := filepath.Abs(staging)
	if err != nil {
		return nil, newInstallError("准备目录", err.Error(), err)
	}
	desc.Dir = absDir

	if err := m.checkBackendExecutable(desc); err != nil {
		return nil, newInstallError("校验后端文件", err.Error(), err)
	}

	// ---------- ④ 冲突检查 ----------
	//
	// ########## 这一步必须在 rename 之前 ##########
	//
	// 若先落地再注册，ID 冲突会导致：磁盘上多了一个目录、
	// 注册表里没有它。用户看到"安装失败"却能在目录里找到它，
	// 下次启动扫描时它又会被加载并再次冲突——一个永远修不好的状态。
	finalDir := filepath.Join(pluginDir, desc.ID)

	m.mu.RLock()
	existing, exists := m.registry[desc.ID]
	m.mu.RUnlock()

	if exists && existing.desc.Builtin {
		// ########## 无论如何都不能覆盖内置插件 ##########
		//
		// 这个判断**不受 Overwrite 影响**：内置插件编译在主程序里、
		// 经过审查，而上传的包是任意来源的。允许覆盖等于给了
		// 任何人一个"替换系统组件"的后门。
		return nil, newInstallError("检查冲突",
			fmt.Sprintf("插件 ID %q 与**内置插件**冲突。内置插件编译在主程序内、"+
				"经过审查，不能被外部插件替换，请改用其它 ID", desc.ID),
			ErrIDConflict)
	}

	if _, statErr := os.Stat(finalDir); statErr == nil {
		// 目录已存在。
		if !opts.Overwrite {
			return nil, newInstallError("检查冲突",
				fmt.Sprintf("插件 %q 已安装（目录 %s 已存在）。"+
					"如需覆盖请确认后重试", desc.ID, finalDir),
				ErrIDConflict)
		}
		// 允许覆盖：但只覆盖**外部**插件目录。
		// 一个已存在的同 ID 外部插件，其注册项可以被替换。
		if exists && !existing.desc.External {
			return nil, newInstallError("检查冲突",
				fmt.Sprintf("插件 %q 已存在且不是外部插件，无法覆盖", desc.ID),
				ErrIDConflict)
		}
	}

	// ---------- ⑤ 原子落地 ----------
	//
	// 覆盖安装时先把旧目录改名挪开，再放新的——
	// 这样"新目录就位"与"旧目录消失"之间没有空窗期，
	// 且失败时可以把旧的挪回来。
	var backupDir string
	if opts.Overwrite {
		if _, statErr := os.Stat(finalDir); statErr == nil {
			backupDir = finalDir + ".old-" + fmt.Sprint(os.Getpid())
			_ = os.RemoveAll(backupDir)
			if err := os.Rename(finalDir, backupDir); err != nil {
				return nil, newInstallError("替换旧版本",
					fmt.Sprintf("无法移开旧目录: %v", err), err)
			}
		}
	}

	// 从注册表里摘掉旧的同名条目（覆盖安装时），否则新插件
	// 会因为"ID 已注册"而注册失败。
	if exists {
		m.unregisterForReinstall(desc.ID)
	}

	if err := os.Rename(staging, finalDir); err != nil {
		// 落地失败：把旧目录挪回来，尽量恢复原状。
		if backupDir != "" {
			_ = os.Rename(backupDir, finalDir)
		}
		return nil, newInstallError("安装到插件目录",
			fmt.Sprintf("无法移动到 %s: %v", finalDir, err), err)
	}

	// 清理备份目录（此时新版本已经就位）。
	if backupDir != "" {
		_ = os.RemoveAll(backupDir)
	}

	// 更新 Dir 为最终位置，并重新绑定可执行文件路径。
	desc.Dir = finalDir

	// ---------- ⑥ 注册 ----------
	if err := m.registerExternal(desc); err != nil {
		// 注册失败（理论上前面已经查过冲突，这里是兜底）：
		// 必须把刚落地的目录删掉，否则就是前面描述过的
		// "磁盘有、注册表没有"的坏状态。
		_ = os.RemoveAll(finalDir)
		return nil, newInstallError("注册插件", err.Error(), err)
	}

	m.logger.Info("外部插件安装成功",
		"plugin", desc.ID,
		"dir", finalDir,
		"files", extracted.Files,
		"bytes", extracted.Bytes,
		"mode", desc.Mode,
		"replaced", exists)

	return &InstallResult{
		ID:       desc.ID,
		Dir:      finalDir,
		Files:    extracted.Files,
		Bytes:    extracted.Bytes,
		Mode:     desc.Mode,
		Replaced: exists,
	}, nil
}

// unregisterForReinstall 在覆盖安装时摘掉旧条目。
//
// ########## 为什么不复用 Stop + 删除 ##########
//
// 因为旧插件的进程（若有）此刻可能正在运行，而新版本即将替换它。
// 这里只从注册表移除，**不碰进程**——真正的进程终止由调用方
// 在覆盖前通过 CloseSession 风格的管理接口完成。
//
// 出于安全，本函数会拒绝移除内置插件（那是保护规则的最后一道）。
func (m *Manager) unregisterForReinstall(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.registry[id]
	if !ok {
		return
	}
	if e.desc.Builtin {
		// 理论到不了这里（调用方已检查），但保留这道防线：
		// 注册表是安全边界的最终载体，任何绕过路径都必须在这里被拦下。
		m.logger.Error("拒绝移除内置插件（这是一个应当被修复的调用路径）",
			"plugin", id)
		return
	}
	delete(m.registry, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}
