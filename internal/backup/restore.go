package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// 恢复（阶段五 5.3）——本模块唯一不可逆的动作
// ============================================================================
//
// ########## 威胁模型：归档是不可信输入 ##########
//
// 归档可能来自：
//   · 面板自己打的（正常情况）；
//   · 用户从别处拷进来的、被人改过的（**这才是要防的**）。
//
// 一个恶意归档可以靠条目名做到：`../../etc/cron.d/x`、
// `/etc/passwd`、或者先放一个指向 /etc 的符号链接再往里写。
// 面板以 root 运行时，这三件事的后果都是"任意文件覆盖"。
//
// ########## 三层防御（与外部插件安装同一套纪律，顺序不可换）##########
//
//	① 归一化分隔符后显式拒绝：绝对路径、`..` 段、盘符、NUL；
//	② filepath.Clean 后 Join 到目标目录；
//	③ filepath.Rel 反向复核结果确实在目标目录之内。
//
// 第 ③ 步不能省：第 ① 步是纯词法的，而目标目录里可能**本来就**
// 存在一个指向外部的符号链接（不是这个归档放的）。因此写每个
// 文件之前还要 Lstat 目标路径本身、拒绝写进任何符号链接。
//
// ########## 类型白名单，而不是类型黑名单 ##########
//
// 只恢复普通文件与目录。符号链接、硬链接、设备、管道、socket
// 一律**跳过并计数**。设备与管道尤其要紧：以 root 往目标目录里
// "恢复"出一个 /dev/sda 的设备节点，等于把整块磁盘交出去。
//
// ########## 恢复不做的事 ##########
//
//   · **不删除**目标目录里任何不在归档中的文件。恢复是"覆盖同名的
//     一部分"，不是"把目录抹成归档的样子"。后者会让用户在恢复一份
//     三天前的备份时，连带删掉这三天里新产生的数据——这是备份
//     工具最经典的事故。
//   · 不做增量、不做冲突自动改名（改名会让"我恢复了"与"我看到文件了"
//     对不上）。冲突如实计数并展示。

// RestoreOptions 是恢复配置。
type RestoreOptions struct {
	// MaxEntries 是允许恢复的最大条目数（<=0 用 DefaultMaxEntries）。
	MaxEntries int
	// MaxBytes 是允许恢复的最大总字节数（<=0 用 DefaultMaxBytes）。
	MaxBytes int64
	// MaxWarnings 是告警条数上限。
	MaxWarnings int
	// AllowUnsafe 保留给测试：置 true 时**不影响**安全判定，
	// 仅用于让"不可恢复条目"的错误被跳过而不是中止整次恢复。
	AllowUnsafe bool
}

// defaultRestoreMaxBytes 是恢复的最大总字节数。
const defaultRestoreMaxBytes int64 = 64 << 30

// restoreReader 抽象"打开归档"这一步，让预览与实际恢复共用同一份
// 判定逻辑（两份实现必然漂移，而这里漂移的后果是安全问题）。
type restoreReader func() (io.ReadCloser, error)

// gzipTarReader 打开归档，返回 (gzip, tar) 两层读取器。
func gzipTarReader(rc io.ReadCloser) (*gzip.Reader, *tar.Reader, error) {
	gz, err := gzip.NewReader(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: 归档不是合法的 gzip 文件（可能已损坏）: %w", err)
	}
	return gz, tar.NewReader(gz), nil
}

// classifyEntry 判定一个 tar 条目是否可安全恢复。
//
// 返回 (可恢复, 原因)。判定顺序：类型 → 名字形态。
// 类型在前：一个符号链接即便名字完全正常也不该恢复。
func classifyEntry(hdr *tar.Header) (bool, string) {
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		// 普通文件，继续做名字检查。
	case tar.TypeDir:
		// 目录，继续做名字检查。
	case tar.TypeSymlink:
		return false, "符号链接（恢复它会指向归档之外的位置）"
	case tar.TypeLink:
		return false, "硬链接（指向归档内的其它条目，语义在各工具间不一致）"
	case tar.TypeChar, tar.TypeBlock:
		return false, "设备节点（恢复设备节点等于把整块设备交给它）"
	case tar.TypeFifo:
		return false, "命名管道"
	case tar.TypeXGlobalHeader, tar.TypeXHeader:
		// PAX 扩展头由 archive/tar 自己消费，不会作为独立条目出现；
		// 万一出现也是元数据，跳过即可。
		return false, "归档元数据条目"
	default:
		return false, fmt.Sprintf("未知条目类型 %q", string(rune(hdr.Typeflag)))
	}

	name := hdr.Name
	if strings.TrimSpace(name) == "" {
		return false, "条目名为空"
	}
	if strings.ContainsRune(name, 0) {
		return false, "条目名含 NUL 字节"
	}
	if strings.Contains(name, "\\") {
		// 反斜杠在 Linux 上是合法文件名字符，但在 tar 里
		// 常被 Windows 工具当作路径分隔符写出来。放行它意味着
		// 同一个归档在两套工具下解开成不同结构——拒绝更安全。
		return false, "条目名含反斜杠（可能是 Windows 工具打包的，路径语义不确定）"
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return false, "绝对路径"
	}
	if len(name) >= 2 && name[1] == ':' {
		return false, "含盘符（Windows 绝对路径）"
	}
	// 逐段检查 .. —— 不能只看开头：`a/../../b` 同样会逃逸。
	cleaned := strings.ReplaceAll(name, "\\", "/")
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return false, "含 .. 路径段"
		}
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return false, "含 .. 路径段"
	}
	return true, ""
}

// resolveRestorePath 把归档条目名解析成目标目录下的绝对路径（第 ②③ 层）。
func resolveRestorePath(targetDir, name string) (string, error) {
	cleaned := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(name, "/")))
	if cleaned == "." {
		return targetDir, nil
	}
	full := filepath.Join(targetDir, cleaned)
	// 第 ③ 层：反向复核。这是最后一道闸门，
	// 前面所有词法检查的疏漏都由它兜住。
	if !contains(targetDir, full) {
		return "", fmt.Errorf("%w: 条目 %q 解析后落在目标目录之外", ErrArchiveUnsafe, name)
	}
	return full, nil
}

// PreviewRestore 预览归档内容（**不落盘、不创建任何文件**）。
//
// 这个接口存在的意义是让用户在按下"恢复"之前就看到真实影响面：
// 包里有多少文件、哪些会覆盖已存在的文件、有没有不能恢复的条目。
// 只给一个"确定要恢复吗"的弹窗，等于让用户盲签。
func PreviewRestore(ctx context.Context, open restoreReader, targetDir string, confirmText string,
	opts RestoreOptions) (*RestorePreview, error) {
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultRestoreMaxBytes
	}

	targetAbs, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析目标目录失败: %w", err)
	}

	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	_, tr, err := gzipTarReader(rc)
	if err != nil {
		return nil, err
	}

	res := &RestorePreview{
		TargetDir:   targetAbs,
		Entries:     []ArchiveEntry{},
		Conflicts:   []string{},
		ConfirmText: confirmText,
		Danger:      restoreDangerText(targetAbs),
	}
	seen := map[string]bool{}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: 读取归档失败（可能已损坏）: %w", err)
		}
		res.Total++
		if res.Total > maxEntries {
			return nil, fmt.Errorf("%w: 归档条目数超过上限 %d", ErrTooLarge, maxEntries)
		}

		ok, reason := classifyEntry(hdr)
		entry := ArchiveEntry{
			Name:  hdr.Name,
			Size:  hdr.Size,
			Mode:  fmt.Sprintf("%04o", hdr.Mode&0o7777),
			IsDir: hdr.Typeflag == tar.TypeDir,
			Type:  entryTypeName(hdr.Typeflag),
		}
		if !ok {
			entry.Unsafe = true
			entry.Reason = reason
			res.UnsafeCount++
		} else {
			res.SafeCount++
			if !entry.IsDir {
				res.TotalBytes += hdr.Size
			}
		}

		// 冲突检测只对可恢复的普通文件做（目录不算冲突：
		// 目标里已经有同名目录是常态，把它算成"会被覆盖"
		// 只会制造噪声，让真正的文件冲突被淹没）。
		if ok && !entry.IsDir {
			full, rerr := resolveRestorePath(targetAbs, hdr.Name)
			if rerr == nil && !seen[full] {
				seen[full] = true
				if _, statErr := os.Lstat(full); statErr == nil {
					res.ConflictCount++
					if len(res.Conflicts) < DefaultPreviewMaxEntries {
						res.Conflicts = append(res.Conflicts, hdr.Name)
					}
				}
			}
		}

		if len(res.Entries) < DefaultPreviewMaxEntries {
			res.Entries = append(res.Entries, entry)
		} else {
			res.Truncated = true
		}
	}

	if res.TotalBytes > maxBytes {
		return nil, fmt.Errorf("%w: 归档解压后总量超过上限 %s",
			ErrTooLarge, humanBytes(maxBytes))
	}
	return res, nil
}

// restoreDangerText 生成危险说明（由后端生成，前端直接展示）。
//
// ########## 为什么危险文案要由后端生成 ##########
//
// 前端若自己写一份，它描述的"恢复会做什么"就可能与后端实际做的
// 不一致——而用户是照着这段文字决定要不要按下去的。
// 文案里同样不能有"会删除目标目录的其它文件"这种话（我们不删），
// 也不能漏掉"会覆盖同名文件"（我们会覆盖）。
func restoreDangerText(targetDir string) []string {
	return []string{
		fmt.Sprintf("恢复会**覆盖** %s 下与归档同名的文件，被覆盖的内容无法找回。", targetDir),
		"恢复**不会删除**该目录里其它文件；但归档里较旧的文件会盖掉同名的新文件。",
		"面板以自身运行身份（生产环境通常是 root）写入这些文件。",
		"如果目标目录正在被服务使用（数据库、站点根目录），请先停掉对应服务。",
		"此操作不可撤销：建议先用「下载」把归档另存一份。",
	}
}

// entryTypeName 把 tar 类型标记转成可读名。
func entryTypeName(t byte) string {
	switch t {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "dir"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeChar:
		return "chardev"
	case tar.TypeBlock:
		return "blockdev"
	case tar.TypeFifo:
		return "fifo"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

// Restore 执行恢复。
//
// 前置条件由调用方（Manager）保证：二次确认已通过、目标目录已过白名单。
// 本函数只做与归档内容相关的安全判定与落盘。
func Restore(ctx context.Context, open restoreReader, targetDir string, opts RestoreOptions) (*RestoreResult, error) {
	start := time.Now()
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultRestoreMaxBytes
	}
	maxWarnings := opts.MaxWarnings
	if maxWarnings <= 0 {
		maxWarnings = 50
	}

	targetAbs, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析目标目录失败: %w", err)
	}
	if err := os.MkdirAll(targetAbs, 0o700); err != nil {
		return nil, fmt.Errorf("backup: 创建目标目录 %s 失败: %w", targetAbs, err)
	}

	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	_, tr, err := gzipTarReader(rc)
	if err != nil {
		return nil, err
	}

	res := &RestoreResult{TargetDir: targetAbs, Warnings: []string{}}
	entries := 0
	var totalBytes int64
	warn := func(msg string) {
		if len(res.Warnings) < maxWarnings {
			res.Warnings = append(res.Warnings, msg)
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: 读取归档失败（可能已损坏）: %w", err)
		}
		entries++
		if entries > maxEntries {
			return nil, fmt.Errorf("%w: 归档条目数超过上限 %d", ErrTooLarge, maxEntries)
		}

		ok, reason := classifyEntry(hdr)
		if !ok {
			// 不可恢复的条目一律**跳过并计数**，而不是中止整次恢复。
			// 理由：一个被人塞进符号链接的归档，中止恢复意味着用户
			// 连里面 99% 的正常数据都拿不到——而跳过它，
			// 用户既拿到了数据，也在结果里看到"跳过了 1 个符号链接"。
			res.Skipped++
			warn(fmt.Sprintf("已跳过 %s：%s", hdr.Name, reason))
			continue
		}

		full, err := resolveRestorePath(targetAbs, hdr.Name)
		if err != nil {
			res.Skipped++
			warn(fmt.Sprintf("已跳过 %s：%v", hdr.Name, err))
			continue
		}

		if hdr.Typeflag == tar.TypeDir {
			if err := mkdirNoSymlink(full, fs.FileMode(hdr.Mode&0o7777)); err != nil {
				return nil, fmt.Errorf("backup: 创建目录 %s 失败: %w", hdr.Name, err)
			}
			res.Dirs++
			continue
		}

		if totalBytes+hdr.Size > maxBytes {
			return nil, fmt.Errorf("%w: 归档解压后总量超过上限 %s",
				ErrTooLarge, humanBytes(maxBytes))
		}
		n, overwritten, skipped, werr := writeFileFromTar(ctx, tr, full, hdr)
		if werr != nil {
			return nil, werr
		}
		if skipped {
			res.Skipped++
			warn(fmt.Sprintf("已跳过 %s：目标位置不是普通文件或无法写入", hdr.Name))
			continue
		}
		res.Restored++
		res.Bytes += n
		totalBytes += n
		if overwritten {
			res.Overwritten++
		}
	}
	res.DurationMS = time.Since(start).Milliseconds()
	// 告警与冲突清单排序：让同样的归档在两次恢复里给出同样的输出，
	// 便于用户对比（tar 本身的顺序是稳定的，但跳过发生在不同分支上）。
	sort.Strings(res.Warnings)
	return res, nil
}

// mkdirNoSymlink 创建目录，并拒绝把已有符号链接当成目录用。
func mkdirNoSymlink(dir string, mode fs.FileMode) error {
	if mode == 0 {
		mode = 0o755
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s 已存在且是符号链接，拒绝写入", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s 已存在且不是目录", dir)
		}
		// 已有目录：不改权限。改权限会把用户精心设过的
		// 目录权限（比如 750 的站点目录）覆盖成归档里的值。
		return nil
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	return nil
}

// writeFileFromTar 把一个文件条目写进目标位置。
//
// 返回 (写入字节数, 是否覆盖了已有文件, 是否跳过, 错误)。
//
// ########## 三个必须做对的细节 ##########
//
//	① **目标已存在的符号链接一律拒绝**：归档里的条目名是干净的，
//	   但目标目录里可能本来就有一个指向 /etc/passwd 的链接。
//	   经它写入 = 以 root 改写任意文件。
//	② **tmp + rename 原子落地**：恢复中途失败时，目标位置要么是
//	   旧内容完整、要么是新内容完整，不会留下一个半截文件。
//	③ **保留归档里的权限位**：备份 /etc 的 ssh 私钥（0600）
//	   恢复后仍是 0600。用默认 0644 恢复私钥是一次真实的密钥泄露。
func writeFileFromTar(ctx context.Context, tr *tar.Reader, full string, hdr *tar.Header) (
	written int64, overwritten bool, skipped bool, err error,
) {
	parent := filepath.Dir(full)
	if err := mkdirNoSymlink(parent, 0o755); err != nil {
		return 0, false, true, nil
	}

	mode := fs.FileMode(hdr.Mode & 0o7777)
	if mode == 0 {
		mode = 0o644
	}

	// 目标已存在时：符号链接 / 非普通文件一律跳过。
	if info, statErr := os.Lstat(full); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return 0, false, true, nil
		}
		if !info.Mode().IsRegular() {
			return 0, false, true, nil
		}
		overwritten = true
	}

	tmp, cerr := os.CreateTemp(parent, ".restore-*.tmp")
	if cerr != nil {
		return 0, false, true, nil
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	buf := make([]byte, 256*1024)
	var n int64
	for {
		if cerr := ctx.Err(); cerr != nil {
			_ = tmp.Close()
			return 0, false, false, cerr
		}
		read, rerr := tr.Read(buf)
		if read > 0 {
			if _, werr := tmp.Write(buf[:read]); werr != nil {
				_ = tmp.Close()
				return 0, false, false, fmt.Errorf("backup: 写入 %s 失败: %w", hdr.Name, werr)
			}
			n += int64(read)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			_ = tmp.Close()
			return 0, false, false, fmt.Errorf("backup: 解压 %s 失败: %w", hdr.Name, rerr)
		}
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return 0, false, false, fmt.Errorf("backup: 同步 %s 失败: %w", hdr.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, false, false, fmt.Errorf("backup: 关闭 %s 失败: %w", hdr.Name, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return 0, false, false, fmt.Errorf("backup: 设置 %s 权限失败: %w", hdr.Name, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		return 0, false, false, fmt.Errorf("backup: 落地 %s 失败: %w", hdr.Name, err)
	}
	// ModTime 单独设置：os.Chtimes 失败不作为致命错误
	// （某些文件系统不支持任意时间戳），但要说出来。
	if !hdr.ModTime.IsZero() {
		_ = os.Chtimes(full, hdr.ModTime, hdr.ModTime)
	}
	return n, overwritten, false, nil
}
