package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// 本地目录存储后端（阶段五 5.3）
// ============================================================================
//
// 最简单也最常用的一个：把归档写进本机的一个目录。
//
// ########## 本地后端的两个额外责任 ##########
//
// ① **自己也要防路径穿越**。key 虽然来自面板（含任务 id 与时间戳），
//    但 ValidateArchiveKey 仍会先过一遍，且这里再做一次
//    「拼出来的绝对路径必须在存储根之下」的复核——与 4.2 的
//    白名单判定同一手法（Rel 而非 HasPrefix）。
//    理由：存储根是用户配的，key 是别处生成的，两个输入合起来
//    出现逃逸时，"上游一定校验过了"是最靠不住的假设。
//
// ② **落地必须原子**。先写 <key>.tmp 再 rename：一个写了一半的
//    .tar.gz 留在目录里，用户会以为备份成功了（文件名一模一样），
//    直到需要恢复的那天才发现它打不开。

// localBackend 是本地目录后端。
type localBackend struct {
	// root 是存储根目录的绝对路径（Clean 后）。
	root string
	// base 是存储根之下的基础路径（可空）。
	base string
}

// newLocalBackend 构造本地后端。
func newLocalBackend(st Storage) (Backend, error) {
	root := strings.TrimSpace(st.Path)
	if root == "" {
		return nil, errors.New("backup: 本地存储路径不能为空")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("backup: 本地存储路径必须是绝对路径: %q", root)
	}
	clean := filepath.Clean(root)

	// 目录必须可建/可写：把失败留在启动或保存配置的那一刻，
	// 而不是等到半夜定时任务跑的时候。
	if err := os.MkdirAll(clean, storeDirMode); err != nil {
		return nil, fmt.Errorf("backup: 创建本地存储目录 %s 失败: %w", clean, err)
	}
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("backup: 检查本地存储目录 %s 失败: %w", clean, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("backup: 本地存储路径 %s 不是目录", clean)
	}
	return &localBackend{root: clean, base: strings.Trim(st.BasePath, "/")}, nil
}

func (b *localBackend) Type() string { return StorageLocal }

func (b *localBackend) Describe() string { return b.root }

func (b *localBackend) Close() error { return nil }

// resolve 把 key 解析成存储根之下的绝对路径。
//
// 两段判定，顺序不能反：
//
//	① 形态校验（相对、无 ..、无控制字符）；
//	② 拼出绝对路径后**反向复核**它确实落在根之下。
//
// 第 ② 步不能省：第 ① 步是纯词法的，而符号链接是词法看不出来的。
// 存储根里若有一个指向 /etc 的链接，词法校验会愉快地放行。
func (b *localBackend) resolve(key string) (string, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return "", err
	}
	full := filepath.Join(b.root, filepath.FromSlash(joinKey(b.base, key)))
	if !contains(b.root, full) {
		return "", fmt.Errorf("backup: 对象名 %q 解析后落在存储目录之外", key)
	}
	return full, nil
}

// Put 写入对象（tmp + rename 原子落地）。
func (b *localBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	full, err := b.resolve(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, storeDirMode); err != nil {
		return fmt.Errorf("backup: 创建目录 %s 失败: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".put-*.tmp")
	if err != nil {
		return fmt.Errorf("backup: 创建临时文件失败: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if err := copyWithContext(ctx, tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("backup: 写入 %s 失败: %w", key, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("backup: 同步 %s 失败: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("backup: 关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(name, storeFileMode); err != nil {
		return fmt.Errorf("backup: 设置文件权限失败: %w", err)
	}
	if err := os.Rename(name, full); err != nil {
		return fmt.Errorf("backup: 落地 %s 失败: %w", key, err)
	}
	return nil
}

// Get 读取对象。
func (b *localBackend) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	full, err := b.resolve(key)
	if err != nil {
		return nil, 0, err
	}
	// Lstat 在前：存储根里若被人放了链接，我们只认普通文件，
	// 不跟随它去读根外的内容。
	info, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
		}
		return nil, 0, fmt.Errorf("backup: 检查 %s 失败: %w", key, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("backup: %s 是符号链接，出于安全考虑拒绝读取", key)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("backup: %s 不是普通文件", key)
	}
	f, err := os.Open(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
		}
		return nil, 0, fmt.Errorf("backup: 打开 %s 失败: %w", key, err)
	}
	return f, info.Size(), nil
}

// Stat 查询对象。
func (b *localBackend) Stat(ctx context.Context, key string) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	full, err := b.resolve(key)
	if err != nil {
		return Object{}, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Object{}, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
		}
		return Object{}, fmt.Errorf("backup: 检查 %s 失败: %w", key, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Object{}, fmt.Errorf("backup: %s 是符号链接，出于安全考虑拒绝访问", key)
	}
	return Object{Key: key, Size: info.Size(), SizeKnown: true, ModTime: info.ModTime()}, nil
}

// Delete 删除对象（幂等：不存在返回 nil）。
func (b *localBackend) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	full, err := b.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("backup: 删除 %s 失败: %w", key, err)
	}
	b.pruneEmptyDirs(filepath.Dir(full))
	return nil
}

// pruneEmptyDirs 自底向上删掉空目录（到存储根为止，绝不动根本身）。
//
// 不清理的话，每建一个任务就在存储里留下一个空目录；
// 但这**不能过头**：绝不能把存储根本身删掉（用户的配置还在指向它）。
func (b *localBackend) pruneEmptyDirs(dir string) {
	for {
		if dir == b.root || !contains(b.root, dir) {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// List 列出具有给定前缀的对象。
//
// 前缀是**对象名**前缀（不是文件系统路径），因此走的是
// 「解析成目录 → 读目录」这条捷径：只有前缀的最后一段可能是不完整的
// 文件名，其余部分必然是目录。
func (b *localBackend) List(ctx context.Context, prefix string) ([]Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := joinKey(b.base, "")
	// 把 prefix 拆成"目录部分"与"文件名前缀部分"。
	// prefix 可能为空（列全部），也可能以 / 结尾（列某个目录）。
	full := joinKey(base, "")
	dirPart := prefix
	namePrefix := ""
	if prefix != "" {
		if strings.HasSuffix(prefix, "/") {
			dirPart = strings.TrimSuffix(prefix, "/")
		} else if i := strings.LastIndex(prefix, "/"); i >= 0 {
			dirPart = prefix[:i]
			namePrefix = prefix[i+1:]
		} else {
			dirPart = ""
			namePrefix = prefix
		}
	}
	full = joinKey(base, dirPart)

	root := b.root
	if full != "" {
		root = filepath.Join(b.root, filepath.FromSlash(full))
		if !contains(b.root, root) {
			return nil, fmt.Errorf("backup: 前缀 %q 解析后落在存储目录之外", prefix)
		}
	}

	out := []Object{}
	// 前缀可能指向一个并不存在的目录（刚建的任务还没备份过）：
	// 那是"没有对象"，不是错误。
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("backup: 读取存储目录失败: %w", err)
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// 单个子目录读不了不该让整个列表失败——但也不能静默：
			// 返回 nil 继续走，让调用方至少拿到能读到的部分。
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// 跳过我们自己的临时文件：它们不是备份，
		// 混进列表会让用户看到一个"大小不对的备份"。
		if strings.HasPrefix(d.Name(), ".put-") && strings.HasSuffix(d.Name(), ".tmp") {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, relErr := filepath.Rel(b.root, p)
		if relErr != nil {
			return nil
		}
		key := filepath.ToSlash(rel)
		// 只保留与 prefix 真正匹配的（目录部分已由 root 限定，
		// 这里再复核一次文件名前缀）。
		if namePrefix != "" && !strings.HasPrefix(d.Name(), namePrefix) {
			if !d.IsDir() {
				return nil
			}
		}
		if !contains(b.root, p) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		out = append(out, Object{Key: key, Size: info.Size(), SizeKnown: true, ModTime: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backup: 遍历存储目录失败: %w", err)
	}
	sortObjects(out)
	return out, nil
}

// copyWithContext 是带 ctx 取消的 io.Copy。
//
// 直接用 io.Copy 的话，一个已经取消的备份仍会继续把几百 MB
// 写进磁盘——用户点了取消却看着磁盘灯继续闪，是很差的体验。
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 256*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}
