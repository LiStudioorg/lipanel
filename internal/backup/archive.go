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
)

// ============================================================================
// 打包（阶段五 5.3）
// ============================================================================
//
// 把一个目录或单个文件打成 .tar.gz。刻意用标准库的 archive/tar +
// compress/gzip：格式是**所有 Linux 都自带解压能力**的那种，
// 用户拿 tar 命令就能自己打开，不依赖面板活着——
// 这正是"备份"这个功能最重要的性质。
//
// ########## 四类特殊条目：跳过并如实记录 ##########
//
//	tar 符号链接 → 会指向归档之外（恢复时就是一次路径逃逸），跳过
//	硬链接       → 同一原因，且 tar 语义在各工具间不一致，跳过
//	设备/管道/socket → 无法用普通文件语义表达，跳过
//	读不了的文件 → 权限不足等，跳过但记进 Warnings
//
// "跳过"必须是**可见的跳过**：静默跳过一个读不了的数据库文件，
// 用户会以为备份是完整的，直到需要恢复的那天才发现少了最关键的东西。
// 因此每一类跳过都进 Warnings 与 Skipped 计数，并显示在历史里。
//
// ########## 为什么归档里不含顶层目录名 ##########
//
// 归档内条目用**相对于源路径**的名字：备份 /var/www 得到的是
// "html/index.html" 而不是 "www/html/index.html"。
// 这样恢复到任意目标目录时，语义就是"把这个目录的内容放进去"，
// 而不是"在目标里再建一层 www"——后者会让用户在恢复后发现
// 数据深了一层，还得手工搬一次。

// ArchiveResult 是打包结果。
type ArchiveResult struct {
	// Bytes 是归档文件的大小。
	Bytes int64
	// FileCount 是归档里的普通文件数。
	FileCount int
	// DirCount 是目录数。
	DirCount int
	// TotalBytes 是原始数据总字节数（未压缩）。
	TotalBytes int64
	// Skipped 是被跳过的条目数。
	Skipped int
	// Warnings 是逐条告警（给用户看的）。
	Warnings []string
}

// ArchiveOptions 是打包配置。
type ArchiveOptions struct {
	// MaxBytes 是原始数据总字节上限（<=0 用 DefaultMaxSourceBytes）。
	MaxBytes int64
	// MaxEntries 是条目数上限（<=0 用 DefaultMaxEntries）。
	MaxEntries int
	// MaxWarnings 是收集的告警条数上限（<=0 用 50）。
	//
	// 没有上限的话，一个有几万个不可读文件的目录会产生几万条
	// 告警字符串，把历史记录文件撑爆——而那些信息早就同质了。
	MaxWarnings int
}

// CreateArchive 把 src 打包到 dstPath。
//
// dstPath 由调用方给出（在 staging 目录里），本函数负责
// 创建、写入、fsync，**失败时删除半成品**。
func CreateArchive(ctx context.Context, src, dstPath string, opts ArchiveOptions) (*ArchiveResult, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSourceBytes
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	maxWarnings := opts.MaxWarnings
	if maxWarnings <= 0 {
		maxWarnings = 50
	}

	fi, err := os.Lstat(src)
	if err != nil {
		return nil, fmt.Errorf("%w: 读取 %s 失败: %v", ErrSourceUnavailable, src, err)
	}
	// 源本身是符号链接时拒绝：用户配的是 /var/www，而它指向别处，
	// 打包出来的东西与他以为的不是同一份。明确拒绝比悄悄跟随更好。
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s 是符号链接，请填写它指向的真实路径",
			ErrSourceUnavailable, src)
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s 既不是普通目录也不是普通文件",
			ErrSourceUnavailable, src)
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), storeDirMode); err != nil {
		return nil, fmt.Errorf("backup: 创建归档目录失败: %w", err)
	}
	f, err := os.Create(dstPath)
	if err != nil {
		return nil, fmt.Errorf("backup: 创建归档文件失败: %w", err)
	}
	// 失败路径统一清理半成品：一个写了一半的 .tar.gz 留在磁盘上，
	// 看起来跟成功的一模一样。
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(dstPath)
	}

	gz, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("backup: 初始化 gzip 失败: %w", err)
	}
	// 压缩级别选 BestSpeed：备份的瓶颈几乎总在磁盘与网络，
	// 而在压缩上省下的那点空间不值得让打包慢好几倍。
	tw := tar.NewWriter(gz)

	res := &ArchiveResult{}
	// ########## base 决定归档内的条目名，取错会让恢复多一层目录 ##########
	//
	// 目录：条目**相对源目录本身**（备份 /var/www 得到 "html/index.html"）。
	//   若取它的父目录，归档里就会多一层 "www/"，恢复到目标目录后
	//   数据深了一层，用户还得手工搬一次。
	// 单文件：条目名就是文件名本身，因此 base 取它的父目录。
	base := src
	if !fi.IsDir() {
		base = filepath.Dir(src)
	}

	addEntry := func(p string, d fs.DirEntry, info fs.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, relErr := filepath.Rel(base, p)
		if relErr != nil {
			return nil
		}
		name := filepath.ToSlash(rel)
		if name == "." || name == "" {
			return nil
		}

		switch {
		case info.IsDir():
			res.DirCount++
		case info.Mode().IsRegular():
			res.FileCount++
			res.TotalBytes += info.Size()
		default:
			// 符号链接、设备、管道、socket：统一跳过。
			res.Skipped++
			addWarning(res, maxWarnings, fmt.Sprintf(
				"已跳过 %s（符号链接/设备/管道等特殊条目，无法安全地放进归档）", name))
			return nil
		}

		if res.FileCount+res.DirCount > maxEntries {
			return fmt.Errorf("%w: 条目数超过上限 %d", ErrTooLarge, maxEntries)
		}
		if res.TotalBytes > maxBytes {
			return fmt.Errorf("%w: 数据总量超过上限 %s",
				ErrTooLarge, humanBytes(maxBytes))
		}

		hdr := &tar.Header{
			Name:    name,
			Mode:    int64(info.Mode().Perm()),
			ModTime: info.ModTime(),
			Format:  tar.FormatPAX,
		}
		if info.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name = name + "/"
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("backup: 写入归档头失败: %w", err)
		}
		if info.IsDir() {
			return nil
		}
		return copyFileInto(ctx, tw, p, info.Size(), res, maxWarnings, name)
	}

	walkErr := walkSource(ctx, src, fi, addEntry)

	// 关闭顺序与打开顺序相反，且**必须**检查 tw.Close 的错误：
	// gzip 的尾部校验和是最后写出的，它的失败意味着归档不完整。
	closeErr := tw.Close()
	if walkErr == nil && closeErr != nil {
		walkErr = fmt.Errorf("backup: 结束 tar 写入失败: %w", closeErr)
	}
	if err := gz.Close(); walkErr == nil && err != nil {
		walkErr = fmt.Errorf("backup: 结束 gzip 写入失败: %w", err)
	}
	if walkErr == nil {
		if err := f.Sync(); err != nil {
			walkErr = fmt.Errorf("backup: 同步归档文件失败: %w", err)
		}
	}
	if walkErr == nil {
		if err := f.Close(); err != nil {
			walkErr = fmt.Errorf("backup: 关闭归档文件失败: %w", err)
		}
	}
	if walkErr != nil {
		_ = f.Close()
		_ = os.Remove(dstPath)
		return nil, walkErr
	}

	out, err := os.Stat(dstPath)
	if err != nil {
		_ = os.Remove(dstPath)
		return nil, fmt.Errorf("backup: 读取归档文件信息失败: %w", err)
	}
	res.Bytes = out.Size()
	return res, nil
}

// walkSource 遍历源（单文件时直接给一个条目）。
func walkSource(ctx context.Context, src string, fi os.FileInfo,
	add func(p string, d fs.DirEntry, info fs.FileInfo) error) error {
	if !fi.IsDir() {
		return add(src, nil, fi)
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// 单个条目读不了（权限、竞态删除）不该让整个备份失败——
			// 但要看是"根目录本身读不了"还是"某个子条目读不了"：
			// 前者说明整个配置就是错的，必须失败。
			if p == src {
				return fmt.Errorf("%w: 打开目录 %s 失败: %v", ErrSourceUnavailable, src, err)
			}
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		return add(p, d, info)
	})
}

// copyFileInto 把文件内容写进 tar。
//
// 读失败（权限不足、读一半被删）时**跳过而不是失败**：
// 一个目录里通常有一两个读不了的文件（比如 /etc/shadow 或
// 正在写入的日志），为此让整次备份失败，用户第二天会看到一个
// "备份失败"然后什么备份都没有——跳过并告知远比全盘失败有用。
func copyFileInto(ctx context.Context, tw *tar.Writer, p string, size int64,
	res *ArchiveResult, maxWarnings int, name string) error {
	f, err := os.Open(p)
	if err != nil {
		res.Skipped++
		res.FileCount--
		res.TotalBytes -= size
		addWarning(res, maxWarnings, fmt.Sprintf("已跳过 %s（无法读取：%v）", name, err))
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 256*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, werr := tw.Write(buf[:n]); werr != nil {
				return fmt.Errorf("backup: 写入归档失败: %w", werr)
			}
			written += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			// 读到一半失败：补零到声明的大小，否则 tar 结构就坏了
			// （后续所有条目都会错位）。补零后归档仍然可解，
			// 这个文件的内容不完整——但要能读出其它文件来。
			res.Skipped++
			addWarning(res, maxWarnings, fmt.Sprintf(
				"文件 %s 读取中断（已读 %d/%d 字节），归档内该文件不完整", name, written, size))
			pad := size - written
			if pad > 0 {
				zeros := make([]byte, 32*1024)
				for pad > 0 {
					n := int64(len(zeros))
					if n > pad {
						n = pad
					}
					if _, werr := tw.Write(zeros[:n]); werr != nil {
						return fmt.Errorf("backup: 归档补齐失败: %w", werr)
					}
					pad -= n
				}
			}
			return nil
		}
	}
	if written != size {
		// 文件在统计与读取之间被改小了：同样补齐，保住归档结构。
		pad := size - written
		if pad > 0 {
			zeros := make([]byte, pad)
			if _, werr := tw.Write(zeros); werr != nil {
				return fmt.Errorf("backup: 归档补齐失败: %w", werr)
			}
		}
		res.Skipped++
		addWarning(res, maxWarnings, fmt.Sprintf(
			"文件 %s 在打包期间被修改（声明 %d 字节，实读 %d 字节）", name, size, written))
	}
	return nil
}

// addWarning 追加一条告警（超过上限时只计数不再追加）。
func addWarning(res *ArchiveResult, max int, msg string) {
	if len(res.Warnings) >= max {
		return
	}
	res.Warnings = append(res.Warnings, msg)
}

// humanBytes 把字节数格式化成人类可读的字符串。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := float64(n)
	for _, u := range units {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f EiB", v/unit)
}
