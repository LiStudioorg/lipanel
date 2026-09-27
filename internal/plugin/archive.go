package plugin

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// 插件包解压（zip / tar.gz）
// ============================================================================
//
// ########## 这是整个外部插件机制里最危险的一段代码 ##########
//
// 它把**用户上传的、不可信的压缩包**写到磁盘上，且面板通常以 root 运行。
// 因此下面每一道校验都不是"防御性编程"式的多余检查，
// 而是针对一个具体攻击手法的拦截。
//
// 主要威胁与对应防线：
//
//	① Zip Slip（目录穿越）
//	   条目名写成 "../../etc/cron.d/evil" 或 "a/../../etc/passwd"，
//	   解压时就会覆盖插件目录之外的任意文件。
//	   → 三层防御，见 safeJoin。
//
//	② Zip Bomb（压缩炸弹）
//	   一个 42 KB 的 zip 可以解压出 4 GB 甚至更多（高度可压缩的重复数据），
//	   把磁盘写满或把内存耗尽。
//	   → 压缩比 + 总解压量 + 条目数 + 单文件大小，四重上限。
//	   → 注意：必须用 io.LimitReader 在**写入过程中**限制，
//	     不能等解压完再看大小（那时磁盘已经满了）。
//
//	③ 符号链接逃逸
//	   条目是一个符号链接，指向 /etc，后续条目再"写入"该链接
//	   就等于写到 /etc 里。tar 天然支持符号链接，zip 通过
//	   Unix 模式位也能表达。
//	   → 一律拒绝符号链接/硬链接/设备文件条目。
//
//	④ 覆盖已有文件
//	   → 解压到临时目录，校验通过后原子 rename；目标目录已存在则拒绝。
//
// ########## 一个必须写清楚的能力边界 ##########
//
// 本文件保证的是「解压过程不会写到目标目录之外」。
// 它**不保证**压缩包里的内容是善意的——一个完全合规的 zip
// 里可以包含一个会删库的 Go 程序。
// 因此安装 ≠ 运行：带后端的插件安装后处于 stopped 状态，
// 必须由管理员手动启动（见 external.go 的 Backend 说明）。

// 解压限制。这些值共同构成 zip bomb 防线。
const (
	// maxArchiveBytes 是上传的压缩包本身的大小上限。
	maxArchiveBytes = 32 << 20 // 32 MiB

	// MaxArchiveBytesForUpload 是 maxArchiveBytes 的导出版本，
	// 供 server 层在 ParseMultipartForm 之前设置请求体上限。
	//
	// ########## 为什么必须在解析 multipart 之前就用它 ##########
	//
	// 若等解压阶段才检查大小，一个恶意客户端可以先送一个 10 GB 的
	// body，在 ParseMultipartForm 内部就把磁盘写满——
	// 那时我们的检查根本没机会执行。
	MaxArchiveBytesForUpload = maxArchiveBytes
	// maxExtractBytes 是解压后**总**字节数上限。
	//
	// 取压缩包上限的 8 倍：正常的插件包（源码 + 前端资源）
	// 压缩比一般在 3~5 倍，8 倍留了足够余量；
	// 而 zip bomb 的压缩比动辄上千倍，会被这一条直接挡掉。
	maxExtractBytes = 256 << 20 // 256 MiB
	// maxExtractFiles 是解压后的文件数上限。
	//
	// 防的是"很多个小文件"型的攻击：每个文件都不大，
	// 但数量上百万会耗尽 inode（磁盘还有空间却写不进任何东西，
	// 且这种故障极难排查）。
	maxExtractFiles = 2000
	// maxSingleFileBytes 是单个解压文件的大小上限。
	maxSingleFileBytes = 64 << 20 // 64 MiB
	// maxCompressionRatio 是单文件的最大压缩比。
	//
	// 这一条专门拦 zip bomb：即使总量没超，一个 1 KiB 的文件
	// 解压出 100 MiB 也是明显的攻击特征。
	maxCompressionRatio = 200
)

// ErrUnsafeArchive 表示压缩包含有不安全的内容，已被拒绝。
var ErrUnsafeArchive = errors.New("plugin: 压缩包不安全")

// ErrIncompatibleAPIVersion 表示插件的 apiVersion 与主程序不兼容。
var ErrIncompatibleAPIVersion = errors.New("plugin: 插件 API 版本不兼容")

// ErrInvalidID 表示插件 ID 非法。
var ErrInvalidID = errors.New("plugin: 插件 ID 非法")

// ErrIDConflict 表示插件 ID 与已存在的插件冲突。
var ErrIDConflict = errors.New("plugin: 插件 ID 冲突")

// ErrNoDescriptor 表示压缩包内没有找到 descriptor.json。
var ErrNoDescriptor = errors.New("plugin: 压缩包内缺少 " + DescriptorFileName)

// supportedArchiveExts 是支持的压缩包扩展名。
var supportedArchiveExts = []string{".zip", ".tar.gz", ".tgz"}

// SupportedArchiveExts 返回支持的扩展名（供 server 层生成提示文案）。
func SupportedArchiveExts() []string {
	return append([]string(nil), supportedArchiveExts...)
}

// ErrUnsupportedArchive 表示压缩包格式不受支持。
//
// 与 ErrUnsafeArchive 区分开：后者是"这个包不安全"（服务端主动拒绝），
// 前者是"这个包我们不会解"（格式问题）。两者的 HTTP 语义也不同——
// server 层把它们分别映射到 400 与 400，但原因文案与排查方向完全不同。
var ErrUnsupportedArchive = errors.New("plugin: 不支持的压缩包格式")

// ArchiveKindOf 根据文件名判断压缩包类型，返回 "" 表示不支持。
func ArchiveKindOf(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "targz"
	default:
		return ""
	}
}

// extractLimits 汇总一次解压的配额消耗，供 zip 与 tar 两条路径共用。
type extractLimits struct {
	files int
	bytes int64
}

// add 记录一个文件的解压量并检查配额。
//
// size 是该文件解压后的**实际**字节数（由调用方边写边统计）。
func (l *extractLimits) add(name string, size int64, compressed int64) error {
	l.files++
	l.bytes += size

	if l.files > maxExtractFiles {
		return fmt.Errorf("%w: 文件数超过上限 %d", ErrUnsafeArchive, maxExtractFiles)
	}
	if l.bytes > maxExtractBytes {
		return fmt.Errorf("%w: 解压总量超过上限 %d 字节", ErrUnsafeArchive, maxExtractBytes)
	}
	if size > maxSingleFileBytes {
		return fmt.Errorf("%w: 文件 %q 过大（%d 字节，上限 %d）",
			ErrUnsafeArchive, name, size, maxSingleFileBytes)
	}
	// 压缩比检查：compressed 为 0 时跳过（小文件在 zip 里可能记录为 0）。
	if compressed > 0 && size/compressed > maxCompressionRatio {
		return fmt.Errorf("%w: 文件 %q 的压缩比过高（%d/%d），疑似压缩炸弹",
			ErrUnsafeArchive, name, size, compressed)
	}
	return nil
}

// safeJoin 是 zip slip 的**三层防御**，也是本文件的核心。
//
// ########## 三层分别拦什么 ##########
//
//	第一层：显式拒绝绝对路径与 .. 段
//	        —— 直接对上攻击payload，错误信息也最清楚
//	           （"条目名含 .."比"越界了"更容易让人看懂）
//
//	第二层：Clean 之后重新拼接，再验证结果仍在目标根内
//	        —— 拦第一层没想到的变体：
//	           "a/./../../b"、"a/b/../../../c"、
//	           以及 Windows 分隔符 "..\\..\\evil"
//
//	第三层：用 filepath.Rel 从**结果反推**，确认没有跳出
//	        —— 这是"信任但要验证"：前两层是基于字符串的判断，
//	           而这一层基于最终路径本身。即使前两层有疏漏，
//	           只要最终路径在根外，就会被拦住。
//
// ########## 为什么不用 filepath.Join 一步到位 ##########
//
// 因为 Join 会**静默地**把 ".." 应用掉：
//
//	filepath.Join("/tmp/root", "../../etc/passwd") == "/etc/passwd"
//
// 它不会报错，只会返回一个越界的路径。直接用 Join 的结果去写文件，
// 就是最经典的 zip slip 漏洞。所以必须"先 Clean、再拼接、再反查"。
func safeJoin(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: 条目名为空", ErrUnsafeArchive)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: 条目名含空字节", ErrUnsafeArchive)
	}

	// 统一分隔符：Windows 上传的包可能用反斜杠，
	// 而 "..\\..\\evil" 在 Linux 上不会被当作路径分隔符，
	// 若不归一化就会**绕过**第一层的检查（写入一个名为 "..\..\evil" 的普通文件），
	// 然后在别的系统上解压时变成穿越。
	norm := strings.ReplaceAll(name, "\\", "/")

	// ---------- 第一层：显式拒绝 ----------
	if strings.HasPrefix(norm, "/") {
		return "", fmt.Errorf("%w: 条目 %q 是绝对路径", ErrUnsafeArchive, name)
	}
	// 盘符形态（C:/...）。
	if len(norm) >= 2 && norm[1] == ':' {
		return "", fmt.Errorf("%w: 条目 %q 含盘符", ErrUnsafeArchive, name)
	}
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: 条目 %q 含 .. 路径段", ErrUnsafeArchive, name)
		}
	}

	// ---------- 第二层：Clean 后拼接 ----------
	clean := filepath.Clean(filepath.FromSlash(norm))
	if clean == "." || clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: 条目 %q 未指向任何文件", ErrUnsafeArchive, name)
	}

	target := filepath.Join(root, clean)

	// ---------- 第三层：从结果反推，确认在根内 ----------
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("%w: 条目 %q 无法定位到插件目录内: %v",
			ErrUnsafeArchive, name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: 条目 %q 解压后会落到插件目录之外", ErrUnsafeArchive, name)
	}

	return target, nil
}

// ExtractResult 描述一次成功的解压。
type ExtractResult struct {
	// Root 是解压后的插件根目录。
	Root string
	// Files 是解压出的文件数。
	Files int
	// Bytes 是解压出的总字节数。
	Bytes int64
}

// ExtractArchive 把压缩包解压到 dst。
//
// ########## 调用者的责任 ##########
//
// dst 必须是**全新的空目录**，且由调用方负责在失败时清理。
// 本函数不删除 dst：它可能是调用方精心挑选的临时路径，
// 由调用方统一清理比在这里猜更安全。
//
// 支持 .zip / .tar.gz / .tgz，由 kind 指定（见 ArchiveKindOf）。
func ExtractArchive(path, kind, dst string) (*ExtractResult, error) {
	switch kind {
	case "zip":
		return extractZip(path, dst)
	case "targz":
		return extractTarGz(path, dst)
	default:
		return nil, fmt.Errorf("plugin: 不支持的压缩包类型 %q（支持 %s）",
			kind, strings.Join(supportedArchiveExts, " / "))
	}
}

// extractZip 解压 zip 包。
func extractZip(path, dst string) (*ExtractResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 读取压缩包失败: %w", err)
	}
	if info.Size() > maxArchiveBytes {
		return nil, fmt.Errorf("%w: 压缩包过大（%d 字节，上限 %d）",
			ErrUnsafeArchive, info.Size(), maxArchiveBytes)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 打开 zip 失败: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// 条目数先粗查一遍：在写任何文件之前就拒绝超大包，
	// 避免写了一半才发现超限（那时磁盘上已经有一堆垃圾）。
	if len(zr.File) > maxExtractFiles {
		return nil, fmt.Errorf("%w: 条目数 %d 超过上限 %d（写盘前即拒绝）",
			ErrUnsafeArchive, len(zr.File), maxExtractFiles)
	}

	lim := &extractLimits{}
	for _, f := range zr.File {
		if err := extractZipEntry(f, dst, lim); err != nil {
			return nil, err
		}
	}
	if lim.files == 0 {
		return nil, fmt.Errorf("%w: 压缩包内没有任何文件", ErrUnsafeArchive)
	}
	return &ExtractResult{Root: dst, Files: lim.files, Bytes: lim.bytes}, nil
}

// extractZipEntry 解压单个 zip 条目。
func extractZipEntry(f *zip.File, dst string, lim *extractLimits) error {
	target, err := safeJoin(dst, f.Name)
	if err != nil {
		return err
	}

	// ########## 拒绝符号链接与特殊文件 ##########
	//
	// zip 用 Unix 模式位的高 16 位表达文件类型。
	// 一个符号链接条目本身不占空间，但后续"写入该链接"的条目
	// 会顺着它写到链接指向的位置（可能是 /etc）。
	//
	// 这里**一律拒绝**而不是"尝试安全地创建"：
	// 插件包不需要符号链接，拒绝掉的成本是零。
	mode := f.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: 条目 %q 是符号链接（出于安全考虑不允许）",
			ErrUnsafeArchive, f.Name)
	}
	if mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
		return fmt.Errorf("%w: 条目 %q 是设备/管道/socket 特殊文件",
			ErrUnsafeArchive, f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o755)
	}

	// ########## 目录也必须过 safeJoin ##########
	//
	// filepath.Dir 可能产出 ".."（例如条目名就叫 "../x"），
	// 那种情况 safeJoin 已经在上面拦掉了；这里再走一次是为了
	// 保证"文件的父目录"同样是安全的。
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("plugin: 创建目录失败: %w", err)
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("plugin: 打开 zip 条目 %q 失败: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	// ########## 解压前先按声明大小预检 ##########
	if int64(f.UncompressedSize64) > maxSingleFileBytes {
		return fmt.Errorf("%w: 文件 %q 声明大小 %d 超过上限 %d",
			ErrUnsafeArchive, f.Name, f.UncompressedSize64, maxSingleFileBytes)
	}

	written, err := writeLimited(target, rc, lim, f.Name, int64(f.CompressedSize64))
	if err != nil {
		return err
	}
	return lim.add(f.Name, written, int64(f.CompressedSize64))
}

// extractTarGz 解压 tar.gz 包。
func extractTarGz(path, dst string) (*ExtractResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 读取压缩包失败: %w", err)
	}
	if info.Size() > maxArchiveBytes {
		return nil, fmt.Errorf("%w: 压缩包过大（%d 字节，上限 %d）",
			ErrUnsafeArchive, info.Size(), maxArchiveBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("plugin: 打开压缩包失败: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("plugin: 解压 gzip 失败: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	lim := &extractLimits{}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("plugin: 读取 tar 失败: %w", err)
		}

		target, err := safeJoin(dst, hdr.Name)
		if err != nil {
			return nil, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, fmt.Errorf("plugin: 创建目录失败: %w", err)
			}
			continue

		case tar.TypeReg:
			// 正常文件，继续往下处理。

		case tar.TypeSymlink, tar.TypeLink:
			return nil, fmt.Errorf("%w: 条目 %q 是链接（出于安全考虑不允许）",
				ErrUnsafeArchive, hdr.Name)

		default:
			// 设备、FIFO、字符设备等一律拒绝。
			return nil, fmt.Errorf("%w: 条目 %q 的类型 %d 不受支持",
				ErrUnsafeArchive, hdr.Name, hdr.Typeflag)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, fmt.Errorf("plugin: 创建目录失败: %w", err)
		}

		// tar 头部声明的大小是攻击者可控的，writeLimited 会用
		// LimitReader 兜住"声明很小、实际很大"的情况。
		// compressed 传 0：tar.gz 是流式的，拿不到单文件的压缩后大小，
		// 因此压缩比检查对 tar 不适用——靠总量上限与单文件上限兜底。
		written, err := writeLimited(target, tr, lim, hdr.Name, 0)
		if err != nil {
			return nil, err
		}
		if err := lim.add(hdr.Name, written, 0); err != nil {
			return nil, err
		}
	}

	if lim.files == 0 {
		return nil, fmt.Errorf("%w: 压缩包内没有任何文件", ErrUnsafeArchive)
	}
	return &ExtractResult{Root: dst, Files: lim.files, Bytes: lim.bytes}, nil
}

// writeLimited 把 r 写入 target，并强制单文件与总量上限。
//
// ########## 为什么不能先全读进内存再写 ##########
//
// 内存版的实现（io.ReadAll 后检查长度）对 zip bomb 完全无效：
// 一个 42 KB 的 bomb 会在 ReadAll 的那一刻就吃掉几 GB 内存，
// 检查发生在"已经太晚"之后。
//
// 因此这里用 io.LimitReader 把读入量**硬限制**在剩余配额内——
// 超出的部分根本不会被分配。
func writeLimited(target string, r io.Reader, lim *extractLimits, name string, compressed int64) (int64, error) {
	// 计算这个文件还允许写多少：单文件上限与总量剩余额度取小。
	remaining := int64(maxExtractBytes) - lim.bytes
	if remaining <= 0 {
		return 0, fmt.Errorf("%w: 解压总量已达上限 %d 字节", ErrUnsafeArchive, maxExtractBytes)
	}
	allowed := int64(maxSingleFileBytes)
	if remaining < allowed {
		allowed = remaining
	}

	// 多读 1 字节：用来判断"是不是被截断了"。
	lr := io.LimitReader(r, allowed+1)

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("plugin: 创建文件 %s 失败: %w", target, err)
	}

	written, copyErr := io.Copy(out, lr)
	closeErr := out.Close()
	if copyErr != nil {
		return written, fmt.Errorf("plugin: 写入 %s 失败: %w", target, copyErr)
	}
	if closeErr != nil {
		return written, fmt.Errorf("plugin: 关闭 %s 失败: %w", target, closeErr)
	}

	// 超出配额：说明被 LimitReader 截断了。
	if written > allowed {
		return written, fmt.Errorf("%w: 文件 %q 解压后超过上限（已写入 %d 字节即被截断，"+
			"单文件上限 %d）", ErrUnsafeArchive, name, written, maxSingleFileBytes)
	}
	// 压缩比兜底（zip 才有 compressed 值）。
	if compressed > 0 && written/compressed > maxCompressionRatio {
		return written, fmt.Errorf("%w: 文件 %q 的压缩比过高（%d/%d），疑似压缩炸弹",
			ErrUnsafeArchive, name, written, compressed)
	}
	return written, nil
}
