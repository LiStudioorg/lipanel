package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 打包与恢复的测试（阶段五 5.3）
// ============================================================================
//
// 本文件是整个模块**安全底线**的证明所在地：
// 恢复可以覆盖目标目录里的文件，因此每一条"拒绝"都必须有用例锁死。
//
// 全程只用 t.TempDir()：绝不碰宿主机上任何真实目录
// （与 4.6 假执行器、5.2 -cron-file 同一条纪律）。

// ---------------------------------------------------------------------------
// 打包
// ---------------------------------------------------------------------------

// writeTree 在 root 下造一棵小目录树。
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("建目录失败: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("写文件失败: %v", err)
		}
	}
}

// readArchive 把归档读成 map[名字]内容（目录条目单独计数）。
func readArchive(t *testing.T, path string) (map[string]string, []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开归档失败: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("归档不是合法 gzip: %v", err)
	}
	defer func() { _ = gz.Close() }()

	files := map[string]string{}
	dirs := []string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("读取归档失败: %v", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			dirs = append(dirs, hdr.Name)
			continue
		}
		body, _ := io.ReadAll(tr)
		files[hdr.Name] = string(body)
	}
	return files, dirs
}

func TestCreateArchiveRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"a.txt":         "hello",
		"sub/b.txt":     "world",
		"sub/c/d.txt":   "deep",
		"sub/中文 名.md":   "# 中文内容",
	})

	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	res, err := CreateArchive(context.Background(), src, dst, ArchiveOptions{})
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	if res.FileCount != 4 {
		t.Fatalf("FileCount = %d, 期望 4", res.FileCount)
	}

	files, dirs := readArchive(t, dst)
	want := map[string]string{
		"a.txt": "hello", "sub/b.txt": "world",
		"sub/c/d.txt": "deep", "sub/中文 名.md": "# 中文内容",
	}
	for name, content := range want {
		got, ok := files[name]
		if !ok {
			t.Fatalf("归档里缺少 %q，实际有 %v", name, keysOf(files))
		}
		if got != content {
			t.Fatalf("%q 内容 = %q, 期望 %q", name, got, content)
		}
	}
	// 条目名必须是**相对路径**：出现 /var/... 这种绝对名，
	// 恢复时就会往目标目录之外写。
	for name := range files {
		if strings.HasPrefix(name, "/") {
			t.Fatalf("归档条目 %q 是绝对路径（应该相对）", name)
		}
		if strings.HasPrefix(name, filepath.Base(src)+"/") {
			t.Fatalf("归档条目 %q 带上了顶层目录名（恢复后会多一层）", name)
		}
	}
	if len(dirs) == 0 {
		t.Fatalf("归档里没有目录条目")
	}
	if res.Bytes <= 0 {
		t.Fatalf("归档体积 = %d, 应为正数", res.Bytes)
	}
}

func TestCreateArchiveSingleFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "one.conf")
	if err := os.WriteFile(p, []byte("key=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "one.tar.gz")
	res, err := CreateArchive(context.Background(), p, dst, ArchiveOptions{})
	if err != nil {
		t.Fatalf("打包单文件失败: %v", err)
	}
	if res.FileCount != 1 {
		t.Fatalf("FileCount = %d, 期望 1", res.FileCount)
	}
	files, _ := readArchive(t, dst)
	if files["one.conf"] != "key=value\n" {
		t.Fatalf("单文件内容 = %q", files["one.conf"])
	}
}

// 符号链接必须被**跳过并记录**，而不是跟随。
//
// 跟随的后果：一个指向 /etc 的链接就能把整个 /etc 打进备份，
// 而用户以为自己只备份了一个小目录。
func TestCreateArchiveSkipsSymlink(t *testing.T) {
	if runtime_isWindows() {
		t.Skip("Windows 上创建符号链接需要特权，跳过")
	}
	src := t.TempDir()
	writeTree(t, src, map[string]string{"real.txt": "data"})
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "link.txt")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	res, err := CreateArchive(context.Background(), src, dst, ArchiveOptions{})
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, 期望 1", res.Skipped)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("跳过符号链接必须留下告警，实际没有")
	}
	files, _ := readArchive(t, dst)
	if _, ok := files["link.txt"]; ok {
		t.Fatalf("符号链接被跟随着打进了归档（应该跳过）")
	}
	if _, ok := files["real.txt"]; !ok {
		t.Fatalf("正常文件应该仍在归档里")
	}
}

// 源本身是符号链接时必须**明确拒绝**：用户配的是 /var/www，
// 而它指向别处，打出来的东西与他以为的不是同一份。
func TestCreateArchiveRejectsSymlinkSource(t *testing.T) {
	if runtime_isWindows() {
		t.Skip("Windows 上创建符号链接需要特权，跳过")
	}
	real := t.TempDir()
	writeTree(t, real, map[string]string{"x.txt": "1"})
	link := filepath.Join(t.TempDir(), "link-dir")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	_, err := CreateArchive(context.Background(), link, dst, ArchiveOptions{})
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("期望 ErrSourceUnavailable，实际 %v", err)
	}
}

// 超出条目数上限时必须失败，且**不留半成品归档**。
func TestCreateArchiveTooManyEntries(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[filepath.Join("f", strings.Repeat("x", i%5)+string(rune('a'+i%26))+".txt")] = "y"
	}
	writeTree(t, src, files)

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "out.tar.gz")
	_, err := CreateArchive(context.Background(), src, dst, ArchiveOptions{MaxEntries: 3})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("期望 ErrTooLarge，实际 %v", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("失败后不应留下半成品归档，实际它还在")
	}
}

// 超出体积上限时同样失败且不留半成品。
func TestCreateArchiveTooLarge(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"big.bin": strings.Repeat("A", 4096)})
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	_, err := CreateArchive(context.Background(), src, dst, ArchiveOptions{MaxBytes: 100})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("期望 ErrTooLarge，实际 %v", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("失败后不应留下半成品归档")
	}
}

func TestCreateArchiveMissingSource(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	_, err := CreateArchive(context.Background(), filepath.Join(t.TempDir(), "nope"), dst, ArchiveOptions{})
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("期望 ErrSourceUnavailable，实际 %v", err)
	}
}

func TestCreateArchiveEmptyDir(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "empty.tar.gz")
	res, err := CreateArchive(context.Background(), src, dst, ArchiveOptions{})
	if err != nil {
		t.Fatalf("空目录打包失败: %v", err)
	}
	if res.FileCount != 0 {
		t.Fatalf("空目录的 FileCount = %d, 期望 0", res.FileCount)
	}
	if _, statErr := os.Stat(dst); statErr != nil {
		t.Fatalf("空目录也应该产出归档文件: %v", statErr)
	}
}

// ---------------------------------------------------------------------------
// 恢复：安全判定（本模块最要紧的一组用例）
// ---------------------------------------------------------------------------

// makeMaliciousArchive 构造一个含指定条目的归档（测试专用）。
func makeMaliciousArchive(t *testing.T, entries []tar.Header, bodies map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, hdr := range entries {
		h := hdr
		if body, ok := bodies[h.Name]; ok {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("写归档头失败: %v", err)
		}
		if body, ok := bodies[h.Name]; ok {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatalf("写归档体失败: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// openLocal 构造一个"打开本地归档"的 restoreReader。
func openLocal(path string) restoreReader {
	return func() (io.ReadCloser, error) { return os.Open(path) }
}

// `../` 逃逸必须被拒绝，且**一个字节都不落盘**。
func TestRestoreRejectsDotDotEscape(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(base, "pwned.txt")

	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "../pwned.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"../pwned.txt": "owned"})

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复本身不该整体失败（应跳过该条目）: %v", err)
	}
	if res.Restored != 0 {
		t.Fatalf("逃逸条目被恢复了（Restored=%d）", res.Restored)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, 期望 1", res.Skipped)
	}
	if _, statErr := os.Stat(sentinel); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("逃逸文件被写到了目标目录之外：%s", sentinel)
	}
}

// 嵌套的 `a/../../evil` 同样必须被拒绝（只检查开头是不够的）。
func TestRestoreRejectsNestedDotDot(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "sub/../../evil.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"sub/../../evil.txt": "x"})

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Restored != 0 || res.Skipped != 1 {
		t.Fatalf("嵌套 .. 未被拒绝：restored=%d skipped=%d", res.Restored, res.Skipped)
	}
	if _, statErr := os.Stat(filepath.Join(base, "evil.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("嵌套逃逸写到了目标目录之外")
	}
}

// 绝对路径条目必须被拒绝。
func TestRestoreRejectsAbsolutePath(t *testing.T) {
	target := t.TempDir()
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "/tmp/lipanel-evil-absolute", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"/tmp/lipanel-evil-absolute": "x"})

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Skipped != 1 || res.Restored != 0 {
		t.Fatalf("绝对路径未被拒绝：restored=%d skipped=%d", res.Restored, res.Skipped)
	}
	if _, statErr := os.Stat("/tmp/lipanel-evil-absolute"); !errors.Is(statErr, os.ErrNotExist) {
		_ = os.Remove("/tmp/lipanel-evil-absolute")
		t.Fatalf("绝对路径条目被恢复了")
	}
}

// 符号链接条目必须被跳过（策略：跳过而非中止，让用户仍拿到其它数据）。
func TestRestoreSkipsSymlinkEntry(t *testing.T) {
	target := t.TempDir()
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "good.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
	}, map[string]string{"good.txt": "fine"})

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Restored != 1 {
		t.Fatalf("正常文件应被恢复，Restored=%d", res.Restored)
	}
	if res.Skipped != 1 {
		t.Fatalf("符号链接应被跳过，Skipped=%d", res.Skipped)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "evil-link")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("符号链接条目被恢复了")
	}
	if got, _ := os.ReadFile(filepath.Join(target, "good.txt")); string(got) != "fine" {
		t.Fatalf("正常文件内容不对: %q", got)
	}
}

// 设备节点必须被跳过：以 root"恢复"出一个块设备等于把整块磁盘交出去。
func TestRestoreSkipsDeviceEntry(t *testing.T) {
	target := t.TempDir()
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "sda", Typeflag: tar.TypeBlock, Mode: 0o660, Devmajor: 8, Devminor: 0},
	}, nil)

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Skipped != 1 || res.Restored != 0 {
		t.Fatalf("设备节点未被拒绝：restored=%d skipped=%d", res.Restored, res.Skipped)
	}
}

// 目标目录里**本来就存在**的符号链接不能被用来覆盖外部文件。
//
// 这是"归档干净、但目标位置脏"的场景：归档里叫 passwd 的普通文件
// 对应到目标目录里一个指向 /etc/passwd 的链接。经它写入 = root 改写任意文件。
func TestRestoreRefusesPreexistingSymlinkTarget(t *testing.T) {
	if runtime_isWindows() {
		t.Skip("Windows 上创建符号链接需要特权，跳过")
	}
	target := t.TempDir()
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "victim.txt")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}

	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "victim.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"victim.txt": "overwritten"})

	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Skipped != 1 {
		t.Fatalf("指向外部的已存在链接应被跳过，Skipped=%d", res.Skipped)
	}
	got, _ := os.ReadFile(outside)
	if string(got) != "original" {
		t.Fatalf("目标目录外的文件被经符号链接改写了: %q", got)
	}
}

// 反斜杠条目名被拒绝（Windows 工具打包的归档路径语义不确定）。
func TestRestoreRejectsBackslashName(t *testing.T) {
	target := t.TempDir()
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: `sub\evil.txt`, Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{`sub\evil.txt`: "x"})
	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Skipped != 1 {
		t.Fatalf("含反斜杠的条目应被跳过，Skipped=%d", res.Skipped)
	}
}

// ---------------------------------------------------------------------------
// 恢复：正常行为
// ---------------------------------------------------------------------------

// 打包 → 恢复 roundtrip：内容与权限位都要一致。
func TestRestoreRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"a.txt":       "hello",
		"sub/b.txt":   "world",
		"sub/c/d.txt": "deep",
	})
	// 一个 0600 的文件：权限位必须被保留。
	secret := filepath.Join(src, "id_rsa")
	if err := os.WriteFile(secret, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}

	arc := filepath.Join(t.TempDir(), "a.tar.gz")
	if _, err := CreateArchive(context.Background(), src, arc, ArchiveOptions{}); err != nil {
		t.Fatalf("打包失败: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restore")
	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Restored != 4 {
		t.Fatalf("Restored = %d, 期望 4", res.Restored)
	}
	for rel, want := range map[string]string{
		"a.txt": "hello", "sub/b.txt": "world",
		"sub/c/d.txt": "deep", "id_rsa": "PRIVATE",
	} {
		got, rerr := os.ReadFile(filepath.Join(target, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("读取恢复后的 %s 失败: %v", rel, rerr)
		}
		if string(got) != want {
			t.Fatalf("%s 内容 = %q, 期望 %q", rel, got, want)
		}
	}
	info, err := os.Stat(filepath.Join(target, "id_rsa"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限 = %04o, 期望 0600（用默认 0644 恢复私钥是一次真实的密钥泄露）",
			info.Mode().Perm())
	}
}

// 恢复**不删除**目标目录里不属于归档的文件。
//
// 这是备份工具最经典的事故：恢复一份三天前的备份，
// 连带删掉这三天里新产生的数据。
func TestRestoreKeepsUnrelatedFiles(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"from-backup.txt": "old"})
	arc := filepath.Join(t.TempDir(), "a.tar.gz")
	if _, err := CreateArchive(context.Background(), src, arc, ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	newer := filepath.Join(target, "created-after-backup.txt")
	if err := os.WriteFile(newer, []byte("important"), 0o644); err != nil {
		t.Fatal(err)
	}
	keepDir := filepath.Join(target, "keepdir")
	if err := os.MkdirAll(keepDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{}); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if got, _ := os.ReadFile(newer); string(got) != "important" {
		t.Fatalf("恢复把无关的新文件删掉或改掉了: %q", got)
	}
	if _, err := os.Stat(keepDir); err != nil {
		t.Fatalf("恢复把无关目录删掉了: %v", err)
	}
}

// 覆盖同名文件时如实计数（前端要拿它做红色警示的正文）。
func TestRestoreCountsOverwrites(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"same.txt": "new", "only.txt": "x"})
	arc := filepath.Join(t.TempDir(), "a.tar.gz")
	if _, err := CreateArchive(context.Background(), src, arc, ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "same.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Restore(context.Background(), openLocal(arc), target, RestoreOptions{})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if res.Overwritten != 1 {
		t.Fatalf("Overwritten = %d, 期望 1", res.Overwritten)
	}
	if res.Restored != 2 {
		t.Fatalf("Restored = %d, 期望 2", res.Restored)
	}
	got, _ := os.ReadFile(filepath.Join(target, "same.txt"))
	if string(got) != "new" {
		t.Fatalf("同名文件未被覆盖为归档内容: %q", got)
	}
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

// 预览必须**不落盘**，且要如实报出冲突与不可恢复条目。
func TestPreviewRestoreDoesNotWrite(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"a.txt": "1", "b.txt": "2"})
	arc := filepath.Join(t.TempDir(), "a.tar.gz")
	if _, err := CreateArchive(context.Background(), src, arc, ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "a.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	prev, err := PreviewRestore(context.Background(), openLocal(arc), target, "任务名", RestoreOptions{})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if prev.Total != 2 {
		t.Fatalf("Total = %d, 期望 2", prev.Total)
	}
	if prev.ConflictCount != 1 {
		t.Fatalf("ConflictCount = %d, 期望 1", prev.ConflictCount)
	}
	if len(prev.Conflicts) != 1 || prev.Conflicts[0] != "a.txt" {
		t.Fatalf("Conflicts = %v", prev.Conflicts)
	}
	if prev.ConfirmText != "任务名" {
		t.Fatalf("ConfirmText = %q", prev.ConfirmText)
	}
	if len(prev.Danger) == 0 {
		t.Fatalf("危险说明不能为空（前端直接展示它）")
	}
	// 预览绝不能创建 b.txt。
	if _, statErr := os.Stat(filepath.Join(target, "b.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("预览落盘了（b.txt 被创建）")
	}
	// 预览也不该改动已存在的文件。
	if got, _ := os.ReadFile(filepath.Join(target, "a.txt")); string(got) != "old" {
		t.Fatalf("预览改动了已存在的文件: %q", got)
	}
}

// 预览要列出恶意条目并标为 unsafe（用户有权知道包里有什么恢复不了）。
func TestPreviewMarksUnsafeEntries(t *testing.T) {
	target := t.TempDir()
	arc := makeMaliciousArchive(t, []tar.Header{
		{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "ok.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"../escape.txt": "x", "ok.txt": "y"})

	prev, err := PreviewRestore(context.Background(), openLocal(arc), target, "n", RestoreOptions{})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if prev.UnsafeCount != 1 {
		t.Fatalf("UnsafeCount = %d, 期望 1", prev.UnsafeCount)
	}
	if prev.SafeCount != 1 {
		t.Fatalf("SafeCount = %d, 期望 1", prev.SafeCount)
	}
	found := false
	for _, e := range prev.Entries {
		if e.Name == "../escape.txt" {
			found = true
			if !e.Unsafe || e.Reason == "" {
				t.Fatalf("逃逸条目未被标为 unsafe: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("预览没有列出逃逸条目")
	}
}

// ---------------------------------------------------------------------------
// 保留策略
// ---------------------------------------------------------------------------

// fakeBackend 是保留策略测试用的内存后端。
type fakeBackend struct {
	objects map[string]Object
	// failDelete 里的 key 删除时返回错误（用于验证"清理失败不阻断备份"）。
	failDelete map[string]bool
	deleted    []string
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{objects: map[string]Object{}, failDelete: map[string]bool{}}
}

func (f *fakeBackend) Type() string     { return "fake" }
func (f *fakeBackend) Describe() string { return "fake" }
func (f *fakeBackend) Close() error     { return nil }

func (f *fakeBackend) Put(_ context.Context, key string, r io.Reader, size int64) error {
	body, _ := io.ReadAll(r)
	f.objects[key] = Object{Key: key, Size: int64(len(body)), SizeKnown: true}
	return nil
}

func (f *fakeBackend) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	obj, ok := f.objects[key]
	if !ok {
		return nil, 0, ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(nil)), obj.Size, nil
}

func (f *fakeBackend) Stat(_ context.Context, key string) (Object, error) {
	obj, ok := f.objects[key]
	if !ok {
		return Object{}, ErrObjectNotFound
	}
	return obj, nil
}

func (f *fakeBackend) Delete(_ context.Context, key string) error {
	if f.failDelete[key] {
		return errors.New("模拟删除失败")
	}
	if _, ok := f.objects[key]; !ok {
		return nil // 幂等
	}
	delete(f.objects, key)
	f.deleted = append(f.deleted, key)
	return nil
}

func (f *fakeBackend) List(_ context.Context, prefix string) ([]Object, error) {
	out := []Object{}
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
		}
	}
	sortObjects(out)
	return out, nil
}

// seedArchives 造 n 份归档，时间从早到晚。
func seedArchives(t *testing.T, f *fakeBackend, task *Task, n int, base time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Hour)
		key := ArchiveKeyFor(task, ts)
		f.objects[key] = Object{Key: key, Size: 100, SizeKnown: true}
	}
}

func TestApplyRetentionKeepCount(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", Name: "t", KeepPolicy: KeepCount, KeepCount: 2}
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	seedArchives(t, fb, task, 5, base)

	res, err := ApplyRetention(context.Background(), fb, task, base.Add(10*time.Hour))
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if res.Deleted != 3 {
		t.Fatalf("Deleted = %d, 期望 3", res.Deleted)
	}
	if res.Kept != 2 {
		t.Fatalf("Kept = %d, 期望 2", res.Kept)
	}
	// 保留的必须是**最新的**两份。
	remaining, _ := fb.List(context.Background(), taskPrefix(task))
	if len(remaining) != 2 {
		t.Fatalf("剩下 %d 份，期望 2", len(remaining))
	}
	for _, obj := range remaining {
		ts, ok := archiveTime(obj.Key)
		if !ok {
			t.Fatalf("对象名解析不出时间戳: %s", obj.Key)
		}
		if ts.Before(base.Add(3 * time.Hour)) {
			t.Fatalf("保留了过旧的备份 %s（应该保留最新的）", obj.Key)
		}
	}
}

func TestApplyRetentionKeepDays(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", Name: "t", KeepPolicy: KeepDays, KeepDays: 2}
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.Local)
	// 造 6 份，跨度 5 天：只有最近 2 天内（3-09 之后）的该留下。
	for i := 0; i < 6; i++ {
		ts := now.AddDate(0, 0, -i)
		key := ArchiveKeyFor(task, ts)
		fb.objects[key] = Object{Key: key, Size: 1, SizeKnown: true}
	}

	res, err := ApplyRetention(context.Background(), fb, task, now)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if res.Kept != 3 { // 第 0、1、2 天（含今天）
		t.Fatalf("Kept = %d, 期望 3", res.Kept)
	}
	if res.Deleted != 3 {
		t.Fatalf("Deleted = %d, 期望 3", res.Deleted)
	}
}

func TestApplyRetentionNone(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", KeepPolicy: KeepNone}
	seedArchives(t, fb, task, 4, time.Now())
	res, err := ApplyRetention(context.Background(), fb, task, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 0 {
		t.Fatalf("KeepNone 不该删任何东西，Deleted=%d", res.Deleted)
	}
}

// 名字里解析不出时间戳的对象**必须保留**：我们不知道它是什么，
// 就不该替用户删掉它。
func TestApplyRetentionKeepsUnparseableNames(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", KeepPolicy: KeepDays, KeepDays: 1}
	now := time.Now()
	fb.objects["abc/手工放进来的文件.tar.gz"] = Object{Key: "abc/手工放进来的文件.tar.gz", Size: 1}
	seedArchives(t, fb, task, 1, now)

	res, err := ApplyRetention(context.Background(), fb, task, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fb.objects["abc/手工放进来的文件.tar.gz"]; !ok {
		t.Fatalf("手工放入的文件被删掉了（解析不出时间戳的一律保留）")
	}
	if res.Deleted != 0 {
		t.Fatalf("Deleted = %d, 期望 0", res.Deleted)
	}
}

// 单份删除失败必须记进 Errors，且**不影响**其它份的清理。
func TestApplyRetentionPartialFailure(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", KeepPolicy: KeepCount, KeepCount: 1}
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	seedArchives(t, fb, task, 3, base)
	// 让最老的一份删不掉。
	oldest := ArchiveKeyFor(task, base)
	fb.failDelete[oldest] = true

	res, err := ApplyRetention(context.Background(), fb, task, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("单份删除失败不该让整体返回错误: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %v, 期望 1 条", res.Errors)
	}
	if res.Deleted != 1 {
		t.Fatalf("Deleted = %d, 期望 1（另一份应仍被删掉）", res.Deleted)
	}
}

// 清理必须基于**存储上的真实清单**，而不是历史记录。
//
// 这条用例锁死的是：历史文件被清空后，清理依然能删掉旧备份。
// 反过来（按历史删）会让旧备份永远留在存储上，磁盘慢慢被吃满。
func TestApplyRetentionUsesStorageListingNotHistory(t *testing.T) {
	fb := newFakeBackend()
	task := &Task{ID: "abcdef123456", KeepPolicy: KeepCount, KeepCount: 1}
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	seedArchives(t, fb, task, 4, base)
	// 完全没有历史记录（模拟历史丢失）。

	res, err := ApplyRetention(context.Background(), fb, task, base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 3 {
		t.Fatalf("Deleted = %d, 期望 3（不依赖历史记录）", res.Deleted)
	}
}

// 两个任务共用同一个 prefix 时，清理**绝不能**动到对方的备份。
func TestRetentionScopedByTaskID(t *testing.T) {
	fb := newFakeBackend()
	t1 := &Task{ID: "aaaaaaaaaaaa", Name: "one", Prefix: "shared", KeepPolicy: KeepCount, KeepCount: 1}
	t2 := &Task{ID: "bbbbbbbbbbbb", Name: "two", Prefix: "shared", KeepPolicy: KeepCount, KeepCount: 1}
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	for i := 0; i < 3; i++ {
		fb.objects[ArchiveKeyFor(t1, base.Add(time.Duration(i)*time.Hour))] = Object{Size: 1}
		fb.objects[ArchiveKeyFor(t2, base.Add(time.Duration(i)*time.Hour))] = Object{Size: 1}
	}

	if _, err := ApplyRetention(context.Background(), fb, t1, base); err != nil {
		t.Fatal(err)
	}
	// t2 的 3 份必须原封不动。
	left, _ := fb.List(context.Background(), taskPrefix(t2))
	if len(left) != 3 {
		t.Fatalf("清理任务一时动了任务二的备份：剩下 %d 份，期望 3", len(left))
	}
}

func TestArchiveKeyForShape(t *testing.T) {
	task := &Task{ID: "abcdef123456", Prefix: "backups"}
	ts := time.Date(2026, 3, 5, 14, 30, 45, 0, time.Local)
	key := ArchiveKeyFor(task, ts)
	want := "backups/abcdef123456/abcdef123456-20260305-143045.tar.gz"
	if key != want {
		t.Fatalf("ArchiveKeyFor = %q, 期望 %q", key, want)
	}
	// 名字必须能反解出时间（保留策略依赖这一点）。
	got, ok := archiveTime(key)
	if !ok {
		t.Fatalf("archiveTime 解析失败: %s", key)
	}
	if !got.Equal(ts) {
		t.Fatalf("archiveTime = %v, 期望 %v", got, ts)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
