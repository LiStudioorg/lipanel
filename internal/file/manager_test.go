package file

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 文件操作测试（阶段四 4.2）
// ============================================================================
//
// 这些用例覆盖的是"功能对不对"，而 root_test.go 覆盖的是"边界守不守得住"。
// 两类都必须有：只有安全测试会漏掉"正常操作根本用不了"，
// 只有功能测试会漏掉"能用，但能越权用"。

func newTestManager(t *testing.T, roots ...string) *Manager {
	t.Helper()
	m, err := NewManager(ManagerOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// 列目录
// ---------------------------------------------------------------------------

func TestList(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)

	listing, err := m.List(root)
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	if listing.Path != root {
		t.Fatalf("Path 应为 %s，实际 %s", root, listing.Path)
	}
	// 根目录自身就是白名单根，没有上级可去。
	if listing.Parent != "" {
		t.Fatalf("根目录的 Parent 应为空，实际 %q", listing.Parent)
	}

	names := map[string]Entry{}
	for _, e := range listing.Entries {
		names[e.Name] = e
	}
	if _, ok := names["inside.txt"]; !ok {
		t.Fatalf("缺少 inside.txt，实际条目: %v", listing.Entries)
	}
	if e := names["sub"]; !e.IsDir {
		t.Fatalf("sub 应为目录，实际 %+v", e)
	}
	if e := names["inside.txt"]; e.Type != "file" || !e.Editable {
		t.Fatalf("inside.txt 应为可编辑文件，实际 %+v", e)
	}
	if listing.Total != 2 {
		t.Fatalf("Total 应为 2，实际 %d", listing.Total)
	}
}

func TestListSortsDirectoriesFirst(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "zebra.txt"), "z")
	writeFile(t, filepath.Join(root, "apple.txt"), "a")
	if err := os.Mkdir(filepath.Join(root, "mmm"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, root)

	listing, err := m.List(root)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(listing.Entries))
	for _, e := range listing.Entries {
		got = append(got, e.Name)
	}
	want := []string{"mmm", "apple.txt", "zebra.txt"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("排序应为 %v，实际 %v", want, got)
	}
}

func TestListSubdirectoryHasParent(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)

	listing, err := m.List(filepath.Join(root, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if listing.Parent != root {
		t.Fatalf("子目录的 Parent 应为 %s，实际 %q", root, listing.Parent)
	}
}

func TestListOnFileFails(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)

	_, err := m.List(filepath.Join(root, "inside.txt"))
	if !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("对文件列目录应返回 ErrNotDirectory，实际 %v", err)
	}
}

func TestListMarksSymlinks(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)

	listing, err := m.List(filepath.Join(root, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Entry{}
	for _, e := range listing.Entries {
		byName[e.Name] = e
	}

	// 根内链接：展示为 symlink 类型，且不是"失效"的。
	if e := byName["link-in"]; e.Type != "symlink" || e.Broken {
		t.Fatalf("link-in 应为有效符号链接，实际 %+v", e)
	}
	// 指向根外的链接：必须标成 Broken（不可操作），
	// 否则用户会看到一个能点、点下去必然 400 的条目。
	if e := byName["link-out"]; e.Type != "symlink" || !e.Broken {
		t.Fatalf("link-out 应标记为 Broken，实际 %+v", e)
	}
	if e := byName["link-dead"]; !e.Broken {
		t.Fatalf("link-dead 应标记为 Broken，实际 %+v", e)
	}
}

func TestListTruncates(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		writeFile(t, filepath.Join(root, "f"+string(rune('a'+i))+".txt"), "x")
	}
	m, err := NewManager(ManagerOptions{Roots: []string{root}, MaxListEntries: 3})
	if err != nil {
		t.Fatal(err)
	}
	listing, err := m.List(root)
	if err != nil {
		t.Fatal(err)
	}
	if !listing.Truncated || len(listing.Entries) != 3 || listing.Total != 10 {
		t.Fatalf("应截断为 3/10，实际 %+v", listing)
	}
	if listing.MaxListEntries != 3 {
		t.Fatalf("应回显上限 3，实际 %d", listing.MaxListEntries)
	}
}

// ---------------------------------------------------------------------------
// 读取
// ---------------------------------------------------------------------------

func TestReadText(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	writeFile(t, path, "hello 世界\n")
	m := newTestManager(t, root)

	got, err := m.ReadText(path)
	if err != nil {
		t.Fatalf("ReadText 失败: %v", err)
	}
	if got.Content != "hello 世界\n" {
		t.Fatalf("内容不符: %q", got.Content)
	}
	if got.Size != int64(len("hello 世界\n")) {
		t.Fatalf("大小不符: %d", got.Size)
	}
}

func TestReadTextRejectsBinary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bin.dat")
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02, 0xff}, 0o644); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, root)

	if _, err := m.ReadText(path); !errors.Is(err, ErrBinaryFile) {
		t.Fatalf("二进制文件应被拒绝，实际 %v", err)
	}
}

func TestReadTextRejectsInvalidUTF8(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bad.txt")
	// 合法的 UTF-8 之外：孤立的续字节序列。
	if err := os.WriteFile(path, []byte{0x41, 0xC3, 0x28, 0x42}, 0o644); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, root)
	if _, err := m.ReadText(path); !errors.Is(err, ErrBinaryFile) {
		t.Fatalf("非法 UTF-8 应被拒绝，实际 %v", err)
	}
}

func TestReadTextRejectsTooLarge(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "big.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerOptions{Roots: []string{root}, MaxEditBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadText(path); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超限文件应被拒绝，实际 %v", err)
	}
}

func TestReadTextExactlyAtLimit(t *testing.T) {
	// 边界用例：刚好等于上限必须能读（不能因为"多读一个字节"的实现
	// 把合法文件误判为超限）。
	root := t.TempDir()
	path := filepath.Join(root, "exact.txt")
	content := strings.Repeat("a", 1024)
	writeFile(t, path, content)
	m, err := NewManager(ManagerOptions{Roots: []string{root}, MaxEditBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadText(path)
	if err != nil {
		t.Fatalf("刚好等于上限的文件应可读，实际 %v", err)
	}
	if got.Content != content {
		t.Fatal("内容被截断")
	}
}

func TestReadTextRejectsDirectory(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)
	if _, err := m.ReadText(filepath.Join(root, "sub")); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("对目录读文本应被拒绝，实际 %v", err)
	}
}

// ---------------------------------------------------------------------------
// 写入
// ---------------------------------------------------------------------------

func TestWriteTextCreatesFile(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	path := filepath.Join(root, "new.txt")

	res, err := m.WriteText(path, []byte("hello"), false)
	if err != nil {
		t.Fatalf("WriteText 失败: %v", err)
	}
	if !res.Created {
		t.Fatal("应标记为新建")
	}
	if res.Size != 5 {
		t.Fatalf("大小应为 5，实际 %d", res.Size)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("内容不符: %q", data)
	}
	// 新建文件应为 0644：面板创建的文件不该是 0600（web 服务器读不到），
	// 也不该带可执行位。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("新建文件权限应为 0644，实际 %04o", info.Mode().Perm())
	}
}

func TestWriteTextRefusesOverwriteWithoutFlag(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	writeFile(t, path, "original")
	m := newTestManager(t, root)

	_, err := m.WriteText(path, []byte("new"), false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("未确认覆盖时应返回 ErrExists，实际 %v", err)
	}
	// 关键断言：拒绝时原文件必须**一个字节都没变**。
	data, _ := os.ReadFile(path)
	if string(data) != "original" {
		t.Fatalf("被拒绝的写入修改了文件内容: %q", data)
	}
}

func TestWriteTextOverwriteKeepsMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "script.sh")
	writeFile(t, path, "#!/bin/sh\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, root)

	if _, err := m.WriteText(path, []byte("#!/bin/sh\necho hi\n"), true); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 保存文本不该把脚本的可执行位抹掉——那是用户会在生产上踩到的坑。
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("覆盖写入应保留 0755，实际 %04o", info.Mode().Perm())
	}
}

func TestWriteTextRejectsOversize(t *testing.T) {
	root := t.TempDir()
	m, err := NewManager(ManagerOptions{Roots: []string{root}, MaxEditBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.WriteText(filepath.Join(root, "big.txt"), bytes.Repeat([]byte("a"), 32), false)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超限写入应被拒绝，实际 %v", err)
	}
}

func TestWriteTextRejectsNUL(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	_, err := m.WriteText(filepath.Join(root, "x.txt"), []byte("a\x00b"), false)
	if !errors.Is(err, ErrBinaryFile) {
		t.Fatalf("含 NUL 的内容应被拒绝，实际 %v", err)
	}
}

func TestWriteTextRejectsDirectoryTarget(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)
	_, err := m.WriteText(filepath.Join(root, "sub"), []byte("x"), true)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("覆盖目录应被拒绝，实际 %v", err)
	}
}

func TestWriteTextMissingParentDirectory(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	// 父目录不存在：应报 ErrNotExist（由 server 翻译成 404），
	// 而不是悄悄建出一棵树。
	_, err := m.WriteText(filepath.Join(root, "nope", "x.txt"), []byte("x"), false)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("父目录不存在应返回 ErrNotExist，实际 %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "nope")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("不应创建缺失的父目录")
	}
}

func TestWriteTextIsAtomic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	writeFile(t, path, "v1")
	m := newTestManager(t, root)

	if _, err := m.WriteText(path, []byte("v2"), true); err != nil {
		t.Fatal(err)
	}
	// 原子写不留临时文件。
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lipanel-") {
			t.Fatalf("残留临时文件: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// 新建目录
// ---------------------------------------------------------------------------

func TestMkdir(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	target := filepath.Join(root, "newdir")

	entry, err := m.Mkdir(target, false)
	if err != nil {
		t.Fatalf("Mkdir 失败: %v", err)
	}
	if !entry.IsDir {
		t.Fatal("返回条目应为目录")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("目录权限应为 0755，实际 %04o", info.Mode().Perm())
	}
}

func TestMkdirExisting(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	target := filepath.Join(root, "dup")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Mkdir(target, false); !errors.Is(err, ErrExists) {
		t.Fatalf("已存在应返回 ErrExists，实际 %v", err)
	}
}

func TestMkdirRequiresParentUnlessAll(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	target := filepath.Join(root, "a", "b", "c")

	// 默认不建中间层级。
	if _, err := m.Mkdir(target, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("默认应因父目录缺失而失败，实际 %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("不应创建任何中间目录")
	}

	// 显式 all=true 才递归创建。
	if _, err := m.Mkdir(target, true); err != nil {
		t.Fatalf("all=true 应成功，实际 %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatal("目录未创建")
	}
}

// ---------------------------------------------------------------------------
// 重命名
// ---------------------------------------------------------------------------

func TestRename(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	oldPath := filepath.Join(root, "old.txt")
	writeFile(t, oldPath, "content")

	entry, err := m.Rename(oldPath, "new.txt", false)
	if err != nil {
		t.Fatalf("Rename 失败: %v", err)
	}
	if entry.Name != "new.txt" {
		t.Fatalf("返回名称应为 new.txt，实际 %s", entry.Name)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("旧路径应已不存在")
	}
	data, err := os.ReadFile(filepath.Join(root, "new.txt"))
	if err != nil || string(data) != "content" {
		t.Fatalf("内容应保留，实际 %q err=%v", data, err)
	}
}

func TestRenameRejectsPathInNewName(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	oldPath := filepath.Join(root, "a.txt")
	writeFile(t, oldPath, "x")

	for _, bad := range []string{"../evil.txt", "sub/x.txt", "", ".", "..", "a\x00b"} {
		if _, err := m.Rename(oldPath, bad, false); err == nil {
			t.Fatalf("新名字 %q 应被拒绝", bad)
		}
	}
	// 拒绝后原文件必须还在。
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal("被拒绝的重命名不应影响原文件")
	}
}

func TestRenameTargetExists(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	writeFile(t, a, "A")
	writeFile(t, b, "B")

	if _, err := m.Rename(a, "b.txt", false); !errors.Is(err, ErrExists) {
		t.Fatalf("目标已存在应返回 ErrExists，实际 %v", err)
	}
	// 未确认覆盖时 b 的内容必须没变。
	if data, _ := os.ReadFile(b); string(data) != "B" {
		t.Fatalf("被拒绝的重命名覆盖了目标: %q", data)
	}

	if _, err := m.Rename(a, "b.txt", true); err != nil {
		t.Fatalf("确认覆盖后应成功，实际 %v", err)
	}
	if data, _ := os.ReadFile(b); string(data) != "A" {
		t.Fatalf("覆盖后内容应为 A，实际 %q", data)
	}
}

func TestRenameSameNameIsNoop(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	p := filepath.Join(root, "a.txt")
	writeFile(t, p, "x")

	entry, err := m.Rename(p, "a.txt", false)
	if err != nil {
		t.Fatalf("同名重命名应为无操作，而不是报错，实际 %v", err)
	}
	if entry.Name != "a.txt" {
		t.Fatalf("名称应为 a.txt，实际 %s", entry.Name)
	}
}

// ---------------------------------------------------------------------------
// 删除
// ---------------------------------------------------------------------------

func TestDeleteFile(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	p := filepath.Join(root, "a.txt")
	writeFile(t, p, "x")

	if err := m.Delete(p, false); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("文件应已删除")
	}
}

func TestDeleteEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	d := filepath.Join(root, "empty")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(d, false); err != nil {
		t.Fatalf("删除空目录应成功，实际 %v", err)
	}
}

func TestDeleteNonEmptyDirectoryRequiresRecursive(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	d := filepath.Join(root, "full")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "x.txt"), "x")

	if err := m.Delete(d, false); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("非空目录应要求 recursive，实际 %v", err)
	}
	// 被拒绝时目录与内容必须完好无损。
	if _, err := os.Stat(filepath.Join(d, "x.txt")); err != nil {
		t.Fatal("被拒绝的删除不应影响目录内容")
	}

	if err := m.Delete(d, true); err != nil {
		t.Fatalf("recursive=true 应成功，实际 %v", err)
	}
	if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("目录应已删除")
	}
}

func TestDeleteSymlinkRemovesLinkNotTarget(t *testing.T) {
	// 这是删除逻辑里最重要的一条：删链接必须只删链接。
	// 若跟随链接，用户在站点目录里删掉一个指向 /etc 的链接，
	// 实际删掉的就是 /etc 里的东西。
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	victim := filepath.Join(outside, "secret.txt")
	writeFile(t, victim, "secret")
	link := filepath.Join(root, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Skip("环境不支持符号链接")
	}

	m := newTestManager(t, root)
	// 指向根外的链接，删除请求本身应被路径校验拒绝。
	if err := m.Delete(link, false); err == nil {
		t.Fatal("指向根外的链接应被路径校验拒绝")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("目标文件必须完好无损: %v", err)
	}

	// 指向根内的链接：允许删除，但只删链接本身。
	inside := filepath.Join(root, "real.txt")
	writeFile(t, inside, "keep me")
	linkIn := filepath.Join(root, "link-in")
	if err := os.Symlink(inside, linkIn); err != nil {
		t.Skip("环境不支持符号链接")
	}
	if err := m.Delete(linkIn, false); err != nil {
		t.Fatalf("删除根内链接应成功，实际 %v", err)
	}
	if _, err := os.Lstat(linkIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("链接本身应已删除")
	}
	if data, err := os.ReadFile(inside); err != nil || string(data) != "keep me" {
		t.Fatalf("链接目标必须保留，实际 %q err=%v", data, err)
	}
}

func TestDeleteDanglingSymlink(t *testing.T) {
	// 失效链接（指向不存在的目标）在列表里很常见，
	// 必须能被删掉——否则用户永远清理不掉这些垃圾条目。
	root := t.TempDir()
	link := filepath.Join(root, "dead")
	if err := os.Symlink(filepath.Join(root, "nonexistent"), link); err != nil {
		t.Skip("环境不支持符号链接")
	}
	m := newTestManager(t, root)
	if err := m.Delete(link, false); err != nil {
		t.Fatalf("删除失效链接应成功，实际 %v", err)
	}
}

func TestDeleteMissing(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	if err := m.Delete(filepath.Join(root, "nope.txt"), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("删除不存在的路径应返回 ErrNotExist，实际 %v", err)
	}
}

// ---------------------------------------------------------------------------
// 上传
// ---------------------------------------------------------------------------

func TestUpload(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)

	res, err := m.Upload(UploadOptions{
		Path:     root,
		Filename: "up.txt",
		Reader:   strings.NewReader("uploaded content"),
	})
	if err != nil {
		t.Fatalf("Upload 失败: %v", err)
	}
	if res.Size != int64(len("uploaded content")) {
		t.Fatalf("大小不符: %d", res.Size)
	}
	data, err := os.ReadFile(filepath.Join(root, "up.txt"))
	if err != nil || string(data) != "uploaded content" {
		t.Fatalf("内容不符: %q err=%v", data, err)
	}
	info, _ := os.Stat(res.Path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("上传文件权限应为 0644，实际 %04o", info.Mode().Perm())
	}
}

func TestUploadRefusesOverwriteWithoutFlag(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "original")
	m := newTestManager(t, root)

	_, err := m.Upload(UploadOptions{
		Path: root, Filename: "a.txt", Reader: strings.NewReader("new"),
	})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("未确认覆盖应返回 ErrExists，实际 %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "a.txt")); string(data) != "original" {
		t.Fatalf("被拒绝的上传修改了文件: %q", data)
	}
}

func TestUploadEnforcesLimit(t *testing.T) {
	root := t.TempDir()
	m, err := NewManager(ManagerOptions{Roots: []string{root}, MaxUploadBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Upload(UploadOptions{
		Path: root, Filename: "big.bin", Reader: strings.NewReader(strings.Repeat("x", 64)),
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超限上传应被拒绝，实际 %v", err)
	}
	// 关键：被拒绝的上传不能在磁盘上留下任何东西（哪怕半截文件）。
	if _, err := os.Stat(filepath.Join(root, "big.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("被拒绝的上传不应留下目标文件")
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lipanel-upload-") {
			t.Fatalf("被拒绝的上传留下临时文件: %s", e.Name())
		}
	}
}

func TestUploadRejectsBadFilename(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	for _, bad := range []string{"", ".", "..", "a/b", "../escape.txt"} {
		_, err := m.Upload(UploadOptions{
			Path: root, Filename: bad, Reader: strings.NewReader("x"),
		})
		if err == nil {
			t.Fatalf("文件名 %q 应被拒绝", bad)
		}
	}
}

func TestUploadRejectsNonDirectoryTarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "x")
	m := newTestManager(t, root)

	_, err := m.Upload(UploadOptions{
		Path: filepath.Join(root, "f.txt"), Filename: "a.txt", Reader: strings.NewReader("x"),
	})
	if !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("目标不是目录应被拒绝，实际 %v", err)
	}
}

func TestUploadIntoEscapingSymlinkDir(t *testing.T) {
	// 上传是"创建型"操作，最容易踩经链接逃逸的坑：
	// 目标目录是个指向根外的符号链接时，必须拒绝。
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "esc")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("环境不支持符号链接")
	}
	m := newTestManager(t, root)

	_, err := m.Upload(UploadOptions{
		Path: link, Filename: "evil.txt", Reader: strings.NewReader("payload"),
	})
	if err == nil {
		t.Fatal("经逃逸链接上传必须被拒绝")
	}
	if _, statErr := os.Stat(filepath.Join(outside, "evil.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("根外目录中不应出现上传的文件")
	}
}

// ---------------------------------------------------------------------------
// 下载句柄
// ---------------------------------------------------------------------------

func TestOpenForDownload(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a.txt")
	writeFile(t, p, "download me")
	m := newTestManager(t, root)

	f, info, err := m.OpenForDownload(p)
	if err != nil {
		t.Fatalf("OpenForDownload 失败: %v", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil || string(data) != "download me" {
		t.Fatalf("内容不符: %q err=%v", data, err)
	}
	if info.Size() != int64(len("download me")) {
		t.Fatalf("大小不符: %d", info.Size())
	}
}

func TestOpenForDownloadRejectsDirectory(t *testing.T) {
	root, _ := newTestLayout(t)
	m := newTestManager(t, root)
	if _, _, err := m.OpenForDownload(filepath.Join(root, "sub")); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("下载目录应被拒绝，实际 %v", err)
	}
}

// ---------------------------------------------------------------------------
// 限制与错误分类
// ---------------------------------------------------------------------------

func TestLimitsDefaults(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	limits := m.Limits()
	if limits.MaxUploadBytes != DefaultMaxUploadBytes {
		t.Fatalf("默认上传上限不符: %d", limits.MaxUploadBytes)
	}
	if limits.MaxEditBytes != DefaultMaxEditBytes {
		t.Fatalf("默认编辑上限不符: %d", limits.MaxEditBytes)
	}
	if limits.MaxListEntries != DefaultMaxListEntries {
		t.Fatalf("默认列表上限不符: %d", limits.MaxListEntries)
	}
}

func TestNewManagerRequiresRoots(t *testing.T) {
	if _, err := NewManager(ManagerOptions{}); err == nil {
		t.Fatal("没有根目录时构造应失败（默认拒绝，而不是默认放行）")
	}
}

func TestClassifyErrorNil(t *testing.T) {
	if err := ClassifyError(nil); err != nil {
		t.Fatalf("nil 应原样返回 nil，实际 %v", err)
	}
}

func TestPathTooLong(t *testing.T) {
	root := t.TempDir()
	m := newTestManager(t, root)
	long := filepath.Join(root, strings.Repeat("a", maxPathBytes+10))
	if _, err := m.List(long); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("超长路径应返回 ErrInvalidPath，实际 %v", err)
	}
}
