package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 路径安全测试（阶段四 4.2 的核心）
// ============================================================================
//
// 本文件是整个模块最重要的测试：其他功能坏了是"不好用"，
// 路径校验坏了是"服务器被接管"。
//
// 测试策略：在 t.TempDir() 里搭出真实的目录与符号链接，
// 用真实路径去撞校验器——**不用 mock**。
// 路径校验的正确性依赖 os.Lstat / EvalSymlinks 的真实行为
// （例如"链接指向不存在目标时 Lstat 成功而 Stat 失败"），
// mock 掉这些等于把要验证的东西假设掉了。

// newTestLayout 搭一个测试用目录树：
//
//	root/
//	  inside.txt
//	  sub/
//	    deep.txt
//	    link-out      -> ../outside      （逃逸链接：指向根外）
//	    link-in       -> ../inside.txt   （根内链接：合法）
//	    link-dead     -> ../nonexistent  （失效链接）
//	outside/
//	  secret.txt
//
// 返回 (root, outside)。
func newTestLayout(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()

	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	sub := filepath.Join(root, "sub")

	for _, d := range []string{root, outside, sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("创建目录 %s 失败: %v", d, err)
		}
	}
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("写入 %s 失败: %v", p, err)
		}
	}
	write(filepath.Join(root, "inside.txt"), "inside")
	write(filepath.Join(sub, "deep.txt"), "deep")
	write(filepath.Join(outside, "secret.txt"), "secret")

	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(sub, name)); err != nil {
			t.Skipf("当前环境不支持符号链接，跳过: %v", err)
		}
	}
	link(filepath.Join("..", "..", "outside"), "link-out")
	link(filepath.Join("..", "inside.txt"), "link-in")
	link(filepath.Join("..", "nonexistent"), "link-dead")

	return root, outside
}

func mustResolver(t *testing.T, roots ...string) *Resolver {
	t.Helper()
	r, err := NewResolver(roots)
	if err != nil {
		t.Fatalf("NewResolver(%v) 失败: %v", roots, err)
	}
	return r
}

// ---------------------------------------------------------------------------
// 词法逃逸
// ---------------------------------------------------------------------------

func TestResolveRejectsTraversal(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	cases := []struct {
		name string
		path string
	}{
		// 经典的 ../ 上游
		{"上级目录", filepath.Join(root, "..", "outside", "secret.txt")},
		{"多级上级", filepath.Join(root, "sub", "..", "..", "outside", "secret.txt")},
		{"直达根", "/etc/passwd"},
		{"父目录本身", filepath.Join(root, "..")},
		// Clean 之后才暴露的形态：中间穿插 ./
		{"点段混淆", filepath.Join(root, "sub", ".", "..", "..", "outside")},
		// 以根名为前缀的兄弟目录（Strings.HasPrefix 会在此翻车）
		{"前缀混淆", root + "-evil/secret.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Resolve(tc.path)
			if err == nil {
				t.Fatalf("路径 %q 应当被拒绝，但通过了", tc.path)
			}
			if !errors.Is(err, ErrOutsideRoot) && !errors.Is(err, ErrSymlinkEscape) {
				t.Fatalf("期望 ErrOutsideRoot/ErrSymlinkEscape，实际: %v", err)
			}
		})
	}
}

func TestResolvePrefixConfusion(t *testing.T) {
	// 专门锁死"前缀匹配"这类漏洞：/tmp/x/root 与 /tmp/x/root-evil
	// 若用 strings.HasPrefix 判定，后者会被误判为在前者之下。
	base := t.TempDir()
	root := filepath.Join(base, "root")
	sibling := filepath.Join(base, "root-evil")
	for _, d := range []string{root, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(sibling, "x.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := mustResolver(t, root)
	if _, err := r.Resolve(target); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("兄弟目录 %s 应被判定为越界，实际 err=%v", target, err)
	}
}

func TestResolveRejectsRelativeAndMalformed(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	cases := []struct {
		name string
		path string
		want error
	}{
		{"空路径", "", ErrEmptyPath},
		{"纯空白", "   ", ErrEmptyPath},
		{"相对路径", "etc/passwd", ErrRelativePath},
		{"单点相对", "./inside.txt", ErrRelativePath},
		{"含 NUL", root + "/inside\x00.txt", ErrInvalidPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Resolve(tc.path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("路径 %q：期望 %v，实际 %v", tc.path, tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 符号链接逃逸
// ---------------------------------------------------------------------------

func TestResolveSymlinkEscape(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	// 这个路径**字面上完全在根内**，只有解析链接才能发现它指向根外。
	escape := filepath.Join(root, "sub", "link-out")
	if _, err := r.Resolve(escape); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("指向根外的符号链接应被拒绝，实际 err=%v", err)
	}

	// 经链接访问链接里的文件：同样必须被拒绝。
	deepEscape := filepath.Join(escape, "secret.txt")
	if _, err := r.Resolve(deepEscape); err == nil {
		t.Fatalf("经逃逸链接访问 %q 应当被拒绝，但通过了", deepEscape)
	}
}

func TestResolveSymlinkInsideAllowed(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	// 根内的合法链接必须放行——否则这个保护会变成"所有链接都不能用"，
	// 而站点目录里链接是极常见的部署形态。
	got, err := r.Resolve(filepath.Join(root, "sub", "link-in"))
	if err != nil {
		t.Fatalf("根内符号链接应被放行，实际: %v", err)
	}
	want := filepath.Join(root, "inside.txt")
	if got != want {
		t.Fatalf("应解析为真实路径 %s，实际 %s", want, got)
	}
}

func TestResolveRejectsSymlinkRootParentEscape(t *testing.T) {
	// 更隐蔽的一种：链接指向"根的父目录"而不是完全无关的目录。
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "up")); err != nil {
		t.Skip("环境不支持符号链接")
	}

	r := mustResolver(t, root)
	if _, err := r.Resolve(filepath.Join(root, "up", "file.txt")); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("指向根父目录的链接应被拒绝，实际 err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// 创建型路径（目标尚不存在）
// ---------------------------------------------------------------------------

func TestResolveForCreate(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	t.Run("不存在的叶子在根内可放行", func(t *testing.T) {
		target := filepath.Join(root, "sub", "brand-new.txt")
		got, err := r.ResolveForCreate(target)
		if err != nil {
			t.Fatalf("应放行，实际 %v", err)
		}
		if got != target {
			t.Fatalf("期望 %s，实际 %s", target, got)
		}
	})

	t.Run("多层不存在的父目录仍在根内可放行", func(t *testing.T) {
		target := filepath.Join(root, "a", "b", "c", "d.txt")
		got, err := r.ResolveForCreate(target)
		if err != nil {
			t.Fatalf("应放行，实际 %v", err)
		}
		if got != target {
			t.Fatalf("期望 %s，实际 %s", target, got)
		}
	})

	t.Run("经逃逸链接创建必须被拒绝", func(t *testing.T) {
		// 这是最关键的一条：/root/sub/link-out 指向根外，
		// "在 link-out 下新建文件"若只做词法校验就会通过，
		// 实际却会在根外建出文件。
		target := filepath.Join(root, "sub", "link-out", "evil.txt")
		_, err := r.ResolveForCreate(target)
		if err == nil {
			t.Fatal("经逃逸链接创建路径必须被拒绝，但通过了")
		}
		if !errors.Is(err, ErrSymlinkEscape) && !errors.Is(err, ErrOutsideRoot) {
			t.Fatalf("期望 ErrSymlinkEscape/ErrOutsideRoot，实际 %v", err)
		}
	})

	t.Run("根外路径被拒绝", func(t *testing.T) {
		if _, err := r.ResolveForCreate("/tmp/whatever-lipanel-test"); !errors.Is(err, ErrOutsideRoot) {
			t.Fatalf("根外创建路径应被拒绝，实际 %v", err)
		}
	})

	t.Run("相对路径被拒绝", func(t *testing.T) {
		if _, err := r.ResolveForCreate("relative/new.txt"); !errors.Is(err, ErrRelativePath) {
			t.Fatalf("相对路径应被拒绝，实际 %v", err)
		}
	})

	t.Run("失效链接作为叶子：在根内按名字创建", func(t *testing.T) {
		// link-dead 指向不存在的目标。创建同名文件时，
		// 我们期望的行为是：ResolveForCreate 拿到的是链接所在目录 + 名字，
		// 因此解析不会去跟随那个坏链接。
		target := filepath.Join(root, "sub", "link-dead")
		if _, err := r.ResolveForCreate(target); err != nil {
			t.Fatalf("失效链接的路径本身在根内，应可解析用于创建，实际 %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 根目录自身的规范化
// ---------------------------------------------------------------------------

func TestNewResolverRejectsBadRoots(t *testing.T) {
	root, _ := newTestLayout(t)

	cases := []struct {
		name  string
		roots []string
	}{
		{"没有根目录", nil},
		{"空字符串根目录", []string{"  "}},
		{"相对路径根目录", []string{"relative/dir"}},
		{"不存在的根目录", []string{filepath.Join(root, "does-not-exist")}},
		{"文件而非目录", []string{filepath.Join(root, "inside.txt")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewResolver(tc.roots); err == nil {
				t.Fatalf("根目录 %v 应当被拒绝", tc.roots)
			}
		})
	}
}

func TestResolverHandlesSymlinkedRoot(t *testing.T) {
	// 管理员把根写成符号链接（/var/www -> /srv/www）是常见写法。
	// 若不把根自身解析成真实路径，所有访问都会因
	// "字面路径 vs 真实路径" 对不上而被误判为逃逸。
	base := t.TempDir()
	real := filepath.Join(base, "real-root")
	link := filepath.Join(base, "link-root")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip("环境不支持符号链接")
	}

	r := mustResolver(t, link)
	got, err := r.Resolve(filepath.Join(link, "f.txt"))
	if err != nil {
		t.Fatalf("经符号链接根目录访问应放行，实际 %v", err)
	}
	if want := filepath.Join(real, "f.txt"); got != want {
		t.Fatalf("期望解析为 %s，实际 %s", want, got)
	}
}

func TestResolverMultipleRoots(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "a")
	b := filepath.Join(base, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := mustResolver(t, a, b)

	for _, d := range []string{a, b} {
		if _, err := r.Resolve(filepath.Join(d, "f.txt")); err != nil {
			t.Fatalf("根 %s 内的路径应放行，实际 %v", d, err)
		}
	}
	// 根的公共父目录不在白名单内。
	if _, err := r.Resolve(filepath.Join(base, "a", "f.txt")); err != nil {
		// a/f.txt 在根 a 内，应当放行。
		t.Fatalf("根内路径应放行，实际 %v", err)
	}
	if _, err := r.Resolve(base); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("公共父目录应越界，实际 %v", err)
	}
}

func TestResolverDeduplicatesRoots(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip("环境不支持符号链接")
	}
	// 同一目录的两个名字（真实路径与链接）应当只保留一个，
	// 而不是让"根目录列表"里出现重复项。
	r := mustResolver(t, real, link)
	if got := len(r.Roots()); got != 1 {
		t.Fatalf("同一目录的重复根应被去重，实际保留 %d 个", got)
	}
}

func TestContainsHelper(t *testing.T) {
	cases := []struct {
		base, target string
		want         bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/bc", false},
		{"/a/b", "/a", false},
		{"/a/b", "/a/b/../c", false}, // 未 Clean 时 Rel 会给出 ..
		{"/", "/anything", true},
	}
	for _, tc := range cases {
		if got := contains(tc.base, tc.target); got != tc.want {
			t.Errorf("contains(%q, %q) = %v，期望 %v", tc.base, tc.target, got, tc.want)
		}
	}
}

func TestValidateName(t *testing.T) {
	ok := []string{"a.txt", ".env", "中文 文件.txt", "a-b_c.d", strings.Repeat("x", 255)}
	for _, name := range ok {
		if err := validateName(name); err != nil {
			t.Errorf("名称 %q 应被接受，实际 %v", name, err)
		}
	}
	bad := []string{"", ".", "..", "a/b", "a\x00b", strings.Repeat("x", 256)}
	for _, name := range bad {
		if err := validateName(name); err == nil {
			t.Errorf("名称 %q 应被拒绝", name)
		}
	}
}

func TestRelForDisplay(t *testing.T) {
	root, _ := newTestLayout(t)
	r := mustResolver(t, root)

	if got := r.Rel(root); got != "/" {
		t.Fatalf("根目录的相对路径应为 /，实际 %q", got)
	}
	if got := r.Rel(filepath.Join(root, "sub", "deep.txt")); got != "/sub/deep.txt" {
		t.Fatalf("期望 /sub/deep.txt，实际 %q", got)
	}
	// 不属于任何根时返回空字符串（调用方据此判断"不在展示范围内"）。
	if got := r.Rel("/tmp"); got != "" {
		t.Fatalf("根外路径应返回空字符串，实际 %q", got)
	}
}
