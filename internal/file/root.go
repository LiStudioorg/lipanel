// Package file 提供面板的文件管理能力（阶段四 4.2，核心自带）。
//
// 本包是整个文件管理模块的**安全底线**所在地：
// 它把「用户能碰到的文件范围」收敛为一组可配置的根目录（白名单），
// 所有操作（列目录、读、写、新建、重命名、删除、上传、下载）都必须
// 先经过 Root.Resolve 系列方法的校验，任何一步不通过就直接拒绝。
//
// # 威胁模型
//
// 面板以 root（或具备等同权限的用户）运行，因此「路径校验漏一个」的后果
// 不是「看到不该看的文件」，而是**以 root 身份读写任意文件**——可以直接
// 改写 /etc/passwd、往 ~/.ssh/authorized_keys 追加公钥、覆盖 systemd 单元。
// 因此这里的原则是：**白名单之外的路径一律拒绝，而不是过滤掉危险的片段**。
//
// 三类逃逸必须分别堵死（只堵一类是不够的）：
//
//  1. **词法逃逸**："/etc/passwd"、"/var/www/../../etc/shadow"。
//     靠 Clean + Rel 判定「是否仍在根目录之下」拦截。
//  2. **符号链接逃逸**：根目录内放一个指向 /etc 的链接，路径字面上完全正常。
//     靠对已存在的部分再做一次 EvalSymlinks + 包含性判定拦截。
//  3. **创建型逃逸**：写文件/新建目录/上传/改名时目标尚不存在，
//     EvalSymlinks 会直接失败，若不特判就会"校验失败即放行"或"报错拒绝一切"。
//     正确做法是对**最近一个已存在的祖先**做真实解析，再把剩余段拼回去复验。
//
// # 一处诚实的局限：TOCTOU
//
// 校验（stat/EvalSymlinks）与真正执行 open(2) 之间存在时间窗口：
// 同机攻击者若能在目标目录里抢先在窗口内放入符号链接，理论上可以换掉目标。
// 彻底消除需要 openat2(RESOLVE_BENEATH/RESOLVE_NO_SYMLINKS)（stdlib 未暴露，
// 需 golang.org/x/sys/unix）或 Go 1.24 的 os.Root（会把 go.mod 从 1.23 顶上去，
// 而 1.23 正是为了对齐 CI 才降下来的，见「已知坑位」38）。
// 两者都与本项目「零新增依赖 + go 1.23」的约束冲突，因此本次**不引入**，
// 但把话说清楚：
//   - 静态符号链接逃逸（真实攻击面：面板用户自己建链接再访问）**已被完全拦截**，
//     由 TestResolveSymlinkEscape 等用例锁死；
//   - 残余窗口要求攻击者已能在受管目录内创建文件，且需要在微秒级完成竞态，
//     属于本阶段的已知取舍，而不是被忽略的缺口。
package file

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 路径校验的哨兵错误。
//
// 分成多个而不是一个笼统的 ErrInvalidPath：调用方要据此给出**不同的提示**
// （"路径越界"与"符号链接指向根目录外"对用户来说是完全不同的两件事，
// 后者往往意味着服务器上真的存在一个可疑的链接，值得单独告警）。
var (
	// ErrEmptyPath 表示路径为空。
	ErrEmptyPath = errors.New("file: 路径不能为空")
	// ErrRelativePath 表示传入了相对路径。
	//
	// 刻意**不支持**相对路径：面板里"当前目录"是前端状态，
	// 后端若也维护一份就会产生两份可能不一致的真相，
	// 而路径校验最怕的就是真相不止一个。
	ErrRelativePath = errors.New("file: 必须是绝对路径（以 / 开头）")
	// ErrInvalidPath 表示路径形态非法（含 NUL 字节、无法 Clean 等）。
	ErrInvalidPath = errors.New("file: 路径形态非法")
	// ErrOutsideRoot 表示路径落在全部白名单根目录之外（词法层面）。
	ErrOutsideRoot = errors.New("file: 路径超出允许的根目录范围")
	// ErrSymlinkEscape 表示路径经符号链接解析后落在了根目录之外。
	ErrSymlinkEscape = errors.New("file: 符号链接指向了允许范围之外")
	// ErrNoRoot 表示没有配置任何根目录。
	ErrNoRoot = errors.New("file: 未配置任何允许的根目录")
)

// DefaultRoot 是 -file-root 未指定时的默认根目录。
//
// 默认给 "/"（整机可管理）：面板管理员本来就该能管理服务器上的文件，
// 这与 systemd 服务管理能操作任意单元是一致的授权粒度。
// 但它是**最容易被忽视的一处授权**，因此 main 在生效时会打一条 WARN，
// 提示用户可以用 -file-root 收窄到具体目录。
//
// 安全边界并不因此变松：即便根是 "/"，`../` 越权、符号链接逃逸、
// 相对路径等仍然全部被拒——白名单决定的是"授权范围"，
// 而路径校验决定的是"能不能绕过这个范围"，两者是独立的两道闸门。
const DefaultRoot = "/"

// Root 是一个已规范化（绝对路径 + Clean + 真实路径）的允许根目录。
//
// 注意 resolved 字段：构造时就把根目录自身解析成真实路径。
// 若管理员把根目录写成一个符号链接（例如 /var/www 指向 /srv/www），
// 那么凡是经该链接访问的路径在 EvalSymlinks 之后都会变成 /srv/www/...，
// 用未解析的 /var/www 去做前缀判定会把**正常访问全部误判为逃逸**。
type Root struct {
	// Path 是配置里给出的原始路径（Clean 后的绝对路径），用于展示与拼装。
	Path string
	// resolved 是 Path 经 EvalSymlinks 得到的真实路径，用于包含性判定。
	resolved string
}

// String 返回便于日志展示的根目录。
func (r Root) String() string { return r.Path }

// Resolver 在一组白名单根目录内做路径校验。
//
// 为什么是「多根」而不是单一根：面板常见需求是同时管理
// /home 下的站点与 /etc/nginx 的配置，单根会逼用户把根设成 /。
// 多根的判定代价只是几微秒的字符串比较，收益是权限可以收得更紧。
type Resolver struct {
	roots []Root
}

// NewResolver 构造路径解析器。
//
// 它会：① 拒绝相对路径；② 对每个根做 EvalSymlinks 得到真实路径；
// ③ 按长度降序排列，保证最长前缀优先（/home/user 优先于 /home）。
//
// 根目录**必须已存在**：一个不存在的根只会在用户操作时报出令人困惑的
// ENOENT，不如启动/构造阶段就明确报错。
func NewResolver(roots []string) (*Resolver, error) {
	if len(roots) == 0 {
		return nil, ErrNoRoot
	}

	seen := make(map[string]bool, len(roots))
	list := make([]Root, 0, len(roots))
	for _, raw := range roots {
		r, err := newRoot(raw)
		if err != nil {
			return nil, err
		}
		if seen[r.resolved] {
			// 去重而不是报错：/var/www 与 /srv/www（同一目录的链接）
			// 同时出现在配置里是合理的写法，按一个根处理即可。
			continue
		}
		seen[r.resolved] = true
		list = append(list, r)
	}

	// 最长路径优先：判定包含关系时先试最具体的根，
	// 否则 /home 会先把 /home/user/www 的路径"吃掉"，
	// 虽然结果同样是允许，但展示给用户/审计的根目录就不准确了。
	sort.SliceStable(list, func(i, j int) bool {
		return len(list[i].resolved) > len(list[j].resolved)
	})
	return &Resolver{roots: list}, nil
}

// newRoot 校验并规范化单个根目录。
func newRoot(raw string) (Root, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return Root{}, fmt.Errorf("%w: 根目录为空", ErrInvalidPath)
	}
	if strings.ContainsRune(p, 0) {
		return Root{}, fmt.Errorf("%w: 根目录含 NUL 字节", ErrInvalidPath)
	}
	if !filepath.IsAbs(p) {
		return Root{}, fmt.Errorf("%w: 根目录 %q 不是绝对路径", ErrRelativePath, p)
	}
	clean := filepath.Clean(p)

	info, err := os.Stat(clean)
	if err != nil {
		return Root{}, fmt.Errorf("file: 根目录 %s 不可用: %w", clean, err)
	}
	if !info.IsDir() {
		return Root{}, fmt.Errorf("file: 根目录 %s 不是目录", clean)
	}

	// 解析真实路径：管理员把根写成符号链接是常见写法（/var/www -> /srv/www），
	// 不解析的话后面所有 EvalSymlinks 结果都对不上，正常访问会被全盘拒绝。
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return Root{}, fmt.Errorf("file: 解析根目录 %s 的真实路径失败: %w", clean, err)
	}
	return Root{Path: clean, resolved: filepath.Clean(resolved)}, nil
}

// Roots 返回全部根目录（副本，调用方修改不影响内部状态）。
func (r *Resolver) Roots() []Root {
	if r == nil {
		return nil
	}
	out := make([]Root, len(r.roots))
	copy(out, r.roots)
	return out
}

// normalize 做与根目录校验同等口径的**词法**检查：非空、绝对、无 NUL。
//
// 注意这里不做 Clean 之外的任何"纠错"：像 "/etc/../etc/passwd" 这种写法
// 会被 Clean 成 /etc/passwd 后正常参与判定——Clean 是**规范化**不是**放行**，
// 真正的放行与否由后面的包含性检查决定。
func normalize(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", ErrEmptyPath
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: 含 NUL 字节", ErrInvalidPath)
	}
	if !filepath.IsAbs(p) {
		return "", ErrRelativePath
	}
	return filepath.Clean(p), nil
}

// contains 判断 real 是否等于 base 或位于 base 之下。
//
// 为什么用 filepath.Rel 而不是 strings.HasPrefix：
//
//	HasPrefix("/home/user", "/home/us") == true —— 把 /home/us 的路径
//	误判为在 /home/user 之下。这类前缀混淆是路径校验里最经典的漏洞，
//	Rel 会返回 "../us"，一看便知。
func contains(base, real string) bool {
	rel, err := filepath.Rel(base, real)
	if err != nil {
		// 理论不可达（两者都是绝对路径）：出错时按"不包含"处理，
		// 也就是默认拒绝，方向是安全的。
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// rootFor 找一个在**词法层面**（未解析符号链接）包含 clean 的根。
func (r *Resolver) rootFor(clean string) (Root, bool) {
	for _, root := range r.roots {
		if contains(root.Path, clean) || contains(root.resolved, clean) {
			return root, true
		}
	}
	return Root{}, false
}

// Resolve 校验一个**已存在**的路径，并返回它的真实路径。
//
// 语义：路径本身必须存在（内部调用 EvalSymlinks）。
// 读文件、删除、下载等"目标必须存在"的操作请用 ResolveExisting，
// 它和本方法是同一份实现，只是名字把意图写明。
//
// 三步（顺序不能调换）：
//
//  1. 词法规范化 + 判断是否落在某个根目录之下 → 否则 ErrOutsideRoot；
//  2. EvalSymlinks 解析真实路径（这一步才真正揭穿符号链接）；
//  3. 对真实路径**再判一次**是否落在根目录之下 → 否则 ErrSymlinkEscape。
//
// 第 3 步是符号链接防护的落点：`/allowed/link` 字面上在根内（第 1 步放行），
// 但它指向 /etc，解析后是 /etc（第 3 步拒绝）。少了任何一步都会留下逃逸口子。
//
// 返回的真实路径用于后续的所有文件系统操作——**不跟随**原始路径，
// 避免"校验用一个路径、操作用另一个路径"这种最危险的写法。
func (r *Resolver) Resolve(p string) (string, error) {
	clean, err := normalize(p)
	if err != nil {
		return "", err
	}
	if _, ok := r.rootFor(clean); !ok {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, clean)
	}

	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		// 不在这里把 fs.ErrNotExist 转成 404：本函数既可能被
		// "必须存在"的调用方（读、删除）使用，也可能被
		// "父目录存在即可"的调用方使用（ResolveForCreate 会先兜住）。
		// 错误语义交给上层翻译，这里保持原样（保留 %w 链）。
		return "", fmt.Errorf("file: 解析路径 %s 失败: %w", clean, err)
	}
	real = filepath.Clean(real)

	if _, ok := r.rootFor(real); !ok {
		return "", fmt.Errorf("%w: %s 实际指向 %s", ErrSymlinkEscape, clean, real)
	}
	return real, nil
}

// ResolveExisting 与 Resolve 等价，存在的意义是**把调用方的意图写进代码**：
// 读文件、删除、下载、进目录都必须走这个入口（目标不存在即失败），
// 而"目标可以不存在"的写操作走 ResolveForCreate。
// 两个名字并列，Review 时一眼能看出某处用的是哪一种语义。
func (r *Resolver) ResolveExisting(p string) (string, error) {
	return r.Resolve(p)
}

// ResolveForCreate 校验一个**将被创建**（或写为改名目标）的路径。
//
// 与 Resolve 的差别只在第 2 步：目标（可能连同若干层父目录）尚不存在，
// 直接 EvalSymlinks 必然失败。因此改为：
//
//	从目标向上找到**最近的一个已存在祖先** → 解析它的真实路径
//	→ 把剩余的不存在段拼回去 → 再判一次包含性。
//
// 这一步不能省：假设根是 /home，攻击者建了 /home/evil -> /etc，
// 那么 "新建目录 /home/evil/cron.d" 若只做词法校验就会通过，
// 实际创建的却是 /etc/cron.d——这正是"校验通过、操作跑偏"的经典形态。
//
// **目标自身已存在时直接返回词法路径**（不解析符号链接）：
// 调用方（覆盖写、重命名目标）要操作的就是那个条目本身，
// 是否允许跟随链接由调用方按业务语义决定。两处典型的正确用法：
//
//   - WriteText：用 Lstat 认出"这是个链接"，再显式解析目标并校验，
//     从而拒绝覆盖设备文件、拒绝把写入悄悄变成"写链接指向的任意文件"；
//   - Rename：目标已存在时要么报 ErrExists，要么按用户确认覆盖，
//     两种情况下都不该先把链接解析掉。
func (r *Resolver) ResolveForCreate(p string) (string, error) {
	clean, err := normalize(p)
	if err != nil {
		return "", err
	}
	if _, ok := r.rootFor(clean); !ok {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, clean)
	}

	// 向上找最近的已存在祖先。
	//
	// ⚠️ 必须用 Lstat 而不是 Stat：对**失效的符号链接**，
	// Lstat 只 stat 链接本身（成功），Stat 会去 stat 它的目标（失败）。
	// 用 Stat 的话 /root/sub/link-dead（指向不存在的目标）会被当成
	// "不存在"，于是继续向上走到 sub，再把 "link-dead" 当作待创建的段——
	// 而 EvalSymlinks("/root/sub/link-dead") 会**跟随那个坏链接**
	// 并因目标不存在而失败，最终把一次合法的"覆盖这个失效链接"的写入
	// 变成 500。
	//
	// 用 Lstat 还有一层正确性：即使链接指向**根外**的某个存在路径，
	// 这里停下来后下面的 EvalSymlinks 解析出的目标仍会被包含性检查拒绝，
	// 因此"停得早"不会放过任何逃逸，只是把判定交给真正该判定的那一步。
	existing := clean
	rest := ""
	for {
		if _, statErr := os.Lstat(existing); statErr == nil {
			break
		} else if !errors.Is(statErr, os.ErrNotExist) {
			// 权限不足等其它错误：按"无法确认安全"处理，直接拒绝。
			// 这里绝不能"出错就当成存在"继续走下去。
			return "", fmt.Errorf("file: 检查路径 %s 失败: %w", existing, statErr)
		}

		parent := filepath.Dir(existing)
		if parent == existing {
			// 已经到根（"/"）却仍不存在：不可能，防御性返回。
			return "", fmt.Errorf("%w: 无法确定 %s 的已存在祖先", ErrInvalidPath, clean)
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}

	// 已存在祖先本身必须是**符号链接之外的真实目录**，或用户想直接操作的那个链接。
	//
	// 分两种情况：
	//   ① rest == ""：目标自身已存在（含"是个（可能失效的）符号链接"）。
	//      此时不解析它——调用方要操作的就是这个链接本身
	//      （删除链接、覆盖链接都是合法操作）。是否允许跟随由调用方决定。
	//   ② rest != ""：目标不存在，祖先必须解析成真实目录，
	//      否则会出现"经链接在根外建目录"的逃逸。
	if rest == "" {
		return clean, nil
	}

	realExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("file: 解析路径 %s 失败: %w", existing, err)
	}
	// 已存在祖先本身就必须在根内（例如根是 /home/user/www 时，
	// 祖先 /home/user 虽在文件系统上存在，却不在根内 → 拒绝）。
	if _, ok := r.rootFor(filepath.Clean(realExisting)); !ok {
		return "", fmt.Errorf("%w: %s 实际位于 %s", ErrSymlinkEscape, existing, realExisting)
	}

	real := filepath.Clean(filepath.Join(realExisting, rest))
	if _, ok := r.rootFor(real); !ok {
		return "", fmt.Errorf("%w: %s", ErrSymlinkEscape, real)
	}
	return real, nil
}

// ResolveForRemoval 校验一个**将被删除**的路径。
//
// 与 ResolveExisting 的差别只有一处，但这一处是必须的：
//
//	ResolveExisting 会 EvalSymlinks，遇到**失效的符号链接**
//	（指向一个不存在的目标）必然失败；
//	而删除这种链接是完全合法且必要的操作——否则站点目录里
//	那些"指向早已删除文件"的链接在面板上永远清理不掉。
//
// 判定规则依然严格，**不存在"解析不了就放行"的漏洞**：
//
//   - Lstat 失败（路径真的不存在）→ 原样返回错误（上层翻译成 404）；
//   - 不是符号链接 → 走完整 Resolve（词法 + 符号链接复核）；
//   - 是符号链接 → ① 链接本身必须落在白名单根内（词法判定）；
//     ② 若目标存在，目标也必须落在白名单内。
//
// 第 ② 条是防"经链接删掉根外文件"的关键：指针指向根外且目标存在时会被拒；
// 目标不存在时根外没有任何东西会被删掉，此时删除链接**本身**是安全的。
func (r *Resolver) ResolveForRemoval(p string) (string, error) {
	clean, err := normalize(p)
	if err != nil {
		return "", err
	}
	if _, ok := r.rootFor(clean); !ok {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, clean)
	}

	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("file: 读取 %s 失败: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		// 普通条目：走完整校验（含符号链接复核，覆盖父目录是链接的情形）。
		return r.Resolve(clean)
	}

	// 符号链接：目标存在时也必须复核目标位置。
	if resolved, evalErr := filepath.EvalSymlinks(clean); evalErr == nil {
		resolved = filepath.Clean(resolved)
		if _, ok := r.rootFor(resolved); !ok {
			return "", fmt.Errorf("%w: %s 实际指向 %s", ErrSymlinkEscape, clean, resolved)
		}
	}
	return clean, nil
}

// Rel 返回路径相对于其所属根目录的展示用相对路径（以 / 开头）。
//
// 仅用于界面展示（前端路径栏）；返回空字符串表示不属于任何根。
// 它不参与任何安全判定，调用方**绝不可**用它来替代 Resolve 的结果。
func (r *Resolver) Rel(real string) string {
	for _, root := range r.roots {
		for _, base := range []string{root.resolved, root.Path} {
			if contains(base, real) {
				rel, err := filepath.Rel(base, real)
				if err != nil {
					continue
				}
				if rel == "." {
					return "/"
				}
				return "/" + filepath.ToSlash(rel)
			}
		}
	}
	return ""
}
