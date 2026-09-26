// 插件权限模型（阶段三 3.3）的单元测试。
//
// 这组用例锁的是「安全判定」本身：权限语法、规则表的最长前缀匹配、
// 默认拒绝、以及最重要的——资源段不参与匹配这一**有意为之**的语义
// （见 permission.go 文件头的能力边界说明）。
//
// 为什么这些断言值得逐条钉死：权限规则的任何一条被改坏，表现都是
// 「某个接口突然 403」或更糟的「本该拒绝的请求被放行」，而后者
// 不会有任何报错，只会在某天变成安全事故。
package plugin

import (
	"strings"
	"testing"
)

// TestParsePermissionValid 覆盖合法权限声明的解析。
func TestParsePermissionValid(t *testing.T) {
	cases := []struct {
		raw      string
		domain   string
		action   string
		resource string
	}{
		{"system.read", "system", "read", ""},
		{"process.read", "process", "read", ""},
		{"process.exec:/usr/bin/systemctl", "process", "exec", "/usr/bin/systemctl"},
		{"file.read:/etc/nginx", "file", "read", "/etc/nginx"},
		{"file.write:/var/log/lipanel", "file", "write", "/var/log/lipanel"},
		{"http.call", "http", "call", ""},
		{"network.read", "network", "read", ""},
		{"service.write", "service", "write", ""},
		// 前后空白应当被裁剪，而不是报错：插件作者在 manifest 里
		// 手写数组时很容易带上空格。
		{"  system.read  ", "system", "read", ""},
	}

	for _, c := range cases {
		p, err := ParsePermission(c.raw)
		if err != nil {
			t.Errorf("ParsePermission(%q) 失败: %v", c.raw, err)
			continue
		}
		if p.Domain != c.domain || p.Action != c.action || p.Resource != c.resource {
			t.Errorf("ParsePermission(%q) = {%s %s %s}, 期望 {%s %s %s}",
				c.raw, p.Domain, p.Action, p.Resource, c.domain, c.action, c.resource)
		}
		if p.Key() != c.domain+"."+c.action {
			t.Errorf("Key() = %q, 期望 %q", p.Key(), c.domain+"."+c.action)
		}
	}
}

// TestParsePermissionInvalid 覆盖非法声明的拒绝。
func TestParsePermissionInvalid(t *testing.T) {
	cases := []struct {
		raw    string
		reason string
	}{
		{"", "空串"},
		{"   ", "全空白"},
		{"system", "缺少动作段"},
		{"system.", "动作段为空"},
		{".read", "域为空"},
		{"sytem.read", "域拼错（未知域）"},
		{"system", "缺少点"},
		{"system.read.extra", "多级动作"},
		{"System.Read", "大写（语法要求小写域）"},
		{"system.read:", "资源段为空"},
		{"system read", "含空格"},
		{"system.read\nfile.write", "含换行（日志注入）"},
		{"system.read;rm -rf /", "含 shell 元字符"},
		{strings.Repeat("a", 200) + ".read", "超长"},
	}

	for _, c := range cases {
		if _, err := ParsePermission(c.raw); err == nil {
			t.Errorf("ParsePermission(%q) 应当报错（%s），实际通过", c.raw, c.reason)
		}
	}
}

// TestParsePermissionRootResource 验证「资源段是 / 」这种边界写法。
//
// 语法上 "system.read:/" 是合法的（资源段非空、字符集合法），
// 它等价于「不限资源」。这里把它显式钉住，是为了说明解析层不做
// 语义解释——资源当前不参与匹配（见 TestPermissionResourceNotMatchable），
// 因此 / 与省略资源在行为上完全一致，解析层没必要为此报错。
func TestParsePermissionRootResource(t *testing.T) {
	p, err := ParsePermission("system.read:/")
	if err != nil {
		t.Fatalf("system.read:/ 语法合法，不该报错: %v", err)
	}
	if p.Resource != "/" {
		t.Errorf("Resource = %q, 期望 %q", p.Resource, "/")
	}
	if p.Key() != "system.read" {
		t.Errorf("Key() = %q, 期望 system.read", p.Key())
	}
}

// TestParsePermissionsDedup 验证重复声明被拒绝。
//
// 刻意选择「报错」而不是「静默去重」：重复通常是复制粘贴忘改，
// 静默去重会让插件作者以为自己声明了另一条权限，排查成本极高。
func TestParsePermissionsDedup(t *testing.T) {
	// 同一条重复。
	if _, err := ParsePermissions([]string{"system.read", "system.read"}); err == nil {
		t.Error("重复声明同一条权限应当报错")
	}
	// 不同资源但同域.动作：仍然算重复（资源不参与匹配，见 Permission.Key）。
	if _, err := ParsePermissions([]string{"file.read:/a", "file.read:/b"}); err == nil {
		t.Error("同一「域.动作」声明两次（资源不同）应当报错")
	}
	// 逗号分隔的简写应当被展开。
	set, err := ParsePermissions([]string{"system.read, process.read"})
	if err != nil {
		t.Fatalf("逗号分隔写法应当被接受: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("Len() = %d, 期望 2", set.Len())
	}
}

// TestPermissionSetZeroValueDenies 验证零值权限集合的行为。
//
// 零值必须可用且**默认拒绝**：newProcess/entry 等结构在权限字段
// 未赋值时是零值，如果零值表示"全部放行"，权限体系会整体失效。
func TestPermissionSetZeroValueDenies(t *testing.T) {
	var empty PermissionSet
	if !empty.Empty() {
		t.Error("零值 PermissionSet 应当是空的")
	}
	if empty.Has("system.read") {
		t.Error("零值 PermissionSet 不应包含任何权限（默认拒绝）")
	}
	if empty.HasAny("system.read", "process.read") {
		t.Error("零值 PermissionSet 的 HasAny 应为 false")
	}
	if got := empty.Strings(); len(got) != 0 {
		t.Errorf("零值 PermissionSet 的 Strings() 应为空，实际 %v", got)
	}
}

// TestRequiredPermission 覆盖规则表判定。
func TestRequiredPermission(t *testing.T) {
	cases := []struct {
		method   string
		path     string
		wantPerm string
		wantOK   bool // ok=false 表示免校验
	}{
		// 骨架接口：由 plugin.Serve 统一提供，插件无权实现，必须免校验。
		{"GET", "/healthz", "", false},
		{"HEAD", "/healthz", "", false},
		{"GET", "/whoami", "", false},
		// 前端资源：宿主对插件的固定调用。
		{"GET", "/assets/plugin.js", "", false},
		{"GET", "/assets/sub/dir/a.png", "", false},

		// 明确的业务规则。
		{"GET", "/runtime", "process.read", true},
		{"GET", "/info", "system.read", true},
		{"GET", "/echo", "system.read", true},
		{"GET", "/services", "service.read", true},
		{"POST", "/services", "service.write", true},
		{"GET", "/files", "file.read", true},
		{"DELETE", "/files/a.txt", "file.write", true},

		// 方法不匹配时回落到兜底权限（而不是免校验）。
		{"POST", "/info", "system.read", true},

		// 规则表未命中 → 兜底权限，且仍需要校验（默认拒绝的落点）。
		{"GET", "/unknown-endpoint", "system.read", true},
		{"POST", "/whatever", "system.read", true},
	}

	for _, c := range cases {
		perm, ok := RequiredPermission(c.method, c.path)
		if ok != c.wantOK {
			t.Errorf("RequiredPermission(%s %s) ok = %v, 期望 %v", c.method, c.path, ok, c.wantOK)
			continue
		}
		if perm != c.wantPerm {
			t.Errorf("RequiredPermission(%s %s) = %q, 期望 %q", c.method, c.path, perm, c.wantPerm)
		}
	}
}

// TestRequiredPermissionPrefixBoundary 验证前缀匹配不会误伤。
//
// "/files-backup" 不该命中 "/files" 的规则——那种误伤会让一个
// 完全无关的接口莫名其妙需要 file.read 权限，且极难定位。
func TestRequiredPermissionPrefixBoundary(t *testing.T) {
	perm, ok := RequiredPermission("GET", "/files-backup")
	if !ok {
		t.Fatal("/files-backup 不该免校验")
	}
	if perm != fallbackPermission {
		t.Errorf("/files-backup 应当回落到兜底权限 %q，实际 %q", fallbackPermission, perm)
	}

	// 但 /files/x 必须命中 file.read。
	if perm, _ := RequiredPermission("GET", "/files/x"); perm != "file.read" {
		t.Errorf("/files/x 应当命中 file.read，实际 %q", perm)
	}
}

// TestCheckPermission 覆盖放行与拒绝两条路径。
func TestCheckPermission(t *testing.T) {
	granted, err := ParsePermissions([]string{"system.read", "process.read"})
	if err != nil {
		t.Fatalf("解析权限失败: %v", err)
	}

	// --- 放行 ---
	dec := CheckPermission("sysinfo", granted, "GET", "/info")
	if !dec.Allowed {
		t.Errorf("GET /info 应当放行（已声明 system.read），实际: %+v", dec)
	}
	if dec.Required != "system.read" {
		t.Errorf("Required = %q, 期望 system.read", dec.Required)
	}

	// 骨架接口免校验。
	dec = CheckPermission("sysinfo", granted, "GET", "/healthz")
	if !dec.Allowed || !dec.Exempt {
		t.Errorf("骨架接口应当免校验放行，实际: %+v", dec)
	}

	// 前端资源免校验。
	dec = CheckPermission("sysinfo", granted, "GET", "/assets/plugin.js")
	if !dec.Allowed || !dec.Exempt {
		t.Errorf("前端资源应当免校验放行，实际: %+v", dec)
	}

	// --- 拒绝 ---
	dec = CheckPermission("sysinfo", granted, "GET", "/files")
	if dec.Allowed {
		t.Error("未声明 file.read，GET /files 应当被拒绝")
	}
	if dec.Required != "file.read" {
		t.Errorf("Required = %q, 期望 file.read", dec.Required)
	}
	if dec.Reason == "" || dec.Hint == "" {
		t.Errorf("拒绝时必须给出 reason 与 hint（前端要展示），实际: %+v", dec)
	}
	// 提示里必须写明能力边界，避免被理解成内核级沙箱。
	if !strings.Contains(dec.Hint, "不是内核级沙箱") {
		t.Errorf("hint 应当说明能力边界，实际: %q", dec.Hint)
	}
}

// TestCheckPermissionEmptySet 验证「未声明任何权限」的拒绝路径。
func TestCheckPermissionEmptySet(t *testing.T) {
	var none PermissionSet

	dec := CheckPermission("bare", none, "GET", "/info")
	if dec.Allowed {
		t.Error("未声明任何权限的插件，业务接口应当被拒绝")
	}
	if !strings.Contains(dec.Reason, "未声明任何权限") {
		t.Errorf("Reason 应当指出「未声明任何权限」，实际: %q", dec.Reason)
	}

	// 但骨架接口与前端资源仍要放行——
	// 否则连健康探测都做不了，插件在管理页会永远显示"未知状态"。
	if dec := CheckPermission("bare", none, "GET", "/healthz"); !dec.Allowed {
		t.Error("骨架接口对未声明权限的插件也必须放行")
	}
	if dec := CheckPermission("bare", none, "GET", "/assets/plugin.js"); !dec.Allowed {
		t.Error("前端资源对未声明权限的插件也必须放行")
	}
}

// TestPermissionResourceNotMatchable 锁定「资源段不参与匹配」这一有意设计。
//
// 这条用例的作用是防止将来有人「顺手」把资源段接进匹配逻辑：
// 当前核心无法验证插件是否真的只用了资源段里的路径（插件是独立进程，
// 核心看不到它的系统调用），把资源并入匹配只会制造「校验很细」的假象。
// 如果将来真的实现了内核级沙箱，这条用例应当被**显式修改**而不是悄悄删掉。
func TestPermissionResourceNotMatchable(t *testing.T) {
	granted, err := ParsePermissions([]string{"file.read:/etc/nginx"})
	if err != nil {
		t.Fatalf("解析权限失败: %v", err)
	}

	// 声明了 file.read:/etc/nginx 后，任意 file.read 请求都被放行——
	// 包括 /etc/shadow。这是当前设计的**已知且已声明**的局限。
	dec := CheckPermission("demo", granted, "GET", "/files")
	if !dec.Allowed {
		t.Error("声明了 file.read:<资源> 后，file.read 级别的请求应当放行（资源不参与匹配）")
	}
	if dec.Required != "file.read" {
		t.Errorf("Required = %q, 期望 file.read（不含资源段）", dec.Required)
	}
}

// TestKnownDomainsSorted 验证错误提示里的域列表稳定有序。
//
// map 遍历顺序随机，若不排序，同一个错误在两次运行里会显示不同内容，
// 测试会变成随机失败。
func TestKnownDomainsSorted(t *testing.T) {
	ds := knownDomains()
	if len(ds) == 0 {
		t.Fatal("knownDomains 不应为空")
	}
	for i := 1; i < len(ds); i++ {
		if ds[i-1] >= ds[i] {
			t.Errorf("knownDomains 未排序: %v", ds)
			break
		}
	}
}
