package site

import (
	"strings"
	"testing"
)

// ============================================================================
// 配置生成测试（阶段四 4.3）
// ============================================================================
//
// 本文件验证两件事：
//
//  1. **正常站点生成正确的配置**——字段完整、语法可用、能过 nginx -t
//     （端到端由 manager_test.go + 真实 nginx 覆盖）。
//  2. **畸形输入进不去模板**——Render 自己再校验一遍，即使调用方漏了。

// staticSite 返回一个合法的静态站定义。
func staticSite() Site {
	return Site{
		Name:   "demo",
		Domain: "demo.example.com",
		Type:   TypeStatic,
		Root:   "/var/www/demo",
	}
}

// proxySite 返回一个合法的反代站定义。
func proxySite() Site {
	return Site{
		Name:     "api",
		Domain:   "api.example.com",
		Type:     TypeProxy,
		Upstream: "http://127.0.0.1:3000",
	}
}

// TestRenderStaticSite 验证静态站配置的关键要素。
func TestRenderStaticSite(t *testing.T) {
	out, err := Render(staticSite(), RenderOptions{})
	if err != nil {
		t.Fatalf("生成静态站配置失败: %v", err)
	}

	mustContain(t, out, "server {")
	mustContain(t, out, "listen 80;")
	mustContain(t, out, "server_name demo.example.com;")
	mustContain(t, out, "root /var/www/demo;")
	mustContain(t, out, "index index.html index.htm;")
	// try_files 的 `=404` 不能少：缺了它，文件不存在时 nginx 会
	// 回落到目录索引（表现为 403 或目录列表），而不是明确的 404。
	mustContain(t, out, "try_files $uri $uri/ =404;")
	// 生成标记必须存在，列表接口靠它区分"面板生成"与"用户手写"。
	mustContain(t, out, GeneratedMarker)
	// 静态站不应出现反代指令。
	mustNotContain(t, out, "proxy_pass")
}

// TestRenderProxySite 验证反代站配置的关键要素。
func TestRenderProxySite(t *testing.T) {
	out, err := Render(proxySite(), RenderOptions{})
	if err != nil {
		t.Fatalf("生成反代站配置失败: %v", err)
	}

	mustContain(t, out, "server_name api.example.com;")
	mustContain(t, out, "proxy_pass http://127.0.0.1:3000;")
	mustContain(t, out, "proxy_http_version 1.1;")
	// 四个标准转发头：缺了后端就拿不到真实客户端信息。
	mustContain(t, out, "proxy_set_header Host $host;")
	mustContain(t, out, "proxy_set_header X-Real-IP $remote_addr;")
	mustContain(t, out, "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	mustContain(t, out, "proxy_set_header X-Forwarded-Proto $scheme;")
	// WebSocket 透传：缺了这两个头，反代后的 WS 会在握手阶段失败。
	mustContain(t, out, "proxy_set_header Upgrade $http_upgrade;")
	// Connection 必须用内置的 $http_connection，**不能**用
	// $connection_upgrade —— 后者不是内置变量，会让 nginx -t 直接失败
	// （真实 nginx 集成测试抓到的缺陷，见 config.go 的说明）。
	mustContain(t, out, "proxy_set_header Connection $http_connection;")
	mustNotContain(t, out, "$connection_upgrade")
	// 反代站不应出现 root 指令。
	mustNotContain(t, out, "root ")
}

// TestRenderRejectsInvalidInput 验证 Render 自身的二次校验。
//
// 这是"纵深防御"的落点：即使将来有人加了一条新的调用路径忘了先校验，
// Render 也生不出畸形配置。
func TestRenderRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		site Site
	}{
		{"站点名含分号", Site{Name: "a;b", Domain: "x.com", Type: TypeStatic, Root: "/var/www"}},
		{"站点名含换行", Site{Name: "a\nb", Domain: "x.com", Type: TypeStatic, Root: "/var/www"}},
		{"站点名为保留名", Site{Name: "default", Domain: "x.com", Type: TypeStatic, Root: "/var/www"}},
		{"域名含分号", Site{Name: "a", Domain: "x.com; root /etc;", Type: TypeStatic, Root: "/var/www"}},
		{"域名含换行", Site{Name: "a", Domain: "x.com\nroot /etc;", Type: TypeStatic, Root: "/var/www"}},
		{"域名含花括号", Site{Name: "a", Domain: "x.com}", Type: TypeStatic, Root: "/var/www"}},
		{"根目录含分号", Site{Name: "a", Domain: "x.com", Type: TypeStatic, Root: "/var/www; root /etc"}},
		{"根目录含反引号", Site{Name: "a", Domain: "x.com", Type: TypeStatic, Root: "/var/www`id`"}},
		{"根目录为相对路径", Site{Name: "a", Domain: "x.com", Type: TypeStatic, Root: "var/www"}},
		{"根目录为 /", Site{Name: "a", Domain: "x.com", Type: TypeStatic, Root: "/"}},
		{"反代目标含分号", Site{Name: "a", Domain: "x.com", Type: TypeProxy, Upstream: "http://127.0.0.1:3000;root /etc;"}},
		{"反代目标为 unix socket", Site{Name: "a", Domain: "x.com", Type: TypeProxy, Upstream: "unix:/var/run/docker.sock"}},
		{"反代目标缺协议", Site{Name: "a", Domain: "x.com", Type: TypeProxy, Upstream: "127.0.0.1:3000"}},
		{"类型非法", Site{Name: "a", Domain: "x.com", Type: "php", Root: "/var/www"}},
		{"类型为空", Site{Name: "a", Domain: "x.com", Type: ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Render(tc.site, RenderOptions{})
			if err == nil {
				t.Errorf("Render 应当拒绝该输入，但生成了配置:\n%s", out)
			}
			// 关键断言：失败时**绝不能**返回半份配置。
			// 否则调用方稍有疏忽就会把它写盘。
			if out != "" {
				t.Errorf("Render 失败时不应返回任何内容，实际返回了 %d 字节", len(out))
			}
		})
	}
}

// TestRenderRejectsInjectionFields 用注入载荷穷举 Render 的防线。
//
// 与 validate_test.go 的区别：那里测的是校验函数本身，
// 这里测的是"绕过校验直接调 Render"——模拟将来有人加了新调用路径
// 却忘了先校验的场景。
func TestRenderRejectsInjectionFields(t *testing.T) {
	for _, r := range nginxMetacharacters {
		c := string(r)
		cases := []Site{
			{Name: "site" + c, Domain: "x.com", Type: TypeStatic, Root: "/var/www"},
			{Name: "site", Domain: "x.com" + c, Type: TypeStatic, Root: "/var/www"},
			{Name: "site", Domain: "x.com", Type: TypeStatic, Root: "/var/www" + c},
			{Name: "site", Domain: "x.com", Type: TypeProxy, Upstream: "http://127.0.0.1:3000" + c},
		}
		for i, s := range cases {
			out, err := Render(s, RenderOptions{})
			if err == nil {
				t.Errorf("元字符 %q（用例 %d）应被 Render 拒绝，但生成了:\n%s", r, i, out)
			}
		}
	}
}

// TestRenderOutputParses 验证生成的配置能被解析器读回关键字段。
//
// 这条链路是列表接口的基础：面板创建站点后再列出来，
// 必须能从配置里还原出 domain / root / upstream。
func TestRenderOutputParses(t *testing.T) {
	t.Run("静态站", func(t *testing.T) {
		content, err := Render(staticSite(), RenderOptions{})
		if err != nil {
			t.Fatalf("Render 失败: %v", err)
		}
		p := ParseContent(content)
		if !p.Generated {
			t.Error("解析结果应标记为面板生成")
		}
		if len(p.ServerNames) != 1 || p.ServerNames[0] != "demo.example.com" {
			t.Errorf("server_name 解析错误: %v", p.ServerNames)
		}
		if p.Root != "/var/www/demo" {
			t.Errorf("root 解析错误: %q", p.Root)
		}
		if p.ProxyPass != "" {
			t.Errorf("静态站不应解析出 proxy_pass: %q", p.ProxyPass)
		}
	})

	t.Run("反代站", func(t *testing.T) {
		content, err := Render(proxySite(), RenderOptions{})
		if err != nil {
			t.Fatalf("Render 失败: %v", err)
		}
		p := ParseContent(content)
		if !p.Generated {
			t.Error("解析结果应标记为面板生成")
		}
		if p.ProxyPass != "http://127.0.0.1:3000" {
			t.Errorf("proxy_pass 解析错误: %q", p.ProxyPass)
		}
		if len(p.Listen) == 0 {
			t.Error("应解析出 listen 指令")
		}
	})
}

// TestParseConfRecognizesExternalConfig 验证外部配置不会被误认为面板生成。
//
// 这是"面板不会覆盖用户手写配置"这一保护的基础：
// 判定依据必须是生成标记，而不是"文件名长得像"。
func TestParseConfRecognizesExternalConfig(t *testing.T) {
	external := `# 用户手写的配置
server {
    listen 80;
    server_name manual.example.com;
    root /srv/manual;
}
`
	p := ParseContent(external)
	if p.Generated {
		t.Error("手工配置不应被判定为面板生成（否则面板会覆盖它）")
	}
	if p.Root != "/srv/manual" {
		t.Errorf("root 解析错误: %q", p.Root)
	}
}

// TestParseConfIgnoresComments 验证注释行不参与解析。
func TestParseConfIgnoresComments(t *testing.T) {
	content := `# server_name commented.example.com;
# root /commented;
server {
    listen 80;
    server_name real.example.com;
    root /real;
}
`
	p := ParseContent(content)
	if len(p.ServerNames) != 1 || p.ServerNames[0] != "real.example.com" {
		t.Errorf("被注释掉的 server_name 不应被解析，实际: %v", p.ServerNames)
	}
	if p.Root != "/real" {
		t.Errorf("被注释掉的 root 不应被解析，实际: %q", p.Root)
	}
}

// TestRenderCustomIndex 验证自定义首页列表。
func TestRenderCustomIndex(t *testing.T) {
	out, err := Render(staticSite(), RenderOptions{Index: []string{"main.html", "home.htm"}})
	if err != nil {
		t.Fatalf("Render 失败: %v", err)
	}
	mustContain(t, out, "index main.html home.htm;")

	// 非法首页名必须被拒绝（它同样会被拼进配置）。
	if _, err := Render(staticSite(), RenderOptions{Index: []string{"a.html; root /etc"}}); err == nil {
		t.Error("非法 index 文件名应被拒绝")
	}
	if _, err := Render(staticSite(), RenderOptions{Index: []string{"../etc/passwd"}}); err == nil {
		t.Error("含路径分隔符的 index 文件名应被拒绝")
	}
}

// TestRenderDeterministic 验证同一输入总是产出同一份配置。
//
// 确定性是"编辑前后 diff 干净"的前提：若每次渲染都略有不同
// （例如 map 遍历顺序），用户的 git diff / 版本对比会充满噪声。
func TestRenderDeterministic(t *testing.T) {
	first, err := Render(proxySite(), RenderOptions{})
	if err != nil {
		t.Fatalf("Render 失败: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := Render(proxySite(), RenderOptions{})
		if err != nil {
			t.Fatalf("第 %d 次 Render 失败: %v", i, err)
		}
		if again != first {
			t.Fatalf("第 %d 次渲染结果与首次不同（渲染不确定）", i)
		}
	}
}

// mustContain 断言子串存在。
func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("配置中应包含 %q，实际内容:\n%s", needle, haystack)
	}
}

// mustNotContain 断言子串不存在。
func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("配置中不应包含 %q，实际内容:\n%s", needle, haystack)
	}
}
