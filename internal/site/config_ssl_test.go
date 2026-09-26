package site

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// SSL 配置生成测试（阶段四 4.4）
// ============================================================================
//
// 本文件验证「证书路径与 TLS 参数如何进配置」这件事。
//
// 它有与 4.3 config_test.go 同样的两层目标：
//
//  1. **启用 SSL 时生成正确的 HTTPS 配置**——含证书路径、
//     TLS 协议、跳转块，且 ACME 挑战路径被放行。
//  2. **畸形输入进不去模板**——证书路径是新的注入面
//     （会被裸拼成 `ssl_certificate <path>;`），必须白名单校验。

// sslConfig 返回一份合法的 SSL 配置。
func okSSLConfig() *SSLConfig {
	return &SSLConfig{
		CertPath:     "/etc/letsencrypt/live/demo.example.com/fullchain.pem",
		KeyPath:      "/etc/letsencrypt/live/demo.example.com/privkey.pem",
		RedirectHTTP: true,
	}
}

// TestRenderSSLStaticSite 验证静态站启用 SSL 后的配置。
func TestRenderSSLStaticSite(t *testing.T) {
	out, err := Render(staticSite(), RenderOptions{SSL: okSSLConfig()})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	// ---------- 必须监听 443 ----------
	if !strings.Contains(out, "listen 443 ssl http2;") {
		t.Errorf("缺少 443 监听:\n%s", out)
	}
	// ---------- 证书路径 ----------
	if !strings.Contains(out, "ssl_certificate     /etc/letsencrypt/live/demo.example.com/fullchain.pem;") {
		t.Errorf("缺少 ssl_certificate:\n%s", out)
	}
	if !strings.Contains(out, "ssl_certificate_key /etc/letsencrypt/live/demo.example.com/privkey.pem;") {
		t.Errorf("缺少 ssl_certificate_key:\n%s", out)
	}
	// ---------- TLS 参数 ----------
	if !strings.Contains(out, "ssl_protocols "+DefaultTLSProtocols+";") {
		t.Errorf("缺少 ssl_protocols:\n%s", out)
	}
	if !strings.Contains(out, "ssl_ciphers "+DefaultTLSCiphers+";") {
		t.Errorf("缺少 ssl_ciphers:\n%s", out)
	}
	// ---------- 站点内容仍在 ----------
	if !strings.Contains(out, "root /var/www/demo;") {
		t.Errorf("启用 SSL 后静态站根目录丢失:\n%s", out)
	}
	if !strings.Contains(out, "try_files $uri $uri/ =404;") {
		t.Errorf("启用 SSL 后 try_files 丢失:\n%s", out)
	}
}

// TestRenderSSLRedirectBlock 验证 HTTP → HTTPS 跳转块。
func TestRenderSSLRedirectBlock(t *testing.T) {
	cfg := okSSLConfig()
	cfg.RedirectHTTP = true
	out, err := Render(staticSite(), RenderOptions{SSL: cfg})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	if !strings.Contains(out, "return 301 https://$host$request_uri;") {
		t.Errorf("缺少 301 跳转，或跳转没有保留原始路径:\n%s", out)
	}
	// 跳转块必须也监听 80
	if n := strings.Count(out, "listen 80;"); n != 1 {
		t.Errorf("跳转块的 listen 80 数量 = %d，期望 1（主块应为 443）:\n%s", n, out)
	}
}

// TestRenderSSLRedirectPreservesPath 验证跳转保留路径而不是跳到首页。
//
// 用 `return 301 https://$host/;` 会让
// `http://example.com/blog/post-1` 跳到首页，
// 用户丢掉了自己要访问的页面，搜索引擎也会认为内容变了。
func TestRenderSSLRedirectPreservesPath(t *testing.T) {
	out, err := Render(staticSite(), RenderOptions{SSL: okSSLConfig()})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	// 必须是 $request_uri（保留路径与查询串），不能是裸的 /
	if strings.Contains(out, "return 301 https://$host/;") {
		t.Errorf("跳转丢失了原始路径（用了裸 / 而不是 $request_uri）:\n%s", out)
	}
	if !strings.Contains(out, "$request_uri") {
		t.Errorf("跳转应当保留 $request_uri:\n%s", out)
	}
}

// TestRenderSSLAllowsACMEChallenge 验证 ACME 挑战路径被豁免跳转。
//
// ########## 这是 Let's Encrypt 部署里最经典的死锁 ##########
//
// 续期时 CA 会用 HTTP 访问 /.well-known/acme-challenge/ 验证域名归属。
// 若该路径被无条件 301 到 HTTPS，CA 的验证请求会跟到 HTTPS——
// 而在证书**即将过期但尚未续期**的时刻，HTTPS 可能正好因为
// 证书过期而握手失败，于是续期也失败：
//
//	要续期 → 需要 HTTP 挑战可达 → 但 HTTP 被跳到 HTTPS
//	→ HTTPS 因证书过期而失败 → 续期失败 → 证书永远续不上
//
// 因此这条豁免是**功能正确性**问题，不只是优化。
func TestRenderSSLAllowsACMEChallenge(t *testing.T) {
	cfg := okSSLConfig()
	cfg.RedirectHTTP = true
	out, err := Render(staticSite(), RenderOptions{SSL: cfg})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	if !strings.Contains(out, ".well-known/acme-challenge/") {
		t.Fatalf("缺少 ACME 挑战路径的放行规则（续期会死锁）:\n%s", out)
	}
	// 必须使用 ^~ 前缀匹配：它让该 location 优先于正则 location，
	// 也明确表达了"这个前缀下不做跳转"的意图。
	if !strings.Contains(out, "location ^~ /.well-known/acme-challenge/") {
		t.Errorf("ACME 挑战 location 应当用 ^~ 前缀匹配:\n%s", out)
	}
	// 挑战目录必须指向真实的站点根目录（挑战文件写在那里）
	if !strings.Contains(out, "root /var/www/demo;") {
		t.Errorf("ACME 挑战应当指向站点根目录:\n%s", out)
	}
}

// TestRenderSSLNoRedirect 验证关闭跳转时不生成跳转块。
func TestRenderSSLNoRedirect(t *testing.T) {
	cfg := okSSLConfig()
	cfg.RedirectHTTP = false
	out, err := Render(staticSite(), RenderOptions{SSL: cfg})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	if strings.Contains(out, "return 301") {
		t.Errorf("RedirectHTTP=false 时不该有跳转:\n%s", out)
	}
	// 仍然必须监听 443
	if !strings.Contains(out, "listen 443 ssl http2;") {
		t.Errorf("仍然应当监听 443:\n%s", out)
	}
	// 不该有 80 监听（没有跳转块时没有理由监听 80）
	if strings.Contains(out, "listen 80;") {
		t.Errorf("无跳转块时不该监听 80（会让明文请求命中）:\n%s", out)
	}
}

// TestRenderSSLProxySite 验证反代站也能启用 SSL。
func TestRenderSSLProxySite(t *testing.T) {
	out, err := Render(proxySite(), RenderOptions{SSL: okSSLConfig()})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, "listen 443 ssl http2;") {
		t.Errorf("反代站启用 SSL 后应监听 443:\n%s", out)
	}
	if !strings.Contains(out, "proxy_pass http://127.0.0.1:3000;") {
		t.Errorf("反代目标丢失:\n%s", out)
	}
}

// TestRenderSSLNilKeepsOldBehavior 验证未启用 SSL 时行为不变。
//
// 这是**回归保护**：引入 4.4 后，4.3 创建的既有站点
// 在下次编辑时不应被意外改成 HTTPS。
func TestRenderSSLNilKeepsOldBehavior(t *testing.T) {
	out, err := Render(staticSite(), RenderOptions{})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(out, "443") {
		t.Errorf("未启用 SSL 时不该出现 443:\n%s", out)
	}
	if strings.Contains(out, "ssl_certificate") {
		t.Errorf("未启用 SSL 时不该出现 ssl_certificate:\n%s", out)
	}
	if !strings.Contains(out, "listen 80;") {
		t.Errorf("未启用 SSL 时应当监听 80:\n%s", out)
	}
	// 也不能出现跳转
	if strings.Contains(out, "return 301") {
		t.Errorf("未启用 SSL 时不该有跳转:\n%s", out)
	}
}

// TestRenderSSLDeterministic 验证渲染结果稳定（便于 diff 与幂等性）。
func TestRenderSSLDeterministic(t *testing.T) {
	a, err := Render(staticSite(), RenderOptions{SSL: okSSLConfig()})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	b, err := Render(staticSite(), RenderOptions{SSL: okSSLConfig()})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if a != b {
		t.Error("相同输入应当产生完全相同的配置（幂等性）")
	}
}

// ---------------------------------------------------------------------------
// 注入防护（证书路径是新的注入面）
// ---------------------------------------------------------------------------

// TestRenderSSLRejectsInjection 穷举证书路径与 TLS 参数的注入载荷。
//
// ########## 为什么这条是最重要的安全测试 ##########
//
// 证书路径会被**裸拼**进 nginx 配置：
//
//	ssl_certificate     <path>;
//
// 因此它和 4.3 的域名一样是注入面：一个含分号的路径
// 就能在配置里插入任意指令（例如 `location / { proxy_pass ... }`）。
//
// 虽然路径来自 certbot 的输出而非用户输入，但"上游可信"
// 不是放弃校验的理由——certbot 的输出格式会随版本变化，
// 而我们的解析器可能被畸形数据误导。
func TestRenderSSLRejectsInjection(t *testing.T) {
	s := staticSite()

	badPaths := []string{
		"",
		// 分号是 nginx 的指令结束符 —— 最直接的注入
		"/etc/ssl/cert.pem; location / { return 200; }",
		"/etc/ssl/cert.pem;",
		// 花括号划分块
		"/etc/ssl/cert.pem}",
		"/etc/ssl/{cert.pem",
		// 引号与美元符号（变量引用 / 字符串边界）
		`/etc/ssl/"cert".pem`,
		"/etc/ssl/$variable/cert.pem",
		`/etc/ssl/'cert'.pem`,
		// 注释符
		"/etc/ssl/cert.pem#comment",
		// 反引号
		"/etc/ssl/`id`.pem",
		// 空白（会让路径被切成两个 token）
		"/etc/ssl/my cert.pem",
		"/etc/ssl/cert.pem\nssl_protocols TLSv1;",
		"/etc/ssl/cert.pem\t",
		// 非绝对路径
		"etc/ssl/cert.pem",
		"relative/cert.pem",
		"./cert.pem",
		// 路径穿越
		"/etc/ssl/../../etc/shadow",
		"/../etc/passwd",
		// 反斜杠
		"/etc/ssl\\cert.pem",
	}

	for _, p := range badPaths {
		t.Run("cert:"+p, func(t *testing.T) {
			out, err := Render(s, RenderOptions{SSL: &SSLConfig{
				CertPath: p,
				KeyPath:  "/etc/ssl/key.pem",
			}})
			if err == nil {
				t.Errorf("非法证书路径 %q 竟然通过了校验，生成:\n%s", p, out)
			}
			// 关键：失败时绝不能产生半截配置
			if out != "" {
				t.Errorf("校验失败时必须返回空字符串，实际返回了 %d 字节", len(out))
			}
		})
	}

	// 私钥路径同样要校验
	for _, p := range badPaths {
		t.Run("key:"+p, func(t *testing.T) {
			out, err := Render(s, RenderOptions{SSL: &SSLConfig{
				CertPath: "/etc/ssl/cert.pem",
				KeyPath:  p,
			}})
			if err == nil {
				t.Errorf("非法私钥路径 %q 竟然通过了校验，生成:\n%s", p, out)
			}
			if out != "" {
				t.Errorf("校验失败时必须返回空字符串")
			}
		})
	}
}

// TestRenderSSLRejectsBadTLSParams 验证 TLS 参数注入被拒绝。
//
// TLS 参数来自用户可控的配置（-cert-* 之外的未来扩展），
// 且同样被裸拼进配置，因此必须校验。
func TestRenderSSLRejectsBadTLSParams(t *testing.T) {
	s := staticSite()

	badProtocols := []string{
		"TLSv1.2; ssl_ciphers HIGH", // 分号注入
		"TLSv1.2 { }",               // 花括号
		"TLSv1.2\ngzip on;",         // 换行注入
		`TLSv1.2"`,                  // 引号
		"TLSv1.2$var",               // 变量
		"TLSv1.2#comment",           // 注释
	}
	for _, p := range badProtocols {
		t.Run("protocols:"+p, func(t *testing.T) {
			out, err := Render(s, RenderOptions{SSL: &SSLConfig{
				CertPath:  "/etc/ssl/cert.pem",
				KeyPath:   "/etc/ssl/key.pem",
				Protocols: p,
			}})
			if err == nil {
				t.Errorf("非法 ssl_protocols %q 竟然通过，生成:\n%s", p, out)
			}
			if out != "" {
				t.Error("校验失败时必须返回空字符串")
			}
		})
	}

	badCiphers := []string{
		"HIGH:!aNULL; ssl_protocols TLSv1",
		"HIGH:!aNULL {}",
		`HIGH:!aNULL"`,
		"HIGH:!aNULL\n",
	}
	for _, c := range badCiphers {
		t.Run("ciphers:"+c, func(t *testing.T) {
			out, err := Render(s, RenderOptions{SSL: &SSLConfig{
				CertPath: "/etc/ssl/cert.pem",
				KeyPath:  "/etc/ssl/key.pem",
				Ciphers:  c,
			}})
			if err == nil {
				t.Errorf("非法 ssl_ciphers %q 竟然通过，生成:\n%s", c, out)
			}
			if out != "" {
				t.Error("校验失败时必须返回空字符串")
			}
		})
	}
}

// TestRenderSSLAcceptsRealisticPaths 验证真实的 certbot 路径被接受。
//
// 校验不能严到把正常路径也拒了——否则功能直接不可用。
func TestRenderSSLAcceptsRealisticPaths(t *testing.T) {
	s := staticSite()
	valid := []*SSLConfig{
		{
			CertPath: "/etc/letsencrypt/live/example.com/fullchain.pem",
			KeyPath:  "/etc/letsencrypt/live/example.com/privkey.pem",
		},
		{
			// 自定义 config-dir
			CertPath: "/opt/certs/live/my-site.example.com/fullchain.pem",
			KeyPath:  "/opt/certs/live/my-site.example.com/privkey.pem",
		},
		{
			// 路径里含 `.` 与 `-`（合法）
			CertPath: "/etc/ssl/certs/my..site-cert.pem",
			KeyPath:  "/etc/ssl/private/my-site_key.pem",
		},
		{
			// 自定义 TLS 参数
			CertPath:  "/etc/ssl/cert.pem",
			KeyPath:   "/etc/ssl/key.pem",
			Protocols: "TLSv1.3",
			Ciphers:   "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
		},
	}
	for _, cfg := range valid {
		out, err := Render(s, RenderOptions{SSL: cfg})
		if err != nil {
			t.Errorf("合法配置被拒绝: %+v，err=%v", cfg, err)
			continue
		}
		if out == "" {
			t.Errorf("合法配置应当生成内容: %+v", cfg)
		}
	}
}

// TestRenderSSLConfigDirectValidation 直接测试 validSSLConfig。
func TestRenderSSLConfigDirectValidation(t *testing.T) {
	// 空路径必须被拒（会让 nginx 收到 ssl_certificate ;）
	if err := validSSLConfig(SSLConfig{CertPath: "", KeyPath: "/k.pem"}); err == nil {
		t.Error("空证书路径应当被拒绝")
	}
	if err := validSSLConfig(SSLConfig{CertPath: "/c.pem", KeyPath: ""}); err == nil {
		t.Error("空私钥路径应当被拒绝")
	}
	// 合法的通过
	if err := validSSLConfig(SSLConfig{
		CertPath: "/etc/ssl/c.pem",
		KeyPath:  "/etc/ssl/k.pem",
	}); err != nil {
		t.Errorf("合法配置不该报错: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 真实 nginx 校验（本文件最重要的一条）
// ---------------------------------------------------------------------------

// TestRenderSSLConfigAcceptedByRealNginx 用**真实的 nginx 二进制**
// 校验生成的 HTTPS 配置。
//
// ########## 为什么这条测试不可替代 ##########
//
// 上面所有用例都是字符串断言：它们能证明"我写了什么"，
// 但**不能证明 nginx 接受它**。这两件事之间的差距是真实存在的：
//
// 本模块的端到端测试就抓到过一次——生成的配置里写了
// `http2 on;`，而该指令是 nginx 1.25.1 才引入的。
// 在发行版常见的 1.18/1.20 上，nginx -t 直接报
// `[emerg] unknown directive "http2"`，导致
// **"证书已获取但配置写入失败"**（CA 配额已消耗）。
//
// 字符串断言当时是**全绿**的：它只检查了 listen 那一行，
// 根本没看 http2。所以这条用真实 nginx 的校验
// 是唯一能拦住这类问题的测试。
//
// nginx 或 openssl 不存在时跳过（不阻断其它平台的开发）。
func TestRenderSSLConfigAcceptedByRealNginx(t *testing.T) {
	nginxBin := findNginxBinary()
	if nginxBin == "" {
		t.Skip("未找到 nginx 可执行文件，跳过真实校验")
	}

	base := t.TempDir()
	prefix := filepath.Join(base, "nginx")
	for _, sub := range []string{"sites-enabled", "logs"} {
		if err := os.MkdirAll(filepath.Join(prefix, sub), 0o755); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
	}

	// 造一张真实的自签名证书：nginx -t 会检查证书文件能否被加载，
	// 用一个不存在的路径会在"证书"这一步失败，而不是"指令"这一步——
	// 那样就测不出我们真正关心的问题。
	certPath, keyPath := makeSelfSignedCert(t, base)

	// 主配置：结构与生产方式一致（include sites-enabled/*.conf）
	//
	// access_log 必须显式指向工作区内的路径：nginx 编译时的默认值是
	// /var/log/nginx/access.log，而测试以普通权限运行时打不开它，
	// 会在 nginx -t 阶段直接以 [emerg] 失败——那是个与配置语法
	// 无关的假失败，会把真正的错误淹没掉。
	mainConf := "worker_processes 1;\n" +
		"error_log " + filepath.Join(prefix, "logs", "error.log") + " warn;\n" +
		"pid " + filepath.Join(prefix, "logs", "nginx.pid") + ";\n" +
		"events { worker_connections 64; }\n" +
		"http {\n" +
		"    access_log " + filepath.Join(prefix, "logs", "access.log") + ";\n" +
		"    client_body_temp_path " + filepath.Join(prefix, "logs", "client_body") + ";\n" +
		"    proxy_temp_path " + filepath.Join(prefix, "logs", "proxy") + ";\n" +
		"    include " + filepath.Join(prefix, "sites-enabled", "*.conf") + ";\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(prefix, "nginx.conf"), []byte(mainConf), 0o644); err != nil {
		t.Fatalf("写主配置失败: %v", err)
	}

	cases := []struct {
		name string
		site Site
		cfg  *SSLConfig
	}{
		{
			name: "静态站+跳转",
			site: staticSiteAt(t, base, "static-redirect"),
			cfg:  &SSLConfig{CertPath: certPath, KeyPath: keyPath, RedirectHTTP: true},
		},
		{
			name: "静态站+无跳转",
			site: staticSiteAt(t, base, "static-plain"),
			cfg:  &SSLConfig{CertPath: certPath, KeyPath: keyPath, RedirectHTTP: false},
		},
		{
			name: "反代站+跳转",
			site: proxySite(),
			cfg:  &SSLConfig{CertPath: certPath, KeyPath: keyPath, RedirectHTTP: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content, err := Render(c.site, RenderOptions{SSL: c.cfg})
			if err != nil {
				t.Fatalf("Render 失败: %v", err)
			}
			confPath := filepath.Join(prefix, "sites-enabled", c.site.Name+".conf")
			if err := os.WriteFile(confPath, []byte(content), 0o644); err != nil {
				t.Fatalf("写站点配置失败: %v", err)
			}

			cmd := exec.Command(nginxBin, "-p", prefix, "-c", "nginx.conf", "-t")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("真实 nginx 拒绝了生成的 HTTPS 配置: %v\n--- nginx 输出 ---\n%s\n--- 生成的配置 ---\n%s",
					err, out, content)
			}
			t.Logf("nginx -t 通过: %s", strings.TrimSpace(string(out)))
		})
	}
}

// staticSiteAt 返回一个根目录真实存在于 base 下的静态站定义。
//
// 必须用真实存在的目录：静态站的 `root` 与 ACME 挑战 location
// 都指向它，目录不存在时 nginx -t 会在"打开目录"这一步失败，
// 那是与配置语法无关的假失败。
func staticSiteAt(t *testing.T, base, name string) Site {
	t.Helper()
	root := filepath.Join(base, "www", name)
	if err := os.MkdirAll(filepath.Join(root, ".well-known", "acme-challenge"), 0o755); err != nil {
		t.Fatalf("创建站点根失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("写首页失败: %v", err)
	}
	s := staticSite()
	s.Name = name
	s.Root = root
	return s
}

// findNginxBinary 查找 nginx 可执行文件，找不到返回空串。
func findNginxBinary() string {
	for _, p := range []string{"/usr/sbin/nginx", "/usr/local/sbin/nginx", "/usr/bin/nginx"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("nginx"); err == nil {
		return p
	}
	return ""
}

// makeSelfSignedCert 生成一张自签名证书，返回 (cert, key) 路径。
func makeSelfSignedCert(t *testing.T, base string) (string, string) {
	t.Helper()
	dir := filepath.Join(base, "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建证书目录失败: %v", err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1", "-keyout", keyPath, "-out", certPath,
		"-subj", "/CN=demo.example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl 不可用，跳过真实 nginx 校验: %v\n%s", err, out)
	}
	return certPath, keyPath
}
