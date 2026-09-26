// 插件前端资源（阶段三 3.2 动态挂载的服务端一半）的验证。
//
// 验证目标：插件自带的 ESM 入口能被核心按 <id> 取到，且路径穿越被拦截。
// 这里用**真实插件实例**（sysinfo）而不是 mock：它自带的前端资源是通过
// go:embed 打进二进制的，只有真跑一遍才能确认「embed 路径、URL 前缀、
// 转发规则」三者确实对得上——这正是动态挂载最容易出错的接缝。
package plugin_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"testing"

	"lipanel/internal/plugin"
	_ "lipanel/internal/plugin/builtin/sysinfo"
)

// sysinfoAssetsPrefix 是前端在浏览器里请求的资源前缀。
// 必须与 sysinfo 插件声明的 frontend.entry / frontend.assets 一致。
const sysinfoAssetsPrefix = "/plugin-assets/sysinfo/"

// TestSysinfoFrontendMetadata 验证插件声明的前端入口符合 3.2 的动态挂载契约。
//
// 这些断言锁的是「约定」：前端 loader.js 靠 <assets>plugin.js 做兜底，
// 靠绝对路径做原生 import。任何一条被改坏，界面上表现为插件页白屏，
// 而单看后端日志很难定位，因此必须在测试里钉死。
func TestSysinfoFrontendMetadata(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}
	fe := h.Descriptor().Frontend

	if !fe.Valid() {
		t.Fatalf("Frontend 元数据不完整: %+v", fe)
	}
	if fe.Entry != sysinfoAssetsPrefix+"plugin.js" {
		t.Errorf("Entry = %q, 期望 %q", fe.Entry, sysinfoAssetsPrefix+"plugin.js")
	}
	if fe.Assets != sysinfoAssetsPrefix {
		t.Errorf("Assets = %q, 期望 %q", fe.Assets, sysinfoAssetsPrefix)
	}
	// Assets 必须以 / 结尾：前端用它做相对入口的解析基准，
	// 少了斜杠会把 plugin.js 拼到父目录上去。
	if !strings.HasSuffix(fe.Assets, "/") {
		t.Error("Assets 必须以 / 结尾")
	}
	// Entry 必须是站点绝对路径：相对路径在原生动态 import 下无法解析，
	// 只能靠 Blob 降级，属于「能省则省」的路径。
	if !strings.HasPrefix(fe.Entry, "/") {
		t.Error("Entry 应当是站点绝对路径（以 / 开头）")
	}
	if !fe.ESMEntry() {
		t.Errorf("Type = %q, 期望为空或 %q", fe.Type, plugin.FrontendTypeESM)
	}
}

// TestSysinfoAssetsServed 验证插件自带前端确实能通过骨架的 /assets 取到。
//
// 这里直接打插件的 mux（plugin.Serve 内部注册的就是它），
// 因此不需要拉起真实进程，但覆盖的代码路径与线上完全一致。
func TestSysinfoAssetsServed(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	provider, ok := h.(plugin.AssetProvider)
	if !ok {
		t.Fatal("sysinfo 应当实现 plugin.AssetProvider（它自带前端界面）")
	}
	assets := provider.Assets()
	if assets == nil {
		t.Fatal("Assets() 返回 nil，说明 go:embed 未生效或路径写错")
	}

	// 直接读文件系统：确认 plugin.js 真的进了二进制。
	data, err := fs.ReadFile(assets, "plugin.js")
	if err != nil {
		t.Fatalf("读取内嵌的 plugin.js 失败: %v", err)
	}
	code := string(data)

	// 契约校验：入口必须 default export 一个对象，
	// 且必须从 'vue' 导入（走 importmap 用宿主那份 Vue）。
	if !strings.Contains(code, "export default") {
		t.Error("plugin.js 必须使用 `export default`（前端 loader 只认默认导出）")
	}
	if !strings.Contains(code, "component") {
		t.Error("plugin.js 的默认导出必须包含 component 字段")
	}
	if !strings.Contains(code, "from 'vue'") && !strings.Contains(code, `from "vue"`) {
		t.Error("plugin.js 应当从 'vue' 导入（由 index.html 的 importmap 解析到宿主同一份 Vue）")
	}

	// 再走一遍 HTTP 处理器：验证 MIME 与缓存头。
	mux := http.NewServeMux()
	registerAssetsForTest(h, mux)

	rec := doGet(t, mux, "/assets/plugin.js")
	if rec.status != http.StatusOK {
		t.Fatalf("GET /assets/plugin.js 状态码 = %d, 期望 200（body=%s）", rec.status, rec.body)
	}
	// 必须是 text/javascript：动态 import 会做 MIME 检查，
	// 返回 application/octet-stream 会被浏览器直接拒绝。
	if ct := rec.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, 期望 text/javascript", ct)
	}
	if rec.header.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q, 期望 no-cache（插件升级后不该继续跑旧前端）",
			rec.header.Get("Cache-Control"))
	}
	if rec.body != code {
		t.Error("HTTP 返回的内容与内嵌文件不一致")
	}
}

// TestSysinfoAssetsTraversalBlocked 验证 /assets 的路径穿越不会泄露内容。
//
// 这些用例对应真实的攻击面：插件前端资源是插件作者可控的内容，
// 一旦这里能穿越，一个（被攻陷的）插件就能读到插件进程可读的任意文件。
//
// 断言的是**结果**而不是状态码，因为 Go 1.22+ 的 ServeMux 会先对路径做
// 清洗与百分号解码，穿越路径通常先被 307 重定向（Location 已规范化），
// 跟随后落到 404。写死「必须是 400」会把标准库的正常行为判成失败，
// 真正要钉死的是：**任何穿越写法都取不到内容，且不泄露宿主文件**。
func TestSysinfoAssetsTraversalBlocked(t *testing.T) {
	h, err := plugin.Build("sysinfo", testLogger())
	if err != nil {
		t.Fatalf("Build(sysinfo) 失败: %v", err)
	}

	mux := http.NewServeMux()
	registerAssetsForTest(h, mux)

	cases := []struct {
		name string
		path string
	}{
		{"向上穿越", "/assets/../plugin.js"},
		{"多级穿越", "/assets/../../etc/passwd"},
		{"编码穿越", "/assets/..%2f..%2fetc%2fpasswd"},
		{"编码穿越(大写)", "/assets/..%2F..%2Fetc%2Fpasswd"},
		{"绝对路径", "/assets//etc/passwd"},
		{"点号穿越", "/assets/./../plugin.js"},
		{"空路径", "/assets/"},
		{"隐藏文件", "/assets/.env"},
		{"不存在的资源", "/assets/nope.js"},
		{"目录", "/assets/sub/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doGet(t, mux, tc.path)

			// 关键断言 1：绝不能返回 plugin.js 的内容。
			// 穿越攻击的全部意义就是读到不该读的文件，读到 200 才是真的失守。
			if rec.status == http.StatusOK && strings.Contains(rec.body, "export default") {
				t.Fatalf("GET %s 取到了 plugin.js 内容，穿越未被拦截", tc.path)
			}

			// 关键断言 2：绝不能泄露宿主系统文件。
			for _, leak := range []string{"root:x:", "/bin/bash", "/bin/sh"} {
				if strings.Contains(rec.body, leak) {
					t.Fatalf("GET %s 疑似泄露系统文件内容: %.200s", tc.path, rec.body)
				}
			}

			// 关键断言 3：穿越路径不得被当作合法资源。
			if rec.status == http.StatusOK {
				t.Fatalf("GET %s 返回 200（body=%.200s），穿越路径不应被当作资源", tc.path, rec.body)
			}

			// 编码穿越会被规范化后重新匹配，命中真实的 /assets 处理器，
			// 因此这里必须是 JSON 错误而不是纯文本 404——
			// 纯文本会让前端按 JSON 解析时报「后端返回了非 JSON 内容」。
			if tc.name == "编码穿越" || tc.name == "编码穿越(大写)" {
				if !strings.Contains(rec.header.Get("Content-Type"), "application/json") {
					t.Errorf("GET %s 的 Content-Type = %q, 期望 JSON 错误响应",
						tc.path, rec.header.Get("Content-Type"))
				}
			}
		})
	}
}

// TestAssetsRouteRegisteredWithoutProvider 验证未自带前端的插件也有 /assets 兜底。
//
// 否则请求会落到 ServeMux 的默认 404（纯文本），前端按 JSON 解析会报
// 「后端返回了非 JSON 内容」，把一个清楚的「该插件没有前端资源」
// 变成一句让人困惑的错误。
func TestAssetsRouteRegisteredWithoutProvider(t *testing.T) {
	mux := http.NewServeMux()
	registerAssetsForTest(noAssetHandler{}, mux)

	rec := doGet(t, mux, "/assets/plugin.js")
	if rec.status != http.StatusNotFound {
		t.Fatalf("状态码 = %d, 期望 404", rec.status)
	}
	if !strings.Contains(rec.header.Get("Content-Type"), "application/json") {
		t.Errorf("Content-Type = %q, 期望 JSON", rec.header.Get("Content-Type"))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(rec.body), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v (%s)", err, rec.body)
	}
	if payload["error"] == nil {
		t.Errorf("响应应包含 error 字段: %s", rec.body)
	}
}

// ---------- 测试辅助 ----------

// noAssetHandler 是一个不提供前端资源的极简插件。
type noAssetHandler struct{}

func (noAssetHandler) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID: "noasset", Name: "无前端插件", Version: "0.0.1", Mode: plugin.ModeManaged,
	}
}

func (noAssetHandler) Routes(mux *http.ServeMux) {}

// registerAssetsForTest 复现 plugin.Serve 中的资源路由注册。
//
// 为什么需要它：registerAssetRoutes 是 plugin 包的私有函数，外部测试包
// 无法直接调用。这里用 plugin.ExportAssetRoutesForTest 这一层薄导出，
// 保证测试覆盖的就是线上真正使用的那个函数（而不是测试里另写一份）。
func registerAssetsForTest(h plugin.Handler, mux *http.ServeMux) {
	plugin.ExportAssetRoutesForTest(mux, h, testLogger())
}

// doGet 对 mux 发起一次 GET 请求，返回 recorder（含状态码、响应头、正文）。
//
// 注意这里用 r.URL.Path 之外还需设置 RawPath 场景：Go 的 ServeMux 会先
// 对路径做百分号解码再匹配，因此像 /assets/..%2f..%2fetc%2fpasswd 这类
// 编码穿越同样会被 r.URL.Path 规范化——测试要覆盖的正是解码之后的行为。
func doGet(t *testing.T, mux *http.ServeMux, path string) *recorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("构造请求 %s 失败: %v", path, err)
	}
	rec := newRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}
