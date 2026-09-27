package store

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// ============================================================================
// 软件清单解析测试（计划要求："新增软件清单解析"测试）
// ============================================================================

// TestLoadCatalogBuiltinValid 断言内置清单本身是合法的。
//
// 这是最重要的一条测试：清单是**数据**，它写错不会让代码编译失败，
// 只会在用户点到那个软件时才炸。解析期的全量校验 + 这条测试
// 把"清单写错"拦在提交阶段。
func TestLoadCatalogBuiltinValid(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("内置清单解析失败: %v", err)
	}
	if len(cat.Software) == 0 {
		t.Fatal("内置清单为空")
	}

	// 计划明确要求的软件必须在清单里。
	want := []string{"php", "nginx", "mysql", "redis", "nodejs"}
	for _, id := range want {
		sw, ok := cat.Get(id)
		if !ok {
			t.Errorf("清单缺少软件 %q", id)
			continue
		}
		// 每个软件都必须有多于一个版本可选（"支持指定版本"是核心目标）。
		if len(sw.Versions) < 2 {
			t.Errorf("软件 %q 只有 %d 个版本，无法体现「指定版本安装」", id, len(sw.Versions))
		}
		// 默认版本必须存在（validateSoftware 已校验，这里再断言一次
		// 是因为它是前端高亮依赖的字段）。
		if _, _, ok := cat.FindVersion(id, sw.DefaultVersion); !ok {
			t.Errorf("软件 %q 的默认版本 %q 不存在", id, sw.DefaultVersion)
		}
		// 每个版本都要有可安装的包名或预编译兜底，否则这个版本点不动。
		for _, v := range sw.Versions {
			if len(v.SystemPackages) == 0 && len(v.AlternativePackages) == 0 && v.Prebuilt == nil {
				t.Errorf("软件 %q 版本 %q 既无包名也无预编译兜底", id, v.ID)
			}
		}
	}
}

// TestParseCatalogRejectsInvalid 穷举清单的各类编辑错误。
func TestParseCatalogRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "空清单",
			body: `{"software":[]}`,
			want: "", // 空清单本身合法（parseCatalog 不强制非空）
		},
		{
			name: "非法软件 ID（大写）",
			body: `{"software":[{"id":"PHP","name":"PHP","default_version":"8.3","versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "软件 ID 非法",
		},
		{
			name: "非法软件 ID（路径穿越）",
			body: `{"software":[{"id":"../etc","name":"x","default_version":"1","versions":[{"id":"1","system_packages":["a"]}]}]}`,
			want: "软件 ID 非法",
		},
		{
			name: "重复软件 ID",
			body: `{"software":[
				{"id":"php","name":"PHP","default_version":"8.3","versions":[{"id":"8.3","system_packages":["php"]}]},
				{"id":"php","name":"PHP2","default_version":"8.3","versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "重复 ID",
		},
		{
			name: "无版本",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","versions":[]}]}`,
			want: "versions 不能为空",
		},
		{
			name: "默认版本不在列表",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"9.9","versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "默认版本",
		},
		{
			name: "版本重复",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","versions":[
				{"id":"8.3","system_packages":["php"]},{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "重复",
		},
		{
			name: "版本号含注入载荷",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3; rm -rf /","versions":[{"id":"8.3; rm -rf /","system_packages":["php"]}]}]}`,
			want: "版本号非法",
		},
		{
			name: "包名含 shell 元字符",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","versions":[{"id":"8.3","system_packages":["php; rm -rf /"]}]}]}`,
			want: "包名非法",
		},
		{
			name: "包名以 - 开头（选项注入）",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","versions":[{"id":"8.3","system_packages":["--force-yes"]}]}]}`,
			want: "包名非法",
		},
		{
			name: "包名含路径穿越",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","versions":[{"id":"8.3","system_packages":["../../etc/passwd"]}]}]}`,
			want: "包名非法",
		},
		{
			name: "依赖悬空",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","depends":["nope"],"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "不在清单中",
		},
		{
			name: "依赖自身",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","depends":["php"],"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "依赖自身",
		},
		{
			name: "官方源家族键非法",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"windows":{"kind":"script","script_url":"https://x.test/a"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "家族键",
		},
		{
			name: "官方源 key_url 非 https",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"debian":{"kind":"apt-key-source","key_url":"http://x.test/k.gpg","keyring_path":"/usr/share/keyrings/a.gpg","list_file":"a.list","source_line_template":"deb https://x.test/ {distro} main"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "必须是 https",
		},
		{
			name: "官方源模板缺占位符",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"debian":{"kind":"apt-key-source","key_url":"https://x.test/k.gpg","keyring_path":"/usr/share/keyrings/a.gpg","list_file":"a.list","source_line_template":"deb https://x.test/ stable main"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "{distro}",
		},
		{
			name: "官方源 kind 未知",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"debian":{"kind":"magic"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "kind 未知",
		},
		{
			name: "keyring 路径含 ..",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"debian":{"kind":"apt-key-source","key_url":"https://x.test/k.gpg","keyring_path":"/usr/share/../../etc/shadow","list_file":"a.list","source_line_template":"deb https://x.test/ {distro} main"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "固定路径",
		},
		{
			name: "list_file 非 .list",
			body: `{"software":[{"id":"php","name":"PHP","default_version":"8.3","official":{"debian":{"kind":"apt-key-source","key_url":"https://x.test/k.gpg","keyring_path":"/usr/share/keyrings/a.gpg","list_file":"a.txt","source_line_template":"deb https://x.test/ {distro} main"}},"versions":[{"id":"8.3","system_packages":["php"]}]}]}`,
			want: "固定文件名非法",
		},
		{
			name: "预编译缺两种取址方式",
			body: `{"software":[{"id":"node","name":"Node","default_version":"22","versions":[{"id":"22","system_packages":["nodejs"],"prebuilt":{"kind":"tar.gz","install_dir":"/usr/local/lib/lipanel/node","link_dir":"/usr/local/bin","binaries":["node"]}}]}]}`,
			want: "缺少 url_template 或 index_url_template",
		},
		{
			name: "预编译同时给两种取址方式",
			body: `{"software":[{"id":"node","name":"Node","default_version":"22","versions":[{"id":"22","system_packages":["nodejs"],"prebuilt":{"kind":"tar.gz","url_template":"https://x.test/n-{arch}.tar.gz","index_url_template":"https://x.test/SHA","file_prefix":"n-","file_suffix":"-{arch}.tar.gz","install_dir":"/usr/local/lib/lipanel/node","link_dir":"/usr/local/bin","binaries":["node"]}}]}]}`,
			want: "同时给了",
		},
		{
			name: "预编译缺 binaries",
			body: `{"software":[{"id":"node","name":"Node","default_version":"22","versions":[{"id":"22","system_packages":["nodejs"],"prebuilt":{"kind":"tar.gz","url_template":"https://x.test/n-{arch}.tar.gz","install_dir":"/usr/local/lib/lipanel/node","link_dir":"/usr/local/bin"}}]}]}`,
			want: "binaries",
		},
		{
			name: "预编译 URL 缺 arch 占位符",
			body: `{"software":[{"id":"node","name":"Node","default_version":"22","versions":[{"id":"22","system_packages":["nodejs"],"prebuilt":{"kind":"tar.gz","url_template":"https://x.test/node.tar.gz","install_dir":"/usr/local/lib/lipanel/node","link_dir":"/usr/local/bin","binaries":["node"]}}]}]}`,
			want: "{arch}",
		},
		{
			name: "yum 仓库文件后缀错",
			body: `{"software":[{"id":"nginx","name":"Nginx","default_version":"1","official":{"rhel":{"kind":"yum-repo-file","key_url":"https://x.test/k","key_path":"/etc/pki/rpm-gpg/k.gpg","repo_file":"/etc/yum.repos.d/x.conf","repo_content_template":"[a]\nbaseurl=https://x.test/{distro}/"}},"versions":[{"id":"1","system_packages":["nginx"]}]}]}`,
			want: ".repo",
		},
		{
			name: "yum 仓库内容含非法变量",
			body: `{"software":[{"id":"nginx","name":"Nginx","default_version":"1","official":{"rhel":{"kind":"yum-repo-file","key_url":"https://x.test/k","key_path":"/etc/pki/rpm-gpg/k.gpg","repo_file":"/etc/yum.repos.d/x.repo","repo_content_template":"[a]\nbaseurl=https://x.test/{distro}/$(whoami)"}},"versions":[{"id":"1","system_packages":["nginx"]}]}]}`,
			want: "非法字符",
		},
		{
			name: "非法 JSON",
			body: `{"software":[`,
			want: "解析软件清单失败",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCatalog([]byte(tc.body))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("预期成功，实际失败: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("预期失败（含 %q），实际成功", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), tc.want)
			}
		})
	}
}

// TestCatalogJSONHasNoUnknownFields 断言清单里的字段名都与结构体对得上。
//
// encoding/json 默认**忽略**未知字段，因此把 "system_package" 写成单数
// 这类错误不会被解析器发现——它会安静地变成一个空列表，
// 然后表现为"这个版本没有包名"。
// 这条测试让拼写错误立刻失败。
func TestCatalogJSONHasNoUnknownFields(t *testing.T) {
	var raw struct {
		Software []map[string]json.RawMessage `json:"software"`
	}
	if err := json.Unmarshal(catalogJSON, &raw); err != nil {
		t.Fatalf("清单不是合法 JSON: %v", err)
	}
	swFields := jsonFields(Software{})
	verFields := jsonFields(Version{})
	prebuiltFields := jsonFields(VersionPrebuilt{})
	officialFields := jsonFields(OfficialSource{})

	for _, sw := range raw.Software {
		var id string
		_ = json.Unmarshal(sw["id"], &id)
		for k := range sw {
			if _, ok := swFields[k]; !ok {
				t.Errorf("软件 %q 含未知字段 %q（拼写错误？）", id, k)
			}
		}
		var versions []map[string]json.RawMessage
		_ = json.Unmarshal(sw["versions"], &versions)
		for _, v := range versions {
			var vid string
			_ = json.Unmarshal(v["id"], &vid)
			for k := range v {
				if _, ok := verFields[k]; !ok {
					t.Errorf("软件 %q 版本 %q 含未知字段 %q", id, vid, k)
				}
			}
			if pb, ok := v["prebuilt"]; ok && string(pb) != "null" {
				var m map[string]json.RawMessage
				_ = json.Unmarshal(pb, &m)
				for k := range m {
					if _, ok := prebuiltFields[k]; !ok {
						t.Errorf("软件 %q 版本 %q 的 prebuilt 含未知字段 %q", id, vid, k)
					}
				}
			}
		}
		if off, ok := sw["official"]; ok && string(off) != "null" {
			var fams map[string]map[string]json.RawMessage
			_ = json.Unmarshal(off, &fams)
			for fam, fields := range fams {
				for k := range fields {
					if _, ok := officialFields[k]; !ok {
						t.Errorf("软件 %q 的 official[%s] 含未知字段 %q", id, fam, k)
					}
				}
			}
		}
	}
}

// jsonFields 返回结构体上声明过的 json 字段名集合。
//
// 用反射读 tag 而不是"序列化一个零值再收集键"：后者会被
// `omitempty` 影响——零值字段不出现在输出里，于是测试会把
// 合法字段误报成"未知字段"（这条测试自己踩过一次）。
func jsonFields(v any) map[string]struct{} {
	t := reflect.TypeOf(v)
	out := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// TestCatalogDependencyOrder 验证依赖拓扑排序。
func TestCatalogDependencyOrder(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		query string
		want  []string
	}{
		{
			name:  "无依赖",
			body:  `{"software":[{"id":"a","name":"A","default_version":"1","versions":[{"id":"1","system_packages":["a"]}]}]}`,
			query: "a",
			want:  nil,
		},
		{
			name: "单层依赖",
			body: `{"software":[
				{"id":"a","name":"A","default_version":"1","versions":[{"id":"1","system_packages":["a"]}]},
				{"id":"b","name":"B","default_version":"1","depends":["a"],"versions":[{"id":"1","system_packages":["b"]}]}]}`,
			query: "b",
			want:  []string{"a"},
		},
		{
			name: "两层依赖按拓扑序返回",
			body: `{"software":[
				{"id":"a","name":"A","default_version":"1","versions":[{"id":"1","system_packages":["a"]}]},
				{"id":"b","name":"B","default_version":"1","depends":["a"],"versions":[{"id":"1","system_packages":["b"]}]},
				{"id":"c","name":"C","default_version":"1","depends":["b"],"versions":[{"id":"1","system_packages":["c"]}]}]}`,
			query: "c",
			want:  []string{"a", "b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := parseCatalog([]byte(tc.body))
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			got, err := cat.DependencyOrder(tc.query)
			if err != nil {
				t.Fatalf("拓扑排序失败: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCatalogDependencyCycle 断言依赖成环会被检出。
//
// 环会让"先装依赖"永远等不到头，必须在加载期就拒绝。
func TestCatalogDependencyCycle(t *testing.T) {
	body := `{"software":[
		{"id":"a","name":"A","default_version":"1","depends":["b"],"versions":[{"id":"1","system_packages":["a"]}]},
		{"id":"b","name":"B","default_version":"1","depends":["a"],"versions":[{"id":"1","system_packages":["b"]}]}]}`
	cat, err := parseCatalog([]byte(body))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, err := cat.DependencyOrder("a"); err == nil {
		t.Fatal("依赖成环未被检出")
	}
}

// TestSortVersionsDesc 验证版本降序排序（前端下拉顺序）。
func TestSortVersionsDesc(t *testing.T) {
	vs := []Version{{ID: "8.3"}, {ID: "8.10"}, {ID: "7.4"}, {ID: "22"}, {ID: "20"}}
	got := SortVersionsDesc(vs)
	want := "22,20,8.10,8.3,7.4"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

// TestCatalogSummary 验证摘要（启动日志用）。
func TestCatalogSummary(t *testing.T) {
	cat := MustCatalog()
	sum := cat.Summary()
	if len(sum) != len(cat.Software) {
		t.Fatalf("摘要条数 %d != 软件数 %d", len(sum), len(cat.Software))
	}
	for _, s := range sum {
		if !strings.Contains(s, "版本") {
			t.Errorf("摘要 %q 缺少版本数", s)
		}
	}
}
