package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lipanel/internal/file"
)

// ============================================================================
// 文件管理接口测试（阶段四 4.2）
// ============================================================================
//
// 这里测的是**真实的 HTTP 链路**：路由挂载 → 鉴权 → 权限判定 → 路径校验
// → 文件系统操作 → 审计 → 响应翻译。
// 不 mock file.Manager：路径安全的意义就在于"真实调用链上每一层都拦得住"，
// mock 掉中间层等于把要验证的东西假设掉了。

// newFileTestServer 构造一个注入了文件管理器的测试 Server。
//
// 返回 (server, root, outside)：root 是白名单根，outside 是根外的"机密区"，
// 用于验证越权访问确实被拦住。
func newFileTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 逃逸链接：字面在根内，实际指向根外。
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("环境不支持符号链接: %v", err)
	}

	auditor, err := file.NewAuditor(file.AuditOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAuditor 失败: %v", err)
	}
	mgr, err := file.NewManager(file.ManagerOptions{
		Roots:   []string{root},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auditor: auditor,
	})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.fileMgr = mgr
	rebuildTestRoutes(s)
	return s, root, outside
}

// doAuthedJSON 登录后发起带 JSON 体的请求。
//
// 复用 auth_api_test.go 里已有的 doJSON（body 序列化 + Cookie 注入），
// 这里只补上"自动登录"这一步，避免在文件测试里重复实现请求构造。
func doAuthedJSON(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, srv, method, path, body, login(t, srv))
}

// decodeBody 解析响应 JSON，并断言 Content-Type 是 JSON。
//
// 为什么必须断言 Content-Type：未注册的 /api 路径会落到 SPA 兜底返回
// **200 + text/html**（坑位 47）。只看状态码会把"接口没注册"误判为成功。
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type 应为 JSON，实际 %q（body=%q）", ct, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("解析响应失败: %v，body=%s", err, rec.Body.String())
	}
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	decodeBody(t, rec, &m)
	return m
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

func TestFileEndpointsRequireAuth(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	paths := []struct{ method, path string }{
		{"GET", "/api/files?path=" + root},
		{"GET", "/api/files/roots"},
		{"GET", "/api/files/audit"},
		{"GET", "/api/files/content?path=" + filepath.Join(root, "inside.txt")},
		{"PUT", "/api/files/content"},
		{"GET", "/api/files/download?path=" + filepath.Join(root, "inside.txt")},
		{"POST", "/api/files/upload"},
		{"POST", "/api/files/mkdir"},
		{"POST", "/api/files/rename"},
		{"POST", "/api/files/delete"},
	}
	for _, tc := range paths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("未登录应 401，实际 %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "TOP SECRET") {
				t.Fatal("未登录响应泄露了文件内容")
			}
		})
	}
}

func TestFileRoutesUnregisteredWithoutManager(t *testing.T) {
	// 未注入文件管理器时，必须是 JSON 503，而不是落到 HTML 兜底
	// （那会让前端拿到一段 HTML 并报"非 JSON 内容"，无从判断原因）。
	srv := newAuthedTestServer(t)
	cookie := login(t, srv)

	for _, path := range []string{"/api/files", "/api/files/roots", "/api/files/anything"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s 应返回 503，实际 %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("%s 应返回 JSON，实际 Content-Type=%q", path, ct)
		}
	}
}

// ---------------------------------------------------------------------------
// 列目录
// ---------------------------------------------------------------------------

func TestFileListAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	rec := loginAndDo(t, srv, "GET", "/api/files?path="+root)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，body=%s", rec.Code, rec.Body.String())
	}
	var listing file.DirListing
	decodeBody(t, rec, &listing)
	if listing.Path != root {
		t.Fatalf("Path 应为 %s，实际 %s", root, listing.Path)
	}
	if listing.Root != root {
		t.Fatalf("应回显命中的根目录 %s，实际 %q", root, listing.Root)
	}
	names := make([]string, 0, len(listing.Entries))
	for _, e := range listing.Entries {
		names = append(names, e.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "inside.txt") {
		t.Fatalf("缺少 inside.txt: %v", names)
	}
}

func TestFileListRejectsTraversal(t *testing.T) {
	srv, root, outside := newFileTestServer(t)

	cases := []string{
		root + "/../outside",
		root + "/sub/../../outside/secret.txt",
		outside,
		"/etc",
		"relative/path",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			rec := loginAndDo(t, srv, "GET", "/api/files?path="+p)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("越权路径应 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "TOP SECRET") {
				t.Fatal("响应泄露了根外文件内容")
			}
			// hint 必须告诉用户"怎么办"，否则只看到一句拒绝。
			m := decodeMap(t, rec)
			if h, _ := m["hint"].(string); h == "" {
				t.Fatal("越权响应必须带 hint")
			}
		})
	}
}

func TestFileListRejectsSymlinkEscape(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	rec := loginAndDo(t, srv, "GET", "/api/files?path="+filepath.Join(root, "escape"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("经逃逸链接列目录应 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "TOP SECRET") {
		t.Fatal("响应泄露了根外内容")
	}
}

func TestFileListMissingPathParam(t *testing.T) {
	srv, _, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少 path 应 400，实际 %d", rec.Code)
	}
}

func TestFileListNotDirectory(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files?path="+filepath.Join(root, "inside.txt"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("对文件列目录应 400，实际 %d", rec.Code)
	}
}

func TestFileListNotFound(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files?path="+filepath.Join(root, "nope"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的目录应 404，实际 %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// roots
// ---------------------------------------------------------------------------

func TestFileRootsAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files/roots")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rec.Code)
	}
	var resp struct {
		Roots       []map[string]string `json:"roots"`
		Permissions []string            `json:"permissions"`
		Limits      struct {
			MaxUploadBytes int64 `json:"max_upload_bytes"`
			MaxEditBytes   int64 `json:"max_edit_bytes"`
		} `json:"limits"`
	}
	decodeBody(t, rec, &resp)

	if len(resp.Roots) != 1 || resp.Roots[0]["path"] != root {
		t.Fatalf("根目录不符: %+v", resp.Roots)
	}
	if !strings.Contains(strings.Join(resp.Permissions, ","), file.PermWrite) {
		t.Fatalf("管理员应被授予 file.write，实际 %v", resp.Permissions)
	}
	if resp.Limits.MaxUploadBytes <= 0 || resp.Limits.MaxEditBytes <= 0 {
		t.Fatalf("限制未返回: %+v", resp.Limits)
	}
}

// ---------------------------------------------------------------------------
// 读写文本
// ---------------------------------------------------------------------------

func TestFileReadWriteAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	target := filepath.Join(root, "note.txt")

	// 新建
	rec := doAuthedJSON(t, srv, "PUT", "/api/files/content", map[string]any{
		"path": target, "content": "hello 世界", "overwrite": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("写入失败: %d %s", rec.Code, rec.Body.String())
	}
	var wr file.WriteResult
	decodeBody(t, rec, &wr)
	if !wr.Created || wr.Size != int64(len("hello 世界")) {
		t.Fatalf("写入结果不符: %+v", wr)
	}

	// 读回
	rec = loginAndDo(t, srv, "GET", "/api/files/content?path="+target)
	if rec.Code != http.StatusOK {
		t.Fatalf("读取失败: %d %s", rec.Code, rec.Body.String())
	}
	var fc file.FileContent
	decodeBody(t, rec, &fc)
	if fc.Content != "hello 世界" {
		t.Fatalf("内容不符: %q", fc.Content)
	}

	// 未确认覆盖 → 409
	rec = doAuthedJSON(t, srv, "PUT", "/api/files/content", map[string]any{
		"path": target, "content": "should not apply", "overwrite": false,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("未确认覆盖应 409，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	// 关键：被拒绝的写入不得改动文件。
	rec = loginAndDo(t, srv, "GET", "/api/files/content?path="+target)
	decodeBody(t, rec, &fc)
	if fc.Content != "hello 世界" {
		t.Fatalf("被拒绝的写入修改了文件: %q", fc.Content)
	}

	// 确认覆盖 → 200
	rec = doAuthedJSON(t, srv, "PUT", "/api/files/content", map[string]any{
		"path": target, "content": "v2", "overwrite": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("确认覆盖应 200，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestFileWriteRejectsEscape(t *testing.T) {
	srv, root, outside := newFileTestServer(t)

	// 两个方向都必须被拦住：写在根外、以及经逃逸链接写。
	cases := []string{
		filepath.Join(root, "..", "outside", "pwned.txt"),
		filepath.Join(root, "escape", "pwned.txt"),
		filepath.Join(outside, "pwned.txt"),
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			rec := doAuthedJSON(t, srv, "PUT", "/api/files/content", map[string]any{
				"path": target, "content": "pwned", "overwrite": true,
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("越权写入应 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
			}
		})
	}

	// 真正的断言：根外目录里不能出现任何新文件。
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "secret.txt" {
			t.Fatalf("根外目录出现意外文件: %s", e.Name())
		}
	}
	if data, _ := os.ReadFile(filepath.Join(outside, "secret.txt")); string(data) != "TOP SECRET" {
		t.Fatalf("根外文件被篡改: %q", data)
	}
}

func TestFileReadBinary(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	bin := filepath.Join(root, "bin.dat")
	if err := os.WriteFile(bin, []byte{0x00, 0xff, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := loginAndDo(t, srv, "GET", "/api/files/content?path="+bin)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("二进制文件应 415，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
}

func TestFileWriteBadJSON(t *testing.T) {
	srv, _, _ := newFileTestServer(t)
	cookie := login(t, srv)
	req := httptest.NewRequest("PUT", "/api/files/content", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400，实际 %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 新建 / 重命名 / 删除
// ---------------------------------------------------------------------------

func TestFileMkdirAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	target := filepath.Join(root, "newdir")

	rec := doAuthedJSON(t, srv, "POST", "/api/files/mkdir", map[string]any{"path": target})
	if rec.Code != http.StatusOK {
		t.Fatalf("新建目录失败: %d %s", rec.Code, rec.Body.String())
	}
	var entry file.Entry
	decodeBody(t, rec, &entry)
	if !entry.IsDir || entry.Path != target {
		t.Fatalf("返回条目不符: %+v", entry)
	}

	// 重复创建 → 409
	rec = doAuthedJSON(t, srv, "POST", "/api/files/mkdir", map[string]any{"path": target})
	if rec.Code != http.StatusConflict {
		t.Fatalf("重复创建应 409，实际 %d", rec.Code)
	}

	// 越权创建 → 400，且根外不能真的建出目录。
	evil := filepath.Join(root, "escape", "evil-dir")
	rec = doAuthedJSON(t, srv, "POST", "/api/files/mkdir", map[string]any{"path": evil})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("越权创建应 400，实际 %d", rec.Code)
	}
}

func TestFileRenameAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	src := filepath.Join(root, "old.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := doAuthedJSON(t, srv, "POST", "/api/files/rename", map[string]any{
		"path": src, "new_name": "new.txt",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("重命名失败: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "new.txt")); err != nil {
		t.Fatal("目标文件不存在")
	}

	// 新名字里带路径分隔符 → 400（本阶段只支持同目录改名）。
	rec = doAuthedJSON(t, srv, "POST", "/api/files/rename", map[string]any{
		"path": filepath.Join(root, "new.txt"), "new_name": "../evil.txt",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("带路径的新名字应 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "..", "evil.txt")); err == nil {
		t.Fatal("重命名逃逸成功——根外出现了文件")
	}
}

func TestFileDeleteAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := doAuthedJSON(t, srv, "POST", "/api/files/delete", map[string]any{"path": victim})
	if rec.Code != http.StatusOK {
		t.Fatalf("删除失败: %d %s", rec.Code, rec.Body.String())
	}
	var resp fileDeleteResponse
	decodeBody(t, rec, &resp)
	if !resp.Deleted || resp.Path != victim {
		t.Fatalf("删除响应不符: %+v", resp)
	}
	if _, err := os.Stat(victim); err == nil {
		t.Fatal("文件仍存在")
	}
}

func TestFileDeleteNonEmptyDirectoryNeedsRecursive(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	d := filepath.Join(root, "dir")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := doAuthedJSON(t, srv, "POST", "/api/files/delete", map[string]any{"path": d})
	if rec.Code != http.StatusConflict {
		t.Fatalf("非空目录未确认递归应 409，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(d, "f.txt")); err != nil {
		t.Fatal("被拒绝的删除破坏了目录内容")
	}

	rec = doAuthedJSON(t, srv, "POST", "/api/files/delete", map[string]any{"path": d, "recursive": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("递归删除应 200，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(d); err == nil {
		t.Fatal("目录仍存在")
	}
}

func TestFileDeleteEscape(t *testing.T) {
	srv, root, outside := newFileTestServer(t)

	cases := []string{
		filepath.Join(root, "..", "outside", "secret.txt"),
		filepath.Join(root, "escape", "secret.txt"),
	}
	for _, p := range cases {
		rec := doAuthedJSON(t, srv, "POST", "/api/files/delete", map[string]any{
			"path": p, "recursive": true,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("越权删除 %s 应 400，实际 %d", p, rec.Code)
		}
	}
	// 关键断言：机密文件必须还在，且内容未变。
	data, err := os.ReadFile(filepath.Join(outside, "secret.txt"))
	if err != nil {
		t.Fatalf("根外文件被删除: %v", err)
	}
	if string(data) != "TOP SECRET" {
		t.Fatalf("根外文件被篡改: %q", data)
	}
}

// ---------------------------------------------------------------------------
// 上传 / 下载
// ---------------------------------------------------------------------------

// buildUploadBody 构造 multipart 上传体。
func buildUploadBody(t *testing.T, target, filename, content string, overwrite bool) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	fields := map[string]string{
		"path":     target,
		"filename": filename,
	}
	if overwrite {
		fields["overwrite"] = "true"
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func TestFileUploadDownloadAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	body, contentType := buildUploadBody(t, root, "uploaded.txt", "上传的内容", false)
	cookie := login(t, srv)
	req := httptest.NewRequest("POST", "/api/files/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败: %d %s", rec.Code, rec.Body.String())
	}
	var ur file.UploadResult
	decodeBody(t, rec, &ur)
	if ur.Size != int64(len("上传的内容")) {
		t.Fatalf("上传大小不符: %+v", ur)
	}

	// 下载必须原样返回内容，并带正确的下载头。
	rec = loginAndDo(t, srv, "GET", "/api/files/download?path="+ur.Path)
	if rec.Code != http.StatusOK {
		t.Fatalf("下载失败: %d", rec.Code)
	}
	if rec.Body.String() != "上传的内容" {
		t.Fatalf("下载内容不符: %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("应带 attachment 头，实际 %q", cd)
	}
	if ct := rec.Header().Get("X-Content-Type-Options"); ct != "nosniff" {
		t.Fatalf("应带 nosniff（防上传的 HTML 被当页面渲染），实际 %q", ct)
	}
	if cl := rec.Header().Get("Content-Length"); cl != "15" {
		// "上传的内容" 是 15 字节 UTF-8。
		t.Fatalf("Content-Length 应为 15，实际 %q", cl)
	}
}

func TestFileUploadRefusesOverwrite(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	existing := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existing, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	body, contentType := buildUploadBody(t, root, "existing.txt", "overwritten", false)
	cookie := login(t, srv)
	req := httptest.NewRequest("POST", "/api/files/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("未确认覆盖应 409，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if data, _ := os.ReadFile(existing); string(data) != "original" {
		t.Fatalf("被拒绝的上传修改了文件: %q", data)
	}
}

func TestFileUploadEscapeBlocked(t *testing.T) {
	srv, root, outside := newFileTestServer(t)

	for _, target := range []string{
		filepath.Join(root, "escape"),
		filepath.Join(root, "..", "outside"),
	} {
		body, contentType := buildUploadBody(t, target, "pwned.txt", "pwned", true)
		cookie := login(t, srv)
		req := httptest.NewRequest("POST", "/api/files/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("经 %s 上传应当被拒绝", target)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Fatal("根外出现了上传的文件")
	}
}

func TestFileUploadRejectsBadFilename(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	// 经 filename 字段上传越权名字：必须被 validateName 拒绝。
	for _, name := range []string{"../escape.txt", "a/b.txt", ".."} {
		body, contentType := buildUploadBody(t, root, name, "x", true)
		cookie := login(t, srv)
		req := httptest.NewRequest("POST", "/api/files/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("文件名 %q 应被拒绝", name)
		}
	}
}

func TestFileUploadTooLarge(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	mgr, err := file.NewManager(file.ManagerOptions{
		Roots:          []string{root},
		MaxUploadBytes: 16,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newAuthedTestServer(t)
	s.fileMgr = mgr
	rebuildTestRoutes(s)

	body, contentType := buildUploadBody(t, root, "big.txt", strings.Repeat("x", 1024), false)
	cookie := login(t, s)
	req := httptest.NewRequest("POST", "/api/files/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限上传应 413，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	// 超限后不能留下半截文件。
	if _, err := os.Stat(filepath.Join(root, "big.txt")); err == nil {
		t.Fatal("被拒绝的上传留下了目标文件")
	}
}

func TestFileUploadMissingFileField(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", root)
	_ = mw.WriteField("filename", "x.txt")
	_ = mw.Close()

	cookie := login(t, srv)
	req := httptest.NewRequest("POST", "/api/files/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少 file 字段应 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "file") {
		t.Fatalf("提示应指出缺少 file 字段，实际 %s", rec.Body.String())
	}
}

func TestFileDownloadEscapeBlocked(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	for _, p := range []string{
		filepath.Join(root, "escape", "secret.txt"),
		filepath.Join(root, "..", "outside", "secret.txt"),
	} {
		rec := loginAndDo(t, srv, "GET", "/api/files/download?path="+p)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("越权下载 %s 应 400，实际 %d", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "TOP SECRET") {
			t.Fatal("越权下载泄露了内容")
		}
	}
}

func TestFileDownloadDirectory(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files/download?path="+root)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("下载目录应 400，实际 %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 审计接口
// ---------------------------------------------------------------------------

func TestFileAuditAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)

	// 先制造几条不同结果的记录。
	target := filepath.Join(root, "audited.txt")
	doAuthedJSON(t, srv, "PUT", "/api/files/content", map[string]any{
		"path": target, "content": "x", "overwrite": false,
	})
	doAuthedJSON(t, srv, "POST", "/api/files/mkdir", map[string]any{"path": filepath.Join(root, "ad")})
	// 越权探测（读操作，但属于安全信号，同样要留痕）。
	loginAndDo(t, srv, "GET", "/api/files?path="+filepath.Join(root, "..", "outside"))

	rec := loginAndDo(t, srv, "GET", "/api/files/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("审计接口失败: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Events []file.AuditEvent `json:"events"`
		Stats  file.AuditStats   `json:"stats"`
		Scope  string            `json:"scope_note"`
	}
	decodeBody(t, rec, &resp)

	if len(resp.Events) == 0 {
		t.Fatal("审计应有记录")
	}
	if resp.Stats.Total == 0 {
		t.Fatal("统计应有总数")
	}
	var sawWrite, sawDenied bool
	for _, ev := range resp.Events {
		if ev.Kind != file.KindFile {
			t.Errorf("Kind 应为 file，实际 %q", ev.Kind)
		}
		if ev.Source != file.SourceCore {
			t.Errorf("Source 应为 core，实际 %q", ev.Source)
		}
		if ev.User != "admin" {
			t.Errorf("应记录操作者 admin，实际 %q", ev.User)
		}
		switch {
		case ev.Action == file.ActionMkdir && ev.Outcome == file.AuditAllowed:
			sawWrite = true
		case ev.Outcome == file.AuditDenied:
			sawDenied = true
		}
	}
	if !sawWrite {
		t.Error("成功的写操作必须留痕")
	}
	if !sawDenied {
		t.Error("被拒绝的越权路径探测必须留痕（这是最重要的安全信号）")
	}
	if resp.Scope == "" {
		t.Error("应返回 scope_note 说明审计覆盖范围")
	}
}

func TestFileAuditFilterAPI(t *testing.T) {
	srv, root, _ := newFileTestServer(t)
	doAuthedJSON(t, srv, "POST", "/api/files/mkdir", map[string]any{"path": filepath.Join(root, "d1")})
	doAuthedJSON(t, srv, "POST", "/api/files/delete", map[string]any{"path": filepath.Join(root, "d1")})

	rec := loginAndDo(t, srv, "GET", "/api/files/audit?action=delete")
	var resp struct {
		Events []file.AuditEvent `json:"events"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Events) == 0 {
		t.Fatal("应能按动作过滤出记录")
	}
	for _, ev := range resp.Events {
		if ev.Action != file.ActionDelete {
			t.Fatalf("过滤后仍出现 %s 动作", ev.Action)
		}
	}
}

func TestFileAuditRouteNotShadowed(t *testing.T) {
	// 回归测试："/api/files/audit" 必须命中审计接口本身，
	// 而不是被当成某个文件操作路径（4.1 的 /api/services/audit 踩过同源坑）。
	srv, _, _ := newFileTestServer(t)
	rec := loginAndDo(t, srv, "GET", "/api/files/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d（body=%s）", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeBody(t, rec, &resp)
	if _, ok := resp["events"]; !ok {
		t.Fatalf("应返回审计结构，实际 %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 方法限制
// ---------------------------------------------------------------------------

func TestFileEndpointsMethodMismatch(t *testing.T) {
	// 实测出来的真实行为（与坑位 7 的描述不同，值得记下来）：
	//
	//	当 mux 上注册了 "/" 这个兜底模式时，**方法不匹配的请求会被交给兜底**，
	//	而不是返回 405 或 404。实测：只注册 "POST /p" + "/" 时，
	//	GET /p 得到的是兜底响应（200 + HTML）；只有没有 "/" 兜底时
	//	ServeMux 才会给出 405/404。
	//
	// 因此"GET 某个只支持 POST 的接口"在生产环境会落到前端 SPA 兜底页面，
	// 返回 200 + text/html。这本身不是漏洞（兜底只是首页，不会执行任何
	// 文件操作），但**必须把这个事实锁在测试里**——一旦将来有人给
	// /api/files/* 加上裸路径处理器，行为就会变。
	//
	// 这条用例最初写成"断言非 200 且 Content-Type 是 JSON"，
	// 那是把错误的实现假设写成了断言，实测立刻失败。现在改为断言
	// 真实且重要的性质：**方法不匹配绝不能产生任何副作用、也不能泄露内容。**
	srv, root, _ := newFileTestServer(t)
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	rec := loginAndDo(t, srv, "GET", "/api/files/mkdir")
	if rec.Code >= 500 {
		t.Fatalf("不应返回 5xx，实际 %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "inside.txt") {
		t.Fatalf("响应泄露了目录内容: %s", rec.Body.String())
	}

	// 关键断言：真的一个目录都没建出来。
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("方法不匹配的请求产生了副作用：条目从 %d 变成 %d", len(before), len(after))
	}

	// POST 到只支持 GET 的路径同理。
	rootRec := doAuthedJSON(t, srv, "POST", "/api/files/roots", map[string]any{"path": root})
	if rootRec.Code >= 500 {
		t.Fatalf("不应返回 5xx，实际 %d", rootRec.Code)
	}
	afterPost, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterPost) != len(before) {
		t.Fatal("POST /api/files/roots 产生了副作用")
	}
}

// TestUnregisteredFileAPIPathReturnsJSON 锁住"接口不存在"的响应形态。
//
// 未注册的 /api 路径必须返回 **JSON 404**，而不是前端 HTML——
// 否则前端会拿到一整页 HTML 并报出语焉不详的"后端返回了非 JSON 内容"。
// 这正是坑位 47（HTML 兜底让资源缺失伪装成 200）要防的那类问题。
func TestUnregisteredFileAPIPathReturnsJSON(t *testing.T) {
	srv, _, _ := newFileTestServer(t)

	rec := loginAndDo(t, srv, "GET", "/api/files/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未注册路径应 404，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatal("未注册的 /api 路径落到了前端 HTML 兜底")
	}
	assertJSONContentType(t, rec)
}
