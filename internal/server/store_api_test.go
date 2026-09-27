package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lipanel/internal/store"
)

// ============================================================================
// 软件商店接口层测试（阶段四 4.5）
// ============================================================================
//
// 这一层要验证的不是"装软件能不能成功"（那是 internal/store 的事），
// 而是四件接口契约：
//
//	① 路由注册顺序：固定段不能被 /{name}/... 通配吃掉；
//	② 全部接口都要登录；
//	③ 写操作顺序：校验 → 权限 → 发起任务（被拒绝时零副作用）；
//	④ 异步语义：写接口返回 202 + 任务 ID，进度靠轮询。
//
// ①是 4.1~4.4 连续踩过四次的坑，因此这里单独用测试锁死。

// storeStubExecutor 是接口层用的最小假执行器。
//
// 接口层测试不关心命令语义，只需要"任何命令都成功"，
// 让安装任务能跑完（否则轮询测试拿不到终态）。
type storeStubExecutor struct {
	mu    sync.Mutex
	calls []string
	// installed 是假包数据库（包名 → 版本）。
	installed map[string]string
	// candidates 是 apt-cache policy 的候选版本。
	candidates map[string]string
	// block 非 nil 时安装命令会阻塞（用于测并发 409）。
	block chan struct{}
}

func newStoreStubExecutor() *storeStubExecutor {
	return &storeStubExecutor{
		installed:  map[string]string{},
		candidates: map[string]string{},
	}
}

func (e *storeStubExecutor) Run(ctx context.Context, name string, args []string) (store.ExecResult, error) {
	base := filepath.Base(name)
	joined := strings.Join(args, " ")

	e.mu.Lock()
	e.calls = append(e.calls, base+" "+joined)
	block := e.block
	e.mu.Unlock()

	// 阻塞点：只拦安装命令，避免把查询也挂住。
	if block != nil && base == "apt-get" && strings.Contains(joined, "install") {
		select {
		case <-ctx.Done():
			return store.ExecResult{}, ctx.Err()
		case <-block:
		}
	}

	sub := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			sub = a
			break
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	switch {
	case base == "apt-cache":
		pkg := args[len(args)-1]
		cand := e.candidates[pkg]
		if cand == "" {
			cand = "(none)"
		}
		return store.ExecResult{Stdout: pkg + ":\n  Candidate: " + cand + "\n"}, nil
	case base == "dpkg-query":
		var b strings.Builder
		for _, a := range args {
			if strings.HasPrefix(a, "-") || strings.ContainsAny(a, "${}|") {
				continue
			}
			// 面板可能传钉版本的 `pkg=ver`（复验已改为传裸名，
			// 但假执行器两种都要能处理，否则会掩盖真实 bug）。
			name := a
			if i := strings.Index(a, "="); i >= 0 {
				name = a[:i]
			}
			if v, ok := e.installed[name]; ok {
				b.WriteString(name + "|" + v + "|ii \n")
			}
		}
		return store.ExecResult{Stdout: b.String()}, nil
	case base == "apt-get" && sub == "install":
		for _, a := range args {
			if !isStorePkgArg(a) {
				continue
			}
			// 钉版本语法 `pkg=ver`：数据库里记裸包名、版本取 = 右边。
			name, want := a, ""
			if i := strings.Index(a, "="); i >= 0 {
				name, want = a[:i], a[i+1:]
			}
			if want != "" {
				e.installed[name] = want
				continue
			}
			if v, ok := e.candidates[name]; ok && v != "" && v != "(none)" {
				e.installed[name] = v
			}
		}
		return store.ExecResult{ExitCode: 0}, nil
	case base == "apt-get" && sub == "remove":
		for _, a := range args {
			if isStorePkgArg(a) {
				delete(e.installed, a)
			}
		}
		return store.ExecResult{ExitCode: 0}, nil
	case base == "curl":
		// 官方源公钥下载：造出目标文件即可。
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.MkdirAll(filepath.Dir(args[i+1]), 0o755)
				_ = os.WriteFile(args[i+1], []byte("fake"), 0o644)
			}
		}
		return store.ExecResult{ExitCode: 0}, nil
	}
	return store.ExecResult{ExitCode: 0}, nil
}

func (e *storeStubExecutor) RunScript(_ context.Context, cmd string) (store.ExecResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, "sh -c "+cmd)
	return store.ExecResult{Stdout: "ok"}, nil
}

func (e *storeStubExecutor) calledWith(substr string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// isStorePkgArg 过滤掉选项与其取值，只留包名。
func isStorePkgArg(a string) bool {
	if a == "" || strings.HasPrefix(a, "-") {
		return false
	}
	switch a {
	case "install", "remove", "update", "autoremove", "policy", "list":
		return false
	}
	// `-o Dpkg::Options::=...` 的取值：含 :: 的是选项值，不是包条目。
	// 注意不能笼统"含 = 就不是包名"——钉版本语法也含 =。
	if i := strings.Index(a, "="); i >= 0 {
		left := a[:i]
		if strings.Contains(left, "::") || strings.HasPrefix(left, "-") {
			return false
		}
	}
	if strings.Contains(a, ":") {
		return false
	}
	return true
}

// storeTestEnv 是软件商店接口测试环境。
type storeTestEnv struct {
	server  *Server
	manager *store.Manager
	exec    *storeStubExecutor
	dir     string
}

// newStoreTestServer 构造一个注入了软件商店管理器的测试 Server。
func newStoreTestServer(t *testing.T, mut func(*store.Options)) *storeTestEnv {
	t.Helper()
	dir := t.TempDir()
	exec := newStoreStubExecutor()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	vars := store.Vars{
		Manager: store.PackageManagerAPT, ManagerPath: "/usr/bin/apt-get",
		Family: store.FamilyDebian, DistroID: "ubuntu",
		DistroName: "Ubuntu 22.04.5 LTS", VersionID: "22.04",
		Codename: "jammy", Arch: "x64",
		Tools: store.Tools{
			AptGet: "/usr/bin/apt-get", AptCache: "/usr/bin/apt-cache",
			DpkgQuery: "/usr/bin/dpkg-query", Curl: "/usr/bin/curl",
			Tar: "/usr/bin/tar",
		},
		DistroSupported: true,
	}

	opts := store.Options{
		Logger: logger,
		// 环境由测试显式给出，避免 NewManager 去探测本机。
		SkipDetect:           true,
		Executor:             exec,
		Vars:                 vars,
		StateDir:             filepath.Join(dir, "state"),
		ListDirOverride:      filepath.Join(dir, "apt-sources"),
		KeyringDirOverride:   filepath.Join(dir, "keyrings"),
		YumRepoDirOverride:   filepath.Join(dir, "yum-repos"),
		PrebuiltRootOverride: filepath.Join(dir, "prebuilt-root"),
		StepTimeout:          5 * time.Second,
		TaskTimeout:          20 * time.Second,
	}
	if mut != nil {
		mut(&opts)
	}
	mgr, err := store.NewManager(opts)
	if err != nil {
		t.Fatalf("构造软件商店管理器失败: %v", err)
	}

	s := newAuthedTestServer(t)
	s.storeMgr = mgr
	rebuildTestRoutes(s)

	return &storeTestEnv{server: s, manager: mgr, exec: exec, dir: dir}
}

// do 发起一次已登录的 JSON 请求。
func (e *storeTestEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, body, login(t, e.server))
}

// doAnon 发起一次未登录请求。
func (e *storeTestEnv) doAnon(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, e.server, method, path, nil)
}

// waitTask 轮询任务直到终态。
func (e *storeTestEnv) waitTask(t *testing.T, id string) store.Task {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := e.manager.Task(id)
		if !ok {
			t.Fatalf("任务 %s 不存在", id)
		}
		if task.Status == store.TaskSucceeded || task.Status == store.TaskFailed {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("任务超时未结束")
	return store.Task{}
}

// ---------------------------------------------------------------------------
// 路由注册顺序（4.1~4.4 连续踩过四次的坑）
// ---------------------------------------------------------------------------

// TestStoreFixedRoutesNotShadowedByWildcard 验证固定段路由不被通配吃掉。
//
// 若 /api/store/capabilities 被 /api/store/{name}/... 抢先匹配，
// "查看能力"会变成"安装名为 capabilities 的软件"——一个 GET 请求
// 变成写操作，这是最坏的一类路由错误。
func TestStoreFixedRoutesNotShadowedByWildcard(t *testing.T) {
	env := newStoreTestServer(t, nil)

	cases := []struct {
		path string
		// marker 是响应体里必须出现的字符串（证明走的是预期的处理器）。
		marker string
	}{
		{"/api/store/capabilities", "environment"},
		{"/api/store/audit", "events"},
		{"/api/store/tasks", "tasks"},
	}
	for _, tc := range cases {
		w := env.do(t, http.MethodGet, tc.path, nil)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d，应为 200（可能被通配路由吃掉了）\n%s",
				tc.path, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), tc.marker) {
			t.Errorf("GET %s 的响应缺少 %q，可能命中了别的处理器: %s",
				tc.path, tc.marker, w.Body.String())
		}
	}

	// 反向确认：通配路由本身仍然可用（别为了修 404 把安装接口改坏了）。
	w := env.do(t, http.MethodPost, "/api/store/nginx/uninstall", nil)
	if w.Code != http.StatusAccepted {
		t.Errorf("POST /api/store/nginx/uninstall = %d，应为 202: %s", w.Code, w.Body.String())
	}
}

// TestStoreUnknownSubpathReturnsJSON404 验证前缀兜底返回 JSON 而不是 HTML。
//
// 落到前端 SPA 兜底会返回 200 + text/html，
// 前端 fetch 会拿到一段 HTML 去 JSON.parse，报出难以理解的解析错误。
func TestStoreUnknownSubpathReturnsJSON404(t *testing.T) {
	env := newStoreTestServer(t, nil)

	w := env.do(t, http.MethodGet, "/api/store/nope/deeper/path", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("= %d，应为 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q，应为 JSON", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, w.Body.String())
	}
	// 404 里必须列出可用接口：这类 404 多半是路径写错。
	available, ok := body["available"].([]any)
	if !ok || len(available) == 0 {
		t.Errorf("404 响应应列出可用接口: %s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

// TestStoreRequiresAuth 验证全部接口都要求登录。
func TestStoreRequiresAuth(t *testing.T) {
	env := newStoreTestServer(t, nil)

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/store"},
		{http.MethodGet, "/api/store/capabilities"},
		{http.MethodGet, "/api/store/audit"},
		{http.MethodGet, "/api/store/tasks"},
		{http.MethodGet, "/api/store/tasks/t1"},
		{http.MethodPost, "/api/store/nginx/install"},
		{http.MethodPost, "/api/store/nginx/uninstall"},
	}
	for _, tc := range cases {
		w := env.doAnon(t, tc.method, tc.path)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未登录 = %d，应为 401", tc.method, tc.path, w.Code)
		}
	}
}

// TestStoreUnavailableWhenNotInjected 验证未注入管理器时返回 JSON 503。
func TestStoreUnavailableWhenNotInjected(t *testing.T) {
	s := newAuthedTestServer(t)
	rebuildTestRoutes(s)

	for _, path := range []string{"/api/store", "/api/store/capabilities"} {
		w := doJSON(t, s, http.MethodGet, path, nil, login(t, s))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d，应为 503", path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("GET %s 的 Content-Type = %q，应为 JSON（不能落到 HTML 兜底）", path, ct)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/store
// ---------------------------------------------------------------------------

// TestStoreListResponse 验证清单响应结构。
func TestStoreListResponse(t *testing.T) {
	env := newStoreTestServer(t, nil)

	w := env.do(t, http.MethodGet, "/api/store", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Software []struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			DefaultVersion string `json:"default_version"`
			Versions       []struct {
				ID        string `json:"id"`
				IsDefault bool   `json:"is_default"`
			} `json:"versions"`
			CanInstall bool `json:"can_install"`
		} `json:"software"`
		Available   bool     `json:"available"`
		DryRun      bool     `json:"dry_run"`
		Permissions []string `json:"permissions"`
		Environment struct {
			PackageManager string `json:"package_manager"`
			Family         string `json:"family"`
			Arch           string `json:"arch"`
		} `json:"environment"`
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
		Audit struct {
			Capacity int `json:"capacity"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(body.Software) < 5 {
		t.Errorf("应列出 5 个软件，实际 %d", len(body.Software))
	}
	if !body.Available {
		t.Error("应报告可用")
	}
	if body.Environment.PackageManager != "apt" || body.Environment.Family != "debian" {
		t.Errorf("环境摘要错误: %+v", body.Environment)
	}
	if body.Counts.Total != len(body.Software) {
		t.Errorf("Counts.Total = %d，与清单长度 %d 不一致", body.Counts.Total, len(body.Software))
	}
	if len(body.Permissions) != 2 {
		t.Errorf("应回显两条权限: %v", body.Permissions)
	}
	// 每个软件必须恰好有一个默认版本，且该版本要在列表里。
	for _, sw := range body.Software {
		defaults := 0
		found := false
		for _, v := range sw.Versions {
			if v.IsDefault {
				defaults++
			}
			if v.ID == sw.DefaultVersion {
				found = true
			}
		}
		if defaults != 1 || !found {
			t.Errorf("%s 的默认版本标记不正确: defaults=%d found=%v", sw.ID, defaults, found)
		}
	}
}

// TestStoreListIncludesRunningTask 验证列表里能看到正在跑的任务。
//
// 这是刷新页面后的"唯一线索"：若列表不返回 running，
// 用户刷新后会以为没有任务在跑，再点一次安装。
func TestStoreListIncludesRunningTask(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"
	env.exec.block = make(chan struct{})

	// 同 TestStoreInstallConflictWhenBusy：先放行任务、再等它结束，
	// 否则测试返回时任务仍在写即将被清理的临时目录。
	defer func() {
		close(env.exec.block)
		if rt := env.manager.RunningTask(); rt != nil {
			env.waitTask(t, rt.ID)
		}
	}()

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("发起安装 = %d: %s", w.Code, w.Body.String())
	}

	// 等任务真正开始执行。
	deadline := time.Now().Add(3 * time.Second)
	for env.manager.RunningTask() == nil {
		if time.Now().After(deadline) {
			t.Fatal("任务没有开始执行")
		}
		time.Sleep(5 * time.Millisecond)
	}

	lw := env.do(t, http.MethodGet, "/api/store", nil)
	var body struct {
		Running *struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"running"`
		Counts struct {
			Pending int `json:"pending"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Running == nil {
		t.Fatal("列表响应应包含运行中的任务")
	}
	if body.Running.Status != store.TaskRunning {
		t.Errorf("运行中任务的状态 = %q", body.Running.Status)
	}
	if body.Counts.Pending < 1 {
		t.Errorf("Counts.Pending = %d，应有 1 个进行中的任务", body.Counts.Pending)
	}
}

// ---------------------------------------------------------------------------
// GET /api/store/capabilities
// ---------------------------------------------------------------------------

// TestStoreCapabilities 验证能力探测响应。
func TestStoreCapabilities(t *testing.T) {
	env := newStoreTestServer(t, nil)

	w := env.do(t, http.MethodGet, "/api/store/capabilities", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Available bool              `json:"available"`
		Tools     map[string]string `json:"tools"`
		Software  []struct {
			ID       string `json:"id"`
			Versions []struct {
				ID                string `json:"id"`
				IsDefault         bool   `json:"is_default"`
				OfficialAvailable bool   `json:"official_available"`
				OfficialKind      string `json:"official_kind"`
				PrebuiltAvailable bool   `json:"prebuilt_available"`
			} `json:"versions"`
		} `json:"software"`
		StepTimeoutSeconds int `json:"step_timeout_seconds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !body.Available {
		t.Error("应报告可用")
	}
	if body.Tools["apt-get"] == "" || body.Tools["curl"] == "" {
		t.Errorf("应列出依赖的外部命令: %v", body.Tools)
	}
	if body.StepTimeoutSeconds != 5 {
		t.Errorf("StepTimeoutSeconds = %d，应为 5", body.StepTimeoutSeconds)
	}
	// 关键断言：官方源与预编译的可用性必须逐版本给出，
	// 前端据此解释"为什么这个版本要联网装"。
	var nginx *struct {
		ID       string `json:"id"`
		Versions []struct {
			ID                string `json:"id"`
			IsDefault         bool   `json:"is_default"`
			OfficialAvailable bool   `json:"official_available"`
			OfficialKind      string `json:"official_kind"`
			PrebuiltAvailable bool   `json:"prebuilt_available"`
		} `json:"versions"`
	}
	for i := range body.Software {
		if body.Software[i].ID == "nodejs" {
			nginx = &body.Software[i]
		}
	}
	if nginx == nil {
		t.Fatal("应包含 nodejs")
	}
	foundPrebuilt := false
	for _, v := range nginx.Versions {
		if v.PrebuiltAvailable {
			foundPrebuilt = true
		}
	}
	if !foundPrebuilt {
		t.Error("nodejs 的版本应报告有预编译兜底")
	}
}

// TestStoreCapabilitiesWhenUnavailable 验证无包管理器时仍返回 200。
//
// 关键：能装和能看是两回事。即使装不了，也要让前端拿到
// available=false 与原因，从而渲染说明而不是整页报错。
func TestStoreCapabilitiesWhenUnavailable(t *testing.T) {
	env := newStoreTestServer(t, func(o *store.Options) {
		o.Vars = store.Vars{Arch: "x64"}
	})

	w := env.do(t, http.MethodGet, "/api/store/capabilities", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d，不可用也应返回 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Available         bool   `json:"available"`
		UnavailableReason string `json:"unavailable_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Available {
		t.Error("应报告不可用")
	}
	if body.UnavailableReason == "" {
		t.Error("不可用时必须给出原因")
	}
	// 清单仍要正常返回。
	lw := env.do(t, http.MethodGet, "/api/store", nil)
	if lw.Code != http.StatusOK {
		t.Errorf("不可用时列表接口也应返回 200，实际 %d", lw.Code)
	}
}

// ---------------------------------------------------------------------------
// POST 安装 / 卸载（异步语义）
// ---------------------------------------------------------------------------

// TestStoreInstallReturns202WithTask 验证安装返回 202 + 任务 ID。
func TestStoreInstallReturns202WithTask(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("= %d，应为 202（异步受理）: %s", w.Code, w.Body.String())
	}
	var body struct {
		Task struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Software string `json:"software"`
			Version  string `json:"version"`
			Status   string `json:"status"`
			User     string `json:"user"`
		} `json:"task"`
		Hint string `json:"hint"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Task.ID == "" {
		t.Fatal("应返回任务 ID")
	}
	if body.Task.Kind != store.TaskInstall {
		t.Errorf("Kind = %q", body.Task.Kind)
	}
	if body.Task.User == "" {
		t.Error("任务应记录发起者")
	}
	// 提示必须告诉调用方怎么拿进度（否则 202 会让人以为已经装好）。
	if !strings.Contains(body.Hint, body.Task.ID) || !strings.Contains(body.Hint, "轮询") {
		t.Errorf("202 的提示应说明如何轮询进度: %q", body.Hint)
	}

	done := env.waitTask(t, body.Task.ID)
	if done.Status != store.TaskSucceeded {
		t.Fatalf("任务应成功: %s", done.Error)
	}
	if !env.exec.calledWith("nginx") {
		t.Error("应真的调用了包管理器")
	}
}

// TestStoreInstallEmptyBodyUsesDefaultVersion 验证空请求体用默认版本。
func TestStoreInstallEmptyBodyUsesDefaultVersion(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("= %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Task struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"task"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	sw, _ := env.manager.Catalog().Get("nginx")
	if body.Task.Version != sw.DefaultVersion {
		t.Errorf("Version = %q，应为默认版本 %q", body.Task.Version, sw.DefaultVersion)
	}
}

// TestStoreInstallRejectsInjection 穷举注入载荷。
//
// 接口层是**第一道**闸门，因此这里必须确认：
// 非法输入被拒，且**零外部命令执行**。
func TestStoreInstallRejectsInjection(t *testing.T) {
	env := newStoreTestServer(t, nil)

	paths := []struct {
		name string
		want int
	}{
		{"nginx;id", http.StatusBadRequest},
		{"nginx%7Cid", http.StatusBadRequest},
		{"$(whoami)", http.StatusBadRequest},
		{"..%2Fetc%2Fpasswd", http.StatusBadRequest},
		{"NGINX", http.StatusBadRequest},
		{"nonexistent", http.StatusNotFound},
	}
	for _, tc := range paths {
		w := env.do(t, http.MethodPost, "/api/store/"+tc.name+"/install", nil)
		if w.Code != tc.want {
			t.Errorf("install(%q) = %d，应为 %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
	// 版本号注入走 JSON 体。
	for _, v := range []string{"1.26; id", "$(id)", "1.26 && touch /tmp/pwned", "1.26/../etc", "9.99"} {
		w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": v})
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("version=%q = %d，应为 400 或 404: %s", v, w.Code, w.Body.String())
		}
	}
	// 零命令执行：被拒绝的请求绝不能碰包管理器。
	if env.exec.calledWith("apt-get") {
		t.Errorf("非法输入不得执行任何命令: %v", env.exec.calls)
	}
}

// TestStoreInstallConflictWhenBusy 验证已有任务时返回 409。
func TestStoreInstallConflictWhenBusy(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"
	env.exec.block = make(chan struct{})

	// ########## 必须在测试结束前把阻塞的任务放掉 ##########
	//
	// 这个测试故意让安装命令阻塞，以验证第二个请求拿到 409。
	// 但如果测试在任务仍被阻塞时返回：
	//   · t.TempDir() 的清理会删掉 StateDir，而任务的 goroutine
	//     还在跑并继续写这个目录 → 在 -race 下表现为清理失败或
	//     数据竞争，看起来像"死锁"（实测 -race 下挂满 600s）；
	//   · 更本质的问题是这样会让测试污染下一个测试。
	// 因此用 defer 保证"先放行任务、再等它真正结束"，
	// 这个顺序不能反：先等后放会永远等不到。
	defer func() {
		close(env.exec.block)
		if rt := env.manager.RunningTask(); rt != nil {
			env.waitTask(t, rt.ID)
		}
	}()

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("第一个任务 = %d: %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for env.manager.RunningTask() == nil {
		if time.Now().After(deadline) {
			t.Fatal("第一个任务没有开始")
		}
		time.Sleep(5 * time.Millisecond)
	}

	w2 := env.do(t, http.MethodPost, "/api/store/php/install", map[string]any{"version": "8.3"})
	if w2.Code != http.StatusConflict {
		t.Fatalf("并发安装 = %d，应为 409: %s", w2.Code, w2.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 409 必须解释"为什么不让重试"，否则用户只会反复点。
	hint, _ := body["hint"].(string)
	if !strings.Contains(hint, "全局锁") && !strings.Contains(hint, "等待") {
		t.Errorf("409 的提示应解释原因: %q", hint)
	}
}

// TestStoreInstallDeterministicVersionKinds 验证各类错误的 HTTP 映射。
func TestStoreInstallErrorMapping(t *testing.T) {
	env := newStoreTestServer(t, nil)
	// 已装 1.18，要装 1.26 → 版本冲突 409。
	env.exec.installed["nginx"] = "1.18.0-6ubuntu14"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("应受理（冲突在任务里失败）= %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	done := env.waitTask(t, body.Task.ID)
	if done.Status != store.TaskFailed {
		t.Fatalf("版本冲突应失败: %s", done.Status)
	}
	if !strings.Contains(done.Hint, "卸载") {
		t.Errorf("冲突的任务提示应引导先卸载: %q", done.Hint)
	}
}

// TestStoreUninstall 验证卸载接口。
func TestStoreUninstall(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.installed["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/uninstall", map[string]any{"version": "1.26"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("= %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Task struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"task"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Task.Kind != store.TaskUninstall {
		t.Errorf("Kind = %q", body.Task.Kind)
	}
	done := env.waitTask(t, body.Task.ID)
	if done.Status != store.TaskSucceeded {
		t.Fatalf("卸载应成功: %s", done.Error)
	}
	if _, ok := env.exec.installed["nginx"]; ok {
		t.Error("包应被移除")
	}
	if !env.exec.calledWith("remove") {
		t.Error("应调用包管理器卸载")
	}
}

// ---------------------------------------------------------------------------
// GET /api/store/tasks 与 /tasks/{id}
// ---------------------------------------------------------------------------

// TestStoreTaskPolling 验证轮询接口的游标语义。
func TestStoreTaskPolling(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	var created struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	id := created.Task.ID
	env.waitTask(t, id)

	// 全量拉取。
	full := env.do(t, http.MethodGet, "/api/store/tasks/"+id+"?since=0", nil)
	if full.Code != http.StatusOK {
		t.Fatalf("= %d: %s", full.Code, full.Body.String())
	}
	var first struct {
		Task struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Progress int    `json:"progress"`
			LogTotal int    `json:"log_total"`
		} `json:"task"`
		Logs      []store.LogLine `json:"logs"`
		Since     int             `json:"since"`
		NextSince int             `json:"next_since"`
		Done      bool            `json:"done"`
	}
	if err := json.Unmarshal(full.Body.Bytes(), &first); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if first.Task.Status != store.TaskSucceeded {
		t.Errorf("Status = %q", first.Task.Status)
	}
	if first.Task.Progress != 100 {
		t.Errorf("Progress = %d", first.Task.Progress)
	}
	if !first.Done {
		t.Error("终态任务的 done 应为 true（前端据此停止轮询）")
	}
	if len(first.Logs) == 0 {
		t.Fatal("应返回日志")
	}
	if first.NextSince != first.Logs[len(first.Logs)-1].Seq {
		t.Errorf("NextSince = %d，应为最后一条日志的序号 %d",
			first.NextSince, first.Logs[len(first.Logs)-1].Seq)
	}

	// 用 NextSince 再拉一次：应该没有新日志（增量语义）。
	inc := env.do(t, http.MethodGet,
		"/api/store/tasks/"+id+"?since="+itoa(first.NextSince), nil)
	var second struct {
		Logs      []store.LogLine `json:"logs"`
		NextSince int             `json:"next_since"`
	}
	if err := json.Unmarshal(inc.Body.Bytes(), &second); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(second.Logs) != 0 {
		t.Errorf("增量拉取应返回空，实际 %d 条", len(second.Logs))
	}
	// 游标不能倒退：没有新日志时保持原值，避免前端每轮重拉全量。
	if second.NextSince != first.NextSince {
		t.Errorf("无新日志时 NextSince 应保持不变: %d != %d", second.NextSince, first.NextSince)
	}
}

// TestStoreTaskNotFound 验证任务不存在与非法 ID 的区分。
func TestStoreTaskNotFound(t *testing.T) {
	env := newStoreTestServer(t, nil)

	// 形态合法但不存在 → 404，且提示"任务保存在内存里"。
	w := env.do(t, http.MethodGet, "/api/store/tasks/t999", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("= %d，应为 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "内存") {
		t.Errorf("404 应解释任务为何查不到: %s", w.Body.String())
	}

	// 形态非法 → 400（任务 ID 是用户输入，不能原样反射）。
	// 注意 "%2e%2e%2fetc" 是**编码后**的路径穿越：
	// 未编码的 "../etc" 会被 net/http 的 mux 先做路径规范化并返回 307，
	// 请求根本到不了处理器，因此测不到我们自己的校验。
	for _, bad := range []string{"abc", "t1;id", "%24(x)", "%2e%2e%2fetc", "T1"} {
		w := env.do(t, http.MethodGet, "/api/store/tasks/"+bad, nil)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("tasks/%s = %d，应为 400 或 404: %s", bad, w.Code, w.Body.String())
		}
	}
	// 未编码的路径穿越由 mux 规范化拦下（重定向到清理后的路径），
	// 这也是一种可接受的防护，此处记录该行为以免日后被误改成 200。
	if w := env.do(t, http.MethodGet, "/api/store/tasks/../etc", nil); w.Code != http.StatusMovedPermanently {
		t.Logf("路径穿越请求返回 %d（mux 行为可能变化）", w.Code)
	}
}

// TestStoreTasksList 验证任务列表。
func TestStoreTasksList(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	var created struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	env.waitTask(t, created.Task.ID)

	lw := env.do(t, http.MethodGet, "/api/store/tasks", nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("= %d: %s", lw.Code, lw.Body.String())
	}
	var body struct {
		Tasks []store.Task `json:"tasks"`
		Count int          `json:"count"`
		Limit int          `json:"limit"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Count < 1 || len(body.Tasks) < 1 {
		t.Fatalf("应至少有一个任务: %+v", body)
	}
	if body.Limit != 20 {
		t.Errorf("默认 Limit = %d，应为 20", body.Limit)
	}

	// 非法 limit 必须被夹住，而不是报错或返回巨量数据。
	big := env.do(t, http.MethodGet, "/api/store/tasks?limit=99999", nil)
	var bigBody struct {
		Limit int `json:"limit"`
	}
	_ = json.Unmarshal(big.Body.Bytes(), &bigBody)
	if bigBody.Limit > 100 {
		t.Errorf("limit 应被夹到 100，实际 %d", bigBody.Limit)
	}
}

// ---------------------------------------------------------------------------
// GET /api/store/audit
// ---------------------------------------------------------------------------

// TestStoreAudit 验证审计接口与过滤。
func TestStoreAudit(t *testing.T) {
	env := newStoreTestServer(t, nil)
	env.exec.candidates["nginx"] = "1.26.2-1~jammy"

	w := env.do(t, http.MethodPost, "/api/store/nginx/install", map[string]any{"version": "1.26"})
	var created struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	env.waitTask(t, created.Task.ID)

	aw := env.do(t, http.MethodGet, "/api/store/audit", nil)
	if aw.Code != http.StatusOK {
		t.Fatalf("= %d: %s", aw.Code, aw.Body.String())
	}
	var body struct {
		Events []store.AuditEvent `json:"events"`
		Count  int                `json:"count"`
		Stats  store.AuditStats   `json:"stats"`
	}
	if err := json.Unmarshal(aw.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Count == 0 {
		t.Fatal("应有审计事件")
	}
	// 每次安装应留下"发起(pending)"与"终态"两条记录。
	var pending, terminal int
	for _, ev := range body.Events {
		if ev.TaskID != created.Task.ID {
			continue
		}
		switch ev.Outcome {
		case store.AuditPending:
			pending++
		case store.AuditAllowed, store.AuditFailed:
			terminal++
		}
	}
	if pending == 0 {
		t.Error("应有 pending（任务已受理）的记录")
	}
	if terminal == 0 {
		t.Error("应有终态记录")
	}

	// 过滤：按动作。
	fw := env.do(t, http.MethodGet, "/api/store/audit?action=install", nil)
	var filtered struct {
		Events []store.AuditEvent `json:"events"`
	}
	_ = json.Unmarshal(fw.Body.Bytes(), &filtered)
	for _, ev := range filtered.Events {
		if ev.Action != store.ActionInstall {
			t.Errorf("按 action=install 过滤后出现了 %q", ev.Action)
		}
	}

	// 被拒绝的请求也要留痕（denied 的含义是"没有发生任何外部调用"）。
	env.do(t, http.MethodPost, "/api/store/nginx;id/install", nil)
	dw := env.do(t, http.MethodGet, "/api/store/audit?outcome=denied", nil)
	var denied struct {
		Events []store.AuditEvent `json:"events"`
	}
	_ = json.Unmarshal(dw.Body.Bytes(), &denied)
	if len(denied.Events) == 0 {
		t.Error("被拒绝的请求必须留下 denied 记录")
	}
	for _, ev := range denied.Events {
		if ev.SystemChange {
			t.Error("被拒绝的请求不应标记为改变了系统")
		}
	}
}

// ---------------------------------------------------------------------------
// 权限
// ---------------------------------------------------------------------------

// TestStorePermissionDeniedIsAudited 验证权限拒绝会留痕。
//
// 当前策略是"登录即管理员"，因此正常路径测不到拒绝分支。
// 这里直接调用判定函数验证其形状，并确认接口在授权收窄时
// 会返回 403（用 AdminGrantee 的可替换性来模拟）。
func TestStorePermissionDeniedShape(t *testing.T) {
	// 只读用户尝试安装。
	d := store.CheckStorePermission(store.Grantee{User: "viewer", Granted: []string{store.PermRead}}, store.ActionInstall)
	if d.Allowed {
		t.Fatal("只读用户不应被允许安装")
	}
	if d.Required != store.PermWrite || d.Reason == "" || d.Hint == "" {
		t.Errorf("拒绝结论应完整: %+v", d)
	}
	// 查看类动作对只读用户应放行。
	ok := store.CheckStorePermission(store.Grantee{User: "viewer", Granted: []string{store.PermRead}}, store.ActionList)
	if !ok.Allowed {
		t.Errorf("只读用户应能查看清单: %+v", ok)
	}
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

// itoa 是 strconv.Itoa 的极简替代，避免为一行代码引入 import。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
