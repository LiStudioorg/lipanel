package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lipanel/internal/auth"
)

// ---------- 测试辅助 ----------

// validHash 生成一个合法的 bcrypt 哈希。
func validHash(t *testing.T, plain string) string {
	t.Helper()
	h, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	return h
}

// writeFile 写入一个文件，用于构造各种配置文件内容。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入文件失败: %v", err)
	}
}

// optSet 构造「被显式指定的 CLI 参数」集合。
func optSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// validConfigJSON 构造一份内容完整的合法配置 JSON。
func validConfigJSON(t *testing.T, mutate func(*Config)) string {
	t.Helper()
	c := Default()
	c.Auth.PasswordHash = validHash(t, "initial-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if mutate != nil {
		mutate(c)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("序列化测试配置失败: %v", err)
	}
	return string(data)
}

// ---------- Default ----------

func TestDefault(t *testing.T) {
	c := Default()

	if c.Version != CurrentVersion {
		t.Errorf("version = %d, 期望 %d", c.Version, CurrentVersion)
	}
	if c.Addr != DefaultAddr {
		t.Errorf("addr = %q, 期望 %q", c.Addr, DefaultAddr)
	}
	if c.LogLevel != DefaultLogLevel {
		t.Errorf("log_level = %q, 期望 %q", c.LogLevel, DefaultLogLevel)
	}
	if c.Auth.Username != DefaultUsername {
		t.Errorf("username = %q, 期望 %q", c.Auth.Username, DefaultUsername)
	}
	// 默认配置绝不能自带任何凭据。
	if c.Auth.PasswordHash != "" {
		t.Error("默认配置不应包含密码哈希")
	}
	if c.Auth.JWTSecret != "" {
		t.Error("默认配置不应包含 JWT 密钥")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("默认配置应当合法: %v", err)
	}
}

// ---------- Load ----------

// 文件不存在不是错误，而是「首次启动」的信号。
func TestLoadMissingFileReturnsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-there.json")

	cfg, exists, err := Load(path)
	if err != nil {
		t.Fatalf("文件不存在不应报错: %v", err)
	}
	if exists {
		t.Error("exists 应为 false")
	}
	if cfg != nil {
		t.Error("文件不存在时 cfg 应为 nil")
	}
}

func TestLoadRejectsEmptyPath(t *testing.T) {
	if _, _, err := Load("  "); err == nil {
		t.Fatal("空路径应当报错")
	}
}

func TestLoadValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))

	cfg, exists, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if !exists {
		t.Error("exists 应为 true")
	}
	if cfg.Auth.Username != DefaultUsername {
		t.Errorf("username = %q", cfg.Auth.Username)
	}
	if !auth.IsBcryptHash(cfg.Auth.PasswordHash) {
		t.Errorf("密码哈希未正确解析: %q", cfg.Auth.PasswordHash)
	}
	if cfg.Addr != DefaultAddr {
		t.Errorf("addr = %q", cfg.Addr)
	}
}

// 手工编写的配置可能省略 version，应按当前版本处理。
func TestLoadDefaultsVersionWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, `{"auth":{"username":"admin"}}`)

	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.Version != CurrentVersion {
		t.Errorf("version = %d, 期望 %d", cfg.Version, CurrentVersion)
	}
	// 未填写的可选项应补上默认值。
	if cfg.Addr != DefaultAddr {
		t.Errorf("addr = %q, 期望默认值 %q", cfg.Addr, DefaultAddr)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("log_level = %q, 期望默认值 %q", cfg.LogLevel, DefaultLogLevel)
	}
	if cfg.Auth.TokenTTL != DefaultTokenTTLText {
		t.Errorf("token_ttl = %q, 期望默认值 %q", cfg.Auth.TokenTTL, DefaultTokenTTLText)
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, `{"auth": {not valid json`)

	_, exists, err := Load(path)
	if err == nil {
		t.Fatal("非法 JSON 应当报错")
	}
	if !exists {
		t.Error("文件存在时 exists 应为 true（即便内容非法）")
	}
}

// 版本高于本程序支持范围时必须拒绝，避免用旧程序误读新配置。
func TestLoadRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Version = CurrentVersion + 1 }))

	if _, _, err := Load(path); err == nil {
		t.Fatal("更高的配置版本应当被拒绝")
	}
}

func TestLoadRejectsBadPasswordHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Auth.PasswordHash = "plain-text-password" }))

	_, _, err := Load(path)
	if err == nil {
		t.Fatal("非法密码哈希应当被拒绝")
	}
	if !strings.Contains(err.Error(), "bcrypt") {
		t.Errorf("错误信息应说明 bcrypt 格式要求，实际: %v", err)
	}
}

func TestLoadRejectsShortJWTSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Auth.JWTSecret = "too-short" }))

	if _, _, err := Load(path); err == nil {
		t.Fatal("过短的密钥应当被拒绝")
	}
}

func TestLoadRejectsBadTokenTTL(t *testing.T) {
	for _, bad := range []string{"abc", "-1h", "0s"} {
		path := filepath.Join(t.TempDir(), "config.json")
		writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Auth.TokenTTL = bad }))

		if _, _, err := Load(path); err == nil {
			t.Errorf("token_ttl = %q 应当被拒绝", bad)
		}
	}
}

func TestLoadRejectsBadLogLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.LogLevel = "verbose" }))

	if _, _, err := Load(path); err == nil {
		t.Fatal("非法日志级别应当被拒绝")
	}
}

func TestLoadRejectsEmptyUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, `{"auth":{"username":"   "}}`)

	if _, _, err := Load(path); err == nil {
		t.Fatal("空用户名应当被拒绝")
	}
}

// 未知字段不应导致加载失败（便于手工加注释性字段与向前兼容）。
func TestLoadToleratesUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, `{"auth":{"username":"admin"},"_comment":"我的备注","future_option":123}`)

	if _, _, err := Load(path); err != nil {
		t.Fatalf("未知字段不应导致失败: %v", err)
	}
}

func TestTokenTTLDuration(t *testing.T) {
	c := Default()
	c.Auth.TokenTTL = "90m"

	d, err := c.TokenTTLDuration()
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if d != 90*time.Minute {
		t.Errorf("时长 = %v, 期望 90m", d)
	}

	// 空值返回 0，交由调用方取默认。
	c.Auth.TokenTTL = ""
	if d, err := c.TokenTTLDuration(); err != nil || d != 0 {
		t.Errorf("空值应返回 (0, nil)，实际 (%v, %v)", d, err)
	}
}

// ---------- Save ----------

func TestSaveCreatesFileAndParentDir(t *testing.T) {
	// 多级不存在的目录也必须能创建。
	path := filepath.Join(t.TempDir(), "var", "lib", "lipanel", "config.json")

	c := Default()
	c.Auth.PasswordHash = validHash(t, "save-test-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"

	if err := c.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("保存后文件不存在: %v", err)
	}
	if info.IsDir() {
		t.Fatal("路径是目录而非文件")
	}
}

// 配置文件含密钥，权限必须是 0600。
func TestSavePermissionsAre0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	c := Default()
	c.Auth.PasswordHash = validHash(t, "perm-test-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if err := c.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限 = %04o, 期望 0600（配置含密钥）", perm)
	}
}

// 保存后再加载应完全一致（往返一致性）。
func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	orig := Default()
	orig.Addr = "0.0.0.0:9000"
	orig.LogLevel = "debug"
	orig.SecureCookie = true
	orig.Auth.PasswordHash = validHash(t, "round-trip-password")
	orig.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	orig.Auth.TokenTTL = "45m"

	if err := orig.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	loaded, exists, err := Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if !exists {
		t.Fatal("文件应存在")
	}

	if loaded.Addr != orig.Addr {
		t.Errorf("addr = %q, 期望 %q", loaded.Addr, orig.Addr)
	}
	if loaded.LogLevel != orig.LogLevel {
		t.Errorf("log_level = %q, 期望 %q", loaded.LogLevel, orig.LogLevel)
	}
	if loaded.SecureCookie != orig.SecureCookie {
		t.Errorf("secure_cookie = %v, 期望 %v", loaded.SecureCookie, orig.SecureCookie)
	}
	if loaded.Auth.PasswordHash != orig.Auth.PasswordHash {
		t.Errorf("密码哈希往返后不一致")
	}
	if loaded.Auth.JWTSecret != orig.Auth.JWTSecret {
		t.Errorf("JWT 密钥往返后不一致")
	}
	if loaded.Auth.TokenTTL != orig.Auth.TokenTTL {
		t.Errorf("token_ttl = %q, 期望 %q", loaded.Auth.TokenTTL, orig.Auth.TokenTTL)
	}
}

// 原子写入不应留下任何临时文件。
func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c := Default()
	c.Auth.PasswordHash = validHash(t, "temp-test-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if err := c.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lipanel-") {
			t.Errorf("残留临时文件: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("目录内文件数 = %d, 期望 1", len(entries))
	}
}

// 非法配置绝不能写入磁盘，避免把好配置覆盖成坏配置。
func TestSaveRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	c := Default()
	c.Auth.Username = "" // 非法
	if err := c.Save(path); err == nil {
		t.Fatal("非法配置应当拒绝保存")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("非法配置不应在磁盘上留下文件")
	}
}

func TestSaveRejectsEmptyPath(t *testing.T) {
	if err := Default().Save(""); err == nil {
		t.Fatal("空路径应当报错")
	}
}

// 覆盖已有文件必须成功（rename 覆盖语义）。
func TestSaveOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	c := Default()
	c.Auth.PasswordHash = validHash(t, "first-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if err := c.Save(path); err != nil {
		t.Fatalf("首次保存失败: %v", err)
	}

	c.Addr = "0.0.0.0:7777"
	if err := c.Save(path); err != nil {
		t.Fatalf("覆盖保存失败: %v", err)
	}

	loaded, _, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if loaded.Addr != "0.0.0.0:7777" {
		t.Errorf("addr = %q, 期望被覆盖为 0.0.0.0:7777", loaded.Addr)
	}
}

// 写出的 JSON 结构必须与文档一致，字段名不可漂移。
func TestSavedJSONShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	c := Default()
	c.Auth.PasswordHash = validHash(t, "shape-test-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if err := c.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("保存的内容不是合法 JSON: %v", err)
	}

	for _, key := range []string{"version", "addr", "log_level", "secure_cookie", "auth"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("配置缺少顶层字段 %q", key)
		}
	}

	authRaw, ok := raw["auth"].(map[string]any)
	if !ok {
		t.Fatalf("auth 字段不是对象: %T", raw["auth"])
	}
	for _, key := range []string{"username", "password_hash", "jwt_secret", "token_ttl"} {
		if _, ok := authRaw[key]; !ok {
			t.Errorf("auth 缺少字段 %q", key)
		}
	}

	// 文件中绝不能出现明文密码。
	if strings.Contains(string(data), "shape-test-password") {
		t.Error("配置文件中出现了明文密码")
	}
}

// ---------- CheckPermissions ----------

func TestCheckPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.Auth.PasswordHash = validHash(t, "perm-check-password")
	c.Auth.JWTSecret = "a-fixed-secret-of-at-least-16-bytes"
	if err := c.Save(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 0600 不应有告警。
	if w := CheckPermissions(path); w != "" {
		t.Errorf("0600 权限不应告警，实际: %s", w)
	}

	// 0644 应被告警。
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod 失败: %v", err)
	}
	if w := CheckPermissions(path); w == "" {
		t.Error("0644 权限应当告警")
	}

	// 文件不存在时静默返回空串。
	if w := CheckPermissions(filepath.Join(t.TempDir(), "nope.json")); w != "" {
		t.Errorf("文件不存在时不应告警，实际: %s", w)
	}
}

// ---------- Bootstrap：无配置文件（纯内存模式） ----------

func TestBootstrapWithoutPathUsesDevDefaults(t *testing.T) {
	res, err := Bootstrap(BootstrapOptions{Set: optSet()})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if res.Persistent {
		t.Error("未指定 -config 时 Persistent 应为 false")
	}
	if res.Saved || res.Created {
		t.Error("未指定 -config 时不应创建或保存文件")
	}
	// 纯内存模式下不应自动生成凭据：没有地方存放，随机密码会永久丢失。
	if res.GeneratedPassword != "" {
		t.Error("纯内存模式不应生成随机密码")
	}
	if res.GeneratedSecret {
		t.Error("纯内存模式不应生成签名密钥")
	}
	if res.Config.Auth.PasswordHash != "" {
		t.Error("纯内存模式下配置中的密码哈希应保持为空（由调用方回退默认口令）")
	}
	if res.Config.Addr != DefaultAddr {
		t.Errorf("addr = %q, 期望默认值", res.Config.Addr)
	}
}

// ---------- Bootstrap：首次启动自动生成并落盘 ----------

func TestBootstrapCreatesConfigAndGeneratesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")

	res, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if !res.Created {
		t.Error("首次启动应标记 Created")
	}
	if !res.Saved {
		t.Error("首次启动应落盘")
	}
	if !res.Persistent {
		t.Error("指定了 -config，Persistent 应为 true")
	}

	// 自动生成密码与密钥。
	if res.GeneratedPassword == "" {
		t.Fatal("首次启动应自动生成管理员密码")
	}
	if len(res.GeneratedPassword) != auth.GeneratedPasswordLength {
		t.Errorf("生成的密码长度 = %d, 期望 %d", len(res.GeneratedPassword), auth.GeneratedPasswordLength)
	}
	if !res.GeneratedSecret {
		t.Error("首次启动应自动生成签名密钥")
	}

	// 文件必须真实存在且权限正确。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("配置文件未创建: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限 = %04o, 期望 0600", perm)
	}

	// 落盘的哈希必须能验证生成的密码（否则用户抄下来的密码登不上去）。
	if err := auth.VerifyPassword(res.Config.Auth.PasswordHash, res.GeneratedPassword); err != nil {
		t.Errorf("生成的密码无法通过落盘哈希校验: %v", err)
	}
}

// 磁盘上绝不能出现明文密码。
func TestBootstrapNeverWritesPlaintextPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	res, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if strings.Contains(string(data), res.GeneratedPassword) {
		t.Error("配置文件中出现了明文密码")
	}
}

// 核心需求：第二次启动直接读取哈希，不需要再次传参，密码保持不变。
func TestBootstrapSecondRunReusesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	first, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()})
	if err != nil {
		t.Fatalf("首次 Bootstrap 失败: %v", err)
	}
	password := first.GeneratedPassword
	if password == "" {
		t.Fatal("首次启动应生成密码")
	}

	// 第二次启动：不带任何凭据参数。
	second, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()})
	if err != nil {
		t.Fatalf("二次 Bootstrap 失败: %v", err)
	}

	if second.GeneratedPassword != "" {
		t.Error("第二次启动不应重新生成密码")
	}
	if second.GeneratedSecret {
		t.Error("第二次启动不应重新生成密钥")
	}
	if second.Created {
		t.Error("第二次启动不应标记 Created")
	}
	if second.Saved {
		t.Error("配置无变化时不应重写文件")
	}
	if second.Config.Auth.PasswordHash != first.Config.Auth.PasswordHash {
		t.Error("密码哈希在重启后发生了变化")
	}
	if second.Config.Auth.JWTSecret != first.Config.Auth.JWTSecret {
		t.Error("签名密钥在重启后发生了变化（会导致所有会话失效）")
	}
	// 首次生成的密码在重启后仍然可用。
	if err := auth.VerifyPassword(second.Config.Auth.PasswordHash, password); err != nil {
		t.Errorf("重启后原密码无法登录: %v", err)
	}
}

// 配置无变化时不应重写文件（bcrypt 带随机 salt，重写会改变文件内容）。
func TestBootstrapDoesNotRewriteUnchangedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if _, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()}); err != nil {
		t.Fatalf("首次 Bootstrap 失败: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	if _, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()}); err != nil {
		t.Fatalf("二次 Bootstrap 失败: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	if string(before) != string(after) {
		t.Error("配置未变化时文件内容被改写")
	}
}

// ---------- Bootstrap：CLI 覆盖配置 ----------

func TestBootstrapCLIPasswordOverridesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))

	res, err := Bootstrap(BootstrapOptions{
		Path:     path,
		Set:      optSet("admin-password"),
		Password: "brand-new-password",
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if !res.PasswordRotated {
		t.Error("应标记密码已被更新")
	}
	if err := auth.VerifyPassword(res.Config.Auth.PasswordHash, "brand-new-password"); err != nil {
		t.Errorf("新密码未生效: %v", err)
	}
	// 旧密码必须失效。
	if err := auth.VerifyPassword(res.Config.Auth.PasswordHash, "initial-password"); err == nil {
		t.Error("旧密码仍然有效")
	}
	// 变更必须落盘。
	reloaded, _, err := Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if err := auth.VerifyPassword(reloaded.Auth.PasswordHash, "brand-new-password"); err != nil {
		t.Errorf("新密码未落盘: %v", err)
	}
}

// 传入与已有哈希相同的密码时不应重写文件。
func TestBootstrapCLISamePasswordDoesNotRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	res, err := Bootstrap(BootstrapOptions{
		Path:     path,
		Set:      optSet("admin-password"),
		Password: "initial-password", // 与文件中已有哈希对应同一密码
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if res.PasswordRotated {
		t.Error("密码未变化时不应标记为已轮换")
	}
	if res.Saved {
		t.Error("密码未变化时不应重写文件")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(before) != string(after) {
		t.Error("文件被无谓改写（bcrypt salt 变化会破坏幂等性）")
	}
}

func TestBootstrapCLIPasswordHashOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))

	hash := validHash(t, "hash-provided-password")
	res, err := Bootstrap(BootstrapOptions{
		Path:         path,
		Set:          optSet("admin-password-hash"),
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}
	if res.Config.Auth.PasswordHash != hash {
		t.Error("传入的哈希未生效")
	}
	if err := auth.VerifyPassword(res.Config.Auth.PasswordHash, "hash-provided-password"); err != nil {
		t.Errorf("传入哈希对应的密码无法登录: %v", err)
	}
}

func TestBootstrapRejectsBadCLIHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if _, err := Bootstrap(BootstrapOptions{
		Path:         path,
		Set:          optSet("admin-password-hash"),
		PasswordHash: "not-a-bcrypt-hash",
	}); err == nil {
		t.Fatal("非法哈希应当被拒绝")
	}
}

func TestBootstrapRejectsShortCLIPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if _, err := Bootstrap(BootstrapOptions{
		Path:     path,
		Set:      optSet("admin-password"),
		Password: "abc",
	}); err == nil {
		t.Fatal("过短密码应当被拒绝")
	}
}

func TestBootstrapCLIAddrOverridesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Addr = "0.0.0.0:9000" }))

	res, err := Bootstrap(BootstrapOptions{
		Path: path,
		Set:  optSet("addr"),
		Addr: "127.0.0.1:7777",
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}
	if res.Config.Addr != "127.0.0.1:7777" {
		t.Errorf("addr = %q, 期望 CLI 值 127.0.0.1:7777", res.Config.Addr)
	}

	// 覆盖结果应落盘，下次启动无需再传。
	reloaded, _, err := Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if reloaded.Addr != "127.0.0.1:7777" {
		t.Errorf("落盘后 addr = %q, 期望 127.0.0.1:7777", reloaded.Addr)
	}
}

// 关键行为：CLI 参数「写成了默认值」也必须覆盖配置文件，
// 这依赖 flag.Visit 而非零值判断。
func TestBootstrapExplicitDefaultOverridesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) { c.Addr = "0.0.0.0:9000" }))

	res, err := Bootstrap(BootstrapOptions{
		Path: path,
		Set:  optSet("addr"),
		Addr: DefaultAddr, // 恰好等于默认值，但用户确实显式写了
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}
	if res.Config.Addr != DefaultAddr {
		t.Errorf("addr = %q, 期望被显式指定的默认值 %q 覆盖", res.Config.Addr, DefaultAddr)
	}
}

// 未显式指定时，配置文件的值必须保留（不被 Go 零值/默认值冲掉）。
func TestBootstrapConfigValuePreservedWhenFlagNotSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, func(c *Config) {
		c.Addr = "0.0.0.0:9000"
		c.LogLevel = "debug"
		c.SecureCookie = true
		c.Auth.TokenTTL = "45m"
	}))

	res, err := Bootstrap(BootstrapOptions{
		Path: path,
		Set:  optSet(), // 一个 CLI 参数都没写
		// 传入 Go 零值，模拟 flag 包的默认填充
		Addr:     DefaultAddr,
		LogLevel: DefaultLogLevel,
		TokenTTL: auth.DefaultTokenTTL,
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if res.Config.Addr != "0.0.0.0:9000" {
		t.Errorf("addr = %q, 期望保留配置文件的值", res.Config.Addr)
	}
	if res.Config.LogLevel != "debug" {
		t.Errorf("log_level = %q, 期望保留配置文件的值", res.Config.LogLevel)
	}
	if !res.Config.SecureCookie {
		t.Error("secure_cookie 应保留配置文件的值 true")
	}
	if got := res.Config.TokenTTLDurationOrDefault(); got != 45*time.Minute {
		t.Errorf("token_ttl = %v, 期望保留 45m", got)
	}
	if res.Saved {
		t.Error("无任何变化时不应重写文件")
	}
}

func TestBootstrapCLISecretOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))

	const newSecret = "a-completely-different-secret-value"
	res, err := Bootstrap(BootstrapOptions{
		Path:      path,
		Set:       optSet("jwt-secret"),
		JWTSecret: newSecret,
	})
	if err != nil {
		t.Fatalf("Bootstrap 失败: %v", err)
	}

	if !res.SecretRotated {
		t.Error("应标记密钥已被更新")
	}
	if res.Config.Auth.JWTSecret != newSecret {
		t.Error("密钥未更新")
	}
	reloaded, _, err := Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if reloaded.Auth.JWTSecret != newSecret {
		t.Error("密钥未落盘")
	}
}

func TestBootstrapRejectsShortCLISecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if _, err := Bootstrap(BootstrapOptions{
		Path:      path,
		Set:       optSet("jwt-secret"),
		JWTSecret: "short",
	}); err == nil {
		t.Fatal("过短的密钥应当被拒绝")
	}
}

// 损坏的配置文件必须报错且绝不被覆盖（否则用户配置会被默默清掉）。
func TestBootstrapDoesNotOverwriteBrokenConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	broken := `{"auth": {"password_hash": "garbage"}`
	writeFile(t, path, broken)

	if _, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()}); err == nil {
		t.Fatal("损坏的配置应当导致启动失败")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(after) != broken {
		t.Error("损坏的配置文件被覆盖了，用户配置丢失")
	}
}

// 权限过宽的已有配置应给出告警，但不阻断启动。
func TestBootstrapWarnsOnLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, validConfigJSON(t, nil))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod 失败: %v", err)
	}

	res, err := Bootstrap(BootstrapOptions{Path: path, Set: optSet()})
	if err != nil {
		t.Fatalf("权限过宽不应阻断启动: %v", err)
	}
	if res.PermissionWarning == "" {
		t.Error("权限过宽的配置应给出告警")
	}
}

// 生成的密码本身必须是高熵的（两次生成不同，且足够长）。
func TestGeneratedPasswordIsRandom(t *testing.T) {
	p1, err := auth.GeneratePassword()
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	p2, err := auth.GeneratePassword()
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if p1 == p2 {
		t.Error("两次生成的密码相同，随机性不足")
	}
	if len(p1) != auth.GeneratedPasswordLength {
		t.Errorf("长度 = %d, 期望 %d", len(p1), auth.GeneratedPasswordLength)
	}
	// 生成的密码必须满足自身的最低长度校验。
	if len([]rune(p1)) < auth.MinPasswordLength {
		t.Error("生成的密码不满足最小长度要求")
	}
}
