// Package config 负责 lipanel 配置文件的加载、校验与原子落盘。
//
// 设计约束：
//   - 格式选 JSON，直接用标准库 encoding/json，不引入 YAML 解析库，
//     保持「单二进制、无外部依赖」这一约束不被打破。
//   - 配置文件包含凭据（密码哈希、JWT 签名密钥），因此落盘权限固定为 0600。
//   - 写入采用「临时文件 + rename」的原子替换，避免写一半被中断导致配置损坏。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lipanel/internal/auth"
)

// CurrentVersion 是当前配置文件格式版本。
// 将来字段语义发生不兼容变化时递增，并在 Load 中做迁移。
const CurrentVersion = 1

// 内置默认值。CLI 参数与配置文件均未指定时生效。
const (
	DefaultAddr         = "127.0.0.1:8080"
	DefaultLogLevel     = "info"
	DefaultUsername     = "admin"
	DefaultTokenTTLText = "2h"
)

// Config 是配置文件的完整结构。
type Config struct {
	// Version 是配置格式版本，便于将来做兼容迁移。
	Version int `json:"version"`
	// Addr 是 HTTP 监听地址。
	Addr string `json:"addr"`
	// LogLevel 是日志级别：debug|info|warn|error。
	LogLevel string `json:"log_level"`
	// SecureCookie 为 true 时只通过 HTTPS 传输会话 Cookie。
	SecureCookie bool `json:"secure_cookie"`
	// Auth 保存鉴权相关配置。
	Auth AuthConfig `json:"auth"`
}

// AuthConfig 保存管理员账号与会话配置。
type AuthConfig struct {
	// Username 是管理员用户名。
	Username string `json:"username"`
	// PasswordHash 是管理员密码的 bcrypt 哈希。
	// 只存哈希不存明文，一旦丢失只能删除该字段后重启重新生成。
	PasswordHash string `json:"password_hash,omitempty"`
	// JWTSecret 是会话 token 的签名密钥（base64url 编码的随机串）。
	// 固定该值才能保证进程重启后已登录用户不掉线。
	JWTSecret string `json:"jwt_secret,omitempty"`
	// TokenTTL 是会话有效期，形如 "2h"、"30m"。
	TokenTTL string `json:"token_ttl,omitempty"`
}

// Default 返回内置默认配置（不含任何凭据）。
func Default() *Config {
	return &Config{
		Version:      CurrentVersion,
		Addr:         DefaultAddr,
		LogLevel:     DefaultLogLevel,
		SecureCookie: false,
		Auth: AuthConfig{
			Username: DefaultUsername,
			TokenTTL: DefaultTokenTTLText,
		},
	}
}

// TokenTTLDuration 解析会话有效期；为空时返回 0 交由调用方取默认值。
func (c *Config) TokenTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(c.Auth.TokenTTL) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Auth.TokenTTL)
	if err != nil {
		return 0, fmt.Errorf("config: auth.token_ttl %q 不是合法时长（如 2h、30m）: %w", c.Auth.TokenTTL, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: auth.token_ttl 必须为正数，实际 %q", c.Auth.TokenTTL)
	}
	return d, nil
}

// TokenTTLDurationOrDefault 解析会话有效期；为空或非法时返回默认值。
// 仅用于「比较是否需要改写配置」这类无需报错的场合，校验仍以 Validate 为准。
func (c *Config) TokenTTLDurationOrDefault() time.Duration {
	d, err := c.TokenTTLDuration()
	if err != nil || d <= 0 {
		return auth.DefaultTokenTTL
	}
	return d
}

// SetTokenTTL 以可读形式写入会话有效期。
func (c *Config) SetTokenTTL(d time.Duration) {
	if d > 0 {
		c.Auth.TokenTTL = d.String()
	}
}

// Validate 校验配置的合法性。
//
// 校验失败的配置一律拒绝启动，而不是静默降级：
// 一个写错的密钥长度或哈希格式如果在启动时被忽略，
// 往往要等到用户登录失败时才暴露，排查成本高得多。
func (c *Config) Validate() error {
	if c.Version > CurrentVersion {
		return fmt.Errorf(
			"config: 配置文件版本为 %d，高于本程序支持的 %d，请升级 lipanel 或改用匹配的配置",
			c.Version, CurrentVersion)
	}

	// 用户名是唯一必填项：其余凭据缺失时可以自动生成。
	if strings.TrimSpace(c.Auth.Username) == "" {
		return errors.New("config: auth.username 不能为空")
	}

	// 密码哈希可以缺失（表示待生成），但一旦存在就必须合法。
	if c.Auth.PasswordHash != "" && !auth.IsBcryptHash(c.Auth.PasswordHash) {
		return errors.New("config: auth.password_hash 不是合法的 bcrypt 哈希（应以 $2a$/$2b$ 开头、共 60 字符）")
	}

	// JWT 密钥同理：缺失可自动生成，存在则必须足够长。
	if c.Auth.JWTSecret != "" && len(c.Auth.JWTSecret) < auth.MinSecretLength {
		return fmt.Errorf("config: auth.jwt_secret 过短（%d 字节），至少需要 %d 字节",
			len(c.Auth.JWTSecret), auth.MinSecretLength)
	}

	if _, err := c.TokenTTLDuration(); err != nil {
		return err
	}

	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level = %q 非法，可选 debug|info|warn|error", c.LogLevel)
	}

	if strings.TrimSpace(c.Addr) == "" {
		return errors.New("config: addr 不能为空")
	}
	return nil
}

// Load 读取并校验配置文件。
//
// 返回值 exists 表示文件是否已存在：
//   - 文件不存在 → 返回 (nil, false, nil)，由调用方决定是否用默认值创建；
//   - 文件存在但内容非法 → 返回错误，绝不覆盖用户已有配置。
func Load(path string) (cfg *Config, exists bool, err error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, errors.New("config: 配置文件路径不能为空")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("config: 读取配置文件 %s 失败: %w", path, err)
	}

	var c Config
	// 未知字段不报错：便于手工在配置里加注释性字段，也方便向前兼容。
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, true, fmt.Errorf("config: 解析配置文件 %s 失败（应为 JSON）: %w", path, err)
	}

	// 手工编写的配置可能省略 version，按当前版本处理。
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	applyDefaults(&c)

	if err := c.Validate(); err != nil {
		return nil, true, fmt.Errorf("config: 配置文件 %s 内容非法: %w", path, err)
	}
	return &c, true, nil
}

// applyDefaults 为「未填写」的可选项补上默认值。
//
// 这里刻意只判断空字符串（而不是 TrimSpace 后为空）：
// 字段完全缺失时 json 会给出 ""，应当补默认值；
// 而写成 "   " 属于用户笔误，应交给 Validate 报错，
// 否则一个写错的用户名会被静默替换成 admin，问题很难被发现。
func applyDefaults(c *Config) {
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.Auth.Username == "" {
		c.Auth.Username = DefaultUsername
	}
	if c.Auth.TokenTTL == "" {
		c.Auth.TokenTTL = DefaultTokenTTLText
	}
}

// Save 原子地写入配置文件。
//
// 步骤：确保目录存在 → 写临时文件（0600）→ fsync → rename 覆盖目标。
// rename 在同一文件系统内是原子操作，因此不会出现「读到半个 JSON」的情况。
func (c *Config) Save(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config: 配置文件路径不能为空")
	}
	if err := c.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: 序列化配置失败: %w", err)
	}
	// 末尾补换行，符合 POSIX 文本文件惯例，也便于 vi 等编辑器处理。
	data = append(data, '\n')

	dir := filepath.Dir(path)
	// 目录权限 0700：配置里含密钥，不应让同机其他用户列出内容。
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: 创建配置目录 %s 失败: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".lipanel-*.tmp")
	if err != nil {
		return fmt.Errorf("config: 创建临时配置文件失败: %w", err)
	}
	tmpName := tmp.Name()
	// 任一失败路径都要清理临时文件，避免留下垃圾。
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp 默认 0600，这里显式再设一次，防止 umask 或平台差异。
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: 设置配置文件权限失败: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: 写入临时配置文件失败: %w", err)
	}
	// fsync 后再 rename，保证掉电时不会出现「文件已改名但内容还在页缓存」。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: 同步临时配置文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: 关闭临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: 替换配置文件 %s 失败: %w", path, err)
	}
	tmpName = "" // 已成功改名，无需再删除。
	return nil
}

// CheckPermissions 检查配置文件的权限是否过于宽松。
// 返回非空字符串表示存在风险，调用方应记录告警（不阻断启动，避免误伤）。
func CheckPermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("配置文件 %s 权限为 %04o，同机其他用户可能读取到密钥，建议执行 chmod 600",
			path, info.Mode().Perm())
	}
	return ""
}
