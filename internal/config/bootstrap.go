package config

import (
	"fmt"
	"strings"
	"time"

	"lipanel/internal/auth"
)

// BootstrapOptions 是启动引导的输入。
//
// 字段来源分为两类：
//   - Path 来自 -config；
//   - 其余字段来自各 CLI 参数，但仅当 Set 中对应键为 true 时才生效。
//
// 之所以要 Set 集合：bool 参数（如 -secure-cookie）与带默认值的参数
// （如 -addr）无法用「零值」判断用户是否显式指定过，
// 只有 flag.Visit 能区分「没写」与「写成默认值」，后者应覆盖配置文件。
type BootstrapOptions struct {
	// Path 是配置文件路径；为空表示不启用配置文件（纯内存模式，不落盘）。
	Path string

	// Set 记录被显式指定的 CLI 参数名（flag.Visit 的结果）。
	Set map[string]bool

	Addr         string
	LogLevel     string
	Username     string
	Password     string
	PasswordHash string
	JWTSecret    string
	TokenTTL     time.Duration
	SecureCookie bool
}

// set 报告某个 CLI 参数是否被显式指定。
func (o BootstrapOptions) set(name string) bool { return o.Set[name] }

// BootstrapResult 描述本次引导的结果，供调用方决定日志与提示。
type BootstrapResult struct {
	// Config 是合并 CLI 与配置文件后的最终配置。
	Config *Config

	// Created 表示配置文件是本次新建的。
	Created bool
	// Saved 表示本次写入了配置文件。
	Saved bool
	// Persistent 表示配置是否会持久化（即指定了 -config）。
	Persistent bool

	// GeneratedPassword 非空表示本次自动生成了管理员密码。
	//
	// 调用方必须立即把它打印给用户：这是唯一一次能看到明文的机会
	// （进程里只留 bcrypt 哈希，文件里也只有哈希，丢了只能重新生成）。
	GeneratedPassword string
	// GeneratedSecret 表示本次自动生成了 JWT 签名密钥。
	GeneratedSecret bool
	// PasswordRotated 表示本次用 CLI 传入的密码更新了已有哈希。
	PasswordRotated bool
	// SecretRotated 表示本次用 CLI 传入的密钥覆盖了已有密钥。
	SecretRotated bool

	// PermissionWarning 非空表示已有配置文件权限过宽，调用方应告警。
	// 这里只告警不阻断：误伤一个能跑的部署，比提示一次风险更糟。
	PermissionWarning string
}

// Bootstrap 按「CLI 参数 > 配置文件 > 内置默认值」的优先级解析配置，
// 并在需要时自动生成凭据与落盘。
//
// 凭据生成策略：
//   - 指定了 -config 且其中没有密码哈希 → 生成随机密码、哈希后落盘；
//   - 指定了 -config 且其中没有 JWT 密钥 → 生成随机密钥并落盘；
//   - 未指定 -config（纯内存模式）→ 不生成，交由调用方使用开发默认口令，
//     因为此时没有地方存放生成结果，随机密码会随进程退出而永久丢失。
func Bootstrap(o BootstrapOptions) (*BootstrapResult, error) {
	res := &BootstrapResult{Persistent: o.Path != ""}

	// ---------- 1. 载入配置文件 ----------
	cfg := Default()
	if o.Path != "" {
		loaded, exists, err := Load(o.Path)
		if err != nil {
			return nil, err
		}
		if exists {
			cfg = loaded
			// 已有文件才谈得上权限问题；新建的文件由 Save 保证 0600。
			res.PermissionWarning = CheckPermissions(o.Path)
		} else {
			res.Created = true
		}
	}

	// dirty 记录配置是否发生了需要落盘的变更。
	dirty := false

	// ---------- 2. 应用 CLI 覆盖 ----------
	if o.set("addr") && strings.TrimSpace(o.Addr) != "" {
		if cfg.Addr != o.Addr {
			cfg.Addr, dirty = o.Addr, true
		}
	}
	if o.set("log-level") && strings.TrimSpace(o.LogLevel) != "" {
		if cfg.LogLevel != o.LogLevel {
			cfg.LogLevel, dirty = o.LogLevel, true
		}
	}
	if o.set("admin-user") && strings.TrimSpace(o.Username) != "" {
		if name := strings.TrimSpace(o.Username); cfg.Auth.Username != name {
			cfg.Auth.Username, dirty = name, true
		}
	}
	if o.set("secure-cookie") && cfg.SecureCookie != o.SecureCookie {
		cfg.SecureCookie, dirty = o.SecureCookie, true
	}
	if o.set("token-ttl") && o.TokenTTL > 0 {
		if cfg.TokenTTLDurationOrDefault() != o.TokenTTL {
			cfg.SetTokenTTL(o.TokenTTL)
			dirty = true
		}
	}

	// ---------- 3. 解析密码哈希 ----------
	// 优先级：-admin-password-hash > -admin-password > 配置文件 > 自动生成
	switch {
	case o.set("admin-password-hash") && o.PasswordHash != "":
		if !auth.IsBcryptHash(o.PasswordHash) {
			return nil, fmt.Errorf(
				"config: -admin-password-hash 不是合法的 bcrypt 哈希（应以 $2a$/$2b$ 开头、共 60 字符）")
		}
		if cfg.Auth.PasswordHash != o.PasswordHash {
			cfg.Auth.PasswordHash, dirty = o.PasswordHash, true
			res.PasswordRotated = true
		}

	case o.set("admin-password") && o.Password != "":
		if len([]rune(o.Password)) < auth.MinPasswordLength {
			return nil, fmt.Errorf("config: 管理员密码过短，至少需要 %d 个字符", auth.MinPasswordLength)
		}
		// 若已有哈希且与新密码匹配，则无需重写。
		// 这一步很重要：bcrypt 带随机 salt，同一个密码每次哈希结果都不同，
		// 不做校验的话每次带 -admin-password 启动都会无谓地重写配置文件。
		if cfg.Auth.PasswordHash != "" && auth.VerifyPassword(cfg.Auth.PasswordHash, o.Password) == nil {
			break
		}
		hash, err := auth.HashPassword(o.Password)
		if err != nil {
			return nil, err
		}
		res.PasswordRotated = cfg.Auth.PasswordHash != ""
		cfg.Auth.PasswordHash, dirty = hash, true

	case cfg.Auth.PasswordHash == "" && o.Path != "":
		// 首次启动：生成随机密码并落盘，管理员无需每次传参。
		plain, err := auth.GeneratePassword()
		if err != nil {
			return nil, err
		}
		hash, err := auth.HashPassword(plain)
		if err != nil {
			return nil, err
		}
		cfg.Auth.PasswordHash = hash
		res.GeneratedPassword = plain
		dirty = true
	}

	// ---------- 4. 解析 JWT 签名密钥 ----------
	// 优先级：-jwt-secret > 配置文件 > 自动生成
	switch {
	case o.set("jwt-secret") && o.JWTSecret != "":
		if len(o.JWTSecret) < auth.MinSecretLength {
			return nil, fmt.Errorf("config: -jwt-secret 过短（%d 字节），至少需要 %d 字节",
				len(o.JWTSecret), auth.MinSecretLength)
		}
		if cfg.Auth.JWTSecret != o.JWTSecret {
			cfg.Auth.JWTSecret, dirty = o.JWTSecret, true
			res.SecretRotated = true
		}

	case cfg.Auth.JWTSecret == "" && o.Path != "":
		secret, err := auth.GenerateSecret()
		if err != nil {
			return nil, err
		}
		cfg.Auth.JWTSecret = secret
		res.GeneratedSecret = true
		dirty = true
	}

	// ---------- 5. 校验并落盘 ----------
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if o.Path != "" && (res.Created || dirty) {
		if err := cfg.Save(o.Path); err != nil {
			return nil, err
		}
		res.Saved = true
	}

	res.Config = cfg
	return res, nil
}
