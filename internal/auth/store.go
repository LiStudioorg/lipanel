package auth

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidCredentials 表示用户名或密码错误。
//
// 该错误对外必须映射为同一个提示（"用户名或密码错误"），
// 不能区分「用户不存在」和「密码错误」，否则会泄露账号是否存在。
var ErrInvalidCredentials = errors.New("auth: 用户名或密码错误")

// User 是面板管理员账号。密码只以 bcrypt 哈希形式保存。
type User struct {
	Username     string
	PasswordHash string
}

// UserStore 抽象账号来源。
//
// 当前阶段（2.1）只有内存实现 MemoryUserStore；
// 阶段 2.6 会新增基于配置文件的实现，此处预留接口以便无痛替换。
type UserStore interface {
	// Authenticate 校验账号密码，成功返回用户名。
	// 失败一律返回 ErrInvalidCredentials（不区分用户不存在与密码错误）。
	Authenticate(username, password string) (string, error)
}

// MemoryUserStore 是单管理员的内存实现。
type MemoryUserStore struct {
	user User
}

// NewMemoryUserStore 构造内存账号库。
// 传入的 passwordHash 必须已经是 bcrypt 哈希，本函数不会做明文加密，
// 以保证「明文不进入常驻内存」这一约束。
func NewMemoryUserStore(username, passwordHash string) (*MemoryUserStore, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("auth: 用户名不能为空")
	}
	if !IsBcryptHash(passwordHash) {
		return nil, fmt.Errorf("auth: %q 的密码哈希格式非法，应为 bcrypt 哈希", username)
	}
	return &MemoryUserStore{user: User{Username: username, PasswordHash: passwordHash}}, nil
}

// Authenticate 实现 UserStore。
func (m *MemoryUserStore) Authenticate(username, password string) (string, error) {
	// 用户名比较使用常量时间函数，避免通过响应耗时枚举账号。
	if !constantTimeEqual(m.user.Username, strings.TrimSpace(username)) {
		// 即使用户名不匹配也走一次 bcrypt，抹平「用户不存在」与「密码错误」的耗时差异。
		_ = VerifyPassword(m.user.PasswordHash, password)
		return "", ErrInvalidCredentials
	}
	if err := VerifyPassword(m.user.PasswordHash, password); err != nil {
		return "", ErrInvalidCredentials
	}
	return m.user.Username, nil
}

// constantTimeEqual 是长度无关的字符串比较（长度不同时仍遍历一遍）。
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// 仍做一次等长比较以保持耗时稳定，再返回 false。
		var diff byte
		for i := 0; i < len(a) && i < len(b); i++ {
			diff |= a[i] ^ b[i]
		}
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
