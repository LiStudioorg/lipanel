// Package auth 提供 lipanel 的登录鉴权能力：密码哈希校验、JWT 签发解析，
// 以及保护受信接口的 HTTP 中间件。
//
// 设计约束：
//   - 只依赖标准库 + 纯 Go 第三方库（x/crypto/bcrypt、golang-jwt/v5），
//     不引入 CGO，保证 CGO_ENABLED=0 静态编译。
//   - 明文密码只在启动参数中短暂出现，进程内一律只保留 bcrypt 哈希。
package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost 是生成密码哈希使用的代价因子。
// 10 是 bcrypt 的默认值：单次校验约 50~80ms，足以抵抗离线爆破，
// 又不会让面板登录接口成为 CPU 放大器。
const BcryptCost = 10

// MinPasswordLength 是启动时对明文密码的最低长度要求。
// 面板暴露在公网时弱口令是最大的风险来源，因此在入口处直接拒绝。
const MinPasswordLength = 6

// HashPassword 将明文密码转换为 bcrypt 哈希。
// 返回值可直接持久化（阶段 2.6 的配置文件会用到）。
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("auth: 密码不能为空")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), BcryptCost)
	if err != nil {
		// bcrypt 仅会在密码超过 72 字节时报错，此处补上明确的下文。
		return "", fmt.Errorf("auth: 生成密码哈希失败: %w", err)
	}
	return string(h), nil
}

// VerifyPassword 校验明文密码与 bcrypt 哈希是否匹配。
//
// 说明：bcrypt.CompareHashAndPassword 内部即常量时间比较，
// 且哈希非法与密码错误返回不同的错误，便于调用方区分「配置损坏」与「密码错误」。
func VerifyPassword(hash, plain string) error {
	if hash == "" {
		return errors.New("auth: 密码哈希为空")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("auth: 密码哈希非法: %w", err)
	}
	return nil
}

// IsBcryptHash 粗略判断字符串是否为 bcrypt 哈希（形如 $2a$10$...）。
// 用于启动参数校验：把「哈希」和「明文」区分开，避免误配。
func IsBcryptHash(s string) bool {
	if len(s) != 60 || s[0] != '$' || s[1] != '2' {
		return false
	}
	if s[3] != '$' || s[6] != '$' {
		return false
	}
	return true
}
