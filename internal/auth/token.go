package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// CookieName 是承载 JWT 的 Cookie 名。
	//
	// 选择 HttpOnly Cookie 而非 localStorage 的原因：前端 JS 读不到 token，
	// 即使页面被注入 XSS 也无法直接窃取会话；配合 SameSite=Lax 收敛 CSRF 面。
	CookieName = "lipanel_token"

	// DefaultTokenTTL 是会话有效期。
	DefaultTokenTTL = 2 * time.Hour

	// issuer 写入 iss 声明，便于将来多服务共用一个密钥时区分来源。
	issuer = "lipanel"

	// SecretSize 是自动生成密钥的字节数（HS256 要求 ≥ 32 字节）。
	SecretSize = 32
)

// Authenticator 负责签发与校验会话 token，并作为鉴权中间件的载体。
type Authenticator struct {
	store     UserStore
	secret    []byte
	ttl       time.Duration
	secure    bool // 是否给 Cookie 加 Secure 标记（HTTPS 部署时开启）
	generated bool // 签名密钥是否为自动生成
	tokenAPI  *jwt.Parser
}

// Options 是构造 Authenticator 的配置。
type Options struct {
	// Store 是账号来源，必填。
	Store UserStore
	// Secret 是 JWT 签名密钥；为空时自动随机生成（重启后旧会话失效）。
	Secret []byte
	// TTL 是会话有效期；<=0 时使用 DefaultTokenTTL。
	TTL time.Duration
	// SecureCookie 表示仅在 HTTPS 下传输 Cookie。反向代理已启用 TLS 时应设为 true。
	SecureCookie bool
}

// New 构造 Authenticator。
func New(opts Options) (*Authenticator, error) {
	if opts.Store == nil {
		return nil, errors.New("auth: UserStore 不能为空")
	}
	secret := opts.Secret
	generated := false
	if len(secret) == 0 {
		// 未显式配置密钥时随机生成：更安全（每次重启使旧 token 失效），
		// 代价是进程重启需要重新登录，调用方应在日志中提示。
		buf := make([]byte, SecretSize)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("auth: 生成随机签名密钥失败: %w", err)
		}
		secret = buf
		generated = true
	}
	if len(secret) < 16 {
		// HS256 的安全性直接取决于密钥长度，过短等同于没有签名。
		return nil, fmt.Errorf("auth: 签名密钥过短（%d 字节），至少需要 16 字节", len(secret))
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}

	return &Authenticator{
		store:     opts.Store,
		secret:    secret,
		ttl:       ttl,
		secure:    opts.SecureCookie,
		generated: generated,
		// 显式限定算法为 HS256，拒绝 alg=none 与 RS256 混淆攻击。
		tokenAPI: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
		),
	}, nil
}

// SecretGenerated 报告签名密钥是否为自动生成（调用方据此打印告警）。
func (a *Authenticator) SecretGenerated() bool { return a.generated }

// TTL 返回会话有效期，供前端展示。
func (a *Authenticator) TTL() time.Duration { return a.ttl }

// Login 校验账号密码，成功后签发 token 并写入 Cookie。
// 返回用户名的同时返回过期时间，便于前端做倒计时或提前续期。
func (a *Authenticator) Login(w http.ResponseWriter, username, password string) (string, time.Time, error) {
	name, err := a.store.Authenticate(username, password)
	if err != nil {
		// 统一转换为对外的 ErrInvalidCredentials，避免泄露账号是否存在。
		return "", time.Time{}, ErrInvalidCredentials
	}

	now := time.Now()
	expiresAt := now.Add(a.ttl)
	claims := jwt.RegisteredClaims{
		Subject:   name,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: 签发 token 失败: %w", err)
	}

	a.setCookie(w, signed, expiresAt)
	return name, expiresAt, nil
}

// Logout 通过让 Cookie 立即过期来结束会话。
//
// 无状态 JWT 无法在服务端吊销单个 token，因此登出只清客户端 Cookie；
// 若将来需要强制下线，可在此引入 token 版本号或黑名单（阶段 2.6 起考虑）。
func (a *Authenticator) Logout(w http.ResponseWriter) {
	a.setCookie(w, "", time.Unix(0, 0))
}

// Username 从请求 Cookie 中解析出当前登录用户名。
func (a *Authenticator) Username(r *http.Request) (string, error) {
	token, err := a.parseRequest(r)
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.Subject == "" {
		return "", errors.New("auth: token 缺少 sub 声明")
	}
	return claims.Subject, nil
}

// ExpiresAt 返回当前会话的过期时间，未登录或解析失败时返回零值。
func (a *Authenticator) ExpiresAt(r *http.Request) time.Time {
	token, err := a.parseRequest(r)
	if err != nil {
		return time.Time{}
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.ExpiresAt == nil {
		return time.Time{}
	}
	return claims.ExpiresAt.Time
}

// parseRequest 取出并校验请求中的 token。
func (a *Authenticator) parseRequest(r *http.Request) (*jwt.Token, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, errors.New("auth: 请求未携带会话 Cookie")
	}

	token, err := a.tokenAPI.ParseWithClaims(c.Value, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) {
		return a.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: token 校验失败: %w", err)
	}
	return token, nil
}

// setCookie 统一写入会话 Cookie，保证各项安全属性一致。
// expires 为零值或已过期时，Cookie 会被浏览器立即删除。
func (a *Authenticator) setCookie(w http.ResponseWriter, value string, expires time.Time) {
	// MaxAge 与 Expires 同时设置，兼容不识别 MaxAge 的老客户端。
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 0 {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,                 // 禁止 JS 读取，防 XSS 窃取
		Secure:   a.secure,             // 仅在 HTTPS 下传输
		SameSite: http.SameSiteLaxMode, // 防跨站请求携带 Cookie
		MaxAge:   maxAge,
		Expires:  expires,
	})
}

// GenerateSecret 生成一个可写入配置文件的随机密钥（base64 编码，便于粘贴）。
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: 生成随机密钥失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
