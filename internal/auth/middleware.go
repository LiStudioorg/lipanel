package auth

import (
	"context"
	"net/http"
	"strings"
)

// ctxKey 是本包私有的 context key 类型，避免与其他包的 key 冲突。
type ctxKey struct{}

// usernameKey 用于在 context 中传递当前登录用户名。
var usernameKey ctxKey

// RequireAuth 返回一个保护 next 的中间件。
//
// 行为约定：
//   - 未携带 / token 非法 / token 过期 → 401 JSON，不重定向（由前端决定跳转登录页）。
//   - 校验通过 → 把用户名注入 context，供 handler 通过 UsernameFrom 读取。
//
// 该中间件按需挂在具体路由上（白名单式），而不是全局拦截 /api/*，
// 这样新增公开接口（如 /api/health）不会被意外挡住，
// 新增受保护接口忘记挂载时也只需改一处注册代码。
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, err := a.Username(r)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUsername(r.Context(), username)))
	})
}

// withUsername 把用户名写入 context。
func withUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

// UsernameFrom 读取 RequireAuth 注入的用户名。
// 未经过中间件的请求返回空字符串与 false。
func UsernameFrom(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(usernameKey).(string)
	return name, ok && name != ""
}

// writeUnauthorized 输出统一的 401 响应。
//
// 这里不依赖 server 包的 writeJSON，以免 auth 反向依赖 server 造成循环引用；
// 响应格式（Content-Type 与 {"error": ...}）与 server 包保持一致。
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	// 写失败只可能是客户端断开，无需额外处理。
	_, _ = w.Write([]byte(`{"error":"未登录或登录已过期，请重新登录"}` + "\n"))
}

// SanitizeNext 校验登录后跳转地址，只允许站内相对路径。
// 用于阻止 ?redirect=//evil.com 形式的开放重定向。
func SanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}
	// "//host" 会被浏览器当作协议相对绝对地址，必须拒绝。
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
		return "/"
	}
	return next
}
