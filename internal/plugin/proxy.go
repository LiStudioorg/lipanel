package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// dialUnix 拨号到指定 Unix socket 路径。
func dialUnix(ctx context.Context, sockPath string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("plugin: 连接 %s 失败: %w", sockPath, err)
	}
	return conn, nil
}

// Proxy 把核心收到的 HTTP 请求转发给插件进程。
//
// 之所以不用 httputil.NewSingleHostReverseProxy 直接建一个带 Transport 的实例，
// 是因为每个插件的 socket 路径不同，而 ReverseProxy 的 Transport 是固定的。
// 这里复用一个 ReverseProxy 实例，
// 通过重写 Director 中的 URL.Scheme 为 "unix" 来区分目标 socket，
// 同时用一个自定义 Transport 按请求上下文取出真正的 socket 路径。
type Proxy struct {
	mgr      *Manager
	proxy    *httputil.ReverseProxy
	timeout  time.Duration
	upstream string // 固定为 "unix"，仅用于让 ReverseProxy 认为 URL 合法
}

// unixConnKey 是存放目标 socket 路径的 context key。
type unixConnKey struct{}

// NewProxy 构造插件请求转发器。
func NewProxy(mgr *Manager) *Proxy {
	p := &Proxy{
		mgr:      mgr,
		timeout:  mgr.RequestTimeout(),
		upstream: "unix",
	}

	transport := &http.Transport{
		// DialContext 从请求上下文里取出目标 socket 路径。
		// 这是把「每个插件不同 socket」塞进固定 Transport 的关键技巧。
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			sockPath, ok := ctx.Value(unixConnKey{}).(string)
			if !ok || sockPath == "" {
				return nil, errors.New("plugin: 请求上下文缺少插件 socket 路径")
			}
			return dialUnix(ctx, sockPath)
		},
		// Unix socket 是本地连接，无需长连接池，也不该复用被插件关掉的连接。
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}

	p.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// 目标地址固定为 http://unix，实际连接由 Transport 决定。
			// 这里不能改动 URL.Path——插件看到的路径由 ServeHTTP 决定。
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = p.upstream
			// 保留原始 Host 会泄露面板的外部域名，插件并不需要，
			// 且可能被插件误用于拼接回跳地址；统一改写为 unix。
			pr.Out.Host = p.upstream

			// 剥离核心自身的凭据：插件绝不能拿到面板的会话 Cookie，
			// 否则一个被攻陷的插件可以直接冒充已登录用户调用全部核心接口。
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			// 标记请求来源，插件可据此区分「来自面板核心」与「被直接访问」。
			pr.Out.Header.Set("X-Lipanel-Plugin-Proxy", "1")
			// 传递原始路径与客户端信息，便于插件做日志与限流。
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// 转发失败的统一出口：区分超时与其它错误，给出可操作的提示。
			status := http.StatusBadGateway
			msg := "插件请求失败: " + err.Error()
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
				msg = fmt.Sprintf("插件响应超时（上限 %s）", p.timeout)
			}
			// 记录到 Manager 的日志，方便定位是哪个插件出的问题。
			id, _ := r.Context().Value(pluginIDKey{}).(string)
			p.mgr.logger.Error("转发插件请求失败", "plugin", id, "path", r.URL.Path, "err", err)

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
		},
	}
	return p
}

// pluginIDKey 用于在请求上下文中携带插件 ID。
type pluginIDKey struct{}

// WithPluginID 把插件 ID 注入上下文。
func WithPluginID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, pluginIDKey{}, id)
}

// PluginIDFrom 取出上下文中的插件 ID。
func PluginIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(pluginIDKey{}).(string)
	return id
}

// ServeHTTP 把请求转发到 id 对应的插件。
//
// subPath 是去掉 /api/plugins/{id} 前缀后的剩余路径（必须以 / 开头）。
// 这个参数由核心路由层显式传入，而不是从 r.URL.Path 里做字符串裁剪——
// 后者很容易因为编码差异（%2e%2e 之类）被绕过，产生路径穿越。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, id, subPath string) {
	// 再次校验 ID：即使调用方已经校验过，这里也不依赖上游的正确性。
	if !ValidID(id) {
		writeProxyError(w, http.StatusBadRequest, "非法插件 ID")
		return
	}
	if !strings.HasPrefix(subPath, "/") {
		writeProxyError(w, http.StatusBadRequest, "非法插件子路径")
		return
	}

	mgr := p.mgr

	// 一次持锁取齐「是否运行」与「socket 路径」：
	// 若分两次取，中间插件可能被停止，就会拿着旧路径去连一个已消失的 socket。
	mgr.mu.RLock()
	e, known := mgr.registry[id]
	var (
		sockPath string
		state    string
	)
	if known {
		sockPath, state = e.sockPath, e.state
	}
	mgr.mu.RUnlock()

	if !known {
		writeProxyError(w, http.StatusNotFound, "插件不存在: "+id)
		return
	}
	if state != StateRunning {
		// 503 而不是 502：这是「服务当前不可用」，且是面板可控的状态，
		// 前端据此提示用户先启动插件，而不是当成插件内部错误。
		w.Header().Set("X-Lipanel-Plugin-State", state)
		writeProxyError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("插件 %s 当前未运行（状态: %s），请先在插件管理页启动", id, state))
		return
	}
	if sockPath == "" {
		writeProxyError(w, http.StatusInternalServerError, "插件 socket 路径缺失")
		return
	}

	// 超时控制：一个卡死的插件不能拖垮整个面板。
	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	ctx = WithPluginID(ctx, id)
	ctx = context.WithValue(ctx, unixConnKey{}, sockPath)

	out := r.Clone(ctx)
	// 只改写 Path 与 RequestURI，其余（方法、Body、Header）原样透传。
	out.URL.Path = subPath
	out.URL.RawPath = ""
	out.RequestURI = ""

	// 补一个客户端地址，插件日志里能看出请求来自哪个 IP。
	if out.RemoteAddr == "" {
		out.RemoteAddr = r.RemoteAddr
	}

	p.proxy.ServeHTTP(w, out)
}

// writeProxyError 以统一格式写出转发层的错误响应。
func writeProxyError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
}

// URL 返回插件在核心中的访问基址，便于日志与前端展示。
func (p *Proxy) URL(id string) string {
	return "/api/plugins/" + url.PathEscape(id)
}
