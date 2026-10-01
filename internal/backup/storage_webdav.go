package backup

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// WebDAV 存储后端（阶段五 5.3）
// ============================================================================
//
// 用 4 个标准方法 + 1 个扩展方法实现：PUT / GET / DELETE / MKCOL / PROPFIND。
// 全部是 RFC 4918 定义的，用 net/http 与 encoding/xml 就能写完，
// 不需要任何 WebDAV 库。
//
// ########## 两处容易踩坑的地方 ##########
//
// ① **PROPFIND 的响应是 207 Multi-Status，且 href 是 URL**。
//    href 可能是绝对 URL、也可能只是路径，还可能带百分号编码；
//    必须统一解码成路径再取相对部分，否则列出对象时
//    会拿到一长串 "https://host/dav/..." 当作对象名。
//
// ② **父目录不存在时 PUT 会返回 409 Conflict**（不是 404）。
//    而我们的对象名带 `<prefix>/<taskid>-<时间>.tar.gz` 两级结构，
//    第一次备份时那个前缀目录并不存在。因此上传前要先确认目录，
//    409 时补一次 MKCOL 再重试——只重试一次，避免打转。

// webdavBackend 是 WebDAV 后端。
type webdavBackend struct {
	baseURL  *url.URL
	username string
	password string
	base     string
	client   *http.Client
}

// newWebDAVBackend 构造 WebDAV 后端。
func newWebDAVBackend(st Storage, opts BackendOptions) (Backend, error) {
	raw := strings.TrimRight(strings.TrimSpace(st.Endpoint), "/")
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析 WebDAV 服务地址失败: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("backup: WebDAV 服务地址必须以 http(s):// 开头: %q", st.Endpoint)
	}
	if strings.TrimSpace(st.Username) == "" {
		return nil, errors.New("backup: WebDAV 用户名不能为空")
	}
	client := opts.HTTPClient
	if client == nil {
		client = newHTTPClient(opts.Timeout, st.InsecureSkipVerify)
	}
	return &webdavBackend{
		baseURL:  u,
		username: strings.TrimSpace(st.Username),
		password: st.Password,
		base:     strings.Trim(st.BasePath, "/"),
		client:   client,
	}, nil
}

func (b *webdavBackend) Type() string { return StorageWebDAV }

// Describe 返回目标描述（**绝不含凭证**）。
func (b *webdavBackend) Describe() string {
	s := b.baseURL.String()
	if b.base != "" {
		s += "/" + b.base
	}
	return s
}

func (b *webdavBackend) Close() error { return nil }

// objectURL 构造对象 URL（每个路径分段单独转义）。
func (b *webdavBackend) objectURL(key string, trailingSlash bool) string {
	segs := []string{}
	if b.base != "" {
		segs = append(segs, strings.Split(b.base, "/")...)
	}
	if key != "" {
		segs = append(segs, strings.Split(key, "/")...)
	}
	escaped := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" {
			continue
		}
		escaped = append(escaped, escapePathSegment(s))
	}
	base := strings.TrimRight(b.baseURL.String(), "/")
	if len(escaped) == 0 {
		if trailingSlash {
			return base + "/"
		}
		return base
	}
	out := base + "/" + strings.Join(escaped, "/")
	if trailingSlash {
		out += "/"
	}
	return out
}

// newRequest 构造带 Basic 认证的请求。
func (b *webdavBackend) newRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("backup: 构造 WebDAV 请求失败: %w", err)
	}
	req.SetBasicAuth(b.username, b.password)
	return req, nil
}

// do 执行请求。
func (b *webdavBackend) do(req *http.Request) (*http.Response, error) {
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("backup: WebDAV 请求失败（%s %s）: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

// readWebDAVError 读取错误响应（正文截断后附在错误里）。
func readWebDAVError(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Sprintf("WebDAV 返回 %d: %s", resp.StatusCode, msg)
}

// Put 上传对象（409 时补建父目录并重试一次）。
func (b *webdavBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ValidateArchiveKey(key); err != nil {
		return err
	}
	target := b.objectURL(key, false)
	// 上传前先确保父目录存在。做一次 MKCOL 是幂等的
	// （目录已存在时服务端返回 405，我们忽略它），
	// 这样绝大多数情况下不会走到"409 再重试"那条路。
	b.ensureParent(ctx, key)

	// 上传体需要可重放：409 重试时要重新读一遍。
	seeker, ok := r.(io.ReadSeeker)
	if !ok {
		return errors.New("backup: WebDAV 上传要求可重放的读取源（内部错误）")
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := b.newRequest(ctx, http.MethodPut, target, seeker)
		if err != nil {
			return err
		}
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := b.do(req)
		if err != nil {
			return err
		}
		status := resp.StatusCode
		// 409/404 表示父目录不存在：补建后重试一次。
		if (status == http.StatusConflict || status == http.StatusNotFound) && attempt == 0 {
			_ = resp.Body.Close()
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("backup: 回绕读取源失败: %w", err)
			}
			if err := b.mkcol(ctx, path.Dir(key)); err != nil {
				return fmt.Errorf("backup: 创建 WebDAV 目录失败: %w", err)
			}
			continue
		}
		body := ""
		if status < 200 || status >= 300 {
			body = readWebDAVError(resp)
		}
		_ = resp.Body.Close()
		if body != "" {
			return fmt.Errorf("backup: 上传 %s 失败: %s", key, body)
		}
		return nil
	}
	return fmt.Errorf("backup: 上传 %s 失败：父目录补建后仍然失败", key)
}

// ensureParent 尽力确保对象的父目录存在（失败不影响后续流程）。
func (b *webdavBackend) ensureParent(ctx context.Context, key string) {
	dir := path.Dir(key)
	if dir == "." || dir == "" || dir == "/" {
		return
	}
	// 忽略错误：409 那条重试路径会兜住。
	_ = b.mkcol(ctx, dir)
}

// mkcol 自顶向下创建目录链（MKCOL 不能一次建多层）。
func (b *webdavBackend) mkcol(ctx context.Context, dir string) error {
	dir = strings.Trim(dir, "/")
	if dir == "" || dir == "." {
		return nil
	}
	parts := strings.Split(dir, "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if cur == "" {
			cur = p
		} else {
			cur = cur + "/" + p
		}
		req, err := b.newRequest(ctx, "MKCOL", b.objectURL(cur, true), nil)
		if err != nil {
			return err
		}
		resp, err := b.do(req)
		if err != nil {
			return err
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		switch status {
		case http.StatusCreated, http.StatusOK, http.StatusNoContent:
			// 建好了。
		case http.StatusMethodNotAllowed, http.StatusConflict:
			// 405 = 已经存在（RFC 4918 允许的响应）；
			// 409 = 父目录还没有，但我们的循环是从最上层开始的，
			// 因此走到这里多半是服务端特性，忽略继续。
		default:
			if status >= 400 && status != http.StatusNotFound {
				return fmt.Errorf("创建目录 %s 失败: WebDAV 返回 %d", cur, status)
			}
		}
	}
	return nil
}

// Get 下载对象。
func (b *webdavBackend) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return nil, 0, err
	}
	req, err := b.newRequest(ctx, http.MethodGet, b.objectURL(key, false), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := b.do(req)
	if err != nil {
		return nil, 0, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, 0, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		msg := readWebDAVError(resp)
		_ = resp.Body.Close()
		return nil, 0, fmt.Errorf("backup: 下载 %s 失败: %s", key, msg)
	}
	return resp.Body, resp.ContentLength, nil
}

// Stat 查询对象（PROPFIND Depth:0）。
//
// 用 PROPFIND 而不是 HEAD：HEAD 不是 WebDAV 标准要求实现的方法，
// 部分服务端（含一些 NAS 与网盘网关）直接返回 405。
func (b *webdavBackend) Stat(ctx context.Context, key string) (Object, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return Object{}, err
	}
	req, err := b.newRequest(ctx, "PROPFIND", b.objectURL(key, false), nil)
	if err != nil {
		return Object{}, err
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml")
	resp, err := b.do(req)
	if err != nil {
		return Object{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return Object{}, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := readWebDAVError(resp)
		_ = resp.Body.Close()
		return Object{}, fmt.Errorf("backup: 查询 %s 失败: %s", key, msg)
	}
	defer func() { _ = resp.Body.Close() }()
	items, err := parseMultiStatus(resp.Body)
	if err != nil {
		return Object{}, fmt.Errorf("backup: 解析 WebDAV 响应失败: %w", err)
	}
	if len(items) == 0 {
		// ########## 空的多状态响应就是"不存在"，不是后端故障 ##########
		//
		// 不少 WebDAV 服务端对不存在的路径**不返回 404**，而是回一个
		// 207，里面只有父集合或干脆没有条目（Nextcloud、部分群晖版本
		// 都是这个行为）。若把它当成普通错误往上抛，后果是：
		//   · 保留策略的删除会因为"查不到"而失败；
		//   · 界面把"这份备份已经没了"显示成"存储连不上"。
		// 二者都会让用户去排查一个根本没坏的东西。
		return Object{}, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
	}
	return Object{
		Key: key, Size: items[0].Size, SizeKnown: true, ModTime: items[0].ModTime,
	}, nil
}

// Delete 删除对象（幂等：404 视为成功）。
func (b *webdavBackend) Delete(ctx context.Context, key string) error {
	if err := ValidateArchiveKey(key); err != nil {
		return err
	}
	req, err := b.newRequest(ctx, http.MethodDelete, b.objectURL(key, false), nil)
	if err != nil {
		return err
	}
	resp, err := b.do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backup: 删除 %s 失败: %s", key, readWebDAVError(resp))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// davMultiStatus 是 PROPFIND 的响应结构（只取我们需要的字段）。
type davMultiStatus struct {
	XMLName   xml.Name  `xml:"multistatus"`
	Responses []davResp `xml:"response"`
}

type davResp struct {
	Href     string      `xml:"href"`
	Propstat []davPropst `xml:"propstat"`
}

type davPropst struct {
	Status string  `xml:"status"`
	Prop   davProp `xml:"prop"`
}

type davProp struct {
	// ContentLength 在部分服务端是 {DAV:}getcontentlength，
	// 在另一些是 getcontentlength（无命名空间）。XML 解码时
	// 带命名空间的元素名仍匹配本地名，因此一个字段即可覆盖两者。
	ContentLength string `xml:"getcontentlength"`
	LastModified  string `xml:"getlastmodified"`
	ResourceType  struct {
		Collection *struct{} `xml:"collection"`
	} `xml:"resourcetype"`
	DisplayName string `xml:"displayname"`
}

// davItem 是解析后的一个条目。
type davItem struct {
	Href     string
	Size     int64
	ModTime  time.Time
	IsDir    bool
	AllProp  bool
	InStatus bool
}

// parseMultiStatus 解析 207 响应。
func parseMultiStatus(r io.Reader) ([]davItem, error) {
	var ms davMultiStatus
	dec := xml.NewDecoder(r)
	// WebDAV 的命名空间前缀在不同服务端上五花八门，
	// 关掉严格模式让本地名匹配生效。
	dec.Strict = false
	if err := dec.Decode(&ms); err != nil {
		return nil, err
	}
	out := make([]davItem, 0, len(ms.Responses))
	for _, resp := range ms.Responses {
		item := davItem{Href: decodeHref(resp.Href)}
		for _, ps := range resp.Propstat {
			// 只看 200 的那一段：404 段是"这个属性不存在"，
			// 把它当数据用会得到一堆空值。
			if ps.Status != "" && !strings.Contains(ps.Status, " 200 ") {
				continue
			}
			item.InStatus = true
			if ps.Prop.ResourceType.Collection != nil {
				item.IsDir = true
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(ps.Prop.ContentLength), 10, 64); err == nil {
				item.Size = n
			}
			if t := parseHTTPTime(strings.TrimSpace(ps.Prop.LastModified)); !t.IsZero() {
				item.ModTime = t
			}
		}
		out = append(out, item)
	}
	return out, nil
}

// decodeHref 把 href 解码成路径（去掉主机与百分号编码）。
func decodeHref(href string) string {
	h := strings.TrimSpace(href)
	if h == "" {
		return ""
	}
	if u, err := url.Parse(h); err == nil && u.Path != "" {
		return u.Path
	}
	return h
}

// List 列出具有给定前缀的对象（PROPFIND Depth:1，逐目录下钻）。
func (b *webdavBackend) List(ctx context.Context, prefix string) ([]Object, error) {
	out := []Object{}
	// 先确定"要列哪个目录"。prefix 的最后一段可能是不完整的文件名，
	// 因此目录取到最后一个 / 之前。
	dir := ""
	namePrefix := ""
	if prefix != "" {
		if strings.HasSuffix(prefix, "/") {
			dir = strings.TrimSuffix(prefix, "/")
		} else if i := strings.LastIndex(prefix, "/"); i >= 0 {
			dir = prefix[:i]
			namePrefix = prefix[i+1:]
		} else {
			namePrefix = prefix
		}
	}
	items, err := b.propfind(ctx, dir)
	if err != nil {
		// 目录不存在 = 还没有备份，不是错误。
		if errors.Is(err, ErrObjectNotFound) {
			return out, nil
		}
		return nil, err
	}
	// 目录部分已由 propfind 限定，这里只剩文件名前缀的复核。
	for _, it := range items {
		if it.IsDir {
			continue
		}
		key := b.relativeKey(it.Href)
		if key == "" {
			continue
		}
		if namePrefix != "" {
			if !strings.HasPrefix(objectName(key), namePrefix) {
				continue
			}
		}
		out = append(out, Object{Key: key, Size: it.Size, SizeKnown: true, ModTime: it.ModTime})
	}
	sortObjects(out)
	return out, nil
}

// propfind 列出某个目录下的条目（Depth:1）。
func (b *webdavBackend) propfind(ctx context.Context, dir string) ([]davItem, error) {
	req, err := b.newRequest(ctx, "PROPFIND", b.objectURL(dir, dir != ""), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := b.do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, dir)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("backup: 列出 %s 失败: %s", dir, readWebDAVError(resp))
	}
	items, err := parseMultiStatus(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析 WebDAV 响应失败: %w", err)
	}
	return items, nil
}

// relativeKey 把 href 路径转成"相对于存储根"的对象名。
//
// ########## 这一步不做的话列表全是垃圾 ##########
//
// href 是**绝对路径**（"/dav/backups/abc.tar.gz"），直接当对象名用
// 会得到一列以 / 开头的字符串；而 ValidateArchiveKey 明确拒绝
// 以 / 开头的 key——于是"列出备份"能成功，但"下载/删除列出来的
// 那一项"必然失败。两个接口对同一个概念用两套表示，是这类
// bug 的经典形态。
func (b *webdavBackend) relativeKey(href string) string {
	p := href
	if p == "" {
		return ""
	}
	// 去掉 baseURL 的路径前缀（可能是 "/dav"）。
	basePath := strings.TrimRight(b.baseURL.Path, "/")
	if basePath != "" && strings.HasPrefix(p, basePath) {
		p = strings.TrimPrefix(p, basePath)
	}
	p = strings.Trim(p, "/")
	if b.base != "" && p == b.base {
		return ""
	}
	if b.base != "" && strings.HasPrefix(p, b.base+"/") {
		p = strings.TrimPrefix(p, b.base+"/")
	}
	return p
}
