package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// S3 兼容对象存储后端（阶段五 5.3）——手写 AWS Signature V4
// ============================================================================
//
// 支持任何 S3 兼容实现（AWS S3、MinIO、Ceph RGW、阿里云 OSS 的
// S3 兼容端点……），因为它只用 5 个 HTTP 动词 + 一个公开的签名算法。
//
// ########## SigV4 最容易写错的四处（都已在测试里锁死）##########
//
//  ① **规范化 URI 必须用已编码的路径**，且 S3 的编码规则与
//     url.PathEscape 不同：斜杠**不**编码，其余非安全字符用大写 hex。
//     用 PathEscape 会把 "a/b" 编成 "a%2Fb"，签名直接对不上。
//  ② **规范化查询串必须按键名排序**，且 list-type=2 这类参数
//     的拼装顺序不能即签即用同一份——必须用同一份**已排序**的结果，
//     否则签的是一份、发的是另一份。
//  ③ **CanonicalHeaders 里必须包含 host**，且值要去首尾空白。
//  ④ **签名密钥是逐级派生的**（kDate → kRegion → kService → kSigning），
//     不是直接用 SecretKey 做 HMAC。
//
// 测试 storage_s3_test.go 里的 httptest 服务端会**独立重算一遍**签名
// 并与收到的 Authorization 头逐字段比对，而不是只断言"请求发出去了"。

// s3Service 是 SigV4 里的服务名（固定值，不是可配项）。
const s3Service = "s3"

// s3UnsignedPayload 是"载荷已签名"模式下的占位符（本实现不用）。
const s3EmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// s3Backend 是 S3 兼容后端。
type s3Backend struct {
	endpoint  *url.URL
	bucket    string
	region    string
	accessKey string
	secretKey string
	pathStyle bool
	base      string
	client    *http.Client
	// now 用于注入时钟（测试可确定地断言签名日期）。
	now func() time.Time
}

// newS3Backend 构造 S3 后端。
func newS3Backend(st Storage, opts BackendOptions) (Backend, error) {
	raw := strings.TrimRight(strings.TrimSpace(st.Endpoint), "/")
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("backup: 解析 S3 服务地址失败: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("backup: S3 服务地址必须以 http(s):// 开头: %q", st.Endpoint)
	}
	if strings.TrimSpace(st.Bucket) == "" {
		return nil, errors.New("backup: S3 桶名不能为空")
	}
	if strings.TrimSpace(st.AccessKey) == "" {
		return nil, errors.New("backup: S3 Access Key ID 不能为空")
	}
	if strings.TrimSpace(st.SecretKey) == "" {
		return nil, errors.New("backup: S3 Secret Access Key 不能为空")
	}
	region := strings.TrimSpace(st.Region)
	if region == "" {
		// 不填区域时按 us-east-1 处理：它是 SigV4 的惯用默认值，
		// MinIO 之类自建实现也只校验格式、不校验具体值。
		region = "us-east-1"
	}
	client := opts.HTTPClient
	if client == nil {
		client = newHTTPClient(opts.Timeout, st.InsecureSkipVerify)
	}
	return &s3Backend{
		endpoint:  u,
		bucket:    strings.TrimSpace(st.Bucket),
		region:    region,
		accessKey: strings.TrimSpace(st.AccessKey),
		secretKey: st.SecretKey,
		pathStyle: st.PathStyle,
		base:      strings.Trim(st.BasePath, "/"),
		client:    client,
		now:       time.Now,
	}, nil
}

func (b *s3Backend) Type() string { return StorageS3 }

// Describe 返回目标描述（**绝不含凭证**）。
func (b *s3Backend) Describe() string {
	return fmt.Sprintf("s3://%s/%s", b.bucket, b.base)
}

func (b *s3Backend) Close() error { return nil }

// buildURL 构造请求 URL（含 path-style 与 virtual-host 两种寻址）。
//
// path-style：  https://endpoint/<bucket>/<key>
// virtual-host：https://<bucket>.endpoint/<key>
//
// 后者在自建实现上常常不可用（没有泛域名证书），因此
// PathStyle 是一个显式开关，默认 path-style。
func (b *s3Backend) buildURL(key string, query url.Values) *url.URL {
	u := *b.endpoint
	objectPath := joinKey(b.base, key)

	var rawPath string
	if b.pathStyle {
		rawPath = "/" + b.bucket
		if objectPath != "" {
			rawPath += "/" + objectPath
		}
	} else {
		u.Host = b.bucket + "." + u.Host
		if objectPath != "" {
			rawPath = "/" + objectPath
		} else {
			rawPath = "/"
		}
	}
	u.RawPath = s3EscapePath(rawPath)
	u.Path = rawPath
	// 注意：**不能**直接用 u.String()，因为它会用 u.Path 重新编码
	// （把 %2F 之类还原），签的与发的就成了两份不同的 URI。
	// 因此这里手工用 RawPath 拼出最终串。
	if query != nil && len(query) > 0 {
		u.RawQuery = encodeQueryCanonical(query)
	} else {
		u.RawQuery = ""
	}
	return &u
}

// requestURLString 返回"实际发出"的 URL 串。
//
// 它必须与签名时用的 canonical URI 完全一致，因此统一走 RawPath。
func requestURLString(u *url.URL, rawQuery string) string {
	s := u.Scheme + "://" + u.Host
	if u.RawPath != "" {
		s += u.RawPath
	} else {
		s += u.Path
	}
	if rawQuery != "" {
		s += "?" + rawQuery
	}
	return s
}

// escapePathSegment 按 SigV4 要求编码单个路径分段。
//
// 未保留字符（A-Z a-z 0-9 - _ . ~）原样输出，其余一律 %XX 大写。
// 斜杠由调用方按路径结构插入，**不经过本函数**。
func escapePathSegment(seg string) string {
	var sb strings.Builder
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// s3EscapePath 编码整条路径（保留斜杠作为分隔符）。
func s3EscapePath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = escapePathSegment(s)
	}
	return strings.Join(segs, "/")
}

// encodeQueryCanonical 按 SigV4 要求编码查询串（键名排序 + 键值编码）。
func encodeQueryCanonical(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		if len(vals) == 0 {
			parts = append(parts, escapePathSegment(k)+"=")
			continue
		}
		for _, v := range vals {
			parts = append(parts, escapePathSegment(k)+"="+escapePathSegment(v))
		}
	}
	return strings.Join(parts, "&")
}

// sign 给请求加上 SigV4 头。
//
// payloadHash 是载荷的 SHA256 十六进制串；请求体为空时用
// s3EmptyPayloadHash（空串的 SHA256 是个众所周知的常量）。
func (b *s3Backend) sign(req *http.Request, payloadHash string, t time.Time) {
	amzDate := t.UTC().Format("20060102T150405Z")
	dateStamp := t.UTC().Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// ① 规范化请求：方法 + 规范 URI + 规范查询串 + 规范头 + 已签名头清单。
	canonicalURI := req.URL.RawPath
	if canonicalURI == "" {
		canonicalURI = s3EscapePath(req.URL.Path)
	}
	canonicalQuery := req.URL.RawQuery

	// 参与签名的头：host 必选，加上全部 x-amz-*。
	headers := map[string]string{"host": req.Host}
	if headers["host"] == "" {
		headers["host"] = req.URL.Host
	}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	// content-type 若存在也纳入签名（PUT 上传时要带）。
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers["content-type"] = strings.TrimSpace(ct)
	}

	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var chBuf strings.Builder
	for _, k := range names {
		chBuf.WriteString(k)
		chBuf.WriteByte(':')
		chBuf.WriteString(headers[k])
		chBuf.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		chBuf.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// ② 待签串。
	scope := strings.Join([]string{dateStamp, b.region, s3Service, "aws4_request"}, "/")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	// ③ 派生签名密钥（逐级 HMAC，不能直接用 SecretKey）。
	kDate := hmacSHA256([]byte("AWS4"+b.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, b.region)
	kService := hmacSHA256(kRegion, s3Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		b.accessKey, scope, signedHeaders, signature))
}

// hmacSHA256 计算 HMAC-SHA256。
func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// do 执行一次已签名的请求，并把非 2xx 响应翻译成有意义的错误。
func (b *s3Backend) do(ctx context.Context, req *http.Request, payloadHash string) (*http.Response, error) {
	// URL 与签名必须用同一份时间戳与同一份 RawQuery，
	// 因此这里在发请求前才最终拼出 RequestURI。
	rawQuery := req.URL.RawQuery
	b.sign(req, payloadHash, b.now())

	// Go 的 http.Client 会用 URL.RequestURI() 生成请求行，
	// 它优先使用 RawPath——这正是我们要的（与签名一致）。
	resp, err := b.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("backup: S3 请求失败（%s %s）: %w", req.Method, sanitizeURL(req.URL, rawQuery), err)
	}
	return resp, nil
}

// sanitizeURL 返回可安全写进日志/错误的 URL（**不含签名与凭证**）。
func sanitizeURL(u *url.URL, rawQuery string) string {
	s := u.Scheme + "://" + u.Host + u.Path
	if rawQuery != "" {
		s += "?" + rawQuery
	}
	return s
}

// s3Error 解析 S3 的错误响应体（XML）。
type s3Error struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// readS3Error 读取并翻译错误响应。
func readS3Error(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	var e s3Error
	if err := xml.Unmarshal(body, &e); err == nil && e.Code != "" {
		return fmt.Errorf("S3 返回 %d: %s（%s）", resp.StatusCode, e.Message, e.Code)
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("S3 返回 %d: %s", resp.StatusCode, msg)
}

// Put 上传对象。
//
// 载荷的 SHA256 由调用方计算的 size 与内容**流式**算出：
// 我们不把归档整个读进内存（那可能是几十 GB），而是先扫一遍
// staging 文件算哈希，再第二遍上传。两遍 I/O 换来的是
// "永远不需要把归档放进内存"——这是必须的取舍。
func (b *s3Backend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ValidateArchiveKey(key); err != nil {
		return err
	}
	// 算载荷哈希：需要在发送前知道它，因此把内容读进一个
	// **可重放的来源**。调用方给的都是 *os.File（staging 文件），
	// 因此这里用 ReadSeeker 双读，而不是缓冲全部内容。
	seeker, ok := r.(io.ReadSeeker)
	if !ok {
		return errors.New("backup: S3 上传要求可重放的读取源（内部错误）")
	}
	hash, err := hashReader(seeker)
	if err != nil {
		return fmt.Errorf("backup: 计算 %s 的校验值失败: %w", key, err)
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("backup: 回绕读取源失败: %w", err)
	}

	u := b.buildURL(key, nil)
	req, err := http.NewRequest(http.MethodPut, requestURLString(u, u.RawQuery), seeker)
	if err != nil {
		return fmt.Errorf("backup: 构造 S3 上传请求失败: %w", err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := b.do(ctx, req, hash)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backup: 上传 %s 失败: %w", key, readS3Error(resp))
	}
	// 排空响应体以便连接复用（S3 的 PUT 响应很小）。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// hashReader 流式计算 SHA256 十六进制串。
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Get 下载对象。
func (b *s3Backend) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return nil, 0, err
	}
	u := b.buildURL(key, nil)
	req, err := http.NewRequest(http.MethodGet, requestURLString(u, u.RawQuery), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("backup: 构造 S3 下载请求失败: %w", err)
	}
	resp, err := b.do(ctx, req, s3EmptyPayloadHash)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, 0, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer func() { _ = resp.Body.Close() }()
		return nil, 0, fmt.Errorf("backup: 下载 %s 失败: %w", key, readS3Error(resp))
	}
	return resp.Body, resp.ContentLength, nil
}

// Stat 查询对象（HEAD）。
func (b *s3Backend) Stat(ctx context.Context, key string) (Object, error) {
	if err := ValidateArchiveKey(key); err != nil {
		return Object{}, err
	}
	u := b.buildURL(key, nil)
	req, err := http.NewRequest(http.MethodHead, requestURLString(u, u.RawQuery), nil)
	if err != nil {
		return Object{}, fmt.Errorf("backup: 构造 S3 查询请求失败: %w", err)
	}
	resp, err := b.do(ctx, req, s3EmptyPayloadHash)
	if err != nil {
		return Object{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return Object{}, fmt.Errorf("%w: %s", ErrObjectNotFound, key)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Object{}, fmt.Errorf("backup: 查询 %s 失败: %w", key, readS3Error(resp))
	}
	return Object{Key: key, Size: resp.ContentLength, SizeKnown: resp.ContentLength >= 0,
		ModTime: parseHTTPTime(resp.Header.Get("Last-Modified"))}, nil
}

// Delete 删除对象（幂等：404 视为成功）。
func (b *s3Backend) Delete(ctx context.Context, key string) error {
	if err := ValidateArchiveKey(key); err != nil {
		return err
	}
	u := b.buildURL(key, nil)
	req, err := http.NewRequest(http.MethodDelete, requestURLString(u, u.RawQuery), nil)
	if err != nil {
		return fmt.Errorf("backup: 构造 S3 删除请求失败: %w", err)
	}
	resp, err := b.do(ctx, req, s3EmptyPayloadHash)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// 404 是幂等语义的一部分：保留策略可能因为远端缓存、
	// 或上一次清理只完成了一半而重复删同一个 key。
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	// S3 对删除不存在的对象返回 204（不是 404），两者都算成功。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backup: 删除 %s 失败: %w", key, readS3Error(resp))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// listBucketResult 是 ListObjectsV2 的响应结构。
type listBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	Contents    []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// List 列出具有给定前缀的对象（自动翻页）。
func (b *s3Backend) List(ctx context.Context, prefix string) ([]Object, error) {
	// 前缀是"对象名前缀"，但 ListObjectsV2 的 prefix 是**完整 key 前缀**，
	// 因此要把 base 拼上。
	fullPrefix := joinKey(b.base, prefix)
	out := []Object{}
	token := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("max-keys", "1000")
		if fullPrefix != "" {
			q.Set("prefix", fullPrefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		// 列出桶内对象时 path 是 /<bucket>（不带 key）。
		u := b.buildURL("", q)
		req, err := http.NewRequest(http.MethodGet, requestURLString(u, u.RawQuery), nil)
		if err != nil {
			return nil, fmt.Errorf("backup: 构造 S3 列表请求失败: %w", err)
		}
		resp, err := b.do(ctx, req, s3EmptyPayloadHash)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := readS3Error(resp)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("backup: 列出对象失败: %w", err)
		}
		var result listBucketResult
		decErr := xml.NewDecoder(resp.Body).Decode(&result)
		_ = resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("backup: 解析 S3 列表响应失败: %w", decErr)
		}
		for _, c := range result.Contents {
			// key 去掉 base 前缀，保持"相对于存储根"的语义，
			// 否则上层拿到的 key 跟其它后端不一致。
			k := strings.TrimPrefix(c.Key, strings.Trim(b.base, "/")+"/")
			if b.base == "" {
				k = c.Key
			}
			out = append(out, Object{
				Key: k, Size: c.Size, SizeKnown: true,
				ModTime: parseHTTPTime(c.LastModified),
			})
		}
		if !result.IsTruncated || result.NextContinuationToken == "" {
			break
		}
		token = result.NextContinuationToken
	}
	sortObjects(out)
	return out, nil
}

// probeKey 是连通性测试写入的对象名。
const probeKey = ".lipanel-connectivity-probe"

// StorageTest 对一个存储配置做连通性测试。
//
// ########## 为什么是"写一个探针再删掉"而不是"连一下端口" ##########
//
// 备份需要的是**写权限**。只做一次 HEAD 或列目录，会放行一个
// "能读不能写"的配置（只读密钥、桶策略只给 GetObject），
// 用户要到第一次备份失败时才发现——而那可能是一周以后。
//
// 探针对象名固定且带 . 前缀，正常备份列表会跳过它。
func StorageTest(ctx context.Context, st Storage, opts BackendOptions) error {
	be, err := NewBackend(st, opts)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	payload := []byte("lipanel connectivity probe " + time.Now().UTC().Format(time.RFC3339))
	if err := be.Put(ctx, probeKey, bytes.NewReader(payload), int64(len(payload))); err != nil {
		return fmt.Errorf("写入测试对象失败（请检查桶是否存在、密钥是否有写权限）: %w", err)
	}
	obj, err := be.Stat(ctx, probeKey)
	if err != nil {
		return fmt.Errorf("读取测试对象失败（写入似乎成功但读不回来）: %w", err)
	}
	if obj.SizeKnown && obj.Size != int64(len(payload)) {
		return fmt.Errorf("测试对象大小不符：期望 %d，实际 %d", len(payload), obj.Size)
	}
	if _, _, err := be.Get(ctx, probeKey); err != nil {
		return fmt.Errorf("下载测试对象失败: %w", err)
	}
	if err := be.Delete(ctx, probeKey); err != nil {
		// 删不掉不影响"能不能备份"这个结论，但要如实说——
		// 留一个探针在桶里是用户的隐私问题。
		return fmt.Errorf("测试对象写入成功，但删除失败（请检查删除权限）: %w", err)
	}
	return nil
}

// parseHTTPTime 解析 HTTP 时间头（失败返回零值）。
func parseHTTPTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{http.TimeFormat, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}
