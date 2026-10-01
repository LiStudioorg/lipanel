package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// 存储后端抽象（阶段五 5.3）
// ============================================================================
//
// 三种后端（本地 / S3 / WebDAV）共用同一份接口，因此：
//   · 备份执行、保留策略清理、下载、恢复**只写一遍**；
//   · 三种后端跑**同一张契约测试表**，谁的行为漂移立刻暴露。
//
// ########## 为什么不引入 SDK ##########
//
// 项目约束是「单二进制 + 零外部依赖」（go.mod 至今只有 4 个依赖）。
// 官方 AWS SDK 是几十 MB 的依赖树；而我们要用的只有 5 个 HTTP 动词
// （PUT/GET/DELETE/HEAD 与 ListObjectsV2），签名算法 SigV4 用
// crypto/hmac 与 crypto/sha256 手写约一百行。WebDAV 更简单，
// PROPFIND 的 XML 用 encoding/xml 就能解析。
//
// 代价是必须自己把签名写对——所以 storage_s3_test.go 里的测试
// **会独立地重算一遍签名**并逐字段比对，而不是只断言"请求发出去了"。

// ErrObjectNotFound 表示对象不存在（接口层 → 404）。
var ErrObjectNotFound = errors.New("backup: 备份文件不存在")

// Object 是存储上的一个对象。
type Object struct {
	// Key 是对象名（相对存储根）。
	Key string
	// Size 是字节数（未知时为 0 且 SizeKnown=false）。
	Size      int64
	SizeKnown bool
	// ModTime 是最后修改时间（未知时为零值）。
	ModTime time.Time
}

// Backend 是一个存储后端。
//
// 所有方法都必须能在 ctx 取消时及时返回：备份与上传可能持续很久，
// 用户关掉面板或超时后还挂着一个往云端写数据的 goroutine，
// 是"看起来停了、其实还在跑"那类问题（坑位 16）。
type Backend interface {
	// Type 返回 local / s3 / webdav。
	Type() string
	// Describe 返回人类可读的目标描述（**不含任何凭证**）。
	Describe() string
	// Put 写入一个对象。
	//
	// size 为 -1 表示长度未知（此时实现应尽量用分块传输）。
	// 我们的调用方一律给准确长度——归档先落在本地 staging 文件上，
	// 因此"不知道多大"这个分支在 S3 上根本不会走到（SigV4 需要 hash）。
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get 读取一个对象，返回的 ReadCloser 由调用方关闭。
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	// Stat 查询一个对象；不存在时返回 ErrObjectNotFound。
	Stat(ctx context.Context, key string) (Object, error)
	// Delete 删除一个对象；对象本来就不存在时**返回 nil**（幂等）。
	//
	// 幂等是刻意要求的：保留策略的清理会在每次备份后跑一遍，
	// 若"已经删掉了"报错，用户会看到一串无意义的失败告警，
	// 而真正该关注的清理失败反而被淹没。
	Delete(ctx context.Context, key string) error
	// List 列出具有给定前缀的对象（按 key 升序）。
	//
	// 排序由实现保证——保留策略依赖「字典序即时间序」这个约定
	// 来决定删哪些，把排序交给调用方会让三种后端各写一遍。
	List(ctx context.Context, prefix string) ([]Object, error)
	// Close 释放资源（幂等；本地后端为 no-op）。
	Close() error
}

// BackendOptions 是构造后端的配置。
type BackendOptions struct {
	// HTTPClient 覆盖默认客户端（测试注入 httptest 的客户端）。
	//
	// 测试注入的不是"假客户端"，而是配置了正确 TLS/超时的真客户端——
	// 我们要验证的是**真的 HTTP 交互**（含签名与 XML 解析），
	// 把 HTTP 层替换掉就等于把被测对象换成了替身。
	HTTPClient *http.Client
	// Timeout 是单次请求的客户端超时。
	Timeout time.Duration
}

// NewBackend 按存储配置构造后端。
//
// 不在这里做连通性检查：构造失败只应发生在"配置本身不成立"时，
// 而"连不上"是运行期状态（见 StorageTest）。
func NewBackend(st Storage, opts BackendOptions) (Backend, error) {
	switch st.Type {
	case StorageLocal:
		return newLocalBackend(st)
	case StorageS3:
		return newS3Backend(st, opts)
	case StorageWebDAV:
		return newWebDAVBackend(st, opts)
	default:
		return nil, fmt.Errorf("backup: 不支持的存储类型 %q", st.Type)
	}
}

// newHTTPClient 构造带超时的 HTTP 客户端。
//
// 代理设置交给 http.ProxyFromEnvironment（与 curl 一致的行为）：
// 用户在企业网里靠 HTTPS_PROXY 访问云存储是很常见的事，
// 自己写一个"忽略代理"的客户端会让备份在他们那里永远失败。
func newHTTPClient(timeout time.Duration, insecureSkipVerify bool) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
	if insecureSkipVerify {
		// 自建 MinIO / WebDAV 用自签证书是常态。这是用户显式勾选的，
		// 且在存储配置页有明确警示文案。
		tr.TLSClientConfig = insecureTLSConfig()
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// joinKey 把基础路径与对象名拼成完整 key（单斜杠分隔）。
func joinKey(base, key string) string {
	base = strings.Trim(base, "/")
	key = strings.Trim(key, "/")
	if base == "" {
		return key
	}
	if key == "" {
		return base
	}
	return base + "/" + key
}

// sortObjects 按 key 升序排序。
//
// 归档名里内嵌了定长的时间戳，因此**字典序即时间序**——
// 保留策略据此决定删哪些，完全不依赖远端的 mtime
// （各家 S3 实现与 WebDAV 服务端对 Last-Modified 的精度与
// 时区处理并不一致，依赖它会导致"该删的没删、不该删的删了"）。
func sortObjects(list []Object) {
	sort.SliceStable(list, func(i, j int) bool { return list[i].Key < list[j].Key })
}

// objectName 从 key 里取展示用的文件名。
func objectName(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}
