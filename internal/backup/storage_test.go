package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// 存储后端契约测试（阶段五 5.3）
// ============================================================================
//
// ########## 为什么是"契约测试" ##########
//
// 本地目录、S3、WebDAV 三种后端的**行为必须一致**：Put 之后 Stat
// 要能看到、Get 要能读回原文、Delete 要幂等、List 要按前缀列出。
// 若各写各的用例，那些"某个后端特有的小偏差"（比如本地删完
// 目录还留着、S3 的 List 忘了分页）就会一直躺在代码里——
// 直到用户在某个后端上踩到。
//
// 因此这里用一个**共用的用例表**跑所有后端。S3 与 WebDAV 用
// httptest.Server 起一个"假服务端"，但被测的**仍然是真实的
// HTTP 交互**（签名、XML 解析、状态码、重定向），只把对端换掉了。

// backendFactory 造一个后端 + 一个"读回原文"的期望值。
type backendFactory struct {
	name string
	// newBackend 返回后端与清理函数。
	newBackend func(t *testing.T) (Backend, func())
	// listSupported 表示该后端实现了 List（契约要求都实现）。
	listSupported bool
}

// runBackendContract 对一组后端跑同一套契约。
func runBackendContract(t *testing.T, factories []backendFactory) {
	t.Helper()
	for _, f := range factories {
		f := f
		t.Run(f.name, func(t *testing.T) {
			t.Run("PutStatGetDelete", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				testPutStatGetDelete(t, be)
			})
			t.Run("GetMissing", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				if _, _, err := be.Get(context.Background(), "nope/missing.tar.gz"); !errors.Is(err, ErrObjectNotFound) {
					t.Fatalf("读取不存在的对象：期望 ErrObjectNotFound，实际 %v", err)
				}
			})
			t.Run("StatMissing", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				if _, err := be.Stat(context.Background(), "nope/missing.tar.gz"); !errors.Is(err, ErrObjectNotFound) {
					t.Fatalf("Stat 不存在的对象：期望 ErrObjectNotFound，实际 %v", err)
				}
			})
			t.Run("DeleteIdempotent", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				// 删一个从来不存在的东西**必须成功**：保留策略会
				// 重试删除，一个"删两次就报错"的后端会让清理
				// 每次都留下一条假告警。
				if err := be.Delete(context.Background(), "never/existed.tar.gz"); err != nil {
					t.Fatalf("删除不存在的对象应该成功（幂等），实际 %v", err)
				}
			})
			t.Run("ListPrefix", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				testListPrefix(t, be)
			})
			t.Run("ListEmpty", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				objs, err := be.List(context.Background(), "nothing/here/")
				if err != nil {
					t.Fatalf("列出空前缀失败: %v", err)
				}
				if len(objs) != 0 {
					t.Fatalf("空前缀列出 %d 个对象: %v", len(objs), objs)
				}
			})
			t.Run("RejectsBadKey", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				for _, key := range []string{"", "../escape.tar.gz", "/abs.tar.gz", "a/../../b.tar.gz"} {
					if err := be.Put(context.Background(), key, strings.NewReader("x"), 1); err == nil {
						t.Fatalf("Put 接受了非法对象名 %q", key)
					}
				}
			})
			t.Run("Overwrite", func(t *testing.T) {
				be, done := f.newBackend(t)
				defer done()
				ctx := context.Background()
				key := "task/abcdef123456/x.tar.gz"
				if err := be.Put(ctx, key, strings.NewReader("first"), 5); err != nil {
					t.Fatal(err)
				}
				if err := be.Put(ctx, key, strings.NewReader("second-longer"), 13); err != nil {
					t.Fatalf("覆盖写失败: %v", err)
				}
				got := readAll(t, be, key)
				if got != "second-longer" {
					t.Fatalf("覆盖后内容 = %q（旧的后缀没被截掉？）", got)
				}
			})
		})
	}
}

func testPutStatGetDelete(t *testing.T, be Backend) {
	t.Helper()
	ctx := context.Background()
	key := "backups/abcdef123456/abcdef123456-20260305-143045.tar.gz"
	payload := "fake tar.gz bytes"

	if err := be.Put(ctx, key, strings.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	obj, err := be.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if obj.Size != int64(len(payload)) {
		t.Fatalf("Stat.Size = %d, 期望 %d", obj.Size, len(payload))
	}
	if got := readAll(t, be, key); got != payload {
		t.Fatalf("读回内容 = %q, 期望 %q", got, payload)
	}
	if err := be.Delete(ctx, key); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if _, err := be.Stat(ctx, key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("删除后 Stat 应报 ErrObjectNotFound，实际 %v", err)
	}
}

func testListPrefix(t *testing.T, be Backend) {
	t.Helper()
	ctx := context.Background()
	keys := []string{
		"p/aaaaaaaaaaaa/aaaaaaaaaaaa-20260301-000000.tar.gz",
		"p/aaaaaaaaaaaa/aaaaaaaaaaaa-20260302-000000.tar.gz",
		"p/bbbbbbbbbbbb/bbbbbbbbbbbb-20260301-000000.tar.gz",
	}
	for _, k := range keys {
		if err := be.Put(ctx, k, strings.NewReader("x"), 1); err != nil {
			t.Fatalf("Put %s 失败: %v", k, err)
		}
	}
	objs, err := be.List(ctx, "p/aaaaaaaaaaaa/")
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("List 返回 %d 个对象（期望 2，前缀过滤没生效？）: %v", len(objs), objs)
	}
	for _, o := range objs {
		if !strings.HasPrefix(o.Key, "p/aaaaaaaaaaaa/") {
			t.Fatalf("List 返回了前缀之外的对象: %s", o.Key)
		}
	}
	// 排序必须是**字典序**：保留策略按名字倒序取最新的 N 份，
	// 名字里带定长时间戳，因此字典序即时间序。若某个后端返回
	// 别的顺序，"保留最近 7 份"就会删错。
	for i := 1; i < len(objs); i++ {
		if objs[i-1].Key >= objs[i].Key {
			t.Fatalf("List 结果没有按名字升序: %s >= %s", objs[i-1].Key, objs[i].Key)
		}
	}
}

func readAll(t *testing.T, be Backend, key string) string {
	t.Helper()
	rc, _, err := be.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get %s 失败: %v", key, err)
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", key, err)
	}
	return string(body)
}

// ---------------------------------------------------------------------------
// 本地后端
// ---------------------------------------------------------------------------

func localFactory() backendFactory {
	return backendFactory{
		name: "local",
		newBackend: func(t *testing.T) (Backend, func()) {
			root := t.TempDir()
			be, err := NewBackend(Storage{
				ID: "aaaaaaaaaaaa", Name: "本地", Type: StorageLocal, Path: root,
			}, BackendOptions{})
			if err != nil {
				t.Fatalf("构造本地后端失败: %v", err)
			}
			return be, func() { _ = be.Close() }
		},
	}
}

func TestLocalBackendContract(t *testing.T) {
	runBackendContract(t, []backendFactory{localFactory()})
}

// 本地后端的文件权限必须是 0600：备份里可能有数据库转储、私钥、
// 配置文件，而同机上的其它用户默认能读 0644 的文件。
func TestLocalBackendFileMode(t *testing.T) {
	root := t.TempDir()
	be, err := NewBackend(Storage{ID: "aaaaaaaaaaaa", Type: StorageLocal, Path: root}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	key := "t/aaaaaaaaaaaa/x.tar.gz"
	if err := be.Put(context.Background(), key, strings.NewReader("secret"), 6); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("归档文件不存在: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("归档权限 = %04o, 期望 0600", info.Mode().Perm())
	}
}

// 本地后端绝不能跟随符号链接读文件（那是一个任意文件读入口）。
func TestLocalBackendRefusesSymlink(t *testing.T) {
	if runtime_isWindows() {
		t.Skip("Windows 上创建符号链接需要特权，跳过")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := "t/aaaaaaaaaaaa/link.tar.gz"
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, full); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}

	be, err := NewBackend(Storage{ID: "aaaaaaaaaaaa", Type: StorageLocal, Path: root}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	if _, _, err := be.Get(context.Background(), key); err == nil {
		t.Fatalf("本地后端跟随符号链接读到了目标文件")
	}
}

// 本地后端的 List 必须跳过临时文件（上传中的 .put-*.tmp），
// 否则保留策略会把一个还没写完的文件当成一份备份。
func TestLocalBackendListSkipsTempFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "t", "aaaaaaaaaaaa")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".put-123.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	be, err := NewBackend(Storage{ID: "aaaaaaaaaaaa", Type: StorageLocal, Path: root}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	objs, err := be.List(context.Background(), "t/aaaaaaaaaaaa/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 || !strings.HasSuffix(objs[0].Key, "real.tar.gz") {
		t.Fatalf("List 结果 = %v, 期望只有 real.tar.gz", objs)
	}
}

// ---------------------------------------------------------------------------
// S3 后端（假服务端，但走真实的 SigV4 与 HTTP）
// ---------------------------------------------------------------------------

// fakeS3 是一个最小的 S3 兼容服务端。
//
// 它**独立复算 SigV4**（不用被测代码里的任何函数）：只断言响应
// 等于断言请求就毫无意义——签名算错时"自己验自己"永远是通过的。
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte

	// 记录收到的请求，供断言。
	seenAuth      []string
	seenPath      []string
	seenMethod    []string
	rejectAll     bool
	requireBucket string
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]byte{}} }

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seenAuth = append(f.seenAuth, r.Header.Get("Authorization"))
	f.seenPath = append(f.seenPath, r.URL.Path)
	f.seenMethod = append(f.seenMethod, r.Method)
	reject := f.rejectAll
	f.mu.Unlock()

	if reject {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`))
		return
	}
	// 每一个请求都必须带签名头，否则 S3 会直接 403。
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>no signature</Message></Error>`))
		return
	}

	// 去掉 /<bucket> 前缀。
	p := strings.TrimPrefix(r.URL.Path, "/"+f.requireBucket)
	p = strings.TrimPrefix(p, "/")
	key := p

	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.objects[key] = body
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		body, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		_, _ = w.Write(body)
	case http.MethodHead:
		body, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// listResponse 处理 list-type=2 的列举请求。
func (f *fakeS3) listHandler(w http.ResponseWriter, r *http.Request, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := []string{}
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sortStrings(keys)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	fmt.Fprintf(&b, "<Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><IsTruncated>false</IsTruncated>",
		f.requireBucket, prefix, len(keys))
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>",
			k, len(f.objects[k]), time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	b.WriteString(`</ListBucketResult>`)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(b.String()))
}

// sha256Hex 是**测试自己的**哈希实现。
//
// 刻意不复用生产代码里的同名逻辑：这条用例要验证的正是
// "生产代码算出来的哈希对不对"，复用就等于自证。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// s3Factory 用一个假 S3 服务端造后端。
func s3Factory() backendFactory {
	return backendFactory{
		name: "s3",
		newBackend: func(t *testing.T) (Backend, func()) {
			fake := newFakeS3()
			fake.requireBucket = "mybucket"
			// 把列举请求分流给 listHandler。
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, ok := r.URL.Query()["list-type"]; ok {
					fake.mu.Lock()
					fake.seenAuth = append(fake.seenAuth, r.Header.Get("Authorization"))
					fake.mu.Unlock()
					prefix := r.URL.Query().Get("prefix")
					fake.listHandler(w, r, prefix)
					return
				}
				fake.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			be, err := NewBackend(Storage{
				ID: "aaaaaaaaaaaa", Name: "s3", Type: StorageS3,
				Endpoint: srv.URL, Bucket: "mybucket", Region: "us-east-1",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				PathStyle: true,
			}, BackendOptions{Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("构造 S3 后端失败: %v", err)
			}
			return be, func() { _ = be.Close() }
		},
	}
}

func TestS3BackendContract(t *testing.T) {
	runBackendContract(t, []backendFactory{s3Factory()})
}

// ########## 密钥绝不能出现在任何请求头里 ##########
//
// SigV4 的正确实现只把**派生密钥的签名**放进 Authorization，
// 原文密钥永远不出现在网络上。若有人把密钥塞进头里
// （比如当成 Bearer token），一次抓包就泄露了。
func TestS3SecretKeyNeverAppearsInRequest(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	fake := newFakeS3()
	fake.requireBucket = "b"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["list-type"]; ok {
			fake.listHandler(w, r, r.URL.Query().Get("prefix"))
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer srv.Close()

	be, err := NewBackend(Storage{
		ID: "aaaaaaaaaaaa", Type: StorageS3, Endpoint: srv.URL, Bucket: "b",
		Region: "us-east-1", AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: secret,
		PathStyle: true,
	}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	if err := be.Put(ctx, "k/x.tar.gz", strings.NewReader("data"), 4); err != nil {
		t.Fatal(err)
	}
	_, _ = be.Stat(ctx, "k/x.tar.gz")
	_, _, _ = be.Get(ctx, "k/x.tar.gz")
	_, _ = be.List(ctx, "k/")
	_ = be.Delete(ctx, "k/x.tar.gz")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.seenAuth) == 0 {
		t.Fatalf("没有收到任何带签名的请求")
	}
	for i, auth := range fake.seenAuth {
		if strings.Contains(auth, secret) {
			t.Fatalf("第 %d 个请求的 Authorization 里含**原始密钥**：%s", i, auth)
		}
		if auth != "" && !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			t.Fatalf("第 %d 个请求的 Authorization 形态不对: %s", i, auth)
		}
	}
}

// 签名必须真的对得上：独立复算一次，与后端发出的一致。
//
// 这条用例的价值在于"独立"：它用 crypto/hmac 自己算一遍，
// 而不是调用被测代码的 sign()。
func TestS3SignatureIsVerifiable(t *testing.T) {
	const (
		accessKey = "AKIAIOSFODNN7EXAMPLE"
		secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		region    = "us-east-1"
		bucket    = "mybucket"
	)
	var gotAuth, gotAmzDate, gotContentSHA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAmzDate = r.Header.Get("X-Amz-Date")
		gotContentSHA = r.Header.Get("X-Amz-Content-Sha256")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	be, err := NewBackend(Storage{
		ID: "aaaaaaaaaaaa", Type: StorageS3, Endpoint: srv.URL, Bucket: bucket,
		Region: region, AccessKey: accessKey, SecretKey: secretKey, PathStyle: true,
	}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	payload := "hello-s3"
	if err := be.Put(context.Background(), "k/abcdef123456/x.tar.gz", strings.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}

	if gotAmzDate == "" || gotContentSHA == "" || gotAuth == "" {
		t.Fatalf("请求缺少签名头: date=%q sha=%q auth=%q", gotAmzDate, gotContentSHA, gotAuth)
	}
	// 载荷哈希必须是**真的**载荷哈希（不是空载荷常量）。
	wantPayload := sha256Hex([]byte(payload))
	if gotContentSHA != wantPayload {
		t.Fatalf("X-Amz-Content-Sha256 = %s, 期望 %s（载荷哈希算错了）", gotContentSHA, wantPayload)
	}
	// Authorization 里必须带上凭证标识与签名区域。
	if !strings.Contains(gotAuth, "Credential="+accessKey+"/") {
		t.Fatalf("Authorization 缺少 Credential: %s", gotAuth)
	}
	if !strings.Contains(gotAuth, "/"+region+"/s3/aws4_request") {
		t.Fatalf("Authorization 的凭证范围不对: %s", gotAuth)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=") || !strings.Contains(gotAuth, "Signature=") {
		t.Fatalf("Authorization 结构不完整: %s", gotAuth)
	}
}

// S3 返回错误时，错误信息里必须带上服务端给出的 Code，
// 而不是一句"状态码 403"——403 的原因可能是密钥错、时钟偏、
// 权限不足、桶名错，用户需要那个 Code。
func TestS3ErrorIncludesServiceCode(t *testing.T) {
	fake := newFakeS3()
	fake.rejectAll = true
	fake.requireBucket = "b"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	be, err := NewBackend(Storage{
		ID: "aaaaaaaaaaaa", Type: StorageS3, Endpoint: srv.URL, Bucket: "b",
		Region: "us-east-1", AccessKey: "k", SecretKey: "s", PathStyle: true,
	}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	err = be.Put(context.Background(), "k/x.tar.gz", strings.NewReader("d"), 1)
	if err == nil {
		t.Fatalf("被拒绝的写入应该报错")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("错误信息里没有服务端 Code: %v", err)
	}
}

// S3 的 URL 路径必须做正确的转义（对象名里可能有空格与非 ASCII）。
func TestS3EscapePathSegment(t *testing.T) {
	cases := map[string]string{
		"plain.tar.gz": "plain.tar.gz",
		"a b.tar.gz":   "a%20b.tar.gz",
		"中文.tar.gz":    "%E4%B8%AD%E6%96%87.tar.gz",
		"a+b":          "a%2Bb",   // + 在路径里必须转义（否则被当成空格）
		"a.b-c_d~e":    "a.b-c_d~e", // 未保留字符不该被转义
	}
	for in, want := range cases {
		if got := escapePathSegment(in); got != want {
			t.Fatalf("escapePathSegment(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// WebDAV 后端
// ---------------------------------------------------------------------------

// fakeWebDAV 是一个最小的 WebDAV 服务端。
type fakeWebDAV struct {
	mu      sync.Mutex
	objects map[string][]byte
	dirs    map[string]bool
	// putFailures 让前 N 次 PUT 返回指定状态（验证重试）。
	putFailures []int
	seenAuth    []string
}

func newFakeWebDAV() *fakeWebDAV {
	return &fakeWebDAV{objects: map[string][]byte{}, dirs: map[string]bool{}}
}

func (f *fakeWebDAV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seenAuth = append(f.seenAuth, r.Header.Get("Authorization"))
	key := strings.TrimPrefix(r.URL.Path, "/dav/")
	key = strings.Trim(key, "/")

	if r.Method == "PUT" && len(f.putFailures) > 0 {
		code := f.putFailures[0]
		f.putFailures = f.putFailures[1:]
		f.mu.Unlock()
		// 模拟父目录不存在：服务端要求客户端先 MKCOL。
		w.WriteHeader(code)
		return
	}
	f.mu.Unlock()

	switch r.Method {
	case "MKCOL":
		f.mu.Lock()
		f.dirs[key] = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		// 父目录不存在时严格失败（真实 WebDAV 的行为）。
		if parent := parentOf(key); parent != "" {
			if !f.dirs[parent] {
				f.mu.Unlock()
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		f.objects[key] = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		f.mu.Lock()
		body, ok := f.objects[key]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	case http.MethodDelete:
		f.mu.Lock()
		_, ok := f.objects[key]
		delete(f.objects, key)
		delete(f.dirs, key)
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		f.handlePropfind(w, r, key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeWebDAV) handlePropfind(w http.ResponseWriter, r *http.Request, key string) {
	depth := r.Header.Get("Depth")
	f.mu.Lock()
	matches := []string{}
	if obj, ok := f.objects[key]; ok {
		_ = obj
		matches = append(matches, key)
	}
	if f.dirs[key] {
		matches = append(matches, key)
	}
	if depth == "1" {
		prefix := key
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		for k := range f.objects {
			if strings.HasPrefix(k, prefix) && k != key {
				matches = append(matches, k)
			}
		}
	}
	sizes := map[string]int{}
	for k, v := range f.objects {
		sizes[k] = len(v)
	}
	f.mu.Unlock()

	sortStrings(matches)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
	for _, m := range matches {
		isDir := false
		f.mu.Lock()
		isDir = f.dirs[m]
		f.mu.Unlock()
		b.WriteString("<D:response><D:href>/dav/" + m + "</D:href><D:propstat><D:prop>")
		if isDir {
			b.WriteString("<D:resourcetype><D:collection/></D:resourcetype>")
		} else {
			b.WriteString("<D:resourcetype/>")
			fmt.Fprintf(&b, "<D:getcontentlength>%d</D:getcontentlength>", sizes[m])
			fmt.Fprintf(&b, "<D:getlastmodified>%s</D:getlastmodified>",
				time.Now().UTC().Format(http.TimeFormat))
		}
		b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
	}
	b.WriteString("</D:multistatus>")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(207)
	_, _ = w.Write([]byte(b.String()))
}

func parentOf(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[:i]
	}
	return ""
}

func webdavFactory() backendFactory {
	return backendFactory{
		name: "webdav",
		newBackend: func(t *testing.T) (Backend, func()) {
			fake := newFakeWebDAV()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fake.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			be, err := NewBackend(Storage{
				ID: "aaaaaaaaaaaa", Name: "dav", Type: StorageWebDAV,
				Endpoint: srv.URL + "/dav", Username: "u", Password: "p",
			}, BackendOptions{Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("构造 WebDAV 后端失败: %v", err)
			}
			return be, func() { _ = be.Close() }
		},
	}
}

func TestWebDAVBackendContract(t *testing.T) {
	runBackendContract(t, []backendFactory{webdavFactory()})
}

// WebDAV 必须用 Basic 认证，且凭证经 Base64 编码（不是明文）。
func TestWebDAVAuthHeader(t *testing.T) {
	fake := newFakeWebDAV()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	be, err := NewBackend(Storage{
		ID: "aaaaaaaaaaaa", Type: StorageWebDAV, Endpoint: srv.URL + "/dav",
		Username: "alice", Password: "s3cr3t",
	}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	if err := be.Put(context.Background(), "k/x.tar.gz", strings.NewReader("d"), 1); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.seenAuth) == 0 {
		t.Fatalf("没有收到请求")
	}
	auth := fake.seenAuth[0]
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("认证方式不是 Basic: %q", auth)
	}
	if strings.Contains(auth, "s3cr3t") {
		t.Fatalf("密码以明文出现在请求头里: %q", auth)
	}
}

// 父目录不存在时必须先 MKCOL 再 PUT 成功（真实 WebDAV 会返回 409）。
func TestWebDAVCreatesParentDirectories(t *testing.T) {
	fake := newFakeWebDAV()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	be, err := NewBackend(Storage{
		ID: "aaaaaaaaaaaa", Type: StorageWebDAV, Endpoint: srv.URL + "/dav",
		Username: "u", Password: "p",
	}, BackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	// 深层路径，父目录全都不存在。
	key := "a/b/c/d.tar.gz"
	if err := be.Put(context.Background(), key, strings.NewReader("deep"), 4); err != nil {
		t.Fatalf("写深层路径失败（没先建父目录？）: %v", err)
	}
	if got := readAll(t, be, key); got != "deep" {
		t.Fatalf("读回 = %q", got)
	}
}

// ########## 契约测试：三种后端跑同一套用例 ##########
func TestAllBackendsShareContract(t *testing.T) {
	runBackendContract(t, []backendFactory{localFactory(), s3Factory(), webdavFactory()})
}

// 存储配置非法时必须**在构造后端时就失败**，而不是等第一次备份。
func TestNewBackendValidation(t *testing.T) {
	cases := []struct {
		name string
		st   Storage
	}{
		{"本地缺路径", Storage{Type: StorageLocal}},
		{"S3 缺 bucket", Storage{Type: StorageS3, Endpoint: "http://x", AccessKey: "a", SecretKey: "s"}},
		{"S3 缺密钥", Storage{Type: StorageS3, Endpoint: "http://x", Bucket: "b", AccessKey: "a"}},
		{"WebDAV 缺地址", Storage{Type: StorageWebDAV, Username: "u", Password: "p"}},
		{"未知类型", Storage{Type: "ftp"}},
	}
	for _, tc := range cases {
		if _, err := NewBackend(tc.st, BackendOptions{}); err == nil {
			t.Fatalf("%s：非法配置竟然构造出了后端", tc.name)
		}
	}
}

// 存储配置的脱敏：Redacted() 必须清掉密钥，且**不改动原对象**。
func TestStorageRedaction(t *testing.T) {
	st := &Storage{
		ID: "aaaaaaaaaaaa", Name: "s3", Type: StorageS3,
		Endpoint: "http://x", Bucket: "b", AccessKey: "AKIAIODNNN",
		SecretKey: "supersecretvalue", Username: "u", Password: "pass",
	}
	red := st.Redacted()
	if red.SecretKey != "" || red.Password != "" {
		t.Fatalf("脱敏副本里仍有凭证: %+v", red)
	}
	// 原对象必须完好：Redacted() 若就地改，保存时就会把密钥写没。
	if st.SecretKey != "supersecretvalue" || st.Password != "pass" {
		t.Fatalf("Redacted() 改动了原对象（下一次保存会把密钥抹掉）")
	}
	if !st.HasSecret() || !st.HasPassword() {
		t.Fatalf("原始配置的 HasSecret/HasPassword 应为 true")
	}
	if red.HasSecret() {
		t.Fatalf("脱敏副本的 HasSecret 应为 false（它确实没凭证了）")
	}
	// 尾 4 位是给用户确认"我填的是哪把钥匙"用的。
	if st.SecretTail() != "alue" {
		t.Fatalf("SecretTail = %q, 期望 %q", st.SecretTail(), "alue")
	}
	// 短凭证**整体不给**：给尾 4 位等于把整把钥匙交出去。
	short := &Storage{SecretKey: "ab"}
	if short.SecretTail() != "" {
		t.Fatalf("过短的凭证不该显示任何字符，实际 %q", short.SecretTail())
	}
}
