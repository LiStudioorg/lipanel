package terminal

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// WebSocket 握手测试
// ============================================================================

// AcceptKey 必须匹配 RFC 6455 第 1.3 节的官方示例。
//
// 这个用例的价值在于：官方示例是唯一**外部权威**的期望值。
// 自己算一遍再自己断言等于什么都没验证——若 SHA-1 输入顺序
// 或 GUID 拼错，自洽的测试会全绿而所有浏览器都连不上。
func TestAcceptKeyRFCExample(t *testing.T) {
	// RFC 6455 §1.3 的示例值。
	const (
		key    = "dGhlIHNhbXBsZSBub25jZQ=="
		expect = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	)
	if got := AcceptKey(key); got != expect {
		t.Fatalf("AcceptKey(%q) = %q，期望 %q", key, got, expect)
	}
}

// AcceptKey 必须等于 SHA1(key + GUID) 的 base64（独立复算一遍）。
func TestAcceptKeyMatchesManualComputation(t *testing.T) {
	key := "x3JJHMbDL1EzLkh9GBhXDw=="
	sum := sha1.Sum([]byte(key + wsGUID))
	want := base64.StdEncoding.EncodeToString(sum[:])

	if got := AcceptKey(key); got != want {
		t.Fatalf("AcceptKey = %q，期望 %q", got, want)
	}
}

// newUpgradeRequest 构造一个合法的 WebSocket 升级请求。
func newUpgradeRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/ws?id=abc", nil)
	req.Header.Set(headerUpgrade, "websocket")
	req.Header.Set(headerConnection, "Upgrade")
	req.Header.Set(headerWSKey, "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set(headerWSVersion, "13")
	return req
}

func TestCheckUpgradeAcceptsValidRequest(t *testing.T) {
	if err := CheckUpgrade(newUpgradeRequest()); err != nil {
		t.Fatalf("合法请求被拒绝: %v", err)
	}
}

// Connection 头是逗号分隔列表，nginx 反代后常见 "keep-alive, Upgrade"。
//
// 这是真实场景：4.3 的站点配置里就为 WebSocket 做了透传。
// 若只做 EqualFold 全串比较，反代后的终端全部连不上。
func TestCheckUpgradeAcceptsConnectionList(t *testing.T) {
	req := newUpgradeRequest()
	req.Header.Set(headerConnection, "keep-alive, Upgrade")

	if err := CheckUpgrade(req); err != nil {
		t.Fatalf("逗号分隔的 Connection 头被拒绝: %v", err)
	}
}

func TestCheckUpgradeRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"方法不是 GET", func(r *http.Request) { r.Method = http.MethodPost }},
		{"缺少 Upgrade 头", func(r *http.Request) { r.Header.Del(headerUpgrade) }},
		{"Upgrade 不是 websocket", func(r *http.Request) { r.Header.Set(headerUpgrade, "h2c") }},
		{"Connection 不含 upgrade", func(r *http.Request) {
			r.Header.Set(headerConnection, "keep-alive")
		}},
		{"缺少 Key", func(r *http.Request) { r.Header.Del(headerWSKey) }},
		{"Key 不是合法 base64", func(r *http.Request) {
			r.Header.Set(headerWSKey, "!!!!not-base64!!!!")
		}},
		{"Key 解码后长度不是 16 字节", func(r *http.Request) {
			r.Header.Set(headerWSKey, base64.StdEncoding.EncodeToString([]byte("short")))
		}},
		{"版本不是 13", func(r *http.Request) { r.Header.Set(headerWSVersion, "8") }},
		{"缺少版本头", func(r *http.Request) { r.Header.Del(headerWSVersion) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newUpgradeRequest()
			tc.mutate(req)
			if err := CheckUpgrade(req); err == nil {
				t.Fatal("非法请求被接受了")
			}
		})
	}
}

// ============================================================================
// 帧编解码测试
// ============================================================================

// encodeClientFrame 按客户端规则（**必须掩码**）编码一个帧，
// 供测试模拟浏览器发来的数据。
func encodeClientFrame(t *testing.T, opcode byte, fin bool, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	buf.WriteByte(b0)

	n := len(payload)
	switch {
	case n <= len7Max:
		buf.WriteByte(0x80 | byte(n)) // mask 位 = 1
	case n <= 0xFFFF:
		buf.WriteByte(0x80 | len16Marker)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf.Write(ext[:])
	default:
		buf.WriteByte(0x80 | len64Marker)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		buf.Write(ext[:])
	}

	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	buf.Write(mask[:])

	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	buf.Write(masked)
	return buf.Bytes()
}

// 三种长度编码（7 位 / 16 位 / 64 位）都必须能正确往返。
//
// 边界值 125 与 126 是经典 off-by-one 位置：125 用 7 位编码，
// 126 必须切到 16 位编码。写错的话只有 >125 字节的粘贴内容会坏，
// 而手敲命令永远测不出来。
func TestFrameRoundTripAllLengthEncodings(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"空载荷", []byte{}},
		{"1 字节", []byte("a")},
		{"7 位编码上界 125 字节", bytes.Repeat([]byte("x"), 125)},
		{"16 位编码下界 126 字节", bytes.Repeat([]byte("y"), 126)},
		{"16 位编码上界 65535 字节", bytes.Repeat([]byte("z"), 65535)},
		{"64 位编码 65536 字节", bytes.Repeat([]byte("w"), 65536)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := encodeClientFrame(t, opText, true, tc.payload)

			f, err := readFrame(bufio.NewReader(bytes.NewReader(raw)))
			if err != nil {
				t.Fatalf("解析帧失败: %v", err)
			}
			if f.Opcode != opText {
				t.Errorf("opcode = 0x%X，期望 0x%X", f.Opcode, opText)
			}
			if !f.Fin {
				t.Error("fin 应为 true")
			}
			if !bytes.Equal(f.Payload, tc.payload) {
				t.Errorf("载荷不一致：长度 %d vs %d", len(f.Payload), len(tc.payload))
			}
		})
	}
}

// 服务端**必须**不加掩码（RFC 6455 §5.3）。
//
// 加了掩码浏览器会以 1002 断开，表现为"握手成功但立刻断开"，
// 没有任何可读报错——因此这条必须被测试锁死。
func TestWriteFrameHasNoMask(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, opText, []byte("hello")); err != nil {
		t.Fatalf("writeFrame 失败: %v", err)
	}

	raw := buf.Bytes()
	if len(raw) < 2 {
		t.Fatalf("帧太短: %d 字节", len(raw))
	}
	if raw[0] != 0x81 {
		t.Errorf("首字节 = 0x%02X，期望 0x81（FIN + text）", raw[0])
	}
	if raw[1]&0x80 != 0 {
		t.Error("服务端帧设置了掩码位，浏览器会以协议错误断开")
	}
	if raw[1] != 5 {
		t.Errorf("长度字节 = %d，期望 5", raw[1])
	}
	if got := string(raw[2:]); got != "hello" {
		t.Errorf("载荷 = %q，期望 hello", got)
	}
}

// 客户端帧缺少掩码必须被拒绝。
func TestReadFrameRejectsUnmaskedClientFrame(t *testing.T) {
	// 手工构造一个 mask 位为 0 的帧（服务端风格的帧）。
	raw := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}

	_, err := readFrame(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Fatal("无掩码的客户端帧被接受了")
	}
	if !strings.Contains(err.Error(), "掩码") {
		t.Errorf("错误信息未提及掩码: %v", err)
	}
}

// 超过上限的帧声明长度必须在**分配内存之前**被拒绝。
//
// 这是 DoS 防线：若先 make 再校验，一个 10 字节的恶意
// 帧头就能让服务端尝试分配 TB 级内存。
func TestReadFrameRejectsOversizedBeforeAllocating(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81)               // FIN + text
	buf.WriteByte(0x80 | len64Marker) // masked + 64 位长度
	var ext [8]byte
	// 声明 1 TB —— 若实现先按长度 make，这里会 OOM 而不是报错。
	binary.BigEndian.PutUint64(ext[:], 1<<40)
	buf.Write(ext[:])
	buf.Write([]byte{1, 2, 3, 4}) // mask key

	_, err := readFrame(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err == nil {
		t.Fatal("超大帧被接受了")
	}
	if !strings.Contains(err.Error(), "过大") {
		t.Errorf("错误信息未说明帧过大: %v", err)
	}
}

// 载荷恰好等于上限时应当被接受（边界正确性）。
func TestFrameAtExactLimitAccepted(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), maxPayloadBytes)
	raw := encodeClientFrame(t, opText, true, payload)

	f, err := readFrame(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("恰好到上限的帧被拒绝: %v", err)
	}
	if len(f.Payload) != maxPayloadBytes {
		t.Errorf("载荷长度 = %d，期望 %d", len(f.Payload), maxPayloadBytes)
	}
}

// RSV 位非零必须被拒绝（不支持的扩展）。
func TestReadFrameRejectsReservedBits(t *testing.T) {
	raw := encodeClientFrame(t, opText, true, []byte("hi"))
	raw[0] |= 0x40 // 置 RSV1

	if _, err := readFrame(bufio.NewReader(bytes.NewReader(raw))); err == nil {
		t.Fatal("RSV1 非零的帧被接受了")
	}
}

// 分片消息必须被正确拼接。
func TestReadMessageReassemblesFragments(t *testing.T) {
	var raw bytes.Buffer
	raw.Write(encodeClientFrame(t, opText, false, []byte("hello ")))
	raw.Write(encodeClientFrame(t, opContinuation, false, []byte("frag")))
	raw.Write(encodeClientFrame(t, opContinuation, true, []byte("mented")))

	conn := &Conn{rw: bufio.NewReader(bytes.NewReader(raw.Bytes()))}
	opcode, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("读取分片消息失败: %v", err)
	}
	if opcode != opText {
		t.Errorf("opcode = 0x%X，期望 0x%X", opcode, opText)
	}
	if string(payload) != "hello fragmented" {
		t.Errorf("拼接结果 = %q，期望 %q", payload, "hello fragmented")
	}
}

// 无前置分片的续帧必须被拒绝。
func TestReadMessageRejectsOrphanContinuation(t *testing.T) {
	raw := encodeClientFrame(t, opContinuation, true, []byte("orphan"))
	conn := &Conn{rw: bufio.NewReader(bytes.NewReader(raw))}

	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("孤儿续帧被接受了")
	}
}

// ============================================================================
// 真实 WebSocket 端到端（走 net.Pipe + 真实握手）
// ============================================================================

// TestWebSocketHandshakeOverRealHTTP 用真实 TCP 连接完成一次握手，
// 验证 Upgrade 写出的 101 响应是浏览器能接受的形态。
func TestWebSocketHandshakeOverRealHTTP(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()

		// 手工读掉客户端的请求行与头（用 http.ReadRequest）。
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			srvErr <- err
			return
		}
		if err := CheckUpgrade(req); err != nil {
			srvErr <- err
			return
		}

		// 写出与 Upgrade 相同形态的 101 响应。
		accept := AcceptKey(strings.TrimSpace(req.Header.Get(headerWSKey)))
		resp := fmt.Sprintf(
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
		if _, err := conn.Write([]byte(resp)); err != nil {
			srvErr <- err
			return
		}
		// 回一条文本帧。
		inner := &Conn{conn: conn}
		srvErr <- inner.WriteText([]byte("pong-from-server"))
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer client.Close()

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	req := fmt.Sprintf(
		"GET /api/terminal/ws?id=abc HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		ln.Addr().String(), key)
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("写出握手请求失败: %v", err)
	}

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读取握手响应失败: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("状态码 = %d，期望 101", resp.StatusCode)
	}
	// 客户端校验 Accept 是否等于自己算的值。
	wantAccept := AcceptKey(key)
	if got := resp.Header.Get(headerWSAccept); got != wantAccept {
		t.Errorf("Sec-WebSocket-Accept = %q，期望 %q", got, wantAccept)
	}

	if err := <-srvErr; err != nil {
		t.Fatalf("服务端出错: %v", err)
	}
}

// newLocalListener 起一个只监听回环的 TCP 监听器。
//
// 只绑 127.0.0.1：测试绝不对外暴露端口。
func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	return ln
}

// 已验证 writeFrame 的载荷上限保护。
func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	err := writeFrame(&buf, opText, bytes.Repeat([]byte("x"), maxPayloadBytes+1))
	if err == nil {
		t.Fatal("超大载荷被接受了")
	}
	if !errorsIs(err, ErrFrameTooLarge) {
		t.Errorf("错误 = %v，期望 ErrFrameTooLarge", err)
	}
}

// errorsIs 是本文件内的小助手，避免为一行引入 errors 包的别名混淆。
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// 写关闭帧后必须能就地产出可解析的关闭帧载荷。
func TestWriteClosePayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteClose(&buf, closeNormal, "user_closed"); err != nil {
		t.Fatalf("写关闭帧失败: %v", err)
	}

	raw := buf.Bytes()
	if raw[0] != 0x80|OpClose {
		t.Errorf("首字节 = 0x%02X，期望 0x%02X", raw[0], 0x80|OpClose)
	}
	payload := raw[2:]
	if len(payload) < 2 {
		t.Fatalf("关闭帧载荷过短: %d", len(payload))
	}
	if code := binary.BigEndian.Uint16(payload[:2]); code != closeNormal {
		t.Errorf("关闭码 = %d，期望 %d", code, closeNormal)
	}
	if reason := string(payload[2:]); reason != "user_closed" {
		t.Errorf("关闭原因 = %q，期望 user_closed", reason)
	}
}

// 关闭原因超过 123 字节必须被截断（RFC 限制控制帧载荷 ≤125，
// 减去 2 字节状态码后只剩 123）。
func TestWriteCloseTruncatesLongReason(t *testing.T) {
	var buf bytes.Buffer
	long := strings.Repeat("r", 500)
	if err := WriteClose(&buf, closeNormal, long); err != nil {
		t.Fatalf("写关闭帧失败: %v", err)
	}

	payload := buf.Bytes()[2:]
	if len(payload) > 125 {
		t.Errorf("控制帧载荷 %d 字节，超过 RFC 上限 125", len(payload))
	}
}

// 关闭后的连接写出必须返回错误而不是 panic。
//
// 关闭与写出存在必然竞态（用户点断开时 PTY 读泵正在写），
// 这是必须优雅处理的正常路径。
func TestClosedConnWriteFails(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	conn := &Conn{conn: server}
	if err := conn.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if err := conn.WriteText([]byte("x")); err == nil {
		t.Fatal("关闭后写出未报错")
	}
	if err := conn.WriteClose(closeNormal, "done"); err == nil {
		t.Fatal("关闭后写关闭帧未报错")
	}
	// 幂等：重复关闭不报错。
	if err := conn.Close(); err != nil {
		t.Errorf("重复关闭报错: %v", err)
	}
}

// 并发写出必须不产生交错的帧（writeMu 的作用）。
//
// 用 -race 跑时这个用例同时验证互斥锁的正确性。
func TestConcurrentWritesAreSerialized(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := &Conn{conn: server}

	const writers = 8
	const perWriter = 20
	done := make(chan struct{})

	// 消费端：解析所有帧，验证每帧都是完整的。
	go func() {
		defer close(done)
		br := bufio.NewReader(client)
		for i := 0; i < writers*perWriter; i++ {
			// 服务端帧无掩码，用 readFrame 的客户端变体不适用，
			// 这里手工读一个无掩码帧。
			if _, _, err := readServerFrame(br); err != nil {
				return
			}
		}
	}()

	for w := 0; w < writers; w++ {
		go func(id int) {
			for i := 0; i < perWriter; i++ {
				// 每个 writer 发一条固定长度的消息，
				// 帧交错会导致长度字段与实际不符。
				_ = conn.WriteText([]byte("0123456789"))
			}
		}(w)
	}

	<-done
}

// readServerFrame 读取一个**服务端发出的**（无掩码）帧。
func readServerFrame(r *bufio.Reader) (byte, []byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	opcode := head[0] & 0x0F
	length := int(head[1] & 0x7F)
	if length == len16Marker {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}
