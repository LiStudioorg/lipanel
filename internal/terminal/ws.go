// Package terminal 提供核心自带的 Web 终端（阶段五 5.1）。
//
// 本文件实现一个**最小可用的 WebSocket 服务端**（RFC 6455）。
//
// #################### 为什么手写而不用第三方库 ####################
//
// 需求只用到 WebSocket 的一个很小的子集：
//
//	· 服务端接收客户端的**文本帧**（键盘输入、resize 控制消息）
//	· 服务端发送**文本帧**（终端输出）
//	· close / ping / pong 的处理
//
// 而引入成熟库（gorilla/websocket、golang.org/x/net/websocket）的代价是：
//
//  1. 实测 golang.org/x/net 会把本项目已锁定的 golang.org/x/crypto
//     从 v0.40.0 **降级**到 v0.39.0——那是登录鉴权模块的依赖，
//     为一个终端功能去动登录模块的依赖是明确的坏交易。
//  2. 本项目从 4.1 起就保持「零新增依赖」，go.mod 长期只有 jwt 与 x/crypto。
//     引入一个只用了 10% 功能的库，换来的是长期的升级/漏洞跟进成本。
//
// 手写的代价是这 400 行代码必须自己正确。因此本文件：
//
//	· 所有解析都做**边界与长度校验**（畸形帧一律返回错误，绝不 panic）
//	· 所有长度上限都有常量（见 maxPayloadBytes），防内存耗尽
//	· 帧编解码是纯函数，可被 ws_test.go 穷举测试
package terminal

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 协议常量
// ============================================================================

// wsGUID 是 RFC 6455 规定的握手魔术字符串（第 4.2.2 节）。
//
// 服务端把客户端的 Sec-WebSocket-Key 拼上这个 GUID 做 SHA-1，
// 再 base64，得到 Sec-WebSocket-Accept。它不是加密，只是
// 「对面真的懂 WebSocket 协议」的证明——因此这里用 SHA-1 是
// **协议规定**，与「SHA-1 已经不安全」无关，不存在选型问题。
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket 操作码（opcode）。
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	OpClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// 帧长度编码的分界值。
const (
	// len7Max 是 7 位长度字段能表示的最大值。
	len7Max = 125
	// len16Marker 表示后续 2 字节为长度（网络序）。
	len16Marker = 126
	// len64Marker 表示后续 8 字节为长度（网络序）。
	len64Marker = 127
	// maxPayloadBytes 是单帧载荷上限。
	//
	// ########## 为什么必须有这个上限 ##########
	//
	// 帧头里的长度字段是**对端声明的**，最大可到 2^63-1。
	// 若直接按声明长度 make([]byte, n)，一个恶意的 10 字节帧头
	// 就能让服务端尝试分配 8 EB 内存——这是最经典的
	// WebSocket 服务端 DoS 手法。
	//
	// 终端场景的真实需求极小：键盘输入几字节，
	// 粘贴一大段文本也就几 KB。4 MB 已极宽松。
	maxPayloadBytes = 4 << 20
)

// 会话关闭码（RFC 6455 第 7.4.1 节）。
const (
	// closeNormal 正常关闭。
	closeNormal = 1000
	// closeGoingAway 服务端即将关闭。
	closeGoingAway = 1001
	// closeProtocolError 协议错误（畸形帧）。
	closeProtocolError = 1002
	// closePolicyViolation 违反策略（如 Origin 校验失败、会话被占用）。
	closePolicyViolation = 1008
	// closeInternalError 服务端内部错误。
	closeInternalError = 1011
)

// 握手相关的 HTTP 头名。
const (
	headerUpgrade    = "Upgrade"
	headerConnection = "Connection"
	headerWSKey      = "Sec-WebSocket-Key"
	headerWSVersion  = "Sec-WebSocket-Version"
	headerWSAccept   = "Sec-WebSocket-Accept"
	headerWSProtocol = "Sec-WebSocket-Protocol"
)

// ErrNotWebSocket 表示该请求不是一个合法的 WebSocket 升级请求。
var ErrNotWebSocket = errors.New("terminal: 不是合法的 WebSocket 升级请求")

// wsVersionSupported 是 RFC 6455 唯一的标准版本号。
const wsVersionSupported = "13"

// ============================================================================
// 握手（纯函数部分，可单测）
// ============================================================================

// AcceptKey 由客户端的 Sec-WebSocket-Key 计算 Sec-WebSocket-Accept。
//
// 纯函数，无副作用：握手正确性是安全边界的一部分
// （算错会导致所有浏览器都连不上，或者接受了伪造的握手）。
func AcceptKey(clientKey string) string {
	h := sha1.New()
	// 按 RFC 6455：key + GUID，SHA-1，再 base64。
	_, _ = io.WriteString(h, clientKey)
	_, _ = io.WriteString(h, wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CheckUpgrade 校验一个 HTTP 请求是否是合法的 WebSocket 升级请求。
//
// 返回 nil 表示可以升级；否则返回可直接展示给调用方的错误。
//
// ########## 为什么要自己校验而不是"看见 Upgrade 头就升级" ##########
//
// 宽松的握手是对外暴露的**解析面**：一个随便带 Upgrade: websocket
// 的普通请求若被当成 WebSocket 处理，会在后续帧解析上产生
// 难以预期的行为。RFC 要求的三项校验（Upgrade / Connection /
// Version）加上 Key 的格式校验，成本几乎为零，却能保证
// 进入帧解析阶段的连接**一定是**按协议说话的。
func CheckUpgrade(r *http.Request) error {
	if r.Method != http.MethodGet {
		return fmt.Errorf("%w: 方法必须是 GET，实际 %s", ErrNotWebSocket, r.Method)
	}

	// Connection 头是**逗号分隔的列表**，且大小写不敏感。
	// 直接比较 "Upgrade" 会漏掉 "keep-alive, Upgrade" 这种合法写法——
	// 而 nginx 反代后正是这种形态（见 4.3 的 WebSocket 透传配置）。
	if !headerContainsToken(r.Header.Get(headerConnection), "upgrade") {
		return fmt.Errorf("%w: Connection 头未包含 upgrade", ErrNotWebSocket)
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get(headerUpgrade)), "websocket") {
		return fmt.Errorf("%w: Upgrade 头必须是 websocket", ErrNotWebSocket)
	}

	key := strings.TrimSpace(r.Header.Get(headerWSKey))
	if key == "" {
		return fmt.Errorf("%w: 缺少 Sec-WebSocket-Key", ErrNotWebSocket)
	}
	// Key 必须是 16 字节的 base64（24 字符含 padding）。
	// 校验长度能挡住"把随机字符串当 key"的畸形客户端，
	// 也保证 AcceptKey 的输入是一个规整的值。
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		return fmt.Errorf("%w: Sec-WebSocket-Key 格式非法", ErrNotWebSocket)
	}

	if v := strings.TrimSpace(r.Header.Get(headerWSVersion)); v != wsVersionSupported {
		return fmt.Errorf("%w: 仅支持 Sec-WebSocket-Version %s，实际 %q",
			ErrNotWebSocket, wsVersionSupported, v)
	}
	return nil
}

// headerContainsToken 判断逗号分隔的头部列表中是否含某 token（大小写不敏感）。
func headerContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// ============================================================================
// 帧（纯函数编解码）
// ============================================================================

// frame 是一个已解析的 WebSocket 帧。
type frame struct {
	// Fin 表示这是消息的最后一帧。
	Fin bool
	// Opcode 见 opText / OpClose / opPing / opPong 等。
	Opcode byte
	// Payload 是解码后的载荷（已脱去掩码）。
	Payload []byte
}

// ErrFrameTooLarge 表示帧声明的长度超过 maxPayloadBytes。
var ErrFrameTooLarge = errors.New("terminal: WebSocket 帧过大")

// writeFrame 把载荷编码为**服务端发出的帧**并写入 w。
//
// ########## 服务端帧为什么绝不加掩码 ##########
//
// RFC 6455 第 5.3 节规定：客户端→服务端**必须**掩码，
// 服务端→客户端**必须不**掩码。服务端若给帧加了掩码，
// 浏览器会直接以协议错误断开（1002）——连接表现为
// "握手成功但立刻断开"，且没有任何可读的报错，
// 排查成本极高。因此这里在类型上就固定 mask=false，
// 不存在"传参传错"的可能。
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	if len(payload) > maxPayloadBytes {
		return ErrFrameTooLarge
	}

	// 帧头最多 2 + 8 字节（服务端不加掩码，无 4 字节 mask key）。
	header := make([]byte, 0, 10)
	header = append(header, 0x80|opcode) // FIN=1 + opcode

	n := len(payload)
	switch {
	case n <= len7Max:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, len16Marker, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(n))
	default:
		header = append(header, len64Marker, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(n))
	}

	// 一次 Write 写出帧头+载荷，避免 Nagle 造成的分片延迟。
	// 先尝试合并成一次写（终端输出的延迟直接影响体感）。
	buf := make([]byte, 0, len(header)+len(payload))
	buf = append(buf, header...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// WriteText 发送一个文本帧（终端输出走这里）。
func WriteText(w io.Writer, payload []byte) error {
	return writeFrame(w, opText, payload)
}

// WriteClose 发送关闭帧（带标准状态码）。
func WriteClose(w io.Writer, code uint16, reason string) error {
	payload := make([]byte, 0, 2+len(reason))
	payload = append(payload, byte(code>>8), byte(code))
	// 关闭原因必须是合法 UTF-8 且 ≤123 字节，这里做截断保护。
	if reason != "" {
		if len(reason) > 123 {
			reason = reason[:123]
		}
		payload = append(payload, reason...)
	}
	return writeFrame(w, OpClose, payload)
}

// readFrame 从 r 读取并解析一个帧。
//
// ########## 客户端帧必须掩码 ##########
//
// 与写方向相反，读方向**必须要求**掩码位为 1。
// 不校验的话就接受了一个不合规的客户端；更重要的是，
// 掩码是 RFC 用来防止"中间代理缓存污染"的机制，
// 放行无掩码帧等于放弃这层保护。
func readFrame(r *bufio.Reader) (frame, error) {
	var f frame

	// --- 前两字节 ---
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return f, err
	}

	f.Fin = head[0]&0x80 != 0
	// RSV1/2/3 必须为 0（本实现不支持扩展）。
	// 非 0 说明对端在用一个我们没协商过的扩展，继续解析会读出垃圾。
	if head[0]&0x70 != 0 {
		return f, errors.New("terminal: 帧的 RSV 位非零（不支持的扩展）")
	}
	f.Opcode = head[0] & 0x0F

	masked := head[1]&0x80 != 0
	if !masked {
		return f, errors.New("terminal: 客户端帧必须携带掩码")
	}

	// --- 长度 ---
	length := uint64(head[1] & 0x7F)
	switch length {
	case len16Marker:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case len64Marker:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		// 最高位必须为 0（RFC 要求），且这里**先校验再转换**，
		// 避免 uint64 → int 溢出成负数。
		if length&(1<<63) != 0 {
			return f, errors.New("terminal: 帧长度最高位非法")
		}
	}

	// 长度校验必须在**分配内存之前**。
	if length > maxPayloadBytes {
		return f, ErrFrameTooLarge
	}

	// --- 掩码 key ---
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return f, err
	}

	// --- 载荷 ---
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return f, err
	}
	// 就地解掩码：payload[i] ^= mask[i%4]。
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	f.Payload = payload
	return f, nil
}

// ============================================================================
// 连接
// ============================================================================

// wsConn 封装一个已升级的 WebSocket 连接。
//
// 并发约定（关键）：
//
//	读：**只允许一个** goroutine 调 ReadMessage（由会话的读泵独占）。
//	写：**允许多个** goroutine 调 WriteText/WriteClose，由 writeMu 串行化。
//
// 之所以写方向要加锁：终端输出来自 PTY 读泵，而
// ping/pong、超时关闭通知来自另外的 goroutine。
// 两个 goroutine 同时写一个 TCP 连接会让帧字节交错，
// 对端直接协议错误断开——这是必须由本类型兜住的，
// 不能指望调用方自觉。
type Conn struct {
	conn     net.Conn
	rw       *bufio.Reader
	writeMu  sync.Mutex
	closed   bool
	closedMu sync.Mutex
}

// Upgrade 把 HTTP 请求升级为 WebSocket 连接。
//
// 调用方必须**先完成鉴权**（RequireAuth）与 Origin 校验，
// 再调用本函数：一旦写出 101，HTTP 语义就结束了，
// 之后再想返回 401/403 已经不可能（浏览器已经把它当 WS 连接）。
//
// 这一点在 terminal_api.go 里的顺序是安全关键，
// 那里有对应的注释与测试锁死。
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if err := CheckUpgrade(r); err != nil {
		return nil, err
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("terminal: ResponseWriter 不支持 Hijack，无法升级为 WebSocket")
	}

	// Hijack 必须在写任何响应之前调用。
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("terminal: Hijack 失败: %w", err)
	}

	accept := AcceptKey(strings.TrimSpace(r.Header.Get(headerWSKey)))

	// 手工拼 101 响应。
	// 这里不能用 w.WriteHeader：连接已被 Hijack，
	// http.ResponseWriter 不再拥有它，写出的字节会丢失。
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	sb.WriteString(headerUpgrade + ": websocket\r\n")
	sb.WriteString(headerConnection + ": Upgrade\r\n")
	sb.WriteString(headerWSAccept + ": " + accept + "\r\n")
	sb.WriteString("\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("terminal: 写出握手响应失败: %w", err)
	}

	return &Conn{conn: conn, rw: rw.Reader}, nil
}

// ReadMessage 读取一条完整消息（自动拼接分片、自动处理控制帧）。
//
// 返回 opcode 与载荷。控制帧（ping/pong/close）由本函数内部处理：
//
//	ping  → 立即回 pong（RFC 要求）
//	pong  → 忽略（本实现不主动发 ping，仅作为保活响应）
//	close → 原样返回给调用方，由调用方决定收尾逻辑
//
// 这样调用方（会话读泵）只需要关心 opText 数据，
// 不必自己实现协议状态机。
func (c *Conn) ReadMessage() (byte, []byte, error) {
	var (
		msgOpcode  byte
		msgBuf     []byte
		fragmented bool
	)

	for {
		f, err := readFrame(c.rw)
		if err != nil {
			return 0, nil, err
		}

		switch f.Opcode {
		case OpClose:
			return OpClose, f.Payload, nil

		case opPing:
			// 控制帧的载荷上限是 125 字节，回显即可。
			if err := c.writeControl(opPong, f.Payload); err != nil {
				return 0, nil, err
			}
			continue

		case opPong:
			continue

		case opContinuation:
			if !fragmented {
				return 0, nil, errors.New("terminal: 收到无前置分片的续帧")
			}
			msgBuf = append(msgBuf, f.Payload...)
			if len(msgBuf) > maxPayloadBytes {
				return 0, nil, ErrFrameTooLarge
			}
			if f.Fin {
				return msgOpcode, msgBuf, nil
			}
			continue

		case opText, opBinary:
			if fragmented {
				return 0, nil, errors.New("terminal: 上一条分片消息尚未结束")
			}
			if f.Fin {
				// 常见路径：单帧完整消息。
				return f.Opcode, f.Payload, nil
			}
			fragmented = true
			msgOpcode = f.Opcode
			msgBuf = append(msgBuf, f.Payload...)
			continue

		default:
			return 0, nil, fmt.Errorf("terminal: 不支持的操作码 0x%X", f.Opcode)
		}
	}
}

// writeControl 发送控制帧（pong / close），受 writeMu 保护。
func (c *Conn) writeControl(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeFrame(c.conn, opcode, payload)
}

// WriteText 发送文本帧。多 goroutine 安全。
//
// 连接已关闭时返回 io.ErrClosedPipe 而不是 panic：
// 关闭与写出必然存在竞态（PTY 读泵正在写时用户点了断开），
// 这是必须优雅处理的正常路径，不是异常。
func (c *Conn) WriteText(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.closedMu.Lock()
	closed := c.closed
	c.closedMu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	return writeFrame(c.conn, opText, payload)
}

// WriteClose 发送关闭帧。
func (c *Conn) WriteClose(code uint16, reason string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.closedMu.Lock()
	closed := c.closed
	c.closedMu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	return WriteClose(c.conn, code, reason)
}

// Close 关闭底层 TCP 连接。
//
// 幂等：重复调用返回 nil（会话关闭与服务端关停会同时触发）。
func (c *Conn) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()
	return c.conn.Close()
}

// SetReadDeadline 设置读超时。
//
// 用于空闲超时：会话层给读操作设一个 deadline，
// 超时即认为空闲并断开。这比"循环里比对时间戳"更可靠——
// 它由内核在超时点唤醒，不依赖对方是否发数据。
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// newSessionID 生成一个不可猜测的会话 ID。
//
// ########## 为什么必须用 crypto/rand 而不是自增/时间戳 ##########
//
// 会话 ID 出现在 WebSocket URL 里（/api/terminal/ws?id=xxx）。
// 若 ID 可预测，攻击者即使没有权限，也能**猜出别人的会话 ID**
// 并尝试 attach——虽然本实现还有"会话绑定用户名"这一层，
// 但可猜测的 ID 会让这层防线成为唯一的防线。
// 用 128 位随机数让 ID 猜测在计算上不可行，是纵深防御的第一层。
func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("terminal: 生成会话 ID 失败: %w", err)
	}
	// RawURLEncoding：无 padding，可直接放进 URL 与 JSON。
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
