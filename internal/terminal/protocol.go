package terminal

import (
	"encoding/json"
	"fmt"
)

// ============================================================================
// 前后端消息协议（阶段五 5.1）
// ============================================================================
//
// 终端连接是**双向字节流**，但纯字节流不足以表达"调整窗口大小"
// 这类带外控制。因此协议分两层：
//
//	控制层：JSON 文本消息，形如 {"type":"resize","cols":80,"rows":24}
//	数据层：直接透传的原始字节（键盘输入 / PTY 输出）
//
// #################### 为什么数据层不用 JSON 包裹 ####################
//
// 一个看似更"整齐"的设计是把所有东西都 JSON 化：
//
//	{"type":"input","data":"bHMgLWxhCg=="}      // base64
//
// 但终端数据是**海量且高频**的（`cat` 一个大文件能在几秒内
// 产生几十 MB）。每个按键都走 base64 + JSON 解析，带来
// 三次额外拷贝与约 33% 的体积膨胀，而收益只是"协议更统一"。
//
// 因此采用的折中是：
//
//	· 客户端 → 服务端：**全部**是 JSON 控制消息。
//	  终端的键盘输入本身就是一个"输入事件"，
//	  走 {"type":"input","data":"ls\n"} 语义清晰，
//	  且输入量以人手打字速度为上限，JSON 的开销可忽略。
//
//	· 服务端 → 客户端：**裸字节**直接作为 WebSocket 文本帧发送。
//	  这是热路径（输出量大），零包装、零 base64。
//	  前端收到即 terminal.write(text)，不需要判断类型。
//
// 于是"输出"是最快的路径，而"输入"保持可扩展（将来要加
// 心跳、粘贴确认等控制消息，都只影响低频率方向）。

// 客户端 → 服务端的消息类型。
const (
	// MsgInput 是键盘输入（含粘贴内容）。
	MsgInput = "input"
	// MsgResize 是终端窗口大小变化。
	MsgResize = "resize"
	// MsgPing 是应用层心跳。
	//
	// 与 WebSocket 协议层的 ping 帧不同，这个心跳由前端 JS 主动发出，
	// 用途是**刷新服务端的空闲计时器**——用户盯着一个静止的输出看
	// （比如 tail -f 没有新行）时，连接不应该被判为空闲而断开。
	// 只要浏览器还开着，前端就持续发心跳，语义上等价于
	// "这个人在看终端"。
	MsgPing = "ping"
)

// ClientMessage 是客户端发来的控制消息。
//
// 用一个结构体承载所有类型（而不是 map 或 json.RawMessage）：
// 字段的零值语义明确，解码失败时能给出确定性的错误，
// 且**未知字段天然被忽略**，将来前端升级（发出新字段）
// 不会导致旧后端报错。
type ClientMessage struct {
	// Type 见 MsgInput / MsgResize / MsgPing。
	Type string `json:"type"`
	// Data 是 MsgInput 的载荷。
	Data string `json:"data,omitempty"`
	// Cols / Rows 是 MsgResize 的载荷（字符列数与行数）。
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
}

// 终端尺寸的合法范围。
//
// ########## 为什么必须限定上下界 ##########
//
// cols/rows 会被直接传给 pty.Setsize 写进内核的
// struct winsize（字段类型是 uint16）。若不校验：
//
//	· 负数会在大端序下回绕成 65535 这样的巨大值；
//	· 极大值会让内核按 rows×cols 计算出一张巨大的
//	  滚动缓冲区，读出的数据量远超预期。
//
// 前端被篡改（或用户手改了 JS）时，这是唯一一道防线，
// 因此放在服务端而不是只在前端 clamp。
const (
	// MinCols / MinRows 是尺寸下界。1 是内核能接受的最小合法值。
	MinCols = 1
	MinRows = 1
	// MaxCols / MaxRows 是尺寸上界。
	//
	// 取 1000：真实终端最大也就 4K 显示器下的 ~500 列。
	// 留一倍余量，同时让恶意值无法构造出巨大的 winsize。
	MaxCols = 1000
	MaxRows = 1000
)

// ErrUnknownMessageType 表示客户端发来了未知的消息类型。
var ErrUnknownMessageType = fmt.Errorf("terminal: 未知的消息类型")

// DecodeClientMessage 解析客户端消息并做**语义校验**。
//
// 校验集中在协议层而不是散落到会话里，理由与 4.6 的
// "把二次确认做成集中判定"一致：新增消息类型时不会漏校验。
//
// 返回的错误信息可以直接回给前端（都是面向人的中文描述）。
func DecodeClientMessage(raw []byte) (ClientMessage, error) {
	var msg ClientMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return msg, fmt.Errorf("terminal: 消息不是合法 JSON: %w", err)
	}

	switch msg.Type {
	case MsgInput:
		// 输入允许为空（用户可能只是敲了一个不可见字符，
		// 或前端做了一次空粘贴），不校验 Data。
		return msg, nil

	case MsgResize:
		if msg.Cols < MinCols || msg.Cols > MaxCols {
			return msg, fmt.Errorf(
				"terminal: cols 必须在 %d~%d 之间，实际 %d", MinCols, MaxCols, msg.Cols)
		}
		if msg.Rows < MinRows || msg.Rows > MaxRows {
			return msg, fmt.Errorf(
				"terminal: rows 必须在 %d~%d 之间，实际 %d", MinRows, MaxRows, msg.Rows)
		}
		return msg, nil

	case MsgPing:
		return msg, nil

	case "":
		return msg, fmt.Errorf("terminal: 消息缺少 type 字段")

	default:
		return msg, fmt.Errorf("%w: %q", ErrUnknownMessageType, msg.Type)
	}
}

// EncodeInput 构造一条输入消息（供测试与客户端使用）。
func EncodeInput(data string) []byte {
	// 忽略序列化错误：本结构体只含 string，json.Marshal 不会失败。
	b, _ := json.Marshal(ClientMessage{Type: MsgInput, Data: data})
	return b
}

// EncodeResize 构造一条尺寸变更消息（供测试与客户端使用）。
func EncodeResize(cols, rows int) []byte {
	b, _ := json.Marshal(ClientMessage{Type: MsgResize, Cols: cols, Rows: rows})
	return b
}

// EncodePing 构造一条心跳消息（供测试与客户端使用）。
func EncodePing() []byte {
	b, _ := json.Marshal(ClientMessage{Type: MsgPing})
	return b
}

// ClampSize 把尺寸收敛到合法区间。
//
// 与 DecodeClientMessage 的"拒绝非法值"不同，本函数用于
// **服务端自己产生**的初始尺寸（PTY 创建时若前端还没告诉
// 我们尺寸，就用一个默认值）。对内部值做收敛而不是报错，
// 因为这里没有"用户输入错误"需要反馈。
func ClampSize(cols, rows int) (int, int) {
	if cols < MinCols {
		cols = DefaultCols
	}
	if cols > MaxCols {
		cols = MaxCols
	}
	if rows < MinRows {
		rows = DefaultRows
	}
	if rows > MaxRows {
		rows = MaxRows
	}
	return cols, rows
}

// 默认终端尺寸（经典 80x24）。
const (
	DefaultCols = 80
	DefaultRows = 24
)
