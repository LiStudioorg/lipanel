package terminal

import (
	"net"
	"time"
)

// ============================================================================
// 测试用的内存连接（阶段五 5.1）
// ============================================================================
//
// 测试需要给会话一个"看起来像 WebSocket 连接"的对端。
// 用 net.Pipe（同步内存管道）而不是真实 TCP，原因有三：
//
//  1. **不占端口**：测试并发跑时不会因为端口冲突而随机失败。
//  2. **不碰网络栈**：即使机器上没有回环网络（CI 容器的某些配置）
//     测试依然可跑。
//  3. **能精确模拟断开**：关掉一端立即让另一端读到 io.EOF/ErrClosedPipe，
//     不需要等待 TCP 的超时（真实 TCP 断开检测要几秒）。

// pipePeer 是 net.Pipe 的客户端一侧。
//
// 单独包一层类型而不是直接用 net.Conn：让测试代码里
// "这是对端"的意图显式，且便于将来加断言辅助方法。
type pipePeer struct {
	net.Conn
}

// Close 关闭对端。
func (p *pipePeer) Close() error { return p.Conn.Close() }

// newPipePair 返回一对相连的内存连接。
//
// 返回的 server 一侧用于构造 wsConn（模拟服务端），
// client 一侧用于测试读取服务端发出的帧。
//
// ########## 为什么两端都要设 deadline ##########
//
// net.Pipe 是**无缓冲同步**的：写方会阻塞直到读方读走。
// 若测试用例里有一端提前退出（比如断言失败 t.Fatal），
// 另一端会永久阻塞在 Write 上，导致整个测试进程卡死
// （而不是干净地失败）。给两端设一个宽松的 deadline
// 让它们最终会报错退出，保证测试一定能结束。
func newPipePair() (server net.Conn, client *pipePeer) {
	s, c := net.Pipe()

	// 30 秒足够任何单条断言，但足以避免永久挂死。
	deadline := time.Now().Add(30 * time.Second)
	_ = s.SetDeadline(deadline)
	_ = c.SetDeadline(deadline)

	return s, &pipePeer{Conn: c}
}
