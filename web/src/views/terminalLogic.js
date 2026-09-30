// Web 终端页的纯逻辑（阶段五 5.1）。
//
// ########## 为什么逻辑要单独一个模块 ##########
//
// 这是本项目第 53 号坑位留下的纪律：前端逻辑若在测试文件里
// **照抄一遍**，组件改了测试也照样全绿——测试锁住的是副本，
// 不是真正运行的代码。
//
// 因此本文件被 TerminalView.vue 与 terminal.logic.test.mjs
// **共同 import**，测试断言的就是页面实际使用的那份实现。
//
// ########## 与后端的一致性 ##########
//
// 下面这些取值必须与 internal/terminal 完全一致，一旦漂移
// 界面就会显示出与真实情况相反的信息：
//
//	MSG_INPUT / MSG_RESIZE / MSG_PING   （protocol.go 的 MsgXxx）
//	CLOSE_REASON_LABEL                   （session.go 的 CloseReasonXxx）
//	STATUS_LABEL                         （session.go 的 StatusXxx）
//	MIN_COLS / MAX_COLS / MIN_ROWS / MAX_ROWS（protocol.go 的尺寸边界）
//
// 因此测试会逐项断言这些常量。

// ---------------------------------------------------------------------------
// 与后端 protocol.go 对齐的消息类型
// ---------------------------------------------------------------------------

export const MSG_INPUT = 'input'
export const MSG_RESIZE = 'resize'
export const MSG_PING = 'ping'

// 与后端 protocol.go 对齐的尺寸边界。
//
// 前端**也要**在发出去之前 clamp：后端会拒绝越界值（并回一条错误），
// 但让用户看到一条"cols 必须在 1~1000 之间"的错误提示，
// 远不如从源头上不产生非法值。两处都做不是冗余——
// 前端是体验，后端是边界（后端绝不能信任前端）。
export const MIN_COLS = 1
export const MAX_COLS = 1000
export const MIN_ROWS = 1
export const MAX_ROWS = 1000

export const DEFAULT_COLS = 80
export const DEFAULT_ROWS = 24

// 与后端 session.go 对齐的会话状态。
export const STATUS_RUNNING = 'running'
export const STATUS_CLOSED = 'closed'
export const STATUS_EXITED = 'exited'

export const STATUS_LABEL = {
  [STATUS_RUNNING]: '运行中',
  [STATUS_CLOSED]: '已关闭',
  [STATUS_EXITED]: '已退出',
}

export function statusLabel(status) {
  if (!status) return '未知'
  return STATUS_LABEL[status] || status
}

// 与后端 session.go 对齐的会话结束原因。
//
// ########## 为什么这些文案要写得这么细 ##########
//
// "会话结束了"对用户几乎没有信息量。他会关心的是：
//
//   · 是**我自己**关的吗？（user_closed / process_exited）
//   · 还是**面板**把它关了？（idle_timeout / server_shutdown）
//     —— 后者意味着"我以为还连着，其实早就断了"，
//        这会直接影响他对刚才操作结果的判断（比如他以为
//        命令还在跑，其实会话已经没了）。
//
// 因此每个原因都写成一句"人话"，而不是直接展示后端的枚举值。
export const CLOSE_REASON_LABEL = {
  user_closed: '已手动断开',
  idle_timeout: '空闲超时自动断开',
  process_exited: 'shell 已退出',
  client_disconnected: '连接已断开',
  server_shutdown: '面板已关闭',
  protocol_error: '协议错误',
}

export function closeReasonLabel(reason) {
  if (!reason) return ''
  return CLOSE_REASON_LABEL[reason] || reason
}

// ---------------------------------------------------------------------------
// 连接状态机
// ---------------------------------------------------------------------------

export const CONN_IDLE = 'idle'
export const CONN_CONNECTING = 'connecting'
export const CONN_OPEN = 'open'
export const CONN_CLOSED = 'closed'
export const CONN_ERROR = 'error'

export const CONN_LABEL = {
  [CONN_IDLE]: '未连接',
  [CONN_CONNECTING]: '连接中',
  [CONN_OPEN]: '已连接',
  [CONN_CLOSED]: '已断开',
  [CONN_ERROR]: '连接失败',
}

// CONN_TYPE 是每个连接状态对应的 Naive UI 标签类型（颜色）。
//
// ########## 为什么把配色也放进纯逻辑 ##########
//
// 颜色在这里不是审美问题而是**语义**问题：
//
//	open   → success（绿色）：你可以开始敲命令了
//	error  → error（红色）：出问题了，需要你看
//	closed → warning（橙色）：不是错误，但不再可用
//	idle   → default（灰色）：还没开始，无需关注
//
// 把它做成映射，测试就能断言"open 一定是绿色"这类契约；
// 散在模板的三元表达式里则完全无法测试。
export const CONN_TYPE = {
  [CONN_IDLE]: 'default',
  [CONN_CONNECTING]: 'info',
  [CONN_OPEN]: 'success',
  [CONN_CLOSED]: 'warning',
  [CONN_ERROR]: 'error',
}

export function connType(state) {
  return CONN_TYPE[state] || 'default'
}

export function connLabel(state) {
  return CONN_LABEL[state] || '未知'
}

// canReconnect 判断当前状态下"重连"按钮是否应该可用。
//
// 连接中或已连接时不该允许重连（会造成同一会话被第二次 attach，
// 被服务端以 409 拒绝，用户看到一条莫名其妙的错误）。
export function canReconnect(state) {
  return state === CONN_CLOSED || state === CONN_ERROR || state === CONN_IDLE
}

// ---------------------------------------------------------------------------
// WebSocket URL
// ---------------------------------------------------------------------------

// buildWSUrl 构造终端 WebSocket 的 URL。
//
// ########## 为什么用 location 而不是硬编码 ##########
//
// 面板可能部署在任意域名/端口，也可能在 nginx 反代之后
// （此时页面是 https://域名/，而面板监听 127.0.0.1:8080）。
// 从 location 推导能天然适配全部情况。
//
// ########## 协议必须跟着页面走（wss） ##########
//
// 若页面是 https 而 WebSocket 用 ws://，浏览器会以
// "Mixed Content" 直接阻断连接——而错误信息里只会说
// "连接失败"，用户完全看不出是协议问题。
// 因此 https → wss、http → ws 是硬性对应。
//
// ########## 会话 ID 必须编码 ##########
//
// ID 是 base64url（含 - 与 _），虽然理论上不需要转义，
// 但**不能依赖这一点**：一旦将来 ID 生成方式变了
// （比如用了标准 base64 的 + / =），不编码会让 URL 直接解析错。
// encodeURIComponent 的成本为零，收益是免疫这种变化。
export function buildWSUrl(sessionId, location) {
  if (!sessionId) {
    throw new Error('buildWSUrl: sessionId 不能为空')
  }
  if (!location || !location.host) {
    throw new Error('buildWSUrl: location 非法')
  }

  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${location.host}/api/terminal/ws?id=${encodeURIComponent(sessionId)}`
}

// ---------------------------------------------------------------------------
// 尺寸计算
// ---------------------------------------------------------------------------

// clampSize 把尺寸收敛到后端允许的区间。
//
// 返回 {cols, rows, clamped}：clamped 表示是否发生过收敛，
// 调用方据此决定是否提示（正常情况下 fit 出来的值不会越界，
// 越界说明窗口极端，值得知道）。
//
// ########## 为什么用 Number.isFinite 而不是 `|| 默认值` ##########
//
// 这是本函数第一版真的踩过的 bug（由 clampSize 的单测抓到）：
//
//	Math.floor(0) || DEFAULT_ROWS   // → 24，而不是收敛到 MIN_ROWS=1
//
// 因为 `||` 把 0 当成假值。后果是**语义完全反了**：
//
//	· 0 是"明确越界的小值"，应当被**收敛到 1**；
//	· 而 `||` 把它当成"没给值"，跳到了默认的 24。
//
// 于是用户把窗口拖到几乎为零时，终端不会变成 1 列，
// 而是**突然跳回 80x24** —— 一个看起来毫无道理的行为。
//
// 正确做法是先区分"是不是一个有效数字"，再做区间收敛：
// 非数字（NaN/undefined/null）才回退默认值，数字一律收敛。
export function clampSize(cols, rows) {
  const c = clampDimension(cols, MIN_COLS, MAX_COLS, DEFAULT_COLS)
  const r = clampDimension(rows, MIN_ROWS, MAX_ROWS, DEFAULT_ROWS)
  return { cols: c, rows: r, clamped: c !== cols || r !== rows }
}

// clampDimension 收敛单个维度。
//
// 三种输入分别处理（顺序不能颠倒）：
//
//	① 非有限数字（NaN/Infinity/undefined）→ 回退默认值
//	② 有限数字                          → 取整后收敛到 [min, max]
//
// 注意 Math.floor(0.5) === 0，因此"取整后"仍可能越界，
// 必须先取整再收敛（反过来会让 0.5 变成 1，而 0 变成 0）。
function clampDimension(value, min, max, fallback) {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, Math.floor(n)))
}

// sizeChanged 判断新尺寸是否与旧的不同（避免发无意义的 resize）。
//
// ########## 为什么必须去重 ##########
//
// 浏览器在窗口拖动时会以极高频率触发 resize 事件。
// fit() 每次都会算出一个尺寸，若每次都发一条 resize 消息，
// 一次拖拽就能产生上百条消息——而 PTY 的 Setsize 会让
// shell 收到上百个 SIGWINCH，全屏程序（top/vim）会疯狂重绘。
export function sizeChanged(prev, next) {
  if (!prev) return true
  return prev.cols !== next.cols || prev.rows !== next.rows
}

// ---------------------------------------------------------------------------
// 重连退避
// ---------------------------------------------------------------------------

// 重连退避参数（毫秒）。
export const RECONNECT_BASE_MS = 1000
export const RECONNECT_MAX_MS = 15000
export const RECONNECT_MAX_ATTEMPTS = 5

// reconnectDelay 计算第 attempt 次重连前的等待时长（指数退避）。
//
// ########## 为什么要退避 ##########
//
// 服务端挂掉时，若前端每 100ms 重试一次，会立刻产生
// 大量失败的握手请求——既刷屏服务端日志，也让浏览器
// 消耗在无效连接上。指数退避让重试逐渐稀疏，
// 同时保留"服务端恢复后能较快连上"的能力。
//
// attempt 从 1 开始。
export function reconnectDelay(attempt) {
  if (attempt < 1) return RECONNECT_BASE_MS
  const delay = RECONNECT_BASE_MS * Math.pow(2, attempt - 1)
  return Math.min(RECONNECT_MAX_MS, delay)
}

// shouldRetryReconnect 判断是否还应该继续重连。
//
// ########## 为什么要有一个上限 ##########
//
// 会话一旦结束（shell 退出、空闲超时、面板关闭），
// 重连**永远不会成功**——服务端会一直返回 404/410。
// 无限重连会让用户看到一个永远在"连接中"的页面，
// 而真正该做的事是"新建一个终端"。
//
// 因此有限次数后放弃，并明确告诉用户原因。
export function shouldRetryReconnect(attempt) {
  return attempt <= RECONNECT_MAX_ATTEMPTS
}

// ---------------------------------------------------------------------------
// 消息编解码
// ---------------------------------------------------------------------------

// encodeInput 构造一条输入消息（与后端 protocol.go 的 ClientMessage 对齐）。
export function encodeInput(data) {
  return JSON.stringify({ type: MSG_INPUT, data })
}

// encodeResize 构造一条尺寸变更消息。
export function encodeResize(cols, rows) {
  const size = clampSize(cols, rows)
  return JSON.stringify({ type: MSG_RESIZE, cols: size.cols, rows: size.rows })
}

// encodePing 构造一条心跳消息。
//
// ########## 心跳的作用 ##########
//
// 后端的空闲超时会断开"30 分钟内没有任何活动"的会话。
// 但用户可能正盯着一个静止的输出（比如 tail -f 没有新行，
// 或一个等待输入的程序）。此时只要浏览器还开着，
// 语义上就是"这个人在看终端"，不应该被判为空闲。
//
// 因此前端持续发心跳来刷新后端的计时器。
export function encodePing() {
  return JSON.stringify({ type: MSG_PING })
}

// 心跳间隔（毫秒）。
//
// 取 30 秒：远小于后端默认的 30 分钟超时（即使后端被配成
// 1 分钟也能兜住），同时对一个打开的页面来说开销可忽略。
export const PING_INTERVAL_MS = 30000

// ---------------------------------------------------------------------------
// 错误处理 / 优雅降级
// ---------------------------------------------------------------------------

// 后端返回的"平台不支持"状态码（与 internal/server/terminal_api.go 对齐）。
export const HTTP_NOT_IMPLEMENTED = 501
export const HTTP_UNAUTHORIZED = 401
export const HTTP_CONFLICT = 409
export const HTTP_SERVICE_UNAVAILABLE = 503

// describeTerminalError 把接口错误翻译成"给用户看的话"。
//
// ########## 为什么不能直接展示后端的 error 字段 ##########
//
// 后端的错误是**面向排查**的（含技术细节），而用户需要的是
// "发生了什么 + 我该怎么办"。例如：
//
//	后端: "terminal: 当前平台不支持 Web 终端。Windows 没有 POSIX 伪终端…"
//	界面: 直接展示上面这句太长，且没有突出"你还能做什么"
//
// 因此这里把它拆成 {title, detail, hint, level}：
// 标题一句话说清，detail 给愿意看的人，hint 给"怎么办"。
//
// ########## level 决定用什么颜色的提示 ##########
//
// 平台不支持不是"错误"（用户没做错任何事），应当用 info/warning；
// 而连接失败是真的出错了，用 error。用红色去糊一个
// "你的系统不支持"会让用户以为面板坏了。
export function describeTerminalError(err, payload) {
  const status = err?.status || payload?.status || 0
  const message = payload?.error || err?.message || '未知错误'
  const hint = payload?.hint || err?.hint || ''

  // ① 平台不支持 —— 环境限制，不是用户的操作错误。
  if (status === HTTP_NOT_IMPLEMENTED || payload?.supported === false) {
    return {
      level: 'warning',
      title: '当前系统不支持 Web 终端',
      detail: payload?.reason || message,
      hint: hint || 'Web 终端依赖伪终端（PTY），这是类 Unix 系统的内核能力。' +
        '在 Windows 上请改用 SSH 客户端连接服务器。',
    }
  }

  // ② 未登录 / 会话过期 —— 需要重新登录。
  if (status === HTTP_UNAUTHORIZED || err?.isUnauthorized) {
    return {
      level: 'error',
      title: '登录已过期',
      detail: message,
      hint: '请重新登录后再使用终端。',
    }
  }

  // ③ 会话被占用或已达上限 —— 重试无用，必须改变状态。
  if (status === HTTP_CONFLICT) {
    return {
      level: 'warning',
      title: '无法建立终端',
      detail: message,
      hint: hint || '会话不能被共享（两个输入源会让命令交错）。' +
        '请先关闭不用的终端，或在别的标签页里继续使用已有会话。',
    }
  }

  // ④ 服务不可用 —— 面板可能正在关闭。
  if (status === HTTP_SERVICE_UNAVAILABLE) {
    return {
      level: 'error',
      title: '终端服务不可用',
      detail: message,
      hint: hint || '面板可能正在重启，请稍后重试。其它功能不受影响。',
    }
  }

  // ⑤ 其它 —— 如实展示，但补上"怎么办"。
  return {
    level: 'error',
    title: '终端连接失败',
    detail: message,
    hint: hint || '请检查面板日志；若持续失败，可尝试刷新页面后新建一个终端。',
  }
}

// isUnsupported 判断某个响应是否表示"平台不支持"。
//
// 单独一个函数而不是在组件里写 `status === 501`：
// 判据可能同时来自 status 与 body（反向代理可能改写状态码），
// 集中一处才能保证两处判断不会漂移。
export function isUnsupported(status, payload) {
  if (status === HTTP_NOT_IMPLEMENTED) return true
  return payload?.supported === false
}
