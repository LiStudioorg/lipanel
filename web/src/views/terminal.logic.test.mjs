// Web 终端页纯逻辑测试（阶段五 5.1）。
//
// ########## 为什么 import 真模块而不是照抄 ##########
//
// 这是本项目第 53 号坑位的纪律：测试若把逻辑照抄一遍，
// 组件改了测试照样全绿——锁住的是副本而不是真正运行的代码。
//
// 因此这里 import 的就是 TerminalView.vue 实际使用的那份实现。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MSG_INPUT,
  MSG_RESIZE,
  MSG_PING,
  MIN_COLS,
  MAX_COLS,
  MIN_ROWS,
  MAX_ROWS,
  STATUS_LABEL,
  CLOSE_REASON_LABEL,
  CONN_IDLE,
  CONN_CONNECTING,
  CONN_OPEN,
  CONN_CLOSED,
  CONN_ERROR,
  CONN_TYPE,
  connType,
  connLabel,
  canReconnect,
  buildWSUrl,
  clampSize,
  sizeChanged,
  reconnectDelay,
  shouldRetryReconnect,
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  RECONNECT_MAX_ATTEMPTS,
  encodeInput,
  encodeResize,
  encodePing,
  describeTerminalError,
  isUnsupported,
  statusLabel,
  closeReasonLabel,
  HTTP_NOT_IMPLEMENTED,
  HTTP_UNAUTHORIZED,
  HTTP_CONFLICT,
  HTTP_SERVICE_UNAVAILABLE,
} from './terminalLogic.js'

// ---------------------------------------------------------------------------
// 与后端 protocol.go / session.go 的常量对齐
// ---------------------------------------------------------------------------

// 消息类型必须与 internal/terminal/protocol.go 完全一致。
//
// 一旦漂移（比如前端发 "stdin" 而后端只认 "input"），
// 表现为"能连上、能收到输出，但敲键盘没反应"——
// 这是最难归因的一类故障：连接看起来完全正常。
test('消息类型与后端 protocol.go 对齐', () => {
  assert.equal(MSG_INPUT, 'input')
  assert.equal(MSG_RESIZE, 'resize')
  assert.equal(MSG_PING, 'ping')
})

// 尺寸边界必须与后端 protocol.go 一致。
//
// 前端比后端宽松会导致"用户拖大窗口后敲什么都被拒绝"，
// 前端比后端严格则会让本来合法的尺寸被无谓收敛。
test('尺寸边界与后端 protocol.go 对齐', () => {
  assert.equal(MIN_COLS, 1)
  assert.equal(MAX_COLS, 1000)
  assert.equal(MIN_ROWS, 1)
  assert.equal(MAX_ROWS, 1000)
})

// 会话状态与结束原因的文案必须覆盖后端全部取值。
test('状态与结束原因的文案覆盖后端全部取值', () => {
  for (const s of ['running', 'closed', 'exited']) {
    assert.ok(STATUS_LABEL[s], `缺少状态 ${s} 的文案`)
  }
  // 与 internal/terminal/session.go 的 CloseReasonXxx 一一对应。
  for (const r of [
    'user_closed',
    'idle_timeout',
    'process_exited',
    'client_disconnected',
    'server_shutdown',
    'protocol_error',
  ]) {
    assert.ok(CLOSE_REASON_LABEL[r], `缺少结束原因 ${r} 的文案`)
  }
})

// ---------------------------------------------------------------------------
// 连接状态
// ---------------------------------------------------------------------------

test('每个连接状态都有类型与文案', () => {
  for (const s of [CONN_IDLE, CONN_CONNECTING, CONN_OPEN, CONN_CLOSED, CONN_ERROR]) {
    assert.ok(CONN_TYPE[s], `缺少状态 ${s} 的颜色映射`)
    assert.ok(connLabel(s), `缺少状态 ${s} 的文案`)
  }
})

// 已连接必须是 success（绿色）：这是"你可以开始敲命令了"的信号。
test('已连接映射为 success', () => {
  assert.equal(connType(CONN_OPEN), 'success')
})

// 连接失败必须是 error（红色），断开必须是 warning（橙色）而非红色。
//
// ########## 为什么断开不用红色 ##########
//
// 正常断开（shell 退出、用户点了关闭）不是故障。
// 用红色会让用户以为出错了，从而去做无谓的排查。
test('断开是 warning 而不是 error', () => {
  assert.equal(connType(CONN_CLOSED), 'warning')
  assert.equal(connType(CONN_ERROR), 'error')
  assert.notEqual(connType(CONN_CLOSED), connType(CONN_ERROR))
})

// 未知状态必须回退到 default，而不是抛异常或返回 undefined。
test('未知连接状态回退到 default', () => {
  assert.equal(connType('nonsense'), 'default')
  assert.equal(connLabel('nonsense'), '未知')
})

// 只有"断开/失败/未开始"时才允许重连。
//
// ########## 为什么连接中或已连接时不能重连 ##########
//
// 对同一个会话发起第二次 attach 会被服务端以 409 拒绝
// （会话不能被共享）。若按钮可用，用户点下去只会看到
// 一条"会话已被占用"的错误——而那其实是他自己造成的。
test('canReconnect 的状态判定', () => {
  assert.equal(canReconnect(CONN_IDLE), true)
  assert.equal(canReconnect(CONN_CLOSED), true)
  assert.equal(canReconnect(CONN_ERROR), true)
  assert.equal(canReconnect(CONN_OPEN), false)
  assert.equal(canReconnect(CONN_CONNECTING), false)
})

// ---------------------------------------------------------------------------
// WebSocket URL
// ---------------------------------------------------------------------------

test('http 页面生成 ws:// 地址', () => {
  const url = buildWSUrl('abc123', { protocol: 'http:', host: '127.0.0.1:8080' })
  assert.equal(url, 'ws://127.0.0.1:8080/api/terminal/ws?id=abc123')
})

// ########## https 页面必须生成 wss:// ##########
//
// 若生成 ws://，浏览器会以 Mixed Content **直接阻断**连接，
// 而错误信息只会说"连接失败"——用户完全看不出是协议问题。
test('https 页面生成 wss:// 地址', () => {
  const url = buildWSUrl('abc123', { protocol: 'https:', host: 'panel.example.com' })
  assert.equal(url, 'wss://panel.example.com/api/terminal/ws?id=abc123')
  assert.ok(url.startsWith('wss://'), 'https 页面必须用 wss://')
})

// 会话 ID 必须被 URL 编码。
test('会话 ID 被正确编码', () => {
  // base64url 含 - 与 _（不该被转义），但 + / = 必须被转义。
  const url = buildWSUrl('a+b/c=d', { protocol: 'http:', host: 'h' })
  assert.ok(url.includes('id=a%2Bb%2Fc%3Dd'), `未正确编码: ${url}`)

  // 常规 ID 保持原样（不产生无谓的转义）。
  const plain = buildWSUrl('AbC-123_x', { protocol: 'http:', host: 'h' })
  assert.ok(plain.includes('id=AbC-123_x'))
})

test('buildWSUrl 对非法输入抛错', () => {
  assert.throws(() => buildWSUrl('', { protocol: 'http:', host: 'h' }))
  assert.throws(() => buildWSUrl('id', null))
  assert.throws(() => buildWSUrl('id', { protocol: 'http:' })) // 缺 host
})

// ---------------------------------------------------------------------------
// 尺寸
// ---------------------------------------------------------------------------

test('clampSize 收敛越界值', () => {
  assert.deepEqual(clampSize(80, 24), { cols: 80, rows: 24, clamped: false })

  // 越界。
  assert.equal(clampSize(0, 24).cols, MIN_COLS)
  assert.equal(clampSize(-10, 24).cols, MIN_COLS)
  assert.equal(clampSize(99999, 24).cols, MAX_COLS)
  assert.equal(clampSize(80, 0).rows, MIN_ROWS)
  assert.equal(clampSize(80, -1).rows, MIN_ROWS)
  assert.equal(clampSize(80, 99999).rows, MAX_ROWS)

  // clamped 标志。
  assert.equal(clampSize(0, 24).clamped, true)
  assert.equal(clampSize(80, 24).clamped, false)
})

// NaN / 非数字必须回退到默认值，而不是产生 NaN 尺寸。
test('clampSize 处理非法数值', () => {
  const r = clampSize(NaN, undefined)
  assert.ok(Number.isInteger(r.cols))
  assert.ok(Number.isInteger(r.rows))
  assert.ok(r.cols >= MIN_COLS && r.cols <= MAX_COLS)
})

// 小数必须取整（PTY 的 winsize 是整数，传小数会被 JSON 序列化成浮点）。
test('clampSize 取整', () => {
  const r = clampSize(80.7, 24.2)
  assert.equal(r.cols, 80)
  assert.equal(r.rows, 24)
})

// sizeChanged 必须能识别"没变"，这是 resize 去重的基础。
//
// ########## 为什么去重很关键 ##########
//
// 拖动窗口会高频触发 resize。不去重的话，一次拖拽能发出上百条
// resize 消息，让 shell 收到上百个 SIGWINCH，
// 全屏程序（top/vim）会疯狂重绘。
test('sizeChanged 正确识别变化', () => {
  assert.equal(sizeChanged(null, { cols: 80, rows: 24 }), true)
  assert.equal(sizeChanged({ cols: 80, rows: 24 }, { cols: 80, rows: 24 }), false)
  assert.equal(sizeChanged({ cols: 80, rows: 24 }, { cols: 81, rows: 24 }), true)
  assert.equal(sizeChanged({ cols: 80, rows: 24 }, { cols: 80, rows: 25 }), true)
})

// ---------------------------------------------------------------------------
// 重连退避
// ---------------------------------------------------------------------------

test('重连退避是指数增长且封顶', () => {
  assert.equal(reconnectDelay(1), RECONNECT_BASE_MS)
  assert.equal(reconnectDelay(2), RECONNECT_BASE_MS * 2)
  assert.equal(reconnectDelay(3), RECONNECT_BASE_MS * 4)

  // 必须封顶，否则第 10 次会变成 ~8.5 分钟。
  assert.equal(reconnectDelay(10), RECONNECT_MAX_MS)
  assert.ok(reconnectDelay(99) <= RECONNECT_MAX_MS)

  // 非法输入回退到基础值，而不是 NaN。
  assert.equal(reconnectDelay(0), RECONNECT_BASE_MS)
  assert.equal(reconnectDelay(-5), RECONNECT_BASE_MS)
})

// 重连必须有次数上限。
//
// ########## 为什么要上限 ##########
//
// 会话一旦结束（shell 退出、空闲超时），重连**永远不会成功**。
// 无限重连会让用户看到一个永远在"连接中"的页面，
// 而真正该做的事是"新建一个终端"。
test('重连次数有上限', () => {
  assert.equal(shouldRetryReconnect(1), true)
  assert.equal(shouldRetryReconnect(RECONNECT_MAX_ATTEMPTS), true)
  assert.equal(shouldRetryReconnect(RECONNECT_MAX_ATTEMPTS + 1), false)
  assert.equal(shouldRetryReconnect(100), false)
})

// ---------------------------------------------------------------------------
// 消息编解码
// ---------------------------------------------------------------------------

test('encodeInput 产生后端正则解析的消息', () => {
  const msg = JSON.parse(encodeInput('ls -la\n'))
  assert.equal(msg.type, 'input')
  assert.equal(msg.data, 'ls -la\n')
})

// 输入中的特殊字符必须被正确转义（不能破坏 JSON）。
test('encodeInput 转义特殊字符', () => {
  const raw = 'echo "a\\b" && printf \'\\t\'\n'
  const msg = JSON.parse(encodeInput(raw))
  assert.equal(msg.data, raw, '往返后内容必须完全一致')
})

test('encodeResize 收敛尺寸', () => {
  const msg = JSON.parse(encodeResize(99999, 0))
  assert.equal(msg.type, 'resize')
  assert.equal(msg.cols, MAX_COLS)
  assert.equal(msg.rows, MIN_ROWS)
})

test('encodePing 格式正确', () => {
  assert.deepEqual(JSON.parse(encodePing()), { type: 'ping' })
})

// ---------------------------------------------------------------------------
// 错误处理 / 优雅降级
// ---------------------------------------------------------------------------

// ########## 501 必须被识别为"平台不支持"而不是"失败" ##########
//
// 这是 5.1 优雅降级的核心：Windows 上终端不可用，
// 但用户没有做错任何事。用 error（红色）去展示会让
// 用户以为面板坏了；用 warning 并给出解释才是对的。
test('501 被识别为平台不支持', () => {
  assert.equal(isUnsupported(HTTP_NOT_IMPLEMENTED, null), true)

  const info = describeTerminalError(
    { status: HTTP_NOT_IMPLEMENTED },
    { error: '不支持', supported: false, reason: 'Windows 没有 PTY', hint: '请用 Linux' },
  )
  assert.equal(info.level, 'warning', '平台不支持不该用 error 级别')
  assert.ok(info.title.includes('不支持'))
  assert.equal(info.detail, 'Windows 没有 PTY')
  assert.equal(info.hint, '请用 Linux')
})

// supported=false 也必须被识别（反代改写状态码时的兜底）。
test('supported=false 单独也能触发降级', () => {
  assert.equal(isUnsupported(200, { supported: false }), true)
  assert.equal(isUnsupported(200, { supported: true }), false)
})

// 401 必须提示重新登录。
test('401 提示重新登录', () => {
  const info = describeTerminalError({ status: HTTP_UNAUTHORIZED }, { error: '未登录' })
  assert.equal(info.level, 'error')
  assert.ok(info.hint.includes('登录'))
})

// 409（会话被占用/达上限）必须给出"改变状态"的建议而不是"重试"。
test('409 给出可行动建议', () => {
  const info = describeTerminalError(
    { status: HTTP_CONFLICT },
    { error: '会话已被占用' },
  )
  assert.equal(info.level, 'warning')
  assert.ok(
    info.hint.includes('关闭') || info.hint.includes('共享'),
    `409 的建议应当指向"关掉别的终端": ${info.hint}`,
  )
})

// 503 提示面板可能正在重启。
test('503 提示稍后重试', () => {
  const info = describeTerminalError({ status: HTTP_SERVICE_UNAVAILABLE }, { error: '关闭中' })
  assert.equal(info.level, 'error')
  assert.ok(info.hint.includes('稍后') || info.hint.includes('重启'))
})

// 未知错误也必须给出非空 title/detail，界面上不能出现空白提示。
test('未知错误也有可读输出', () => {
  const info = describeTerminalError(new Error('boom'), null)
  assert.ok(info.title)
  assert.ok(info.detail)
  assert.ok(info.hint)
  assert.equal(info.level, 'error')
})

// 后端给的 hint 必须优先于前端硬编码的兜底（后端的更了解上下文）。
test('优先采用后端给出的 hint', () => {
  const info = describeTerminalError(
    { status: 500 },
    { error: 'x', hint: '后端专属建议' },
  )
  assert.equal(info.hint, '后端专属建议')
})

// ---------------------------------------------------------------------------
// 文案助手
// ---------------------------------------------------------------------------

test('statusLabel / closeReasonLabel 处理未知值', () => {
  assert.equal(statusLabel('running'), '运行中')
  assert.equal(statusLabel(''), '未知')
  assert.equal(statusLabel('weird'), 'weird') // 原样返回便于排错

  assert.equal(closeReasonLabel('idle_timeout'), '空闲超时自动断开')
  assert.equal(closeReasonLabel(''), '')
  assert.equal(closeReasonLabel('weird'), 'weird')
})
