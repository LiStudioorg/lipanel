// Web 终端接口封装（阶段五 5.1）。
//
// 约定与 api/client.js、api/services.js、api/files.js、api/sites.js、
// api/ssl.js、api/store.js、api/firewall.js 保持一致：带超时、
// 携带会话 Cookie、失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
//
// ########## 本模块与其它 api/*.js 的关键差异 ##########
//
// 终端有一个 **WebSocket** 端点，而它不能用 fetch 封装：
// WebSocket 的握手由浏览器自己发起（会自动带上同源 Cookie），
// 失败原因也比 HTTP 少得多（拿不到状态码与响应体）。
//
// 因此本文件只负责三条 REST 接口（status/sessions/create/close/audit），
// WebSocket 的生命周期由 TerminalView.vue 自己管理
// （见 terminalLogic.js 的 buildWSUrl 与连接状态机）。
import { ApiError } from '@/api/client'

// 读操作超时。
const TERMINAL_READ_TIMEOUT_MS = 15000
// 创建会话要 fork 一个 shell 进程，给稍长的超时。
const TERMINAL_CREATE_TIMEOUT_MS = 20000

async function request(path, { timeout = TERMINAL_READ_TIMEOUT_MS, ...init } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  let resp
  try {
    resp = await fetch(path, {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      signal: controller.signal,
      ...init,
    })
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new ApiError(`请求超时（${timeout / 1000}s）：${path}`, { cause: err })
    }
    throw new ApiError(`无法连接后端：${err.message}`, { cause: err })
  } finally {
    clearTimeout(timer)
  }

  let payload = null
  const text = await resp.text()
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (!resp.ok) {
    const msg = payload?.error || text?.slice(0, 200) || `HTTP ${resp.status}`
    // 把后端给出的结构化信息挂到错误对象上。
    //
    // ########## 终端模块为什么必须带上这些字段 ##########
    //
    // 本模块有一类**别的模块没有**的错误语义：
    //
    //   501 平台不支持 —— 这不是"操作失败"而是"环境限制"。
    //                     前端必须据此渲染 n-alert 说明页，
    //                     而不是一个红色错误框。若只拿到一句
    //                     error 文本，前端就只能一律当失败处理，
    //                     用户会以为面板坏了。
    //
    //   409 会话被占用 —— 必须告诉用户"先关掉别的终端"，
    //                     而不是让他反复点"新建"。
    //
    // payload 通过扩展属性传递（见 withPayload 的说明）。
    throw withPayload(
      new ApiError(msg, {
        status: resp.status,
        hint: payload?.hint || '',
      }),
      payload,
    )
  }

  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// withPayload 把后端的原始响应体挂到 ApiError 上。
//
// ########## 为什么不直接改 client.js 的 ApiError ##########
//
// ApiError 是所有模块共用的错误类。加一个字段看似无害，
// 但会让"所有接口都可能带 payload"这个印象扩散开——
// 而实际上只有终端模块需要它（读 supported/reason 做降级判断）。
//
// 用扩展属性把影响面限制在本模块内：其它模块完全不受影响，
// 将来若真的需要，再统一提升到 ApiError 也不迟。
function withPayload(err, payload) {
  if (payload) err.payload = payload
  return err
}

// getTerminalStatus 查询终端平台能力与会话统计。
//
// ########## 这是终端页的**第一个**请求 ##########
//
// 组件挂载时必须先调它：supported=false 时直接渲染说明页，
// **绝不去尝试建立 WebSocket**——那会让用户看到一个连接失败的红框，
// 而真正的原因（平台不支持）反而被埋起来。
export function getTerminalStatus() {
  return request('/api/terminal/status')
}

// listTerminalSessions 查询当前会话列表。
export function listTerminalSessions() {
  return request('/api/terminal/sessions')
}

// createTerminalSession 创建终端会话。
export function createTerminalSession({ cols, rows } = {}) {
  return request('/api/terminal/sessions', {
    method: 'POST',
    timeout: TERMINAL_CREATE_TIMEOUT_MS,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ cols, rows }),
  })
}

// closeTerminalSession 关闭终端会话。
//
// ########## confirm=true 是必须的 ##########
//
// 后端的关闭接口强制二次确认（不带 confirm 返回 428）。
// 这不是前端能"偷偷省掉"的一步：服务端会拦。
// 前端传它，是因为**用户已经在弹窗里确认过了**——
// 这个参数表达的是"用户确认过"，不是"前端同意"。
//
// 会话里可能正跑着长任务（apt install、rsync），
// 因此关闭是一个破坏性动作，弹窗里要写明会话 ID。
export function closeTerminalSession(sessionId) {
  const q = new URLSearchParams({ id: sessionId, confirm: 'true' })
  return request(`/api/terminal/sessions?${q.toString()}`, {
    method: 'DELETE',
  })
}

// getTerminalAudit 查询终端操作审计。
export function getTerminalAudit(params = {}) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  }
  const qs = q.toString()
  return request(`/api/terminal/audit${qs ? `?${qs}` : ''}`)
}
