// SSL 证书接口封装（阶段四 4.4）。
//
// 约定与 api/client.js、api/services.js、api/files.js、api/sites.js 保持一致：
// 所有请求带超时、携带会话 Cookie、失败时抛出 ApiError，
// 由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 证书申请/续期要等 certbot 与 Let's Encrypt 完整往返
// （注册账号 → 下单 → 写挑战文件 → CA 回源验证 → 取回证书），
// 网络慢时可能超过一分钟。后端默认单次 certbot 命令 120s 超时，
// 因此这里放宽到 180s，避免前端先于后端超时而给出误导性的「请求超时」。
//
// 超时的代价在这里比别处更严重：进程被杀时 CA 那边**可能已经签发完成**，
// 配额已经消耗，而用户却看到"超时"从而重试——又消耗一次配额。
const SSL_WRITE_TIMEOUT_MS = 180000

async function request(path, { timeout = 15000, ...init } = {}) {
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
    // 把后端给出的结构化提示挂到错误对象上。
    //
    // ########## SSL 模块为什么必须带上这些字段 ##########
    //
    // 本模块有两类**别的模块没有**的错误语义，只显示一句 error
    // 会让用户做出错误的下一步动作：
    //
    //   issued        —— CA 是否已签发（配额已消耗）。
    //                    true 时必须告诉用户"不要重复申请"，
    //                    否则他会一直重试直到撞上速率限制。
    //   maybe_issued  —— 超时的情形：结果**未知**，可能已签发。
    //                    必须引导用户先查询而不是立即重试。
    //
    // 因此这两个标记必须从响应体透传到错误对象。
    throw new ApiError(msg, {
      status: resp.status,
      hint: payload?.hint,
      // rolledBack 让界面能说明"配置已自动回滚，服务未受影响"。
      rolledBack: Boolean(payload?.rolled_back),
      issued: Boolean(payload?.issued || payload?.maybe_issued),
      maybeIssued: Boolean(payload?.maybe_issued),
    })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

function sendJSON(path, body, { timeout = SSL_WRITE_TIMEOUT_MS } = {}) {
  // 不带 body 时**不要**发送空的 JSON 对象：后端对"无请求体"
  // 与"畸形请求体"的处理不同（前者等价于 force=false，后者 400）。
  // 发 `{}` 虽然也能通过，但会让"没带参数"与"显式传空"这两件事
  // 在日志里无法区分。这里直接省略 body。
  const init = { method: 'POST' }
  if (body !== undefined && body !== null) {
    init.headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    }
    init.body = JSON.stringify(body)
  }
  return request(path, { ...init, timeout })
}

// 获取所有站点的 SSL 状态。
//
// 返回 { sites, client, available, unavailable_reason, renew_days,
//        dry_run, counts, scanned_at, scheduler, audit, permissions }。
//
// available 为 false 表示无法申请证书（没装 certbot 等），
// 此时界面应展示 unavailable_reason 并禁用申请按钮，
// **但站点列表与已有证书状态仍然有效**，不该整页报错。
export function fetchSSLStatus() {
  return request('/api/ssl', { timeout: 20000 })
}

// 获取 SSL 能力探测信息。
export function fetchSSLCapabilities() {
  return request('/api/ssl/capabilities', { timeout: 20000 })
}

// 获取 SSL 操作审计。options 支持 { target, user, action, outcome, limit }。
export function fetchSSLAudit({
  target = '',
  user = '',
  action = '',
  outcome = '',
  limit = 100,
} = {}) {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (user) params.set('user', user)
  if (action) params.set('action', action)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/ssl/audit${query ? `?${query}` : ''}`)
}

// 为站点申请证书。
//
// 路径里的站点名要 encodeURIComponent：虽然后端对站点名有严格白名单
// （不允许特殊字符），前端仍应正确编码而不是依赖"名字一定安全"——
// 那会变成一处隐式的耦合，将来若放宽命名规则就会立刻出问题。
//
// force 默认 false：Let's Encrypt 对同一组域名有每周 5 次
// 重复签发的限制，无脑 force 很容易把配额打满。
export function issueCertificate(name, { force = false } = {}) {
  return sendJSON(`/api/ssl/${encodeURIComponent(name)}/issue`, { force })
}

// 为站点续期证书。
export function renewCertificate(name, { force = false } = {}) {
  return sendJSON(`/api/ssl/${encodeURIComponent(name)}/renew`, { force })
}
