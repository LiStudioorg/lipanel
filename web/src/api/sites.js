// 网站管理接口封装（阶段四 4.3）。
//
// 约定与 api/client.js、api/services.js、api/files.js 保持一致：
// 所有请求带超时、携带会话 Cookie、失败时抛出 ApiError，
// 由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 站点写操作要等后端跑完 nginx -t 与 reload，可能较慢
// （后端默认单次 nginx 命令 30s 超时，且失败时还要回滚 + 复验），
// 因此这里放宽到 90s，避免前端先于后端超时而给出误导性的「请求超时」。
const SITE_WRITE_TIMEOUT_MS = 90000

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
    // 把 hint（后端给出的「怎么办」）挂到错误对象上：
    // 站点管理里「nginx 拒绝了配置并已回滚」「权限不足」都靠它
    // 才能给出可操作的提示，只显示一句 error 用户仍然不知道下一步做什么。
    throw new ApiError(msg, {
      status: resp.status,
      hint: payload?.hint,
      // rolledBack 让界面能明确告诉用户「配置已自动回滚，服务未受影响」。
      // 这是本模块最重要的一条用户可见信息：出了错但系统是安全的。
      rolledBack: Boolean(payload?.rolled_back),
    })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

function sendJSON(path, method, body, { timeout = SITE_WRITE_TIMEOUT_MS } = {}) {
  return request(path, {
    method,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body ?? {}),
    timeout,
  })
}

// 获取站点列表。
//
// 返回 { sites, total, enabled, available, unavailable_reason, mode, audit, permissions }。
// available 为 false 表示系统没有可用的 nginx，此时界面应展示
// unavailable_reason 并禁用操作按钮，而不是报错。
export function fetchSites() {
  return request('/api/sites', { timeout: 20000 })
}

// 获取能力探测信息（nginx 可用性、配置目录、限制、类型清单）。
export function fetchSiteCapabilities() {
  return request('/api/sites/capabilities', { timeout: 20000 })
}

// 获取站点操作审计。options 支持 { target, user, action, outcome, limit }。
export function fetchSiteAudit({ target = '', user = '', action = '', outcome = '', limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (user) params.set('user', user)
  if (action) params.set('action', action)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/sites/audit${query ? `?${query}` : ''}`)
}

// 创建站点。payload 见 buildSitePayload。
export function createSite(payload) {
  return sendJSON('/api/sites', 'POST', payload)
}

// 编辑站点。
//
// 注意路径里的站点名要 encodeURIComponent：虽然后端对站点名有严格白名单
// （不允许特殊字符），前端仍应正确编码而不是依赖"名字一定安全"——
// 那会变成一处隐式的耦合，将来若放宽命名规则就会立刻出问题。
export function updateSite(name, payload) {
  return sendJSON(`/api/sites/${encodeURIComponent(name)}`, 'PUT', payload)
}

// 删除站点。
export function deleteSite(name) {
  return sendJSON(`/api/sites/${encodeURIComponent(name)}`, 'DELETE', null)
}

// 启用/禁用站点。
export function setSiteEnabled(name, enabled) {
  const action = enabled ? 'enable' : 'disable'
  return sendJSON(`/api/sites/${encodeURIComponent(name)}/${action}`, 'POST', null)
}
