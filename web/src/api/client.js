// 统一的 API 客户端。
//
// 约定：
//   - 所有请求都带超时（AbortController），避免面板卡在“转圈”状态。
//   - 会话通过 HttpOnly Cookie 传递，因此必须显式带上 credentials: 'same-origin'。
//     前端拿不到 token，也就无从被 XSS 窃取。
//   - 非 2xx 响应统一抛出 ApiError，错误信息优先取后端返回的 { error } 字段。
//   - 调用方负责 Loading 与错误提示；本模块只负责“把失败说清楚”。
const DEFAULT_TIMEOUT_MS = 10000

export class ApiError extends Error {
  constructor(message, { status = 0, cause } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.cause = cause
  }

  // 401 需要特殊处理：路由守卫与视图据此跳转登录页。
  get isUnauthorized() {
    return this.status === 401
  }
}

async function request(path, { timeout = DEFAULT_TIMEOUT_MS, ...init } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  let resp
  try {
    resp = await fetch(path, {
      headers: { Accept: 'application/json' },
      // 携带会话 Cookie（HttpOnly，JS 不可读）。
      credentials: 'same-origin',
      signal: controller.signal,
      ...init,
    })
  } catch (err) {
    // 区分“主动超时”和“网络不可达”，让提示更有指向性。
    if (err.name === 'AbortError') {
      throw new ApiError(`请求超时（${timeout / 1000}s）：${path}`, { cause: err })
    }
    throw new ApiError(`无法连接后端：${err.message}`, { cause: err })
  } finally {
    clearTimeout(timer)
  }

  // 后端错误统一返回 JSON，但代理层可能返回 HTML，因此容错解析。
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
    throw new ApiError(msg, { status: resp.status })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// 发送 JSON 请求体（POST/PUT 等）。
function postJSON(path, body, opts = {}) {
  return request(path, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body ?? {}),
    ...opts,
  })
}

// ---------- 公开接口 ----------

// 获取服务健康状态，用于首屏探活。
export function fetchHealth() {
  return request('/api/health')
}

// 登录。成功后会话由后端通过 HttpOnly Cookie 下发，前端不保存任何 token。
// redirect 会被后端清洗，非法值一律回落为 "/"。
export function login(username, password, redirect = '') {
  const query = redirect ? `?redirect=${encodeURIComponent(redirect)}` : ''
  return postJSON(`/api/login${query}`, { username, password })
}

// 登出。后端清除 Cookie；即使请求失败，前端也应清理本地状态。
export function logout() {
  return postJSON('/api/logout')
}

// ---------- 受保护接口 ----------

// 查询当前登录态，供路由守卫在刷新页面后恢复会话。
// 未登录时抛出 status=401 的 ApiError。
export function fetchCurrentUser() {
  return request('/api/auth/me')
}

// 获取系统基础信息（CPU / 内存 / 磁盘 / 系统版本）。
export function fetchSystemInfo() {
  // 该接口需要读 /proc 并做 CPU 采样，比普通接口慢，单独放宽超时。
  return request('/api/system/info', { timeout: 15000 })
}
