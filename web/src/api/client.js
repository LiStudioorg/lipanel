// 统一的 API 客户端。
//
// 约定：
//   - 所有请求都带超时（AbortController），避免面板卡在“转圈”状态。
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
}

async function request(path, { timeout = DEFAULT_TIMEOUT_MS, ...init } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  let resp
  try {
    resp = await fetch(path, {
      headers: { Accept: 'application/json' },
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

// 获取服务健康状态，用于首屏探活。
export function fetchHealth() {
  return request('/api/health')
}
