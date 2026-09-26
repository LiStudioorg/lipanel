// 服务管理接口封装（阶段四 4.1）。
//
// 约定与 api/client.js、api/plugins.js 保持一致：所有请求带超时、
// 携带会话 Cookie、失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 服务启停要等 systemctl 真正完成，可能较慢（后端默认每次调用 60s 超时），
// 因此这里放宽到 90s，避免前端先于后端超时而给出误导性的「请求超时」。
const SERVICE_ACTION_TIMEOUT_MS = 90000

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
    // 服务管理里「权限不足」「服务不存在」都靠它才能给出可操作的提示，
    // 只显示一句 error 用户仍然不知道下一步做什么。
    throw new ApiError(msg, { status: resp.status, hint: payload?.hint })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// 获取服务列表。
//
// 返回 { services, total, running, available, unavailable_reason, audit, permissions }。
// available 为 false 表示系统没有 systemd（容器/Alpine/WSL1），
// 此时界面应展示 unavailable_reason 并禁用操作按钮，而不是报错。
export function fetchServices() {
  return request('/api/services', { timeout: 20000 })
}

// 服务操作：start / stop / restart。
//
// 统一走一个函数而不是写三个：它们的行为、超时与错误处理完全一致，
// 写三份只会让「将来改超时忘了改另一处」这类问题出现。
export function serviceAction(name, action) {
  if (!['start', 'stop', 'restart'].includes(action)) {
    return Promise.reject(new ApiError(`不支持的服务操作: ${action}`))
  }
  return request(`/api/services/${encodeURIComponent(name)}/${action}`, {
    method: 'POST',
    timeout: SERVICE_ACTION_TIMEOUT_MS,
  })
}

// 获取服务操作审计记录。options 支持 { target, user, outcome, limit }。
export function fetchServiceAudit({ target = '', user = '', outcome = '', limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (user) params.set('user', user)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/services/audit${query ? `?${query}` : ''}`)
}
