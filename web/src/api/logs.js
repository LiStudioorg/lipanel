// 日志查看接口封装（阶段五 5.4.1，核心自带）。
//
// 取值与应用层约定一致：带超时、携带会话 Cookie、失败抛 ApiError。
// 日志查询可能跑到 15s（journalctl / 大文件），因此查询给 20s。
import { ApiError } from '@/api/client'

const TIMEOUT_MS = 20000

async function request(path, { timeout = TIMEOUT_MS, ...init } = {}) {
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
    throw new ApiError(msg, { status: resp.status, hint: payload?.hint || '' })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// 列出可用日志源。
export function listSources() {
  return request('/api/logs/sources')
}

// 查询日志。opts: { source, lines, filter, level }
export function queryLogs(opts = {}) {
  const params = new URLSearchParams()
  if (opts.source) params.set('source', opts.source)
  if (opts.lines) params.set('lines', String(opts.lines))
  if (opts.filter) params.set('filter', opts.filter)
  if (opts.level) params.set('level', opts.level)
  const qs = params.toString()
  return request(`/api/logs/query${qs ? `?${qs}` : ''}`)
}

// 操作审计。
export function fetchAudit(limit = 100) {
  return request(`/api/logs/audit?limit=${limit}`)
}