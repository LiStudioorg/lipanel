// 插件系统接口封装。
//
// 约定与 api/client.js 保持一致：所有请求都带超时、携带会话 Cookie、
// 失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 插件的启动需要等核心 fork 出进程并等 socket 就绪，比普通接口慢，
// 因此单独放宽超时（后端 StartTimeout 默认 10s，这里留出余量）。
const PLUGIN_ACTION_TIMEOUT_MS = 20000

async function request(path, { timeout = 10000, ...init } = {}) {
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
    throw new ApiError(msg, { status: resp.status })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// ---------- 管理接口 ----------

// 获取插件列表（含实时状态与前端插槽元数据）。
export function fetchPlugins() {
  return request('/api/plugins')
}

// 查询单个插件状态。
export function fetchPlugin(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}`)
}

// 启动插件。后端会拉起进程并等待 socket 就绪，因此超时给得较宽。
export function startPlugin(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}/start`, {
    method: 'POST',
    timeout: PLUGIN_ACTION_TIMEOUT_MS,
  })
}

// 停止插件。
export function stopPlugin(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}/stop`, {
    method: 'POST',
    timeout: PLUGIN_ACTION_TIMEOUT_MS,
  })
}

// 重启插件。
export function restartPlugin(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}/restart`, {
    method: 'POST',
    timeout: PLUGIN_ACTION_TIMEOUT_MS,
  })
}

// 主动健康探测。
export function checkPluginHealth(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}/health`, {
    method: 'POST',
    timeout: PLUGIN_ACTION_TIMEOUT_MS,
  })
}

// ---------- 转发接口 ----------

// callPlugin 通过核心代理调用插件自身的接口。
//
// 路径形如 /api/plugins/<id>/<subPath>，由核心转发给插件进程。
// 插件未运行时后端返回 503（ApiError.status === 503），
// 调用方可据此提示「请先启动插件」。
export function callPlugin(id, subPath, { timeout = 15000, ...init } = {}) {
  const clean = String(subPath || '').replace(/^\/+/, '')
  if (!clean) {
    return Promise.reject(new ApiError('插件子路径不能为空'))
  }
  return request(`/api/plugins/${encodeURIComponent(id)}/${clean}`, { timeout, ...init })
}
