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

// ---------- 审计接口（阶段三 3.3） ----------

// 获取全局审计记录。options 支持 { plugin, outcome, limit }。
//
// 审计页是排查工具：它自己必须尽量不失败。因此这里对参数做宽容处理
// （后端也会回落默认值），失败时由调用方展示错误并保留上一次的数据。
export function fetchAuditLog({ plugin = '', outcome = '', limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (plugin) params.set('plugin', plugin)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/plugins/audit${query ? `?${query}` : ''}`)
}

// 获取单个插件的审计记录。
export function fetchPluginAudit(id, { outcome = '', limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/plugins/${encodeURIComponent(id)}/audit${query ? `?${query}` : ''}`)
}

// 获取单个插件声明并已被核心接受的权限清单。
export function fetchPluginPermissions(id) {
  return request(`/api/plugins/${encodeURIComponent(id)}/permissions`)
}

// ---------- 沙箱桥接专用（阶段三 3.3） ----------

// callPluginRaw 是给 sandbox iframe 桥用的「不抛异常」版本。
//
// 与 callPlugin 的区别（这个区别很关键）：
//   · callPlugin 失败时 throw ApiError —— 适合宿主自己的代码（用 try/catch 处理）；
//   · callPluginRaw 失败时返回 {status, body} —— 适合桥接，因为插件前端
//     需要看到**状态码本身**（403 要展示缺失的权限、503 要提示先启动插件），
//     而不是一个被统一成字符串的异常。
//
// 这里刻意不做任何路径校验：路径白名单由 bridge.js 的
// buildPluginAPIPath 强制（安全边界必须在宿主侧、且只有一处）。
// 本函数只负责「把请求发出去、把结果原样带回来」。
export async function callPluginRaw(path, init = {}, externalSignal = null) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PLUGIN_ACTION_TIMEOUT_MS)

  // 桥可以在组件卸载时取消请求：把外部 signal 接进来。
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else externalSignal.addEventListener('abort', () => controller.abort(), { once: true })
  }

  let resp
  try {
    resp = await fetch(path, {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      ...init,
      signal: controller.signal,
    })
  } catch (err) {
    clearTimeout(timer)
    const msg = err?.name === 'AbortError' ? '请求超时或已被取消' : `无法连接后端：${err.message}`
    return { status: 0, body: { error: msg } }
  } finally {
    clearTimeout(timer)
  }

  const text = await resp.text()
  let body = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      // 非 JSON 响应（例如反向代理返回的 HTML 错误页）：
      // 截断后原样带回去，比丢掉更能帮助排查。
      body = { error: text.slice(0, 300) }
    }
  }
  return { status: resp.status, body }
}
