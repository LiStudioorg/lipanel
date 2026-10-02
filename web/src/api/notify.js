// 通知渠道接口封装（阶段五 5.4.2，核心自带）。
//
// 约定与其它 api 模块一致。凭证安全由后端保证（只返回脱敏视图），
// 前端绝不在本地长存 webhook/token 明文 —— 编辑表单里空串=不改动。
import { ApiError } from '@/api/client'

const TIMEOUT_MS = 30000

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

function postJSON(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

// 渠道列表（脱敏视图）。
export function listChannels() {
  return request('/api/notify')
}

// 各渠道能力声明。
export function fetchCapabilities() {
  return request('/api/notify/capabilities')
}

// 新建渠道。payload 含明文凭证（创建时必填）。
export function createChannel(payload) {
  return postJSON('/api/notify', payload)
}

// 编辑渠道。密文字段空串 = 不改动。
export function updateChannel(id, payload) {
  return request(`/api/notify/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

// 删除渠道。
export function deleteChannel(id) {
  return request(`/api/notify/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// 测试发送。channel 为空串表示对全部启用渠道发送。
export function testChannel(channelId = '') {
  const qs = channelId ? `?channel=${encodeURIComponent(channelId)}` : ''
  return postJSON(`/api/notify/test${qs}`, {})
}