// 防火墙接口封装（阶段四 4.6）。
//
// 约定与 api/client.js、api/services.js、api/files.js、api/sites.js、
// api/ssl.js、api/store.js 保持一致：带超时、携带会话 Cookie、
// 失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 防火墙写操作的超时。
//
// 后端单条命令的默认超时是 15s，且一次操作**可能执行多条命令**
// （any 协议会展开成 tcp+udp 两条，firewalld 还要额外 reload）。
// 因此前端给到 30s，避免后端还在执行时前端先报"超时"——
// 那会让用户以为操作没生效从而重复提交。
const FIREWALL_WRITE_TIMEOUT_MS = 30000
const FIREWALL_READ_TIMEOUT_MS = 15000

async function request(path, { timeout = FIREWALL_READ_TIMEOUT_MS, ...init } = {}) {
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
    // ########## 防火墙模块为什么必须带上这些字段 ##########
    //
    // 本模块有三类**别的模块没有**的错误语义，只显示一句 error
    // 会让用户做出错误的下一步动作：
    //
    //   428 缺少二次确认 —— 必须引导用户走确认流程，而不是"重试"
    //   409 端口受保护   —— 必须让用户看到保护原因与 force 选项
    //   409 规则不可删   —— 必须解释"为什么这条删不掉"
    //                       （否则用户会反复点击删除按钮）
    //
    // kind 是后端给出的分类标签（"端口受保护"等），
    // hint 是后端写好的可操作建议，直接展示即可。
    const err = new ApiError(msg, {
      status: resp.status,
      hint: payload?.hint,
    })
    // kind 是后端给出的分类标签（"端口受保护"等），
    // ApiError 的构造函数不接受它，因此挂到实例上。
    // 保留它是因为 status 单独一个数字不足以区分 409 的两种含义：
    // "端口受保护" 与 "规则不可精确删除" 都返回 409，
    // 但给用户的下一步动作完全不同。
    err.kind = payload?.kind || ''
    err.confirmRequired = resp.status === 428 ||
      resp.headers?.get?.('X-Lipanel-Confirm-Required') === 'true'
    err.protectedPort = resp.status === 409 && payload?.kind === '端口受保护'
    err.notDeletable = resp.status === 409 && payload?.kind === '规则无法精确删除'
    err.permissionDenied = resp.status === 403
    err.available = payload?.available
    throw err
  }

  return payload
}

// ---------------------------------------------------------------------------
// 读操作
// ---------------------------------------------------------------------------

// fetchFirewallStatus 查询防火墙状态（后端、保护端口、审计统计、权限）。
export function fetchFirewallStatus() {
  return request('/api/firewall')
}

// fetchFirewallRules 查询规则列表。
export function fetchFirewallRules() {
  return request('/api/firewall/rules')
}

// fetchFirewallCapabilities 查询能力探测结果。
export function fetchFirewallCapabilities() {
  return request('/api/firewall/capabilities')
}

// fetchFirewallAudit 查询操作审计。
export function fetchFirewallAudit({ limit = 100, user = '', action = '', outcome = '', backend = '', systemChange = false } = {}) {
  const qs = new URLSearchParams()
  qs.set('limit', String(limit))
  if (user) qs.set('user', user)
  if (action) qs.set('action', action)
  if (outcome) qs.set('outcome', outcome)
  if (backend) qs.set('backend', backend)
  if (systemChange) qs.set('system_change', 'true')
  return request(`/api/firewall/audit?${qs.toString()}`)
}

// ---------------------------------------------------------------------------
// 写操作
// ---------------------------------------------------------------------------

// addFirewallPort 放行/拒绝端口。
export function addFirewallPort(payload) {
  return request('/api/firewall/ports', {
    method: 'POST',
    timeout: FIREWALL_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(payload),
  })
}

// deleteFirewallPort 删除端口规则。
//
// ########## confirm 必须为 true ##########
//
// 后端会强制校验：不带 confirm 一律返回 **428 Precondition Required**。
// 前端弹窗只是体验，服务端强制才是边界——所以这里即便调用方
// 忘了传，后端也不会真的删掉规则。
//
// force：受保护端口（面板自身 / SSH）需要显式强制。
// 该操作会被记入审计（Force 字段 + Forced 计数）。
export function deleteFirewallPort({ port, protocol = 'tcp', source = '', action = 'allow', confirm = false, force = false }) {
  return request('/api/firewall/ports', {
    method: 'DELETE',
    timeout: FIREWALL_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ port, protocol, source, action, confirm, force }),
  })
}

// addFirewallIP 添加 IP 黑白名单。
export function addFirewallIP(payload) {
  return request('/api/firewall/ips', {
    method: 'POST',
    timeout: FIREWALL_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(payload),
  })
}

// deleteFirewallIP 删除 IP 黑白名单条目（同样强制 confirm）。
export function deleteFirewallIP({ ip, direction = 'deny', confirm = false }) {
  return request('/api/firewall/ips', {
    method: 'DELETE',
    timeout: FIREWALL_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ ip, direction, confirm }),
  })
}
