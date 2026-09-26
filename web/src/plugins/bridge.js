// 插件前端「强隔离」协议的宿主侧实现（阶段三 3.3）。
//
// ============ 一、它在整个方案里的位置 ============
//
// 3.2 的插件前端与宿主共享 Realm（插件能读 document.cookie、能直连 /api/*）。
// 3.3 把默认方式换成 sandbox iframe + postMessage 桥：
//
//   宿主页面（有会话 Cookie、有 /api/* 直连能力）
//     └─ <iframe sandbox="allow-scripts">（opaque origin，读不到 cookie）
//          └─ 插件代码：只能渲染 + postMessage
//               ↑↓ 本文件负责这条通道
//
// **本文件是安全边界所在**。iframe 侧的 plugin-frame.js 也会做路径检查，
// 但那只是"体验"（早点报错），真正的强制必须在宿主侧：
// 客户端代码永远运行在攻击者可控的环境里，任何"客户端校验"都不算安全。
//
// ============ 二、协议 v1 ============
//
//  iframe → 宿主
//    {protocol, type:'lipanel:ready'}                          握手（可选 mounted 标记）
//    {protocol, type:'lipanel:api', id, method, path, body}    请宿主代发请求
//    {protocol, type:'lipanel:resize', height}                 内容高度
//    {protocol, type:'lipanel:notify', text, level}            请求宿主提示
//    {protocol, type:'lipanel:error', message}                 上报错误
//    {protocol, type:'lipanel:navigate', to}                   请求站内跳转
//
//  宿主 → iframe
//    {protocol, type:'lipanel:plugin-data', pluginId, plugin, entry, assets}  下发元数据
//    {protocol, type:'lipanel:api-result', id, ok, status, body, error}       代发结果
//    {protocol, type:'lipanel:measure'}                                       请求重新测量
//
// 每次 postMessage 都带 protocol 字段：宿主侧对不匹配的版本直接拒绝服务
// 并给出可读提示，而不是让插件在半坏状态下运行。
//
// ============ 三、宿主侧的强制检查（缺一不可） ============
//
//  1. **来源窗口**：event.source 必须等于该 iframe 的 contentWindow。
//     只比较 origin 是不够的——opaque origin 的序列化都是 "null"，
//     别的 sandbox iframe（甚至攻击者页面）也可能报 "null"。
//  2. **插件绑定**：每条消息只被当作「该 iframe 所代表的那个插件」的请求，
//     插件 ID 由宿主自己记录（不取自信任 iframe 的字段）。
//  3. **API 路径白名单**：只允许 /api/plugins/<自身 id>/ 前缀，
//     因此 A 插件无法借桥调用 B 插件的接口，也无法调用 /api/system/*、
//     /api/plugins（管理接口）等更敏感的核心接口。
//  4. **方法白名单**：GET/POST/PUT/DELETE/HEAD，其它一律拒绝。
//  5. **响应体大小上限**：一个失控插件不该让宿主的标签页 OOM。
//  6. **resize 值 clamp**：防止插件把 iframe 高度撑到几十万像素。
//  7. **notify 限流**：防止插件刷屏（每条都要弹 UI）。
//
// ============ 四、为什么 targetOrigin 用 '*' ============
//
// iframe 处于 opaque origin，其 origin 序列化为 "null"，无法用一个具体的
// origin 字符串去匹配（传具体 origin 会导致消息发不出去）。这不是漏洞：
//   · 载荷里只有插件本来就该看到的数据（插件元数据、它自己接口的响应）；
//   · 会话 Cookie 始终留在宿主侧，从不进入 postMessage；
//   · iframe 无法把消息转交给第三方——它处于 opaque origin，
//     发出去的消息只能由宿主窗口接收。
// 真正需要防的是"谁在给宿主发消息"，那是上面第 1 条的职责。
'use strict'

// 协议版本：与 web/plugins/plugin-assets/frame/plugin-frame.js 必须一致。
// 之所以两边各写一份常量而不是共享模块：iframe 侧代码经 Vite publicDir
// 原样分发（不打包），无法 import 宿主 src/ 下的文件。这是一处**有意接受
// 的重复**，改动时必须同步两处，否则插件前端会在握手阶段被明确拒绝
// （而不是静默坏掉，这正是版本号存在的意义）。
export const FRAME_PROTOCOL_VERSION = 1

// ---------- 消息类型 ----------
const MSG_READY = 'lipanel:ready'
const MSG_API = 'lipanel:api'
const MSG_RESIZE = 'lipanel:resize'
const MSG_NOTIFY = 'lipanel:notify'
const MSG_ERROR = 'lipanel:error'
const MSG_NAVIGATE = 'lipanel:navigate'

const MSG_PLUGIN_DATA = 'lipanel:plugin-data'
const MSG_API_RESULT = 'lipanel:api-result'
const MSG_MEASURE = 'lipanel:measure'

// ---------- 限额 ----------

// 允许的 HTTP 方法白名单。
// 刻意不含 PATCH/OPTIONS/TRACE：插件接口目前用不到，
// 白名单越短，将来出现意料外调用路径的机会越小。
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])

// 单次桥接响应的最大字节数（1 MiB）。
// 超过就拒绝并报错，而不是把宿主的标签页拖爆。
const MAX_RESPONSE_BYTES = 1 << 20

// iframe 高度的合法区间。
// 下限 120 保证插件界面不会被压成一条缝；上限 20000 保证
// 一个失控插件（例如高度算成 1e9）不会把宿主页面撑到无法操作。
const MIN_FRAME_HEIGHT = 120
const MAX_FRAME_HEIGHT = 20000

// notify 限流：窗口内最多几条。
// 插件可能在一个循环里疯狂 notify，每条都会弹一个 UI 组件。
const NOTIFY_WINDOW_MS = 10000
const NOTIFY_MAX_IN_WINDOW = 5

// API 请求超时（毫秒）。与 api/plugins.js 的转发超时保持一致。
const API_TIMEOUT_MS = 20000

/**
 * 校验并拼装插件 API 路径。
 *
 * 只接受形如 `/info`、`/files/a.txt` 的**相对本插件**的路径，
 * 最终拼成 `/api/plugins/<id>/info`。返回 null 表示拒绝。
 *
 * 为什么在这里做而不是交给调用方：这是安全边界，必须内聚，
 * 不允许调用方"忘记校验"。
 *
 * @param {string} pluginId 宿主记录的插件 ID（不来自 iframe）
 * @param {string} path iframe 请求的路径
 * @returns {string|null} 可用于 fetch 的绝对路径，或 null
 */
export function buildPluginAPIPath(pluginId, path) {
  const id = String(pluginId || '')
  const raw = String(path || '')
  if (!id || !raw) return null

  // 必须以 / 开头（拒绝 "info" 这种含糊写法，也拒绝完整 URL）。
  if (!raw.startsWith('/')) return null
  // 拒绝协议相对地址（//evil.com/x）与任何带 scheme 的地址。
  if (raw.startsWith('//')) return null
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return null
  // 拒绝空字节与换行（可能被下游解析器误处理）。
  if (/[\u0000\r\n]/.test(raw)) return null

  // 拒绝 "/api/..." 形式的路径。
  //
  // 这类路径**不会造成逃逸**（拼出来是 /api/plugins/<id>/api/system/info，
  // 仍然落在自己的命名空间里），但它是插件作者的常见误解：
  // 他以为桥接是"反向代理"，可以直接写核心接口路径。
  // 若不显式拒绝，请求会被静默转发到一个不存在的插件路由，
  // 表现为语焉不详的 404 —— 排查成本远高于在这里直接说清楚。
  if (raw === '/api' || raw.startsWith('/api/')) return null

  // 拒绝路径穿越段。虽然我们只是把它拼到前缀后面，
  // 但拼接后的结果会被后端重新解析，多校验一层成本极低。
  const segments = raw.split('/')
  for (const seg of segments) {
    if (seg === '..' || seg === '.') return null
    // 拒绝百分号编码的穿越（%2e%2e 等）：
    // 后端已做过规范化解码后的校验，这里再做一次是纵深防御。
    const lower = seg.toLowerCase()
    if (lower.includes('%2e') || lower.includes('%2f') || lower.includes('%5c')) return null
  }

  return `/api/plugins/${encodeURIComponent(id)}${raw}`
}

/**
 * 校验跳转目标。
 *
 * 只允许站内相对路径：这是防开放重定向，也是防止插件把用户
 * 骗到钓鱼页面（插件的界面是不可信的，它请求跳转时必须受限）。
 *
 * @param {string} to
 * @returns {string|null}
 */
export function safeNavigateTarget(to) {
  const target = String(to || '')
  if (!target) return null
  // 只接受以单个 / 开头的站内路径。
  if (!target.startsWith('/') || target.startsWith('//')) return null
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return null
  if (/[\u0000\r\n]/.test(target)) return null
  if (target.includes('..')) return null
  return target
}

/**
 * clamp iframe 高度到合法区间。
 *
 * @param {number} height
 * @returns {number}
 */
export function clampFrameHeight(height) {
  const h = Math.round(Number(height) || 0)
  if (!Number.isFinite(h) || h <= 0) return MIN_FRAME_HEIGHT
  return Math.min(MAX_FRAME_HEIGHT, Math.max(MIN_FRAME_HEIGHT, h))
}

/**
 * PluginFrameBridge 管理「宿主 ↔ 某个插件 iframe」这一条通道。
 *
 * 生命周期：创建 → attach(frameEl) → …消息往来… → dispose()
 * 每个插件页面实例一个 Bridge，互不共享状态（因此 A 插件的消息
 * 不可能被当成 B 插件的请求）。
 *
 * 设计要点：所有回调都通过构造参数注入，Bridge 本身不依赖 Vue，
 * 因此可以在没有 DOM 的环境里对协议逻辑做单元测试。
 */
export class PluginFrameBridge {
  /**
   * @param {object} options
   * @param {string} options.pluginId 插件 ID（宿主记录的，权威值）
   * @param {object} options.plugin 插件元数据（下发给 iframe）
   * @param {object} options.frame 插件前端声明（entry / assets）
   * @param {(path: string, init: object, signal: AbortSignal) => Promise<{status:number, body:any}>} options.request
   *        代发请求的实现。由调用方注入（通常是 api/plugins.js 的 callPluginRaw），
   *        便于测试替换。
   * @param {(message: string) => void} [options.onError] 错误上报
   * @param {(text: string, level: string) => void} [options.onNotify] 提示上报
   * @param {(height: number) => void} [options.onResize] 高度变化
   * @param {(to: string) => void} [options.onNavigate] 请求跳转
   * @param {(mounted: boolean) => void} [options.onMounted] 插件前端挂载完成
   */
  constructor(options = {}) {
    this.pluginId = String(options.pluginId || '')
    this.plugin = options.plugin || null
    this.frameInfo = options.frame || {}
    this.request = options.request
    this.onError = options.onError || (() => {})
    this.onNotify = options.onNotify || (() => {})
    this.onResize = options.onResize || (() => {})
    this.onNavigate = options.onNavigate || (() => {})
    this.onMounted = options.onMounted || (() => {})

    // frameWindow 是当前绑定 iframe 的 contentWindow。
    // 只有来自它的消息才会被处理（见 _handleMessage 的第一道检查）。
    this.frameWindow = null
    // disposed 之后不再处理任何消息：Vue 组件卸载后迟到的消息
    // 不该再去动已经销毁的组件状态。
    this.disposed = false

    // notify 限流用：窗口起点与窗口内已发送条数。
    this._notifyWindowStart = 0
    this._notifyCount = 0

    // 进行中的桥接请求，dispose 时统一 abort，
    // 避免组件卸载后还挂着一堆未结束的 fetch。
    this._inflight = new Set()

    this._listener = (event) => this._handleMessage(event)
  }

  /**
   * 绑定到具体的 iframe 元素并开始监听消息。
   * @param {HTMLIFrameElement} frameEl
   */
  attach(frameEl) {
    if (!frameEl || !frameEl.contentWindow) return
    this.frameWindow = frameEl.contentWindow
    window.addEventListener('message', this._listener)
  }

  /** 解除监听并取消所有在途请求。 */
  dispose() {
    this.disposed = true
    window.removeEventListener('message', this._listener)
    for (const controller of this._inflight) {
      try {
        controller.abort()
      } catch {
        /* 忽略：abort 失败不影响卸载 */
      }
    }
    this._inflight.clear()
    this.frameWindow = null
  }

  /**
   * 向 iframe 下发插件元数据。
   *
   * 入口地址、资源基址都在这里给：iframe 的 src 里只有一个 id，
   * 因此它无法通过伪造 URL 让自己去加载别的插件前端。
   */
  sendPluginData() {
    this._post({
      type: MSG_PLUGIN_DATA,
      pluginId: this.pluginId,
      plugin: this.plugin,
      entry: String(this.frameInfo.entry || ''),
      assets: String(this.frameInfo.assets || ''),
    })
  }

  /** 请求 iframe 重新测量并上报尺寸。 */
  requestMeasure() {
    this._post({ type: MSG_MEASURE })
  }

  /** 统一的发送出口：所有宿主 → iframe 的消息都带上协议版本。 */
  _post(payload) {
    if (this.disposed || !this.frameWindow) return
    try {
      // targetOrigin 用 '*' 的理由见文件头第四节。
      this.frameWindow.postMessage({ protocol: FRAME_PROTOCOL_VERSION, ...payload }, '*')
    } catch (err) {
      this.onError(`无法向插件沙箱发送消息：${err?.message || err}`)
    }
  }

  /** 消息入口：先做来源校验，再分发。 */
  _handleMessage(event) {
    if (this.disposed) return

    // ---- 强制检查 1：必须来自本插件 iframe 的那个窗口 ----
    // 只比 origin 不够：opaque origin 全都序列化成 "null"，
    // 别的 sandbox iframe 也会报 "null"。
    if (!this.frameWindow || event.source !== this.frameWindow) return

    const msg = event.data
    if (!msg || typeof msg !== 'object') return

    // 版本不匹配：拒绝并明确告知（不静默忽略，否则表现为"插件没反应"）。
    if (Number(msg.protocol) !== FRAME_PROTOCOL_VERSION) {
      this.onError(
        `插件沙箱协议版本不匹配：收到 ${msg.protocol}，宿主支持 ${FRAME_PROTOCOL_VERSION}。` +
          '请同步升级插件前端与主程序。',
      )
      return
    }

    switch (msg.type) {
      case MSG_READY:
        // 握手：iframe 脚本已就绪，下发元数据。
        // 每次 ready 都重发（iframe 可能因为 reload 再次握手）。
        this.sendPluginData()
        if (msg.mounted) this.onMounted(true)
        return

      case MSG_API:
        this._handleAPI(msg)
        return

      case MSG_RESIZE:
        this.onResize(clampFrameHeight(msg.height))
        return

      case MSG_NOTIFY:
        this._handleNotify(msg)
        return

      case MSG_ERROR:
        this.onError(String(msg.message || '插件沙箱报告了未知错误').slice(0, 2000))
        return

      case MSG_NAVIGATE: {
        const target = safeNavigateTarget(msg.to)
        if (!target) {
          this.onError(`插件请求跳转到不被允许的地址：${String(msg.to || '').slice(0, 200)}`)
          return
        }
        this.onNavigate(target)
        return
      }

      default:
        // 未知类型一律忽略：协议演进时不该因为"看不懂"就报错刷屏。
        return
    }
  }

  /** 处理代发请求。 */
  async _handleAPI(msg) {
    const reqId = msg.id
    if (reqId === undefined || reqId === null) return

    const method = String(msg.method || 'GET').toUpperCase()

    // ---- 强制检查 4：方法白名单 ----
    if (!ALLOWED_METHODS.has(method)) {
      this._postAPIResult(reqId, {
        ok: false,
        status: 400,
        error: `桥接不支持的方法：${method}`,
      })
      return
    }

    // ---- 强制检查 3：路径白名单（只能访问本插件自己的接口） ----
    const path = buildPluginAPIPath(this.pluginId, msg.path)
    if (!path) {
      this._postAPIResult(reqId, {
        ok: false,
        status: 400,
        error:
          `插件只能通过桥接访问自己的接口（形如 /info）。` +
          `收到的不合法路径：${String(msg.path || '').slice(0, 200)}`,
      })
      return
    }

    if (typeof this.request !== 'function') {
      this._postAPIResult(reqId, {
        ok: false,
        status: 500,
        error: '宿主未注入桥接请求实现（内部错误）',
      })
      return
    }

    const controller = new AbortController()
    this._inflight.add(controller)
    const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS)

    try {
      const init = { method, signal: controller.signal }
      if (msg.body !== undefined && msg.body !== null) {
        init.headers = { 'Content-Type': 'application/json' }
        init.body = typeof msg.body === 'string' ? msg.body : JSON.stringify(msg.body)
      }

      const resp = await this.request(path, init, controller.signal)

      // ---- 强制检查 5：响应体大小上限 ----
      const text = typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body ?? null)
      if (text && text.length > MAX_RESPONSE_BYTES) {
        this._postAPIResult(reqId, {
          ok: false,
          status: 502,
          error: `插件响应过大（超过 ${Math.round(MAX_RESPONSE_BYTES / 1024)} KiB），已拒绝传给插件前端`,
        })
        return
      }

      if (resp.status >= 200 && resp.status < 400) {
        this._postAPIResult(reqId, { ok: true, status: resp.status, body: resp.body })
        return
      }

      // 失败也要把 body 带回去：403 的 required/hint、503 的提示文案
      // 都是插件前端需要展示给用户的内容。
      this._postAPIResult(reqId, {
        ok: false,
        status: resp.status,
        body: resp.body,
        error: extractError(resp.body, resp.status),
      })
    } catch (err) {
      const msg2 = err?.name === 'AbortError' ? '请求超时或已被取消' : err?.message || String(err)
      this._postAPIResult(reqId, { ok: false, status: 0, error: msg2 })
    } finally {
      clearTimeout(timer)
      this._inflight.delete(controller)
    }
  }

  /** 处理提示请求（带限流）。 */
  _handleNotify(msg) {
    const now = Date.now()
    if (now - this._notifyWindowStart > NOTIFY_WINDOW_MS) {
      this._notifyWindowStart = now
      this._notifyCount = 0
    }
    this._notifyCount++
    if (this._notifyCount > NOTIFY_MAX_IN_WINDOW) {
      // 超限时只在窗口内第一次提示，避免"因为刷屏所以再刷一条"。
      if (this._notifyCount === NOTIFY_MAX_IN_WINDOW + 1) {
        this.onNotify('插件提示过于频繁，已限流', 'warning')
      }
      return
    }
    const text = String(msg.text || '').slice(0, 500)
    if (!text) return
    this.onNotify(text, normalizeLevel(msg.level))
  }

  /** 回传代发结果。 */
  _postAPIResult(id, payload) {
    this._post({ type: MSG_API_RESULT, id, ...payload })
  }
}

/** 把后端返回体里的 error 字段提取成一句提示。 */
export function extractError(body, status) {
  if (body && typeof body === 'object') {
    if (typeof body.error === 'string' && body.error) return body.error
    // 403 权限拒绝带 hint，那比 error 更有指导性。
    if (typeof body.hint === 'string' && body.hint) return body.hint
  }
  if (typeof body === 'string' && body.trim()) return body.slice(0, 300)
  return `请求失败（HTTP ${status || 0}）`
}

/** 归一化提示级别到宿主 UI 支持的三档。 */
function normalizeLevel(level) {
  const l = String(level || '').toLowerCase()
  if (l === 'error' || l === 'warning' || l === 'success') return l
  return 'info'
}

/** 构造 iframe 的 src（只带插件 ID，不带任何入口地址）。 */
export function frameSrc(pluginId) {
  return `/plugin-assets/frame.html?id=${encodeURIComponent(String(pluginId || ''))}`
}
