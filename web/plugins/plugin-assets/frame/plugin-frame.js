// 插件前端「强隔离」协议的 iframe 侧实现（阶段三 3.3）。
//
// ============ 一、为什么需要这个文件 ============
//
// 3.2 的插件前端与宿主**共享同一个 Realm**：插件代码能读 document.cookie、
// 能直接 fetch('/api/*')（带会话）、能拿到 window.__LIPANEL__。
// 这意味着「插件装了但不可信」时，面板的会话等于交给了它。
//
// 3.3 把默认加载方式换成 **sandbox iframe + postMessage 桥**：
//
//   ┌─────────────── 宿主页面 (origin: https://panel) ───────────────┐
//   │  Vue 应用、会话 Cookie (HttpOnly)、/api/* 直连能力             │
//   │  ┌──────────── 插件 iframe (opaque origin) ────────────┐      │
//   │  │  sandbox="allow-scripts"（刻意不含 allow-same-origin）│      │
//   │  │  · document.cookie → 抛异常/空                        │      │
//   │  │  · localStorage/sessionStorage → 抛异常               │      │
//   │  │  · fetch('/api/*') → 不带 Cookie，被后端 401           │      │
//   │  │  插件代码在这里运行，能力只剩：渲染 + postMessage      │      │
//   │  └──────────────────────────────────────────────────────┘      │
//   └────────────────────────────────────────────────────────────────┘
//
// 关键点：**没有 allow-same-origin** 让 iframe 处于 opaque origin，
// 于是它与宿主之间的同源能力被浏览器强制切断——这不是我们"约定"不去读
// cookie，而是浏览器不让读。插件要拿数据只能通过 postMessage 请宿主代取。
//
// ============ 二、Vue 怎么还是同一份实例 ============
//
// 插件前端写 `import { ref } from 'vue'` 的写法**保持不变**。iframe 内的
// import map 把裸说明符 "vue" 指向 /assets/plugin-runtime.js，该入口在
// iframe 自己的 Realm 里 `import * as vue from 'vue'`，然后把这份 Vue 挂到
// window.__LIPANEL__.vue 上，并 resolve 一个等待中的 Promise。
//
// 本文件先 `await __LIPANEL__.vueReady`，再去 import 插件模块——
// 这样插件模块求值时 window.__LIPANEL__ 已完整就绪，不会出现
// 「插件顶层读了 undefined」的时序 bug。
//
// iframe 内所有插件共享同一份 Vue（同一个 URL → 浏览器模块表里同一个实例），
// 因此插件之间、插件与引导层之间不会出现"两套响应式系统"的问题。
//
// ============ 三、通信协议 v1 ============
//
// 完整协议表见 web/src/plugins/bridge.js 文件头（宿主侧）与本文件末尾的
// 常量定义，两侧必须保持一致。协议版本号不匹配时宿主会拒绝服务并给出提示，
// 而不是让插件在半坏的状态下运行。
//
// ============ 四、这个方案不能做什么（诚实边界） ============
//
// 1. iframe 隔离保护的是**宿主页面**（cookie、DOM、会话、其它插件），
//    它不限制插件**后端进程**的系统权限——那是 internal/plugin 的
//    权限声明负责的，且同样不是内核级沙箱。
// 2. 插件前端仍会占用宿主页面的 CPU（渲染、循环）；iframe 无法限制算力。
// 3. 桥接 API 只允许访问「该插件自己的」接口（路径白名单在宿主侧强制），
//    因此 A 插件无法借桥去调 B 插件的接口。
// 4. 插件通过 postMessage 只能拿到宿主**主动提供**的元数据（插件信息、
//    主题、尺寸），拿不到任意宿主状态。
'use strict'

// ---------- 协议常量 ----------
//
// 与宿主侧（web/src/plugins/bridge.js）必须逐字一致。
// 之所以两边各写一份而不是共享一个模块：iframe 侧的代码由 Vite
// publicDir 原样分发（不经打包），无法 import 宿主 src/ 下的模块——
// 这正是「插件前端自包含」的代价，已在 README 中说明。
const PROTOCOL_VERSION = 1

// iframe → 宿主
const MSG_READY = 'lipanel:ready'
const MSG_API = 'lipanel:api'
const MSG_RESIZE = 'lipanel:resize'
const MSG_NOTIFY = 'lipanel:notify'
const MSG_ERROR = 'lipanel:error'
const MSG_NAVIGATE = 'lipanel:navigate'

// 宿主 → iframe
const MSG_PLUGIN_DATA = 'lipanel:plugin-data'
const MSG_API_RESULT = 'lipanel:api-result'

// 每次 postMessage 都带上 protocol 字段，便于将来协议演进时
// 双方能明确地拒绝不兼容的对端，而不是静默地误解析。
function envelope(type, payload) {
  return { protocol: PROTOCOL_VERSION, type, ...(payload || {}) }
}

// ---------- 与宿主的消息通道 ----------

// send 向宿主发送一条消息。
//
// targetOrigin 必须是 '*'：iframe 处于 opaque origin，
// 宿主无法用一个具体的 origin 字符串匹配它（它的 origin 序列化就是 "null"）。
// 这不是安全缺陷——载荷里不含任何机密，凭据始终留在宿主侧；
// 而宿主发给 iframe 的消息本来就是要给插件看的数据。
function send(type, payload) {
  if (!window.parent || window.parent === window) return
  window.parent.postMessage(envelope(type, payload), '*')
}

// pending 保存「已发出但未收到结果」的 API 请求。
const pending = new Map()
let nextRequestId = 1

// apiCall 通过宿主代发一个 API 请求。
//
// path 只能是**本插件自己的**接口路径（形如 /info、/runtime）。
// 安全性由宿主侧强制（宿主会拼上 /api/plugins/<自身 id> 前缀并校验），
// iframe 侧不做也不该做白名单判断——客户端校验永远只是"体验"，
// 不是安全边界。
function apiCall(path, options) {
  const id = nextRequestId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    send(MSG_API, {
      id,
      method: (options && options.method) || 'GET',
      path,
      body: options && options.body,
    })
    // 超时兜底：宿主可能已经销毁（用户切走了页面），
    // 没有超时的话插件的 await 会永远挂住（表现为界面一直转圈）。
    setTimeout(() => {
      if (!pending.has(id)) return
      pending.delete(id)
      reject(new Error('插件桥接请求超时（宿主可能已关闭该插件页面）'))
    }, 30000)
  })
}

// ---------- 桥接 API（暴露给插件） ----------

// pluginHost 是暴露给插件的桥接对象。
//
// 刻意保持**小而固定**的接口面：只有 api / ui 两组能力。
// 接口面越小，将来加隔离措施时越不容易破坏插件兼容性。
const pluginHost = {
  protocol: PROTOCOL_VERSION,

  // api：代发 HTTP 请求。返回宿主转发后的响应体。
  api: {
    // get/post 是最常用的两个；其余方法用 request 显式指定。
    async get(path) {
      return apiCall(path, { method: 'GET' })
    },
    async post(path, body) {
      return apiCall(path, { method: 'POST', body })
    },
    async request(path, options) {
      return apiCall(path, options)
    },
  },

  // ui：向宿主请求界面层面的配合。
  ui: {
    // resize 上报内容高度，由宿主调整 iframe 高度。
    // 值由宿主 clamp 到合理区间，防止插件把面板撑爆。
    resize(height) {
      send(MSG_RESIZE, { height: Number(height) || 0 })
    },
    // notify 请求宿主弹一条提示（限流由宿主负责）。
    notify(text, level) {
      send(MSG_NOTIFY, { text: String(text || '').slice(0, 500), level: level || 'info' })
    },
    // navigate 请求宿主做站内跳转（白名单在宿主侧强制）。
    navigate(to) {
      send(MSG_NAVIGATE, { to: String(to || '') })
    },
  },
}

// ---------- 引导流程 ----------

// boot 是 iframe 的入口：握手 → 拿元数据 → 加载插件模块 → 挂载。
async function boot() {
  // 依赖 Vue 运行时入口先就绪（见文件头第二节）。
  // 失败时给出可操作的提示，而不是让页面空白。
  let vue
  try {
    vue = await window.__LIPANEL__.vueReady
  } catch (err) {
    return fail(
      '插件运行环境初始化失败：无法加载宿主共享的 Vue 实例（/assets/plugin-runtime.js）。' +
        '请确认面板前端已正确构建，或刷新页面重试。' +
        '（原始错误：' + (err && err.message ? err.message : err) + '）',
    )
  }

  // 等待宿主下发插件元数据。
  // iframe 的 src 里只带一个不带敏感信息的 id；真正的入口地址、
  // 插件信息都由宿主在握手后通过 postMessage 提供——
  // 这样 iframe 无法通过伪造 URL 让自己去加载别的插件前端。
  const data = await waitForHostData()
  return mount(vue, data)
}

// waitForHostData 等待宿主发来的 lipanel:plugin-data。
function waitForHostData() {
  return new Promise((resolve, reject) => {
    let settled = false

    // 超时：宿主可能根本没能加载插件元数据（例如插件已被移除）。
    // 没有超时的话 iframe 会一直空着，用户只看到一片空白。
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      reject(new Error('等待宿主下发插件信息超时（15s）'))
    }, 15000)

    window.addEventListener('message', function onMessage(event) {
      // 只接受来自宿主的消息。
      // 注意：iframe 处于 opaque origin，宿主的 origin 我们看不到具体值
      // （顶层页面访问 event.origin 会得到自身的 null origin 语义），
      // 因此这里靠「是不是 parent 这个窗口」来判断。
      if (event.source !== window.parent) return
      const msg = event.data
      if (!msg || typeof msg !== 'object') return
      if (msg.type !== MSG_PLUGIN_DATA) return

      // 协议版本校验：不匹配时明确拒绝，而不是半坏地运行。
      if (Number(msg.protocol) !== PROTOCOL_VERSION) {
        if (settled) return
        settled = true
        clearTimeout(timer)
        window.removeEventListener('message', onMessage)
        reject(
          new Error(
            '插件隔离协议版本不匹配：宿主报 ' + msg.protocol + '，插件前端需要 ' + PROTOCOL_VERSION +
              '。请同步升级插件前端与主程序。',
          ),
        )
        return
      }

      settled = true
      clearTimeout(timer)
      window.removeEventListener('message', onMessage)
      resolve(msg)
    })

    // 先声明「我准备好了」，宿主收到后才下发元数据。
    // 由 iframe 主动发起（而不是宿主直接 push）的好处是：宿主能确定
    // iframe 的脚本真的跑起来了，避免"宿主发了但 iframe 还没装监听"的竞态。
    send(MSG_READY, {})
  })
}

// mount 加载插件 ESM 模块并挂载到 iframe 内的 #app。
async function mount(vue, data) {
  const pluginId = String(data.pluginId || '')
  const entry = String(data.entry || '')
  const assets = String(data.assets || '')

  if (!entry) {
    return fail('宿主未下发插件前端入口地址（frontend.entry 为空）。')
  }

  // 解析入口地址：与 3.2 的 loader 规则保持一致。
  let url
  try {
    url = resolveEntryURL(entry, assets)
  } catch (err) {
    return fail('插件前端入口地址无法解析：' + (err && err.message ? err.message : err))
  }

  let mod
  try {
    mod = await import(/* @vite-ignore */ url)
  } catch (err) {
    // 入口失败 → 兜底到 <assets>plugin.js（与 3.2 的降级策略一致）。
    const fallback = assets ? new URL('plugin.js', assets).href : ''
    if (fallback && fallback !== url) {
      try {
        mod = await import(/* @vite-ignore */ fallback)
      } catch (fallbackErr) {
        return fail(describeEntryError(pluginId, url, err, fallback, fallbackErr))
      }
    } else {
      return fail(describeEntryError(pluginId, url, err, '', null))
    }
  }

  // 模块契约校验：必须 default export 出 component（或组件本身）。
  const exported = mod && mod.default
  const component = isComponent(exported) ? exported.component || exported : null
  if (!component) {
    return fail(
      '插件「' + pluginId + '」的入口 ' + url + ' 未按契约导出组件：' +
        '需要 `export default { component }`（组件也可以是 default export 本身）。',
    )
  }

  // 注入宿主提供的 prop：pluginId 与 plugin（与 3.2 的契约完全一致，
  // 因此插件组件代码不需要为隔离模式做任何改动）。
  const app = vue.createApp({
    render() {
      return vue.h(component, {
        pluginId,
        plugin: data.plugin || null,
      })
    },
  })

  // 让插件内部的错误可见（而不是静默失败）：
  // 插件组件 setup 里抛错时，宿主页应当看到具体原因。
  app.config.errorHandler = (err, _instance, info) => {
    send(MSG_ERROR, {
      message: '插件组件运行出错：' + (err && err.message ? err.message : String(err)) +
        '（位置：' + info + '）',
    })
  }

  app.mount('#app')

  // 上报初始高度，并持续观察内容变化后的高度。
  reportSize()
  observeSize()

  // 通知宿主：插件前端已成功挂载（宿主据此清掉"加载中"状态）。
  send(MSG_READY, { mounted: true, pluginId })
}

// reportSize 把当前内容高度上报给宿主。
function reportSize() {
  const el = document.documentElement
  if (!el) return
  // 取 body 与 documentElement 的较大值：只读 body 在某些布局下会偏小，
  // 导致 iframe 里出现内部滚动条（体验上很突兀）。
  const height = Math.max(
    el.scrollHeight || 0,
    document.body ? document.body.scrollHeight || 0 : 0,
  )
  if (height > 0) send(MSG_RESIZE, { height })
}

// observeSize 监听内容尺寸变化并上报。
//
// 用 ResizeObserver 而不是 setInterval：面板上多个插件 iframe 各自
// 轮询会白白消耗 CPU，而 ResizeObserver 只在真的变化时触发。
function observeSize() {
  if (typeof ResizeObserver === 'undefined' || !document.body) return
  try {
    const ro = new ResizeObserver(() => reportSize())
    ro.observe(document.body)
  } catch {
    // 老浏览器不支持时退化为「只在挂载时上报一次」，
    // 不影响功能，只是内容变化后宿主高度可能不跟随。
  }
}

// ---------- 辅助 ----------

// resolveEntryURL 解析插件声明的入口地址。
//
// 规则与 3.2 的 loader.js 保持一致：
//   - 站点绝对路径（以 / 开头）→ 原样使用（浏览器按当前站点解析）
//   - 相对路径 → 相对 assets 基址解析
//   - 远端 http(s) → 拒绝（安全策略：面板不该悄悄从第三方取代码）
function resolveEntryURL(entry, assets) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(entry)) {
    // 允许 http(s) 的例外：只有当它与本站同源时才放行。
    const u = new URL(entry, window.location.href)
    if (u.origin !== window.location.origin) {
      throw new Error('远端插件入口默认被禁用（安全策略）：' + entry)
    }
    return u.href
  }
  if (entry.startsWith('/')) {
    // iframe 处于 opaque origin，无法用 new URL(entry) 得到绝对地址
    // （没有可用的 base），但动态 import 接受以 / 开头的站点绝对路径。
    return entry
  }
  const base = assets || '/'
  return new URL(entry, new URL(base, window.location.href)).href
}

// isComponent 判断 default export 是否符合插件模块契约。
function isComponent(exported) {
  if (!exported) return false
  if (typeof exported === 'object' && 'component' in exported) {
    return Boolean(exported.component)
  }
  return typeof exported === 'function' || typeof exported === 'object'
}

// describeEntryError 把入口加载失败翻译成一句可操作的话。
function describeEntryError(pluginId, url, err, fallback, fallbackErr) {
  const first = err && err.message ? err.message : String(err)
  let msg =
    '插件「' + pluginId + '」的前端入口加载失败：' + url + '\n原因：' + first
  if (fallback) {
    msg += '\n兜底位置 ' + fallback + ' 也失败：' +
      (fallbackErr && fallbackErr.message ? fallbackErr.message : String(fallbackErr))
  }
  msg += '\n请确认插件已随程序分发，且已在插件管理页启动。'
  return msg
}

// fail 展示一条可读的错误信息（绝不白屏）。
function fail(message) {
  const app = document.getElementById('app')
  const text = String(message || '未知错误')

  if (app) {
    app.textContent = ''
    const box = document.createElement('div')
    box.setAttribute('data-lipanel-frame-error', '1')
    box.style.cssText =
      'border-left:3px solid #d03050;background:rgba(128,128,128,0.10);' +
      'border-radius:4px;padding:12px 14px;font-size:13px;white-space:pre-wrap;' +
      'line-height:1.6;color:inherit;'

    const title = document.createElement('strong')
    title.textContent = '✖ 插件前端无法加载'
    box.appendChild(title)

    const body = document.createElement('div')
    body.style.marginTop = '6px'
    body.textContent = text
    box.appendChild(body)

    app.appendChild(box)
  }

  // 同时告知宿主：宿主页可以把这条错误显示在插件页面顶部，
  // 用户不必点进 iframe 才能看到原因。
  send(MSG_ERROR, { message: text })
  reportSize()
}

// ---------- 消息处理（宿主 → iframe） ----------

window.addEventListener('message', (event) => {
  if (event.source !== window.parent) return
  const msg = event.data
  if (!msg || typeof msg !== 'object') return

  switch (msg.type) {
    case MSG_API_RESULT: {
      const entry = pending.get(msg.id)
      if (!entry) return // 超时后已被清理，忽略迟到的响应。
      pending.delete(msg.id)
      if (msg.ok) {
        entry.resolve(msg.body)
      } else {
        // 把 HTTP 状态码挂在 error 上：插件可以据此区分
        // 403（权限不足）、503（插件未运行）、401（会话过期）。
        const err = new Error(msg.error || ('请求失败（HTTP ' + msg.status + '）'))
        err.status = msg.status
        err.body = msg.body
        entry.reject(err)
      }
      return
    }

    // 宿主主动要求重新测量尺寸（例如窗口大小变化）。
    case 'lipanel:measure': {
      reportSize()
      return
    }

    default:
      // 未知消息类型一律忽略：协议演进时旧版本不该因为
      // "看不懂" 就报错刷屏。
      return
  }
})

// ---------- 启动 ----------

// window.__LIPANEL__ 是插件可依赖的宿主运行时对象。
//
// 注意：vue 字段由 /assets/plugin-runtime.js 填充（它不是本文件的一部分），
// 因此这里只搭骨架；vueReady 供 boot 等待。
window.__LIPANEL__ = Object.assign(window.__LIPANEL__ || {}, pluginHost, {
  // vue 由运行时入口注入（见 web/src/frame-runtime.js）。
  vue: null,
  // vueReady 在运行时入口执行完毕后 resolve。
  vueReady: new Promise((resolve, reject) => {
    window.__LIPANEL__.__resolveVue = resolve
    window.__LIPANEL__.__rejectVue = reject
  }),
  // frame 标记：插件可据此判断自己跑在隔离 iframe 里（而不是 3.2 的共享 Realm）。
  frame: true,
})

// 启动引导。用 try/catch 包住：引导过程中的任何异常都必须变成
// 可见的错误提示，而不是一个静默空白的 iframe。
boot().catch((err) => {
  fail('插件前端引导失败：' + (err && err.message ? err.message : String(err)))
})
