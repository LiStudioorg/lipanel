// 插件前端「动态加载内核」。
//
// 阶段三 3.2 起，插件前端不再是主程序里的一个静态查表项，而是**插件自带的
// ESM 模块**：核心通过 GET /api/plugins 返回插件声明的前端入口地址，
// 前端把这个地址动态 import() 进来，取出默认导出的挂载点。
//
// ============ 一、入口规范（与后端 plugin.Frontend 一一对应）============
//
//   frontend.entry   前端入口地址。三种形态：
//                      ""                       → 无前端
//                      "plugin.js"              → 相对插件自己的基址（frontend.assets）
//                      "/plugin-assets/x/a.js"  → 站点绝对路径（推荐，内置插件用这个）
//                      "https://..."            → 第三方托管（默认禁用，见 allowRemote）
//   frontend.assets  菜单图标标识同级的「资源基址」，用于兜底位置与相对路径。
//   frontend.type    入口类型，缺省 "esm"（本阶段只支持 ESM）。
//
// ============ 二、模块契约 ============
//
// 插件入口必须 default export 一个对象：
//
//   export default {
//     meta: { id, title, version },  // 可选，用作加载期校验与调试信息
//     component: VueComponent,       // 必需，宿主注入 pluginId / plugin 两个 prop
//   }
//
// 只认 default export 是有意为之：命名导出会让「插件到底导出了什么」
// 变成一个开放式问题，宿主解析起来只能靠猜；单默认导出最好校验。
//
// ============ 三、为什么要「原生 import → fetch + Blob」两层 ============
//
// 直接用 import(url) 是最干净的，但它有一个致命限制：
// **Vite 会在构建期改写动态 import 的说明符**。实测 `import(url)`（url 是
// 运行时字符串）会被产成 `__vitePreload(() => import("./plugin.js"))`，
// 请求的是**主程序自己的资源目录**，而不是插件入口——功能直接失效。
// `/* @vite-ignore */` 能阻止这种改写，但随后浏览器只接受「绝对 URL」：
//   - 以 "." / ".." 开头的相对路径 → TypeError: Failed to resolve module specifier
//   - 独立部署（-static-dir，没有 <base>）下的 "/xxx.js" → 同样的报错
// 因此策略是：
//   1) 先试原生 import()（绝对路径 + 线上部署的绝大多数情况）；
//   2) 失败则 fetch 源码 → new Blob → import(blobURL)。
//      Blob 模块里的 `import 'vue'` 必须靠 index.html 的 importmap 解析，
//      这样插件用的是**宿主同一份 Vue 实例**——否则插件内的 ref/render
//      来自另一份 Vue，「响应式不生效 / h() 报错」这类问题极难排查。
//
// 代价：import maps 需要 Firefox 108+ / Safari 16.4+。更旧的浏览器会
// 加载失败——这是「兜底优先」的取舍：失败会给出明确提示，而不是白屏。
//
// ============ 四、安全边界（请与后端 3.3 的权限设计一起看）============
//
// 本层做的是**抑制**而非**隔离**：
//   - 用 Blob 加载可以让插件 **躲开主程序构建产物的 CSP**（blob: 通常不在
//     script-src 白名单里），避免"插件装了却因为 CSP 加载不了"这种死局；
//   - 但插件代码与主程序共享同一个 Realm：它能读 document.cookie、
//     能调用 /api/*（带会话）、能拿到 window.__LIPANEL__。
//     因此**不应该让不信任的插件前端跑在面板页面里**。
//     真正的强隔离（sandbox iframe + postMessage 桥）留待后续阶段。
import { defineAsyncComponent, markRaw } from 'vue'

// 插件资源 URL 的部署基址。
//
// 固定为 '/'：面板目前总是部署在站点根（Vite 的 base 也是默认值），
// 改动这里必须同步改 vite.config.js 的 base，否则构建产物里的资源
// 路径会对不上。把它抽成常量是为了让「子路径部署」将来只有一处要改。
const assetBase = '/'

// 是否允许加载 http(s):// 的远端入口。
// 默认关闭：它会让面板在页面加载时向第三方发起请求（信息泄露面 + 供应链面），
// 需要的部署再显式打开。
let allowRemote = false

// 是否已经探测过 importmap 支持。
let importMapChecked = false
let importMapSupported = false

// pluginEntries 是「插件 ID → 前端入口」的清单。
//
// 它的唯一作用是让菜单/按钮能做**同步**判定：只有清单里存在的 entry
// 才可能在界面上出现，而不会因为一次异步加载把菜单渲染拖成异步。
const pluginEntries = new Map()

// viewCache 缓存已成功解析的组件；loadErrors 记录失败原因（用于界面提示）。
const viewCache = new Map()
const loadErrors = new Map()

// inFlight 保证同一个插件并发请求时只加载一次。
const inFlight = new Map()

// entryOf 返回某插件已登记的入口地址（未登记返回 ''）。
export function entryOf(id) {
  return pluginEntries.get(String(id || '')) || ''
}

// setEntry 登记/注销某个插件的前端入口。
//
// 清单变化时清掉该插件的失败记录：用户可能刚刚重新构建/启动了插件，
// 不清缓存的话他点了「重试」也还是看到上一条错误。
export function setEntry(id, entry) {
  const key = String(id || '')
  if (!key) return
  const value = String(entry || '')
  if (value) {
    if (pluginEntries.get(key) !== value) loadErrors.delete(key)
    pluginEntries.set(key, value)
  } else {
    pluginEntries.delete(key)
    loadErrors.delete(key)
    viewCache.delete(key)
  }
}

// applyPlugins 用后端返回的插件列表刷新入口清单。
//
// 返回值是「本次清单里声明了前端入口的插件数」，调用方据此更新界面状态。
export function applyPlugins(plugins) {
  const seen = new Set()
  for (const p of plugins || []) {
    const id = String(p?.id || '')
    if (!id) continue
    // 资源基址先登记：它是相对入口与兜底位置 plugin.js 的解析基准。
    setAssets(id, String(p?.frontend?.assets || '').trim())

    const entry = String(p?.frontend?.entry || '').trim()
    if (entry) seen.add(id)
    setEntry(id, entry)
  }
  // 后端列表里已经不存在的插件（被移除/停用），其入口也要一并清理，
  // 否则菜单会残留一个永远打不开的入口。
  for (const id of [...pluginEntries.keys()]) {
    if (!seen.has(id)) {
      setEntry(id, '')
      setAssets(id, '')
    }
  }
  return seen.size
}

// getPluginLoadError 返回某插件最近一次加载失败的原因（无失败返回 ''）。
export function getPluginLoadError(id) {
  return loadErrors.get(String(id || '')) || ''
}

// clearViewCache 清空加载缓存（失败与成功都清）。
export function clearViewCache() {
  viewCache.clear()
  loadErrors.clear()
  inFlight.clear()
}

// clearPluginView 只清某个插件的加载缓存，用于「重试」。
//
// 与 clearViewCache 的区别很重要：重试某个插件时不该把其它插件的
// 加载结果一起丢掉（那会让已打开的界面重新拉一次模块）。
export function clearPluginView(id) {
  const key = String(id || '')
  viewCache.delete(key)
  loadErrors.delete(key)
  inFlight.delete(key)
}

// hasEntry 判断某插件是否声明了前端入口（同步，不触发任何加载）。
export function hasEntry(id) {
  return Boolean(entryOf(id))
}

// listEntryIds 返回已登记前端入口的插件 ID（按字典序，便于稳定输出）。
export function listEntryIds() {
  return [...pluginEntries.keys()].sort()
}

// resolvePluginView 解析插件前端组件。
//
// 注意：这是**展示判定**（hasPluginView 用的也是它），必须在没有入口时
// 同步返回 null 且不产生任何网络请求；只有清单里确实登记了入口时，
// 才返回一个异步组件（真正加载发生在挂载那一刻）。
export function resolvePluginView(id) {
  const key = String(id || '')
  const entry = entryOf(key)
  if (!entry) return null

  if (viewCache.has(key)) return viewCache.get(key)

  const component = markRaw(
    defineAsyncComponent({
      loader: () => loadPluginView(key, entry),
      // 失败时把原因写进 loadErrors，宿主页据此显示可操作的提示。
      onError: (err, _retry, fail) => {
        loadErrors.set(key, describeLoadError(err, entry))
        fail()
      },
      // 不做超时限制：插件资源可能来自较慢的自托管服务器；
      // 加载中/失败都有 UI 兜底，卡住也不会白屏。
      suspensible: false,
    }),
  )
  viewCache.set(key, component)
  return component
}

// loadPluginView 真正加载并校验插件模块，返回 Vue 组件。
async function loadPluginView(id, entry) {
  if (inFlight.has(id)) return inFlight.get(id)

  const task = (async () => {
    const url = resolveURL(entry, id)
    let mod
    try {
      mod = await importModule(url)
    } catch (err) {
      // 入口声明的位置加载失败 → 降级到约定位置：
      // 插件在 frontend.assets 基址下放一个 plugin.js 就一定能被找到。
      const fallback = fallbackURL(id)
      if (!fallback || fallback === url) throw err
      try {
        mod = await importModule(fallback)
      } catch (fallbackErr) {
        // 两个位置都失败：把**首次**错误抛出去。
        // 首次错误指向插件自己声明的入口，对插件作者更有指导意义；
        // 兜底位置的失败原因作为附加信息带上。
        err.fallbackError = fallbackErr
        err.fallbackURL = fallback
        throw err
      }
    }

    const exported = mod?.default
    if (!isValidPluginModule(exported)) {
      throw new PluginLoadError(
        `插件「${id}」的入口 ${url} 未按契约导出组件：` +
          '需要 `export default { component }`（组件也可以是 default export 本身）。',
      )
    }
    if (exported.meta?.id && String(exported.meta.id) !== id) {
      // 只告警不阻断：ID 不一致通常是复制粘贴改了 id 字段忘了改，
      // 直接拒绝会让插件彻底不可用，代价大于收益。
      console.warn(
        `[lipanel] 插件入口声明的 id (${exported.meta.id}) 与注册 ID (${id}) 不一致，已按注册 ID 处理`,
      )
    }
    return exported.component
  })()

  inFlight.set(id, task)
  try {
    return await task
  } finally {
    inFlight.delete(id)
  }
}

// importModule 按「原生 import → fetch + Blob」两层加载一个 ESM 模块。
export async function importModule(url) {
  try {
    return await import(/* @vite-ignore */ url)
  } catch (err) {
    if (!shouldFallbackToBlob(err)) throw err
    return await importViaBlob(url)
  }
}

// shouldFallbackToBlob 判断某个 import 失败是否值得改用 Blob 再试一次。
//
// 只对「说明符无法解析」这一类错误降级：
//   - Firefox: TypeError: Failed to resolve module specifier 'x'
//   - Chrome : TypeError: Failed to fetch dynamically imported module（相对路径）
//   - 独立部署的绝对路径: TypeError: Invalid URL / ERR_UNSUPPORTED_ESM_URL_SCHEME
// 真实的 404/网络错误不在此列——那种情况下再 fetch 一次也是白搭。
export function shouldFallbackToBlob(err) {
  const msg = String(err?.message || err || '')
  return (
    /Failed to resolve module specifier/i.test(msg) ||
    /Invalid URL/i.test(msg) ||
    /ERR_UNSUPPORTED_ESM_URL_SCHEME/i.test(msg) ||
    /Failed to fetch dynamically imported module/i.test(msg)
  )
}

// blobMap caches Blob URLs by module URL so repeated imports share one object URL.
const blobMap = new Map()

// importViaBlob 取回模块源码、重写其中的相对说明符，再用 Blob URL 导入。
//
// 这一步是「相对路径入口」能工作的关键：Blob URL 内部没有真实的目录结构，
// `import './util.js'` 这样的写法在 Blob 里必然解析失败，
// 因此必须先把相对说明符改写成基于原模块地址的绝对 URL。
async function importViaBlob(url) {
  const cached = blobMap.get(url)
  if (cached) return import(/* @vite-ignore */ cached)

  let code
  try {
    const resp = await fetch(url, { credentials: 'same-origin' })
    if (!resp.ok) {
      throw new PluginLoadError(`加载插件资源失败：HTTP ${resp.status} ${url}`)
    }
    code = await resp.text()
  } catch (err) {
    if (err instanceof PluginLoadError) throw err
    throw new PluginLoadError(`无法获取插件资源 ${url}：${err?.message || err}`, { cause: err })
  }

  if (!importMapSupportedNow()) {
    throw new PluginLoadError(
      `当前浏览器不支持 import maps，无法加载插件前端（${url}）。` +
        '请升级到 Chrome 89+ / Firefox 108+ / Safari 16.4+ 后再试。',
    )
  }

  const rewritten = rewriteRelativeSpecifiers(code, url)
  const blobURL = URL.createObjectURL(new Blob([rewritten], { type: 'text/javascript' }))
  blobMap.set(url, blobURL)
  return import(/* @vite-ignore */ blobURL)
}

// importMapSupportedNow 探测浏览器是否支持 import maps（结果缓存）。
//
// 探测方式：往 <script type="importmap">.textContent 写入一个哨兵值。
// 支持 importmap 的浏览器会解析并保存这段 JSON；不支持的浏览器不认这个
// type，textContent 保持原样。注意**绝不能用 src 属性探测**——那会触发
// 一次真实的网络请求。
export function importMapSupportedNow() {
  if (importMapChecked) return importMapSupported
  importMapChecked = true
  try {
    if (typeof document === 'undefined') return (importMapSupported = false)
    const probe = document.createElement('script')
    probe.type = 'importmap'
    probe.textContent = '{"imports":{"lipanel-importmap-probe":"data:text/javascript,"}}'
    document.head.appendChild(probe)
    const parsed = probe.textContent
    document.head.removeChild(probe)
    importMapSupported = parsed !== null && parsed.includes('lipanel-importmap-probe')
  } catch {
    importMapSupported = false
  }
  return importMapSupported
}

// importSpecifierPattern 匹配模块里的静态与动态 import 说明符。
//
// 只处理相对说明符（"./x"、"../x"）：裸说明符（"vue"）交给 importmap，
// 绝对 URL 原样保留。用正则而不是完整解析器是因为插件源码由我们自己
// 或插件作者编写，且改动范围极小；把 Vue 编译器搬进面板并不划算。
const importSpecifierPattern =
  /(\bfrom\s*|\bimport\s*\(?\s*)(['"])(\.\.?\/[^'"]*)\2/g

// rewriteRelativeSpecifiers 把源码里的相对 import 说明符改写为绝对 URL。
//
// 导出仅为便于单测；正常调用方不需要关心。
export function rewriteRelativeSpecifiers(code, baseURL) {
  return code.replace(importSpecifierPattern, (match, prefix, quote, spec) => {
    return `${prefix}${quote}${new URL(spec, baseURL).href}${quote}`
  })
}

// resolveURL 把插件声明的入口地址解析为可 import 的 URL。
export function resolveURL(entry, id) {
  const raw = String(entry || '').trim()
  if (!raw) throw new PluginLoadError('插件未声明前端入口地址')

  // 远端入口：默认拒绝，避免面板页面悄悄向第三方取代码。
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    if (!allowRemote) {
      throw new PluginLoadError(
        `插件「${id}」声明了远端前端入口 ${raw}，但远端入口默认被禁用（安全策略）。`,
      )
    }
    return raw
  }

  // 相对入口按「插件自己的资源基址」解析——这就是 frontend.assets 的用途。
  if (!raw.startsWith('/')) {
    const base = baseURLOf(id)
    return new URL(raw, base).href
  }

  // 站点绝对路径 → 拼上部署基址（见 assetBase 的说明）。
  return stripTrailingSlash(assetBase) + raw || '/'
}

// fallbackURL 返回插件的「约定位置」：<assets 基址>/plugin.js。
//
// 这是加载失败的兜底：只要插件在资源基址下放了 plugin.js，
// 即使它的 entry 写错（或压根没写全），也依然能被加载起来。
export function fallbackURL(id) {
  const base = baseURLOf(id)
  if (!base) return ''
  return new URL('plugin.js', base).href
}

// baseURLOf 返回插件的资源基址；无法确定时回落到 siteBaseURL + id 目录。
function baseURLOf(id) {
  const declared = String(assetsOf(id) || '').trim()
  if (declared) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(declared)) return declared
    const path = declared.startsWith('/') ? declared : `/${declared}`
    return new URL(ensureTrailingSlash(path), siteBaseURL()).href
  }
  return new URL(`__lipanel/plugins/${id}/`, siteBaseURL()).href
}

// assetsMap holds each plugin's declared asset base (frontend.assets).
const assetsMap = new Map()

// setAssets 登记某插件的资源基址（applyPlugins 会调用）。
export function setAssets(id, base) {
  const key = String(id || '')
  if (!key) return
  const value = String(base || '')
  if (value) assetsMap.set(key, value)
  else assetsMap.delete(key)
}

function assetsOf(id) {
  return assetsMap.get(String(id || '')) || ''
}

// siteBaseURL 返回站点根（含部署基址）。
function siteBaseURL() {
  if (typeof window === 'undefined' || !window.location) return 'http://localhost/'
  return new URL(stripTrailingSlash(assetBase) + '/', window.location.href).href
}

function stripTrailingSlash(s) {
  return String(s || '').replace(/\/+$/, '')
}

function ensureTrailingSlash(s) {
  return String(s || '').endsWith('/') ? s : `${s}/`
}

// isValidPluginModule 校验插件模块是否符合契约。
//
// 允许两种写法：
//   export default { component }
//   export default SomeComponent          （组件本身即默认导出）
export function isValidPluginModule(exported) {
  if (!exported) return false
  if (typeof exported === 'object' && 'component' in exported) {
    return Boolean(exported.component)
  }
  // 函数/对象形态的组件（含 defineComponent 的产物）
  return typeof exported === 'function' || typeof exported === 'object'
}

// describeLoadError 把加载异常转成一句给人看的话。
export function describeLoadError(err, entry) {
  if (err instanceof PluginLoadError) return err.message
  const msg = String(err?.message || err || '未知错误')
  if (shouldFallbackToBlob(err)) {
    return (
      `无法解析插件前端入口「${entry}」（${msg}）。` +
      '请确认插件已随程序分发，或检查浏览器是否支持 import maps。'
    )
  }
  return `加载插件前端失败：${msg}`
}

// PluginLoadError 表示插件前端加载过程中的可预期失败。
export class PluginLoadError extends Error {
  constructor(message, { cause } = {}) {
    super(message)
    this.name = 'PluginLoadError'
    this.cause = cause
  }
}

// setAllowRemote 控制是否允许加载 http(s):// 形态的远端插件入口。
//
// 默认关闭（安全边界见文件头）。保留这个开关是给「自建插件源」这类
// 部署留的口子；本阶段没有调用方，属于有意保留的能力位。
export function setAllowRemote(value) {
  allowRemote = Boolean(value)
}
