// 插件沙箱 iframe 的 Vue 运行时入口 —— 宿主侧的构建期源文件（阶段三 3.3）。
//
// ============ 它解决什么问题 ============
//
// 插件前端的沙箱 iframe 是 opaque origin，与宿主不在同一个 Realm：
// 跨 Realm 无法直接传对象（postMessage 只能结构化克隆），因此 iframe
// **不能**直接用宿主 window 上的 Vue。iframe 内必须自己加载一份 Vue 模块。
//
// iframe 里的 importmap 把裸说明符 "vue" 指向固定路径
// /assets/plugin-runtime.js，本文件就是那个路径的源文件：
// 它在 iframe 自己的 Realm 里 `import * as vue from 'vue'`，
// 然后把这份 Vue 交给 iframe 的引导层（plugin-frame.js）。
//
// ============ 为什么"自己加载一份"不会造成两套响应式系统 ============
//
// 关键是 iframe 内**所有插件共享同一份**：importmap 让每个插件的
// `import 'vue'` 都解析到同一个 URL，浏览器模块表保证它们是同一个实例。
// 因此 iframe 内的插件之间、插件与引导层之间，响应式系统完全一致。
//
// 与宿主的关系：两个 Realm 各有一份 Vue，但协议上只传纯数据
// （JSON 化的响应体），不传响应式对象或组件实例，因此不构成问题。
//
// ============ 为什么 dev 下有一份等价的内联实现 ============
//
// dev 模式下这个固定路径并不天然存在（本文件是构建期入口），
// 因此 vite.config.js 里有一段中间件返回等价的源码并交给 Vite 转换
// （让它的 `import 'vue'` 与 iframe 内插件解析到同一个模块实例）。
// 这正是 3.2 记录过的坑位 28：凡是 importmap 指向的固定路径，
// 必须同时保证 dev 与 build 两条路都在，且 MIME 必须是 JS。
import * as vue from 'vue'

const host = window.__LIPANEL__
if (host) {
  host.vue = vue
  // resolve 掉引导层的等待（plugin-frame.js 会 await vueReady）。
  if (typeof host.__resolveVue === 'function') host.__resolveVue(vue)
  // 这两个内部函数不该成为插件可依赖的接口面，用完即删。
  delete host.__resolveVue
  delete host.__rejectVue
} else {
  // 加载顺序有误（本文件必须在 plugin-frame.js 之前引入）。
  // 明确报错，而不是让插件一直转圈。
  console.error('[lipanel] 插件运行时入口在 __LIPANEL__ 建立之前执行，加载顺序有误')
}
