// iframe 内的 Vue 运行时入口（阶段三 3.3）。
//
// 职责只有一个：在**插件沙箱 iframe 自己的 Realm 里**建立一份 Vue 实例，
// 把它交给 plugin-frame.js 使用，从而让 iframe 内的插件前端可以照常写
// `import { ref, h } from 'vue'`。
//
// ============ 为什么不直接用宿主那份 window.__LIPANEL__.vue ============
//
// 3.2 里插件与宿主共享 Realm，所以宿主可以把 Vue 挂在 window 上给插件用。
// 3.3 的 iframe 是 opaque origin，**跨 Realm 的对象无法直接传递**
// （postMessage 只能传结构化克隆数据，函数与类实例都不行）。
// 因此 iframe 内必须自己加载一份 Vue 模块。
//
// ============ iframe 内的 Vue 为什么仍是"同一份" ============
//
// 这里 import 的是宿主构建产物中的同一个模块（由 importmap 指向
// /assets/plugin-runtime.js，它在构建期与主应用共享同一个 runtime-dom chunk）。
// 关键是 iframe 内**所有插件共享这一份**：
//
//   /assets/plugin-runtime.js  ──►  window.__LIPANEL__.vue
//   插件 A 的 import 'vue'     ──►  ┐
//   插件 B 的 import 'vue'     ──►  ├─ importmap 都指向上面那个 URL
//   插件 C 的 import 'vue'     ──►  ┘   → 浏览器模块表里是同一个实例
//
// 于是 iframe 内不会出现「两套响应式系统」的问题（那正是 3.2 记录过的坑）。
// 与宿主的关系则是：两个 Realm 各有一份 Vue，但协议上只传**纯数据**
// （JSON 化的对象），不传响应式对象或组件实例，因此不构成问题。
//
// ============ 为什么不用包含编译器的构建 ============
//
// 插件前端按契约用 h() 手写渲染函数（不能用 .vue 单文件，见 README），
// 因此不需要模板编译器。用 vue/dist/vue.runtime.esm-bundler.js 的等价物
// 可以让 iframe 的加载体积更小——面板页面里可能同时挂多个插件 iframe，
// 每个都拖一份编译器并不划算。
'use strict'

import * as vue from 'vue'

// 把 Vue 交给引导层。plugin-frame.js 会 await __LIPANEL__.vueReady，
// 因此这里的赋值必须在它 await 之前完成——本文件在 frame.html 中
// 先于 plugin-frame.js 加载，时序上有保证。
function install() {
  const host = window.__LIPANEL__
  if (!host) {
    // 理论上不会发生（plugin-frame.js 在本文件之前建立骨架）。
    // 真发生了就明确报错，而不是静默失败让插件一直转圈。
    console.error('[lipanel] 插件运行时入口在 __LIPANEL__ 建立之前执行，加载顺序有误')
    return
  }

  host.vue = vue
  if (typeof host.__resolveVue === 'function') {
    host.__resolveVue(vue)
  }
  // 释放这两个内部函数：它们不该成为插件可依赖的接口面。
  delete host.__resolveVue
  delete host.__rejectVue
}

install()
