// 插件运行时入口 —— 插件前端与宿主共享同一份 Vue 的「接缝」。
//
// 这个文件会被构建成 **dist/assets/vue.js**（固定路径，见 vite.config.js 的
// rollupOptions.input 与 entryFileNames），并由 index.html 的 importmap
// 把裸说明符 "vue" 指向它：
//
//     index.html:  {"imports": {"vue": "/assets/vue.js"}}
//
// 于是插件模块里写的 `import { ref, h } from 'vue'` 拿到的正是宿主
// 正在使用的**同一个模块实例**（Vite/Rollup 对同一个 'vue' 模块只会有
// 一份实例，第二个入口无非是同一实例的另一个引用）。
//
// ============ 维护者注意：这个文件是有意“什么都不做”的 ============
//
// 它不能写成 `export * as vue from 'vue'`——实测 Rollup 会把这种纯命名空间
// 再导出优化成空 chunk（0 字节）。它也不能引用 src/ 下的其它模块，
// 否则一旦形成跨 chunk 引用，/assets/vue.js 就依赖带哈希的 chunk 文件，
// 而 importmap 指向的是固定路径：重建一次（哈希变了）插件就会 404。
//
// 因此本文件只允许出现两件事：
//   1. `import * as vue from 'vue'`
//   2. 把 vue 挂到 window.__LIPANEL__
//
// 校验方式：`npm run build` 后跑 `node ../scripts/check-runtime-entry.mjs`，
// 它会断言 assets/vue.js 自包含、且包含 __LIPANEL__ 赋值。
import * as vue from 'vue'

// 宿主运行时对象：插件前端唯一的依赖面。
window.__LIPANEL__ = {
  ...(window.__LIPANEL__ || {}),
  vue,
}
