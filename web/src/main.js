// 前端入口：启动 Vue 应用与路由。
//
// 与 3.1 相比只多了一件事：在挂载前**动态 import 运行时入口**
// （src/runtime.js → dist/assets/vue.js），把宿主那份 Vue 暴露到
// window.__LIPANEL__，供插件前端使用。
//
// 为什么用动态 import 而不是在 index.html 里再写一个 <script>：
// runtime.js 与 main.js 都依赖同一个 'vue' 模块（Rollup 会把它拆成
// 共享 chunk），动态 import 能保证「共享 chunk 先于 runtime.js 求值」，
// 避免任何求值顺序问题；而静态 import 会为了拿副作用把 runtime 提前
// 拉进主 chunk，反而让 /assets/vue.js 变成空文件。
//
// 为什么不让插件直接 `import '/assets/vue.js'` 或读 window：
// 依赖 window 全局是个隐式契约，插件作者很难发现；importmap 才是
// 标准做法——插件写 `import { ref } from 'vue'`，浏览器自动来取这里。
//
// Naive UI 采用按需引入（见 vite.config.js 的 unplugin-vue-components），
// 此处不 import 任何全局 CSS，保持包体轻量。
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

await import('./runtime.js')

createApp(App).use(router).mount('#app')
