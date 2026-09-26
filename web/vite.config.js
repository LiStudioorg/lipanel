import { fileURLToPath, URL } from 'node:url'
import { writeFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { NaiveUiResolver } from 'unplugin-vue-components/resolvers'

// RUNTIME_RENAMES 是需要改名的入口：**产物文件名** → 固定的运行时路径。
//
//   src/runtime.js          → /assets/vue.js
//     宿主页面 importmap 里裸说明符 "vue" 的目标（3.2 起）
//   src/frame-runtime.js    → /assets/plugin-runtime.js
//     插件沙箱 iframe 里 importmap 的目标（3.3 新增）
//
// 两者都必须落在**不带内容哈希**的固定路径上，否则 importmap 没法写死目标；
// 而 Vite 默认给入口 chunk 带哈希，因此只能在构建期改名。
//
// 注意 key 用的是**产物名**：rollupOptions.input 的键是 frameRuntime
// （驼峰入口名），Vite 产出的是 assets/frameRuntime.js，
// 与源文件名 frame-runtime.js 并不一致（3.3 踩过坑，见「已知坑位」41）。
//
// 放在模块作用域的原因：renderChunk（改代码引用）与 generateBundle（改文件名）
// 必须使用**同一份**映射，否则两者一旦漂移就会产出「引用不存在文件」的产物。
const RUNTIME_RENAMES = {
  'assets/runtime.js': 'assets/vue.js',
  'assets/frameRuntime.js': 'assets/plugin-runtime.js',
}

// 构建产物直接输出到 web/dist，供 Go 的 go:embed 打包进单二进制。
export default defineConfig({
  plugins: [
    vue(),
    // go:embed 要求 web/dist 非空，而 emptyOutDir 会清空整个目录。
    // 构建后补回占位文件，避免每次构建都“删除”被 Git 跟踪的 .gitkeep。
    {
      name: 'lipanel-keep-dist-placeholder',
      closeBundle() {
        const keep = fileURLToPath(new URL('./dist/.gitkeep', import.meta.url))
        writeFileSync(
          keep,
          '# 占位文件：go:embed 需要目标目录非空，请勿删除。\n' +
            '# 前端构建产物（index.html、assets/、plugin-assets/）不入库，由 ./build.sh 生成。\n',
        )
      },
    },
    // 按需自动引入 Naive UI 组件：只有用到的组件才会被打包，
    // 不需要在 main.js 里全量注册，也不引入重型全局 CSS。
    AutoImport({
      imports: [
        'vue',
        {
          'naive-ui': ['useMessage', 'useDialog', 'useNotification', 'useLoadingBar'],
        },
      ],
      dts: false,
    }),
    Components({
      resolvers: [NaiveUiResolver()],
      dts: false,
    }),
    // 开发态：把 /assets/vue.js 变成「从源码 re-export Vue」的模块。
    //
    // 为什么需要这个中间件：importmap 把裸说明符 "vue" 指向固定的
    // /assets/vue.js，而该路径只在**构建产物**里存在（见下面 rollupOptions
    // 的 runtime 入口）。dev 下它并不存在，Vite 会把请求落到 SPA 兜底，
    // 返回 200 + text/html——浏览器按 MIME 检查会拒绝执行，
    // 表现为「dev 下插件前端加载失败、构建后却正常」这种极难排查的偏差。
    //
    // 这里直接返回一段 re-export 源码，由 Vite 自己转换：
    // 走 /node_modules/.vite/deps 的预构建 Vue，与主应用用的是**同一个
    // 模块实例**（同样的裸说明符、同样的 URL），因此 dev 与线上语义一致。
    {
      name: 'lipanel-dev-runtime-entry',
      apply: 'serve',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const path = (req.url || '').split('?')[0]

          if (path === '/assets/vue.js') {
            res.setHeader('Content-Type', 'text/javascript')
            res.setHeader('Cache-Control', 'no-cache')
            res.end(
              "import * as vue from 'vue'\n" +
                'window.__LIPANEL__ = { ...(window.__LIPANEL__ || {}), vue }\n',
            )
            return
          }

          // 插件沙箱 iframe 的 Vue 入口（阶段三 3.3）。
          //
          // 与 /assets/vue.js 同样的道理：它是 importmap 指向的**固定路径**，
          // 所以 dev 下也必须真的存在且 Content-Type 是 JS。
          // 否则 iframe 里的 `import 'vue'` 会拿到 SPA 兜底的 200 + text/html，
          // 被浏览器按 MIME 拒绝执行，表现为「dev 下插件沙箱白屏、构建后正常」。
          // 内容与源码 web/plugins/plugin-assets/frame/plugin-runtime.js 等价，
          // 但由 Vite 转换其 `import 'vue'`（保证与 iframe 内插件解析到同一个实例）。
          if (path === '/assets/plugin-runtime.js') {
            res.setHeader('Content-Type', 'text/javascript')
            res.setHeader('Cache-Control', 'no-cache')
            res.end(
              "import * as vue from 'vue'\n" +
                'const host = window.__LIPANEL__\n' +
                'if (host) {\n' +
                '  host.vue = vue\n' +
                "  if (typeof host.__resolveVue === 'function') host.__resolveVue(vue)\n" +
                '  delete host.__resolveVue\n' +
                '  delete host.__rejectVue\n' +
                '}\n',
            )
            return
          }

          return next()
        })
      },
    },

    // 构建态：把入口 chunk runtime.js 改名为 vue.js。
    //
    // 为什么必须改名：index.html 的 importmap 把裸说明符 "vue" 固定指向
    // /assets/vue.js（稳定路径，不能带内容哈希）。而 rollupOptions 里的入口
    // 名是 runtime（源文件 src/runtime.js），Vite 会产出 assets/runtime.js。
    // 若不做这一步，importmap 指向的 /assets/vue.js **根本不存在**，
    // 请求会落到 SPA 兜底返回 index.html，浏览器按 MIME 拒绝执行，
    // 表现为「主应用正常、插件前端加载失败」。
    //
    // 实现方式：见下方 renderChunk（改代码引用）与 generateBundle（改文件名）两个钩子。
    //
    // ⚠️ 改名必须**同时**处理两处，缺一不可（下面两个钩子各负责一处）：
    //
    //   ① 文件命名        → generateBundle 改 chunk.fileName 及相关元数据
    //   ② **代码里的引用** → renderChunk 改代码字符串
    //
    // 只做 ① 是一个真实发生过的 P1 缺陷：generateBundle 里改 fileName
    // 只影响 Rollup 的元数据，**不会**触碰已经生成好的代码字符串。
    // main.js 用的是 `await import('./runtime.js')`，产物里就写死成
    // `import("./runtime.js")`——文件已改名，引用还是旧名，
    // 浏览器去请求 /assets/runtime.js 拿到 SPA 兜底的 index.html
    // （200 但 Content-Type: text/html），模块按 MIME 被拒绝执行，
    // **整个页面白屏**。而 dev 模式走源码路径、根本没有这个改名，
    // 所以只在生产构建里复现，极难排查。
    //
    // 为什么用 renderChunk 而不是在 generateBundle 里改 code：
    // renderChunk 处于「代码已生成、即将写入 bundle」的阶段，
    // 此处返回新 code 会被 Rollup 正常采纳；而 generateBundle 阶段
    // 代码已定稿，改 code 属于事后打补丁且不一定生效。
    // 职责因此更清晰：renderChunk 管代码内容，generateBundle 管文件命名。
    //
    // 这里必须用闭包里的 this 而非箭头函数——Rollup 通过 this 暴露插件上下文。
    {
      name: 'lipanel-runtime-entry',
      apply: 'build',

      // ---------- ① 代码内容：替换对已改名 chunk 的引用 ----------
      renderChunk(code, chunk) {
        // 只处理「代码里真的出现了旧路径」的 chunk，其余返回 null
        // （表示不改动），既省开销也彻底排除误伤其它 chunk 的可能。
        //
        // 安全性说明（为什么这些替换不会误伤）：
        //   替换目标是**带路径前缀的具体文件名**（"runtime.js" 前必须有
        //   "./" 或 "assets/"），而不是裸词 "runtime"。因此：
        //     · 不会命中变量名（如 const runtime = ...）；
        //     · 不会命中其它 chunk（如 runtime-dom.esm-bundler-XXXX.js，
        //       因为它不以 ./runtime.js 或 assets/runtime.js 结尾）；
        //     · 不会命中普通文本（前后缀已经限定它是模块说明符形态）。
        //
        // 映射直接由 RUNTIME_RENAMES 推导，避免两处清单各自维护而漂移：
        //   assets/runtime.js → 相对形态 ./runtime.js 与绝对形态 assets/runtime.js
        const replacements = Object.entries(RUNTIME_RENAMES).flatMap(([from, to]) => {
          const base = from.replace(/^assets\//, '')
          const toBase = to.replace(/^assets\//, '')
          return [
            // 相对说明符：动态 import('./runtime.js') / import "./runtime.js"
            [`./${base}`, `./${toBase}`],
            // 绝对形式：Rollup 在解析 base 或 import.meta.url 后可能产出此形态
            [from, to],
          ]
        })

        let next = code
        let changed = false
        for (const [from, to] of replacements) {
          if (next.includes(from)) {
            next = next.split(from).join(to)
            changed = true
          }
        }

        if (!changed) return null

        this.info(
          `[lipanel-runtime-entry] ${chunk.fileName}: ` +
            '已把代码中的 runtime.js 引用重写为 vue.js',
        )
        return { code: next, map: null }
      },

      // ---------- ② 文件命名：把入口 chunk 改成固定路径 ----------
      generateBundle(_options, bundle) {
        // 先校验所有需要改名的入口都真实存在。
        // 静默跳过是 3.3 踩过的坑（改名没生效却毫无提示），
        // 而这里的失败后果更严重：产物会引用一个根本不存在的路径。
        // 因此缺一个就**直接让构建失败**，绝不产出一个「构建成功但
        // 运行时白屏」的二进制。
        const missing = Object.keys(RUNTIME_RENAMES).filter((from) => !bundle[from])
        if (missing.length > 0) {
          this.error(
            `[lipanel-runtime-entry] 期望的入口 chunk 不存在: ${missing.join(', ')}。` +
              '请检查 rollupOptions.input 的入口名与 entryFileNames 是否与本插件同步。',
          )
        }

        for (const [from, to] of Object.entries(RUNTIME_RENAMES)) {
          bundle[from].fileName = to
        }

        // 同步修正引用这些 chunk 的其它 bundle 的**元数据**
        // （index.html 的 script src、动态 import 记录等）。
        // 注意：这里只改元数据，代码字符串由上面的 renderChunk 负责。
        const resolve = (name) => RUNTIME_RENAMES[name] || name
        for (const item of Object.values(bundle)) {
          if (item.type !== 'chunk') continue
          if (item.imports) item.imports = item.imports.map(resolve)
          if (item.dynamicImports) item.dynamicImports = item.dynamicImports.map(resolve)
        }
      },
    },
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  // publicDir 是「插件前端源码」目录（阶段三 3.2 起）。
  //
  // Vite 会把它的内容原样拷贝到**输出目录根部**，因此源码多留一层
  // plugin-assets，让构建产物与源码路径逐段对应：
  //
  //   web/plugins/plugin-assets/<id>/plugin.js   （源码，入库）
  //     → dist/plugin-assets/<id>/plugin.js      （产物，进 embed）
  //
  // 产物路径 = 源码路径去掉 web/plugins 前缀，而前端在浏览器里请求的
  // 正是 /plugin-assets/<id>/plugin.js，三者一眼可对上。
  //
  // 额外的好处：
  //   - 内置插件前端与插件后端（internal/plugin/builtin/<id>/）结构对称；
  //   - 构建产物里的 JS 保持可读，插件作者直接看构建结果就能调试；
  //   - 插件前端不经过 Vite 打包，因此不能使用 .vue 单文件与 @ 别名，
  //     只能依赖 importmap 里的 'vue'
  //     （详见 web/plugins/plugin-assets/README.md）。
  publicDir: 'plugins',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // 浏览器目标：与「插件前端依赖 import maps」的取舍保持一致
    // （支持 import maps 的最低版本见 web/plugins/plugin-assets/README.md）。
    //
    // 默认目标（chrome87/safari14...）不允许顶层 await，而 main.js 正是
    // 用 `await import('./runtime.js')` 保证共享 chunk 先于 runtime 求值。
    // 把目标提到支持 import maps 的版本，两个决策就对齐了：
    // 能被支持的浏览器必然也支持 import maps。
    target: ['chrome89', 'edge89', 'firefox108', 'safari16.4'],
    // 便于排查产物体积，不做激进拆包（面板首屏很小）。
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      input: {
        // 主应用入口（index.html）。
        index: fileURLToPath(new URL('./index.html', import.meta.url)),
        // 插件依赖入口：把宿主那份 Vue 实例暴露出去。
        //
        // 单独一个入口是必须的：index.html 的 importmap 需要把裸说明符
        // "vue" 固定指向一个**稳定路径**（/assets/vue.js），而带哈希的
        // 资源名做不到这一点。做法见本文件末尾的 lipanel-runtime-entry 插件。
        runtime: fileURLToPath(new URL('./src/runtime.js', import.meta.url)),
        // 插件沙箱 iframe 的 Vue 入口（阶段三 3.3）。
        // iframe 是 opaque origin，无法直接用宿主 window 上的 Vue，
        // 必须在自己的 Realm 里加载一份 → 由它提供固定路径 /assets/plugin-runtime.js。
        frameRuntime: fileURLToPath(new URL('./src/frame-runtime.js', import.meta.url)),
      },
      output: {
        // 只对入口 chunk 固定命名；带哈希的普通 chunk 仍走默认策略。
        //
        // 注意不要改成 chunkFileNames：那会波及 index.html 引用的主 chunk，
        // 页面直接白屏。这里只固定入口名，且入口只有 runtime 一个非 HTML 入口。
        // runtime 与 frameRuntime 都要固定名（它们各自的 importmap 需要稳定路径）；
        // 其余入口仍带哈希。
        entryFileNames: (chunk) =>
          chunk.name === 'runtime' || chunk.name === 'frameRuntime'
            ? 'assets/[name].js'
            : 'assets/[name]-[hash].js',
      },
    },
  },
  server: {
    port: 5173,
    // 开发时把 /api 代理到 Go 后端，前后端可分别热更新。
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
