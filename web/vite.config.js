import { fileURLToPath, URL } from 'node:url'
import { writeFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { NaiveUiResolver } from 'unplugin-vue-components/resolvers'

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
            '# 前端构建产物（index.html、assets/）不入库，由 ./build.sh 生成。\n',
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
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // 便于排查产物体积，不做激进拆包（面板首屏很小）。
    chunkSizeWarningLimit: 900,
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
