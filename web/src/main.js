import { createApp } from 'vue'
import App from './App.vue'

// Naive UI 采用按需引入（见 vite.config.js 的 unplugin-vue-components），
// 此处不 import 任何全局 CSS，保持包体轻量。
createApp(App).mount('#app')
