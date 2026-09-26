<script setup>
// 插件前端沙箱容器（阶段三 3.3）。
//
// 职责：把一个插件前端放进 <iframe sandbox="allow-scripts">，
// 通过 PluginFrameBridge 与它通信（协议见 src/plugins/bridge.js）。
//
// 为什么是 `allow-scripts` 而**不含** `allow-same-origin`：
//   · allow-scripts 是必需的（插件前端就是一段脚本）；
//   · 一旦加上 allow-same-origin，iframe 就与宿主同源，
//     沙箱形同虚设——它能读 document.cookie、直连 /api/*，
//     等于回到 3.2 的共享 Realm 状态。
//   两者同时给还会让浏览器警告「allow-scripts + allow-same-origin
//   可以自己摘掉 sandbox」，属于典型的误配。
//
// 这个组件的兜底策略（与工程约束一致，任何一步失败都不能白屏）：
//   1. iframe 一直没握手        → 超时提示 + 重试
//   2. 插件上报错误             → 顶部 n-alert 展示
//   3. 高度没有上报             → 用一个保守的默认高度
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useMessage } from 'naive-ui'
import { PluginFrameBridge, frameSrc } from '@/plugins/bridge'
import { callPluginRaw } from '@/api/plugins'

const props = defineProps({
  // pluginId 是插件唯一标识（路由参数，由宿主页传入）。
  pluginId: { type: String, required: true },
  // plugin 是后端返回的插件元数据。
  plugin: { type: Object, default: null },
})

const message = useMessage()

// frameEl 是 iframe 元素引用；bridge 是通信桥实例。
const frameEl = ref(null)
const bridge = shallowRef(null)

// height 是 iframe 当前高度（由 iframe 内容上报，已 clamp）。
// 初值给一个保守值：等上报到达前也要有可见区域，
// 否则用户会看到一条几乎不可见的缝，以为页面坏了。
const height = ref(240)

// error 是插件沙箱上报的错误；mounted 标记插件前端是否已成功挂载。
const error = ref('')
const mounted = ref(false)

// loadKey 用于「重试」：换 key 让 Vue 销毁并重建 iframe。
const loadKey = ref(0)

// 握手超时：iframe 加载成功但脚本没跑起来（例如 importmap 不被支持、
// 或插件入口 404）时，必须给出提示而不是让用户对着空白等。
let handshakeTimer = null
const HANDSHAKE_TIMEOUT_MS = 15000

const src = computed(() => frameSrc(props.pluginId))

function clearHandshakeTimer() {
  if (handshakeTimer) {
    clearTimeout(handshakeTimer)
    handshakeTimer = null
  }
}

// setupBridge 创建桥并绑定到 iframe。
function setupBridge() {
  teardownBridge()
  error.value = ''
  mounted.value = false

  const fe = frameEl.value
  if (!fe) return

  const b = new PluginFrameBridge({
    pluginId: props.pluginId,
    plugin: props.plugin,
    frame: props.plugin?.frontend || {},
    // 代发请求：由 api/plugins.js 提供，内部走 /api/plugins/<id>/...
    // 路径白名单已在 Bridge 内强制（见 bridge.js 的 buildPluginAPIPath）。
    request: callPluginRaw,
    onError: (msg) => {
      error.value = msg
    },
    onNotify: (text, level) => {
      // 插件请求的提示：这是插件的界面行为，走宿主的 message 组件。
      if (level === 'error') message.error(text)
      else if (level === 'warning') message.warning(text)
      else if (level === 'success') message.success(text)
      else message.info(text)
    },
    onResize: (h) => {
      height.value = h
    },
    onNavigate: (to) => {
      // 站内跳转：用 location.assign 而不是 router.push，
      // 因为插件前端只关心"跳过去"，由宿主路由守卫接管即可。
      window.location.assign(to)
    },
    onMounted: () => {
      mounted.value = true
      clearHandshakeTimer()
    },
  })

  b.attach(fe)
  bridge.value = b

  // iframe 已经加载完（例如热重载场景）时补一次握手请求。
  // 正常情况下 iframe 自己会发 ready，这里只是兜底。
  handshakeTimer = setTimeout(() => {
    if (mounted.value || error.value) return
    error.value =
      `插件沙箱在 ${HANDSHAKE_TIMEOUT_MS / 1000}s 内没有完成握手。` +
      '可能原因：浏览器不支持 import maps（需要 Chrome 89+ / Firefox 108+ / Safari 16.4+），' +
      '或插件前端资源未随程序分发。可点击「重试」或改用兼容模式。'
  }, HANDSHAKE_TIMEOUT_MS)
}

function teardownBridge() {
  clearHandshakeTimer()
  if (bridge.value) {
    bridge.value.dispose()
    bridge.value = null
  }
}

// retry 重建 iframe 与桥。
function retry() {
  teardownBridge()
  loadKey.value += 1
  // 等 DOM 更新后再绑定（nextTick 由 watch 触发路径覆盖，
  // 这里用一个微任务确保新 iframe 已插入）。
  queueMicrotask(setupBridge)
}

onMounted(() => {
  // iframe 元素在这一刻已存在（v-if 未使用），直接绑定。
  setupBridge()
})

onBeforeUnmount(teardownBridge)

// 切换插件（同一路由被复用）时重建。
watch(
  () => props.pluginId,
  () => retry(),
)

// 元数据变化时把新信息推给 iframe（插件状态可能从 stopped 变 running）。
watch(
  () => props.plugin,
  (val) => {
    if (bridge.value && val) {
      bridge.value.plugin = val
      bridge.value.frameInfo = val.frontend || {}
      bridge.value.sendPluginData()
    }
  },
  { deep: true },
)
</script>

<template>
  <div class="plugin-frame">
    <!-- 沙箱上报的错误：显示在 iframe 外面，用户不必点进去才能看到原因 -->
    <n-alert v-if="error" type="error" title="插件前端出现问题" style="margin-bottom: 12px">
      <n-space vertical :size="10">
        <n-text style="white-space: pre-wrap">{{ error }}</n-text>
        <n-space :size="8">
          <n-button size="small" @click="retry">重试</n-button>
        </n-space>
      </n-space>
    </n-alert>

    <!--
      沙箱样式：
        border: none       —— 去掉 iframe 默认边框
        background: transparent —— 让面板背景透过来，避免一块突兀的白底
        display: block     —— 避免 inline 元素底部多出几像素空隙
      高度由内容上报，最小 120px（clamp 在 bridge 内做）。
    -->
    <iframe
      :key="loadKey"
      ref="frameEl"
      :src="src"
      :style="{ height: height + 'px' }"
      class="plugin-frame__iframe"
      sandbox="allow-scripts"
      referrerpolicy="no-referrer"
      loading="eager"
      title="插件沙箱"
    />

    <!-- 挂载中提示：只在还没握手成功时显示，成功后立即隐藏 -->
    <n-text v-if="!mounted && !error" depth="3" style="font-size: 12px">
      插件沙箱加载中…
    </n-text>
  </div>
</template>

<style scoped>
.plugin-frame {
  display: flex;
  flex-direction: column;
}

.plugin-frame__iframe {
  display: block;
  width: 100%;
  border: none;
  background: transparent;
  /* 沙箱内是独立文档，溢出由我们的高度控制接管 */
  overflow: hidden;
}
</style>
