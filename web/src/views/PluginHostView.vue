<script setup>
// 插件前端宿主页 —— 插件的挂载点。
//
// 阶段三 3.2：把路由参数 :id 交给前端注册表，动态 import 插件自带的 ESM。
// 阶段三 3.3：**默认改为 sandbox iframe 强隔离**（见 components/PluginFrame.vue）。
//
// 两种模式的区别（这是本页最重要的概念）：
//
//   隔离模式（默认）  sandbox iframe + postMessage 桥
//                     插件代码跑在 opaque origin 里，读不到 document.cookie，
//                     也无法直连 /api/*；要数据只能请宿主代取。
//                     ← 用于运行不完全信任的插件前端。
//
//   兼容模式（?legacy=1 或 frontend.legacy=true）
//                     3.2 的做法：与宿主共享 Realm，动态 import 后直接渲染。
//                     插件能用宿主的 fetch 与会话、能读 cookie。
//                     ← 只应在插件前端完全可信时使用。
//
// 兼容模式被保留（而不是删掉）的原因：迁移期需要一个对照物来定位
// 「是插件的问题还是沙箱的问题」，同时让已有的可信插件不被破坏。
// 但它**必须显式开启**：默认永远是安全的那一种。
//
// 四种情况都必须有明确兜底（不能白屏）：
//   1. 插件不存在于后端列表        → 提示可能已被移除
//   2. 插件存在但未声明前端入口    → 提示该插件只有后端能力
//   3. 声明了入口但加载失败        → 展示具体原因 + 重试
//   4. 插件未运行                  → 提示先去插件管理页启动
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchPlugins } from '@/api/plugins'
import {
  applyPlugins,
  clearPluginView,
  getPluginLoadError,
  resolvePluginView,
} from '@/plugins/registry'
import AppLayout from '@/layouts/AppLayout.vue'
import PluginFrame from '@/components/PluginFrame.vue'

const route = useRoute()
const router = useRouter()

const pluginId = computed(() => String(route.params.id || ''))

const loading = ref(false)
const error = ref('')
// plugin 是后端返回的该插件元数据；null 表示未找到。
const plugin = ref(null)
// loadError 是插件前端模块加载失败的原因（兼容模式下的 loader 记录）。
const loadError = ref('')
// viewKey 用于「重试」：改变 key 强制 Vue 销毁并重新创建组件。
const viewKey = ref(0)

// ---------- 隔离模式 / 兼容模式 ----------

// legacyQuery 记录 URL 上是否显式要求兼容模式。
const legacyQuery = computed(() => String(route.query.legacy || '') === '1')

// sandboxDisabled 表示插件自己声明「我这个前端要跑在宿主 Realm 里」。
// 这是一个**插件主动放弃隔离**的开关，后端 Descriptor.Frontend 里可设。
const sandboxDisabled = computed(() => plugin.value?.frontend?.sandbox === false)

// isolated 决定用哪种模式。默认隔离（true）。
const isolated = computed(() => !legacyQuery.value && !sandboxDisabled.value)

// hasFrontend 是否有前端入口（同步判定：只看清单，不触发加载）。
const hasFrontend = computed(() => Boolean(plugin.value?.frontend?.entry))

// viewComponent 只在「兼容模式 + 确实声明了入口」时解析。
// 隔离模式下不走这条路径，插件的 ESM 由 iframe 自己加载。
const viewComponent = computed(() =>
  !isolated.value && hasFrontend.value ? resolvePluginView(pluginId.value) : null,
)

// toggleMode 在两种模式间切换（写进 URL，便于刷新后保持与分享链接）。
function toggleMode() {
  router.replace({
    query: { ...route.query, legacy: isolated.value ? '1' : undefined },
  })
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await fetchPlugins()
    const list = data.plugins || []
    // 关键：先把后端元数据登记进注册表，再解析组件。
    // 注册表的判定是同步的，因此这一步必须在 viewComponent 求值之前完成。
    applyPlugins(list)

    const found = list.find((p) => p.id === pluginId.value)
    plugin.value = found || null
    if (!found) {
      error.value = `未找到插件「${pluginId.value}」，它可能已被移除。`
    }
    loadError.value = getPluginLoadError(pluginId.value)
  } catch (err) {
    plugin.value = null
    error.value = err?.message || '无法加载插件信息'
  } finally {
    loading.value = false
  }
}

// retry 清掉失败记录并重新挂载插件前端。
//
// 只清该插件的缓存，不清整页：用户可能只是改了插件文件想重载，
// 刷新整页会丢掉其它页面的状态。
function retry() {
  loadError.value = ''
  clearPluginView(pluginId.value)
  // 换 key 让 Vue 丢弃上一个（失败的）组件实例并重新加载。
  viewKey.value += 1
}

onMounted(load)

// 切换插件时重新加载元数据（同一宿主页会被不同 :id 复用）。
watch(pluginId, () => {
  viewKey.value += 1
  load()
})

// 切换模式时也重建视图：两种模式加载的是完全不同的东西，
// 复用同一个实例会让状态串味（例如沙箱的 error 留在兼容模式界面上）。
watch(isolated, () => {
  viewKey.value += 1
  loadError.value = ''
})
</script>

<template>
  <AppLayout>
    <n-spin :show="loading">
    <n-space vertical :size="16">
      <!-- 当前加载模式：把「插件跑在哪」明确告诉用户。
           隔离模式是安全的默认值，兼容模式必须显眼地标出来。 -->
      <n-alert v-if="plugin && hasFrontend" :type="isolated ? 'success' : 'warning'" size="small">
        <n-space align="center" justify="space-between">
          <n-text style="font-size: 13px">
            <template v-if="isolated">
              <strong>隔离模式</strong>：插件前端运行在 sandbox iframe 中（无同源权限），
              读不到会话 Cookie，也无法直连 <code>/api/*</code>，需数据时经 postMessage 请宿主代取。
            </template>
            <template v-else>
              <strong>兼容模式（不安全）</strong>：插件前端与宿主共享 Realm，
              可读取 <code>document.cookie</code> 并直连 <code>/api/*</code>。
              仅应在插件前端完全可信时使用。
            </template>
          </n-text>
          <n-button size="tiny" quaternary @click="toggleMode">
            {{ isolated ? '改用兼容模式' : '回到隔离模式' }}
          </n-button>
        </n-space>
      </n-alert>

      <!-- 插件未运行时，这里就是最直接的提示位（插件自己的视图也会再提示一次） -->
      <n-alert
        v-if="plugin && plugin.state !== 'running'"
        type="warning"
        title="插件未运行"
      >
        插件「{{ plugin.name }}」当前状态为
        <strong>{{ plugin.state }}</strong>，其接口暂时不可用。
        请到
        <router-link :to="{ name: 'plugin-list' }">插件管理</router-link>
        页启动后再回到此页面。
      </n-alert>

      <n-alert v-if="error" type="error" title="无法打开插件页面">
        {{ error }}
      </n-alert>

      <!-- 插件存在但前端没有实现：说明这是「只有后端能力」的插件 -->
      <n-alert
        v-else-if="plugin && !hasFrontend"
        type="info"
        title="该插件未提供前端界面"
      >
        插件「{{ plugin.name }}」没有声明前端入口（<code>frontend.entry</code>），
        因此它只提供后端能力。
        <template v-if="plugin.description">
          <br />插件说明：{{ plugin.description }}
        </template>
      </n-alert>

      <!-- 声明了入口但隔离模式下的沙箱加载失败（3.2 起就有这条兜底，
           3.3 把「加载失败」拆成沙箱内与沙箱外两种展示位置） -->
      <template v-else-if="plugin && hasFrontend">
        <n-alert v-if="!isolated && loadError" type="error" title="插件前端加载失败">
          <n-space vertical :size="10">
            <n-text>{{ loadError }}</n-text>
            <n-text depth="3" style="font-size: 12px">
              入口地址：<code>{{ plugin?.frontend?.entry }}</code>
              <template v-if="plugin?.frontend?.assets">
                <br />资源基址：<code>{{ plugin.frontend.assets }}</code>
              </template>
              （加载失败时会自动尝试基址下的 <code>plugin.js</code> 兜底）
            </n-text>
            <n-space :size="8">
              <n-button size="small" @click="retry">重试</n-button>
              <n-button size="small" @click="load">刷新插件信息</n-button>
            </n-space>
          </n-space>
        </n-alert>

        <!-- 隔离模式：沙箱容器（内部自己处理加载中/失败/重试） -->
        <PluginFrame
          v-else-if="isolated"
          :key="viewKey"
          :plugin-id="pluginId"
          :plugin="plugin"
        />

        <!-- 兼容模式：把动态加载到的组件交给 Vue 渲染。
             pluginId / plugin 两个 prop 是插件前端的契约（两种模式一致）。 -->
        <component
          v-else-if="viewComponent"
          :is="viewComponent"
          :key="viewKey"
          :plugin-id="pluginId"
          :plugin="plugin"
          @error="loadError = $event"
        />
      </template>
    </n-space>
    </n-spin>
  </AppLayout>
</template>
