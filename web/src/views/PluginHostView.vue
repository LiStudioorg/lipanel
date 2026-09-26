<script setup>
// 插件前端宿主页 —— 「动态挂载插件前端」的挂载点。
//
// 职责非常单一：把路由参数 :id 交给前端注册表，由注册表动态 import
// 插件自带的 ESM 入口并渲染。宿主本身不认识任何具体插件，
// 因此新增插件时本文件无需改动。
//
// 四种情况都必须有明确兜底（不能白屏）：
//   1. 插件不存在于后端列表        → 提示可能已被移除
//   2. 插件存在但未声明前端入口    → 提示该插件只有后端能力
//   3. 声明了入口但加载失败        → 展示具体原因 + 重试（3.2 新增）
//   4. 插件未运行                  → 提示先去插件管理页启动
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { fetchPlugins } from '@/api/plugins'
import {
  applyPlugins,
  clearPluginView,
  getPluginLoadError,
  resolvePluginView,
} from '@/plugins/registry'
import AppLayout from '@/layouts/AppLayout.vue'

const route = useRoute()

const pluginId = computed(() => String(route.params.id || ''))

const loading = ref(false)
const error = ref('')
// plugin 是后端返回的该插件元数据；null 表示未找到。
const plugin = ref(null)
// loadError 是插件前端模块加载失败的原因（由 loader 记录）。
const loadError = ref('')
// viewKey 用于「重试」：改变 key 强制 Vue 销毁并重新创建异步组件。
const viewKey = ref(0)

// 是否有前端入口（同步判定：只看清单，不触发加载）。
const hasFrontend = computed(() => Boolean(plugin.value?.frontend?.entry))

// viewComponent 只在「确实声明了入口」时解析，避免无谓的加载尝试。
const viewComponent = computed(() => (hasFrontend.value ? resolvePluginView(pluginId.value) : null))

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
  // 换 key 让 Vue 丢弃上一个（失败的）异步组件实例并重新加载。
  viewKey.value += 1
}

onMounted(load)

// 切换插件时重新加载元数据（同一宿主页会被不同 :id 复用）。
watch(pluginId, () => {
  viewKey.value += 1
  load()
})
</script>

<template>
  <AppLayout>
    <n-spin :show="loading">
    <n-space vertical :size="16">
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

      <!-- 3.2 新增：声明了入口但模块加载失败。
           必须把原因和「怎么办」都写出来，否则用户只看到一个空白页。 -->
      <n-alert v-else-if="loadError" type="error" title="插件前端加载失败">
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

      <!-- 正常挂载：把动态加载到的组件交给 Vue 渲染。
           pluginId / plugin 两个 prop 是插件前端的契约。 -->
      <component
        :is="viewComponent"
        v-else-if="viewComponent"
        :key="viewKey"
        :plugin-id="pluginId"
        :plugin="plugin"
        @error="loadError = $event"
      />
    </n-space>
    </n-spin>
  </AppLayout>
</template>
