<script setup>
// 插件前端宿主页 —— 「动态挂载插件前端」的挂载点。
//
// 职责非常单一：把路由参数 :id 交给前端注册表，由注册表决定渲染哪个组件。
// 宿主本身不认识任何具体插件，因此新增插件时本文件无需改动。
//
// 三种情况都必须有明确兜底（不能白屏）：
//   1. 插件不存在于后端列表      → 提示可能已被移除
//   2. 插件存在但前端未提供界面  → 提示该插件只有后端能力
//   3. 插件未运行                → 提示先去插件管理页启动
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { fetchPlugins } from '@/api/plugins'
import { resolvePluginView } from '@/plugins/registry'
import AppLayout from '@/layouts/AppLayout.vue'

const route = useRoute()

const pluginId = computed(() => String(route.params.id || ''))

const loading = ref(false)
const error = ref('')
// plugin 是后端返回的该插件元数据；null 表示未找到。
const plugin = ref(null)

// viewComponent 是解析出的插件前端组件；null 表示没有前端实现。
const viewComponent = computed(() => resolvePluginView(plugin.value?.frontend?.entry))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await fetchPlugins()
    const found = (data.plugins || []).find((p) => p.id === pluginId.value)
    plugin.value = found || null
    if (!found) {
      error.value = `未找到插件「${pluginId.value}」，它可能已被移除。`
    }
  } catch (err) {
    plugin.value = null
    error.value = err?.message || '无法加载插件信息'
  } finally {
    loading.value = false
  }
}

onMounted(load)
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
        v-else-if="plugin && !viewComponent"
        type="info"
        title="该插件未提供前端界面"
      >
        插件「{{ plugin.name }}」声明的前端入口为
        <code>{{ plugin.frontend?.entry || '（未声明）' }}</code>，
        但当前前端没有对应的界面实现。
        <template v-if="plugin.description">
          <br />插件说明：{{ plugin.description }}
        </template>
      </n-alert>

      <!-- 正常挂载：把组件交给 Vue 渲染，pluginId 作为 prop 注入 -->
      <component :is="viewComponent" v-else-if="viewComponent" :plugin-id="pluginId" />
    </n-space>
    </n-spin>
  </AppLayout>
</template>
