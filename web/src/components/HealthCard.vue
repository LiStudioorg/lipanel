<script setup>
import { onMounted, ref } from 'vue'
import { fetchHealth } from '@/api/client'

// 本组件位于 n-message-provider 内部，可安全使用 useMessage。
const message = useMessage()

// loading 覆盖首屏加载与手动刷新，避免重复请求。
const loading = ref(false)
// error 作为兜底展示：即使 message 弹出失败，页面上也能看到错误原因。
const error = ref('')
const health = ref(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    health.value = await fetchHealth()
  } catch (err) {
    health.value = null
    error.value = err?.message || '未知错误'
    message.error(`探活失败：${error.value}`)
  } finally {
    // 无论成功失败都复位 Loading，防止界面永久转圈。
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <n-spin :show="loading">
    <n-card title="后端连接状态" style="max-width: 640px">
      <template #header-extra>
        <n-button size="small" :loading="loading" @click="load">刷新状态</n-button>
      </template>

      <!-- 错误优先展示，保证任何失败都有可见原因 -->
      <n-alert v-if="error" type="error" title="无法获取后端状态">
        {{ error }}
      </n-alert>

      <n-descriptions v-else-if="health" :column="1" bordered>
        <n-descriptions-item label="状态">
          <n-tag :type="health.status === 'ok' ? 'success' : 'warning'">
            {{ health.status }}
          </n-tag>
        </n-descriptions-item>
        <n-descriptions-item label="版本">{{ health.version }}</n-descriptions-item>
        <n-descriptions-item label="服务器时间">{{ health.time }}</n-descriptions-item>
      </n-descriptions>

      <n-empty v-else description="暂无数据" />
    </n-card>
  </n-spin>
</template>
