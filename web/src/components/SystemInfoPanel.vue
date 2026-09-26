<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { fetchSystemInfo, ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
// 格式化函数已抽到 utils/format.js：插件版系统信息视图需要用同一套规则，
// 内联两份会出现「同一个数字在两处显示不一致」的问题。
import { formatBytes, formatUptime, percentStatus, usageText } from '@/utils/format'

const message = useMessage()
const router = useRouter()

// loading 覆盖首屏加载与手动刷新，避免重复请求。
const loading = ref(false)
// error 作为兜底展示：即使 message 弹出失败，页面上也能看到错误原因。
const error = ref('')
const info = ref(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    info.value = await fetchSystemInfo()
  } catch (err) {
    info.value = null
    error.value = err?.message || '未知错误'

    // 会话过期（例如后端重启换了签名密钥）时，清理本地状态并回登录页，
    // 而不是让用户对着一个永远失败的页面反复点刷新。
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/' } })
      return
    }
    message.error(`加载系统信息失败：${error.value}`)
  } finally {
    // 无论成功失败都复位 Loading，防止界面永久转圈。
    loading.value = false
  }
}

onMounted(load)

// 交换分区未启用时单独提示，而不是显示一个恒为 0 的进度条。
const swapEnabled = computed(() => (info.value?.swap?.total_bytes ?? 0) > 0)

// cpuLoadText 把 1/5/15 分钟负载拼成一行。
const cpuLoadText = computed(() => {
  const load = info.value?.cpu?.load_avg
  if (!Array.isArray(load) || load.length < 3) {
    return '-'
  }
  return load.map((v) => v.toFixed(2)).join(' / ')
})
</script>

<template>
  <n-spin :show="loading">
    <n-space vertical :size="16" style="max-width: 960px">
      <!-- 错误优先展示，保证任何失败都有可见原因 -->
      <n-alert v-if="error" type="error" title="无法获取系统信息">
        {{ error }}
      </n-alert>

      <n-alert
        v-if="info?.warnings?.length"
        type="warning"
        title="部分信息采集失败"
      >
        <ul style="margin: 0; padding-left: 18px">
          <li v-for="(w, i) in info.warnings" :key="i">{{ w }}</li>
        </ul>
      </n-alert>

      <template v-if="info">
        <n-card title="系统概况" size="small">
          <template #header-extra>
            <n-button size="small" :loading="loading" @click="load">刷新</n-button>
          </template>

          <n-descriptions :column="2" label-placement="left" bordered size="small">
            <n-descriptions-item label="主机名">
              {{ info.hostname || '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="操作系统">
              {{ info.os || '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="内核版本">
              {{ info.kernel || '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="架构">{{ info.arch || '-' }}</n-descriptions-item>
            <n-descriptions-item label="运行时长">
              {{ formatUptime(info.uptime_seconds) }}
            </n-descriptions-item>
            <n-descriptions-item label="采集时间">
              {{ info.collected_at || '-' }}
            </n-descriptions-item>
          </n-descriptions>
        </n-card>

        <n-grid :cols="2" :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <!-- CPU -->
          <n-grid-item span="2 s:2 m:2 l:1">
            <n-card title="CPU" size="small" style="height: 100%">
              <n-space vertical :size="12">
                <n-text depth="3" style="font-size: 12px; word-break: break-all">
                  {{ info.cpu.model || '未知型号' }}
                </n-text>

                <n-progress
                  type="line"
                  :percentage="info.cpu.usage_percent"
                  :status="percentStatus(info.cpu.usage_percent)"
                  :height="14"
                  :border-radius="4"
                >
                  使用率 {{ info.cpu.usage_percent }}%
                </n-progress>

                <n-descriptions :column="1" label-placement="left" size="small">
                  <n-descriptions-item label="逻辑核心">
                    {{ info.cpu.cores }} 核
                  </n-descriptions-item>
                  <n-descriptions-item label="平均负载">
                    {{ cpuLoadText }}（1 / 5 / 15 分钟）
                  </n-descriptions-item>
                </n-descriptions>
              </n-space>
            </n-card>
          </n-grid-item>

          <!-- 内存 -->
          <n-grid-item span="2 s:2 m:2 l:1">
            <n-card title="内存" size="small" style="height: 100%">
              <n-space vertical :size="12">
                <n-progress
                  type="line"
                  :percentage="info.memory.usage_percent"
                  :status="percentStatus(info.memory.usage_percent)"
                  :height="14"
                  :border-radius="4"
                >
                  使用率 {{ info.memory.usage_percent }}%
                </n-progress>

                <n-descriptions :column="1" label-placement="left" size="small">
                  <n-descriptions-item label="已用 / 总量">
                    {{ usageText(info.memory.used_bytes, info.memory.total_bytes, info.memory.usage_percent) }}
                  </n-descriptions-item>
                  <n-descriptions-item label="可用">
                    {{ formatBytes(info.memory.free_bytes) }}
                  </n-descriptions-item>
                  <n-descriptions-item label="缓存">
                    {{ formatBytes(info.memory.cached_bytes) }}
                  </n-descriptions-item>
                  <n-descriptions-item label="交换分区">
                    <template v-if="swapEnabled">
                      {{ usageText(info.swap.used_bytes, info.swap.total_bytes, info.swap.usage_percent) }}
                    </template>
                    <n-text v-else depth="3">未启用</n-text>
                  </n-descriptions-item>
                </n-descriptions>
              </n-space>
            </n-card>
          </n-grid-item>

          <!-- 磁盘 -->
          <n-grid-item span="2">
            <n-card :title="`磁盘（${info.disk.path}）`" size="small">
              <n-space vertical :size="12">
                <n-progress
                  type="line"
                  :percentage="info.disk.usage_percent"
                  :status="percentStatus(info.disk.usage_percent)"
                  :height="14"
                  :border-radius="4"
                >
                  使用率 {{ info.disk.usage_percent }}%
                </n-progress>

                <n-descriptions :column="3" label-placement="left" size="small">
                  <n-descriptions-item label="总容量">
                    {{ formatBytes(info.disk.total_bytes) }}
                  </n-descriptions-item>
                  <n-descriptions-item label="已用">
                    {{ formatBytes(info.disk.used_bytes) }}
                  </n-descriptions-item>
                  <n-descriptions-item label="可用">
                    {{ formatBytes(info.disk.free_bytes) }}
                  </n-descriptions-item>
                </n-descriptions>
              </n-space>
            </n-card>
          </n-grid-item>
        </n-grid>
      </template>

      <n-card v-else-if="!loading && !error">
        <n-empty description="暂无数据" />
      </n-card>
    </n-space>
  </n-spin>
</template>
