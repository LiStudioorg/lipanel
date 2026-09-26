<script setup>
// sysinfo 插件的专属前端界面。
//
// 关键点：本组件的数据**全部来自插件进程**，而不是核心的 /api/system/info。
// 请求路径是 /api/plugins/sysinfo/info —— 核心只做转发，
// 因此这个页面能跑起来，就证明「核心 → 插件进程」的整条链路是通的。
//
// 它同时演示了插件前端的三段式结构（后续外部插件照此实现即可）：
//   1. 调用插件自己的接口（callPlugin）
//   2. Loading / Error 兜底
//   3. 展示数据
import { computed, onMounted, ref } from 'vue'
import { callPlugin } from '@/api/plugins'
import {
  formatBytes,
  formatDuration,
  formatTime,
  formatUptime,
  percentStatus,
  usageText,
} from '@/utils/format'

const props = defineProps({
  // 插件 ID 由宿主页面（PluginHostView）通过路由注入。
  pluginId: { type: String, required: true },
})

const loading = ref(false)
const error = ref('')
// info 是插件返回的完整负载：{ plugin, info: {...} }
const payload = ref(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    payload.value = await callPlugin(props.pluginId, 'info')
  } catch (err) {
    payload.value = null
    // 503 是「插件未运行」，这不是错误而是可操作的状态，
    // 因此单独给一句明确的指引，而不是笼统的「加载失败」。
    error.value =
      err?.status === 503
        ? '插件当前未运行。请到「插件管理」页启动后再回到此页面。'
        : err?.message || '未知错误'
  } finally {
    loading.value = false
  }
}

onMounted(load)

const info = computed(() => payload.value?.info || null)

// cpuLoadText 把 1/5/15 分钟负载拼成一行。
const cpuLoadText = computed(() => {
  const load = info.value?.cpu?.load_avg
  if (!Array.isArray(load) || load.length < 3) return '-'
  return load.map((v) => v.toFixed(2)).join(' / ')
})

// swapEnabled：交换分区未启用时单独提示，而不是显示恒为 0 的进度条。
const swapEnabled = computed(() => (info.value?.swap?.total_bytes ?? 0) > 0)
</script>

<template>
  <n-spin :show="loading">
    <n-space vertical :size="16">
      <n-alert v-if="error" type="error" title="无法从插件获取数据">
        {{ error }}
      </n-alert>

      <n-alert v-if="info?.warnings?.length" type="warning" title="部分信息采集失败">
        <ul style="margin: 0; padding-left: 18px">
          <li v-for="(w, i) in info.warnings" :key="i">{{ w }}</li>
        </ul>
      </n-alert>

      <template v-if="info">
        <n-card title="系统概况（数据来自插件进程）" size="small">
          <template #header-extra>
            <n-space align="center" :size="8">
              <n-tag size="small" type="success" :bordered="false">
                经 Unix socket 转发
              </n-tag>
              <n-button size="small" :loading="loading" @click="load">刷新</n-button>
            </n-space>
          </template>

          <n-descriptions :column="2" label-placement="left" bordered size="small">
            <n-descriptions-item label="插件 ID">
              {{ payload.plugin }}
            </n-descriptions-item>
            <n-descriptions-item label="主机名">
              {{ info.hostname || '-' }}
            </n-descriptions-item>
            <n-descriptions-item label="操作系统">{{ info.os || '-' }}</n-descriptions-item>
            <n-descriptions-item label="内核版本">{{ info.kernel || '-' }}</n-descriptions-item>
            <n-descriptions-item label="架构">{{ info.arch || '-' }}</n-descriptions-item>
            <n-descriptions-item label="运行时长">
              {{ formatUptime(info.uptime_seconds) }}
            </n-descriptions-item>
            <n-descriptions-item label="采集时间">
              {{ formatTime(info.collected_at) }}
            </n-descriptions-item>
          </n-descriptions>
        </n-card>

        <n-grid :cols="2" :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <!-- CPU -->
          <n-grid-item span="2 s:2 m:2 l:1">
            <n-card title="CPU" size="small" style="height: 100%">
              <n-space vertical :size="12">
                <n-text depth="3" style="font-size: 12px; word-break: break-all">
                  {{ info.cpu?.model || '未知型号' }}
                </n-text>
                <n-progress
                  type="line"
                  :percentage="info.cpu?.usage_percent ?? 0"
                  :status="percentStatus(info.cpu?.usage_percent ?? 0)"
                  :height="14"
                  :border-radius="4"
                />
                <n-space justify="space-between">
                  <n-text depth="3">核心数：{{ info.cpu?.cores ?? '-' }}</n-text>
                  <n-text depth="3">负载(1/5/15m)：{{ cpuLoadText }}</n-text>
                </n-space>
              </n-space>
            </n-card>
          </n-grid-item>

          <!-- 内存 -->
          <n-grid-item span="2 s:2 m:2 l:1">
            <n-card title="内存" size="small" style="height: 100%">
              <n-space vertical :size="12">
                <n-progress
                  type="line"
                  :percentage="info.memory?.usage_percent ?? 0"
                  :status="percentStatus(info.memory?.usage_percent ?? 0)"
                  :height="14"
                  :border-radius="4"
                />
                <n-text depth="3">
                  已用 {{ formatBytes(info.memory?.used_bytes) }} /
                  总计 {{ formatBytes(info.memory?.total_bytes) }}
                </n-text>
                <n-space justify="space-between">
                  <n-text depth="3">可用：{{ formatBytes(info.memory?.free_bytes) }}</n-text>
                  <n-text depth="3">缓存：{{ formatBytes(info.memory?.cached_bytes) }}</n-text>
                </n-space>

                <n-divider style="margin: 4px 0" />

                <template v-if="swapEnabled">
                  <n-text depth="3">交换分区</n-text>
                  <n-progress
                    type="line"
                    :percentage="info.swap?.usage_percent ?? 0"
                    :status="percentStatus(info.swap?.usage_percent ?? 0)"
                    :height="10"
                    :border-radius="4"
                  />
                  <n-text depth="3" style="font-size: 12px">
                    {{ usageText(info.swap?.used_bytes, info.swap?.total_bytes, info.swap?.usage_percent) }}
                  </n-text>
                </template>
                <n-text v-else depth="3" style="font-size: 12px">交换分区未启用</n-text>
              </n-space>
            </n-card>
          </n-grid-item>

          <!-- 磁盘 -->
          <n-grid-item span="2">
            <n-card size="small" :title="`磁盘 ${info.disk?.path || '/'}`">
              <n-space vertical :size="12">
                <n-progress
                  type="line"
                  :percentage="info.disk?.usage_percent ?? 0"
                  :status="percentStatus(info.disk?.usage_percent ?? 0)"
                  :height="14"
                  :border-radius="4"
                />
                <n-space justify="space-between">
                  <n-text depth="3">
                    已用 {{ formatBytes(info.disk?.used_bytes) }} /
                    总计 {{ formatBytes(info.disk?.total_bytes) }}
                  </n-text>
                  <n-text depth="3">可用：{{ formatBytes(info.disk?.free_bytes) }}</n-text>
                </n-space>
              </n-space>
            </n-card>
          </n-grid-item>
        </n-grid>

        <n-alert type="info" :bordered="false" title="这条数据是怎么来的">
          本页数据取自插件进程
          <code>{{ payload.plugin }}</code>
          ：核心收到 <code>/api/plugins/{{ payload.plugin }}/info</code> 后，
          经 Unix socket 转发给插件处理。可与「系统概览」页的核心直连接口对比。
        </n-alert>
      </template>
    </n-space>
  </n-spin>
</template>
