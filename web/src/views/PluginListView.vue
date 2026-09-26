<script setup>
// 插件管理页。
//
// 本阶段（3.1）只做「展示内置插件 + 启停」，不支持安装/卸载外部插件。
//
// 交互约定（与工程约束一致）：
//   - 所有操作都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 启停这类有副作用的操作走二次确认
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import {
  checkPluginHealth,
  fetchPlugins,
  restartPlugin,
  startPlugin,
  stopPlugin,
} from '@/api/plugins'
import { applyPlugins, hasPluginView, resolveNavIcon } from '@/plugins/registry'
import { formatDuration, formatTime } from '@/utils/format'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const plugins = ref([])
const socketDir = ref('')

// busy 记录每个插件正在执行的操作，用于按钮级 Loading。
// 用对象而不是单个布尔量：操作 A 插件时不该让 B 插件的按钮也转圈。
const busy = ref({})

// 自动刷新定时器：插件崩溃是异步发生的，管理页应当能自己发现，
// 而不是等用户手动刷新才看到「失败」状态。
let timer = null
const AUTO_REFRESH_MS = 5000

function isBusy(id) {
  return Boolean(busy.value[id])
}

function setBusy(id, value) {
  busy.value = { ...busy.value, [id]: value }
}

async function load({ silent = false } = {}) {
  // silent 用于自动刷新：不显示整页 Loading，避免界面每 5 秒闪一次。
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchPlugins()
    plugins.value = data.plugins || []
    socketDir.value = data.socket_dir || ''
    // 登记前端入口：下面 hasPluginView(p.id) 的同步判定依赖它。
    applyPlugins(plugins.value)
  } catch (err) {
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/plugins' } })
      return
    }
    // 自动刷新失败时不覆盖已有列表，只记录错误：
    // 网络抖动一下就把整个列表清空，比不刷新更糟。
    error.value = err?.message || '未知错误'
    if (!silent) {
      plugins.value = []
    }
  } finally {
    if (!silent) loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(() => load({ silent: true }), AUTO_REFRESH_MS)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

// runAction 统一处理「执行操作 → 提示结果 → 刷新列表」的流程。
async function runAction(plugin, actionName, fn, successText) {
  setBusy(plugin.id, true)
  try {
    await fn(plugin.id)
    message.success(successText)
    await load({ silent: true })
  } catch (err) {
    // external 模式停止时后端返回 409 并附带新状态：
    // 这不是纯粹的失败，需要把原因说清楚，同时刷新界面。
    const detail = err?.message || '未知错误'
    message.error(`${actionName}失败：${detail}`)
    error.value = `${actionName}「${plugin.name}」失败：${detail}`
    await load({ silent: true })
  } finally {
    setBusy(plugin.id, false)
  }
}

function confirmStart(plugin) {
  // 启动是会真实拉起进程的操作，给一次确认。
  dialog.info({
    title: '确认启动插件',
    content: `即将启动插件「${plugin.name}」（${plugin.id}）。核心会拉起独立进程并等待其就绪。`,
    positiveText: '启动',
    negativeText: '取消',
    onPositiveClick: () =>
      runAction(plugin, '启动', startPlugin, `插件「${plugin.name}」已启动`),
  })
}

function confirmStop(plugin) {
  dialog.warning({
    title: '确认停止插件',
    content: `即将停止插件「${plugin.name}」。停止后其接口将不可访问。`,
    positiveText: '停止',
    negativeText: '取消',
    onPositiveClick: () => runAction(plugin, '停止', stopPlugin, `插件「${plugin.name}」已停止`),
  })
}

function confirmRestart(plugin) {
  dialog.warning({
    title: '确认重启插件',
    content: `即将重启插件「${plugin.name}」。重启期间其接口会短暂不可用。`,
    positiveText: '重启',
    negativeText: '取消',
    onPositiveClick: () =>
      runAction(plugin, '重启', restartPlugin, `插件「${plugin.name}」已重启`),
  })
}

function doHealth(plugin) {
  return runAction(plugin, '健康探测', checkPluginHealth, `插件「${plugin.name}」健康探测通过`)
}

// openPlugin 跳转到插件自己的页面。
function openPlugin(plugin) {
  router.push({ name: 'plugin-view', params: { id: plugin.id } })
}

// ---------- 展示辅助 ----------

// stateMeta 把后端状态映射为标签文案与颜色。
const stateMeta = {
  running: { type: 'success', text: '运行中' },
  stopped: { type: 'default', text: '已停止' },
  failed: { type: 'error', text: '失败' },
}

function stateOf(state) {
  return stateMeta[state] || { type: 'warning', text: state || '未知' }
}

// modeText 说明插件的运行模式。
function modeText(mode) {
  if (mode === 'managed') return '核心托管'
  if (mode === 'external') return '外部托管'
  return mode || '-'
}

const runningCount = computed(() => plugins.value.filter((p) => p.state === 'running').length)
const summary = computed(() => `共 ${plugins.value.length} 个插件，${runningCount.value} 个运行中`)
</script>

<template>
  <AppLayout>
    <n-space vertical :size="16">
    <n-card size="small">
      <template #header>
        <n-space align="center" :size="10">
          <span>插件管理</span>
          <n-tag size="small" :bordered="false" type="info">{{ summary }}</n-tag>
        </n-space>
      </template>
      <template #header-extra>
        <n-button size="small" :loading="loading" @click="load()">刷新</n-button>
      </template>

      <n-space vertical :size="12">
        <n-text depth="3" style="font-size: 12px">
          当前版本仅支持内置插件（编译进主程序）。
          核心通过 Unix socket 与插件进程通讯，请求路径
          <code>/api/plugins/&lt;id&gt;/*</code> 会被转发给对应插件。
          <template v-if="socketDir">
            <br />Socket 目录：<code>{{ socketDir }}</code>
          </template>
        </n-text>

        <n-alert v-if="error" type="error" title="操作或加载出现问题">
          {{ error }}
        </n-alert>
      </n-space>
    </n-card>

    <n-spin :show="loading">
      <!-- 空列表也要有明确提示，避免用户以为页面坏了 -->
      <n-empty
        v-if="!loading && plugins.length === 0"
        description="没有可用的插件"
        style="padding: 40px 0"
      />

      <n-space v-else vertical :size="12">
        <n-card v-for="p in plugins" :key="p.id" size="small">
          <template #header>
            <n-space align="center" :size="8">
              <span>{{ resolveNavIcon(p.frontend?.nav_icon) }}</span>
              <span>{{ p.name }}</span>
              <n-tag size="small" :bordered="false" :type="stateOf(p.state).type">
                {{ stateOf(p.state).text }}
              </n-tag>
              <n-tag v-if="p.builtin" size="small" :bordered="false">内置</n-tag>
              <n-tag size="small" :bordered="false" type="warning">{{ modeText(p.mode) }}</n-tag>
            </n-space>
          </template>

          <template #header-extra>
            <!-- 打开插件页面：只有「运行中 + 前端有实现」才可点 -->
            <n-button
              size="small"
              :disabled="p.state !== 'running' || !hasPluginView(p.id)"
              @click="openPlugin(p)"
            >
              打开
            </n-button>
          </template>

          <n-space vertical :size="10">
            <n-text depth="3">{{ p.description || '（无描述）' }}</n-text>

            <n-descriptions :column="3" label-placement="left" size="small" bordered>
              <n-descriptions-item label="ID">
                <code>{{ p.id }}</code>
              </n-descriptions-item>
              <n-descriptions-item label="版本">{{ p.version }}</n-descriptions-item>
              <n-descriptions-item label="PID">
                {{ p.pid || '-' }}
              </n-descriptions-item>
              <n-descriptions-item label="运行时长">
                {{ p.state === 'running' ? formatDuration(p.uptime_seconds) : '-' }}
              </n-descriptions-item>
              <n-descriptions-item label="重启次数">{{ p.restarts }}</n-descriptions-item>
              <n-descriptions-item label="最近启动">
                {{ p.started_at ? formatTime(p.started_at) : '-' }}
              </n-descriptions-item>
            </n-descriptions>

            <!-- 失败原因必须可见：否则用户只看到一个红标签，无从下手 -->
            <n-alert v-if="p.last_error" type="error" :bordered="false" title="最近一次错误">
              {{ p.last_error }}
            </n-alert>

            <n-space :size="8">
              <n-button
                v-if="p.state !== 'running'"
                size="small"
                type="primary"
                :loading="isBusy(p.id)"
                :disabled="isBusy(p.id)"
                @click="confirmStart(p)"
              >
                启动
              </n-button>
              <n-button
                v-else
                size="small"
                :loading="isBusy(p.id)"
                :disabled="isBusy(p.id)"
                @click="confirmStop(p)"
              >
                停止
              </n-button>

              <n-button
                size="small"
                :loading="isBusy(p.id)"
                :disabled="isBusy(p.id)"
                @click="confirmRestart(p)"
              >
                重启
              </n-button>

              <n-button
                size="small"
                :loading="isBusy(p.id)"
                :disabled="isBusy(p.id) || p.state !== 'running'"
                @click="doHealth(p)"
              >
                健康探测
              </n-button>
            </n-space>

            <!-- 前端插槽状态：让「插件有没有界面」一目了然 -->
            <n-text depth="3" style="font-size: 12px">
              前端入口：<code>{{ p.frontend?.entry || '（未声明）' }}</code>
              <template v-if="!p.frontend?.entry">
                —— 该插件未提供前端界面
              </template>
            </n-text>
          </n-space>
        </n-card>
      </n-space>
    </n-spin>
    </n-space>
  </AppLayout>
</template>
