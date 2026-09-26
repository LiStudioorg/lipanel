<script setup>
// 插件操作审计页（阶段三 3.3）。
//
// 用途：回答「哪个插件、在什么时间、请求了什么资源、结果如何」。
//
// 为什么这个页面重要：权限拒绝是**静默**发生的（插件调用被 403，
// 主面板其它功能完全正常），没有审计页的话用户根本不知道
// 「我的插件有个功能一直没工作，因为少声明了一个权限」。
// 因此本页把拒绝记录醒目标红，并直接展示缺失的权限。
//
// 交互约定（与工程约束一致）：
//   - 所有操作都有 Loading，且在 finally 中复位
//   - 失败必须可见
//   - 自动刷新失败时不覆盖已有数据（网络抖一下不该清空排查现场）
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import { fetchAuditLog, fetchPlugins } from '@/api/plugins'
import { formatTime } from '@/utils/format'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const events = ref([])
const stats = ref(null)
const byPlugin = ref({})

// 过滤器：插件与结果。
const filterPlugin = ref('')
const filterOutcome = ref('')
const filterLimit = ref(100)

// plugins 用于过滤器下拉：让用户从已有插件里选，而不是手打 ID。
const plugins = ref([])

// 自动刷新：审计是排查工具，用户往往一边点插件一边看记录，
// 5 秒刷新一次比手动点更顺手。
let timer = null
const AUTO_REFRESH_MS = 5000

const outcomeOptions = [
  { label: '全部结果', value: '' },
  { label: '已放行', value: 'allowed' },
  { label: '已拒绝', value: 'denied' },
  { label: '失败', value: 'failed' },
]

const limitOptions = [50, 100, 200, 500].map((n) => ({ label: `${n} 条`, value: n }))

const pluginOptions = computed(() => [
  { label: '全部插件', value: '' },
  ...plugins.value.map((p) => ({ label: `${p.name}（${p.id}）`, value: p.id })),
])

async function load({ silent = false } = {}) {
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchAuditLog({
      plugin: filterPlugin.value,
      outcome: filterOutcome.value,
      limit: filterLimit.value,
    })
    events.value = data.events || []
    stats.value = data.stats || null
    byPlugin.value = data.by_plugin || {}
  } catch (err) {
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/plugins/audit' } })
      return
    }
    // 自动刷新失败时保留已有记录：清空排查现场比不刷新更糟。
    error.value = err?.message || '未知错误'
    if (!silent) events.value = []
  } finally {
    if (!silent) loading.value = false
  }
}

// loadPlugins 拉插件列表填过滤器（失败不阻断审计展示）。
async function loadPlugins() {
  try {
    const data = await fetchPlugins()
    plugins.value = data.plugins || []
  } catch {
    plugins.value = []
  }
}

onMounted(() => {
  loadPlugins()
  load()
  timer = setInterval(() => load({ silent: true }), AUTO_REFRESH_MS)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

// ---------- 展示辅助 ----------

// outcomeMeta 把结果映射为标签样式与文案。
const outcomeMeta = {
  allowed: { type: 'success', text: '已放行' },
  denied: { type: 'error', text: '已拒绝' },
  failed: { type: 'warning', text: '失败' },
}

function outcomeOf(outcome) {
  return outcomeMeta[outcome] || { type: 'default', text: outcome || '未知' }
}

// reasonText 给出一句人话解释「这条记录为什么是这个结果」。
function reasonText(row) {
  if (row.method === 'REGISTER') {
    return `插件注册，声明权限 ${(row.granted || []).length} 条`
  }
  if (row.outcome === 'denied') {
    return `未声明权限 ${row.required || '（未知）'}：${row.reason || ''}`
  }
  if (row.outcome === 'failed') {
    return row.reason || `HTTP ${row.status}`
  }
  return row.required ? `需要权限 ${row.required}` : '免权限校验（骨架接口或前端资源）'
}

const deniedCount = computed(() => stats.value?.denied ?? 0)

const summary = computed(() => {
  const s = stats.value
  if (!s) return ''
  const parts = [`累计 ${s.total} 条`, `内存保留 ${s.retained}/${s.capacity}`]
  if (s.denied) parts.push(`拒绝 ${s.denied}`)
  if (s.failed) parts.push(`失败 ${s.failed}`)
  if (s.persist_path) parts.push('已落盘')
  else parts.push('仅内存')
  return parts.join(' · ')
})

// pluginDenied 返回某插件在内存中的拒绝次数（用于表格行着色提示）。
function pluginDenied(id) {
  return byPlugin.value?.[id]?.denied ?? 0
}
</script>

<template>
  <AppLayout>
    <n-space vertical :size="16">
      <n-card size="small">
        <template #header>
          <n-space align="center" :size="10">
            <span>插件操作审计</span>
            <n-tag v-if="deniedCount" size="small" :bordered="false" type="error">
              {{ deniedCount }} 条拒绝
            </n-tag>
          </n-space>
        </template>
        <template #header-extra>
          <n-button size="small" :loading="loading" @click="load()">刷新</n-button>
        </template>

        <n-space vertical :size="12">
          <n-text depth="3" style="font-size: 12px">
            记录「哪个插件在什么时间请求了什么资源、结果如何」。
            <strong>已拒绝</strong>表示插件未声明该操作所需的权限，请求被核心拦下、
            根本没有到达插件进程。
          </n-text>

          <n-text v-if="summary" depth="3" style="font-size: 12px">
            审计状态：{{ summary }}
            <template v-if="stats?.persist_path">
              <br />日志文件：<code>{{ stats.persist_path }}</code>
            </template>
            <template v-if="stats?.write_errors">
              <br /><strong>注意：有 {{ stats.write_errors }} 次落盘失败，日志可能不完整。</strong>
            </template>
          </n-text>

          <n-space :size="10" align="center">
            <n-select
              v-model:value="filterPlugin"
              :options="pluginOptions"
              size="small"
              style="width: 220px"
              @update:value="load()"
            />
            <n-select
              v-model:value="filterOutcome"
              :options="outcomeOptions"
              size="small"
              style="width: 140px"
              @update:value="load()"
            />
            <n-select
              v-model:value="filterLimit"
              :options="limitOptions"
              size="small"
              style="width: 120px"
              @update:value="load()"
            />
          </n-space>

          <n-alert v-if="error" type="error" title="加载审计记录失败">
            {{ error }}
          </n-alert>
        </n-space>
      </n-card>

      <n-spin :show="loading">
        <n-empty
          v-if="!loading && events.length === 0"
          description="没有匹配的审计记录"
          style="padding: 40px 0"
        />

        <n-card v-else size="small">
          <n-table :bordered="false" :single-line="false" size="small">
            <thead>
              <tr>
                <th style="width: 170px">时间</th>
                <th style="width: 120px">插件</th>
                <th style="width: 90px">方法</th>
                <th>路径 / 说明</th>
                <th style="width: 90px">结果</th>
                <th style="width: 70px">状态</th>
                <th style="width: 90px">耗时</th>
                <th style="width: 120px">来源 IP</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in events" :key="row.seq">
                <td>{{ formatTime(row.time) }}</td>
                <td>
                  <code>{{ row.plugin }}</code>
                  <n-tag
                    v-if="pluginDenied(row.plugin)"
                    size="tiny"
                    :bordered="false"
                    type="error"
                    style="margin-left: 4px"
                  >
                    {{ pluginDenied(row.plugin) }}
                  </n-tag>
                </td>
                <td>
                  <n-tag size="tiny" :bordered="false" :type="row.method === 'REGISTER' ? 'info' : 'default'">
                    {{ row.method }}
                  </n-tag>
                </td>
                <td>
                  <div><code>{{ row.path }}</code></div>
                  <!-- 说明文字：把「为什么是这个结果」直接写出来，
                       用户不必去对照权限规则表 -->
                  <n-text depth="3" style="font-size: 12px">{{ reasonText(row) }}</n-text>
                </td>
                <td>
                  <n-tag size="small" :bordered="false" :type="outcomeOf(row.outcome).type">
                    {{ outcomeOf(row.outcome).text }}
                  </n-tag>
                </td>
                <td>{{ row.status || '-' }}</td>
                <td>{{ row.duration_ms ? row.duration_ms + ' ms' : '-' }}</td>
                <td><code>{{ row.client_ip || '-' }}</code></td>
              </tr>
            </tbody>
          </n-table>
        </n-card>
      </n-spin>
    </n-space>
  </AppLayout>
</template>
