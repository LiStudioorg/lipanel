<template>
  <div class="logs-view">
    <n-card :bordered="false" class="logs-card">
      <!-- 顶部工具栏：源选择 + 过滤 -->
      <div class="logs-toolbar">
        <n-select
          v-model:value="activeSource"
          :options="sourceOptions"
          placeholder="选择日志源"
          clearable
          class="source-select"
          style="width: 240px"
        />
        <n-input
          v-model:value="filterText"
          placeholder="关键词过滤（回车查询）"
          clearable
          style="width: 260px"
          @keyup.enter="doQuery"
        />
        <n-select
          v-if="activeSourceMeta?.capability?.level"
          v-model:value="level"
          :options="levelOptions"
          class="level-select"
          style="width: 120px"
        />
        <n-input-number
          v-model:value="lines"
          :min="1"
          :max="2000"
          placeholder="100"
          style="width: 110px"
        />
        <n-button type="primary" size="small" @click="doQuery" :loading="loading">
          查询
        </n-button>
        <n-button size="small" @click="toggleAuto">
          {{ autoRefresh ? '暂停自动刷新' : '自动刷新' }}
        </n-button>
      </div>

      <!-- 左侧源说明 + 右侧内容 -->
      <n-layout has-sider class="logs-layout">
        <n-layout-sider bordered :width="220" class="logs-sider">
          <div class="sider-title">日志源</div>
          <div
            v-for="src in sources"
            :key="src.id"
            class="source-item"
            :class="{ active: src.id === activeSource }"
            @click="selectSource(src)"
          >
            <div class="source-name">
              <n-tag :type="sourceTypeMetaOf(src.type).tag" size="small" bordered>
                {{ sourceTypeMetaOf(src.type).text }}
              </n-tag>
              {{ src.name }}
            </div>
            <div class="source-status" :class="src.available ? 'ok' : 'bad'">
              {{ src.available ? '可用' : '不可用' }}
            </div>
            <div v-if="!src.available" class="source-reason">{{ src.unavailable_reason }}</div>
          </div>
        </n-layout-sider>

        <n-layout-content class="logs-content">
          <!-- 源不可用 / 无选择提示 -->
          <n-empty
            v-if="!activeSource"
            description="请在左侧选择一个日志源"
            class="logs-empty"
          />
          <n-alert
            v-else-if="activeSourceMeta && !activeSourceMeta.available"
            type="warning"
            :title="`${activeSourceMeta.name} 当前不可用`"
          >
            {{ activeSourceMeta.unavailable_reason }}
          </n-alert>
          <template v-else>
            <div class="log-meta">
              <span v-if="normalized.scanned">共扫描 {{ normalized.scanned }} 行</span>
              <span v-if="normalized.entries.length">
                显示 {{ normalized.entries.length }} 行
              </span>
              <n-tag v-if="normalized.truncated" type="warning" size="small" bordered>
                已截断（仅显示最近的 {{ lines }} 行）
              </n-tag>
            </div>
            <pre class="log-pre">
              <template v-for="(entry, i) in normalized.entries" :key="i">
                <span v-if="entry.timestamp" class="log-ts">{{ entry.timestamp }}  </span>{{ escapeHtml(entry.line) }}
              </template>
            </pre>
            <n-empty
              v-if="!normalized.entries.length"
              description="没有匹配的行"
              class="logs-empty-sm"
            />
          </template>
        </n-layout-content>
      </n-layout>
    </n-card>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { NAlert, NButton, NCard, NEmpty, NInput, NInputNumber, NSelect, NTag, useMessage } from 'naive-ui'
import { listSources, queryLogs } from '@/api/logs'
import { buildQuery, escapeHtml, LEVELS, normalizeQuery, sourceTypeMetaOf } from '@/views/logsLogic'

const message = useMessage()

const sources = ref([])
const activeSource = ref('')
const filterText = ref('')
const level = ref('')
const lines = ref(100)
const loading = ref(false)
const autoRefresh = ref(true)
const normalized = ref({ entries: [], truncated: false, scanned: 0 })

let refreshTimer = null

const activeSourceMeta = computed(() =>
  sources.value.find((s) => s.id === activeSource.value) || null,
)

const sourceOptions = computed(() =>
  sources.value.map((s) => ({
    label: s.name,
    value: s.id,
    disabled: !s.available,
  })),
)

const levelOptions = LEVELS.map((l) => ({ label: l.label, value: l.value }))

async function loadSources() {
  try {
    const res = await listSources()
    sources.value = res.sources || []
    // 默认选中第一个可用源。
    if (sources.value.length && !activeSource.value) {
      const firstAvail = sources.value.find((s) => s.available)
      if (firstAvail) activeSource.value = firstAvail.id
    }
    // 若当前选中源变得不可用，回落到第一个可用源。
    if (activeSource.value) {
      const cur = sources.value.find((s) => s.id === activeSource.value)
      if (cur && !cur.available) {
        const firstAvail = sources.value.find((s) => s.available)
        activeSource.value = firstAvail ? firstAvail.id : ''
      }
    }
    if (sources.value.length && activeSource.value) {
      await doQuery()
    }
  } catch (err) {
    message.error(`加载日志源失败：${err.message}`)
  }
}

function selectSource(src) {
  activeSource.value = src.id
  doQuery()
}

async function doQuery() {
  if (!activeSource.value) return
  loading.value = true
  try {
    const q = buildQuery({
      source: activeSource.value,
      lines: lines.value,
      filter: filterText.value,
      level: activeSourceMeta.value?.capability?.level ? level.value : '',
    })
    const res = await queryLogs(q)
    normalized.value = normalizeQuery(res)
  } catch (err) {
    message.error(`查询失败：${err.message}`)
    normalized.value = { entries: [], truncated: false, scanned: 0 }
  } finally {
    loading.value = false
  }
}

function toggleAuto() {
  autoRefresh.value = !autoRefresh.value
  if (autoRefresh.value) {
    startAutoRefresh()
  } else {
    stopAutoRefresh()
  }
}

function startAutoRefresh() {
  stopAutoRefresh()
  refreshTimer = window.setInterval(() => {
    if (!loading.value && activeSource.value) doQuery()
  }, 5000)
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

onMounted(() => {
  loadSources()
  startAutoRefresh()
})
onBeforeUnmount(() => stopAutoRefresh())
</script>

<style scoped>
.logs-view {
  height: 100%;
}
.logs-card {
  min-height: calc(100vh - 120px);
}
.logs-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.logs-layout {
  border: 1px solid var(--n-border-color, #eee);
  border-radius: 6px;
  height: 620px;
}
.logs-sider {
  padding: 8px 0;
}
.sider-title {
  padding: 4px 12px 8px;
  font-weight: 600;
  color: #888;
  font-size: 12px;
}
.source-item {
  padding: 8px 12px;
  cursor: pointer;
  border-left: 3px solid transparent;
}
.source-item:hover {
  background: rgba(0, 0, 0, 0.04);
}
.source-item.active {
  background: rgba(0, 0, 0, 0.06);
  border-left-color: var(--primary-color, #18a058);
}
.source-name {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
}
.source-status {
  font-size: 12px;
}
.source-status.ok {
  color: #18a058;
}
.source-status.bad {
  color: #d03050;
}
.source-reason {
  font-size: 11px;
  color: #b0b0b0;
  margin-top: 4px;
  word-break: break-all;
}
.logs-content {
  padding: 12px 16px;
  background: #fafafa;
  overflow: auto;
}
.log-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: #888;
  margin-bottom: 8px;
}
.log-pre {
  margin: 0;
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 12px;
  border-radius: 6px;
  max-height: 520px;
  overflow: auto;
}
.log-ts {
  color: #6a9955;
  user-select: none;
}
.logs-empty {
  padding-top: 100px;
}
.logs-empty-sm {
  padding-top: 30px;
}
</style>