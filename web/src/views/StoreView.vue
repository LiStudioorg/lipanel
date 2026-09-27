<script setup>
// 软件商店页（阶段四 4.5）。
//
// 内置基础页面（不是插件）：一键安装运行环境是面板的核心能力，
// 依赖插件机制反而会让用户在插件未启动时无法部署环境。
//
// ########## 这一页与其它四个模块的交互差异 ##########
//
// 4.1~4.4 的写操作都是**同步**的：点一下，等结果，刷新列表。
// 软件商店不是：装一个 MySQL 要几十秒到几分钟，请求不可能一直挂着。
// 因此后端返回 202 + 任务 ID，本页要做三件额外的事：
//
//   ① 轮询进度（含增量日志游标）；
//   ② 组件卸载时**必须停止轮询**，否则会留下永不停止的定时器
//      ——用户切走后仍在每 1.5 秒打一次后端；
//   ③ 刷新页面后要能从任务列表恢复"正在安装"的界面，
//      否则用户以为没在装，再点一次（要么被 409 拒，要么更糟）。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 安装/卸载是**有真实代价**的操作（以 root 跑包管理器、写系统源、
//     可能让站点下线），一律走二次确认，且确认文案里逐条写清会发生什么
//   - 失败时同时展示后端给的 hint（那是"下一步该做什么"，比 error 更有用）
import { computed, h, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  NAlert,
  NButton,
  NCard,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NProgress,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NStep,
  NSteps,
  NTag,
  NText,
  NTooltip,
} from 'naive-ui'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import {
  fetchStoreList,
  fetchStoreTask,
  fetchStoreTasks,
  installSoftware,
  pollStoreTask,
  uninstallSoftware,
} from '@/api/store'
import {
  canInstall,
  canUninstall,
  defaultVersionOf,
  environmentText,
  formatLogLine,
  installConfirmText,
  isTerminal,
  logLevelMeta,
  mergeLogs,
  progressStatus,
  softwareStatusMeta,
  strategyMeta,
  stepStatusMeta,
  taskStatusMeta,
  uninstallConfirmText,
  versionOptions,
} from '@/views/storeLogic'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

const loading = ref(false)
const acting = ref(false)
const error = ref('')
const data = ref({
  software: [],
  counts: { total: 0, installed: 0, pending: 0 },
  available: false,
  unavailable_reason: '',
  running: null,
  dry_run: false,
  environment: {},
  permissions: [],
})

// selected 记录每个软件当前选中的版本（软件 ID → 版本 ID）。
// 用对象而不是表格行内的字段：后端每次刷新都会返回全新的行对象，
// 把选择状态存在行里会在轮询刷新时被清空。
const selected = ref({})

// 当前展示的任务（安装或卸载中）。
const task = ref(null)
const taskLogs = ref([])
const taskPolling = ref(false)

// 轮询的取消句柄。组件卸载时必须调用，否则定时器会成为孤儿。
let pollAbort = null

const canWrite = computed(() => (data.value.permissions || []).includes('store.write'))
const running = computed(() => data.value.running || null)
const busy = computed(() => Boolean(running.value) || taskPolling.value)

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

async function load() {
  loading.value = true
  error.value = ''
  try {
    const payload = await fetchStoreList()
    data.value = payload
    // 为每个软件选定默认版本（已有选择则不覆盖，避免刷新时把用户
    // 刚选好的版本重置掉）。
    const next = { ...selected.value }
    for (const sw of payload.software || []) {
      if (!next[sw.id]) {
        next[sw.id] = defaultVersionOf(sw)
      }
    }
    selected.value = next

    // 刷新后若发现后端有任务在跑，恢复到它的进度界面。
    //
    // 这一步是**必须**的：不恢复的话，用户刷新页面会看到一个
    // 静止的列表，以为安装没开始，于是再点一次。
    if (payload.running && (!task.value || task.value.id !== payload.running.id)) {
      resumeTask(payload.running)
    }
  } catch (err) {
    error.value = describeError(err)
    message.error(error.value)
  } finally {
    loading.value = false
  }
}

// resumeTask 接管一个已经在跑的任务（刷新页面后）。
async function resumeTask(t) {
  if (taskPolling.value) return
  task.value = t
  taskLogs.value = []
  // 从头拉一次已有日志，避免刷新后日志面板是空的。
  try {
    const payload = await fetchStoreTask(t.id, { since: 0 })
    task.value = payload.task
    taskLogs.value = payload.logs || []
    if (payload.done || isTerminal(payload.task?.status)) {
      onTaskFinished(payload.task)
      return
    }
    startPolling(t.id, payload.next_since || 0)
  } catch (err) {
    // 任务可能在刷新的一瞬间刚好结束并被清理，这不是错误。
    if (err instanceof ApiError && err.status === 404) {
      task.value = null
      return
    }
    message.warning(`恢复任务进度失败：${describeError(err)}`)
  }
}

// startPolling 开始轮询任务进度。
//
// 游标从后端给的 next_since 起算：用 0 会每轮全量重拉，
// 而安装日志动辄上千行。
function startPolling(id, since) {
  if (pollAbort) pollAbort.abort()
  pollAbort = new AbortController()
  taskPolling.value = true

  pollStoreTask(id, {
    since,
    intervalMs: 1500,
    signal: pollAbort.signal,
    onUpdate: ({ task: latest, logs }) => {
      if (latest) task.value = latest
      taskLogs.value = mergeLogs(taskLogs.value, logs)
    },
  })
    .then((final) => {
      if (final) onTaskFinished(final)
    })
    .catch((err) => {
      // 轮询自身出错（超过次数上限）时不能静默：用户会以为还在装。
      taskPolling.value = false
      message.error(describeError(err))
    })
    .finally(() => {
      taskPolling.value = false
      pollAbort = null
    })
}

// onTaskFinished 处理任务终态。
function onTaskFinished(final) {
  taskPolling.value = false
  if (!final) return
  task.value = final
  if (final.status === 'succeeded') {
    message.success(
      `${final.software_name || final.software} ${final.version || ''} ${
        final.kind === 'uninstall' ? '已卸载' : '安装完成'
      }`.trim(),
    )
  } else {
    // 失败时必须同时给出 hint：那是"下一步做什么"，
    // 比 error 本身更有指导意义。
    message.error(final.error || '任务失败')
    if (final.hint) {
      message.info(final.hint, { duration: 8000 })
    }
  }
  // 无论成败都刷新列表：失败也可能已经部分改变了系统
  // （例如官方源已经写进去了，或包已装上但版本不符）。
  load()
}

function describeError(err) {
  if (err instanceof ApiError) {
    const parts = [err.message]
    if (err.hint) parts.push(err.hint)
    return parts.join(' —— ')
  }
  return String(err?.message || err)
}

onMounted(async () => {
  await authStore.ensureLoaded?.()
  await load()
})

// 组件卸载时停止轮询。
//
// 不做这一步的话，用户切到别的页面后，这里的定时器仍在每 1.5 秒
// 请求一次后端；更糟的是 onUpdate 会继续写已经卸载的响应式状态。
onBeforeUnmount(() => {
  if (pollAbort) {
    pollAbort.abort()
    pollAbort = null
  }
})

// ---------------------------------------------------------------------------
// 操作
// ---------------------------------------------------------------------------

// doInstall 发起安装。
async function doInstall(sw) {
  const version = selected.value[sw.id] || defaultVersionOf(sw)
  const check = canInstall(sw, version, {
    available: data.value.available,
    running: busy.value,
  })
  if (!check.ok) {
    message.warning(check.reason)
    return
  }

  const versionMeta = (sw.versions || []).find((v) => v.id === version) || {}
  dialog.warning({
    title: `安装 ${sw.name} ${version}`,
    content: installConfirmText(sw, version, {
      officialAvailable: versionMeta.official_available,
    }),
    positiveText: '开始安装',
    negativeText: '取消',
    onPositiveClick: async () => {
      acting.value = true
      try {
        const payload = await installSoftware(sw.id, { version })
        task.value = payload.task
        taskLogs.value = []
        startPolling(payload.task.id, 0)
        message.info('安装任务已开始，可在下方查看实时进度与日志')
      } catch (err) {
        // 409 有特殊含义：不是"出错了"，而是"现在不行"。
        // 必须把这一点讲清楚，否则用户会反复点。
        if (err instanceof ApiError && err.status === 409) {
          message.warning(`已有任务正在进行：${err.hint || err.message}`)
          await load()
        } else {
          message.error(describeError(err))
        }
      } finally {
        acting.value = false
      }
    },
  })
}

// doUninstall 发起卸载。
async function doUninstall(sw) {
  const meta = softwareStatusMeta(sw)
  const version =
    selected.value[sw.id] && meta.key === 'installed'
      ? selected.value[sw.id]
      : (sw.installed_versions || [])[0] || ''

  const check = canUninstall(sw, { available: data.value.available, running: busy.value })
  if (!check.ok) {
    message.warning(check.reason)
    return
  }

  dialog.error({
    title: `卸载 ${sw.name}`,
    content: uninstallConfirmText(sw, version),
    positiveText: '确认卸载',
    negativeText: '取消',
    onPositiveClick: async () => {
      acting.value = true
      try {
        const payload = await uninstallSoftware(sw.id, { version })
        task.value = payload.task
        taskLogs.value = []
        startPolling(payload.task.id, 0)
        message.info('卸载任务已开始')
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) {
          message.warning(`已有任务正在进行：${err.hint || err.message}`)
          await load()
        } else {
          message.error(describeError(err))
        }
      } finally {
        acting.value = false
      }
    },
  })
}

function dismissTask() {
  task.value = null
  taskLogs.value = []
}

// ---------------------------------------------------------------------------
// 表格
// ---------------------------------------------------------------------------

const columns = [
  {
    title: '软件',
    key: 'name',
    minWidth: 200,
    render(row) {
      const meta = softwareStatusMeta(row)
      return h('div', { class: 'store-name' }, [
        h('div', { class: 'store-name__title' }, [
          h('span', { class: 'store-name__text' }, row.name),
          h(
            NTag,
            { size: 'small', type: meta.type === 'success' ? 'success' : 'default', bordered: false },
            { default: () => meta.label },
          ),
        ]),
        h('div', { class: 'store-name__desc' }, row.description || ''),
        row.detected_version && !row.installed_versions?.length
          ? h('div', { class: 'store-name__detected' },
              `系统里已安装 ${row.detected_version}`)
          : null,
        (row.depends || []).length
          ? h('div', { class: 'store-name__deps' },
              `依赖：${row.depends.join('、')}${row.depends_installed ? '（已就绪）' : '（安装时自动补齐）'}`)
          : null,
      ])
    },
  },
  {
    title: '版本',
    key: 'version',
    width: 190,
    render(row) {
      const options = versionOptions(row).map((o) => ({
        label: o.installed
          ? `${o.label}（已安装${o.installedVersion ? ` ${o.installedVersion}` : ''}）`
          : o.isDefault
            ? `${o.label}（默认）`
            : o.label,
        value: o.value,
      }))
      return h(NSelect, {
        value: selected.value[row.id],
        options,
        size: 'small',
        disabled: busy.value || !canWrite.value,
        placeholder: '选择版本',
        'onUpdate:value': (v) => {
          selected.value = { ...selected.value, [row.id]: v }
        },
      })
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 190,
    render(row) {
      const meta = softwareStatusMeta(row)
      const version = selected.value[row.id] || defaultVersionOf(row)
      const installCheck = canInstall(row, version, {
        available: data.value.available,
        running: busy.value,
      })
      const uninstallCheck = canUninstall(row, {
        available: data.value.available,
        running: busy.value,
      })

      const buttons = []
      if (meta.key !== 'installed' && meta.key !== 'detected') {
        buttons.push(
          h(
            NButton,
            {
              size: 'small',
              type: 'primary',
              disabled: !installCheck.ok || !canWrite.value || acting.value,
              loading: acting.value && task.value?.software === row.id,
              onClick: () => doInstall(row),
            },
            { default: () => '安装' },
          ),
        )
      }
      if (uninstallCheck.ok) {
        buttons.push(
          h(
            NButton,
            {
              size: 'small',
              tertiary: true,
              type: 'error',
              disabled: !canWrite.value || acting.value,
              onClick: () => doUninstall(row),
            },
            { default: () => '卸载' },
          ),
        )
      }
      // 按钮不可用时把原因挂在 title 上：tooltip 能解释"为什么点不了"，
      // 否则用户只会觉得按钮坏了。
      const reason = installCheck.ok ? '' : installCheck.reason
      const node = h(NSpace, { size: 8 }, { default: () => buttons })
      return reason ? h(NTooltip, { trigger: 'hover' }, {
        trigger: () => node,
        default: () => reason,
      }) : node
    },
  },
]

// 表格数据：把"正在运行的软件"标记出来，让用户知道哪一行在动。
const tableData = computed(() => {
  const list = data.value.software || []
  const runningID = task.value?.software || running.value?.software
  return list.map((sw) => ({ ...sw, __running: sw.id === runningID }))
})

const rowClassName = (row) => (row.__running ? 'store-row--running' : '')

// ---------------------------------------------------------------------------
// 任务面板
// ---------------------------------------------------------------------------

const taskMeta = computed(() => taskStatusMeta(task.value?.status))
const taskStrategy = computed(() =>
  task.value?.strategy ? strategyMeta(task.value.strategy) : null,
)
const taskProgressStatus = computed(() => progressStatus(task.value))
const taskStepList = computed(() => task.value?.steps || [])

// visibleLogs 只保留最后 400 行用于渲染。
//
// 日志可能上千行，全部渲染会让页面卡顿；而排查问题看的几乎总是
// 末尾（失败原因总在最后）。完整日志仍保留在 taskLogs 里。
const visibleLogs = computed(() => {
  const all = taskLogs.value
  return all.length > 400 ? all.slice(all.length - 400) : all
})

// ---------------------------------------------------------------------------
// 环境与统计
// ---------------------------------------------------------------------------

const envText = computed(() => environmentText(data.value.environment))
const officialAvailable = computed(() => Boolean(data.value.environment?.official_sources))
</script>

<template>
  <AppLayout>
    <div class="store-page">
      <n-space vertical :size="16">
        <!-- 试运行提示：必须非常显眼，否则用户会以为真的装上了 -->
        <n-alert v-if="data.dry_run" type="warning" title="试运行模式">
          面板以 <code>-store-dry-run</code> 启动：所有安装/卸载只会记录将要执行的命令，
          <strong>不会真的安装任何软件，也不会写入任何系统文件</strong>。
          任务会被标记为「模拟执行」。关闭该模式请重启面板并去掉该参数。
        </n-alert>

        <!-- 环境不可用：说明原因，但不整页报错（清单仍然可看） -->
        <n-alert v-if="!data.available && !loading" type="warning" title="本机无法安装软件">
          {{ data.unavailable_reason || '未探测到可用的包管理器' }}
          <div class="store-hint">
            已安装的软件状态仍可正常查看；如需安装，请先在本机安装 apt / dnf / yum 之一。
          </div>
        </n-alert>

        <n-alert v-if="error" type="error" title="加载失败" closable @close="error = ''">
          {{ error }}
        </n-alert>

        <!-- 权限提示 -->
        <n-alert v-if="!canWrite" type="info" title="只读权限">
          当前账号没有 <code>store.write</code> 权限，因此安装与卸载按钮不可用。
          安装软件会以 root 身份运行发行版包管理器，因此被单独管控。
        </n-alert>

        <n-card :bordered="false">
          <template #header>
            <n-space align="center" :size="12">
              <span>软件商店</span>
              <n-tag size="small" :bordered="false">{{ envText }}</n-tag>
              <n-tag v-if="officialAvailable" size="small" type="info" :bordered="false">
                支持官方源
              </n-tag>
              <n-tag v-else size="small" :bordered="false">无官方源（仅系统源/预编译）</n-tag>
            </n-space>
          </template>
          <template #header-extra>
            <n-button size="small" :loading="loading" @click="load">刷新</n-button>
          </template>

          <n-space :size="32" class="store-stats">
            <n-statistic label="可安装软件" :value="data.counts.total" />
            <n-statistic label="已安装" :value="data.counts.installed" />
            <n-statistic label="进行中" :value="data.counts.pending" />
          </n-space>

          <div class="store-hint store-hint--block">
            安装会按 <strong>系统源 → 官方源 → 预编译包</strong> 的顺序逐级尝试，成功即停。
            系统源不需要新增任何第三方仓库；官方源会写入系统包管理器的源配置；
            预编译包解包到 <code>/usr/local</code>，不经过包管理器。
            同一时刻只允许一个安装/卸载任务（apt/dpkg 与 rpm 都有全局锁）。
          </div>
        </n-card>

        <!-- 任务进度面板：安装中或刚结束 -->
        <n-card v-if="task" :bordered="false" class="store-task">
          <template #header>
            <n-space align="center" :size="12">
              <span>
                {{ task.kind === 'uninstall' ? '卸载' : '安装' }}
                {{ task.software_name || task.software }}
                <template v-if="task.version">{{ task.version }}</template>
              </span>
              <n-tag size="small" :type="taskMeta.type" :bordered="false">
                {{ taskMeta.label }}
              </n-tag>
              <n-tag v-if="task.simulated" size="small" type="warning" :bordered="false">
                模拟执行
              </n-tag>
              <n-tag v-if="taskStrategy" size="small" :type="taskStrategy.type" :bordered="false">
                {{ taskStrategy.label }}
              </n-tag>
            </n-space>
          </template>
          <template #header-extra>
            <n-button size="small" quaternary @click="dismissTask">收起</n-button>
          </template>

          <n-space vertical :size="12">
            <div>
              <div class="store-stage">
                {{ task.stage || taskMeta.desc }}
                <span v-if="!isTerminal(task.status)" class="store-stage__pulse">●</span>
              </div>
              <n-progress
                type="line"
                :percentage="task.progress || 0"
                :status="taskProgressStatus"
                :processing="!isTerminal(task.status)"
                indicator-placement="inside"
              />
            </div>

            <!-- 步骤：让用户看到"它试过哪几条路" -->
            <n-steps v-if="taskStepList.length" size="small" :current="taskStepList.length">
              <n-step
                v-for="step in taskStepList"
                :key="step.key"
                :title="step.name"
                :status="stepStatusMeta(step.status).label === '失败' ? 'error'
                  : step.status === 'skipped' ? 'finish'
                  : step.status === 'succeeded' ? 'finish' : 'process'"
                :description="step.detail || stepStatusMeta(step.status).label"
              />
            </n-steps>

            <!-- 失败原因 + 下一步该做什么 -->
            <n-alert v-if="task.status === 'failed'" type="error" title="任务失败">
              <div class="store-error">{{ task.error }}</div>
              <div v-if="task.hint" class="store-hint">{{ task.hint }}</div>
            </n-alert>

            <n-descriptions v-if="task.packages?.length || task.prebuilt_url || task.dependencies?.length"
                            size="small" :column="1" label-placement="left">
              <n-descriptions-item v-if="task.dependencies?.length" label="自动补齐的依赖">
                {{ task.dependencies.join('、') }}
              </n-descriptions-item>
              <n-descriptions-item v-if="task.packages?.length" label="软件包">
                {{ task.packages.join(' ') }}
              </n-descriptions-item>
              <n-descriptions-item v-if="task.prebuilt_url" label="预编译包地址">
                <n-text code>{{ task.prebuilt_url }}</n-text>
              </n-descriptions-item>
            </n-descriptions>

            <!-- 实时日志 -->
            <n-collapse :default-expanded-names="['log']">
              <n-collapse-item name="log">
                <template #header>
                  执行日志（{{ taskLogs.length }} 行{{ task.log_dropped ? `，已丢弃最早 ${task.log_dropped} 行` : '' }}）
                </template>
                <div class="store-log">
                  <div v-if="!visibleLogs.length" class="store-log__empty">暂无日志</div>
                  <div
                    v-for="line in visibleLogs"
                    :key="line.seq"
                    class="store-log__line"
                    :class="`store-log__line--${line.level}`"
                  >
                    <span class="store-log__level">{{ logLevelMeta(line.level).label }}</span>
                    <span class="store-log__text">{{ formatLogLine(line) }}</span>
                  </div>
                </div>
              </n-collapse-item>
            </n-collapse>
          </n-space>
        </n-card>

        <n-card :bordered="false">
          <template #header>可安装的软件</template>
          <n-spin :show="loading">
            <n-data-table
              :columns="columns"
              :data="tableData"
              :row-class-name="rowClassName"
              :bordered="false"
              size="small"
            />
            <n-empty
              v-if="!loading && !tableData.length"
              description="商店清单为空"
              class="store-empty"
            />
          </n-spin>
        </n-card>
      </n-space>
    </div>
  </AppLayout>
</template>

<style scoped>
.store-page {
  padding: 4px;
}

.store-hint {
  margin-top: 6px;
  color: #6b7280;
  font-size: 12px;
  line-height: 1.7;
}

.store-hint--block {
  margin-top: 14px;
  padding-top: 10px;
  border-top: 1px solid var(--n-border-color, #efefef);
}

.store-hint code,
.store-page code {
  padding: 1px 5px;
  border-radius: 4px;
  background: rgba(127, 127, 127, 0.14);
  font-size: 12px;
}

.store-stats {
  margin-bottom: 4px;
}

.store-name__title {
  display: flex;
  align-items: center;
  gap: 8px;
}

.store-name__text {
  font-weight: 600;
}

.store-name__desc {
  margin-top: 2px;
  color: #6b7280;
  font-size: 12px;
}

.store-name__detected {
  margin-top: 2px;
  color: #d97706;
  font-size: 12px;
}

.store-name__deps {
  margin-top: 2px;
  color: #9ca3af;
  font-size: 12px;
}

.store-stage {
  margin-bottom: 6px;
  font-size: 13px;
}

.store-stage__pulse {
  margin-left: 6px;
  color: var(--n-color-target, #2080f0);
  animation: store-pulse 1.2s ease-in-out infinite;
}

@keyframes store-pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.25;
  }
}

.store-error {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

.store-log {
  max-height: 340px;
  overflow: auto;
  padding: 10px 12px;
  border-radius: 6px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  line-height: 1.65;
}

.store-log__empty {
  color: #64748b;
}

.store-log__line {
  display: flex;
  gap: 8px;
  white-space: pre-wrap;
  word-break: break-all;
}

.store-log__level {
  flex: 0 0 auto;
  min-width: 52px;
  color: #64748b;
}

.store-log__line--warn .store-log__text,
.store-log__line--warn .store-log__level {
  color: #fbbf24;
}

.store-log__line--error .store-log__text,
.store-log__line--error .store-log__level,
.store-log__line--stderr .store-log__text,
.store-log__line--stderr .store-log__level {
  color: #f87171;
}

.store-log__line--command .store-log__text,
.store-log__line--command .store-log__level {
  color: #7dd3fc;
}

.store-empty {
  padding: 24px 0;
}

:deep(.store-row--running) {
  background: rgba(32, 128, 240, 0.06);
}
</style>
