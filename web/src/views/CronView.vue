<script setup>
// 计划任务页（阶段五 5.2，核心自带）。
//
// 内置基础页面（不是插件）：定时任务是服务器的基础设施，
// 依赖插件机制会让用户在插件未启动时改不了备份任务。
//
// ########## 这一页最需要小心的地方 ##########
//
// 其它模块的误操作后果发生在按下按钮的那一刻；本模块的后果发生在
// **未来某个无人值守的时刻**：一条被写坏的备份任务不会报错，
// 它只是不跑，而你要等到需要恢复备份的那天才发现。
//
// 因此这一页有四处刻意的设计：
//
//   ① 顶部永远写明「面板正在管理谁的 crontab」。
//      默认是面板运行身份（生产上即 root）的 crontab，其中可能
//      有系统包管理器留下的条目。隔离模式（-cron-file）单独用
//      黄色警示条说明「这里改了不会影响真实 cron」。
//   ② 命令字段给明确警示：完整 shell 命令、以面板身份执行、原文进审计。
//      面板不做命令黑白名单（有终端功能的前提下任何过滤都拦不住
//      真想绕过的人），安全靠的是鉴权 + 权限 + 二次确认 + 完整审计。
//   ③ 表达式预览走后端 POST /api/cron/validate：
//      「下次执行时间」必须与列表同源，否则同一界面出现两个矛盾的时间。
//   ④ 删除弹窗**写明表达式与命令原文**（计划明确要求），
//      后端还会独立强制一次（428），所以即便这里出 bug 也不会误删。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 后端给的 hint 要一并展示（那是"下一步该做什么"）
import { computed, h, onMounted, ref, watch } from 'vue'
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
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSpace,
  NSpin,
  NTabPane,
  NTabs,
  NTag,
  NText,
  useMessage,
} from 'naive-ui'
import {
  fetchCronStatus,
  fetchCronJobs,
  fetchCronLogs,
  fetchCronAudit,
  validateCronExpr,
  createCronJob,
  updateCronJob,
  deleteCronJob,
} from '@/api/cron'
import {
  EXPR_EXAMPLES,
  MODE_LABEL,
  MAX_COMMAND_BYTES,
  MAX_COMMENT_BYTES,
  actionLabel,
  backupsHint,
  canWrite as canWriteOf,
  commandPreview,
  deleteConfirmText,
  errorText,
  exitText,
  expectedIds,
  filterJobs,
  formatTimeFull,
  healthAlert,
  looksLikeExpr,
  logStatusMeta,
  nextRunText,
  outcomeMeta,
  relativeText,
  resultNotice,
  saveConfirmText,
  summarizeJobs,
  targetWarning,
  validateForm,
  byteLength,
} from './cronLogic.js'

const message = useMessage()

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

const loading = ref(false)
const submitting = ref(false)
const errorText_ = ref('')

const status = ref(null)
const jobs = ref([])
const settings = ref([])
const activeTab = ref('jobs')

const keyword = ref('')

// 新建 / 编辑弹窗。
const editing = ref(null) // null=关闭；{ mode, job }
const form = ref({ expression: '', command: '', comment: '' })
const formError = ref('')
// preview 来自后端 /api/cron/validate，是唯一可信的「下次执行时间」来源。
const preview = ref(null)
const previewError = ref('')
const previewLoading = ref(false)

// 保存前的最终确认。pendingSave 存的是**已校验通过**的载荷；
// 点「保存前确认」只做本地校验并把内容摊开给用户看，
// 真正的写请求在 doSubmitJob 里——这样弹窗里显示的内容
// 与实际提交的内容一定是同一份（不会出现「看到的不是写进去的」）。
const pendingSave = ref(null)

// 删除确认。
const deleteTarget = ref(null)
const deleting = ref(false)

// 日志抽屉。
const logsTarget = ref(null)
const logsResult = ref(null)
const logsLoading = ref(false)
const logsError = ref('')

// 审计。
const audit = ref(null)
const auditLoading = ref(false)
const auditOutcome = ref('')

// 现在时刻：只由调用处注入（不在 cronLogic 里读 Date.now，
// 否则 relativeText 的用例无法测）。每次刷新列表时更新一次即可，
// 「还有多久」这类信息没必要精确到秒。
const now = ref(new Date())

// ---------------------------------------------------------------------------
// 计算属性
// ---------------------------------------------------------------------------

const available = computed(() => status.value?.available === true)
const isFileMode = computed(() => status.value?.mode === 'file')
const writable = computed(() => canWriteOf(status.value?.permissions))
const health = computed(() => healthAlert(status.value))
const summary = computed(() => summarizeJobs(jobs.value))
const shownJobs = computed(() => filterJobs(jobs.value, { keyword: keyword.value }))
const rows = computed(() => {
  const base = now.value
  return shownJobs.value.map((j) => ({ ...j, _next: nextRunText(j, base) }))
})
const formByteLeft = computed(() => MAX_COMMAND_BYTES - byteLength(form.value.command))
const formCommentLeft = computed(() => MAX_COMMENT_BYTES - byteLength(form.value.comment))
const adoptHint = computed(
  () => editing.value?.mode === 'edit' && editing.value?.job?.managed === false,
)
const deleteConfirm = computed(() => deleteConfirmText(deleteTarget.value))

// ---------------------------------------------------------------------------
// 加载
// ---------------------------------------------------------------------------

async function refreshJobs({ quiet = false } = {}) {
  loading.value = true
  if (!quiet) errorText_.value = ''
  try {
    const res = await fetchCronJobs()
    jobs.value = res?.jobs || []
    settings.value = res?.settings || []
    status.value = res?.status || status.value
    now.value = new Date()
    errorText_.value = ''
  } catch (err) {
    if (err.isUnauthorized) throw err
    // crontab 不可用时列表拿不到东西，但仍要把原因显示出来：
    // 单独取一次状态，让页面渲染成「说明页」而不是一个红色错误框。
    errorText_.value = errorText(err)
    await refreshStatus().catch(() => {})
  } finally {
    loading.value = false
  }
}

async function refreshStatus() {
  try {
    const res = await fetchCronStatus()
    status.value = res?.status || null
    return res
  } catch (err) {
    // 状态接口本身出错才真的是错误。
    errorText_.value = errorText(err)
    return null
  }
}

async function refreshAudit() {
  auditLoading.value = true
  try {
    audit.value = await fetchCronAudit({ limit: 100, outcome: auditOutcome.value })
  } catch (err) {
    message.error(errorText(err))
  } finally {
    auditLoading.value = false
  }
}

async function refreshAll() {
  await refreshStatus()
  await refreshJobs({ quiet: true })
  if (activeTab.value === 'audit') await refreshAudit()
}

// ---------------------------------------------------------------------------
// 表达式预览（后端是唯一裁决者）
// ---------------------------------------------------------------------------

let previewTimer = null
let previewSeq = 0

// 防抖 + 序号丢弃：
// 用户在输入框里连续敲字时，先发出去的后发先至会让预览显示成
// 上一个表达式的结果——那种"看起来对但错了"的时间比不显示更危险。
watch(
  () => form.value.expression,
  (expr) => {
    preview.value = null
    previewError.value = ''
    if (previewTimer) clearTimeout(previewTimer)
    if (!looksLikeExpr(expr)) return
    previewTimer = setTimeout(runPreview, 350)
  },
)

async function runPreview() {
  const expr = String(form.value.expression || '').trim()
  if (!looksLikeExpr(expr)) return
  const seq = ++previewSeq
  previewLoading.value = true
  try {
    const res = await validateCronExpr(expr)
    if (seq !== previewSeq) return // 已有更新的请求，丢弃这次结果
    if (res?.valid) {
      preview.value = res.preview || null
      previewError.value = ''
    } else {
      preview.value = null
      previewError.value = res?.error || '表达式非法'
    }
  } catch (err) {
    if (seq !== previewSeq) return
    preview.value = null
    previewError.value = errorText(err)
  } finally {
    if (seq === previewSeq) previewLoading.value = false
  }
}

// ---------------------------------------------------------------------------
// 新建 / 编辑
// ---------------------------------------------------------------------------

function openCreate() {
  editing.value = { mode: 'create' }
  form.value = { expression: '', command: '', comment: '' }
  formError.value = ''
  preview.value = null
  previewError.value = ''
}

function openEdit(job) {
  editing.value = { mode: 'edit', job }
  form.value = {
    expression: job.expression || '',
    command: job.command_missing ? '' : job.command || '',
    comment: job.comment || '',
  }
  formError.value = ''
  preview.value = null
  previewError.value = ''
  if (job.command_missing) {
    formError.value =
      '包装脚本已丢失（数据目录被动过），面板读不到原始命令。' +
      '这里**刻意不猜测**原命令：请核对后重新填写，或先删除该任务再重建。'
  }
  runPreview()
}

function closeEditor() {
  if (submitting.value) return
  editing.value = null
  pendingSave.value = null
}

function submitJob() {
  formError.value = ''
  const bad = validateForm({
    expression: form.value.expression,
    command: form.value.command,
    comment: form.value.comment,
    status: status.value,
  })
  if (bad) {
    formError.value = bad
    return
  }
  // 表达式合法性只认后端的判定。预览还没回来时先补一次，
  // 而不是拿一个**没验证过的**表达式直接提交。
  if (previewError.value) {
    formError.value = `表达式未被后端接受：${previewError.value}`
    return
  }
  if (!preview.value) {
    runPreview().then(() => {
      if (preview.value && !previewError.value) {
        pendingSave.value = { mode: editing.value?.mode, job: editing.value?.job || null }
      } else {
        formError.value = previewError.value || '表达式校验未通过，请检查后重试'
      }
    })
    return
  }
  pendingSave.value = { mode: editing.value?.mode, job: editing.value?.job || null }
}

async function doSubmitJob() {
  const target = pendingSave.value
  if (!target) return
  pendingSave.value = null
  const mode = target.mode
  const job = target.job
  try {
    submitting.value = true
    let res
    if (mode === 'create') {
      res = await createCronJob({
        expression: form.value.expression.trim(),
        command: form.value.command,
        comment: form.value.comment.trim(),
        expectedIds: expectedIds(jobs.value),
      })
    } else {
      res = await updateCronJob(job.id, {
        expression: form.value.expression.trim(),
        command: form.value.command,
        comment: form.value.comment.trim(),
        expectedIds: expectedIds(jobs.value),
      })
    }
    jobs.value = res?.jobs || jobs.value
    now.value = new Date()
    editing.value = null
    message.success(resultNotice(res, mode === 'create' ? '任务已新增' : '任务已保存'), {
      duration: 6000,
    })
    if (res?.warning) message.warning(res.warning, { duration: 8000 })
  } catch (err) {
    if (err.isUnauthorized) return
    if (err.editConflict) {
      // 别人的改动不能被覆盖：直接刷新列表，让用户重看一遍再编辑。
      message.warning('任务已被外部修改，列表已刷新，请重新编辑后再提交', { duration: 8000 })
      await refreshJobs({ quiet: true })
    }
    formError.value = errorText(err)
    // 表单保持打开：用户写了一次命令，不该因为一次冲突就全丢掉。
  } finally {
    submitting.value = false
  }
}

function onTab(name) {
  if (name === 'audit' && !(audit.value?.events || []).length) refreshAudit()
}

// ---------------------------------------------------------------------------
// 删除（服务端强制二次确认）
// ---------------------------------------------------------------------------

function openDelete(job) {
  deleteTarget.value = job
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  try {
    deleting.value = true
    const res = await deleteCronJob(deleteTarget.value.id, {
      confirm: true,
      expectedIds: expectedIds(jobs.value),
    })
    jobs.value = res?.jobs || []
    now.value = new Date()
    deleteTarget.value = null
    message.success(resultNotice(res, '任务已删除'), { duration: 6000 })
  } catch (err) {
    if (err.isUnauthorized) return
    if (err.editConflict) {
      message.warning('任务已被外部修改，列表已刷新，请确认后再删除', { duration: 8000 })
      await refreshJobs({ quiet: true })
    }
    message.error(errorText(err), { duration: 9000 })
  } finally {
    deleting.value = false
  }
}

// ---------------------------------------------------------------------------
// 执行日志
// ---------------------------------------------------------------------------

async function openLogs(job) {
  logsTarget.value = job
  logsResult.value = null
  logsError.value = ''
  logsLoading.value = true
  try {
    logsResult.value = await fetchCronLogs(job.id, 300)
  } catch (err) {
    logsError.value = errorText(err)
  } finally {
    logsLoading.value = false
  }
}

async function reloadLogs() {
  if (!logsTarget.value) return
  await openLogs(logsTarget.value)
}

function closeLogs() {
  logsTarget.value = null
  logsResult.value = null
}

// ---------------------------------------------------------------------------
// 渲染辅助（列定义里要用 h()）
// ---------------------------------------------------------------------------

function renderTags(job) {
  const list = []
  if (job.valid === false) list.push({ label: '表达式非法', type: 'error' })
  if (job.managed) list.push({ label: '面板管理', type: 'info' })
  else list.push({ label: '外部添加', type: 'warning' })
  if (job.command_missing) list.push({ label: '命令不可读', type: 'error' })
  if (!list.length) return h(NText, { depth: 3 }, { default: () => '—' })
  return h(
    NSpace,
    { size: 4, wrap: false },
    {
      default: () =>
        list.map((t) =>
          h(NTag, { size: 'tiny', type: t.type, bordered: false }, { default: () => t.label }),
        ),
    },
  )
}

const columns = computed(() => [
  {
    title: '表达式',
    key: 'expression',
    width: 190,
    render: (row) =>
      h('div', {}, [
        h(NText, { code: true, strong: true }, { default: () => row.expression || '—' }),
        row.human
          ? h('div', {}, [h(NText, { depth: 3, style: 'font-size: 12px' }, { default: () => row.human })])
          : null,
      ]),
  },
  { title: '备注', key: 'comment', width: 150, ellipsis: { tooltip: true }, render: (row) => row.comment || '—' },
  {
    title: '命令',
    key: 'command',
    minWidth: 260,
    ellipsis: { tooltip: true },
    render: (row) =>
      row.command_missing
        ? h(NText, { type: 'error' }, { default: () => '包装脚本丢失，命令不可读' })
        : h(NText, { code: true, style: 'font-size: 12px' }, { default: () => commandPreview(row.command, 120) }),
  },
  {
    title: '下次执行',
    key: '_next',
    width: 210,
    render: (row) =>
      h(
        NText,
        { type: row.valid === false ? 'error' : undefined, style: 'font-size: 12px' },
        { default: () => row._next },
      ),
  },
  { title: '标记', key: 'tags', width: 150, render: renderTags },
  {
    title: '操作',
    key: 'ops',
    width: 220,
    fixed: 'right',
    render: (row) =>
      h(
        NSpace,
        { size: 6, wrap: false },
        {
          default: () => [
            h(
              NButton,
              { size: 'tiny', tertiary: true, disabled: !available.value, onClick: () => openLogs(row) },
              { default: () => '日志' },
            ),
            h(
              NButton,
              {
                size: 'tiny',
                type: 'primary',
                tertiary: true,
                disabled: !writable.value || !available.value || row.valid === false,
                title:
                  row.valid === false
                    ? '表达式不被面板支持时不会替你改写，请用 crontab -e 处理'
                    : row.managed
                      ? '编辑任务'
                      : '编辑即收编：补标记注释并启用日志包装脚本',
                onClick: () => openEdit(row),
              },
              { default: () => '编辑' },
            ),
            h(
              NButton,
              {
                size: 'tiny',
                type: 'error',
                tertiary: true,
                disabled: !writable.value || !available.value,
                onClick: () => openDelete(row),
              },
              { default: () => '删除' },
            ),
          ],
        },
      ),
  },
])

const auditColumns = computed(() => [
  { title: '时间', key: 'time', width: 170, render: (row) => formatTimeFull(row.time) },
  {
    title: '操作',
    key: 'action',
    width: 110,
    render: (row) => actionLabel(row.action),
  },
  { title: '用户', key: 'user', width: 100, render: (row) => row.user || '—' },
  {
    title: '结果',
    key: 'outcome',
    width: 90,
    render: (row) => {
      const m = outcomeMeta(row.outcome)
      return h(NTag, { size: 'tiny', type: m.type, bordered: false }, { default: () => m.label })
    },
  },
  {
    title: '表达式 / 命令原文',
    key: 'detail',
    minWidth: 320,
    ellipsis: { tooltip: true },
    render: (row) => {
      const parts = []
      if (row.expression) parts.push(row.expression)
      if (row.command) parts.push(`→ ${row.command}`)
      if (row.rollback_error) parts.push(`⚠️ 回滚失败：${row.rollback_error}`)
      if (row.reason && !row.rollback_error) parts.push(row.reason)
      return h(NText, { style: 'font-size: 12px' }, { default: () => parts.join('  ') || '—' })
    },
  },
  {
    title: '确认 / 备份',
    key: 'backup',
    width: 200,
    ellipsis: { tooltip: true },
    render: (row) =>
      h(NText, { depth: 3, style: 'font-size: 12px' }, {
        default: () =>
          [row.confirmed ? '已确认' : '', row.backup_path || ''].filter(Boolean).join('｜') || '—',
      }),
  },
])

onMounted(async () => {
  await refreshAll()
})

// 供模板使用的少量派生值。
const previewRuns = computed(() => (preview.value?.runs || []).map(formatTimeFull))
const saveConfirm = computed(() =>
  saveConfirmText({
    job: editing.value?.job || null,
    expression: form.value.expression,
    command: form.value.command,
    preview: preview.value,
    adopt: adoptHint.value,
  }),
)
const canOpenEditor = computed(() => writable.value && available.value)
const logMeta = (s) => logStatusMeta(s)
const modeText = (m) => MODE_LABEL[m] || m || '未知'
const relText = (iso) => relativeText(iso, now.value)
</script>

<template>
  <div class="cron-page">
    <n-spin :show="loading">
      <n-card title="计划任务" size="small" class="cron-card">
        <template #header-extra>
          <n-space size="small">
            <n-button size="small" tertiary :loading="loading" @click="refreshAll">刷新</n-button>
            <n-button
              size="small"
              type="primary"
              :disabled="!canOpenEditor"
              @click="openCreate"
            >
              新建任务
            </n-button>
          </n-space>
        </template>

        <n-alert
          v-if="errorText_"
          type="error"
          class="cron-alert"
          closable
          @close="errorText_ = ''"
        >
          <span style="white-space: pre-line">{{ errorText_ }}</span>
        </n-alert>

        <!-- 顶部状态：面板到底在改谁的 crontab -->
        <n-alert :type="health.type" :show-icon="true" class="cron-alert">
          <template #header>{{ health.label }}</template>
          {{ health.detail }}
        </n-alert>

        <n-alert v-if="targetWarning(status)" type="warning" class="cron-alert">
          {{ targetWarning(status) }}
        </n-alert>

        <n-alert v-if="isFileMode" type="warning" class="cron-alert">
          当前是<strong>隔离文件模式</strong>（-cron-file）：这里的改动只会写进那个文件，
          <strong>系统 cron 不会执行它们</strong>。仅用于开发、验证与 CI。
        </n-alert>

        <n-alert v-if="!writable" type="warning" class="cron-alert">
          当前账号未被授予 <code>cron.write</code>，只能查看。
          面板自身的每一次写操作同样要走这个判定——不存在「面板自己可以绕过」的特权路径。
        </n-alert>

        <n-descriptions :column="3" size="small" label-placement="top" bordered class="cron-desc">
          <n-descriptions-item label="存取模式">
            <n-space size="small">
              <n-tag size="small" :type="isFileMode ? 'warning' : 'info'" :bordered="false">
                {{ modeText(status?.mode) }}
              </n-tag>
            </n-space>
          </n-descriptions-item>
          <n-descriptions-item label="管理对象">
            {{ status?.target || '—' }}
          </n-descriptions-item>
          <n-descriptions-item label="数据目录">
            <n-text depth="3" style="font-size: 12px">{{ status?.data_dir || '—' }}</n-text>
          </n-descriptions-item>
          <n-descriptions-item label="任务条数">
            {{ summary.total }}
            <n-text depth="3" style="font-size: 12px">
              （面板 {{ summary.managed }} ／ 外部 {{ summary.external }}
              <template v-if="summary.invalid"> ／ 非法 {{ summary.invalid }}</template>）
            </n-text>
          </n-descriptions-item>
          <n-descriptions-item label="审计">
            共 {{ status?.audit?.total ?? 0 }} 条，被拒 {{ status?.audit?.denied ?? 0 }} 条
          </n-descriptions-item>
          <n-descriptions-item label="日志上限">
            {{ ((status?.audit?.capacity ?? 1000)) }} 条内存缓冲
          </n-descriptions-item>
        </n-descriptions>

        <div v-if="backupsHint(status)" class="cron-backups">
          {{ backupsHint(status) }}
        </div>

        <n-tabs v-model:value="activeTab" type="line" class="cron-tabs" @update:value="onTab">
          <!-- ==================== 任务列表 ==================== -->
          <n-tab-pane name="jobs" tab="任务列表">
            <n-input
              v-model:value="keyword"
              size="small"
              clearable
              placeholder="按表达式 / 命令 / 备注 / ID 过滤（仅影响显示，统计仍按全量）"
              class="cron-filter"
            />
            <n-data-table
              :columns="columns"
              :data="rows"
              :row-key="(r) => r.id"
              size="small"
              :scroll-x="1180"
              :pagination="{ pageSize: 20, showSizePicker: false }"
            />
            <n-empty v-if="!rows.length" description="暂无任务" class="cron-empty" />

            <n-collapse v-if="settings.length" class="cron-settings">
              <n-collapse-item :title="`crontab 里的全局设置（${settings.length} 条，只读）`" name="s">
                <n-text depth="3" style="font-size: 12px">
                  这些行由你在 crontab 里手工添加，面板<strong>绝不改写</strong>它们
                  （MAILTO 等会影响 cron 的输出投递，改了会造成预期之外的邮件行为）。
                </n-text>
                <pre
                  v-for="s in settings"
                  :key="s.line_no"
                  class="cron-raw"
                >{{ s.raw }}</pre>
              </n-collapse-item>
            </n-collapse>
          </n-tab-pane>

          <!-- ==================== 操作审计 ==================== -->
          <n-tab-pane name="audit" tab="操作审计">
            <n-space class="cron-filter" size="small" align="center">
              <n-button size="small" tertiary :loading="auditLoading" @click="refreshAudit">
                刷新审计
              </n-button>
              <n-button
                size="small"
                :type="auditOutcome === '' ? 'primary' : 'default'"
                tertiary
                @click="auditOutcome = ''; refreshAudit()"
              >
                全部
              </n-button>
              <n-button
                size="small"
                :type="auditOutcome === 'denied' ? 'error' : 'default'"
                tertiary
                @click="auditOutcome = 'denied'; refreshAudit()"
              >
                只看被拒绝
              </n-button>
              <n-text depth="3" style="font-size: 12px">
                计划任务以面板身份执行任意命令，因此命令<strong>原文</strong>必须留痕，
                包括被拒绝的越权尝试。
              </n-text>
            </n-space>
            <n-data-table
              :columns="auditColumns"
              :data="audit?.events || []"
              :row-key="(r) => r.seq"
              size="small"
              :scroll-x="1100"
              :pagination="{ pageSize: 20 }"
            />
            <n-empty v-if="!(audit?.events || []).length" description="暂无审计记录" />
          </n-tab-pane>
        </n-tabs>
      </n-card>
    </n-spin>

    <!-- ==================== 新建 / 编辑弹窗 ==================== -->
    <n-modal
      :show="editing !== null"
      preset="card"
      :title="editing?.mode === 'create' ? '新建计划任务' : '编辑计划任务'"
      style="max-width: 720px"
      :mask-closable="false"
      @update:show="closeEditor"
    >
      <n-form label-placement="top" size="small">
        <n-form-item label="cron 表达式">
          <div class="cron-expr">
            <n-input
              v-model:value="form.expression"
              placeholder="分 时 日 月 周，或 @daily 之类的别名"
              @blur="runPreview"
            />
            <div class="cron-chips">
              <n-button
                v-for="e in EXPR_EXAMPLES"
                :key="e.expr"
                size="tiny"
                tertiary
                :title="e.expr"
                @click="form.expression = e.expr"
              >
                {{ e.label }}
              </n-button>
            </div>
          </div>
        </n-form-item>

        <n-alert v-if="previewError" type="error" class="cron-alert">
          {{ previewError }}
        </n-alert>
        <n-alert v-else-if="preview" type="info" class="cron-alert">
          <div>
            实际写入：<code>{{ preview.expression }}</code>
            <span v-if="preview.human">　{{ preview.human }}</span>
          </div>
          <div v-if="previewRuns.length" class="cron-runs">
            <div>接下来 {{ previewRuns.length }} 次执行（本地时区）：</div>
            <div v-for="(t, i) in previewRuns" :key="t" class="cron-run-row">
              {{ t }}
              <n-text depth="3" style="font-size: 12px">{{ relText(preview.runs[i]) }}</n-text>
            </div>
          </div>
          <div v-else-if="preview.note" class="cron-runs">{{ preview.note }}</div>
          <div v-else-if="preview.reason" class="cron-runs">⚠️ {{ preview.reason }}</div>
        </n-alert>

        <n-form-item label="要执行的命令">
          <n-input
            v-model:value="form.command"
            type="textarea"
            :autosize="{ minRows: 2, maxRows: 8 }"
            placeholder="例如：/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1"
          />
        </n-form-item>
        <div class="cron-count">
          命令剩余 {{ formByteLeft }} 字节　·　备注剩余 {{ formCommentLeft }} 字节
        </div>

        <n-alert type="warning" :show-icon="true" class="cron-alert">
          <strong>命令以面板运行身份（生产环境通常是 root）在无人值守的时刻执行。</strong>
          面板允许完整 shell 命令，也<strong>不做任何命令黑白名单</strong>——
          有终端功能的前提下，任何过滤都拦不住真想绕过的人，只会挡住正常运维写法。
          因此安全靠的是：登录鉴权 + 权限判定 + 二次确认 + <strong>命令原文完整进审计</strong>。
          请只写你自己理解并验证过的命令。
        </n-alert>

        <n-alert v-if="adoptHint" type="info" class="cron-alert">
          你正在编辑一条<strong>外部添加</strong>的任务，保存即「收编」：
          面板会在它上方补一行标记注释（备注存在那里），并把执行命令换成面板生成的
          日志包装脚本（命令原文原样搬进脚本文件，这样才能记录输出与退出码）。
          原始行在「原始行」折叠区里始终可见。
        </n-alert>

        <n-form-item label="备注（存进 crontab 的标记注释，可选）">
          <n-input v-model:value="form.comment" placeholder="例如：每天 02:30 备份数据库" />
        </n-form-item>

        <n-collapse class="cron-raw-box">
          <n-collapse-item title="这条任务在 crontab 里的原始行" name="raw">
            <pre class="cron-raw">{{ editing?.job?.raw || '（新建：保存后生成）' }}</pre>
          </n-collapse-item>
        </n-collapse>

        <n-alert v-if="formError" type="error" class="cron-alert">
          <span style="white-space: pre-line">{{ formError }}</span>
        </n-alert>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button :disabled="submitting" @click="closeEditor">取消</n-button>
          <n-button
            type="primary"
            :loading="submitting || previewLoading"
            @click="submitJob"
          >
            保存前确认
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ==================== 保存前的最终确认（写明命令与执行时间） ==================== -->
    <n-modal
      :show="pendingSave !== null"
      preset="card"
      title="确认保存计划任务"
      style="max-width: 620px"
      :mask-closable="false"
      @update:show="(v) => { if (!v) pendingSave = null }"
    >
      <n-alert type="warning" :show-icon="true" class="cron-alert">
        <span style="white-space: pre-line">{{ saveConfirm }}</span>
      </n-alert>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="submitting" @click="pendingSave = null">返回修改</n-button>
          <n-button type="primary" :loading="submitting" @click="doSubmitJob">确认保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ==================== 删除确认（写明表达式与命令原文） ==================== -->
    <n-modal
      :show="deleteTarget !== null"
      preset="card"
      title="确认删除计划任务"
      style="max-width: 620px"
      :mask-closable="false"
      @update:show="(v) => { if (!v) deleteTarget = null }"
    >
      <n-alert type="error" :show-icon="true" class="cron-alert">
        <span style="white-space: pre-line">{{ deleteConfirm }}</span>
      </n-alert>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="deleting" @click="deleteTarget = null">取消</n-button>
          <n-button type="error" :loading="deleting" @click="confirmDelete">确认删除</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ==================== 执行日志 ==================== -->
    <n-modal
      :show="logsTarget !== null"
      preset="card"
      :title="`执行日志 · ${logsTarget?.expression || ''}`"
      style="max-width: 900px"
      @update:show="(v) => { if (!v) closeLogs() }"
    >
      <n-spin :show="logsLoading">
        <n-space class="cron-filter" size="small">
          <n-button size="small" tertiary @click="reloadLogs">重新读取</n-button>
          <n-text depth="3" style="font-size: 12px">
            输出与退出码由面板生成的包装脚本写入
            <code>{{ logsResult?.log_path || logsTarget?.log_path || '（数据目录/logs/）' }}</code>
          </n-text>
        </n-space>
        <n-alert v-if="logsError" type="error" class="cron-alert">
          <span style="white-space: pre-line">{{ logsError }}</span>
        </n-alert>
        <n-alert v-else-if="logsResult && !logsResult.found" type="info" class="cron-alert">
          {{ logsResult.reason || '还没有执行记录。' }}
        </n-alert>
        <n-alert v-if="logsResult?.truncated" type="warning" class="cron-alert">
          日志已超出返回窗口，以下是最近的部分。完整内容请直接读日志文件。
        </n-alert>

        <div v-if="(logsResult?.entries || []).length" class="cron-log">
          <div
            v-for="(e, i) in logsResult.entries"
            :key="i"
            class="cron-log-entry"
          >
            <n-tag size="tiny" :type="logMeta(e.status).type" :bordered="false">
              {{ logMeta(e.status).label }} · {{ exitText(e) }}
            </n-tag>
            <pre class="cron-raw">{{ e.raw }}</pre>
          </div>
        </div>
        <pre v-else-if="logsResult?.tail" class="cron-raw cron-raw-block">{{ logsResult.tail }}</pre>
        <n-empty v-else-if="!logsError && logsResult && !logsResult.found" description="无内容" />

        <n-text v-if="logsResult?.command" depth="3" style="font-size: 12px">
          当次命令：{{ commandPreview(logsResult.command) }}
        </n-text>
      </n-spin>
    </n-modal>
  </div>
</template>

<style scoped>
.cron-page {
  padding: 16px;
}
.cron-card {
  margin-bottom: 16px;
}
.cron-alert {
  margin-bottom: 12px;
}
.cron-desc {
  margin-bottom: 8px;
}
.cron-backups {
  margin: 8px 0 4px;
  font-size: 12px;
  color: var(--n-text-color-3, #999);
}
.cron-tabs {
  margin-top: 8px;
}
.cron-filter {
  margin-bottom: 12px;
}
.cron-empty {
  margin: 16px 0;
}
.cron-settings {
  margin-top: 12px;
}
.cron-raw {
  margin: 6px 0 0;
  padding: 6px 8px;
  background: rgba(128, 128, 128, 0.12);
  border-radius: 4px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
.cron-raw-block {
  max-height: 320px;
  overflow: auto;
}
.cron-raw-box {
  margin-bottom: 12px;
}
.cron-expr {
  width: 100%;
}
.cron-chips {
  margin-top: 8px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.cron-runs {
  margin-top: 6px;
  font-size: 12px;
}
.cron-run-row {
  font-size: 12px;
}
.cron-count {
  font-size: 12px;
  color: var(--n-text-color-3, #999);
  margin: -6px 0 10px;
}
.cron-log {
  max-height: 420px;
  overflow: auto;
}
.cron-log-entry {
  margin-bottom: 10px;
}
</style>
