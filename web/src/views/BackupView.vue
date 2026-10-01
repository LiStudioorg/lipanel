<script setup>
// 备份恢复页（阶段五 5.3，核心自带）。
//
// 内置基础页面（不是插件）：备份是服务器的基础设施，
// 依赖插件机制会让用户在插件未启动时配不了备份任务。
//
// ########## 这一页与其它所有页面的本质区别 ##########
//
// 备份里有一件**不可逆**的操作：恢复到目标目录会**覆盖**同名文件，
// 且没有撤销。其它页面再坏也只是一次操作失败；
// 这次坏掉的是数据本身——而且往往要到几天后才被发现。
//
// 因此这一页有四处刻意的设计：
//
//   ① 恢复是红色警示 + **逐字输入任务名**才放行。
//      前端弹窗只是体验；后端还独立强制 confirm=true + 逐字比对
//      （428），所以即便这里出 bug 也不会误覆盖。
//
//   ② 4 个标签页各管一件事：任务 / 历史 / 存储配置 / 审计。
//      恢复需要的证据横跨四页，分开反而让"出了事该去哪看"更清楚。
//
//   ③ 源 / 恢复目标目录用**只读**的文件选择器（走 4.2 的 file API），
//      不做成手输——手输路径是除白名单外最常见的越界来源。
//
//   ④ 任务列表首列有一句**聚合状态摘要**（describeTask），
//      让用户一眼看出"这条任务到底会不会跑"。
//
// 交互约定（与工程约束一致）：所有请求都有 Loading 且在 finally 复位；
// 失败必须可见；后端给的 hint 一并展示。
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  NAlert,
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NRadioButton,
  NRadioGroup,
  NSpace,
  NSpin,
  NStatistic,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  NText,
  useMessage,
} from 'naive-ui' 
import {
  fetchBackupStatus,
  fetchBackupTasks,
  fetchBackupHistory,
  fetchBackupFiles,
  fetchBackupStorages,
  fetchBackupAudit,
  previewBackupRestore,
  createBackupTask,
  updateBackupTask,
  deleteBackupTask,
  runBackupTask,
  deleteBackupFile,
  restoreBackup,
  createBackupStorage,
  updateBackupStorage,
  deleteBackupStorage,
  testBackupStorage,
  downloadBackupFile,
} from '@/api/backup'
import { validateCronExpr } from '@/api/cron'
import { EXPR_EXAMPLES } from './cronLogic.js'
import {
  emptyTaskForm,
  taskToForm,
  validateTaskForm,
  normalizeTaskPayload,
  emptyStorageForm,
  storageToForm,
  validateStorageForm,
  normalizeStoragePayload,
  resolveStorageTypes,
  resolveKeepPolicies,
  storageTypeFields,
  storageTypeLabel,
  storageCredentialHint,
  restoreDangerLines,
  restoreConfirmHint,
  restoreRiskLevel,
  canSubmitRestore,
  describeTask,
  historyRowOf,
  fileRowOf,
  auditRowOf,
  summarizeStorageUsage,
  resolveRestoreTarget,
  restoreRootsHint,
  cronUnavailableHint,
} from './backupLogic.js' 
import { fetchListing } from '@/api/files'

const message = useMessage()

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

const loading = ref(false)
const errorText_ = ref('')
const activeTab = ref('tasks')

const status = ref(null)
const tasks = ref([])
const files = ref([])
const storages = ref([])
const audit = ref([])
const auditLoading = ref(false)
const auditFilter = ref({ outcome: '' })

const selectedTaskId = ref('')
const selectedTaskHistory = ref([])
const historyLoading = ref(false)

// 表单 / 弹窗。
const showTaskModal = ref(false)
const form = ref(emptyTaskForm())
const submittingTask = ref(false)
const exprPreview = ref(null)
const exprPreviewLoading = ref(false)

const showStorageModal = ref(false)
const storageForm = ref(emptyStorageForm())
const submittingStorage = ref(false)

// 立即执行。
const runningId = ref('')

// 删除确认。
const deleteTaskTarget = ref(null)
const deleteFileTarget = ref(null)
const deleteStorageTarget = ref(null)

// 恢复。
const showRestoreModal = ref(false)
const restoreFile_ = ref(null)
const restoreTarget = ref('')
const restoreConfirmText = ref('')
const restorePreview = ref(null)
const restorePreviewLoading = ref(false)
const restorePreviewError = ref('')
const restoring = ref(false)

const now = ref(new Date())

// ---------------------------------------------------------------------------
// 计算属性
// ---------------------------------------------------------------------------

const tl = (s) => (Array.isArray(status.value?.permissions) ? status.value.permissions : null)
const writable = computed(() => {
  const p = tl()
  if (!p) return true // 未知权限不锁死（老版本后端）
  return p.includes('backup.write')
})

const storageTypes = computed(() => resolveStorageTypes(status.value))
const keepPolicies = computed(() => resolveKeepPolicies(status.value))

const storageOptions = computed(() =>
  storages.value.map((it) => ({
    label: `${it.storage.name}（${storageTypeLabel(storageTypes.value, it.storage.type)}）`,
    value: it.storage.id,
  }))
)
const storageTypeOptions = computed(() => storageTypes.value.map((t) => ({ label: t.label, value: t.type })))

const taskRows = computed(() =>
  tasks.value.map((t) => {
    const d = describeTask(t, { now: now.value })
    return { ...t, _statusType: d.type, _statusText: d.text }
  })
)

const usage = computed(() => summarizeStorageUsage(files.value))

const fileRows = computed(() =>
  files.value.map((f) => ({ ...fileRowOf(f), _file: f }))
)

const auditRows = computed(() =>
  audit.value.map((ev) => auditRowOf(ev, { now: now.value }))
)

const historyRows = computed(() =>
  selectedTaskHistory.value.map((e) => ({ ...historyRowOf(e, { now: now.value }), _entry: e }))
)

const canRestore = computed(() => {
  const f = restoreFile_.value
  return Boolean(f && f.key && f.storageId && writable.value)
})

// 恢复确认输入框是否与任务名逐字相等。
const confirmMatches = computed(() =>
  restoreFile_.value ? restoreConfirmMatches(restoreFile_.value.taskName, restoreConfirmText.value) : false
)

const taskFormErrors = computed(() => validateTaskForm(form.value, { storageTypes: storageTypes.value }))
const storageFormErrors = computed(() => validateStorageForm(storageForm.value))
const storageFields = computed(() => storageTypeFields(storageTypes.value, storageForm.value.type))
const storageFieldSet = computed(() => new Set(storageFields.value))

const storageRows = computed(() =>
  storages.value.map((it) => ({ ...it, _credential: storageCredentialHint(it) }))
)

const restoreRootsScopeHint = computed(() => restoreRootsHint(status.value))
const cronHint = computed(() => cronUnavailableHint(status.value))
const restoreTargetDefault = computed(() => resolveRestoreTarget(status.value))

// 保留策略选项。
const keepSelectOptions = computed(() =>
  keepPolicies.value.map((p) => ({ label: p.label, value: p.policy, description: p.description }))
)

// 是否清理 staging 后端的本地副本其实无所谓，这里不体现。

// ---------------------------------------------------------------------------
// 基础加载
// ---------------------------------------------------------------------------

async function loadStatus() {
  try {
    const res = await fetchBackupStatus()
    // 后端返回 { status: {...} } 或直接是状态对象，兼容两种。
    status.value = res?.status && res.status.restore_roots ? res.status : res
  } catch (err) {
    errorText_.value = err.message
  }
}

async function reloadTasks() {
  try {
    const res = await fetchBackupTasks()
    tasks.value = res?.tasks || []
    if (!selectedTaskId.value && tasks.value.length > 0) {
      selectedTaskId.value = tasks.value[0].id
      await loadHistory()
    }
  } catch (err) {
    message.error(`加载任务失败：${err.message}`)
  }
}

async function reloadFiles() {
  try {
    const res = await fetchBackupFiles()
    files.value = res?.files || []
  } catch (err) {
    message.error(`加载备份清单失败：${err.message}`)
  }
}

async function reloadStorages() {
  try {
    const res = await fetchBackupStorages()
    storages.value = res?.storages || []
  } catch (err) {
    message.error(`加载存储配置失败：${err.message}`)
  }
}

async function loadHistory() {
  if (!selectedTaskId.value) {
    selectedTaskHistory.value = []
    return
  }
  historyLoading.value = true
  try {
    const res = await fetchBackupHistory(selectedTaskId.value, 200)
    selectedTaskHistory.value = res?.entries || []
  } catch (err) {
    message.error(`加载执行历史失败：${err.message}`)
  } finally {
    historyLoading.value = false
  }
}

async function loadAudit() {
  auditLoading.value = true
  try {
    const res = await fetchBackupAudit({ limit: 300, outcome: auditFilter.value.outcome })
    audit.value = res?.events || []
  } catch (err) {
    message.error(`加载审计失败：${err.message}`)
  } finally {
    auditLoading.value = false
  }
}

async function loadAll() {
  loading.value = true
  errorText_.value = ''
  try {
    await Promise.all([loadStatus(), reloadTasks(), reloadFiles(), reloadStorages()])
  } finally {
    loading.value = false
  }
}

function refreshEverything() {
  return Promise.all([loadStatus(), reloadTasks(), reloadFiles(), reloadStorages()])
}

// 选中的任务变化时刷新历史。
watch(selectedTaskId, () => loadHistory())
watch(activeTab, (t) => {
  if (t === 'audit') loadAudit()
  if (t === 'history' && selectedTaskId.value) loadHistory()
})

onMounted(() => loadAll())

// ---------------------------------------------------------------------------
// 表达式校验
// ---------------------------------------------------------------------------

async function onExprChange() {
  const expr = (form.value.expr || '').trim()
  exprPreview.value = null
  if (!expr) return
  exprPreviewLoading.value = true
  try {
    const res = await validateCronExpr(expr)
    exprPreview.value = res || null
  } catch {
    exprPreview.value = null
  } finally {
    exprPreviewLoading.value = false
  }
}

// ---------------------------------------------------------------------------
// 目录选择器（只读）
// ---------------------------------------------------------------------------
//
// 复用 4.2 的文件管理接口（fetchListing）。它返回的条目带后端算好的
// 绝对路径（entry.path）与 is_dir 标记。前端**只用后端给的路径**，
// 不在选择器里自己拼路径——这是"白名单被绕开"之外最安全的做法：
// 后端 file.Resolver 已经在每次列目录时把结果限制在白名单内了。
//
// 这是只读浏览：面板不会因为"选个目录"这个动作写任何东西。

const dirPicker = ref(null) // { title, setter }
// 弹窗的 v-model 需要可变表达式（不能是 Boolean(dirPicker)），
// 用一个可写的 computed 转接。
const dirPickerShow = computed({
  get: () => Boolean(dirPicker.value),
  set: (v) => { if (!v) dirPicker.value = null },
})
// 删除类弹窗同样需要可变表达式（v-model 不能是 Boolean(...) 这种函数调用）。
const deleteTaskShow = computed({
  get: () => Boolean(deleteTaskTarget.value),
  set: (v) => { if (!v) deleteTaskTarget.value = null },
})
const deleteFileShow = computed({
  get: () => Boolean(deleteFileTarget.value),
  set: (v) => { if (!v) deleteFileTarget.value = null },
})
const deleteStorageShow = computed({
  get: () => Boolean(deleteStorageTarget.value),
  set: (v) => { if (!v) deleteStorageTarget.value = null },
})
const currentDir = ref('/')
const currentEntries = ref([])
const dirPickerLoading = ref('')

function openDirPicker(title, setter) {
  dirPicker.value = { title, setter }
  currentDir.value = '/'
  browseDir('/')
}

async function browseDir(path) {
  currentDir.value = path
  dirPickerLoading.value = path
  currentEntries.value = []
  try {
    const data = await fetchListing(path)
    currentEntries.value = data?.entries || []
  } catch (err) {
    message.error(`读取目录失败：${err.message}`)
  } finally {
    dirPickerLoading.value = ''
  }
}

function enterDir(entry) {
  if (!entry?.is_dir) return
  browseDir(entry.path || entry.name)
}

function upDir() {
  const parent = parentPathOf(currentDir.value)
  if (parent !== currentDir.value) browseDir(parent)
}

// parentPathOf 取上一级：/a/b -> /a，/a -> /，/ -> /。
function parentPathOf(path) {
  const p = String(path ?? '/')
  if (p === '/' || p === '') return '/'
  const trimmed = p.replace(/\/+$/, '')
  const idx = trimmed.lastIndexOf('/')
  if (idx <= 0) return '/'
  return trimmed.slice(0, idx)
}

function pickThisDir() {
  if (dirPicker.value?.setter) dirPicker.value.setter(currentDir.value)
  dirPicker.value = null
}

function closeDirPicker() {
  dirPicker.value = null
}

// ---------------------------------------------------------------------------
// 任务：打开 / 保存 / 删除
// ---------------------------------------------------------------------------

function openCreateTask() {
  form.value = emptyTaskForm()
  exprPreview.value = null
  showTaskModal.value = true
}

function openEditTask(task) {
  form.value = taskToForm(task)
  exprPreview.value = null
  showTaskModal.value = true
}

function setSourcePath(path) {
  form.value.source_path = path
}

async function submitTask() {
  const errors = validateTaskForm(form.value, { storageTypes: storageTypes.value })
  const expr = (form.value.expr || '').trim()
  if (Object.keys(errors).length) {
    message.error(Object.values(errors)[0])
    return
  }
  if (!expr) {
    message.error('请填写 cron 表达式')
    return
  }
  submittingTask.value = true
  try {
    const payload = normalizeTaskPayload(form.value)
    if (form.value.id) {
      payload.expected_ids = tasks.value.map((t) => t.id)
      await updateBackupTask(form.value.id, payload)
      message.success('任务已更新')
    } else {
      await createBackupTask(payload)
      message.success('备份任务已创建')
    }
    showTaskModal.value = false
    await refreshEverything()
  } catch (err) {
    message.error(err.message)
    if (err.confirmRequired) {
      message.warning(err.hint || '该操作需要二次确认。')
    }
  } finally {
    submittingTask.value = false
  }
}

async function performDeleteTask() {
  if (!deleteTaskTarget.value) return
  try {
    await deleteBackupTask(deleteTaskTarget.value.id, {
      confirm: true,
      expectedIds: tasks.value.map((t) => t.id),
    })
    message.success('备份任务已删除')
    deleteTaskTarget.value = null
    await refreshEverything()
  } catch (err) {
    message.error(err.message)
  }
}

// ---------------------------------------------------------------------------
// 任务：立即执行
// ---------------------------------------------------------------------------

async function performRun(id) {
  runningId.value = id
  try {
    const res = await runBackupTask(id)
    if (res?.skipped) {
      message.warning('该任务已有一次备份在执行，本次已跳过。')
    } else {
      const bytes = res?.result?.entry?.archive_bytes
      message.success(bytes ? `备份完成（${humanBytes(bytes)}）` : '备份完成')
    }
    await refreshEverything()
  } catch (err) {
    message.error(err.message)
  } finally {
    runningId.value = ''
  }
}

// ---------------------------------------------------------------------------
// 存储：打开 / 保存 / 测试 / 删除
// ---------------------------------------------------------------------------

function openCreateStorage() {
  storageForm.value = emptyStorageForm()
  showStorageModal.value = true
}

function openEditStorage(item) {
  storageForm.value = storageToForm(item.storage)
  showStorageModal.value = true
}

function setStoragePath(path) {
  storageForm.value.path = path
}

async function submitStorage() {
  const errors = validateStorageForm(storageForm.value)
  if (Object.keys(errors).length) {
    message.error(Object.values(errors)[0])
    return
  }
  submittingStorage.value = true
  try {
    const payload = normalizeStoragePayload(storageForm.value)
    if (storageForm.value.id) {
      await updateBackupStorage(storageForm.value.id, payload)
      message.success('存储配置已更新')
    } else {
      await createBackupStorage(payload)
      message.success('存储配置已创建')
    }
    showStorageModal.value = false
    await reloadStorages()
  } catch (err) {
    message.error(err.message)
  } finally {
    submittingStorage.value = false
  }
}

async function performTestStorage() {
  const errors = validateStorageForm(storageForm.value)
  if (Object.keys(errors).length) {
    message.error(Object.values(errors)[0])
    return
  }
  submittingStorage.value = true
  try {
    const payload = normalizeStoragePayload(storageForm.value)
    await testBackupStorage(payload, { id: storageForm.value.id || '' })
    message.success('连通性正常（已写入并删除测试对象）')
  } catch (err) {
    message.error(err.message)
    message.warning(err.hint || '')
  } finally {
    submittingStorage.value = false
  }
}

async function performDeleteStorage() {
  if (!deleteStorageTarget.value) return
  try {
    await deleteBackupStorage(deleteStorageTarget.value.id, { confirm: true })
    message.success('存储配置已删除')
    deleteStorageTarget.value = null
    await reloadStorages()
  } catch (err) {
    if (err.storageInUse) {
      message.error('该存储仍被以下任务引用：' + (err.usedBy || []).join('、'))
    } else {
      message.error(err.message)
    }
  }
}

// ---------------------------------------------------------------------------
// 备份文件：下载 / 删除 / 恢复
// ---------------------------------------------------------------------------

async function performDownloadFile(file) {
  try {
    await downloadBackupFile({
      storageId: file.storage_id,
      key: file.key,
      filename: file.name,
    })
    message.success('已开始下载')
  } catch (err) {
    message.error(err.message)
  }
}

async function performDeleteFile() {
  if (!deleteFileTarget.value) return
  try {
    await deleteBackupFile({
      storageId: deleteFileTarget.value.storage_id,
      key: deleteFileTarget.value.key,
      confirm: true,
    })
    message.success('备份文件已删除')
    deleteFileTarget.value = null
    await reloadFiles()
  } catch (err) {
    message.error(err.message)
  }
}

function openRestore(file) {
  restoreFile_.value = {
    storageId: file.storage_id,
    key: file.key,
    name: file.name,
    taskName: file.task_name,
  }
  restoreTarget.value = ''
  restoreConfirmText.value = ''
  restorePreview.value = null
  restorePreviewError.value = ''
  showRestoreModal.value = true
  // 默认目标目录：面板自己的恢复根 + 存储名。
  restoreTarget.value = resolveRestoreTarget(status.value, file.storage_type || '')
}

async function refreshRestorePreview() {
  if (!restoreFile_.value) return
  if (!restoreTarget.value.trim()) {
    message.warning('请先填写恢复目标目录')
    return
  }
  restorePreviewLoading.value = true
  restorePreviewError.value = ''
  try {
    const res = await previewBackupRestore({
      storageId: restoreFile_.value.storageId,
      key: restoreFile_.value.key,
      targetDir: restoreTarget.value.trim(),
    })
    restorePreview.value = res?.preview || null
  } catch (err) {
    restorePreview.value = null
    restorePreviewError.value = err.message
  } finally {
    restorePreviewLoading.value = false
  }
}

function setRestoreTarget(path) {
  restoreTarget.value = path
}

async function performRestore() {
  if (!restoreFile_.value) return
  if (!confirmMatches.value) {
    message.error('请逐字输入任务名后再恢复')
    return
  }
  restoring.value = true
  try {
    await restoreBackup({
      storageId: restoreFile_.value.storageId,
      key: restoreFile_.value.key,
      targetDir: restoreTarget.value.trim(),
      confirm: true,
      confirmText: restoreConfirmText.value,
    })
    message.success('恢复完成')
    showRestoreModal.value = false
  } catch (err) {
    message.error(err.message)
    message.warning(err.hint || '')
  } finally {
    restoring.value = false
  }
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

async function applyAuditFilter() {
  await loadAudit()
}

// ---------------------------------------------------------------------------
// 表格列
// ---------------------------------------------------------------------------

const taskColumns = [
  { title: '任务名', key: 'name', width: 200 },
  { title: '状态', key: '_statusText', width: 340 },
  { title: '源路径', key: 'source_path', width: 240 },
  { title: '目标存储', key: 'storage_name', width: 140 },
  { title: '计划', key: 'expr', width: 160 },
  {
    title: '上次执行',
    key: 'last',
    render: (row) =>
      row.last_status ? h(NText, null, () => statusMeta(row.last_status).label) : h(NText, null, '—'),
  },
  {
    title: '操作',
    key: 'actions',
    width: 320,
    render: (row) =>
      h(NSpace, null, () => [
        h(NButton, { size: 'small', disabled: row._running, onClick: () => performRun(row.id) }, () =>
          row._running ? '执行中…' : '立即执行'),
        h(NButton, { size: 'small', onClick: () => openEditTask(row) }, () => '编辑'),
        h(NButton, { size: 'small', type: 'error', quaternary: true, onClick: () => (deleteTaskTarget.value = row) }, () => '删除'),
      ]),
  },
]

const historyColumns = [
  { title: '开始时间', key: 'started_at', width: 190 },
  { title: '状态', key: 'status_label', width: 90 },
  { title: '触发', key: 'trigger', width: 70 },
  { title: '大小', key: 'size_text', width: 100 },
  { title: '耗时', key: 'duration', width: 100 },
  { title: '文件数', key: 'files', width: 80 },
  { title: '清理', key: 'pruned', width: 70 },
  {
    title: '备注/错误',
    key: 'note',
    render: (row) =>
      row.error
        ? h(NText, { type: 'error', depth: 3 }, () => row.error)
        : row.warnings && row.warnings.length
          ? h(NText, { depth: 2 }, () => row.warnings.length + ' 条打包告警')
          : h(NText, null, '—'),
  },
]

const fileColumns = [
  { title: '备份对象', key: 'name', width: 320 },
  { title: '所属任务', key: 'task_name', width: 160 },
  { title: '存储', key: 'storage_type', width: 100 },
  { title: '大小', key: 'size_text', width: 100 },
  { title: '写入时间', key: 'stamp', width: 170 },
  {
    title: '操作',
    key: 'actions',
    width: 260,
    render: (row) =>
      h(NSpace, null, () => [
        h(NButton, { size: 'small', onClick: () => performDownloadFile(row._file) }, () => '下载'),
        h(NButton, { size: 'small', type: 'warning', onClick: () => openRestore(row._file) }, () => '恢复'),
        h(NButton, { size: 'small', type: 'error', quaternary: true, onClick: () => (deleteFileTarget.value = row._file) }, () => '删除'),
      ]),
  },
]

const storageColumns = [
  { title: '名称', key: 'name', width: 180 },
  {
    title: '类型',
    key: 'type',
    render: (row) => h(NTag, null, () => storageTypeLabel(storageTypes.value, row.storage.type)),
  },
  { title: '目标 / 地址', key: 'desc', width: 280 },
  { title: '凭证', key: '_credential', width: 220 },
  {
    title: '操作',
    key: 'actions',
    width: 260,
    render: (row) =>
      h(NSpace, null, () => [
        h(NButton, { size: 'small', onClick: () => openEditStorage(row) }, () => '编辑'),
        h(NButton, { size: 'small', type: 'error', quaternary: true, onClick: () => (deleteStorageTarget.value = row.storage) }, () => '删除'),
      ]),
  },
]


const auditColumns = [
  { title: '时间', key: 'time', width: 190 },
  { title: '用户', key: 'user', width: 100 },
  { title: '来源 IP', key: 'client_ip', width: 120 },
  { title: '操作', key: 'action_label', width: 100 },
  { title: '对象', key: 'target', width: 200 },
  {
    title: '结果',
    key: 'outcome_label',
    render: (row) =>
      h(NTag, { type: { allowed: 'success', denied: 'warning', failed: 'error' }[row.outcome] || 'default' }, () => row.outcome_label),
  },
  { title: '耗时', key: 'duration', width: 100 },
  { title: '详情', key: 'reason', width: 240 },
]
</script>
<template>
  <div class="backup-view">
    <n-card
      title="备份与恢复"
      :bordered="false"
      :segmented="{ content: true }"
    >
      <template #header-extra>
        <n-space align="center">
          <n-button size="small" tertiary :loading="loading" @click="loadAll()">刷新</n-button>
        </n-space>
      </template>

      <n-alert
        v-if="errorText_"
        type="error"
        title="加载失败"
        class="mb-12"
        @close="errorText_ = ''"
      >
        {{ errorText_ }}
      </n-alert>

      <n-alert
        v-if="restoreRootsScopeHint"
        type="info"
        class="mb-12"
        :show-icon="true"
      >
        {{ restoreRootsScopeHint }}
      </n-alert>

      <n-alert
        v-if="cronHint"
        type="warning"
        class="mb-12"
        :show-icon="true"
      >
        {{ cronHint }}
      </n-alert>

      <n-space class="mb-12" align="baseline">
        <n-statistic label="备份文件" :value="usage.total" />
        <n-statistic label="占用空间" :value="usage.totalBytes">
          <template #suffix>{{ humanBytes(usage.totalBytes) }}</template>
        </n-statistic>
      </n-space>

      <n-tabs v-model:value="activeTab" type="line" animated>
        <!-- ===================== 任务 ===================== -->
        <n-tab-pane name="tasks" tab="任务">
          <div class="tb">
            <n-space justify="space-between">
              <n-button type="primary" :disabled="!writable" @click="openCreateTask()">
                新建备份任务
              </n-button>
            </n-space>
          </div>

          <n-data-table
            :columns="taskColumns"
            :data="taskRows"
            :loading="loading"
            :row-key="(r) => r.id"
            size="small"
            :scroll-x="1200"
          />
          <n-empty v-if="!loading && taskRows.length === 0" description="还没有备份任务">
            <template #extra>
              <n-button type="primary" :disabled="!writable" @click="openCreateTask()">新建第一个任务</n-button>
            </template>
          </n-empty>
        </n-tab-pane>

        <!-- ===================== 历史 ===================== -->
        <n-tab-pane name="history" tab="历史">
          <n-space class="mb-12" justify="space-between">
            <n-select
              v-model:value="selectedTaskId"
              :options="tasks.map((t) => ({ label: t.name, value: t.id }))"
              placeholder="选择任务查看其执行历史"
              style="width: 320px"
              :clearable="true"
            />
          </n-space>

          <n-data-table
            :columns="historyColumns"
            :data="historyRows"
            :loading="historyLoading"
            :row-key="(r) => r.id"
            size="small"
            :scroll-x="1000"
          />
          <n-empty
            v-if="!historyLoading && selectedTaskId && historyRows.length === 0"
            description="该任务还没有执行记录"
          />
          <n-empty v-else-if="!selectedTaskId" description="先在右侧选择一条任务" />
        </n-tab-pane>

        <!-- ===================== 存储配置 ===================== -->
        <n-tab-pane name="storages" tab="存储配置">
          <div class="tb">
            <n-space justify="space-between">
              <n-button type="primary" :disabled="!writable" @click="openCreateStorage()">
                新增存储配置
              </n-button>
            </n-space>
          </div>

          <n-data-table
            :columns="storageColumns"
            :data="storageRows"
            :loading="loading"
            :row-key="(r) => r.storage.id"
            size="small"
            :scroll-x="1100"
          />
          <n-empty
            v-if="!loading && storageRows.length === 0"
            description="还没有存储配置。新建备份任务前至少需要一个存储（本地目录 / S3 / WebDAV）。"
          >
            <template #extra>
              <n-button type="primary" :disabled="!writable" @click="openCreateStorage()">新增存储配置</n-button>
            </template>
          </n-empty>
        </n-tab-pane>

        <!-- ===================== 审计 ===================== -->
        <n-tab-pane name="audit" tab="审计">
          <n-space class="mb-12" align="baseline">
            <n-select
              v-model:value="auditFilter.outcome"
              :options="[
                { label: '全部结果', value: '' },
                { label: '允许', value: 'allowed' },
                { label: '拒绝', value: 'denied' },
                { label: '失败', value: 'failed' },
              ]"
              style="width: 160px"
              @update:value="applyAuditFilter()"
            />
          </n-space>
          <n-data-table
            :columns="auditColumns"
            :data="auditRows"
            :loading="auditLoading"
            :row-key="(r) => r.seq"
            size="small"
            :scroll-x="1100"
          />
          <n-empty v-if="!auditLoading && auditRows.length === 0" description="暂无操作记录" />
        </n-tab-pane>
      </n-tabs>
    </n-card>

    <!-- ===================== 任务编辑弹窗 ===================== -->
    <n-modal
      v-model:show="showTaskModal"
      preset="card"
      class="modal-lg"
      :title="form.id ? '编辑备份任务' : '新建备份任务'"
      :style="{ width: '680px' }"
    >
      <n-form :model="form" label-placement="top">
        <n-form-item label="任务名" :show-feedback="false" :validation-status="taskFormErrors.name ? 'error' : undefined"
          :feedback="taskFormErrors.name">
          <n-input v-model:value="form.name" placeholder="例如：nginx 配置备份" :maxlength="100" />
          <div class="cap">恢复时要逐字输入这个任务名才能继续——起个你能想起来且不会弄混的名字。</div>
        </n-form-item>

        <n-form-item label="源路径" :show-feedback="false" :validation-status="taskFormErrors.source_path ? 'error' : undefined"
          :feedback="taskFormErrors.source_path">
          <n-input v-model:value="form.source_path" placeholder="/var/www" />
          <div class="row-actions">
            <n-button size="tiny" tertiary @click="openDirPicker('选择备份源目录', setSourcePath)">浏览目录</n-button>
          </div>
        </n-form-item>

        <n-form-item label="源类型">
          <n-radio-group v-model:value="form.source_type">
            <n-radio-button value="dir">目录</n-radio-button>
            <n-radio-button value="file">单个文件</n-radio-button>
          </n-radio-group>
        </n-form-item>

        <n-form-item label="目标存储" :show-feedback="false"
          :validation-status="taskFormErrors.storage_id ? 'error' : undefined"
          :feedback="taskFormErrors.storage_id">
          <n-select
            v-model:value="form.storage_id"
            :options="storageOptions"
            placeholder="选择把备份送到哪"
            :clearable="true"
          />
          <div v-if="storageOptions.length === 0" class="cap">
            还没有可用的存储。请先切到「存储配置」标签页加一个（本地目录 / S3 / WebDAV）。
          </div>
        </n-form-item>

        <n-form-item label="对象前缀（可选）" :show-feedback="false"
          :validation-status="taskFormErrors.prefix ? 'error' : undefined"
          :feedback="taskFormErrors.prefix">
          <n-input v-model:value="form.prefix" placeholder="web / prod（对象存储里的目录）" />
          <div class="cap">留空则归档直接落在存储根下。前缀里会拼上任务 id，不同任务的备份天然隔离。</div>
        </n-form-item>

        <n-form-item label="执行计划（cron 表达式）" :show-feedback="false"
          :validation-status="taskFormErrors.expr ? 'error' : undefined"
          :feedback="taskFormErrors.expr">
          <n-input v-model:value="form.expr" placeholder="0 3 * * *" @update:value="onExprChange" />
          <n-space class="mt-6" size="small" wrap>
            <n-tag
              v-for="ex in EXPR_EXAMPLES"
              :key="ex.expr"
              checkable
              size="small"
              :checked="form.expr === ex.expr"
              @click="form.expr = ex.expr; onExprChange()"
            >
              {{ ex.label }}
            </n-tag>
          </n-space>
          <n-text v-if="exprPreview" type="info" depth="2" class="mt-6">
            {{ exprPreview.human || '' }}
            <span v-if="exprPreview.next5 && exprPreview.next5.length">· 下次 {{ exprPreview.next5[0] }}</span>
          </n-text>
          <n-text v-else-if="exprPreviewLoading" depth="3" class="mt-6">正在解析表达式…</n-text>
        </n-form-item>

        <n-form-item label="保留策略">
          <n-select v-model:value="form.keep_policy" :options="keepSelectOptions" style="width: 240px" />
          <div v-if="form.keep_policy === 'count'" class="mt-6">
            <label class="cap">保留最近</label>
            <n-input-number
              v-model:value="form.keep_count"
              :min="1"
              :max="1000"
              :show-button="false"
              style="width: 120px; margin: 0 8px"
            />
            <label class="cap">份</label>
          </div>
          <div v-else-if="form.keep_policy === 'days'" class="mt-6">
            <label class="cap">保留最近</label>
            <n-input-number
              v-model:value="form.keep_days"
              :min="1"
              :max="3650"
              :show-button="false"
              style="width: 120px; margin: 0 8px"
            />
            <label class="cap">天内的备份</label>
          </div>
          <n-text v-if="form.keep_policy === 'none'" type="warning" depth="2">
            不自动清理：所有备份都会保留，磁盘会慢慢被吃满，需要你定期手动清理。
          </n-text>
        </n-form-item>

        <n-form-item label="备注（可选）">
          <n-input v-model:value="form.comment" type="textarea" :rows="2" placeholder="这条备份是干什么用的" :maxlength="200" />
        </n-form-item>

        <n-form-item label="启用定时执行">
          <n-switch v-model:value="form.enabled" />
          <span class="cap">关闭后任务仍保留、仍可手动执行，但不会再定时跑。</span>
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button @click="showTaskModal = false">取消</n-button>
          <n-button type="primary" :loading="submittingTask" @click="submitTask">
            {{ form.id ? '保存修改' : '创建任务' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ===================== 存储配置弹窗 ===================== -->
    <n-modal
      v-model:show="showStorageModal"
      preset="card"
      :title="storageForm.id ? '编辑存储配置' : '新增存储配置'"
      :style="{ width: '640px' }"
    >
      <n-form :model="storageForm" label-placement="top">
        <n-form-item label="名称" :show-feedback="false"
          :validation-status="storageFormErrors.name ? 'error' : undefined"
          :feedback="storageFormErrors.name">
          <n-input v-model:value="storageForm.name" placeholder="例如：备份到另一台机器" />
        </n-form-item>

        <n-form-item label="类型">
          <n-select
            v-model:value="storageForm.type"
            :options="storageTypeOptions"
            @update:value="storageForm.path = ''; storageForm.secret_key = null; storageForm.password = null"
          />
        </n-form-item>

        <n-form-item v-if="storageFieldSet.has('path')" label="本地目录" :show-feedback="false"
          :validation-status="storageFormErrors.path ? 'error' : undefined"
          :feedback="storageFormErrors.path">
          <n-input v-model:value="storageForm.path" placeholder="/var/lib/lipanel/backups" />
          <div class="row-actions">
            <n-button size="tiny" tertiary @click="openDirPicker('选择本地存储目录', setStoragePath)">浏览目录</n-button>
          </div>
        </n-form-item>

        <n-form-item v-if="storageFieldSet.has('endpoint')" label="服务地址" :show-feedback="false"
          :validation-status="storageFormErrors.endpoint ? 'error' : undefined"
          :feedback="storageFormErrors.endpoint">
          <n-input v-model:value="storageForm.endpoint"
            :placeholder="storageForm.type === 's3' ? 'http://minio:9000' : 'https://dav.example.com/remote.php/dav/files/user'" />
        </n-form-item>

        <n-form-item v-if="storageForm.type === 's3'" label="Bucket">
          <n-input v-model:value="storageForm.bucket" placeholder="my-backups" />
        </n-form-item>
        <n-form-item v-if="storageForm.type === 's3'" label="Region（可选）">
          <n-input v-model:value="storageForm.region" placeholder="us-east-1" />
        </n-form-item>
        <n-form-item v-if="storageFieldSet.has('access_key')" label="Access Key ID">
          <n-input v-model:value="storageForm.access_key" placeholder="AKIA…" />
        </n-form-item>
        <n-form-item v-if="storageForm.type === 's3'" label="Secret Access Key">
          <n-input
            v-model:value="storageForm.secret_key"
            type="password"
            show-password-on="click"
            :placeholder="storageForm.id ? '留空表示不改动' : '必填'"
          />
        </n-form-item>
        <n-form-item v-if="storageFieldSet.has('username')" label="用户名">
          <n-input v-model:value="storageForm.username" placeholder="alice" />
        </n-form-item>
        <n-form-item v-if="storageForm.type === 'webdav'" label="密码">
          <n-input
            v-model:value="storageForm.password"
            type="password"
            show-password-on="click"
            :placeholder="storageForm.id ? '留空表示不改动' : '必填'"
          />
        </n-form-item>

        <n-form-item v-if="storageForm.type === 's3'" label="寻址方式">
          <n-switch v-model:value="storageForm.path_style">
            <template #checked>Path-style</template>
            <template #unchecked>Virtual-host</template>
          </n-switch>
          <span class="cap">自建 MinIO / Ceph 请开启 Path-style（虚拟主机寻址通常只有 AWS 官方才用）。</span>
        </n-form-item>

        <n-form-item v-if="storageForm.type !== 'local'" label="Insecure Skip TLS 校验">
          <n-switch v-model:value="storageForm.insecure_skip_verify" />
          <span class="cap">仅当你的服务端证书不受信任（自签）且你确知风险时才开启。生产环境不应使用。</span>
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="space-between">
          <n-button
            v-if="storageForm.type !== 'local'"
            size="small"
            tertiary
            :loading="submittingStorage"
            @click="performTestStorage()"
          >
            测试连通性
          </n-button>
          <n-space justify="end">
            <n-button @click="showStorageModal = false">取消</n-button>
            <n-button type="primary" :loading="submittingStorage" @click="submitStorage">
              {{ storageForm.id ? '保存修改' : '创建存储' }}
            </n-button>
          </n-space>
        </n-space>
      </template>
    </n-modal>

    <!-- ===================== 恢复弹窗 ===================== -->
    <n-modal
      v-model:show="showRestoreModal"
      preset="card"
      title="从备份恢复"
      :style="{ width: '640px' }"
    >
      <template v-if="restoreFile_">
        <n-alert type="warning" title="该操作不可撤销">
          <template #default>
            <p>你正在从 <b>{{ restoreFile_.name }}</b> 恢复到目标目录。</p>
            <n-text type="error" depth="2">
              <ul class="restore-danger">
                <li v-for="(ln, i) in restoreDangerLines(restorePreview, restoreTarget)" :key="i">{{ ln }}</li>
              </ul>
            </n-text>
          </template>
        </n-alert>

        <n-form class="mt-12" label-placement="top">
          <n-form-item label="目标目录" :validation-status="!restoreTarget.trim() ? 'warning' : undefined"
            :feedback="!restoreTarget.trim() ? '请填写恢复目标目录' : undefined">
            <n-input v-model:value="restoreTarget" placeholder="/var/lib/lipanel/restore" />
            <div class="row-actions">
              <n-button size="tiny" tertiary @click="openDirPicker('选择恢复目标目录', setRestoreTarget)">浏览目录</n-button>
            </div>
            <div class="cap">恢复会解压到这里；目标目录里与归档同名的文件会被覆盖。默认落在 {{ restoreTargetDefault || restoreRootsScopeHint || '恢复白名单目录' }}。</div>
          </n-form-item>

          <n-button type="primary" secondary :loading="restorePreviewLoading" @click="refreshRestorePreview()">
            预览会发生什么
          </n-button>
          <n-text v-if="restorePreviewError" type="error" class="mt-6">
            {{ restorePreviewError }}
          </n-text>

          <n-form-item v-if="restorePreview && !restorePreviewError" label="确认" class="mt-12">
            <div class="cap">
              {{ restoreConfirmHint(restorePreview) }}
            </div>
            <n-input
              v-model:value="restoreConfirmText"
              type="password"
              show-password-on="click"
              :placeholder="restoreFile_.taskName"
              @keyup.enter="performRestore()"
            />
          </n-form-item>
        </n-form>
      </template>

      <template #footer>
        <n-space justify="end">
          <n-button @click="showRestoreModal = false">取消</n-button>
          <n-button
            v-if="restorePreview && !restorePreviewError"
            type="error"
            :disabled="!confirmMatches || restoring"
            :loading="restoring"
            @click="performRestore()"
          >
            {{ canSubmitRestore({ preview: restorePreview, confirmText: restoreConfirmText, targetDir: restoreTarget, restoring }) ? '确认并恢复' : '恢复（请输入任务名）' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ===================== 目录选择弹窗（只读） ===================== -->
    <n-modal
      v-model:show="dirPickerShow"
      preset="card"
      :title="dirPicker ? dirPicker.title : ''"
      :style="{ width: '520px' }"
    >
      <n-space class="mb-6" align="center">
        <n-button size="small" @click="upDir()" :disabled="currentDir === '/'">上一级</n-button>
        <n-text code>{{ currentDir }}</n-text>
        <n-button size="small" type="primary" @click="pickThisDir()" :loading="dirPickerLoading === currentDir">
          选当前目录
        </n-button>
      </n-space>

      <n-spin :show="dirPickerLoading === currentDir">
        <div class="dir-list">
          <div
            v-for="e in currentEntries"
            :key="e.path || e.name"
            class="dir-row"
            :class="{ dir: e.is_dir }"
            @dblclick="enterDir(e)"
          >
            <span class="dir-icon">{{ e.is_dir ? '📁' : '📄' }}</span>
            <span class="dir-name" @click="enterDir(e)">{{ e.name }}</span>
          </div>
          <n-empty v-if="!dirPickerLoading && currentEntries.length === 0" description="空目录" size="small" />
        </div>
      </n-spin>

      <template #footer>
        <n-space justify="end">
          <n-button @click="closeDirPicker()">取消</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- ===================== 删除任务确认 ===================== -->
    <n-modal
      v-model:show="deleteTaskShow"
      preset="dialog"
      type="error"
      title="删除备份任务"
      positive-text="确认删除"
      negative-text="取消"
      @positive-click="performDeleteTask"
      @negative-click="deleteTaskTarget = null"
      @mask-click="deleteTaskTarget = null"
    >
      <p>真的要删除备份任务 <b>{{ deleteTaskTarget?.name }}</b> 吗？</p>
      <p>删除后**不再有任何新的备份**。已产生的备份文件仍在存储上，可以手动下载或删除。</p>
      <p><n-text type="error">到需要恢复的那天，你可能会发现自己以为有备份、其实没有——请确认你已经明白这一点。</n-text></p>
    </n-modal>

    <!-- ===================== 删除备份文件确认 ===================== -->
    <n-modal
      v-model:show="deleteFileShow"
      preset="dialog"
      type="warning"
      title="删除备份文件"
      positive-text="确认删除"
      negative-text="取消"
      @positive-click="performDeleteFile"
      @negative-click="deleteFileTarget = null"
      @mask-click="deleteFileTarget = null"
    >
      <p>真的要删除这份备份 <b>{{ deleteFileTarget?.name }}</b> 吗？</p>
      <p>只是删除存储上的这一份归档，**不会**影响备份任务本身，也不会删除其它备份。</p>
    </n-modal>

    <!-- ===================== 删除存储配置确认 ===================== -->
    <n-modal
      v-model:show="deleteStorageShow"
      preset="dialog"
      type="warning"
      title="删除存储配置"
      positive-text="确认删除"
      negative-text="取消"
      @positive-click="performDeleteStorage"
      @negative-click="deleteStorageTarget = null"
      @mask-click="deleteStorageTarget = null"
    >
      <p>真的要删除存储配置 <b>{{ deleteStorageTarget?.name }}</b> 吗？</p>
      <p>被删除的配置不再可用，但**已经备份到该存储上的文件不会因此丢失**。</p>
      <p>如果它仍被某个备份任务引用，后端会拒绝删除（并在列表里告诉你是哪个任务）。</p>
    </n-modal>
  </div>
</template>

<style scoped>
.backup-view {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.tb {
  margin-bottom: 12px;
}
.cap {
  font-size: 12px;
  color: var(--n-text-color-3, #999);
  margin-top: 4px;
  line-height: 1.6;
}
.mb-12 {
  margin-bottom: 12px;
}
.mt-6 {
  margin-top: 8px;
}
.mt-12 {
  margin-top: 12px;
}
.row-actions {
  display: flex;
  gap: 6px;
  margin-top: 6px;
}
.modal-lg .n-modal-body {
  max-height: 72vh;
  overflow: auto;
}
.restore-danger {
  margin: 8px 0 0;
  padding-left: 20px;
  line-height: 1.8;
}
.dir-list {
  max-height: 360px;
  overflow: auto;
  border: 1px solid var(--n-border-color, #eee);
  border-radius: 6px;
}
.dir-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  cursor: pointer;
}
.dir-row:hover {
  background: var(--n-action-color, #f5f5f5);
}
.dir-icon {
  flex: 0 0 auto;
}
.dir-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
