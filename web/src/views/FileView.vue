<script setup>
// 文件管理页（阶段四 4.2）。
//
// 内置基础页面（不是插件）：文件读写是面板最核心的运维能力，
// 依赖插件机制反而会让用户在插件未启动时无法管理文件
// （与 4.1 服务管理同样的架构决定）。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 删除、覆盖一律走二次确认，且**弹窗里写明文件全路径**，
//     防止用户点错行却按下了确认
//   - 写操作成功后做**局部更新**并刷新一次列表（局部更新保证即时反馈，
//     刷新保证与磁盘真实状态一致——别的进程可能也在改这些文件）
import { computed, h, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NSpace, NTag, NText } from 'naive-ui'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import {
  createDirectory,
  deleteEntry,
  downloadURL,
  fetchFileContent,
  fetchFileMeta,
  fetchListing,
  renameEntry,
  saveFileContent,
  uploadFile,
} from '@/api/files'
import {
  breadcrumbs,
  canWrite as canWriteWith,
  deleteConfirmText,
  deleteNeedsRecursive,
  displayTypeText,
  filterEntries,
  formatModTime,
  formatSize,
  isEditable,
  joinPath,
  parentPath,
  removeEntry,
  replaceEntryPath,
  typeMeta,
  upsertEntry,
  uploadTooLarge,
  validateNewName,
} from '@/views/fileLogic'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

// ---------- 状态 ----------
const loading = ref(false)
const error = ref('')
const currentPath = ref('')
const entries = ref([])
const total = ref(0)
const truncated = ref(false)
const permissions = ref([])
const roots = ref([])
const limits = ref({ max_upload_bytes: 0, max_edit_bytes: 0, max_list_entries: 0 })

const keyword = ref('')
const onlyDirs = ref(false)

// busy 记录正在进行的行级操作（用路径做键），用于按钮级 Loading——
// 操作 A 文件时不该让 B 文件的按钮也转圈。
const busy = ref({})
function isBusy(path) {
  return Boolean(busy.value[path])
}
function setBusy(path, value) {
  busy.value = { ...busy.value, [path]: value }
}

// uploading 是上传进度（0-100），null 表示没有上传在进行。
const uploading = ref(null)
let uploadHandle = null

// ---------- 派生状态 ----------
const canWrite = computed(() => canWriteWith(permissions.value))
const crumbs = computed(() => breadcrumbs(currentPath.value))
const parent = computed(() => parentPath(currentPath.value))

// visibleEntries 是本页真正渲染的数据（过滤只影响展示，
// 不影响任何操作使用的路径——操作始终用后端给的绝对路径）。
const visibleEntries = computed(() =>
  filterEntries(entries.value, { keyword: keyword.value, onlyDirs: onlyDirs.value }),
)

// ---------- 数据加载 ----------
async function loadMeta() {
  try {
    const meta = await fetchFileMeta()
    roots.value = meta.roots || []
    permissions.value = meta.permissions || []
    limits.value = meta.limits || limits.value
  } catch (err) {
    // 元信息加载失败不阻断浏览：默认给最小权限，
    // 写操作按钮会被禁用，用户仍能查看目录。
    permissions.value = []
    handleError(err, '加载文件管理配置失败')
  }
}

async function load(path, { silent = false } = {}) {
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchListing(path)
    currentPath.value = data.path
    entries.value = data.entries || []
    total.value = data.total ?? entries.value.length
    truncated.value = Boolean(data.truncated)
  } catch (err) {
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/files' } })
      return
    }
    error.value = err?.messageWithHint || err?.message || '未知错误'
    // 静默刷新失败时保留原列表：网络抖一下就把列表清空比不刷新更糟。
    if (!silent) {
      entries.value = []
    }
  } finally {
    if (!silent) loading.value = false
  }
}

// handleError 统一处理非 401 错误：既弹提示，也在页面上留一条
// （弹窗会自动消失，页面内的 alert 让用户能回看原因）。
function handleError(err, prefix) {
  if (err instanceof ApiError && err.isUnauthorized) {
    authStore.clear()
    message.warning('登录已过期，请重新登录')
    router.replace({ name: 'login', query: { redirect: '/files' } })
    return
  }
  const detail = err?.messageWithHint || err?.message || '未知错误'
  error.value = prefix ? `${prefix}：${detail}` : detail
  message.error(error.value, { duration: 8000 })
}

onMounted(async () => {
  await loadMeta()
  // 首次进入：默认打开第一个白名单根目录。
  // 先取根列表再取目录，而不是硬编码 "/"——白名单可能收窄到
  // /home 之类的目录，硬编码会让默认页面直接 400。
  const first = roots.value[0]?.path
  if (!first) {
    error.value = '未配置任何可访问的根目录'
    return
  }
  await load(first)
})

// ---------- 导航 ----------
function enter(entry) {
  // 失效链接不可进入：后端会因为路径校验失败而拒绝，
  // 这里提前拦住以免用户点了没反应（看起来像卡住）。
  if (entry.broken) {
    message.warning(`「${entry.name}」是失效的符号链接，无法进入`)
    return
  }
  if (!entry.is_dir) return
  load(entry.path)
}

function goUp() {
  if (parent.value) load(parent.value)
}

function goTo(path) {
  if (path && path !== currentPath.value) load(path)
}

// ---------- 新建文件夹 ----------
const mkdirVisible = ref(false)
const mkdirName = ref('')
const mkdirError = ref('')
const mkdirBusy = ref(false)

function openMkdir() {
  mkdirName.value = ''
  mkdirError.value = ''
  mkdirVisible.value = true
}

async function submitMkdir() {
  const invalid = validateNewName(mkdirName.value)
  if (invalid) {
    mkdirError.value = invalid
    return
  }
  mkdirBusy.value = true
  mkdirError.value = ''
  const target = joinPath(currentPath.value, mkdirName.value)
  try {
    const entry = await createDirectory(target)
    message.success(`已创建目录「${entry.name}」`)
    mkdirVisible.value = false
    // 局部插入：不必等整目录重新拉取，用户立刻看到结果；
    // 随后再做一次静默刷新与磁盘对齐。
    entries.value = upsertEntry(entries.value, entry)
    load(currentPath.value, { silent: true })
  } catch (err) {
    // 保留弹窗：用户输入的目录名还在，改一下就能重试。
    mkdirError.value = err?.messageWithHint || err?.message || '未知错误'
  } finally {
    mkdirBusy.value = false
  }
}

// ---------- 上传 ----------
// 用 n-upload 的 custom-request，自己走 XHR 以便拿到进度。
const uploadVisible = ref(false)
const uploadOverwrite = ref(false)

function openUpload() {
  uploadOverwrite.value = false
  uploadVisible.value = true
}

// uploadRequest 由 n-upload 调用，返回 { promise } 以接入它的状态管理。
function uploadRequest({ file, onFinish, onError }) {
  const raw = file.file
  if (!raw) {
    onError()
    return
  }
  if (uploadTooLarge(raw.size, limits.value.max_upload_bytes)) {
    const msg =
      `文件「${raw.name}」${formatSize(raw.size)} 超过上传上限 ` +
      `${formatSize(limits.value.max_upload_bytes)}`
    message.error(msg, { duration: 8000 })
    error.value = msg
    onError()
    return
  }

  uploading.value = 0
  const handle = uploadFile({
    dir: currentPath.value,
    file: raw,
    overwrite: uploadOverwrite.value,
    onProgress: (p) => {
      uploading.value = p
    },
  })
  uploadHandle = handle

  handle.promise
    .then((res) => {
      message.success(`已上传「${raw.name}」（${formatSize(res.size)}）`)
      onFinish()
      // 上传结果是后端给出的权威条目信息，但接口只回 path/size/mode，
      // 因此这里刷新列表拿到完整元数据（大小、mtime、是否可编辑）。
      load(currentPath.value, { silent: true })
    })
    .catch((err) => {
      onError()
      // 409 表示同名文件已存在：给出可操作的提示而不是一句"已存在"。
      if (err instanceof ApiError && err.status === 409) {
        const msg = `「${raw.name}」已存在。若需替换，请勾选「覆盖同名文件」后重试。`
        message.error(msg, { duration: 8000 })
        error.value = msg
        return
      }
      handleError(err, `上传「${raw.name}」失败`)
    })
    .finally(() => {
      uploading.value = null
      uploadHandle = null
    })

  return { promise: handle.promise }
}

function cancelUpload() {
  if (uploadHandle) {
    uploadHandle.abort()
  }
}

// ---------- 编辑 ----------
const editorVisible = ref(false)
const editorLoading = ref(false)
const editorSaving = ref(false)
const editorError = ref('')
const editorPath = ref('')
const editorName = ref('')
const editorContent = ref('')
const editorMeta = ref({ size: 0, mod_time: '', mode: '' })

async function openEditor(entry) {
  editorVisible.value = true
  editorLoading.value = true
  editorError.value = ''
  editorPath.value = entry.path
  editorName.value = entry.name
  editorContent.value = ''
  try {
    const data = await fetchFileContent(entry.path)
    editorContent.value = data.content
    editorMeta.value = {
      size: data.size,
      mod_time: data.mod_time,
      mode: data.mode,
    }
  } catch (err) {
    // 415（二进制）/413（过大）都会给出 hint，直接展示给用户，
    // 比"打开失败"有用得多。
    editorError.value = err?.messageWithHint || err?.message || '未知错误'
  } finally {
    editorLoading.value = false
  }
}

async function saveEditor() {
  editorSaving.value = true
  editorError.value = ''
  try {
    // overwrite=true 是**明确**的：用户是在编辑既有文件，
    // 保存本身就是覆盖意图（打开时已经读过内容）。
    const res = await saveFileContent(editorPath.value, editorContent.value, {
      overwrite: true,
    })
    message.success(`已保存「${editorName.value}」（${formatSize(res.size)}）`)
    editorVisible.value = false
    load(currentPath.value, { silent: true })
  } catch (err) {
    editorError.value = err?.messageWithHint || err?.message || '未知错误'
  } finally {
    editorSaving.value = false
  }
}

// ---------- 重命名 ----------
const renameVisible = ref(false)
const renameBusy = ref(false)
const renameError = ref('')
const renameTarget = ref(null)
const renameName = ref('')

function openRename(entry) {
  renameTarget.value = entry
  renameName.value = entry.name
  renameError.value = ''
  renameVisible.value = true
}

async function submitRename() {
  const entry = renameTarget.value
  if (!entry) return
  const next = renameName.value
  if (next === entry.name) {
    // 没有任何变化：直接关掉，不打扰后端。
    renameVisible.value = false
    return
  }
  const invalid = validateNewName(next)
  if (invalid) {
    renameError.value = invalid
    return
  }

  renameBusy.value = true
  setBusy(entry.path, true)
  renameError.value = ''
  try {
    const updated = await renameEntry(entry.path, next)
    message.success(`已重命名为「${updated.name}」`)
    renameVisible.value = false
    entries.value = replaceEntryPath(entries.value, entry.path, updated.name)
    load(currentPath.value, { silent: true })
  } catch (err) {
    // 409（同名已存在）在弹窗里提示，让用户改名后直接重试。
    if (err instanceof ApiError && err.status === 409) {
      renameError.value = `「${next}」已存在，请换一个名字。`
      return
    }
    renameError.value = err?.messageWithHint || err?.message || '未知错误'
  } finally {
    renameBusy.value = false
    setBusy(entry.path, false)
  }
}

// ---------- 删除 ----------
function confirmDelete(entry) {
  const recursive = deleteNeedsRecursive(entry)
  dialog.warning({
    title: recursive ? '确认删除目录' : '确认删除',
    // 弹窗正文里写明名字与完整路径，并说明是否递归——
    // 这是防误删的最后一道人工关卡。
    content: deleteConfirmText(entry),
    positiveText: recursive ? '递归删除' : '删除',
    negativeText: '取消',
    onPositiveClick: () => runDelete(entry, recursive),
  })
}

async function runDelete(entry, recursive) {
  setBusy(entry.path, true)
  try {
    await deleteEntry(entry.path, { recursive })
    message.success(`已删除「${entry.name}」`)
    entries.value = removeEntry(entries.value, entry.path)
    load(currentPath.value, { silent: true })
  } catch (err) {
    // 409 且是目录：说明后端判定它非空，而前端按"空目录"处理了。
    // 这是竞态（确认期间别的进程往里放了东西），因此**不能自动递归删**，
    // 必须把"目录非空"这个新信息告诉用户并重新确认一次。
    if (err instanceof ApiError && err.status === 409 && entry.is_dir && !recursive) {
      dialog.warning({
        title: '目录非空',
        content:
          `目录「${entry.name}」中仍有内容（${err.message}）。\n\n` +
          '递归删除会连带删除其中的全部文件，且无法恢复。确定继续吗？',
        positiveText: '递归删除',
        negativeText: '取消',
        onPositiveClick: () => runDelete(entry, true),
      })
      return
    }
    handleError(err, `删除「${entry.name}」失败`)
  } finally {
    setBusy(entry.path, false)
  }
}

// ---------- 下载 ----------
function download(entry) {
  // 直接交给浏览器导航：会话 Cookie 自动携带，后端 ServeContent
  // 支持 Range 续传；不用 fetch+Blob（大文件会把标签页读崩）。
  const url = downloadURL(entry.path)
  // 用一个临时 <a> 触发下载，避免 window.open 被拦截后
  // 在当前标签页里打开文件内容。
  const a = document.createElement('a')
  a.href = url
  a.rel = 'noopener'
  // download 属性只是建议：真正的文件名由后端的
  // Content-Disposition 决定（含 UTF-8 文件名）。
  a.download = entry.name
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
}

// ---------- 表格列 ----------
const columns = computed(() => [
  {
    title: '名称',
    key: 'name',
    minWidth: 260,
    render(row) {
      const isDir = row.is_dir && !row.broken
      return h(
        NButton,
        {
          text: true,
          type: isDir ? 'primary' : 'default',
          disabled: row.broken,
          onClick: () => enter(row),
          // 目录与可编辑文件才可点：点一个不可点的东西没有反馈，
          // 用户会以为页面卡了。
          style: isDir || isEditable(row) ? '' : 'cursor: default',
        },
        { default: () => (row.type === 'symlink' ? `🔗 ${row.name}` : row.name) },
      )
    },
  },
  {
    title: '类型',
    key: 'type',
    width: 130,
    render(row) {
      const meta = typeMeta(row.type)
      return h(
        NTag,
        { size: 'small', type: meta.type, bordered: false },
        { default: () => displayTypeText(row) },
      )
    },
  },
  {
    title: '大小',
    key: 'size',
    width: 110,
    render(row) {
      // 目录不显示 0 B（那会让人以为目录是空的），统一显示 "-"。
      return h(
        NText,
        { depth: 3 },
        { default: () => (row.is_dir ? '-' : formatSize(row.size)) },
      )
    },
  },
  {
    title: '修改时间',
    key: 'mod_time',
    width: 170,
    render(row) {
      return h(NText, { depth: 3 }, { default: () => formatModTime(row.mod_time) })
    },
  },
  {
    title: '权限',
    key: 'mode',
    width: 120,
    render(row) {
      return h(
        NText,
        { depth: 3, style: 'font-size: 12px' },
        { default: () => row.mode || '-' },
      )
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 300,
    render(row) {
      const rowBusy = isBusy(row.path)
      const buttons = []

      if (isEditable(row)) {
        buttons.push(
          h(
            NButton,
            { size: 'small', tertiary: true, disabled: rowBusy, onClick: () => openEditor(row) },
            { default: () => '编辑' },
          ),
        )
      }
      if (!row.is_dir && !row.broken) {
        buttons.push(
          h(
            NButton,
            { size: 'small', tertiary: true, disabled: rowBusy, onClick: () => download(row) },
            { default: () => '下载' },
          ),
        )
      }
      buttons.push(
        h(
          NButton,
          {
            size: 'small',
            tertiary: true,
            // 无写权限时禁用（后端也会拒绝，这里只是体验）。
            disabled: rowBusy || !canWrite.value,
            onClick: () => openRename(row),
          },
          { default: () => '重命名' },
        ),
      )
      buttons.push(
        h(
          NButton,
          {
            size: 'small',
            tertiary: true,
            type: 'error',
            disabled: rowBusy,
            loading: rowBusy,
            onClick: () => confirmDelete(row),
          },
          { default: () => '删除' },
        ),
      )

      return h(NSpace, { size: 4 }, { default: () => buttons })
    },
  },
])

const rowKey = (row) => row.path
</script>

<template>
  <AppLayout>
    <n-space vertical :size="16">
      <n-h2 style="margin: 0">文件管理</n-h2>

      <n-alert v-if="error" type="error" closable @close="error = ''">
        {{ error }}
      </n-alert>

      <n-alert v-if="!canWrite" type="info" :bordered="false">
        当前账号未被授予 <code>file.write</code> 权限，只能浏览与下载，无法修改文件。
      </n-alert>

      <n-card>
        <!-- 工具栏：面包屑 + 操作 -->
        <n-space vertical :size="12">
          <n-space align="center" justify="space-between" :size="12" style="flex-wrap: wrap">
            <n-space align="center" :size="8" style="flex-wrap: wrap">
              <n-button size="small" :disabled="!parent" @click="goUp">↑ 上级</n-button>
              <n-button size="small" :loading="loading" @click="load(currentPath)">刷新</n-button>
              <n-breadcrumb>
                <n-breadcrumb-item
                  v-for="crumb in crumbs"
                  :key="crumb.path"
                  @click="goTo(crumb.path)"
                >
                  <span style="cursor: pointer">{{ crumb.label }}</span>
                </n-breadcrumb-item>
              </n-breadcrumb>
            </n-space>

            <n-space align="center" :size="8">
              <n-input
                v-model:value="keyword"
                placeholder="按名称过滤"
                clearable
                size="small"
                style="width: 180px"
              />
              <n-checkbox v-model:checked="onlyDirs" size="small">只看目录</n-checkbox>
              <n-button size="small" type="primary" :disabled="!canWrite" @click="openMkdir">
                新建文件夹
              </n-button>
              <n-button size="small" :disabled="!canWrite" @click="openUpload">上传文件</n-button>
            </n-space>
          </n-space>

          <!-- 上传进度：显式展示"传到哪了"，并允许取消 -->
          <n-space v-if="uploading !== null" align="center" :size="12">
            <n-progress
              type="line"
              :percentage="uploading"
              :height="10"
              style="flex: 1; min-width: 200px"
            />
            <n-button size="small" @click="cancelUpload">取消上传</n-button>
          </n-space>

          <n-text depth="3" style="font-size: 12px">
            当前目录：<code>{{ currentPath || '-' }}</code>
            <template v-if="roots.length">
              ｜可访问根目录：
              <code v-for="root in roots" :key="root.path" style="margin-right: 6px">
                {{ root.path }}
              </code>
            </template>
            ｜共 {{ total }} 项<template v-if="visibleEntries.length !== total">
              （当前显示 {{ visibleEntries.length }} 项）</template
            >
          </n-text>

          <n-alert v-if="truncated" type="warning" :bordered="false" style="font-size: 12px">
            目录条目过多，只显示前 {{ limits.max_list_entries }} 项。请用上方搜索框缩小范围。
          </n-alert>

          <n-data-table
            :columns="columns"
            :data="visibleEntries"
            :loading="loading"
            :row-key="rowKey"
            :bordered="false"
            :single-line="false"
            size="small"
            :max-height="520"
            virtual-scroll
          />

          <n-empty
            v-if="!loading && visibleEntries.length === 0"
            :description="entries.length === 0 ? '这个目录是空的' : '没有匹配的条目'"
            style="margin-top: 16px"
          />
        </n-space>
      </n-card>

      <n-text depth="3" style="font-size: 12px">
        说明：所有写操作（新建 / 上传 / 保存 / 重命名 / 删除）都会记入审计，
        且只能在本面板配置的根目录内进行；越权路径与符号链接逃逸会被服务端拒绝。
      </n-text>
    </n-space>

    <!-- 新建文件夹 -->
    <n-modal
      v-model:show="mkdirVisible"
      preset="card"
      title="新建文件夹"
      style="max-width: 520px"
      :mask-closable="!mkdirBusy"
    >
      <n-space vertical :size="12">
        <n-text depth="3">将在 <code>{{ currentPath }}</code> 下创建：</n-text>
        <n-input
          v-model:value="mkdirName"
          placeholder="文件夹名称"
          :status="mkdirError ? 'error' : undefined"
          @keyup.enter="submitMkdir"
        />
        <n-alert v-if="mkdirError" type="error" :bordered="false">{{ mkdirError }}</n-alert>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="mkdirBusy" @click="mkdirVisible = false">取消</n-button>
          <n-button type="primary" :loading="mkdirBusy" @click="submitMkdir">创建</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 上传 -->
    <n-modal
      v-model:show="uploadVisible"
      preset="card"
      title="上传文件"
      style="max-width: 560px"
    >
      <n-space vertical :size="12">
        <n-text depth="3">
          上传到 <code>{{ currentPath }}</code>，单个文件不超过
          {{ formatSize(limits.max_upload_bytes) }}。
        </n-text>
        <n-checkbox v-model:checked="uploadOverwrite">覆盖同名文件</n-checkbox>
        <n-upload
          :custom-request="uploadRequest"
          :show-file-list="true"
          :multiple="true"
          :disabled="!canWrite"
        >
          <n-button :disabled="!canWrite">选择文件</n-button>
        </n-upload>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="uploading !== null" @click="uploadVisible = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 编辑 -->
    <n-modal
      v-model:show="editorVisible"
      preset="card"
      :title="`编辑 ${editorName}`"
      style="max-width: 900px; width: 90vw"
      :mask-closable="!editorSaving"
    >
      <n-space vertical :size="12">
        <n-text depth="3" style="font-size: 12px">
          路径：<code>{{ editorPath }}</code>
          <template v-if="editorMeta.mod_time">
            ｜原大小 {{ formatSize(editorMeta.size) }}｜修改于
            {{ formatModTime(editorMeta.mod_time) }}｜权限 {{ editorMeta.mode }}
          </template>
        </n-text>

        <n-alert v-if="editorError" type="error" :bordered="false">{{ editorError }}</n-alert>

        <n-spin :show="editorLoading">
          <n-input
            v-model:value="editorContent"
            type="textarea"
            :autosize="{ minRows: 16, maxRows: 28 }"
            placeholder="文件内容"
            :disabled="editorLoading || Boolean(editorError) || !canWrite"
            style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace"
          />
        </n-spin>

        <n-text depth="3" style="font-size: 12px">
          保存会覆盖整个文件内容。二进制文件请用「下载」后用本地工具修改，
          避免在文本域里被破坏。
        </n-text>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="editorSaving" @click="editorVisible = false">取消</n-button>
          <n-button
            type="primary"
            :loading="editorSaving"
            :disabled="editorLoading || Boolean(editorError) || !canWrite"
            @click="saveEditor"
          >
            保存
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 重命名 -->
    <n-modal
      v-model:show="renameVisible"
      preset="card"
      title="重命名"
      style="max-width: 520px"
      :mask-closable="!renameBusy"
    >
      <n-space vertical :size="12">
        <n-text depth="3">
          原名：<code>{{ renameTarget?.name }}</code>
          （同目录改名，不支持跨目录移动）
        </n-text>
        <n-input
          v-model:value="renameName"
          placeholder="新名称"
          :status="renameError ? 'error' : undefined"
          @keyup.enter="submitRename"
        />
        <n-alert v-if="renameError" type="error" :bordered="false">{{ renameError }}</n-alert>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button :disabled="renameBusy" @click="renameVisible = false">取消</n-button>
          <n-button type="primary" :loading="renameBusy" @click="submitRename">确定</n-button>
        </n-space>
      </template>
    </n-modal>
  </AppLayout>
</template>
