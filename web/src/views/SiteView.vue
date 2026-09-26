<script setup>
// 网站管理页（阶段四 4.3）。
//
// 内置基础页面（不是插件）：nginx 站点是面板的核心运维能力，
// 依赖插件机制反而会让用户在插件未启动时无法管理站点。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 删除/启停是有副作用的操作，一律走二次确认，且**弹窗里写明域名**，
//     防止用户点错行却按下了确认
//   - 操作后自动刷新（失败也刷新：nginx 可能已部分生效）
//   - 后端返回 rolled_back 时，必须**明确告诉用户配置已自动回滚**——
//     这是本模块最重要的一条用户可见信息：出错了但系统是安全的
import { computed, h, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NSpace, NTag, NText, NThing } from 'naive-ui'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import {
  createSite,
  deleteSite,
  fetchSiteCapabilities,
  fetchSites,
  setSiteEnabled,
  updateSite,
} from '@/api/sites'
import {
  actionDisabled,
  buildSitePayload,
  canOperate,
  deleteConfirmText,
  emptyForm,
  filterSites,
  formFromSite,
  formatTarget,
  statusMeta,
  summarize,
  toggleConfirmText,
  typeMeta,
  validateForm,
} from '@/views/siteLogic'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const sites = ref([])
const available = ref(true)
const unavailableReason = ref('')
const mode = ref('')
const permissions = ref([])
const auditStats = ref(null)
const capabilities = ref(null)

// busy 记录每个站点正在执行的操作，用于**按钮级** Loading。
// 用对象而不是单个布尔量：操作 A 站点时不该让 B 站点的按钮也转圈。
const busy = ref({})

// 搜索与过滤：站点数量可能很多，没有过滤的话用户只能在长列表里翻找。
const keyword = ref('')
const onlyEnabled = ref(false)

// ---------- 弹窗状态 ----------
const showForm = ref(false)
const submitting = ref(false)
const editingName = ref('') // 非空表示编辑模式
const form = reactive(emptyForm())
// formErrors 保存字段级错误，由 siteLogic 的 validateForm 统一产出。
const formErrors = reactive({})

const isEdit = computed(() => Boolean(editingName.value))

// canWrite 表示当前用户是否被授予 site.write。
//
// 注意：这只是**体验优化**（无权限时按钮置灰），真正的强制点在后端
// （site.CheckSitePermission）。前端标记被篡改也不会获得任何权限。
const canWrite = computed(() => permissions.value.includes('site.write'))

// filteredSites 是本页真正渲染的数据。
//
// 过滤逻辑抽在 @/views/siteLogic，由 node:test 覆盖
// （组件本身依赖 Vue/Naive UI，在本仓库的前端测试环境里无法直接 import）。
const filteredSites = computed(() =>
  filterSites(sites.value, {
    keyword: keyword.value,
    onlyEnabled: onlyEnabled.value,
  }),
)

const stats = computed(() => summarize(sites.value))

function isBusy(name) {
  return Boolean(busy.value[name])
}

function setBusy(name, value) {
  busy.value = { ...busy.value, [name]: value }
}

// ---------- 数据加载 ----------

async function load({ silent = false } = {}) {
  // silent 用于操作后的刷新：不显示整页 Loading，避免列表闪烁。
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchSites()
    sites.value = data.sites || []
    available.value = data.available !== false
    unavailableReason.value = data.unavailable_reason || ''
    mode.value = data.mode || ''
    permissions.value = data.permissions || []
    auditStats.value = data.audit || null
  } catch (err) {
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/sites' } })
      return
    }
    error.value = err?.messageWithHint || err?.message || '未知错误'
    // 操作后的静默刷新失败时不覆盖已有列表：
    // 网络抖动一下就把整个列表清空，比不刷新更糟。
    if (!silent) {
      sites.value = []
    }
  } finally {
    if (!silent) loading.value = false
  }
}

// loadCapabilities 拉取能力信息（配置目录、限制），用于页面说明。
//
// 失败不阻断页面：它只是补充信息，站点列表才是主内容。
async function loadCapabilities() {
  try {
    capabilities.value = await fetchSiteCapabilities()
  } catch {
    capabilities.value = null
  }
}

onMounted(() => {
  load()
  loadCapabilities()
})

// ---------- 表单 ----------

function openCreate() {
  editingName.value = ''
  Object.assign(form, emptyForm())
  clearErrors()
  showForm.value = true
}

function openEdit(site) {
  editingName.value = site.name
  Object.assign(form, formFromSite(site))
  clearErrors()
  showForm.value = true
}

function clearErrors() {
  for (const key of Object.keys(formErrors)) {
    delete formErrors[key]
  }
}

// onTypeChange 在切换类型时清空另一个字段。
//
// 后端对"类型与字段不匹配"是**直接拒绝**（不静默丢弃），
// 因此这里必须主动清空，否则用户切换类型后会一直提交失败。
function onTypeChange(type) {
  if (type === 'static') {
    form.upstream = ''
    delete formErrors.upstream
  } else if (type === 'proxy') {
    form.root = ''
    delete formErrors.root
  }
}

// revalidate 在用户输入时清掉该字段的错误（体验优化）。
function revalidate() {
  const errors = validateForm(form, { isEdit: isEdit.value })
  Object.assign(formErrors, errors)
  for (const key of Object.keys(formErrors)) {
    if (!(key in errors)) delete formErrors[key]
  }
}

async function submitForm() {
  const errors = validateForm(form, { isEdit: isEdit.value })
  clearErrors()
  if (Object.keys(errors).length > 0) {
    Object.assign(formErrors, errors)
    message.error('表单校验未通过，请检查下方标红的字段')
    return
  }

  submitting.value = true
  const payload = buildSitePayload(form)
  try {
    if (isEdit.value) {
      await updateSite(editingName.value, payload)
      message.success(`站点「${payload.domain}」已保存`)
    } else {
      await createSite(payload)
      message.success(`站点「${payload.domain}」已创建`)
    }
    showForm.value = false
    await load({ silent: true })
  } catch (err) {
    handleWriteError(err)
  } finally {
    submitting.value = false
  }
}

// handleWriteError 把写操作的失败翻译成用户能理解并据以行动的信息。
//
// 这里最重要的是区分两类失败：
//   - 校验/冲突类（400/409）：用户改输入就能解决；
//   - nginx 拒绝配置（422/502）且已回滚：用户的输入没错，是 nginx
//     不接受这份配置，而且**面板已经自动恢复了**，服务没受影响。
//     必须把"已回滚"这件事明确说出来，否则用户会以为站点已经挂了。
function handleWriteError(err) {
  if (err instanceof ApiError && err.isUnauthorized) {
    authStore.clear()
    message.warning('登录已过期，请重新登录')
    router.replace({ name: 'login', query: { redirect: '/sites' } })
    return
  }

  const base = err?.messageWithHint || err?.message || '未知错误'

  if (err?.rolledBack) {
    dialog.error({
      title: 'nginx 拒绝了这份配置（已自动回滚）',
      content: () =>
        h('div', [
          h(
            'p',
            { style: 'margin:0 0 8px' },
            '配置已自动回滚到修改前的状态，并通过 nginx -t 复验，现有站点未受影响。',
          ),
          h('pre', {
            style:
              'white-space:pre-wrap;word-break:break-all;background:#f5f5f5;padding:8px;border-radius:4px;margin:0;max-height:240px;overflow:auto',
          }, base),
        ]),
      positiveText: '知道了',
    })
    return
  }

  message.error(base)
}

// ---------- 行操作 ----------

// runToggle 是启用/禁用的统一实现。
//
// 流程：二次确认 → 置 busy → 调接口 → 提示结果 → **无论成败都刷新**。
// 失败也刷新是刻意的：配置可能已经写盘、只是 reload 没成功，
// 不刷新会让界面显示一个过期的状态。
function runToggle(site, enabled) {
  dialog.warning({
    title: enabled ? '启用站点' : '禁用站点',
    content: toggleConfirmText(site, enabled),
    positiveText: enabled ? '启用' : '禁用',
    negativeText: '取消',
    onPositiveClick: async () => {
      setBusy(site.name, true)
      try {
        await setSiteEnabled(site.name, enabled)
        message.success(`站点「${site.domain || site.name}」已${enabled ? '启用' : '禁用'}`)
      } catch (err) {
        handleWriteError(err)
      } finally {
        setBusy(site.name, false)
        await load({ silent: true })
      }
    },
  })
}

// runDelete 删除站点。
//
// 二次确认的正文由 siteLogic.deleteConfirmText 生成，**必须包含域名**
// （计划明确要求）：用户对域名的记忆远比内部站点名清晰，
// 写错名字的站点被误删是最难挽回的事故。
function runDelete(site) {
  dialog.error({
    title: '删除站点',
    content: () => h('pre', {
      style: 'white-space:pre-wrap;margin:0;font-family:inherit',
    }, deleteConfirmText(site)),
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      setBusy(site.name, true)
      try {
        await deleteSite(site.name)
        message.success(`站点「${site.domain || site.name}」已删除`)
      } catch (err) {
        handleWriteError(err)
      } finally {
        setBusy(site.name, false)
        await load({ silent: true })
      }
    },
  })
}

// ---------- 表格列 ----------

const columns = [
  {
    title: '域名',
    key: 'domain',
    minWidth: 180,
    render(row) {
      return h('div', [
        h('div', { style: 'font-weight:500' }, row.domain || row.name),
        h(
          NText,
          { depth: 3, style: 'font-size:12px' },
          { default: () => `站点名：${row.name}` },
        ),
      ])
    },
  },
  {
    title: '类型',
    key: 'type',
    width: 110,
    render(row) {
      const meta = typeMeta(row.type)
      return h(
        NTag,
        { type: meta.type, size: 'small', bordered: false },
        { default: () => meta.label },
      )
    },
  },
  {
    title: '根目录 / 反代目标',
    key: 'target',
    minWidth: 220,
    // 表头按类型动态变化没有意义（表格里可能混合两种类型），
    // 因此用固定表头 + 单元格内标明类型的方式。
    render(row) {
      const target = formatTarget(row)
      return h('code', { style: 'word-break:break-all;font-size:12px' }, target)
    },
  },
  {
    title: '状态',
    key: 'status',
    width: 110,
    render(row) {
      const meta = statusMeta(row)
      return h(
        NTag,
        { type: meta.type, size: 'small', bordered: false },
        { default: () => meta.text },
      )
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 250,
    render(row) {
      const readonly = !canOperate(row)
      const busyRow = isBusy(row.name)
      const common = {
        size: 'small',
        disabled: actionDisabled({
          available: available.value,
          canWrite: canWrite.value,
          site: row,
          busy: busyRow,
        }),
      }

      const buttons = []
      if (row.generated) {
        buttons.push(
          h(
            NButton,
            { ...common, onClick: () => runToggle(row, !row.enabled) },
            { default: () => (row.enabled ? '禁用' : '启用') },
          ),
        )
      }
      buttons.push(
        h(
          NButton,
          { ...common, onClick: () => openEdit(row) },
          { default: () => '编辑' },
        ),
      )
      buttons.push(
        h(
          NButton,
          { ...common, type: 'error', ghost: true, onClick: () => runDelete(row) },
          { default: () => '删除' },
        ),
      )

      const wrap = h(NSpace, { size: 6, wrap: false }, { default: () => buttons })
      if (!readonly) return wrap
      // 外部配置：按钮已置灰，再补一句说明"为什么不能点"。
      return h('div', [
        wrap,
        h(
          NText,
          { depth: 3, style: 'font-size:12px;display:block;margin-top:4px' },
          { default: () => '非面板创建，只读' },
        ),
      ])
    },
  },
]
</script>

<template>
  <AppLayout>
    <n-space vertical :size="16">
      <!-- 页面头：标题 + 新建按钮 -->
      <n-space justify="space-between" align="center">
        <n-h2 style="margin: 0">网站管理</n-h2>
        <n-button type="primary" :disabled="!available || !canWrite" @click="openCreate">
          新建站点
        </n-button>
      </n-space>

      <!-- 失败必须可见：整页 alert 兜底（message 可能已被关掉） -->
      <n-alert v-if="error" type="error" closable @close="error = ''">
        {{ error }}
      </n-alert>

      <!-- nginx 不可用：明确说明原因并让其它功能照常可用 -->
      <n-alert v-if="!available" type="warning" title="站点管理不可用">
        {{ unavailableReason }}
      </n-alert>

      <!-- 外部配置提示：让用户明白列表里那些灰色条目是什么 -->
      <n-alert v-if="available && stats.external > 0" type="info">
        列表中有 {{ stats.external }} 个站点不是由面板创建（缺少生成标记）。
        面板会以「只读」展示它们，<strong>不会修改</strong>你的手写配置。
      </n-alert>

      <n-card :bordered="false">
        <template #header>
          <n-space align="center" :size="12">
            <span>站点列表</span>
            <n-tag size="small" :bordered="false">共 {{ stats.total }}</n-tag>
            <n-tag size="small" type="success" :bordered="false">
              启用 {{ stats.enabled }}
            </n-tag>
          </n-space>
        </template>

        <template #header-extra>
          <n-space align="center" :size="12">
            <n-checkbox v-model:checked="onlyEnabled" size="small">只看已启用</n-checkbox>
            <n-input
              v-model:value="keyword"
              size="small"
              placeholder="搜索域名 / 站点名 / 路径"
              clearable
              style="width: 220px"
            />
          </n-space>
        </template>

        <n-data-table
          :columns="columns"
          :data="filteredSites"
          :loading="loading"
          :bordered="false"
          :single-line="false"
          size="small"
          :row-key="(row) => row.name"
          :max-height="560"
        />

        <n-empty
          v-if="!loading && filteredSites.length === 0"
          :description="
            sites.length === 0
              ? available
                ? '还没有站点，点右上角「新建站点」开始'
                : '站点管理不可用'
              : '没有匹配的站点'
          "
          style="margin-top: 24px"
        />
      </n-card>

      <!-- 配置目录说明：用户有权知道面板在动哪些文件 -->
      <n-card v-if="capabilities && capabilities.available" size="small" :bordered="false">
        <n-thing title="面板会修改哪些文件">
          <template #description>
            <n-space vertical :size="4" style="font-size: 12px">
              <span>
                布局模式：
                <n-tag size="small" :bordered="false">{{ capabilities.mode }}</n-tag>
              </span>
              <span>
                站点定义目录：<code>{{ capabilities.available_dir }}</code>
              </span>
              <span>
                启用目录：<code>{{ capabilities.enabled_dir }}</code>
              </span>
              <span>{{ capabilities.scope_note }}</span>
            </n-space>
          </template>
        </n-thing>
      </n-card>

      <n-text depth="3" style="font-size: 12px">
        说明：每次修改都会先执行 <code>nginx -t</code> 校验，通过后才 reload；
        校验失败会<strong>自动回滚</strong>到上一个可用版本。所有操作都会记入审计
        <template v-if="auditStats">
          （本次运行已记录 {{ auditStats.total }} 条，其中失败
          {{ auditStats.failed }} 条、被拒 {{ auditStats.denied }} 条、回滚
          {{ auditStats.rolled_back }} 次）
        </template>
        。
      </n-text>
    </n-space>

    <!-- 新建 / 编辑弹窗 -->
    <n-modal
      v-model:show="showForm"
      preset="card"
      :title="isEdit ? `编辑站点：${editingName}` : '新建站点'"
      style="width: 620px"
      :mask-closable="false"
    >
      <n-form label-placement="top" :show-require-mark="false">
        <n-form-item
          label="站点名"
          :validation-status="formErrors.name ? 'error' : undefined"
          :feedback="formErrors.name"
        >
          <n-input
            v-model:value="form.name"
            :disabled="isEdit"
            placeholder="例如 example.com（会作为配置文件名，不支持改名）"
            @input="revalidate"
          />
        </n-form-item>

        <n-form-item
          label="域名"
          :validation-status="formErrors.domain ? 'error' : undefined"
          :feedback="formErrors.domain"
        >
          <n-input
            v-model:value="form.domain"
            placeholder="例如 example.com；通配写 *.example.com；默认站点填 _"
            @input="revalidate"
          />
        </n-form-item>

        <n-form-item
          label="类型"
          :validation-status="formErrors.type ? 'error' : undefined"
          :feedback="formErrors.type"
        >
          <n-radio-group
            v-model:value="form.type"
            @update:value="(v) => { onTypeChange(v); revalidate() }"
          >
            <n-space>
              <n-radio value="static">静态站</n-radio>
              <n-radio value="proxy">反向代理</n-radio>
            </n-space>
          </n-radio-group>
        </n-form-item>

        <!-- 类型切换：静态站填根目录 -->
        <n-form-item
          v-if="form.type === 'static'"
          label="根目录"
          :validation-status="formErrors.root ? 'error' : undefined"
          :feedback="formErrors.root"
        >
          <n-input
            v-model:value="form.root"
            placeholder="例如 /var/www/example.com（必须是存在的绝对路径）"
            @input="revalidate"
          />
        </n-form-item>

        <!-- 类型切换：反向代理填后端地址 -->
        <n-form-item
          v-else
          label="后端地址"
          :validation-status="formErrors.upstream ? 'error' : undefined"
          :feedback="formErrors.upstream"
        >
          <n-input
            v-model:value="form.upstream"
            placeholder="例如 http://127.0.0.1:3000"
            @input="revalidate"
          />
        </n-form-item>

        <!-- 类型不匹配时的残留字段提示 -->
        <n-form-item v-if="formErrors.upstream && form.type === 'static'" :show-label="false">
          <n-text type="error" style="font-size: 12px">{{ formErrors.upstream }}</n-text>
        </n-form-item>
        <n-form-item v-if="formErrors.root && form.type === 'proxy'" :show-label="false">
          <n-text type="error" style="font-size: 12px">{{ formErrors.root }}</n-text>
        </n-form-item>

        <n-form-item label="启用">
          <n-switch v-model:value="form.enabled" />
          <n-text depth="3" style="font-size: 12px; margin-left: 12px">
            启用后 nginx 会立即加载该配置
          </n-text>
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button :disabled="submitting" @click="showForm = false">取消</n-button>
          <n-button type="primary" :loading="submitting" @click="submitForm">
            {{ isEdit ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>
  </AppLayout>
</template>
