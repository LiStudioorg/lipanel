<script setup>
// 防火墙与端口管理页（阶段四 4.6）。
//
// 内置基础页面（不是插件）：防火墙是服务器的安全底线，
// 依赖插件机制会让用户在插件未启动时无法管理端口。
//
// ########## 这一页最需要小心的地方 ##########
//
// 4.1~4.5 的误操作最多让某个功能不可用，本模块的误操作
// 可以让用户**同时失去 SSH 与面板的访问**——而这件事
// 无法通过网络修好，只能去物理控制台或云服务商控制台。
//
// 因此这一页有三处刻意的设计：
//
//   ① 删除一律走二次确认，且**文案里写明具体端口与协议**
//      （计划明确要求）。后端还会独立强制一次（428），
//      所以即便这里出了 bug，规则也不会被误删。
//   ② 受保护端口（面板自身 / SSH）用醒目的标签标出，
//      删除时弹窗升级为红色警告，并要求额外的强制勾选。
//   ③ 不可精确删除的规则**不显示删除按钮**，而是显示原因。
//      给一个点了必然失败的按钮只会让用户反复尝试。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 后端给的 hint 要一并展示（那是"下一步该做什么"）
import { computed, h, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  NAlert,
  NButton,
  NCard,
  NCheckbox,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NTabPane,
  NTabs,
  NTag,
  NText,
  NTooltip,
  useMessage,
} from 'naive-ui'
import { authStore } from '@/stores/auth'
import {
  fetchFirewallStatus,
  fetchFirewallRules,
  fetchFirewallCapabilities,
  fetchFirewallAudit,
  addFirewallPort,
  deleteFirewallPort,
  addFirewallIP,
  deleteFirewallIP,
} from '@/api/firewall'
import {
  actionMeta,
  protectMeta,
  protectionIndex,
  findProtection,
  validatePort,
  validateIP,
  validateComment,
  buildPortPayload,
  buildIPPayload,
  deletePortConfirmText,
  deleteIPConfirmText,
  ruleTargetText,
  protocolLabel,
  sourceLabel,
  portLabel,
  familyLabel,
  defaultPolicyText,
  firewallHealthMeta,
  protectionSummary,
  filterRules,
  summarizeRules,
  auditOutcomeMeta,
  auditActionLabel,
  formatAuditTime,
  commandTimeoutText,
  backendLabel,
} from './firewallLogic.js'

const message = useMessage()
const router = useRouter()

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

const loading = ref(false)
const rulesLoading = ref(false)
const auditLoading = ref(false)
const errorText = ref('')

const status = ref(null)
const rulesResult = ref(null)
const capabilities = ref(null)
const audit = ref(null)
const activeTab = ref('ports')

// 过滤条件。
const keyword = ref('')
const actionFilter = ref('')
const kindFilter = ref('')

// 新规则表单。
const portForm = ref({ port: '', protocol: 'tcp', source: '', action: 'allow', comment: '' })
const portFormError = ref('')
const submitting = ref(false)

const ipForm = ref({ ip: '', direction: 'deny', comment: '' })
const ipFormError = ref('')
const ipSubmitting = ref(false)

// 删除确认。
const deleteTarget = ref(null)      // { kind: 'port' | 'ip', rule, protection }
const deleteAcknowledged = ref(false)
const deleting = ref(false)

// 能力探测折叠区的开关。
const showDetail = ref(false)

// ---------------------------------------------------------------------------
// 计算属性
// ---------------------------------------------------------------------------

const available = computed(() => status.value?.available === true)
const detection = computed(() => status.value?.detection || {})
const detail = computed(() => status.value?.detail || {})
const protection = computed(() => status.value?.protection || { ports: [] })
const protectIdx = computed(() => protectionIndex(protection.value))
const health = computed(() => firewallHealthMeta(status.value))
const summary = computed(() => summarizeRules(rulesResult.value))

const canWrite = computed(() => {
  const perms = status.value?.permissions || []
  return perms.includes('firewall.write') || authStore.isAdmin === true
})

const allRules = computed(() => rulesResult.value?.rules || [])
const ports = computed(() =>
  filterRules(rulesResult.value?.ports || [], {
    keyword: keyword.value, action: actionFilter.value, kind: kindFilter.value,
  }),
)
const ipRules = computed(() =>
  filterRules(rulesResult.value?.ip_rules || [], {
    keyword: keyword.value, action: actionFilter.value, kind: kindFilter.value,
  }),
)

const policyText = computed(() => defaultPolicyText(detail.value))
const protectText = computed(() => protectionSummary(protection.value))
const timeoutText = computed(() => commandTimeoutText(status.value?.command_timeout_seconds))

const portFormValidation = computed(() => {
  const portErr = validatePort(portForm.value.port)
  const sourceErr = portForm.value.source ? validateIP(portForm.value.source) : null
  const commentErr = validateComment(portForm.value.comment)
  return { portErr, sourceErr, commentErr, ok: !portErr && !sourceErr && !commentErr }
})

const ipFormValidation = computed(() => {
  const ipErr = validateIP(ipForm.value.ip)
  const commentErr = validateComment(ipForm.value.comment)
  return { ipErr, commentErr, ok: !ipErr && !commentErr }
})

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

async function loadStatus() {
  loading.value = true
  errorText.value = ''
  try {
    status.value = await fetchFirewallStatus()
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    errorText.value = err.messageWithHint
  } finally {
    loading.value = false
  }
}

async function loadRules() {
  rulesLoading.value = true
  try {
    rulesResult.value = await fetchFirewallRules()
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    errorText.value = err.messageWithHint
  } finally {
    rulesLoading.value = false
  }
}

async function loadCapabilities() {
  try {
    capabilities.value = await fetchFirewallCapabilities()
  } catch (err) {
    // 能力探测失败不影响主流程——它只是说明性信息。
    if (err.status === 401) router.push('/login')
  }
}

async function loadAudit() {
  auditLoading.value = true
  try {
    audit.value = await fetchFirewallAudit({ limit: 100 })
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    errorText.value = err.messageWithHint
  } finally {
    auditLoading.value = false
  }
}

async function refreshAll() {
  await loadStatus()
  await Promise.all([loadRules(), loadCapabilities()])
}

onMounted(refreshAll)

// ---------------------------------------------------------------------------
// 添加端口
// ---------------------------------------------------------------------------

async function submitPort() {
  portFormError.value = ''
  const v = portFormValidation.value
  if (!v.ok) {
    // 只展示第一个错误：一次弹三条用户反而看不清重点。
    portFormError.value = v.portErr || v.sourceErr || v.commentErr
    return
  }

  submitting.value = true
  try {
    const result = await addFirewallPort(buildPortPayload(portForm.value))
    message.success(result?.message || '规则已添加')
    // 命令要在成功提示里回显：用户可能想在其他机器上做同样的事。
    if (result?.commands?.length) {
      message.info(`执行命令：${result.commands.join(' ; ')}`, { duration: 8000 })
    }
    portForm.value = { port: '', protocol: 'tcp', source: '', action: 'allow', comment: '' }
    await Promise.all([loadRules(), loadStatus()])
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    portFormError.value = err.messageWithHint
    // 被拒绝的操作会写审计，重新拉一次让用户看到记录。
    if (err.status === 403) loadAudit()
  } finally {
    submitting.value = false
  }
}

// ---------------------------------------------------------------------------
// 添加 IP 规则
// ---------------------------------------------------------------------------

async function submitIP() {
  ipFormError.value = ''
  const v = ipFormValidation.value
  if (!v.ok) {
    ipFormError.value = v.ipErr || v.commentErr
    return
  }

  ipSubmitting.value = true
  try {
    const result = await addFirewallIP(buildIPPayload(ipForm.value))
    message.success(result?.message || 'IP 规则已添加')
    if (result?.commands?.length) {
      message.info(`执行命令：${result.commands.join(' ; ')}`, { duration: 8000 })
    }
    ipForm.value = { ip: '', direction: 'deny', comment: '' }
    await Promise.all([loadRules(), loadStatus()])
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    ipFormError.value = err.messageWithHint
    if (err.status === 403) loadAudit()
  } finally {
    ipSubmitting.value = false
  }
}

// ---------------------------------------------------------------------------
// 删除（本页最关键的流程）
// ---------------------------------------------------------------------------

// openDeletePort 打开端口规则的删除确认框。
//
// ########## 为什么要把保护信息一起带进弹窗 ##########
//
// 用户点删除时，未必记得这条规则是不是 SSH 端口——
// 尤其当端口是范围（20-30）时，肉眼看不出它覆盖了 22。
// 因此在打开弹窗的这一刻就把保护判定算好并带进去。
function openDeletePort(rule) {
  deleteTarget.value = {
    kind: 'port',
    rule,
    protection: findProtection(protectIdx.value, rule.port_text || rule.port),
  }
  deleteAcknowledged.value = false
}

function openDeleteIP(rule) {
  deleteTarget.value = { kind: 'ip', rule, protection: null }
  deleteAcknowledged.value = false
}

const deleteConfirmText = computed(() => {
  const t = deleteTarget.value
  if (!t) return ''
  return t.kind === 'port'
    ? deletePortConfirmText(t.rule, t.protection)
    : deleteIPConfirmText(t.rule)
})

// deleteBlocked 表示当前确认框里的目标受保护且尚未勾选强制。
//
// ########## 为什么要有这个额外的勾选 ##########
//
// 受保护端口的删除是"明知故犯"的操作。让用户多做一个
// 明确的手势（勾选），把"顺手点确定"与"我真的要删"区分开。
// 后端也会记审计（Force 字段），所以这一步不是唯一防线，
// 但它是把风险摆在用户眼前的那一步。
const deleteBlocked = computed(
  () => Boolean(deleteTarget.value?.protection) && !deleteAcknowledged.value,
)

async function confirmDelete() {
  const t = deleteTarget.value
  if (!t) return
  deleting.value = true
  try {
    if (t.kind === 'port') {
      // confirm 必须为 true —— 后端不带它就返回 428。
      const result = await deleteFirewallPort({
        port: t.rule.port_text || t.rule.port,
        protocol: t.rule.protocol,
        source: t.rule.source || '',
        action: t.rule.action,
        confirm: true,
        force: Boolean(t.protection),
      })
      message.success(result?.message || '规则已删除')
    } else {
      const result = await deleteFirewallIP({
        ip: t.rule.source,
        direction: t.rule.action === 'allow' ? 'allow' : 'deny',
        confirm: true,
      })
      message.success(result?.message || 'IP 规则已删除')
    }
    deleteTarget.value = null
    await Promise.all([loadRules(), loadStatus()])
  } catch (err) {
    if (err.status === 401) return router.push('/login')
    // 428 说明前端漏传了 confirm —— 这是本页的 bug，
    // 因此提示要明确，便于快速定位。
    if (err.confirmRequired) {
      message.error('请求缺少二次确认标记，操作未执行（这是界面异常，请刷新后重试）')
    } else {
      message.error(err.messageWithHint)
    }
    if (err.status === 403 || err.status === 409) loadAudit()
  } finally {
    deleting.value = false
  }
}

// ---------------------------------------------------------------------------
// 表格列
// ---------------------------------------------------------------------------

function renderPortTag(row) {
  const tags = [h(NTag, { size: 'small', type: 'info', bordered: false }, { default: () => portLabel(row) })]
  if (row.protocol) {
    tags.push(
      h(NTag, { size: 'small', bordered: false }, { default: () => protocolLabel(row.protocol) }),
    )
  }
  if (row.family === 'ipv6') {
    tags.push(h(NTag, { size: 'small', type: 'warning', bordered: false }, { default: () => 'IPv6' }))
  }
  return h(NSpace, { size: 4, wrap: false }, { default: () => tags })
}

function renderActionTag(row) {
  const meta = actionMeta(row.action)
  return h(
    NTag,
    { size: 'small', type: meta.type, bordered: false },
    { default: () => `${meta.icon} ${meta.label}` },
  )
}

function renderBadges(row) {
  const nodes = []
  if (row.origin === 'external') {
    nodes.push(
      h(NTag, { size: 'tiny', bordered: false }, { default: () => '外部创建' }),
    )
  }
  if (row.protected) {
    const meta = protectMeta(row.protection_kind)
    nodes.push(
      h(
        NTooltip,
        { trigger: 'hover' },
        {
          trigger: () =>
            h(
              NTag,
              { size: 'tiny', type: meta.type, bordered: false },
              { default: () => `${meta.icon} ${meta.label}` },
            ),
          default: () => row.protected_reason || '该端口受保护，删除后可能失去连接',
        },
      ),
    )
  }
  if (!nodes.length) return h(NText, { depth: 3 }, { default: () => '—' })
  return h(NSpace, { size: 4, wrap: false }, { default: () => nodes })
}

function renderDeleteCell(row, openFn) {
  // ########## 不可删除时不给按钮，而是给原因 ##########
  //
  // 给一个点了必然失败的按钮只会让用户反复尝试，
  // 然后来问"为什么删不掉"。直接把原因写在这里更省事。
  if (row.deletable === false) {
    return h(
      NTooltip,
      { trigger: 'hover' },
      {
        trigger: () =>
          h(NText, { depth: 3, style: 'cursor: help' }, { default: () => '不可删除 ⓘ' }),
        default: () => row.not_deletable_reason || '该规则无法被精确删除',
      },
    )
  }
  return h(
    NButton,
    {
      size: 'small',
      tertiary: true,
      type: row.protected ? 'error' : 'default',
      disabled: !canWrite.value,
      onClick: () => openFn(row),
    },
    { default: () => '删除' },
  )
}

const portColumns = computed(() => [
  { title: '端口', key: 'port', render: renderPortTag },
  { title: '来源', key: 'source', render: (row) => sourceLabel(row.source) },
  { title: '动作', key: 'action', render: renderActionTag },
  { title: '标记', key: 'badges', render: renderBadges },
  {
    title: '备注',
    key: 'comment',
    ellipsis: { tooltip: true },
    render: (row) => row.comment || h(NText, { depth: 3 }, { default: () => '—' }),
  },
  {
    title: '操作',
    key: 'ops',
    render: (row) => renderDeleteCell(row, openDeletePort),
  },
])

const ipColumns = computed(() => [
  { title: '地址 / 网段', key: 'source', render: (row) => row.source || '—' },
  { title: '族', key: 'family', render: (row) => familyLabel(row.family) },
  { title: '动作', key: 'action', render: renderActionTag },
  { title: '来源', key: 'origin', render: renderBadges },
  {
    title: '备注',
    key: 'comment',
    ellipsis: { tooltip: true },
    render: (row) => row.comment || h(NText, { depth: 3 }, { default: () => '—' }),
  },
  {
    title: '操作',
    key: 'ops',
    render: (row) => renderDeleteCell(row, openDeleteIP),
  },
])

const auditColumns = [
  { title: '时间', key: 'time', render: (row) => formatAuditTime(row.time) },
  { title: '用户', key: 'user' },
  { title: '操作', key: 'action', render: (row) => auditActionLabel(row.action) },
  { title: '目标', key: 'target', render: (row) => row.target || '—' },
  {
    title: '结果',
    key: 'outcome',
    render: (row) => {
      const meta = auditOutcomeMeta(row.outcome)
      return h(NTag, { size: 'small', type: meta.type, bordered: false }, { default: () => meta.label })
    },
  },
  { title: '后端', key: 'backend', render: (row) => backendLabel(row.backend) },
  {
    title: '命令',
    key: 'command',
    ellipsis: { tooltip: true },
    render: (row) => row.command || h(NText, { depth: 3 }, { default: () => '—' }),
  },
]

// capabilityRows 把能力探测结果转成描述列表。
const capabilityRows = computed(() => capabilities.value?.backends || [])

const protocolOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
  { label: 'TCP + UDP', value: 'any' },
]

const actionOptions = [
  { label: '允许', value: 'allow' },
  { label: '拒绝', value: 'deny' },
]
</script>

<template>
  <div class="fw-page">
    <n-spin :show="loading">
      <!-- 顶部：后端与状态 -->
      <n-card title="防火墙" size="small" class="fw-card">
        <template #header-extra>
          <n-button size="small" tertiary :loading="loading" @click="refreshAll">刷新</n-button>
        </template>

        <n-alert v-if="errorText" type="error" class="fw-alert" closable @close="errorText = ''">
          {{ errorText }}
        </n-alert>

        <!-- 整体健康状态：未安装 / 未启用 / 默认放行 / 正常 -->
        <n-alert :type="health.type" class="fw-alert" :show-icon="true">
          <template #header>{{ health.label }}</template>
          {{ health.detail }}
        </n-alert>

        <!-- 未检测到防火墙：给出安装指引与降级说明 -->
        <template v-if="!available">
          <n-alert type="info" class="fw-alert">
            面板无法管理防火墙，但其它功能不受影响。
            <template v-if="status?.install_hint">
              <br />
              {{ status.install_hint }}
            </template>
          </n-alert>
        </template>

        <template v-else>
          <n-descriptions :column="3" size="small" label-placement="top" bordered>
            <n-descriptions-item label="后端">
              {{ detection.label || backendLabel(detection.backend) }}
              <n-tag v-if="detection.selected" size="tiny" type="success" :bordered="false">
                自动选择
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="运行状态">
              <n-tag :type="detail.enabled ? 'success' : 'warning'" size="small" :bordered="false">
                {{ detail.enabled ? '运行中' : '未启用' }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="规则条数">
              <n-statistic :value="status?.rule_count ?? 0" />
            </n-descriptions-item>
            <n-descriptions-item label="默认策略">
              {{ policyText || '—' }}
            </n-descriptions-item>
            <n-descriptions-item label="命令超时">
              {{ timeoutText }}
            </n-descriptions-item>
            <n-descriptions-item label="试运行">
              <n-tag :type="status?.dry_run ? 'warning' : 'default'" size="small" :bordered="false">
                {{ status?.dry_run ? '已开启（不修改规则）' : '关闭' }}
              </n-tag>
            </n-descriptions-item>
          </n-descriptions>

          <!-- 保护端口 -->
          <n-alert v-if="protectText" type="warning" class="fw-alert fw-protect" :show-icon="true">
            <template #header>端口保护</template>
            <span style="white-space: pre-line">{{ protectText }}</span>
          </n-alert>

          <!-- 后端说明 -->
          <n-alert v-if="detection.reason" type="info" class="fw-alert">
            {{ detection.reason }}
          </n-alert>
          <n-alert
            v-for="(note, i) in detail.notes || []"
            :key="i"
            type="warning"
            class="fw-alert"
          >
            {{ note }}
          </n-alert>
        </template>
      </n-card>

      <template v-if="available">
        <n-tabs v-model:value="activeTab" type="line" class="fw-tabs">
          <!-- ============ 端口规则 ============ -->
          <n-tab-pane name="ports" tab="端口规则">
            <n-card size="small" class="fw-card">
              <template #header>
                放行 / 拒绝端口
                <n-text depth="3" style="font-size: 12px; margin-left: 8px">
                  TCP 与 UDP 需分别添加；范围请用「起始-结束」
                </n-text>
              </template>

              <n-alert v-if="portFormError" type="error" class="fw-alert" closable
                       @close="portFormError = ''">
                {{ portFormError }}
              </n-alert>

              <n-form label-placement="top" :show-feedback="false">
                <n-space :size="12" align="flex-end" :wrap="true">
                  <n-form-item label="端口 / 范围" style="min-width: 160px">
                    <n-input v-model:value="portForm.port" placeholder="8080 或 8080-8090" />
                  </n-form-item>
                  <n-form-item label="协议" style="min-width: 130px">
                    <n-select v-model:value="portForm.protocol" :options="protocolOptions" />
                  </n-form-item>
                  <n-form-item label="来源（留空为任意）" style="min-width: 200px">
                    <n-input v-model:value="portForm.source" placeholder="192.168.1.0/24" />
                  </n-form-item>
                  <n-form-item label="动作" style="min-width: 110px">
                    <n-select v-model:value="portForm.action" :options="actionOptions" />
                  </n-form-item>
                  <n-form-item label="备注" style="min-width: 160px">
                    <n-input v-model:value="portForm.comment" placeholder="可选，最多 128 字" />
                  </n-form-item>
                  <n-form-item>
                    <n-button
                      type="primary"
                      :loading="submitting"
                      :disabled="!canWrite"
                      @click="submitPort"
                    >
                      添加规则
                    </n-button>
                  </n-form-item>
                </n-space>
              </n-form>

              <n-alert v-if="!canWrite" type="warning" class="fw-alert">
                当前账号没有防火墙写权限（firewall.write），只能查看规则。
              </n-alert>

              <!-- 过滤 -->
              <n-space :size="12" align="center" class="fw-filter" :wrap="true">
                <n-input
                  v-model:value="keyword"
                  placeholder="搜索端口 / 来源 / 备注"
                  style="width: 240px"
                  clearable
                />
                <n-select
                  v-model:value="actionFilter"
                  :options="[{ label: '全部动作', value: '' }, ...actionOptions]"
                  style="width: 130px"
                />
                <n-select
                  v-model:value="kindFilter"
                  :options="[
                    { label: '全部类别', value: '' },
                    { label: '端口', value: 'port' },
                    { label: 'IP', value: 'ip' },
                  ]"
                  style="width: 130px"
                />
                <n-text depth="3" style="font-size: 12px">
                  共 {{ summary.total }} 条（可删除 {{ summary.deletable }}）
                  <template v-if="summary.notDeletable > 0">
                    ，其中 {{ summary.notDeletable }} 条无法精确删除（详见各行说明）
                  </template>
                </n-text>
              </n-space>

              <n-data-table
                :columns="portColumns"
                :data="ports"
                :loading="rulesLoading"
                :bordered="false"
                size="small"
                :row-key="(row) => `p-${row.index}-${row.port_text}-${row.protocol}-${row.source}`"
                class="fw-table"
              >
                <template #empty>
                  <n-empty description="暂无端口规则" />
                </template>
              </n-data-table>
            </n-card>
          </n-tab-pane>

          <!-- ============ IP 黑白名单 ============ -->
          <n-tab-pane name="ips" tab="IP 黑白名单">
            <n-card size="small" class="fw-card">
              <template #header>添加 IP 黑白名单</template>

              <n-alert v-if="ipFormError" type="error" class="fw-alert" closable
                       @close="ipFormError = ''">
                {{ ipFormError }}
              </n-alert>

              <n-form label-placement="top" :show-feedback="false">
                <n-space :size="12" align="flex-end" :wrap="true">
                  <n-form-item label="IP / 网段" style="min-width: 220px">
                    <n-input v-model:value="ipForm.ip" placeholder="203.0.113.5 或 10.0.0.0/8" />
                  </n-form-item>
                  <n-form-item label="类型" style="min-width: 170px">
                    <n-radio-group v-model:value="ipForm.direction">
                      <n-radio-button value="deny">黑名单（拒绝）</n-radio-button>
                      <n-radio-button value="allow">白名单（放行）</n-radio-button>
                    </n-radio-group>
                  </n-form-item>
                  <n-form-item label="备注" style="min-width: 200px">
                    <n-input v-model:value="ipForm.comment" placeholder="可选，例如：恶意扫描" />
                  </n-form-item>
                  <n-form-item>
                    <n-button
                      type="primary"
                      :loading="ipSubmitting"
                      :disabled="!canWrite"
                      @click="submitIP"
                    >
                      添加
                    </n-button>
                  </n-form-item>
                </n-space>
              </n-form>

              <n-alert type="info" class="fw-alert">
                黑白名单作用于**任意端口**的该来源地址。若要限制某来源访问特定端口，
                请改用上方「端口规则」的来源字段。
              </n-alert>

              <n-data-table
                :columns="ipColumns"
                :data="ipRules"
                :loading="rulesLoading"
                :bordered="false"
                size="small"
                :row-key="(row) => `i-${row.index}-${row.source}-${row.action}`"
                class="fw-table"
              >
                <template #empty>
                  <n-empty description="暂无 IP 黑白名单规则" />
                </template>
              </n-data-table>
            </n-card>
          </n-tab-pane>

          <!-- ============ 操作审计 ============ -->
          <n-tab-pane name="audit" tab="操作审计">
            <n-card size="small" class="fw-card">
              <template #header>
                操作审计
                <n-text depth="3" style="font-size: 12px; margin-left: 8px">
                  含被拒绝的尝试（它们没有改变任何规则）
                </n-text>
              </template>
              <template #header-extra>
                <n-button size="small" tertiary :loading="auditLoading" @click="loadAudit">
                  刷新
                </n-button>
              </template>

              <n-alert type="info" class="fw-alert">
                防火墙没有「回收站」：这里记录了每次写操作实际执行的命令与规则规格，
                是事后恢复与追责的依据。
              </n-alert>

              <n-data-table
                :columns="auditColumns"
                :data="audit?.events || []"
                :loading="auditLoading"
                :bordered="false"
                size="small"
                :row-key="(row) => row.seq"
                class="fw-table"
              >
                <template #empty>
                  <n-empty description="暂无审计记录（点击上方「刷新」加载）" />
                </template>
              </n-data-table>
            </n-card>
          </n-tab-pane>

          <!-- ============ 能力探测 ============ -->
          <n-tab-pane name="capabilities" tab="后端能力">
            <n-card size="small" class="fw-card">
              <template #header>后端能力与删除语义</template>

              <n-alert type="info" class="fw-alert">
                不同防火墙的删除方式不同，这解释了「为什么某些规则删不掉」。
              </n-alert>

              <n-descriptions :column="1" size="small" label-placement="top" bordered>
                <n-descriptions-item
                  v-for="cap in capabilityRows"
                  :key="cap.backend"
                  :label="cap.label"
                >
                  <n-space vertical :size="4">
                    <n-text>{{ cap.deletion }}</n-text>
                    <n-space :size="6">
                      <n-tag size="tiny" :bordered="false"
                             :type="cap.supports_comment ? 'success' : 'default'">
                        备注 {{ cap.supports_comment ? '支持' : '不支持' }}
                      </n-tag>
                      <n-tag size="tiny" :bordered="false"
                             :type="cap.supports_source ? 'success' : 'default'">
                        来源限定 {{ cap.supports_source ? '支持' : '不支持' }}
                      </n-tag>
                      <n-tag size="tiny" :bordered="false"
                             :type="cap.supports_any_protocol ? 'success' : 'default'">
                        单条覆盖 TCP+UDP {{ cap.supports_any_protocol ? '支持' : '不支持' }}
                      </n-tag>
                    </n-space>
                  </n-space>
                </n-descriptions-item>
              </n-descriptions>

              <n-alert type="warning" class="fw-alert">
                删除规则需要二次确认（服务端强制）：不带确认的删除请求会被拒绝，
                规则不会被执行。
              </n-alert>
            </n-card>
          </n-tab-pane>
        </n-tabs>
      </template>
    </n-spin>

    <!-- ==================== 删除确认弹窗 ==================== -->
    <n-modal
      :show="deleteTarget !== null"
      preset="card"
      :title="deleteTarget?.protection ? '⚠️ 删除受保护端口的规则' : '确认删除规则'"
      style="max-width: 560px"
      :mask-closable="false"
      @update:show="(v) => { if (!v) deleteTarget = null }"
    >
      <!-- 文案里写明了具体端口、协议与后果（计划明确要求） -->
      <n-alert
        :type="deleteTarget?.protection ? 'error' : 'warning'"
        :show-icon="true"
        class="fw-alert"
      >
        <span style="white-space: pre-line">{{ deleteConfirmText }}</span>
      </n-alert>

      <n-alert
        v-if="deleteTarget?.protection"
        type="error"
        class="fw-alert"
        :show-icon="false"
      >
        <n-checkbox v-model:checked="deleteAcknowledged">
          我确认要删除这个受保护端口的规则，并了解可能导致无法再连接到服务器
        </n-checkbox>
      </n-alert>

      <template #footer>
        <n-space justify="end">
          <n-button @click="deleteTarget = null">取消</n-button>
          <n-button
            type="error"
            :loading="deleting"
            :disabled="deleteBlocked"
            @click="confirmDelete"
          >
            {{ deleteTarget?.protection ? '强制删除' : '确认删除' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.fw-page {
  padding: 16px;
}
.fw-card {
  margin-bottom: 16px;
}
.fw-alert {
  margin-bottom: 12px;
}
.fw-protect {
  margin-top: 12px;
}
.fw-tabs {
  margin-top: 8px;
}
.fw-filter {
  margin: 16px 0;
}
.fw-table {
  margin-top: 8px;
}
</style>
