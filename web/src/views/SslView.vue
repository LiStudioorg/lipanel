<script setup>
// SSL 证书页（阶段四 4.4）。
//
// 内置基础页面（不是插件）：证书是面板对外提供服务的基础能力，
// 依赖插件机制反而会让用户在插件未启动时无法管理证书。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 申请/续期是**有真实代价**的操作（消耗 CA 配额、改写 HTTPS 配置），
//     一律走二次确认，且弹窗里写清代价与前置条件
//   - 操作后自动刷新（失败也刷新：证书可能已经签发成功了）
//   - 后端返回 issued=true 但 applied=false 时，必须明确告诉用户
//     「证书已经拿到了，不要重复申请」——否则他会一直重试
//     直到撞上 Let's Encrypt 的速率限制
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
  NInput,
  NSpace,
  NStatistic,
  NTag,
  NText,
  NTooltip,
} from 'naive-ui'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import {
  fetchSSLCapabilities,
  fetchSSLStatus,
  issueCertificate,
  renewCertificate,
} from '@/api/ssl'
import {
  attentionSites,
  attentionText,
  clientText,
  daysText,
  expiryText,
  filterSites,
  issueConfirmText,
  issueDisabled,
  issueResultText,
  renewConfirmText,
  renewDisabled,
  renewResultText,
  statusMeta,
  STATUS_OPTIONS,
  summarize,
} from '@/views/sslLogic'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const sites = ref([])
const client = ref(null)
const available = ref(true)
const unavailableReason = ref('')
const renewDays = ref(30)
const dryRun = ref(false)
const counts = ref(null)
const scheduler = ref(null)
const auditStats = ref(null)
const permissions = ref([])
const capabilities = ref(null)

// busy 记录每个站点正在执行的操作，用于**按钮级** Loading。
// 用对象而不是单个布尔量：操作 A 站点时不该让 B 站点的按钮也转圈。
const busy = ref({})

// 搜索与状态过滤。
const keyword = ref('')
const statusFilter = ref('')

// canWrite 表示当前用户是否被授予 ssl.write。
//
// 注意：这只是**体验优化**（无权限时按钮置灰），真正的强制点在后端
// （ssl.CheckSSLPermission）。前端标记被篡改也不会获得任何权限。
const canWrite = computed(() => permissions.value.includes('ssl.write'))

// filteredSites 是本页真正渲染的数据。
//
// 过滤逻辑抽在 @/views/sslLogic，由 node:test 覆盖
// （组件本身依赖 Vue/Naive UI，在本仓库的前端测试环境里无法直接 import）。
const filteredSites = computed(() =>
  filterSites(sites.value, { keyword: keyword.value, status: statusFilter.value }),
)

// stats 基于**全量**数据统计（不受过滤影响），这样顶部的数字
// 始终代表整台机器的真实状况。
const stats = computed(() => summarize(sites.value))

// attention 是需要用户立刻关注的站点（已过期/即将过期/状态异常）。
const attention = computed(() => attentionSites(sites.value))
const attentionMsg = computed(() => attentionText(sites.value))

// clientInfo 把 ACME 客户端信息转成展示用的三元组。
const clientInfo = computed(() => clientText(client.value))

onMounted(() => {
  load()
})

// load 拉取状态与能力信息。
//
// silent 为 true 时不动全局 loading（用于操作后的静默刷新，
// 避免整页闪一下 loading 反而让人以为出了错）。
async function load({ silent = false } = {}) {
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchSSLStatus()
    sites.value = data.sites || []
    client.value = data.client || null
    available.value = data.available !== false
    unavailableReason.value = data.unavailable_reason || ''
    renewDays.value = data.renew_days ?? 30
    dryRun.value = Boolean(data.dry_run)
    counts.value = data.counts || null
    scheduler.value = data.scheduler || null
    auditStats.value = data.audit || null
    permissions.value = data.permissions || []
  } catch (err) {
    if (handleAuthError(err)) return
    error.value = err?.messageWithHint || err?.message || '加载 SSL 状态失败'
  } finally {
    if (!silent) loading.value = false
  }

  // 能力信息单独拉取：它失败不该让整页没有数据，
  // 因此放在状态加载之后且不参与上面的 try。
  try {
    capabilities.value = await fetchSSLCapabilities()
  } catch {
    capabilities.value = null
  }
}

// handleAuthError 处理 401：清空登录态并跳回登录页。
//
// 返回 true 表示已处理，调用方应当直接 return。
function handleAuthError(err) {
  if (err instanceof ApiError && err.isUnauthorized) {
    authStore.clear()
    message.warning('登录已过期，请重新登录')
    router.replace({ name: 'login', query: { redirect: '/ssl' } })
    return true
  }
  return false
}

// setBusy 设置/清除某个站点的忙碌标记。
function setBusy(name, value) {
  busy.value = { ...busy.value, [name]: value }
}

function isBusy(name) {
  return Boolean(busy.value[name])
}

// ---------- 操作 ----------

// runIssue 申请证书。
//
// ########## 为什么必须二次确认且写清代价 ##########
//
// 这不是"改一个本地文件"——它会向 Let's Encrypt 发起真实请求
// 并**消耗签发配额**。同一组域名每周只有 5 次重复签发机会，
// 误点几下就可能把配额打满，之后整整一周都无法为这个域名
// 签发证书（包括紧急续期）。
//
// 因此确认弹窗由 sslLogic.issueConfirmText 生成，写清三件事：
// 会做什么、消耗什么、需要什么前置条件。
function runIssue(site, { force = false } = {}) {
  dialog.warning({
    title: '申请 Let\'s Encrypt 证书',
    content: () =>
      h(
        'pre',
        { style: 'white-space:pre-wrap;margin:0;font-family:inherit;line-height:1.7' },
        issueConfirmText(site),
      ),
    positiveText: force ? '强制申请' : '确认申请',
    negativeText: '取消',
    onPositiveClick: async () => {
      setBusy(site.site, true)
      try {
        const res = await issueCertificate(site.site, { force })
        // 结果文案由 sslLogic 统一生成：它区分了「完全成功」
        // 与「证书已获取但配置未写入」这两种含义完全不同的结果。
        if (res.issued && !res.applied) {
          message.warning(issueResultText(res), { duration: 10000 })
        } else {
          message.success(issueResultText(res))
        }
      } catch (err) {
        handleIssueError(err)
      } finally {
        setBusy(site.site, false)
        // 失败也刷新：证书可能已经签发成功了（只是配置没写进去），
        // 不刷新会让界面显示一个过期的状态，进而诱导用户重复申请。
        await load({ silent: true })
      }
    },
  })
}

// runRenew 续期证书。
//
// 默认不强制：certbot 只在证书进入续期窗口时才真正签发，
// 未到窗口会跳过（且**不消耗配额**）。用户想立刻重签可以勾选强制。
function runRenew(site, { force = false } = {}) {
  dialog.warning({
    title: '续期证书',
    content: () =>
      h(
        'pre',
        { style: 'white-space:pre-wrap;margin:0;font-family:inherit;line-height:1.7' },
        renewConfirmText(site, { force }),
      ),
    positiveText: force ? '强制续期' : '确认续期',
    negativeText: '取消',
    onPositiveClick: async () => {
      setBusy(site.site, true)
      try {
        const res = await renewCertificate(site.site, { force })
        // "跳过"必须用 info 而不是 success：它确实没做任何事，
        // 显示成绿色成功会让用户以为到期时间被延长了。
        if (res.skipped) {
          message.info(renewResultText(res))
        } else {
          message.success(renewResultText(res))
        }
      } catch (err) {
        handleRenewError(err)
      } finally {
        setBusy(site.site, false)
        await load({ silent: true })
      }
    },
  })
}

// handleIssueError 把申请失败翻译成用户能理解并据以行动的信息。
//
// ########## 这里最关键的是区分三种失败 ##########
//
//  ① 无权限（403）／环境不可用（503）／输入非法（400）
//     → 用户改输入或装软件就能解决，直接提示即可。
//
//  ② 证书已获取但配置写入失败（422，issued=true）
//     → CA 配额**已经消耗**。若只说一句"申请失败"，
//       用户会直接重试，每次都再消耗一次配额。
//       必须明确告诉他"证书已经拿到了，不要重复申请"。
//
//  ③ 超时（504，maybe_issued=true）
//     → 结果**未知**：CA 那边可能已经签发成功。
//       必须引导用户先刷新查看，而不是立即重试。
function handleIssueError(err) {
  if (handleAuthError(err)) return

  const base = err?.messageWithHint || err?.message || '未知错误'

  if (err?.maybeIssued) {
    dialog.warning({
      title: '申请超时，结果未知',
      content: () =>
        h('div', [
          h(
            'p',
            { style: 'margin:0 0 8px;font-weight:500' },
            '超时不代表没有签发——Let\'s Encrypt 可能已经完成签发并计入配额。',
          ),
          h(
            'p',
            { style: 'margin:0 0 8px' },
            '请先点击「刷新」查看证书是否已存在，确认之前不要重复申请，' +
              '否则会白白消耗配额（同一域名每周最多 5 次）。',
          ),
          h('pre', { style: preStyle }, base),
        ]),
      positiveText: '知道了',
    })
    return
  }

  if (err?.issued) {
    dialog.error({
      title: '证书已获取，但配置未生效',
      content: () =>
        h('div', [
          h(
            'p',
            { style: 'margin:0 0 8px;font-weight:500' },
            '证书已经成功获取（CA 配额已消耗），但写入 nginx 配置时失败。',
          ),
          h(
            'p',
            { style: 'margin:0 0 8px' },
            '请修复下面的问题后**直接重试**——已存在的证书不会重复签发，' +
              '因此不会再次消耗配额。',
          ),
          h('pre', { style: preStyle }, base),
        ]),
      positiveText: '知道了',
    })
    return
  }

  message.error(base, { duration: 8000 })
}

// handleRenewError 处理续期失败（语义与申请相同，但标题不同）。
function handleRenewError(err) {
  if (handleAuthError(err)) return

  const base = err?.messageWithHint || err?.message || '未知错误'

  if (err?.maybeIssued) {
    dialog.warning({
      title: '续期超时，结果未知',
      content: () =>
        h('div', [
          h(
            'p',
            { style: 'margin:0 0 8px' },
            '超时不代表没有续期成功。请先点击「刷新」查看到期时间是否已更新。',
          ),
          h('pre', { style: preStyle }, base),
        ]),
      positiveText: '知道了',
    })
    return
  }

  message.error(base, { duration: 8000 })
}

const preStyle =
  'white-space:pre-wrap;word-break:break-all;background:#f5f5f5;' +
  'padding:8px;border-radius:4px;margin:0;max-height:240px;overflow:auto;font-size:12px'

// ---------- 表格列 ----------

const columns = [
  {
    title: '站点 / 域名',
    key: 'domain',
    minWidth: 200,
    render(row) {
      return h('div', [
        h('div', { style: 'font-weight:500' }, row.domain || row.site),
        h(
          NText,
          { depth: 3, style: 'font-size:12px' },
          { default: () => `站点名：${row.site}` },
        ),
      ])
    },
  },
  {
    title: '证书状态',
    key: 'status',
    width: 130,
    render(row) {
      const meta = statusMeta(row.status)
      // 状态标签带 tooltip：像"未知"这类状态，只看到两个字
      // 用户不知道是什么意思、也不知道该怎么办。
      return h(
        NTooltip,
        { trigger: 'hover' },
        {
          trigger: () =>
            h(
              NTag,
              { type: meta.type, size: 'small', bordered: false },
              { default: () => meta.label },
            ),
          default: () => meta.desc || meta.label,
        },
      )
    },
  },
  {
    title: '到期时间',
    key: 'expiry',
    width: 190,
    render(row) {
      if (!row.issued) {
        return h(NText, { depth: 3 }, { default: () => '—' })
      }
      return h('div', [
        h('div', expiryText(row.expiry)),
        h(
          NText,
          {
            // 剩余天数本身也有颜色：这样即使不看状态标签，
            // 也能从数字上直观看出紧迫程度。
            type: row.status === 'expired' ? 'error' : row.status === 'expiring' ? 'warning' : 'success',
            style: 'font-size:12px',
          },
          { default: () => daysText(row.days_remaining) },
        ),
      ])
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 260,
    render(row) {
      const busyRow = isBusy(row.site)
      const issue = issueDisabled(row, {
        canWrite: canWrite.value,
        available: available.value,
      })
      const renew = renewDisabled(row, {
        canWrite: canWrite.value,
        available: available.value,
      })

      // 按钮禁用时用 tooltip 说明**为什么**不能点。
      // 禁用而不说原因是糟糕的体验：用户只会觉得按钮坏了。
      const makeButton = ({ label, type, ghost, disabledInfo, onClick }) => {
        const btn = h(
          NButton,
          {
            size: 'small',
            type,
            ghost,
            loading: busyRow,
            disabled: busyRow || disabledInfo.disabled,
            onClick,
          },
          { default: () => label },
        )
        if (!disabledInfo.disabled) return btn
        return h(
          NTooltip,
          { trigger: 'hover' },
          {
            trigger: () => h('span', { style: 'display:inline-block' }, btn),
            default: () => disabledInfo.reason,
          },
        )
      }

      const buttons = [
        makeButton({
          label: row.issued ? '重新申请' : '申请证书',
          type: 'primary',
          disabledInfo: issue,
          onClick: () => runIssue(row),
        }),
        makeButton({
          label: '续期',
          disabledInfo: renew,
          onClick: () => runRenew(row),
        }),
      ]

      // 只有即将过期/已过期的证书才提供"强制续期"：
      // 它对健康证书是纯粹的配额浪费（每周 5 次限制）。
      if (row.issued && (row.status === 'expiring' || row.status === 'expired')) {
        buttons.push(
          makeButton({
            label: '强制续期',
            type: 'warning',
            ghost: true,
            disabledInfo: renew,
            onClick: () => runRenew(row, { force: true }),
          }),
        )
      }

      return h(NSpace, { size: 6, wrap: false }, { default: () => buttons })
    },
  },
]

// isRowProps 给表格行加底色，让过期的行在长列表里一眼可见。
function rowProps(row) {
  if (row.status === 'expired') {
    return { style: 'background-color: rgba(208, 48, 80, 0.06)' }
  }
  if (row.status === 'expiring') {
    return { style: 'background-color: rgba(240, 160, 32, 0.06)' }
  }
  return {}
}
</script>

<template>
  <AppLayout>
    <div class="ssl-view">
      <!-- 页面标题 -->
      <div class="page-head">
        <div>
          <h2 class="page-title">SSL 证书</h2>
          <p class="page-desc">
            为站点申请 Let's Encrypt 证书并自动续期。使用 HTTP-01 验证，
            复用站点现有的 80 端口，申请过程不会中断服务。
          </p>
        </div>
        <NButton :loading="loading" @click="load()">刷新</NButton>
      </div>

      <!-- 错误兜底：加载失败必须可见 -->
      <NAlert v-if="error" type="error" closable class="mb" @close="error = ''">
        {{ error }}
      </NAlert>

      <!-- 需要关注的证书：主动把紧迫的问题摆到最上面 -->
      <NAlert v-if="attentionMsg" type="warning" class="mb" title="需要关注">
        {{ attentionMsg }}。证书到期后站点会无法通过 HTTPS 访问，建议尽快处理。
      </NAlert>

      <!-- 试运行模式提示 -->
      <NAlert v-if="dryRun" type="info" class="mb" title="试运行模式">
        当前为试运行模式（-cert-dry-run）：使用 ACME staging 环境，
        签发的证书不被浏览器信任，且不会写入证书文件。
        该模式<strong>不消耗</strong>生产配额，适合先验证域名解析与 80 端口是否就绪。
      </NAlert>

      <!-- 能力不可用提示：不报错，只说明原因与下一步 -->
      <NAlert
        v-if="!available"
        type="warning"
        class="mb"
        title="当前无法申请证书"
      >
        {{ unavailableReason || 'ACME 客户端不可用。' }}
        <template v-if="clientInfo.detail">
          <br />{{ clientInfo.detail }}
        </template>
      </NAlert>

      <!-- 统计卡片 -->
      <div class="stat-grid">
        <NCard size="small">
          <NStatistic label="站点总数" :value="stats.total" />
        </NCard>
        <NCard size="small">
          <NStatistic label="已申请" :value="stats.issued" />
        </NCard>
        <NCard size="small">
          <NStatistic label="有效" :value="stats.valid" />
        </NCard>
        <NCard size="small">
          <NStatistic label="即将过期" :value="stats.expiring">
            <template v-if="stats.expiring > 0" #suffix>
              <NText type="warning" style="font-size:13px">
                ≤{{ renewDays }}天
              </NText>
            </template>
          </NStatistic>
        </NCard>
        <NCard size="small">
          <NStatistic label="已过期" :value="stats.expired" />
        </NCard>
        <NCard size="small">
          <NStatistic label="未申请" :value="stats.none" />
        </NCard>
      </div>

      <!-- 客户端与运行信息 -->
      <NCard size="small" class="mb" title="运行信息">
        <NDescriptions :column="2" label-placement="left" size="small">
          <NDescriptionsItem label="ACME 客户端">
            <NTag :type="clientInfo.type" size="small" :bordered="false">
              {{ clientInfo.label }}
            </NTag>
          </NDescriptionsItem>
          <NDescriptionsItem label="验证方式">
            <NTag size="small" :bordered="false" type="info">HTTP-01（webroot）</NTag>
          </NDescriptionsItem>
          <NDescriptionsItem label="续期阈值">
            剩余 {{ renewDays }} 天判定为即将过期
          </NDescriptionsItem>
          <NDescriptionsItem label="自动续期">
            <template v-if="scheduler && scheduler.running">
              <NTag type="success" size="small" :bordered="false">已启用</NTag>
              <NText depth="3" style="font-size:12px;margin-left:6px">
                每 {{ scheduler.interval }} 检查一次
                <template v-if="scheduler.last_run">
                  ，上次 {{ scheduler.last_run }}
                </template>
              </NText>
            </template>
            <NTag v-else size="small" :bordered="false">未启用</NTag>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="clientInfo.detail" label="客户端路径" :span="2">
            <NText depth="3" style="font-size:12px">{{ clientInfo.detail }}</NText>
          </NDescriptionsItem>
          <NDescriptionsItem
            v-if="auditStats && auditStats.persist_path"
            label="审计日志"
            :span="2"
          >
            <NText depth="3" style="font-size:12px">
              {{ auditStats.persist_path }}（累计 {{ auditStats.total }} 条）
            </NText>
          </NDescriptionsItem>
        </NDescriptions>

        <!-- 配额消耗统计：Let's Encrypt 每周 5 次的限制是用户
             最容易踩到的坑，把已消耗次数摆出来让他心里有数。 -->
        <NAlert
          v-if="auditStats && auditStats.issued > 0"
          type="info"
          size="small"
          style="margin-top:12px"
        >
          本次运行已向 CA 发起 <strong>{{ auditStats.issued }}</strong> 次签发。
          Let's Encrypt 对同一组域名限制每周 5 次重复签发，请留意剩余额度。
          <template v-if="auditStats.issued_not_applied > 0">
            <br />
            <NText type="warning">
              其中 {{ auditStats.issued_not_applied }} 次证书已获取但配置未生效，
              请检查这些站点的 nginx 配置。
            </NText>
          </template>
        </NAlert>
      </NCard>

      <!-- 能力说明（来自后端 scope_note） -->
      <NAlert
        v-if="capabilities && capabilities.scope_note"
        type="default"
        class="mb"
        title="面板会做什么"
      >
        {{ capabilities.scope_note }}
        <template v-if="capabilities.notes && capabilities.notes.length">
          <ul class="note-list">
            <li v-for="(note, i) in capabilities.notes" :key="i">{{ note }}</li>
          </ul>
        </template>
      </NAlert>

      <!-- 过滤 -->
      <NCard size="small" class="mb">
        <NSpace align="center" :size="12">
          <NInput
            v-model:value="keyword"
            placeholder="搜索站点名或域名"
            clearable
            style="width: 260px"
          />
          <NSpace :size="4">
            <NButton
              v-for="opt in STATUS_OPTIONS"
              :key="opt.value"
              size="small"
              :type="statusFilter === opt.value ? 'primary' : 'default'"
              :ghost="statusFilter !== opt.value"
              @click="statusFilter = opt.value"
            >
              {{ opt.label }}
            </NButton>
          </NSpace>
          <NText depth="3" style="font-size:12px">
            共 {{ filteredSites.length }} 个站点
          </NText>
        </NSpace>
      </NCard>

      <!-- 主表格 -->
      <NCard size="small">
        <NDataTable
          :columns="columns"
          :data="filteredSites"
          :loading="loading"
          :row-props="rowProps"
          :row-key="(row) => row.site"
          :bordered="false"
          size="small"
          :max-height="560"
          :scroll-x="900"
        />
        <NText
          v-if="!loading && filteredSites.length === 0"
          depth="3"
          style="display:block;text-align:center;padding:24px 0"
        >
          <template v-if="sites.length === 0">
            还没有站点。请先到「网站管理」创建站点。
          </template>
          <template v-else>
            没有符合条件的站点。
          </template>
        </NText>
      </NCard>
    </div>
  </AppLayout>
</template>

<style scoped>
.ssl-view {
  max-width: 1200px;
}
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
}
.page-title {
  margin: 0 0 4px;
  font-size: 20px;
  font-weight: 600;
}
.page-desc {
  margin: 0;
  color: #666;
  font-size: 13px;
  line-height: 1.6;
}
.mb {
  margin-bottom: 16px;
}
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.note-list {
  margin: 8px 0 0;
  padding-left: 20px;
  line-height: 1.8;
}
</style>
