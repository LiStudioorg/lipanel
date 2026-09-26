<script setup>
// 服务管理页（阶段四 4.1）。
//
// 内置基础页面（不是插件）：systemd 服务是面板的核心能力，
// 依赖插件机制反而会让用户在插件未启动时无法管理服务。
//
// 交互约定（与工程约束一致）：
//   - 所有请求都有 Loading，且在 finally 中复位
//   - 失败必须可见（message 弹出 + 页面内 alert 兜底）
//   - 启停/重启是有副作用的操作，一律走二次确认，且**弹窗里写明服务名**，
//     防止用户点错行却按下了确认
//   - 操作后自动刷新状态；**失败也刷新**（systemd 可能已部分生效）
import { computed, h, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NSpace, NTag, NText } from 'naive-ui'
import { ApiError } from '@/api/client'
import { authStore } from '@/stores/auth'
import { fetchServices, serviceAction } from '@/api/services'
import {
  ACTION_TEXT,
  actionDisabled,
  filterServices,
  stateMeta,
  unitFileLabel,
} from '@/views/servicesLogic'
import AppLayout from '@/layouts/AppLayout.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

const loading = ref(false)
const error = ref('')
const services = ref([])
const total = ref(0)
const running = ref(0)
const available = ref(true)
const unavailableReason = ref('')
const permissions = ref([])
// auditStats 仅用于在页面上显示「操作是否在留痕」，属于锦上添花的信息。
const auditStats = ref(null)

// busy 记录每个服务正在执行的操作，用于**按钮级** Loading。
// 用对象而不是单个布尔量：操作 A 服务时不该让 B 服务的按钮也转圈。
const busy = ref({})

// 搜索关键字：服务数量常见上百个（实测本机 182 个），
// 没有过滤的话用户只能在长列表里翻找。
const keyword = ref('')
// 只看运行中：运维最常用的视图切换。
const onlyRunning = ref(false)

function isBusy(name) {
  return Boolean(busy.value[name])
}

function setBusy(name, value) {
  busy.value = { ...busy.value, [name]: value }
}

// canWrite 表示当前用户是否被授予 service.write。
//
// 注意：这只是**体验优化**（无权限时按钮置灰），真正的强制点在后端
// （service.CheckServicePermission）。前端标记被篡改也不会获得任何权限。
const canWrite = computed(() => permissions.value.includes('service.write'))

// filteredServices 是本页真正渲染的数据：先按状态过滤，再按关键字匹配。
//
// 过滤逻辑抽在 @/views/servicesLogic，由 node:test 覆盖
// （组件本身依赖 Vue/Naive UI，在本仓库的前端测试环境里无法直接 import）。
const filteredServices = computed(() =>
  filterServices(services.value, {
    keyword: keyword.value,
    onlyRunning: onlyRunning.value,
  }),
)

async function load({ silent = false } = {}) {
  // silent 用于操作后的刷新：不显示整页 Loading，避免列表闪烁。
  if (!silent) loading.value = true
  error.value = ''
  try {
    const data = await fetchServices()
    services.value = data.services || []
    total.value = data.total ?? services.value.length
    running.value = data.running ?? 0
    available.value = data.available !== false
    unavailableReason.value = data.unavailable_reason || ''
    permissions.value = data.permissions || []
    auditStats.value = data.audit || null
  } catch (err) {
    if (err instanceof ApiError && err.isUnauthorized) {
      authStore.clear()
      message.warning('登录已过期，请重新登录')
      await router.replace({ name: 'login', query: { redirect: '/services' } })
      return
    }
    error.value = err?.messageWithHint || err?.message || '未知错误'
    // 操作后的静默刷新失败时不覆盖已有列表：
    // 网络抖动一下就把整个列表清空，比不刷新更糟。
    if (!silent) {
      services.value = []
    }
  } finally {
    if (!silent) loading.value = false
  }
}

onMounted(() => {
  load()
})

// 状态展示、按钮禁用等判定全部来自 servicesLogic（同一份实现被测试覆盖）。
// 组件里不再重复定义，避免"组件改了、测试测的还是旧逻辑"。

// runAction 是三个操作的统一实现。
//
// 流程：置 busy → 调接口 → 提示结果 → **无论成败都刷新** → 复位 busy。
// 失败也刷新是刻意的：systemctl 返回非 0 时服务状态仍可能已经改变
// （例如启动超时但进程已拉起），不刷新会让界面显示一个过期的状态。
async function runAction(svc, action) {
  const meta = ACTION_TEXT[action]
  setBusy(svc.name, true)
  try {
    const updated = await serviceAction(svc.name, action)
    message.success(`${meta.verb}成功：${svc.name}（当前状态：${stateMeta(updated?.state).text}）`)
    await load({ silent: true })
  } catch (err) {
    // hint 是后端给出的「怎么办」：权限不足提示要用 root 运行、
    // 服务不存在提示去核对服务名。不带 hint 的话用户只知道失败了。
    const detail = err?.messageWithHint || err?.message || '未知错误'
    message.error(`${meta.verb}失败：${detail}`, { duration: 8000 })
    error.value = `${meta.verb}「${svc.name}」失败：${detail}`
    await load({ silent: true })
  } finally {
    setBusy(svc.name, false)
  }
}

// confirmAction 弹出二次确认。
//
// 防误操作的两个要点：
//   1. 弹窗**必须写明服务名**——用户点错行时能立刻发现；
//   2. 用 warning/dialog 而不是悄悄执行——启停服务是有实际影响的运维动作。
function confirmAction(svc, action) {
  const meta = ACTION_TEXT[action]
  const content =
    action === 'stop'
      ? `即将停止服务 ${svc.name}。停止后依赖它的业务会中断，确定继续吗？`
      : `即将${meta.verb}服务 ${svc.name}，确定继续吗？`

  dialog.warning({
    title: `确认${meta.verb}服务`,
    content,
    positiveText: `确认${meta.verb}`,
    negativeText: '取消',
    onPositiveClick: () => runAction(svc, action),
  })
}

// 表格列定义。
//
// 用 render 函数而不是模板里的 slot：Naive UI 的 data-table 列定义
// 需要函数式渲染，写在这里比在模板里堆 #name="{ row }" 更集中、更好读。
const columns = computed(() => [
  {
    title: '服务名',
    key: 'name',
    minWidth: 200,
    render(row) {
      return h(NText, { strong: true }, { default: () => row.name })
    },
  },
  {
    title: '状态',
    key: 'state',
    width: 96,
    render(row) {
      const meta = stateMeta(row.state)
      return h(
        NTag,
        { type: meta.type, size: 'small', bordered: false },
        { default: () => meta.text },
      )
    },
  },
  {
    title: '子状态',
    key: 'sub_state',
    width: 100,
    render(row) {
      // 子状态能区分「同为运行中，但一个是 running 一个是 exited」，
      // 对排查 oneshot 类服务很有用，因此单列展示而不是塞进描述里。
      return h(NText, { depth: 3, style: 'font-size: 12px' }, { default: () => row.sub_state || '-' })
    },
  },
  {
    title: '开机自启',
    key: 'unit_file_state',
    width: 110,
    render(row) {
      return h(NText, { depth: 3, style: 'font-size: 12px' }, { default: () => unitFileLabel(row.unit_file_state) })
    },
  },
  {
    title: '描述',
    key: 'description',
    minWidth: 220,
    // ellipsis 让超长描述不撑破表格；tooltip 保留完整内容。
    ellipsis: { tooltip: true },
    render(row) {
      return row.description || '-'
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    render(row) {
      const busyNow = isBusy(row.name)
      return h(NSpace, { size: 4 }, {
        default: () =>
          ['start', 'stop', 'restart'].map((action) => {
            const meta = ACTION_TEXT[action]
            return h(
              NButton,
              {
                size: 'small',
                type: meta.type,
                tertiary: true,
                // 禁用条件（systemd 不可用 / 无写权限 / 操作无意义）
                // 由 actionDisabled 统一判定，与测试覆盖的是同一份实现。
                disabled: actionDisabled({
                  available: available.value,
                  canWrite: canWrite.value,
                  action,
                  state: row.state,
                }),
                loading: busyNow,
                onClick: () => confirmAction(row, action),
              },
              { default: () => meta.label },
            )
          }),
      })
    },
  },
])

// 打开服务操作审计页不需要单独页面：这里只提供跳转提示，
// 完整审计视图由后续（若需要）单独做，避免本阶段范围扩大。
</script>

<template>
  <AppLayout>
    <n-space vertical :size="16">
      <n-h2 style="margin: 0">服务管理</n-h2>

      <!-- systemd 不可用：常驻提示 + 原因，而不是一个红色错误框 -->
      <n-alert v-if="!available" type="warning" title="系统未提供 systemd">
        {{ unavailableReason }}
      </n-alert>

      <n-alert v-if="error" type="error" closable @close="error = ''">
        {{ error }}
      </n-alert>

      <n-card>
        <n-space align="center" justify="space-between" :size="12" style="margin-bottom: 12px">
          <n-space align="center" :size="12">
            <n-input
              v-model:value="keyword"
              placeholder="按服务名或描述搜索"
              clearable
              style="width: 260px"
            />
            <n-checkbox v-model:checked="onlyRunning">只看运行中</n-checkbox>
          </n-space>

          <n-space align="center" :size="12">
            <n-text depth="3">
              共 {{ total }} 个服务，运行中
              <n-text strong type="success">{{ running }}</n-text>
              个<span v-if="filteredServices.length !== total">
                （当前显示 {{ filteredServices.length }} 个）</span
              >
            </n-text>
            <n-button size="small" :loading="loading" @click="load()">刷新</n-button>
          </n-space>
        </n-space>

        <!-- 权限不足时明确说明，避免用户对着置灰的按钮猜原因 -->
        <n-alert v-if="available && !canWrite" type="info" :bordered="false" style="margin-bottom: 12px">
          当前账号未被授予 <code>service.write</code> 权限，只能查看服务状态，无法启停。
        </n-alert>

        <n-data-table
          :columns="columns"
          :data="filteredServices"
          :loading="loading"
          :row-key="(row) => row.name"
          :bordered="false"
          :single-line="false"
          size="small"
          :max-height="560"
          virtual-scroll
        />

        <n-empty
          v-if="!loading && filteredServices.length === 0"
          :description="
            services.length === 0
              ? available
                ? '没有可管理的服务'
                : '服务管理不可用'
              : '没有匹配的服务'
          "
          style="margin-top: 24px"
        />
      </n-card>

      <n-text depth="3" style="font-size: 12px">
        说明：列表已过滤 systemd 内部服务。所有启停操作都会记入审计
        <template v-if="auditStats">
          （本次运行已记录 {{ auditStats.total }} 条，其中失败
          {{ auditStats.failed }} 条、被拒 {{ auditStats.denied }} 条）
        </template>
        。
      </n-text>
    </n-space>
  </AppLayout>
</template>
