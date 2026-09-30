<script setup>
// Web 终端页（阶段五 5.1，核心自带）。
//
// ########## 这一页与本项目其它页面的根本区别 ##########
//
// 其它页面是"表单 → 请求 → 表格刷新"，而这一页是一个
// **双向字节流**：用户的每一次按键要立刻送到服务器的 shell，
// shell 的每一段输出要立刻渲染出来。因此它不能用常规的
// "Loading + 数据 + 错误" 三段式来组织，而是围绕
// **一个长连接的生命周期**来组织。
//
// 页面结构对应三段：
//
//	① 能力探测（挂载时一次）—— supported=false 时整个页面变成说明页
//	② 会话管理（按需）      —— 新建/关闭，走 REST
//	③ 终端连接（核心）      —— WebSocket + xterm.js
//
// ########## 关于"优雅降级" ##########
//
// Windows 等没有 PTY 的平台上，后端会明确返回 supported=false。
// 此时页面展示 n-alert 说明并**隐藏新建按钮**，
// 而不是让用户点进去看一个连接失败的红框——
// 后者会让用户以为面板坏了，而真相是"这个功能在你的系统上
// 本来就不存在，但其它功能都正常"。
import { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { FitAddon } from '@xterm/addon-fit'
import { useMessage, useDialog } from 'naive-ui'

import {
  getTerminalStatus,
  createTerminalSession,
  closeTerminalSession,
} from '@/api/terminal'
import {
  buildWSUrl,
  clampSize,
  sizeChanged,
  encodeInput,
  encodeResize,
  encodePing,
  connType,
  connLabel,
  canReconnect,
  reconnectDelay,
  shouldRetryReconnect,
  describeTerminalError,
  statusLabel,
  closeReasonLabel,
  isUnsupported,
  CONN_IDLE,
  CONN_CONNECTING,
  CONN_OPEN,
  CONN_CLOSED,
  CONN_ERROR,
  PING_INTERVAL_MS,
  RECONNECT_MAX_ATTEMPTS,
} from '@/views/terminalLogic'

const message = useMessage()
const dialog = useDialog()

// ---------- 能力探测 ----------

const loading = ref(true)
// capability 是后端的能力快照。supported=false 时页面变成说明页。
const capability = ref({ supported: true, os: '', reason: '', hint: '' })
const shellName = ref('')
const idleTimeout = ref('')
const sessionsInfo = ref({ total: 0, running: 0, max: 0 })

// ---------- 会话 ----------

const creating = ref(false)
// session 是当前正在使用的会话（同一时刻只持有一个：
// 服务端强制"一个会话只能被一个客户端连接"，多标签没有意义
// ——它们会互相抢同一个 shell）。
const session = ref(null)

// ---------- 连接 ----------

const connState = ref(CONN_IDLE)
const connError = ref(null)
// reconnectAttempt 是当前已尝试的重连次数。
const reconnectAttempt = ref(0)

const termEl = ref(null)

// 非响应式的内部句柄：它们不需要触发渲染，
// 放进 ref 反而会因为 Proxy 包装而让 xterm 内部状态出问题。
let term = null
let fitAddon = null
let ws = null
let pingTimer = null
let reconnectTimer = null
let resizeObserver = null
let lastSize = null
// disposed 标记组件已卸载，防止异步回调在卸载后继续操作 DOM。
let disposed = false

const supported = computed(() => capability.value.supported !== false)
const connStatusType = computed(() => connType(connState.value))
const connStatusLabel = computed(() => connLabel(connState.value))
const canReconnectNow = computed(() => canReconnect(connState.value))

// capabilityAlert 把后端的能力说明整理成 n-alert 需要的形状。
//
// 统一走 describeTerminalError，让"挂载时探测到不支持"与
// "操作过程中收到 501"两条路径**展示完全一致**的文案——
// 否则同一种情况会因为入口不同而出现两种说法。
const capabilityAlert = computed(() => {
  if (supported.value) return null
  return describeTerminalError(null, {
    supported: false,
    error: capability.value.reason,
    reason: capability.value.reason,
    hint: capability.value.hint,
  })
})

// ---------- 生命周期 ----------

onMounted(async () => {
  await loadStatus()
  loading.value = false
})

onBeforeUnmount(() => {
  disposed = true
  teardownTerminal()
})

// ---------- 能力探测 ----------

async function loadStatus() {
  try {
    const data = await getTerminalStatus()
    capability.value = {
      supported: data.supported !== false,
      os: data.os || '',
      reason: data.reason || '',
      hint: data.hint || '',
    }
    shellName.value = data.shell || ''
    idleTimeout.value = data.idle_timeout || ''
    if (data.sessions) sessionsInfo.value = data.sessions
  } catch (err) {
    // 探测失败不等于"不支持"——可能只是网络问题。
    // 因此这里不把 supported 置为 false，而是让用户看到错误
    // 并且仍能看到"新建终端"按钮（点下去会得到更具体的错误）。
    const info = describeTerminalError(err, err.payload)
    connError.value = info
    if (isUnsupported(err.status, err.payload)) {
      capability.value = { supported: false, os: '', reason: info.detail, hint: info.hint }
    }
  }
}

// ---------- 新建 / 关闭 ----------

async function handleCreate() {
  if (creating.value) return

  // 二次确认：这是一个**全权限 shell**，不是只读页面。
  // 与其它模块的危险操作一样，弹窗要写明后果。
  dialog.warning({
    title: '新建终端',
    content:
      `将在这台服务器上启动一个 shell（${shellName.value || '系统默认'}）。` +
      '终端拥有与面板进程相同的权限，可执行任意命令，' +
      '包括修改系统文件、安装软件、调整防火墙。请确认这是你的本意。',
    positiveText: '创建',
    negativeText: '取消',
    onPositiveClick: () => createSession(),
  })
}

async function createSession() {
  creating.value = true
  try {
    // 用终端的当前尺寸创建，避免创建后再 resize（会闪一下）。
    const size = currentTermSize()
    const data = await createTerminalSession(size)
    session.value = data.session

    message.success('终端已创建')
    await nextTick()
    await mountTerminal(data.session)
  } catch (err) {
    const info = describeTerminalError(err, err.payload)
    // 平台不支持时把整页切到说明状态（而不是只弹一条消息）。
    if (isUnsupported(err.status, err.payload)) {
      capability.value = { supported: false, os: '', reason: info.detail, hint: info.hint }
    }
    message.error(info.title + (info.detail ? `：${info.detail}` : ''))
  } finally {
    creating.value = false
  }
}

// handleClose 关闭当前会话。
//
// ########## 为什么必须二次确认且写明会话 ID ##########
//
// 会话里可能正跑着长任务（apt install、rsync、一个正在编译的进程）。
// 关闭它会连同那些任务一起终止（PTY 关闭 → SIGHUP → 前台进程组）。
// 弹窗写明会话 ID 是为了让用户能把"我要关的那个"与
// "正在跑东西的那个"对上号——他可能开着多个标签页。
function handleClose() {
  if (!session.value) return
  const id = session.value.id

  dialog.warning({
    title: '关闭终端',
    content:
      `将关闭会话 ${id.slice(0, 8)}… 并终止其中的 shell。` +
      '如果里面正在运行命令（安装、传输、编译），它们会被一并终止。',
    positiveText: '关闭',
    negativeText: '取消',
    onPositiveClick: () => closeSession(),
  })
}

async function closeSession() {
  if (!session.value) return
  const id = session.value.id
  try {
    await closeTerminalSession(id)
    message.success('终端已关闭')
  } catch (err) {
    const info = describeTerminalError(err, err.payload)
    message.error(info.title + (info.detail ? `：${info.detail}` : ''))
  } finally {
    // 无论服务端是否成功，本地都要拆掉连接与视图——
    // 否则用户会看到一个"已经点了关闭但还连着"的界面。
    teardownTerminal()
    session.value = null
    connState.value = CONN_CLOSED
  }
}

// ---------- 终端挂载 ----------

// mountTerminal 创建 xterm 实例并连接 WebSocket。
async function mountTerminal(sess) {
  if (!termEl.value) return

  teardownTerminal()

  term = new Terminal({
    // 光标闪烁：默认开启，但**失焦时停止**（见 setFocusHandler）。
    cursorBlink: true,
    cursorStyle: 'block',
    // 字号与行高：13px 是终端场景下兼顾密度与可读性的常见取值。
    fontSize: 13,
    lineHeight: 1.2,
    fontFamily:
      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
    // 回滚缓冲：1000 行足够回看，再多会显著增加内存占用
    // （每行都会在 DOM 里渲染，这是 xterm 的渲染模型决定的）。
    scrollback: 1000,
    theme: {
      background: '#1e1e1e',
      foreground: '#d4d4d4',
      cursor: '#ffffff',
    },
  })
  fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(termEl.value)

  // 初始 fit + 连接。顺序很重要：先 fit 拿到真实尺寸，
  // 再把尺寸告诉服务端，这样 shell 的第一屏输出就是对的
  // （否则会先按 80x24 输出再来一次重排，用户看到闪一下）。
  fit()
  connect(sess)

  // 用户输入 → 送到服务端。
  term.onData((data) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(encodeInput(data))
    }
  })

  // 窗口尺寸变化 → fit + 通知服务端。
  //
  // ############ 为什么用 ResizeObserver 而不是 window.resize ############
  //
  // 终端的可用空间取决于**容器的尺寸**，而容器可能因为
  // 侧边栏折叠、消息条出现等原因变化——那些都不会触发
  // window 的 resize 事件。ResizeObserver 观察的是元素本身，
  // 因此能覆盖全部情况。
  if (typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(() => {
      // 下一帧再 fit：ResizeObserver 回调时元素尺寸可能尚未最终确定。
      window.requestAnimationFrame(() => fit())
    })
    resizeObserver.observe(termEl.value)
  }

  term.focus()
}

// fit 重新计算终端尺寸并同步给服务端。
function fit() {
  if (!term || !fitAddon) return
  try {
    fitAddon.fit()
  } catch {
    // 容器被隐藏（display:none）时 fit 会抛错，忽略即可：
    // 尺寸没变，也没有需要同步的东西。
    return
  }

  const next = clampSize(term.cols, term.rows)
  // 去重：拖动窗口会高频触发 resize，不去重会灌爆服务端
  // （每条都会触发 PTY 的 SIGWINCH，让全屏程序疯狂重绘）。
  if (!sizeChanged(lastSize, next)) return
  lastSize = next

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(encodeResize(next.cols, next.rows))
  }
}

// currentTermSize 返回当前终端尺寸（未挂载时用默认值）。
function currentTermSize() {
  if (term) {
    const size = clampSize(term.cols, term.rows)
    return { cols: size.cols, rows: size.rows }
  }
  return clampSize(80, 24)
}

// ---------- WebSocket ----------

function connect(sess) {
  connError.value = null
  connState.value = CONN_CONNECTING

  let url
  try {
    url = buildWSUrl(sess.id, window.location)
  } catch (err) {
    connState.value = CONN_ERROR
    connError.value = describeTerminalError(err, null)
    return
  }

  let socket
  try {
    socket = new WebSocket(url)
  } catch (err) {
    connState.value = CONN_ERROR
    connError.value = describeTerminalError(err, null)
    return
  }
  ws = socket

  socket.onopen = () => {
    if (disposed) return
    connState.value = CONN_OPEN
    reconnectAttempt.value = 0
    // 连上后立刻同步一次尺寸：创建时的尺寸可能与现在不同
    // （用户在"新建"确认弹窗期间调整了窗口）。
    const size = currentTermSize()
    lastSize = size
    socket.send(encodeResize(size.cols, size.rows))
    startPing()
  }

  socket.onmessage = (event) => {
    if (disposed || !term) return
    // 输出是**裸字节**（见后端 protocol.go 的设计说明：
    // 热路径不做 JSON 包装），直接写给 xterm。
    term.write(event.data)
  }

  socket.onerror = () => {
    if (disposed) return
    // onerror 不带任何细节（浏览器出于安全考虑不暴露），
    // 真正的信息在 onclose 里。这里只标记状态。
    if (connState.value === CONN_CONNECTING) {
      connState.value = CONN_ERROR
    }
  }

  socket.onclose = (event) => {
    if (disposed) return
    stopPing()

    // ########## 关闭码的语义 ##########
    //
    // 1000/1001 是"正常关闭"——服务端有意断开（用户点了关闭、
    // shell 退出了、面板关停了）。这些**不应该自动重连**：
    // 会话已经不存在了，重连只会一直失败。
    //
    // 其它码（1006 异常断开、1008 策略违规等）才考虑重连。
    const normalClose = event.code === 1000 || event.code === 1001
    connState.value = normalClose ? CONN_CLOSED : CONN_ERROR

    if (!normalClose) {
      connError.value = {
        level: 'error',
        title: '终端连接已断开',
        detail: event.reason || `连接异常关闭（代码 ${event.code}）`,
        hint: '可能是网络中断或面板重启。可点击"重连"恢复；' +
          '若反复失败，请新建一个终端。',
      }
      scheduleReconnect(sess)
    } else if (event.reason) {
      connState.value = CONN_CLOSED
      connError.value = {
        level: 'warning',
        title: '终端会话已结束',
        detail: closeReasonLabel(event.reason) || event.reason,
        hint: '会话结束后不能恢复（shell 进程已经不存在）。' +
          '请新建一个终端继续操作。',
      }
    }
  }
}

// ---------- 心跳 ----------

// startPing 启动应用层心跳。
//
// 作用见 terminalLogic.js 的 encodePing 注释：刷新服务端的空闲计时器，
// 让"盯着静止输出"的用户不会被误判为空闲而断开。
function startPing() {
  stopPing()
  pingTimer = window.setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(encodePing())
    }
  }, PING_INTERVAL_MS)
}

function stopPing() {
  if (pingTimer) {
    window.clearInterval(pingTimer)
    pingTimer = null
  }
}

// ---------- 重连 ----------

// scheduleReconnect 安排一次自动重连（指数退避，有限次数）。
function scheduleReconnect(sess) {
  if (disposed) return
  if (!shouldRetryReconnect(reconnectAttempt.value + 1)) {
    connError.value = {
      level: 'error',
      title: '重连失败',
      detail: `已尝试 ${RECONNECT_MAX_ATTEMPTS} 次仍未成功。`,
      hint: '会话可能已经结束。请新建一个终端；' +
        '若仍失败，请检查面板是否在运行。',
    }
    connState.value = CONN_ERROR
    return
  }

  reconnectAttempt.value += 1
  const delay = reconnectDelay(reconnectAttempt.value)
  message.info(`连接断开，${Math.round(delay / 1000)} 秒后重试…`)

  reconnectTimer = window.setTimeout(() => {
    if (disposed || !session.value) return
    connect(sess)
  }, delay)
}

// handleReconnect 用户手动重连。
function handleReconnect() {
  if (!session.value) {
    message.warning('没有可重连的会话，请先新建终端')
    return
  }
  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  reconnectAttempt.value = 0
  connect(session.value)
}

// ---------- 清理 ----------

// teardownTerminal 释放终端相关的全部资源。
//
// ########## 必须清理的东西，一个都不能漏 ##########
//
//	ws            —— 不关会泄漏一条长连接（服务端也会保留会话）
//	pingTimer     —— 不关会持续向一个已关闭的 ws 发消息
//	reconnectTimer—— 不关会在组件卸载后重连，产生幽灵连接
//	resizeObserver—— 不关会持续观察一个已卸载的 DOM 节点
//	term.dispose()—— 释放 xterm 的 DOM 与事件监听
//
// 这些泄漏在单页应用里很隐蔽：用户来回切页面几次，
// 就会积累一堆僵尸 WebSocket 与后台定时器。
function teardownTerminal() {
  stopPing()

  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  if (ws) {
    // 先摘掉回调再关：否则 close 事件会触发重连逻辑，
    // 而我们要的是**彻底结束**（用户主动关闭/组件卸载）。
    ws.onopen = null
    ws.onmessage = null
    ws.onerror = null
    ws.onclose = null
    try {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
    } catch {
      // 关闭失败无需处理（连接可能已经没了）。
    }
    ws = null
  }
  if (term) {
    term.dispose()
    term = null
  }
  fitAddon = null
  lastSize = null
}

// 会话变化时重建终端。
watch(session, (next) => {
  if (!next) {
    teardownTerminal()
    connState.value = CONN_IDLE
    connError.value = null
  }
})
</script>

<template>
  <div class="terminal-page">
    <!-- ########## 平台不支持：整页降级为说明页 ########## -->
    <!--
      这是 5.1 优雅降级的落点：Windows 等没有 PTY 的平台上，
      用户看到的是**解释**而不是一个失败的红框。
      同时隐藏"新建终端"按钮——让用户点一个必然失败的按钮是最糟的设计。
    -->
    <n-alert v-if="!loading && !supported" type="warning" title="当前系统不支持 Web 终端" class="mb">
      <!--
        不能同时写裸插值 {{ }} 和具名 #default 插槽：
        Vue 编译器会报 "Extraneous children found when component
        already has explicitly named default slot"（本页真的撞到过）。
        内容全部放进 #default 里。
      -->
      <div class="alert-body">
        <p>{{ capabilityAlert?.detail }}</p>
        <p class="hint">{{ capabilityAlert?.hint }}</p>
      </div>
    </n-alert>

    <!-- 顶部状态栏 -->
    <n-card size="small" class="mb">
      <div class="toolbar">
        <div class="toolbar-left">
          <n-tag :type="connStatusType" size="small" round>
            {{ connStatusLabel }}
          </n-tag>
          <n-tag v-if="session" size="small" :bordered="false">
            会话 {{ session.id.slice(0, 8) }}… · {{ statusLabel(session.status) }}
          </n-tag>
          <n-text v-if="shellName" depth="3" class="meta">{{ shellName }}</n-text>
          <n-text v-if="idleTimeout" depth="3" class="meta">空闲超时 {{ idleTimeout }}</n-text>
          <n-text v-if="supported" depth="3" class="meta">
            会话 {{ sessionsInfo.total }}/{{ sessionsInfo.max }}
          </n-text>
        </div>

        <div class="toolbar-right">
          <n-button
            v-if="supported"
            type="primary"
            size="small"
            :loading="creating"
            :disabled="!!session && connState === CONN_OPEN"
            @click="handleCreate"
          >
            新建终端
          </n-button>
          <n-button
            size="small"
            :disabled="!canReconnectNow || !session"
            @click="handleReconnect"
          >
            重连
          </n-button>
          <n-button size="small" :disabled="!session" @click="handleClose">
            断开
          </n-button>
        </div>
      </div>
    </n-card>

    <!-- 连接错误提示 -->
    <n-alert
      v-if="connError"
      :type="connError.level === 'warning' ? 'warning' : 'error'"
      :title="connError.title"
      closable
      class="mb"
      @close="connError = null"
    >
      <div class="alert-body">
        <p>{{ connError.detail }}</p>
        <p v-if="connError.hint" class="hint">{{ connError.hint }}</p>
      </div>
    </n-alert>

    <!-- 终端容器 -->
    <n-card size="small" :content-style="{ padding: '0' }">
      <div class="term-wrap">
        <!--
          xterm 挂载点。**不能**用 v-if 控制它的显隐：
          xterm 需要真实的 DOM 尺寸来计算行列数，
          若元素在 fit 时还不存在（或 display:none），
          fit 会失败或算出错误的尺寸。
        -->
        <div ref="termEl" class="term"></div>

        <!-- 空状态：没有会话时覆盖在终端区上 -->
        <div v-if="!session" class="empty">
          <n-empty :description="supported ? '尚未创建终端' : '当前系统不支持 Web 终端'">
            <template v-if="supported" #extra>
              <n-button size="small" type="primary" :loading="creating" @click="handleCreate">
                新建终端
              </n-button>
            </template>
          </n-empty>
        </div>
      </div>
    </n-card>
  </div>
</template>

<style scoped>
.terminal-page {
  display: flex;
  flex-direction: column;
  /* 撑满可用高度，让终端有最大的可视区域。 */
  height: 100%;
}

.mb {
  margin-bottom: 12px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.toolbar-left,
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.meta {
  font-size: 12px;
}

.alert-body p {
  margin: 2px 0;
}

.hint {
  opacity: 0.75;
  font-size: 12px;
}

.term-wrap {
  position: relative;
  /* 终端区域高度：撑满剩余空间并给一个下限，
     保证在小窗口下也至少有十来行可见。 */
  height: calc(100vh - 260px);
  min-height: 320px;
  padding: 8px;
  background: #1e1e1e;
  border-radius: 4px;
  overflow: hidden;
}

.term {
  width: 100%;
  height: 100%;
}

.empty {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #1e1e1e;
}
</style>
