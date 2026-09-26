// 服务管理页的纯逻辑（阶段四 4.1）。
//
// 为什么单独一个模块而不是写在 ServicesView.vue 里：
//
//   1. **可测**。本仓库前端测试用 node:test，没有 DOM（不引入 jsdom，
//      保持「轻量」约束），因此组件本身无法直接 import。
//      把可判定逻辑抽成纯函数，测试就能锁住**真正被使用的代码**——
//      如果测试里重述一遍逻辑，组件改了而测试没改也照样全绿，
//      那种测试是假的。
//
//   2. **可读**。组件专注于视图装配，这些"什么算运行中""按钮该不该禁用"
//      的判定集中在一处，比散落在模板与 render 函数里更好审查。

// STATE_META 把后端的归一化状态映射为展示用的文案与标签类型。
//
// 状态集合由 internal/service 的 normalizeState 定义
// （running/stopped/failed/activating/unknown）。
export const STATE_META = {
  running: { type: 'success', text: '运行中' },
  stopped: { type: 'default', text: '已停止' },
  failed: { type: 'error', text: '失败' },
  activating: { type: 'warning', text: '处理中' },
  unknown: { type: 'default', text: '未知' },
}

// stateMeta 返回状态的展示元数据，未知状态安全回落。
export function stateMeta(state) {
  return STATE_META[state] || STATE_META.unknown
}

// unitFileLabel 把开机自启状态翻译成中文。
//
// 只翻译含义明确的 enabled/disabled；其余取值（static/generated/indirect）
// **原样展示**——把它们强行说成「已禁用」是错的，会误导用户。
export function unitFileLabel(state) {
  if (!state) return '-'
  const map = { enabled: '开机自启', disabled: '未自启' }
  return map[state] || state
}

// filterServices 按关键字与运行状态过滤服务列表。
//
// 纯函数：返回新数组，不修改入参（模板里直接绑定它，若原地修改
// 会破坏 Vue 的响应式比较，导致列表不更新）。
export function filterServices(services, { keyword = '', onlyRunning = false } = {}) {
  let list = services || []
  if (onlyRunning) {
    list = list.filter((s) => s.state === 'running')
  }
  const kw = String(keyword || '').trim().toLowerCase()
  if (kw) {
    list = list.filter(
      (s) =>
        s.name.toLowerCase().includes(kw) ||
        (s.description || '').toLowerCase().includes(kw),
    )
  }
  return list
}

// ACTION_TEXT 定义三个操作的文案与按钮类型。
export const ACTION_TEXT = {
  start: { label: '启动', verb: '启动', type: 'primary' },
  stop: { label: '停止', verb: '停止', type: 'warning' },
  restart: { label: '重启', verb: '重启', type: 'default' },
}

// isPointless 判断某操作对当前状态是否无意义。
//
// 目的：避免展示会误导用户的按钮。对运行中的服务点「启动」，
// systemctl 会返回 0 但什么也没发生，用户会以为操作生效了；
// 反过来对已停止的服务点「停止」同理。
export function isPointless(action, state) {
  return (
    (action === 'start' && state === 'running') ||
    (action === 'stop' && state === 'stopped')
  )
}

// actionDisabled 汇总某行某按钮的禁用条件。
//
// 禁用来源有三：systemd 不可用、无写权限、操作无意义。
// 集中在一处是为了让"为什么这个按钮点不动"只有一个答案来源。
export function actionDisabled({ available, canWrite, action, state }) {
  if (!available) return true
  if (!canWrite) return true
  return isPointless(action, state)
}
