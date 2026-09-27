// 软件商店页的纯逻辑（阶段四 4.5）。
//
// 为什么单独一个模块而不是写在 StoreView.vue 里：
//
//   1. **可测**。本仓库前端测试用 node:test，没有 DOM（不引入 jsdom，
//      保持「轻量」约束），因此组件本身无法直接 import。
//      把可判定逻辑抽成纯函数，测试就能锁住**真正被使用的代码**。
//
//   2. **与后端规则一致**。下面的策略标签、按钮禁用条件、
//      进度分级逐条对应 internal/store 的实现。
//      **但前端校验只是体验优化**——真正的强制点始终在后端。
//
//   3. **一致性风险最高**。这里最容易出错的不是"逻辑写错"，
//      而是**与后端不一致**：把 prebuilt 显示成"官方源安装"、
//      或者把 failed 显示成绿色，用户就会得到与真实情况
//      相反的信息——而这一页的每个动作都可能改动生产环境。

// ---------------------------------------------------------------------------
// 安装策略
// ---------------------------------------------------------------------------

// STRATEGY_META 是安装策略的展示元数据。
//
// 三级的含义与后端完全一致（internal/store 的 StrategySystem 等）：
//
//	system   —— 发行版自带仓库里就有目标版本。**最干净**：
//	            不新增任何第三方仓库，升级由系统统一管理。
//	official —— 追加了软件官方仓库（sury / NodeSource / remi）。
//	            功能最新，但从此这个软件的升级不走发行版了。
//	prebuilt —— 官方预编译包解包到 /usr/local。**不经过包管理器**：
//	            系统里查不到它，升级要手动，但不需要动软件源。
//
// 颜色刻意不用 success/warning 来暗示"好坏"：
// 它们都是**正常**结果，只是权衡不同。用红色标 official
// 会让用户以为出了问题。
export const STRATEGY_META = {
  system: {
    label: '系统源',
    type: 'success',
    desc: '直接使用发行版自带的软件仓库，不新增第三方源，后续由系统统一升级',
  },
  official: {
    label: '官方源',
    type: 'info',
    desc: '已追加软件官方的软件源（如 sury / NodeSource / remi），版本最新',
  },
  prebuilt: {
    label: '预编译包',
    type: 'warning',
    desc: '使用官方预编译包解包到 /usr/local，不经过包管理器，系统里查不到它',
  },
}

// strategyMeta 返回策略元数据，未知策略安全回落。
export function strategyMeta(strategy) {
  return (
    STRATEGY_META[strategy] || {
      label: strategy || '未知',
      type: 'default',
      desc: '未知的安装来源',
    }
  )
}

// ---------------------------------------------------------------------------
// 任务状态
// ---------------------------------------------------------------------------

// TASK_STATUS_META 是任务状态展示元数据。
export const TASK_STATUS_META = {
  pending: { label: '排队中', type: 'default', desc: '任务已创建，等待前一个任务结束' },
  running: { label: '进行中', type: 'info', desc: '正在执行安装/卸载' },
  succeeded: { label: '成功', type: 'success', desc: '任务已成功完成' },
  failed: { label: '失败', type: 'error', desc: '任务失败，原因见日志' },
}

export function taskStatusMeta(status) {
  return (
    TASK_STATUS_META[status] || {
      label: status || '未知',
      type: 'default',
      desc: '',
    }
  )
}

// STEP_STATUS_META 是步骤状态展示元数据。
export const STEP_STATUS_META = {
  pending: { label: '待执行', type: 'default' },
  running: { label: '执行中', type: 'info' },
  succeeded: { label: '成功', type: 'success' },
  failed: { label: '失败', type: 'error' },
  skipped: { label: '跳过', type: 'default' },
}

export function stepStatusMeta(status) {
  return STEP_STATUS_META[status] || { label: status || '未知', type: 'default' }
}

// isTerminal 判断任务是否已结束。
//
// 界面据此停止轮询。**只看 done 字段是不够的**：
// 网络异常时 done 永远等不到，必须同时判断状态。
export function isTerminal(status) {
  return status === 'succeeded' || status === 'failed'
}

// ---------------------------------------------------------------------------
// 软件状态
// ---------------------------------------------------------------------------

// softwareStatusMeta 汇总一个软件的展示状态。
//
// ########## 这里有一个必须区分的真实情况 ##########
//
// 系统里可能装着一个**不在清单里**的版本（发行版自带的 nginx 1.18，
// 而清单提供 1.26/1.24/1.18 之外的组合，或者用户手动 apt 装的）。
// 此时后端返回 installed=true 但 installed_versions 为空，
// 只有 detected_version 有值。
//
// 若界面按 installed_versions 判断，就会显示成"未安装"，
// 用户于是再装一个 —— 两个版本争抢 /usr/bin 下的同名文件。
// 因此这里把 detected_version 单独作为一档状态呈现。
export function softwareStatusMeta(sw) {
  if (!sw) {
    return { key: 'unknown', label: '未知', type: 'default', desc: '' }
  }

  const hasListed = Array.isArray(sw.installed_versions) && sw.installed_versions.length > 0
  const detected = (sw.detected_version || '').trim()

  if (hasListed) {
    return {
      key: 'installed',
      label: '已安装',
      type: 'success',
      desc: `已安装版本：${sw.installed_versions.join(', ')}`,
    }
  }
  if (detected) {
    // 已安装但不在可选列表里 —— 这是**信息**不是错误，
    // 但对用户而言很重要（他不能再装一个）。
    return {
      key: 'detected',
      label: `已安装 ${detected}`,
      type: 'warning',
      desc: `系统里已安装 ${sw.name || sw.id} ${detected}，` +
        '但它不在本页提供的版本列表里（可能是发行版自带或手动安装的）。' +
        '同一软件同时装多个版本会互相覆盖可执行文件与配置，' +
        '因此安装按钮已被禁用；如需更换版本，请先用系统包管理器处理。',
    }
  }
  return {
    key: 'none',
    label: '未安装',
    type: 'default',
    desc: '该软件尚未安装',
  }
}

// canInstall 判断"安装"按钮是否可用。
//
// 返回 { ok, reason }：ok=false 时 reason 说明原因（界面展示用）。
//
// 禁用条件逐条对应后端的拒绝条件，**但不替代后端校验**：
// 前端禁用只是省一次必然失败的请求。
export function canInstall(sw, version, { available, running } = {}) {
  if (!available) {
    return { ok: false, reason: '本机未探测到可用的包管理器（apt-get / dnf / yum），无法安装软件' }
  }
  if (running) {
    return { ok: false, reason: '已有安装/卸载任务正在进行，请等待其结束（同一时刻只允许一个）' }
  }
  if (!sw) {
    return { ok: false, reason: '软件不存在' }
  }
  const meta = softwareStatusMeta(sw)
  if (meta.key === 'installed') {
    return { ok: false, reason: `已经安装（${meta.desc}）` }
  }
  if (meta.key === 'detected') {
    return { ok: false, reason: meta.desc }
  }
  if (!version) {
    return { ok: false, reason: '请选择要安装的版本' }
  }
  // 依赖未就绪不阻止安装：后端会自动补齐依赖（除非用户显式跳过）。
  return { ok: true, reason: '' }
}

// canUninstall 判断"卸载"按钮是否可用。
export function canUninstall(sw, { available, running } = {}) {
  if (!available) {
    return { ok: false, reason: '本机未探测到可用的包管理器，无法卸载' }
  }
  if (running) {
    return { ok: false, reason: '已有安装/卸载任务正在进行，请等待其结束' }
  }
  if (!sw) {
    return { ok: false, reason: '软件不存在' }
  }
  const meta = softwareStatusMeta(sw)
  if (meta.key === 'none') {
    return { ok: false, reason: '该软件未安装，无需卸载' }
  }
  if (meta.key === 'detected') {
    // 能卸载：后端会按"实际已安装的包名"清理，
    // 因此发行版自带的版本也能通过面板卸掉。
    return { ok: true, reason: '' }
  }
  return { ok: true, reason: '' }
}

// ---------------------------------------------------------------------------
// 版本选择
// ---------------------------------------------------------------------------

// defaultVersionOf 返回软件的默认版本 ID。
//
// 后端保证每个软件恰好有一个 default_version，但前端不能假设：
// 清单被改坏、或接口返回了旧版本数据时，这里必须能优雅回落，
// 否则下拉框会显示空白，用户点安装时提交一个空版本。
export function defaultVersionOf(sw) {
  if (!sw) return ''
  if (sw.default_version) {
    const ids = (sw.versions || []).map((v) => v.id)
    if (ids.includes(sw.default_version)) return sw.default_version
  }
  // 回落顺序：显式标记 is_default 的 → 第一个版本 → 空串。
  const marked = (sw.versions || []).find((v) => v.is_default)
  if (marked) return marked.id
  return (sw.versions || [])[0]?.id || ''
}

// versionOptions 生成版本下拉项。
//
// 默认版本**排在最前**而不是按版本号排序：用户十有八九要装默认版本，
// 把它放在列表中间会让每次安装都多一次寻找。
// 已安装的版本会被标记，避免用户对着已装的版本反复点击。
export function versionOptions(sw) {
  if (!sw || !Array.isArray(sw.versions)) return []
  const def = defaultVersionOf(sw)
  const options = sw.versions.map((v) => ({
    value: v.id,
    label: v.label || v.id,
    isDefault: v.id === def,
    installed: Boolean(v.installed),
    installedVersion: v.installed_version || '',
    via: v.via || '',
    notes: v.notes || [],
    officialAvailable: Boolean(v.official_available),
    officialReason: v.official_reason || '',
    prebuiltAvailable: Boolean(v.prebuilt_available),
    prebuiltNotes: v.prebuilt_notes || [],
  }))
  options.sort((a, b) => {
    if (a.isDefault !== b.isDefault) return a.isDefault ? -1 : 1
    // 其余按版本号从新到旧（后端已排好序，这里做一次稳健的兜底）。
    return compareVersions(b.value, a.value)
  })
  return options
}

// compareVersions 按数字段比较版本号（"8.3" > "7.4"）。
//
// 不用字符串比较："8.10" < "8.3" 在字符串序里成立，
// 而这是版本号，用户看到顺序错乱会以为列错了。
export function compareVersions(a, b) {
  const pa = String(a || '').split('.')
  const pb = String(b || '').split('.')
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i += 1) {
    const na = Number.parseInt(pa[i] ?? '0', 10)
    const nb = Number.parseInt(pb[i] ?? '0', 10)
    const va = Number.isFinite(na) ? na : 0
    const vb = Number.isFinite(nb) ? nb : 0
    if (va !== vb) return va - vb
  }
  return 0
}

// ---------------------------------------------------------------------------
// 进度与日志
// ---------------------------------------------------------------------------

// progressStatus 返回进度条的状态类型。
//
// 失败时返回 exception：一个停在 60% 的蓝色进度条看起来像"还在装"，
// 而失败的任务其实已经结束了。
export function progressStatus(task) {
  if (!task) return 'default'
  if (task.status === 'failed') return 'error'
  if (task.status === 'succeeded') return 'success'
  return 'info'
}

// mergeLogs 合并增量日志。
//
// 后端按 seq 递增下发，这里按 seq 去重后追加——
// 若直接 concat，一次重试或游标回退就会让日志出现重复段落，
// 而日志是排查失败的**唯一**依据，重复行会让人怀疑漏看了什么。
export function mergeLogs(existing, incoming) {
  const out = Array.isArray(existing) ? existing.slice() : []
  const seen = new Set(out.map((l) => l.seq))
  for (const line of incoming || []) {
    if (line == null) continue
    if (seen.has(line.seq)) continue
    seen.add(line.seq)
    out.push(line)
  }
  out.sort((a, b) => a.seq - b.seq)
  return out
}

// LOG_LEVEL_META 是日志级别展示元数据。
export const LOG_LEVEL_META = {
  info: { label: '信息', type: 'default' },
  warn: { label: '警告', type: 'warning' },
  error: { label: '错误', type: 'error' },
  command: { label: '命令', type: 'info' },
  stdout: { label: '输出', type: 'default' },
  stderr: { label: '错误输出', type: 'error' },
  step: { label: '步骤', type: 'default' },
}

export function logLevelMeta(level) {
  return LOG_LEVEL_META[level] || { label: level || '信息', type: 'default' }
}

// formatLogLine 把一条日志渲染成单行文本。
export function formatLogLine(line) {
  if (!line) return ''
  const parts = []
  if (line.step) parts.push(`[${line.step}]`)
  parts.push(line.text || '')
  return parts.join(' ')
}

// ---------------------------------------------------------------------------
// 环境展示
// ---------------------------------------------------------------------------

// FAMILY_LABEL 是发行版家族的中文名。
export const FAMILY_LABEL = {
  debian: 'Debian 系',
  rhel: 'RHEL 系',
  unknown: '未知发行版',
}

// PACKAGE_MANAGER_LABEL 是包管理器展示名。
export const PACKAGE_MANAGER_LABEL = {
  apt: 'apt (dpkg)',
  dnf: 'dnf (rpm)',
  yum: 'yum (rpm)',
}

export function environmentText(env) {
  if (!env) return '未知环境'
  const parts = []
  if (env.distro) parts.push(env.distro)
  else if (env.family) parts.push(FAMILY_LABEL[env.family] || env.family)
  if (env.package_manager) {
    parts.push(PACKAGE_MANAGER_LABEL[env.package_manager] || env.package_manager)
  }
  if (env.arch) parts.push(env.arch)
  return parts.length ? parts.join(' · ') : '未知环境'
}

// ---------------------------------------------------------------------------
// 确认对话框文案
// ---------------------------------------------------------------------------

// uninstallConfirmText 生成卸载确认文案。
//
// ########## 为什么必须逐条列出将要发生的事 ##########
//
// 卸载在生产机器上是**破坏性**操作：卸掉 php-fpm 会让站点立刻 502，
// 卸掉 nginx 会让整台机器的 Web 服务消失。
// 一句"确定卸载吗？"把判断责任推给了用户，而他并不知道面板会做什么
// （尤其是"官方源已经写进 /etc/apt"这件事——面板**不会**撤销它）。
export function uninstallConfirmText(sw, version) {
  if (!sw) return '确定要卸载吗？'
  const meta = softwareStatusMeta(sw)
  const lines = [`即将卸载 ${sw.name || sw.id}`]
  if (version) lines.push(`版本：${version}`)
  else if (meta.key === 'installed') lines.push(`版本：${sw.installed_versions.join(', ')}`)
  else if (meta.key === 'detected') lines.push(`版本：${meta.desc}`)

  lines.push('')
  lines.push('将会执行：')
  lines.push('· 用系统包管理器卸载对应的软件包')
  lines.push('· 清理不再被依赖的孤儿包（apt 环境）')
  if (sw.installed_via === 'prebuilt') {
    lines.push('· 删除 /usr/local 下的安装目录与软链接（预编译安装的文件）')
  }
  lines.push('· 卸载后重新校验，确认软件包确实已移除')
  lines.push('')
  lines.push('注意：面板**不会**删除你的网站文件与数据库数据，')
  lines.push('也不会撤销之前追加的第三方软件源。')
  lines.push('依赖该软件的站点或服务会立即停止工作。')
  return lines.join('\n')
}

// installConfirmText 生成安装确认文案。
//
// 安装也要确认：它同样改动系统（新增软件源、以 root 运行 postinst），
// 而这些改动用户看不见。尤其是"会追加第三方源"这一条。
export function installConfirmText(sw, version, { officialAvailable } = {}) {
  if (!sw) return '确定要安装吗？'
  const lines = [`即将安装 ${sw.name || sw.id}${version ? ` ${version}` : ''}`]
  const deps = sw.depends || []
  if (deps.length) {
    lines.push('')
    lines.push(`会自动先安装依赖：${deps.join(', ')}（如已安装则跳过）`)
  }
  lines.push('')
  lines.push('安装顺序（逐级回退，成功即停）：')
  lines.push('1. 系统软件源：若已有目标版本，直接安装（不新增任何源）')
  lines.push('2. 官方源：追加软件官方仓库后安装' +
    (officialAvailable === false ? '（当前环境不可用）' : '（可能写入 /etc/apt 或 /etc/yum.repos.d）'))
  lines.push('3. 预编译包：解包到 /usr/local 并建立软链接（不经过包管理器）')
  lines.push('')
  lines.push('同一时刻只允许一个安装任务；执行过程可在本页查看实时日志。')
  return lines.join('\n')
}
