// 计划任务页的纯逻辑（阶段五 5.2）。
//
// ########## 为什么逻辑要单独一个模块 ##########
//
// 这是本项目第 53 号坑位留下的纪律：前端逻辑若在测试文件里
// **照抄一遍**，组件改了测试也照样全绿——测试锁住的是副本，
// 不是真正运行的代码。
//
// 因此本文件被 CronView.vue 与 cron.logic.test.mjs **共同 import**，
// 测试断言的就是页面实际使用的那份实现。
//
// ########## 与后端的一致性 ##########
//
// 下面这些取值必须与 internal/cron 完全一致，一旦漂移界面就会
// 显示出与真实情况相反的信息（例如把「失败的一次执行」显示成绿色）：
//
//	ACTION_LABEL（permission.go 的 Action）
//	OUTCOME_META（audit.go 的三态）
//	LOG_STATUS_META（logtail.go buildEntry 的四种 status）
//	MAX_COMMAND_BYTES / MAX_COMMENT_BYTES（validate.go 的上限）
//
// 因此测试会逐项断言这些常量。
//
// ########## 本模块刻意**不**实现 cron 表达式解析 ##########
//
// 表达式的校验与「下次执行时间」一律走后端 POST /api/cron/validate。
// 若前端再写一份解析器，就会出现「前端说合法、后端拒绝」或
// 「前端显示的下次执行时间与列表里的不一样」——同一个界面上两个
// 互相矛盾的时间，比不显示更糟，因为用户会相信面板显示的时间。
// 这也是本模块**没有引入任何 JS cron 库**的原因（保持零新增依赖）。

// ---------------------------------------------------------------------------
// 权限（与 internal/cron/permission.go 对齐）
// ---------------------------------------------------------------------------

export const CRON_READ = 'cron.read'
export const CRON_WRITE = 'cron.write'

// canWrite 判断当前用户能否增删改任务。
//
// 只用于**界面体验**（禁用按钮并说明原因）。真正的强制点永远在后端：
// 篡改前端拿到的权限标记不会得到任何额外能力。
export function canWrite(permissions) {
  if (!Array.isArray(permissions)) return false
  return permissions.some((p) => String(p).toLowerCase() === CRON_WRITE)
}

// ---------------------------------------------------------------------------
// 输入上限（与 internal/cron/validate.go 对齐）
// ---------------------------------------------------------------------------

// MAX_COMMAND_BYTES 是命令原文的字节上限。
//
// crontab 单行长度受 LINE_BUFFER 限制（常见 1000 字节），超出后 cron
// 会**静默忽略**该行——「保存成功但永远不执行」是最难排查的故障，
// 所以后端在入口就拒绝，前端只是提前提醒。
export const MAX_COMMAND_BYTES = 900
export const MAX_COMMENT_BYTES = 200
export const MAX_EXPR_BYTES = 200

// byteLength 返回 UTF-8 字节数（不是字符数）。
//
// 用字符数判上限会让「命令里有一串中文」的文件在中文环境下
// 提前几百字节就报满，或者反过来放行一个超限的 ASCII 长命令。
export function byteLength(text) {
  if (text === null || text === undefined) return 0
  return new TextEncoder().encode(String(text)).length
}

// ---------------------------------------------------------------------------
// 表达式示例
// ---------------------------------------------------------------------------

// EXPR_EXAMPLES 是弹窗里一键填入的常用表达式。
//
// 只放**验证过**的写法：示例本身就是这份模块的测试用例之一
// （测试断言每条都是 5 段式或 @ 别名），免得有人加一个
// `0 */2 * * *` 之外的写法却没人核对它的真实语义。
export const EXPR_EXAMPLES = [
  { expr: '* * * * *', label: '每分钟' },
  { expr: '*/5 * * * *', label: '每 5 分钟' },
  { expr: '*/30 * * * *', label: '每 30 分钟' },
  { expr: '0 * * * *', label: '每小时整点' },
  { expr: '30 2 * * *', label: '每天 02:30' },
  { expr: '0 3 * * 0', label: '每周日 03:00' },
  { expr: '0 4 1 * *', label: '每月 1 日 04:00' },
  { expr: '15 2-4 * * 1-5', label: '工作日 02:15-04:15 每小时' },
  { expr: '@daily', label: '@daily（每天 0 点）' },
  { expr: '@hourly', label: '@hourly（每小时）' },
  { expr: '@weekly', label: '@weekly（周日 0 点）' },
  { expr: '@monthly', label: '@monthly（每月 1 日 0 点）' },
  { expr: '@reboot', label: '@reboot（系统启动时）' },
]

// looksLikeExpr 做一个**廉价**的形态检查（段数或 @ 别名）。
//
// 它不是校验器，只用来决定「要不要现在去打后端」：
// 用户刚敲了 "*/" 就发请求毫无意义，还会把输入过程变成一串
// 后端 400。真正的合法性判定永远只有后端那一份。
export function looksLikeExpr(expr) {
  const s = String(expr || '').trim()
  if (!s) return false
  if (s.startsWith('@')) return !s.includes(' ')
  return s.split(/\s+/).length === 5
}

// ---------------------------------------------------------------------------
// 任务列表的展示辅助
// ---------------------------------------------------------------------------

// LOG_STATUS_META 与 internal/cron/logtail.go 的四种 status 对齐。
//
// running 用 warning 而不是 success：它的真实含义是
// 「只看到开始标记，没看到结束标记」——要么还在跑，要么被 kill 了。
// 把它显示成中性/正常会让人以为任务还在正常执行，
// 而实际上它可能三天前就被 OOM killer 干掉了。
export const LOG_STATUS_META = {
  ok: { label: '成功', type: 'success' },
  failed: { label: '失败', type: 'error' },
  running: { label: '未见结束标记', type: 'warning' },
  unknown: { label: '无法判定', type: 'default' },
}

// logStatusMeta 返回日志块的状态元信息（未知值如实回落）。
export function logStatusMeta(status) {
  if (status && LOG_STATUS_META[status]) return LOG_STATUS_META[status]
  return { label: status ? String(status) : '无法判定', type: 'default' }
}

// exitText 返回退出码展示文本。
//
// exit=-1 不是「退出码 -1」，而是「没取到结束标记」，
// 直接显示 -1 会让人以为程序返回了 -1。
export function exitText(entry) {
  if (!entry) return '—'
  if (entry.exit === null || entry.exit === undefined || entry.exit < 0) return '无结束标记'
  return `exit=${entry.exit}`
}

// ACTION_LABEL 与 internal/cron/permission.go 的 Action 对齐。
export const ACTION_LABEL = {
  list: '查看',
  logs: '查看日志',
  create: '新增任务',
  update: '编辑任务',
  delete: '删除任务',
}

// actionLabel 返回操作中文名。
export function actionLabel(action) {
  if (!action) return '—'
  return ACTION_LABEL[action] || String(action)
}

// OUTCOME_META 与 internal/cron/audit.go 的三态对齐（与各核心模块同名同义）。
export const OUTCOME_META = {
  allowed: { label: '成功', type: 'success' },
  denied: { label: '被拒绝', type: 'error' },
  failed: { label: '失败', type: 'warning' },
}

// outcomeMeta 返回审计结果元信息。
export function outcomeMeta(outcome) {
  if (outcome && OUTCOME_META[outcome]) return OUTCOME_META[outcome]
  return { label: outcome ? String(outcome) : '—', type: 'default' }
}

// pad2 零补齐（自己的两位格式化，避免依赖 Date  locale 差异）。
function pad2(n) {
  return String(n).padStart(2, '0')
}

// formatRunTime 把 RFC3339 时间转成「MM-DD HH:mm」的短展示。
//
// 后端给的是带时区偏移的 RFC3339，浏览器会按**本地时区**渲染。
// 解析失败时原样返回：一个显示出来的怪时间比「—」更容易被发现出错。
export function formatRunTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

// formatTimeFull 返回完整可读时间（含年与秒，用于 title 提示）。
export function formatTimeFull(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

// relativeText 返回「n 分钟后」这类相对描述。
//
// 面板上「下次执行时间」真正想回答的是「还有多久」。只给绝对时间，
// 用户得自己在心里做减法；给出相对值才能一眼看出「就在 3 分钟后」。
//
// now 参数**必须由调用方传入**：逻辑里直接调 Date.now() 就没法测
// （跨分钟的用例会在 CI 上随机飘）。
export function relativeText(iso, now) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const base = now instanceof Date ? now.getTime() : Number(now)
  if (!Number.isFinite(base)) return ''
  const diffMin = Math.round((d.getTime() - base) / 60000)
  if (diffMin <= 0) return '即将执行'
  if (diffMin < 60) return `${diffMin} 分钟后`
  if (diffMin < 60 * 24) {
    const h = Math.floor(diffMin / 60)
    const m = diffMin % 60
    return m ? `${h} 小时 ${m} 分后` : `${h} 小时后`
  }
  const days = Math.floor(diffMin / (60 * 24))
  const hours = Math.round((diffMin % (60 * 24)) / 60)
  return hours ? `${days} 天 ${hours} 小时后` : `${days} 天后`
}

// nextRunText 返回一个任务的「下次执行」列文本。
//
// 三种非时间的情形必须区别对待，它们各自意味着完全不同的事：
//
//	@reboot   → 没有日历时间（不是出错）
//	表达式非法 → 这条任务**根本不会被 cron 执行**，必须显眼
//	永不匹配  → 表达式合法但 5 年内无匹配（如 0 0 30 feb）
export function nextRunText(job, now) {
  if (!job) return '—'
  if (job.reboot) return '@reboot：仅系统启动时执行'
  if (job.valid === false) return '表达式非法，不会被执行'
  if (!job.next_run_has || !job.next_run) return '5 年内无匹配时间'
  const rel = relativeText(job.next_run, now)
  return rel ? `${formatRunTime(job.next_run)}（${rel}）` : formatRunTime(job.next_run)
}

// jobTagList 返回一个任务的标记（面板管理 / 外部添加 / 非法 / 缺脚本）。
//
// 「外部添加」必须有独立标记：它说明这条任务不是面板生成的，
// 一旦在面板里编辑就会被「收编」（补标记注释并换成日志包装脚本）。
// 不提前说清楚，用户会以为只是改个时间。
export function jobTagList(job) {
  const tags = []
  if (!job) return tags
  if (job.valid === false) tags.push({ label: '表达式非法', type: 'error' })
  if (job.managed) tags.push({ label: '面板管理', type: 'info' })
  else tags.push({ label: '外部添加', type: 'warning' })
  if (job.command_missing) tags.push({ label: '命令不可读', type: 'error' })
  if (job.reboot) tags.push({ label: '@reboot', type: 'default' })
  return tags
}

// summarizeJobs 汇总列表统计。
export function summarizeJobs(jobs) {
  const list = Array.isArray(jobs) ? jobs : []
  const out = { total: list.length, managed: 0, external: 0, invalid: 0, reboot: 0 }
  for (const j of list) {
    if (!j) continue
    if (j.managed) out.managed += 1
    else out.external += 1
    if (j.valid === false) out.invalid += 1
    if (j.reboot) out.reboot += 1
  }
  return out
}

// filterJobs 按关键词过滤（表达式 / 命令 / 备注 / id）。
//
// 大小写不敏感、空关键词放行全部——过滤只是查找辅助，
// 绝不做「过滤后看不见的任务就不存在」这种危险语义，
// 因此统计数字始终基于全量列表。
export function filterJobs(jobs, { keyword = '' } = {}) {
  const list = Array.isArray(jobs) ? jobs : []
  const kw = String(keyword || '').trim().toLowerCase()
  if (!kw) return list.slice()
  return list.filter((j) => {
    if (!j) return false
    const hay = [j.expression, j.command, j.comment, j.id, j.raw]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    return hay.includes(kw)
  })
}

// expectedIds 构造乐观并发断言用的 id 集合。
//
// 后端拿它核对「你编辑的是不是你看到的那一版」。
// 不传的话面板仍会安全地做行级改写，但可能静默覆盖
// 别人用 crontab -e 加的任务——前端一律带上。
export function expectedIds(jobs) {
  if (!Array.isArray(jobs)) return []
  return jobs.map((j) => j && j.id).filter(Boolean)
}

// ---------------------------------------------------------------------------
// 表单校验（**只有形态检查**，合法性由后端裁决）
// ---------------------------------------------------------------------------

// validateForm 返回表单级错误文本（空串表示可提交）。
//
// 它拦的是两类**后端也会拦**但值得提前说明的问题：
// 空值、超限字节数、明显的段数错误。
// 表达式的具体语义一律不在这里判断（见文件头）。
export function validateForm({ expression = '', command = '', comment = '', status = null } = {}) {
  const expr = String(expression || '').trim()
  if (!expr) return '请填写 cron 表达式'
  if (byteLength(expr) > MAX_EXPR_BYTES) {
    return `表达式超过 ${MAX_EXPR_BYTES} 字节（当前 ${byteLength(expr)} 字节）`
  }
  if (!looksLikeExpr(expr)) {
    return '表达式应为 5 段（分 时 日 月 周）或 @ 别名（如 @daily）'
  }
  if (!String(command || '').trim()) return '请填写要执行的命令'
  const cmdBytes = byteLength(command)
  if (cmdBytes > MAX_COMMAND_BYTES) {
    return `命令超过 ${MAX_COMMAND_BYTES} 字节（当前 ${cmdBytes} 字节）。` +
      '过长的命令会被 cron 静默忽略——请改成调用一个脚本文件。'
  }
  if (/[\r\n]/.test(String(command || ''))) {
    return '命令不能包含换行：那会被 crontab 解析成两条任务。需要多条命令请写成 `cmd1 && cmd2`'
  }
  if (String(command || '').includes('\t')) {
    return '命令不能包含制表符，请改用空格'
  }
  if (byteLength(comment) > MAX_COMMENT_BYTES) {
    return `备注超过 ${MAX_COMMENT_BYTES} 字节（当前 ${byteLength(comment)} 字节）`
  }
  if (/[\r\n]/.test(String(comment || ''))) return '备注不能包含换行'
  if (status && status.available === false) {
    return `当前无法管理 crontab：${status.reason || '原因未知'}`
  }
  if (!canWrite(status?.permissions)) return '当前账号未被授予 cron.write 权限'
  return ''
}

// ---------------------------------------------------------------------------
// 确认文案（弹窗里必须写明**具体会改哪条命令**）
// ---------------------------------------------------------------------------

// commandPreview 返回命令的单行预览（截断但不改写内容）。
export function commandPreview(command, max = 200) {
  const s = String(command || '')
  if (!s) return '（空）'
  // 换行不可能来自后端（校验已拒），这里只处理超长。
  if (s.length <= max) return s
  return `${s.slice(0, max)}…（共 ${s.length} 字符）`
}

// deleteConfirmText 生成删除二次确认的正文。
//
// 计划明确要求「删除二次确认，写明命令」。为什么要把命令原文写进弹窗：
// 一条正在跑的生产定时任务（数据库备份、证书续期）被误删后，
// 后果往往要几天后才被发现，而那时当天的备份已经没有了。
// 只问「确定删除任务 a1b2c3…？」的弹窗等于没问。
export function deleteConfirmText(job) {
  if (!job) return '确定删除该任务吗？'
  const lines = [
    `表达式：${job.expression || '—'}`,
    job.human ? `含义：${job.human}` : '',
    `命令：${commandPreview(job.command)}`,
    job.comment ? `备注：${job.comment}` : '',
    job.managed ? '' : '⚠️ 这条任务是外部添加的（不是面板生成的）。',
  ].filter(Boolean)
  lines.push('')
  lines.push('删除后该任务将不再执行，且此操作不可撤销（面板会保留改动前的备份文件）。')
  return lines.join('\n')
}

// saveConfirmText 生成保存（新增/编辑）的确认正文。
//
// preview 是后端 /api/cron/validate 的结果：把**真实会执行的时间**
// 摆进确认框，用户才有机会发现「我写的 0 3 * * 0 是周日不是月初」。
export function saveConfirmText({ job = null, expression = '', command = '', preview = null, adopt = false }) {
  const lines = [
    `表达式：${expression || job?.expression || '—'}`,
    preview?.human ? `含义：${preview.human}` : job?.human ? `含义：${job.human}` : '',
    preview?.expression && preview.expression !== expression
      ? `实际写入：${preview.expression}（@ 别名会展开成 5 段式）`
      : '',
    `命令：${commandPreview(command || job?.command)}`,
  ].filter(Boolean)

  const runs = Array.isArray(preview?.runs) ? preview.runs : []
  if (runs.length) {
    lines.push('')
    lines.push(`接下来 ${runs.length} 次执行：`)
    for (const r of runs) lines.push(`　${formatTimeFull(r)}`)
  } else if (preview?.reboot) {
    lines.push('')
    lines.push('该任务只在系统启动时执行一次，没有日历意义上的下次执行时间。')
  } else if (preview?.reason) {
    lines.push('')
    lines.push(`⚠️ ${preview.reason}`)
  }

  if (adopt) {
    lines.push('')
    lines.push(
      '⚠️ 你正在编辑一条**外部添加**的任务，保存即「收编」：\n' +
      '　· 面板会在它上方加一行标记注释（备注就存在那里）；\n' +
      '　· 执行命令会被换成面板生成的包装脚本，命令原文搬进脚本文件里，\n' +
      '　　这样才能记录输出与退出码；\n' +
      '　· 原始行在列表的「原始行」列中始终可见。',
    )
  }
  lines.push('')
  lines.push('任务以**面板运行身份**（生产环境通常是 root）执行，且每次改动都会写入审计日志。')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 状态卡片
// ---------------------------------------------------------------------------

// MODE_LABEL 与 internal/cron 的 ModeCrontab / ModeFile 对齐。
export const MODE_LABEL = {
  crontab: '系统 crontab',
  file: '隔离文件模式',
}

// modeLabel 返回存取模式的展示名。
export function modeLabel(mode) {
  if (!mode) return '未知'
  return MODE_LABEL[mode] || String(mode)
}

// healthAlert 返回顶部状态条的类型与文案。
//
// ########## 隔离模式必须醒目 ##########
//
// 用 -cron-file 跑起来的面板，改任务**不会**影响真实 cron。
// 若这里显示成一个普通的绿色「已就绪」，用户会以为任务已经生效，
// 等到半夜备份没跑才发现面板其实一直在写一个临时文件。
export function healthAlert(status) {
  if (!status) {
    return { type: 'default', label: '状态未知', detail: '尚未取得计划任务模块状态。' }
  }
  if (status.mode === 'file') {
    return {
      type: 'warning',
      label: '隔离文件模式（不会改动系统 crontab）',
      detail: `所有读写都落在 ${status.target}，仅用于开发、验证与 CI。` +
        '想让任务真正生效，请不要带 -cron-file 启动面板。',
    }
  }
  if (!status.available) {
    return {
      type: 'warning',
      label: '计划任务当前不可用',
      detail: `${status.reason || '原因未知'}。面板其它功能不受影响。`,
    }
  }
  return {
    type: 'success',
    label: '计划任务已就绪',
    detail: `面板正在管理：${status.target}。`,
  }
}

// targetWarning 返回「面板在改谁的任务」的警示文本（无警示时空串）。
//
// 面板默认改**自己运行身份**的 crontab（生产上即 root）。这一点
// 必须写在页面最显眼处：用户以为在改「面板的任务」，实际在改
// root 的定时任务，包括系统包管理器留下的条目。
export function targetWarning(status) {
  if (!status) return ''
  if (status.mode === 'file') return ''
  const user = status.user || '面板运行用户'
  return `保存后任务会写入 ${status.target}。` +
    `它以 ${user} 身份在无人值守的时刻执行任意 shell 命令，请确认命令来源可靠。`
}

// backupsHint 返回备份位置说明（「改坏了去哪找」的唯一答案）。
export function backupsHint(status) {
  if (!status) return ''
  const list = Array.isArray(status.backups) ? status.backups.filter(Boolean) : []
  if (!list.length) {
    return `尚无备份。每次改动前面板都会把改动前的完整内容写入 ${status.data_dir || ''}/backups/。`
  }
  return `最近备份：${list.slice(0, 3).join('、')}` +
    `（目录 ${status.data_dir || ''}/backups/；` +
    '需要手工恢复时执行 `crontab <备份文件>`）'
}

// ---------------------------------------------------------------------------
// 错误呈现
// ---------------------------------------------------------------------------

// errorText 把接口错误转成给用户看的文本。
//
// ########## 回滚失败时必须把备份路径顶到脸上 ##########
//
// 后端写 crontab 失败会自动回滚；连回滚也失败时，crontab 可能停在
// 半截状态，此时**唯一的恢复手段是那份备份文件**。
// 把这条信息降级成一句「保存失败」是本项目不可接受的失败：
// 用户会重试，而每次重试都在往一个可能已经半截的文件里写。
export function errorText(err) {
  if (!err) return '未知错误'
  if (err.rollbackError) {
    return [
      '自动回滚也失败了，crontab 可能处于改动后的状态。',
      err.restoreHint || `请手工执行：crontab ${err.backupPath || ''}`,
      `原始错误：${err.message}`,
    ].filter(Boolean).join('\n')
  }
  if (err.editConflict) {
    return `任务已被外部修改。${err.hint || '请刷新列表后重新编辑，不要直接重试提交。'}`
  }
  if (err.confirmRequired) {
    return err.message || '删除任务需要二次确认。'
  }
  if (err.notAdoptable) {
    return err.message || '该任务的表达式不被面板支持，不会替你改写。'
  }
  if (err.rolledBack) {
    // 写失败但已回滚：要明确告诉用户「crontab 还是旧的」，
    // 否则他会以为改动生效了从而不再检查。
    return `${err.message}\n改动已自动回滚，crontab 仍是改动前的内容。`
  }
  if (err.hint) return `${err.message}（${err.hint}）`
  return err.message || String(err)
}

// resultNotice 返回写成功后的提示（含备份路径与警告）。
export function resultNotice(res, actionLabel_) {
  const parts = [actionLabel_ || '操作已完成']
  if (res?.backup_path) parts.push(`已备份原内容：${res.backup_path}`)
  if (res?.warning) parts.push(`⚠️ ${res.warning}`)
  if (typeof res?.after_count === 'number') parts.push(`当前共 ${res.after_count} 条任务`)
  return parts.join('；')
}

// restoreCommandOf 返回恢复用的完整命令（供一键复制）。
export function restoreCommandOf(backupPath) {
  if (!backupPath) return ''
  return `crontab ${backupPath}`
}
