// 备份恢复的纯逻辑模块（阶段五 5.3）。
//
// ########## 为什么单独抽一个文件 ##########
//
// 与 cronLogic.js、terminalLogic.js 同一纪律：把「决定界面说什么」
// 的逻辑从 .vue 组件里搬出来，放进一个既能被组件 import、
// 又能被 node --test 直接跑的纯模块。
//
// 好处不只是"可测"：恢复的确认判定、危险的措辞、载荷的归一化
// 这类东西一旦写在组件里，就会**只有一条路径能到达它**——
// 测不到那些分支，也就没人知道它们在边界上是什么行为。
// 而恢复是本模块唯一不可逆的操作。

// ---------------------------------------------------------------------------
// 常量（必须与后端一致，改动时两边一起改）
// ---------------------------------------------------------------------------

// 与 internal/backup/validate.go 保持一致。
export const MAX_NAME_LEN = 100
export const MAX_PATH_LEN = 500
export const MAX_COMMENT_LEN = 200
export const MAX_EXPR_LEN = 200
export const MAX_PREFIX_LEN = 120
export const MAX_KEEP_COUNT = 1000
export const MAX_KEEP_DAYS = 3650

// 与 internal/backup/types.go 保持一致。
export const STORAGE_LOCAL = 'local'
export const STORAGE_S3 = 's3'
export const STORAGE_WEBDAV = 'webdav'

export const KEEP_NONE = 'none'
export const KEEP_COUNT = 'count'
export const KEEP_DAYS = 'days'

export const SOURCE_DIR = 'dir'
export const SOURCE_FILE = 'file'

export const STATUS_OK = 'ok'
export const STATUS_FAILED = 'failed'
export const STATUS_RUNNING = 'running'
export const STATUS_SKIPPED = 'skipped'

// 执行状态的中文标签与颜色。
//
// 颜色只表达"要不要人管"这一件事：
//   ok      → success（绿色）
//   running → info（蓝色，只是进行中，不需要人做什么）
//   skipped → warning（黄色：没有产出备份，但不一定是错误）
//   failed  → error（红色）
// 把 skipped 也标成红色会让"并发跳过"看起来像故障，
// 而它其实是我们主动的自我保护。
export const STATUS_META = {
  [STATUS_OK]: { label: '成功', type: 'success' },
  [STATUS_FAILED]: { label: '失败', type: 'error' },
  [STATUS_RUNNING]: { label: '执行中', type: 'info' },
  [STATUS_SKIPPED]: { label: '已跳过', type: 'warning' },
}

export function statusMeta(status) {
  return STATUS_META[status] || { label: status || '未知', type: 'default' }
}

// ---------------------------------------------------------------------------
// 存储类型与保留策略
// ---------------------------------------------------------------------------

// 后端未给出清单时的兜底（接口不可用时表单仍要能渲染）。
//
// 正常情况下**用后端给的**：加一种存储类型时前端会自动多一个选项，
// 这正是"新增能力不改前端"这条纪律的落地方式。
export const FALLBACK_STORAGE_TYPES = [
  {
    type: STORAGE_LOCAL,
    label: '本地目录',
    description: '把归档写进本机的一个目录，不需要任何外部依赖。',
    fields: ['path', 'base_path'],
    builtin: true,
  },
  {
    type: STORAGE_S3,
    label: 'S3 兼容对象存储',
    description: 'AWS S3、MinIO、Ceph 等一切兼容 S3 协议的对象存储。',
    fields: ['endpoint', 'bucket', 'region', 'access_key', 'secret_key',
      'base_path', 'path_style', 'insecure_skip_verify'],
  },
  {
    type: STORAGE_WEBDAV,
    label: 'WebDAV',
    description: 'Nextcloud、坚果云、群晖等 WebDAV 服务端。',
    fields: ['endpoint', 'base_path', 'username', 'password', 'insecure_skip_verify'],
  },
]

export const FALLBACK_KEEP_POLICIES = [
  { policy: KEEP_NONE, label: '不自动清理', needs_value: false },
  { policy: KEEP_COUNT, label: '按份数保留', needs_value: true, value_field: 'keep_count', max_value: MAX_KEEP_COUNT },
  { policy: KEEP_DAYS, label: '按天数保留', needs_value: true, value_field: 'keep_days', max_value: MAX_KEEP_DAYS },
]

// resolveStorageTypes 取后端给的存储类型清单，缺失时用兜底。
export function resolveStorageTypes(status) {
  const list = status?.storage_types
  if (Array.isArray(list) && list.length > 0) return list
  return FALLBACK_STORAGE_TYPES
}

// resolveKeepPolicies 取后端给的保留策略清单，缺失时用兜底。
export function resolveKeepPolicies(status) {
  const list = status?.keep_policies
  if (Array.isArray(list) && list.length > 0) return list
  return FALLBACK_KEEP_POLICIES
}

// storageTypeMeta 查一种存储类型的元信息。
export function storageTypeMeta(types, type) {
  const found = (types || []).find((t) => t.type === type)
  if (found) return found
  return FALLBACK_STORAGE_TYPES.find((t) => t.type === type) || { type, label: type, fields: [] }
}

// storageTypeLabel 取存储类型的中文名。
export function storageTypeLabel(types, type) {
  return storageTypeMeta(types, type).label || type
}

// storageTypeFields 取该类型需要填写的字段名集合。
export function storageTypeFields(types, type) {
  return storageTypeMeta(types, type).fields || []
}

// ---------------------------------------------------------------------------
// 任务表单
// ---------------------------------------------------------------------------

// emptyTaskForm 返回一个空的任务表单。
//
// 默认值刻意选了"最安全"的一端：
//   · source_type = dir    —— 备份一个目录比备份一个文件常见得多
//   · keep_policy = count  —— 默认**要**清理。默认"不清理"会让磁盘
//                             在用户毫无察觉的情况下被吃满
//   · keep_count = 7       —— 一周，一个能让人放心的默认
//   · enabled = true       —— 新建的任务默认就该跑（见后端同名说明）
export function emptyTaskForm() {
  return {
    id: '',
    name: '',
    type: 'full',
    source_type: SOURCE_DIR,
    source_path: '',
    storage_id: '',
    prefix: '',
    expr: '0 3 * * *',
    comment: '',
    keep_policy: KEEP_COUNT,
    keep_count: 7,
    keep_days: 30,
    enabled: true,
  }
}

// taskToForm 把后端任务转成表单对象。
export function taskToForm(task) {
  if (!task) return emptyTaskForm()
  return {
    id: task.id || '',
    name: task.name || '',
    type: task.type || 'full',
    source_type: task.source_type || SOURCE_DIR,
    source_path: task.source_path || '',
    storage_id: task.storage_id || '',
    prefix: task.prefix || '',
    expr: task.expr || '0 3 * * *',
    comment: task.comment || '',
    keep_policy: task.keep_policy || KEEP_NONE,
    keep_count: task.keep_count || 0,
    keep_days: task.keep_days || 0,
    enabled: task.enabled !== false,
  }
}

// normalizeTaskPayload 把表单转成后端期望的 JSON（纯函数，可单测）。
//
// ########## enabled 为什么必须显式给 ##########
//
// 后端用 *bool 承接：**省略该字段 = 启用**。若这里永远带上布尔值，
// 那就等于每次编辑都明确表态，语义更清楚；而漏掉它则意味着
// "用户想停用却停不掉"（后端会读成"省略=启用"）。
// 因此这里显式转成布尔。
export function normalizeTaskPayload(form) {
  const enabled = form?.enabled !== false
  const payload = {
    name: String(form?.name ?? '').trim(),
    type: 'full',
    source_type: form?.source_type === SOURCE_FILE ? SOURCE_FILE : SOURCE_DIR,
    source_path: String(form?.source_path ?? '').trim(),
    storage_id: String(form?.storage_id ?? '').trim(),
    prefix: String(form?.prefix ?? '').trim(),
    expr: String(form?.expr ?? '').trim(),
    comment: String(form?.comment ?? '').trim(),
    keep_policy: form?.keep_policy || KEEP_NONE,
    keep_count: 0,
    keep_days: 0,
    enabled,
  }
  // 只在对应的策略下带上数值：给一个不相关的字段塞数字会让
  // 后端的校验看到"你选了不清理，却给了 7 份"这种矛盾输入。
  if (payload.keep_policy === KEEP_COUNT) {
    payload.keep_count = toPositiveInt(form?.keep_count)
  }
  if (payload.keep_policy === KEEP_DAYS) {
    payload.keep_days = toPositiveInt(form?.keep_days)
  }
  if (Array.isArray(form?.expected_ids)) {
    payload.expected_ids = form.expected_ids
  }
  return payload
}

// validateTaskForm 做**前端**的表单校验，返回 { field: message }。
//
// ########## 前端校验的定位 ##########
//
// 它**不是**安全边界（后端必须独立校验，这是纪律）。
// 它的价值只有一个：让用户在还没点提交时就知道哪里不对，
// 而不是等一次来回之后看到一个红色的接口错误。
// 因此这里只查"格式明显不对"的东西，不重复后端的全部规则。
export function validateTaskForm(form, { storageTypes = FALLBACK_STORAGE_TYPES } = {}) {
  const errors = {}
  const name = String(form?.name ?? '').trim()
  const sourcePath = String(form?.source_path ?? '').trim()
  const expr = String(form?.expr ?? '').trim()
  const comment = String(form?.comment ?? '').trim()
  const prefix = String(form?.prefix ?? '').trim()

  if (!name) {
    errors.name = '请填写任务名（恢复时需要逐字输入它来确认，所以起个你记得住的名字）'
  } else if (name.length > MAX_NAME_LEN) {
    errors.name = `任务名不能超过 ${MAX_NAME_LEN} 个字符`
  } else if (/[\r\n\t]/.test(name)) {
    errors.name = '任务名不能包含换行或制表符'
  }

  if (!sourcePath) {
    errors.source_path = '请选择要备份的目录或文件'
  } else if (!sourcePath.startsWith('/')) {
    errors.source_path = '请填写绝对路径（以 / 开头）'
  } else if (sourcePath.length > MAX_PATH_LEN) {
    errors.source_path = `路径不能超过 ${MAX_PATH_LEN} 个字符`
  }

  if (!form?.storage_id) {
    errors.storage_id = '请选择目标存储。还没有的话，先去「存储配置」标签页加一个'
  }

  if (!expr) {
    errors.expr = '请填写 cron 表达式（例如 0 3 * * * 表示每天凌晨 3 点）'
  } else if (expr.length > MAX_EXPR_LEN) {
    errors.expr = `表达式不能超过 ${MAX_EXPR_LEN} 个字符`
  } else if (/[\r\n\t]/.test(expr)) {
    errors.expr = '表达式不能包含换行或制表符'
  }

  if (comment.length > MAX_COMMENT_LEN) {
    errors.comment = `备注不能超过 ${MAX_COMMENT_LEN} 个字符`
  }
  if (/[\r\n]/.test(comment)) {
    errors.comment = '备注不能包含换行'
  }

  if (prefix) {
    if (prefix.length > MAX_PREFIX_LEN) {
      errors.prefix = `前缀不能超过 ${MAX_PREFIX_LEN} 个字符`
    } else if (/^\/|\.\.|\/\/|[\r\n]/.test(prefix)) {
      errors.prefix = '前缀是对象存储里的相对目录，不能以 / 开头、不能含 .. 或连续斜杠'
    }
  }

  if (form?.keep_policy === KEEP_COUNT) {
    const n = toPositiveInt(form?.keep_count)
    if (!n) {
      errors.keep_count = '请填写保留份数'
    } else if (n > MAX_KEEP_COUNT) {
      errors.keep_count = `份数不能超过 ${MAX_KEEP_COUNT}`
    }
  }
  if (form?.keep_policy === KEEP_DAYS) {
    const n = toPositiveInt(form?.keep_days)
    if (!n) {
      errors.keep_days = '请填写保留天数'
    } else if (n > MAX_KEEP_DAYS) {
      errors.keep_days = `天数不能超过 ${MAX_KEEP_DAYS}`
    }
  }

  return errors
}

// hasErrors 判断校验结果里有没有错误。
export function hasErrors(errors) {
  return Object.keys(errors || {}).length > 0
}

function toPositiveInt(v) {
  const n = Number.parseInt(v, 10)
  if (!Number.isFinite(n) || n <= 0) return 0
  return n
}

// ---------------------------------------------------------------------------
// 存储表单
// ---------------------------------------------------------------------------

// emptyStorageForm 返回一个空的存储表单。
export function emptyStorageForm(type = STORAGE_LOCAL) {
  return {
    id: '',
    name: '',
    type,
    path: '',
    endpoint: '',
    bucket: '',
    region: '',
    access_key: '',
    // 密钥字段用 null 表示"不改动"——编辑时用户不重填就是 null。
    secret_key: null,
    path_style: false,
    base_path: '',
    username: '',
    password: null,
    insecure_skip_verify: false,
  }
}

// storageToForm 把后端存储转成表单对象。
//
// ########## 密钥字段一律留空 ##########
//
// 后端不回显凭证，这里也**绝不能**把 secret_tail 填进输入框：
// 尾 4 位是给用户**核对**的，不是让他编辑的。
// 提交时 null 表示"不改动"，见 normalizeStoragePayload。
export function storageToForm(storage) {
  if (!storage) return emptyStorageForm()
  return {
    id: storage.id || '',
    name: storage.name || '',
    type: storage.type || STORAGE_LOCAL,
    path: storage.path || '',
    endpoint: storage.endpoint || '',
    bucket: storage.bucket || '',
    region: storage.region || '',
    access_key: storage.access_key || '',
    secret_key: null,
    path_style: storage.path_style === true,
    base_path: storage.base_path || '',
    username: storage.username || '',
    password: null,
    insecure_skip_verify: storage.insecure_skip_verify === true,
  }
}

// normalizeStoragePayload 把存储表单转成后端期望的 JSON（纯函数，可单测）。
//
// ########## 空密钥必须转成 null，不能转成 "" ##########
//
// 后端把 nil 读作"不改动"、把 "" 读作"清空"。若这里把用户
// 没填的空串原样传上去，**每次编辑都会把凭证清空**——
// 而用户只是改了一下名字。下一次备份直接失败，
// 而失败的原因（"密钥没了"）与用户做过的动作（"改了个名字"）
// 之间毫无关联，极难排查。
//
// 因此：null / undefined / 空串 / 纯空白 → null（不改动）。
// 要真的清空，用户在界面上没有这个入口（那不是一个有意义的操作）。
export function normalizeStoragePayload(form) {
  const type = form?.type || STORAGE_LOCAL
  const payload = {
    name: String(form?.name ?? '').trim(),
    type,
    path: '',
    endpoint: '',
    bucket: '',
    region: '',
    access_key: '',
    secret_key: null,
    path_style: false,
    base_path: String(form?.base_path ?? '').trim(),
    username: '',
    password: null,
    insecure_skip_verify: form?.insecure_skip_verify === true,
  }

  // 只带上该类型用得到的字段：给本地存储塞一个 endpoint，
  // 会让后端收到"看起来还配着远端"的配置。
  const fields = new Set(storageTypeFields(FALLBACK_STORAGE_TYPES, type))

  if (fields.has('path')) {
    payload.path = String(form?.path ?? '').trim()
  }
  if (fields.has('endpoint')) {
    payload.endpoint = String(form?.endpoint ?? '').trim()
  }
  if (fields.has('bucket')) {
    payload.bucket = String(form?.bucket ?? '').trim()
  }
  if (fields.has('region')) {
    payload.region = String(form?.region ?? '').trim()
  }
  if (fields.has('access_key')) {
    payload.access_key = String(form?.access_key ?? '').trim()
  }
  if (fields.has('secret_key')) {
    payload.secret_key = secretOrNull(form?.secret_key)
  }
  if (fields.has('path_style')) {
    payload.path_style = form?.path_style === true
  }
  if (fields.has('username')) {
    payload.username = String(form?.username ?? '').trim()
  }
  if (fields.has('password')) {
    payload.password = secretOrNull(form?.password)
  }

  if (form?.id) payload.id = form.id
  return payload
}

// secretOrNull 把密钥输入转成"新值"或"不改动"。
export function secretOrNull(value) {
  if (value === null || value === undefined) return null
  const trimmed = String(value).trim()
  if (trimmed === '') return null
  return trimmed
}

// validateStorageForm 做前端的存储表单校验。
export function validateStorageForm(form) {
  const errors = {}
  const name = String(form?.name ?? '').trim()
  const type = form?.type || STORAGE_LOCAL

  if (!name) {
    errors.name = '请给这个存储起个名字（列表里要靠它区分）'
  } else if (name.length > MAX_NAME_LEN) {
    errors.name = `名字不能超过 ${MAX_NAME_LEN} 个字符`
  }

  if (type === STORAGE_LOCAL) {
    const path = String(form?.path ?? '').trim()
    if (!path) {
      errors.path = '请填写本地目录的绝对路径'
    } else if (!path.startsWith('/')) {
      errors.path = '请填写绝对路径（以 / 开头）'
    }
  }

  if (type === STORAGE_S3 || type === STORAGE_WEBDAV) {
    const endpoint = String(form?.endpoint ?? '').trim()
    if (!endpoint) {
      errors.endpoint = '请填写服务地址'
    } else if (!/^https?:\/\//i.test(endpoint)) {
      errors.endpoint = '地址要以 http:// 或 https:// 开头'
    }
  }

  if (type === STORAGE_S3) {
    if (!String(form?.bucket ?? '').trim()) errors.bucket = '请填写 Bucket 名称'
    if (!String(form?.access_key ?? '').trim()) errors.access_key = '请填写 Access Key ID'
    // 新建时必须有密钥；编辑时留空表示沿用旧的。
    if (!form?.id && secretOrNull(form?.secret_key) === null) {
      errors.secret_key = '请填写 Secret Access Key'
    }
  }

  if (type === STORAGE_WEBDAV) {
    if (!String(form?.username ?? '').trim()) errors.username = '请填写用户名'
    if (!form?.id && secretOrNull(form?.password) === null) {
      errors.password = '请填写密码'
    }
  }

  return errors
}

// storageCredentialHint 生成"凭证状态"的提示文案。
//
// 它回答用户唯一关心的问题：「我到底配没配密钥？」
// 而接口只回显尾 4 位，这里绝不把它当成可编辑的值。
export function storageCredentialHint(item) {
  if (!item) return ''
  const parts = []
  if (item.has_secret) {
    parts.push(item.secret_tail ? `密钥已设置（尾号 ${item.secret_tail}）` : '密钥已设置')
  } else {
    parts.push('未设置密钥')
  }
  if (item.has_password) {
    parts.push(item.password_tail ? `密码已设置（尾号 ${item.password_tail}）` : '密码已设置')
  }
  return parts.join('，')
}

// ---------------------------------------------------------------------------
// 恢复：确认判定与危险文案
// ---------------------------------------------------------------------------

// restoreConfirmMatches 判断用户输入的确认文字是否**逐字**等于任务名。
//
// ########## 这里绝不能"聪明" ##########
//
// 不要 trim、不要忽略大小写、不要接受"包含"。
// 后端是严格逐字比对（见 backup.Manager.RestoreFile），
// 前端若在这里放宽，用户会看到"确认按钮亮了"但提交后拿到 428——
// 那比直接不亮更让人困惑。
//
// 唯一的例外是在**提交前**去一次首尾空白：用户从别处复制任务名时
// 很容易带上空格，而那是输入习惯问题、不是"他确认了别的什么东西"。
// 这个处理只发生在提交的那一刻（见 buildRestorePayload），
// 不发生在按钮亮不亮的判定里——按钮的亮灭必须与后端的判定完全一致。
export function restoreConfirmMatches(taskName, input) {
  if (!taskName) return false
  return String(input ?? '') === String(taskName)
}

// canSubmitRestore 判断恢复按钮是否可以点。
export function canSubmitRestore({ preview, confirmText, targetDir, restoring = false } = {}) {
  if (restoring) return false
  if (!preview) return false
  if (!String(targetDir ?? '').trim()) return false
  return restoreConfirmMatches(preview.confirm_text || preview.task_name, confirmText)
}

// buildRestorePayload 组装恢复请求体。
//
// ########## 提交前去掉首尾空白是**有意**的 ##########
//
// 后端逐字比对，因此这里去掉空白相当于帮用户一个忙：
// 他从别处复制任务名时带上的尾随空格不会让操作失败。
// 这不是放松门槛——去空白之后仍然要求完全相等，
// 用户还是得准确打出那个名字。
export function buildRestorePayload({ storageId, key, targetDir, confirmText }) {
  return {
    storage_id: storageId,
    key,
    target_dir: String(targetDir ?? '').trim(),
    confirm: true,
    confirm_text: String(confirmText ?? '').trim(),
  }
}

// restoreDangerLines 生成恢复确认框里的危险提示行。
//
// ########## 文案来自两个地方，缺一不可 ##########
//
//   · preview.danger  —— **后端**生成的说明。它必须来自后端，
//                        否则文案会与真实行为漂移：哪天后端改成
//                        会删除多余文件了，前端那句话还在说"不会删除"。
//   · 下面这些        —— 由**预览数据**算出来的具体数字
//                        （"将覆盖 3 个已存在的文件"）。
//
// 只给一句笼统的"恢复会覆盖文件"，用户无法判断这次操作有多大影响。
export function restoreDangerLines(preview, targetDir) {
  const lines = []
  const p = preview || {}

  if (p.danger) lines.push(String(p.danger))

  const target = String(targetDir || p.target_dir || '').trim()
  if (target) {
    lines.push(`归档会被解压到：${target}`)
  }

  const total = toNonNegInt(p.total)
  const overwrite = toNonNegInt(p.conflict_count)
  if (total > 0) {
    lines.push(`共 ${total} 个条目将被写入`)
  }
  if (overwrite > 0) {
    lines.push(`其中 ${overwrite} 个文件在目标目录里**已经存在**，会被覆盖且无法撤销`)
  } else if (total > 0) {
    lines.push('目标目录里没有同名文件，本次不会覆盖任何已存在的内容')
  }

  const unsafe = toNonNegInt(p.unsafe_count)
  if (unsafe > 0) {
    lines.push(`有 ${unsafe} 个条目（符号链接、设备节点、或路径越界的条目）会被**跳过**，它们不会恢复`)
  }

  if (p.truncated) {
    lines.push('条目过多，预览只列出了前一部分；实际恢复仍会处理全部条目')
  }

  return lines
}

// restoreConfirmHint 生成输入框上方的提示。
export function restoreConfirmHint(preview) {
  const name = preview?.confirm_text || preview?.task_name || ''
  if (!name) {
    return '请在下面**逐字**输入任务名以确认这次恢复。'
  }
  return `请在下面**逐字**输入任务名「${name}」以确认这次恢复。`
}

function toNonNegInt(v) {
  const n = Number.parseInt(v, 10)
  if (!Number.isFinite(n) || n < 0) return 0
  return n
}

// ---------------------------------------------------------------------------
// 展示辅助
// ---------------------------------------------------------------------------

// humanBytes 把字节数转成人类可读。
export function humanBytes(bytes) {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  const digits = v >= 100 || i === 0 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(digits)} ${units[i]}`
}

// humanDuration 把毫秒转成人类可读的耗时。
export function humanDuration(ms) {
  const n = Number(ms)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1000) return `${Math.round(n)} 毫秒`
  const sec = n / 1000
  if (sec < 60) return `${sec.toFixed(1)} 秒`
  const min = Math.floor(sec / 60)
  const rem = Math.round(sec % 60)
  if (min < 60) return `${min} 分 ${rem} 秒`
  const hour = Math.floor(min / 60)
  return `${hour} 小时 ${min % 60} 分`
}

// formatTime 把 RFC3339 时间显示成"本地时间 + 相对时间"。
//
// 只显示绝对时间的话，用户得自己心算"这是多久以前"；
// 而备份这件事的判断标准恰恰是"上次成功是多久以前"。
export function formatTime(rfc3339, now = Date.now()) {
  if (!rfc3339) return '—'
  const t = Date.parse(rfc3339)
  if (!Number.isFinite(t)) return String(rfc3339)

  const d = new Date(t)
  const pad = (v) => String(v).padStart(2, '0')
  const absolute = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`

  const diff = now - t
  if (!Number.isFinite(diff)) return absolute
  const abs = Math.abs(diff)
  if (abs < 60 * 1000) return `${absolute}（刚刚）`
  const rel = humanDuration(abs)
  return diff >= 0 ? `${absolute}（${rel}前）` : `${absolute}（${rel}后）`
}

// describeTask 生成任务列表里那一行的状态摘要。
//
// ########## 它存在的理由是"别让用户自己拼状态" ##########
//
// 一条任务是否健康，要看源路径、存储、表达式、crontab 挂接
// 四件事。让用户对着四个字段自己判断"这条任务到底会不会跑"，
// 结果就是没人看——直到需要恢复的那天才发现它从没跑过。
export function describeTask(task, { now = Date.now() } = {}) {
  if (!task) return { type: 'default', text: '—' }

  if (task.storage_missing) {
    return { type: 'error', text: '目标存储配置已被删除，这条任务无法执行' }
  }
  if (task.source_exists === false) {
    return { type: 'error', text: task.source_reason || '源路径不存在或不可读' }
  }
  if (task.valid === false) {
    return { type: 'error', text: `cron 表达式不被支持：${task.invalid_reason || '格式有误'}` }
  }
  if (task.running) {
    return { type: 'info', text: '正在执行中' }
  }
  if (!task.enabled) {
    return { type: 'warning', text: '已停用（不会定时执行，仍可手动执行）' }
  }
  if (!task.cron_managed) {
    return {
      type: 'warning',
      text: task.cron_reason
        ? `未挂到计划任务上：${task.cron_reason}`
        : '未挂到计划任务上，不会定时执行',
    }
  }
  if (task.last_status === STATUS_FAILED) {
    return { type: 'error', text: `上次执行失败：${task.last?.error || '原因见历史'}` }
  }
  if (!task.last) {
    return { type: 'warning', text: '尚未执行过（保存后还没跑过第一次）' }
  }
  return { type: 'success', text: '配置正常，按计划执行' }
}

// summarizeStorageUsage 统计各存储上的备份占用。
export function summarizeStorageUsage(files) {
  const byStorage = new Map()
  let total = 0
  let totalBytes = 0
  for (const f of files || []) {
    total++
    totalBytes += Number(f.size) || 0
    const key = f.storage_id || ''
    const cur = byStorage.get(key) || { count: 0, bytes: 0 }
    cur.count++
    cur.bytes += Number(f.size) || 0
    byStorage.set(key, cur)
  }
  return { total, totalBytes, byStorage }
}

// resolveRestoreTarget 给出恢复目标目录的默认建议。
//
// 默认值来自**后端**的状态接口（restore_roots 的第一项），
// 而不是前端写死一个 /var/lib/lipanel/restore：
// 管理员可能已经用 -backup-restore-root 改过白名单，
// 前端写死会让用户填一个必然被拒的路径。
export function resolveRestoreTarget(status, storageName = '') {
  const roots = status?.restore_roots || []
  const base = roots[0] || ''
  if (!base) return ''
  const leaf = sanitizePathSegment(storageName) || 'restore'
  return `${base.replace(/\/+$/, '')}/${leaf}`
}

// sanitizePathSegment 把一段文字变成安全的路径片段。
export function sanitizePathSegment(s) {
  return String(s ?? '')
    .replace(/[/\\]+/g, '-')
    .replace(/[\0\r\n\t]/g, '')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 64)
}

// restoreRootNarrow 说明恢复根是否处于默认的收紧状态。
export function restoreRootNarrow(status) {
  return status?.restore_root_narrow === true
}

// restoreRootsHint 给出恢复目标白名单的说明。
export function restoreRootsHint(status) {
  const roots = (status?.restore_roots || []).join('、') || '（未配置）'
  if (restoreRootNarrow(status)) {
    return `恢复目标已收紧到面板自有目录：${roots}。` +
      '需要恢复到别处时，用启动参数 -backup-restore-root 显式放开。'
  }
  return `恢复目标白名单：${roots}。恢复会覆盖这些目录里的同名文件，请确认它们是安全的恢复位置。`
}

// cronUnavailableHint 在 crontab 不可用时给出可操作的建议。
export function cronUnavailableHint(status) {
  if (status?.cron_available) return ''
  return status?.cron_install_hint ||
    '计划任务当前不可用，备份任务仍可保存并手动执行。'
}

// ---------------------------------------------------------------------------
// 历史与清单的表格列
// ---------------------------------------------------------------------------

// historyRowOf 把一条历史记录转成表格行（时间与大小都已格式化）。
export function historyRowOf(entry, { now = Date.now() } = {}) {
  if (!entry) return null
  const meta = statusMeta(entry.status)
  return {
    id: entry.id || '',
    task_id: entry.task_id || '',
    started_at: formatTime(entry.started_at, now),
    duration: entry.duration_ms ? humanDuration(entry.duration_ms) : '—',
    status: entry.status || '',
    status_label: meta.label,
    status_type: meta.type,
    trigger: entry.trigger === 'cron' ? '定时' : entry.trigger === 'test' ? '测试' : '手动',
    archive_key: entry.archive_key || '',
    archive_bytes: entry.archive_bytes || 0,
    size_text: entry.archive_bytes ? humanBytes(entry.archive_bytes) : '—',
    files: entry.file_count || 0,
    total_text: entry.total_bytes ? humanBytes(entry.total_bytes) : '—',
    pruned: entry.pruned || 0,
    skipped: entry.skipped || 0,
    warnings: entry.warnings || [],
    prune_errors: entry.prune_errors || [],
    error: entry.error || '',
    // 只有"成功且有归档"的记录才能被下载或恢复。
    downloadable: entry.status === STATUS_OK && !!entry.archive_key,
  }
}

// fileRowOf 把一个备份文件转成表格行。
export function fileRowOf(file) {
  if (!file) return null
  return {
    key: file.key || '',
    name: file.name || file.key || '',
    storage_id: file.storage_id || '',
    storage_type: file.storage_type || '',
    task_id: file.task_id || '',
    task_name: file.task_name || '（任务已删除）',
    size: file.size || 0,
    size_text: humanBytes(file.size),
    mod_time: file.mod_time || '—',
    local_path: file.local_path || '',
    // 时间戳从对象名里解析出来（名字里带定长时间戳，见后端说明）。
    stamp: archiveStampOf(file.key),
  }
}

// archiveStampOf 从归档对象名里解析出时间戳文本。
//
// 名字形态：<prefix>/<taskID>/<taskID>-YYYYMMDD-HHMMSS.tar.gz
// 解析不出来时返回空串——**不要猜**，猜错的时间比不显示更糟。
export function archiveStampOf(key) {
  const name = String(key || '')
  const m = name.match(/(\d{8})-(\d{6})\.tar\.gz$/)
  if (!m) return ''
  const d = m[1]
  const t = m[2]
  return `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)} ` +
    `${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4, 6)}`
}

// auditRowOf 把一条审计记录转成表格行。
export function auditRowOf(event, { now = Date.now() } = {}) {
  if (!event) return null
  const outcomeMeta = {
    allowed: { label: '允许', type: 'success' },
    denied: { label: '拒绝', type: 'warning' },
    failed: { label: '失败', type: 'error' },
  }[event.outcome] || { label: event.outcome || '—', type: 'default' }

  return {
    seq: event.seq,
    time: formatTime(event.time, now),
    user: event.user || '—',
    client_ip: event.client_ip || '—',
    action: event.action || '',
    action_label: ACTION_LABELS[event.action] || event.action || '',
    target: event.target || '—',
    task_name: event.task_name || '—',
    storage_type: event.storage_type || '',
    archive_key: event.archive_key || '',
    size_text: event.archive_bytes ? humanBytes(event.archive_bytes) : '',
    outcome: event.outcome || '',
    outcome_label: outcomeMeta.label,
    outcome_type: outcomeMeta.type,
    status: event.status || 0,
    reason: event.reason || '',
    duration: event.duration_ms ? humanDuration(event.duration_ms) : '—',
    confirmed: event.confirmed === true,
    confirm_text_ok: event.confirm_text_ok === true,
  }
}

// ACTION_LABELS 是审计动作的中文名。
export const ACTION_LABELS = {
  list: '查看',
  history: '查看历史',
  create: '创建任务',
  update: '编辑任务',
  delete: '删除任务',
  run: '立即执行',
  download: '下载备份',
  delete_file: '删除备份文件',
  restore_preview: '恢复预览',
  restore: '执行恢复',
  storage_create: '新增存储',
  storage_update: '编辑存储',
  storage_delete: '删除存储',
  storage_test: '测试存储',
}

export function actionLabel(action) {
  return ACTION_LABELS[action] || action || ''
}

// restoreRiskLevel 判断一次恢复的风险等级，用于决定警示的强烈程度。
//
// 三档：
//   high   会覆盖已存在的文件 —— 红色，必须逐字确认
//   medium 会写入全新文件     —— 黄色，仍需确认
//   low    没有可恢复的条目   —— 灰色
//
// 分档的价值在于**让用户一眼看出这次操作有多大影响**。
// 全部标红等于没有信号。
export function restoreRiskLevel(preview) {
  if (!preview) return 'low'
  const total = toNonNegInt(preview.total)
  if (total === 0) return 'low'
  if (toNonNegInt(preview.conflict_count) > 0) return 'high'
  return 'medium'
}
