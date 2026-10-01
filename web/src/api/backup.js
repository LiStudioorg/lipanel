// 备份恢复接口封装（阶段五 5.3）。
//
// 约定与 api/client.js、services.js、files.js、sites.js、ssl.js、
// store.js、firewall.js、cron.js 保持一致：带超时、携带会话 Cookie、
// 失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'
import { normalizeTaskPayload, normalizeStoragePayload } from '@/views/backupLogic'

// ########## 超时取值（本模块与其它模块最大的不同）##########
//
// 备份是**长时间操作**：打包一个几十 GB 的目录再传给远端，
// 几十分钟是正常的。因此执行与恢复两个接口的超时给到 35 分钟——
// 必须**长于**后端（backup.ExecTimeout 默认 30 分钟）。
//
// 反过来（前端先超时）会发生什么：后端还在打包上传，
// 前端已经报了"请求超时"，用户以为没成功、再点一次，
// 于是同一条任务上出现了两次执行。后端有跨进程锁会跳过第二次，
// 但用户看到的是"备份失败了"——他会去排查一个根本没坏的东西。
const BACKUP_READ_TIMEOUT_MS = 15000
const BACKUP_WRITE_TIMEOUT_MS = 60000

// 执行/恢复是长操作，单独给足 35 分钟。
const BACKUP_LONG_TIMEOUT_MS = 35 * 60 * 1000

async function request(path, { timeout = BACKUP_READ_TIMEOUT_MS, ...init } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  let resp
  try {
    resp = await fetch(path, {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      signal: controller.signal,
      ...init,
    })
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new ApiError(`请求超时（${Math.round(timeout / 60000) || timeout / 1000}${timeout >= 60000 ? ' 分钟' : 's'}）：${path}`, { cause: err })
    }
    throw new ApiError(`无法连接后端：${err.message}`, { cause: err })
  } finally {
    clearTimeout(timer)
  }

  // ########## 下载是二进制，不能走这里 ##########
  //
  // 本函数一律把响应体当 JSON 解析；下载接口另走 downloadBackupFile，
  // 它直接拿 Blob，不经过 JSON 解析。
  let payload = null
  const text = await resp.text()
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (!resp.ok) {
    const msg = payload?.error || text?.slice(0, 200) || `HTTP ${resp.status}`
    const err = new ApiError(msg, { status: resp.status, hint: payload?.hint })

    // ########## 这些附加字段为什么必须挂上去 ##########
    //
    // 本模块有六处错误语义，光看 status 会让用户做出**错误的下一步动作**：
    //
    //   428 缺少/错误的二次确认 —— 该去把任务名打对，不是重试
    //   409 并发冲突             —— 必须「刷新后重新编辑」，重试会覆盖别人的改动
    //   409 存储被引用           —— 该先去改那些任务，删存储没用
    //   409 已有执行在跑         —— 该等，不是重试（会互相覆盖同一份备份）
    //   413 超出体积上限         —— 该收窄源路径或调启动参数，重试一万次也一样
    //   503 crontab 不可用       —— 环境没有这个能力，不是面板坏了
    //
    // kind / field 是后端给出的分类与字段名，直接展示或挂到表单项即可。
    err.kind = payload?.kind || ''
    err.field = payload?.field || ''
    err.confirmRequired = resp.status === 428 ||
      resp.headers?.get?.('X-Lipanel-Confirm-Required') === 'true'
    err.editConflict = resp.status === 409 && payload?.kind === '配置已被外部修改'
    err.storageInUse = resp.status === 409 && payload?.kind === '存储配置仍被引用'
    err.alreadyRunning = resp.status === 409 && payload?.kind === '已有执行在进行'
    err.unavailable = resp.status === 503
    err.tooLarge = resp.status === 413
    err.usedBy = payload?.used_by || []
    throw err
  }

  return payload
}

function postJSON(path, body, timeout = BACKUP_WRITE_TIMEOUT_MS) {
  return request(path, {
    method: 'POST',
    timeout,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body ?? {}),
  })
}

function putJSON(path, body, timeout = BACKUP_WRITE_TIMEOUT_MS) {
  return request(path, {
    method: 'PUT',
    timeout,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body ?? {}),
  })
}

// ---------------------------------------------------------------------------
// 读操作
// ---------------------------------------------------------------------------

// fetchBackupStatus 查询模块状态（数据目录、白名单、cron 可用性、权限）。
//
// 它同时返回 storage_types 与 keep_policies 两个**由后端给出**的清单：
// 存储类型与保留策略的选项不写死在前端，加一种后端能力时前端会自动多一项。
export function fetchBackupStatus() {
  return request('/api/backup')
}

// fetchBackupTasks 查询备份任务列表（含派生字段：下次执行时间、源是否可用）。
export function fetchBackupTasks() {
  return request('/api/backup/tasks')
}

// fetchBackupHistory 查询某任务的执行历史。
export function fetchBackupHistory(taskId, limit = 50) {
  const qs = new URLSearchParams()
  qs.set('limit', String(limit))
  return request(`/api/backup/tasks/${encodeURIComponent(taskId)}/history?${qs.toString()}`)
}

// fetchBackupFiles 汇总各存储上的备份文件。
//
// 返回的每一项都带 storage_id + key，下载与删除**只接受这里出现过的**组合
// （后端会反查它属于哪条任务，见 backup.Manager.ResolveKey）。
export function fetchBackupFiles({ taskId = '', limit = 500 } = {}) {
  const qs = new URLSearchParams()
  qs.set('limit', String(limit))
  if (taskId) qs.set('task_id', taskId)
  return request(`/api/backup/files?${qs.toString()}`)
}

// fetchBackupStorages 查询存储配置列表（凭证已脱敏，只给尾 4 位）。
export function fetchBackupStorages() {
  return request('/api/backup/storages')
}

// fetchBackupAudit 查询操作审计。
export function fetchBackupAudit({ limit = 100, taskId = '', user = '', outcome = '', action = '' } = {}) {
  const qs = new URLSearchParams()
  qs.set('limit', String(limit))
  if (taskId) qs.set('task_id', taskId)
  if (user) qs.set('user', user)
  if (outcome) qs.set('outcome', outcome)
  if (action) qs.set('action', action)
  return request(`/api/backup/audit?${qs.toString()}`)
}

// previewBackupRestore 预览恢复的影响面（**只读，不落盘**）。
//
// 它告诉用户：会写入哪些条目、会覆盖几个已存在的文件、
// 有哪些条目因为不安全会被跳过、以及必须逐字输入什么才能继续。
export function previewBackupRestore({ storageId, key, targetDir }) {
  return postJSON('/api/backup/restore/preview', {
    storage_id: storageId,
    key,
    target_dir: targetDir,
  })
}

// ---------------------------------------------------------------------------
// 写操作
// ---------------------------------------------------------------------------

// createBackupTask 新增备份任务。
export function createBackupTask(input) {
  return postJSON('/api/backup/tasks', normalizeTaskPayload(input))
}

// updateBackupTask 编辑备份任务。
//
// expectedIds 是乐观并发断言：后端发现集合与现状不符时返回 **409**，
// 前端应当提示「刷新后重新编辑」——直接重试会覆盖别人的改动。
export function updateBackupTask(id, input) {
  return putJSON(`/api/backup/tasks/${encodeURIComponent(id)}`, normalizeTaskPayload(input))
}

// deleteBackupTask 删除任务。
//
// ########## confirm 必须为 true ##########
//
// 后端强制：不带 confirm 一律 **428**。前端弹窗只是体验，
// 服务端强制才是边界。删掉一条备份任务意味着**从此不再有新的备份**，
// 而这件事往往要到需要恢复的那天才被发现。
export function deleteBackupTask(id, { confirm = false, expectedIds = [] } = {}) {
  return request(`/api/backup/tasks/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    timeout: BACKUP_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ confirm, expected_ids: expectedIds }),
  })
}

// runBackupTask 立即执行一次备份（**同步等待**）。
//
// 用 35 分钟的长超时：打包 + 上传是分钟级到十分钟级的操作。
// 同步返回的好处是界面上「上次执行」列立刻就有结果，
// 而不是"刷新几次看看"。
export function runBackupTask(id) {
  return postJSON(`/api/backup/tasks/${encodeURIComponent(id)}/run`, {}, BACKUP_LONG_TIMEOUT_MS)
}

// deleteBackupFile 删除一份备份文件。
//
// 只删存储上的对象，**不删任务、也不动历史**：删掉一份旧备份
// 不该让"这条任务曾经成功备份过"这件事从界面上消失。
export function deleteBackupFile({ storageId, key, confirm = false }) {
  const qs = new URLSearchParams()
  qs.set('storage_id', storageId)
  qs.set('key', key)
  if (confirm) qs.set('confirm', 'true')
  return request(`/api/backup/files?${qs.toString()}`, {
    method: 'DELETE',
    timeout: BACKUP_WRITE_TIMEOUT_MS,
  })
}

// restoreBackup 执行恢复。
//
// ########## 本函数是全前端唯一不可逆的操作入口 ##########
//
// 后端要求 confirm=true **且** confirm_text 逐字等于任务名，
// 缺任一返回 **428**。调用方必须把 dangerCopy 原文展示给用户，
// 并让他亲手打出任务名——不要替他填好。
export function restoreBackup({ storageId, key, targetDir, confirm = false, confirmText = '' }) {
  return postJSON('/api/backup/restore', {
    storage_id: storageId,
    key,
    target_dir: targetDir,
    confirm,
    confirm_text: confirmText,
  }, BACKUP_LONG_TIMEOUT_MS)
}

// createBackupStorage 新增存储配置。
//
// ********** 密钥字段的省略语义 **********
//
// secret_key / password 省略（或传 null）表示「不改动」。
// 编辑时接口不回显密钥，因此前端提交表单时**不要**把空字符串
// 当新值传上去——那会把已配好的凭证清空，
// 而用户只是改了一下名字。
export function createBackupStorage(input) {
  return postJSON('/api/backup/storages', normalizeStoragePayload(input))
}

// updateBackupStorage 编辑存储配置（同上：不传密钥 = 不改动）。
export function updateBackupStorage(id, input) {
  return putJSON(`/api/backup/storages/${encodeURIComponent(id)}`, normalizeStoragePayload(input))
}

// deleteBackupStorage 删除存储配置（被任务引用时后端返回 409 + used_by）。
export function deleteBackupStorage(id, { confirm = false } = {}) {
  return request(`/api/backup/storages/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    timeout: BACKUP_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ confirm }),
  })
}

// testBackupStorage 测试存储连通性。
//
// 可以测一个**尚未保存**的配置：用户真正需要的顺序是
// "先试试连得上，再决定要不要存"。传 id 时后端会用已保存的密钥。
export function testBackupStorage(input, { id = '' } = {}) {
  const qs = new URLSearchParams()
  if (id) qs.set('id', id)
  const path = qs.toString() ? `/api/backup/storages/test?${qs}` : '/api/backup/storages/test'
  return postJSON(path, normalizeStoragePayload(input), BACKUP_WRITE_TIMEOUT_MS)
}

// ---------------------------------------------------------------------------
// 下载（二进制，不走 request()）
// ---------------------------------------------------------------------------

// downloadBackupFile 下载一份备份。
//
// ########## 这里没有任何"路径"参数 ##########
//
// 只接受 storage_id + key，且后端会反查这个 key 属于哪条任务
// （见 backup.Manager.ResolveKey）。若这里开一个 path 参数，
// 那就是「登录即可读取服务器上任意文件」。
//
// 用 fetch + Blob 而不是直接跳转 URL：直接跳转会把浏览器带到
// 一个 JSON 错误页上（比如 key 不属于任何任务时的 404），
// 用户看到一屏 JSON 而不知道该做什么。
export async function downloadBackupFile({ storageId, key, filename = '' }) {
  const qs = new URLSearchParams()
  qs.set('storage_id', storageId)
  qs.set('key', key)

  let resp
  try {
    resp = await fetch(`/api/backup/files/download?${qs.toString()}`, {
      credentials: 'same-origin',
    })
  } catch (err) {
    throw new ApiError(`无法连接后端：${err.message}`, { cause: err })
  }

  if (!resp.ok) {
    // 失败时后端返回的是 JSON，这里把它读出来给用户看真正的原因。
    let msg = `HTTP ${resp.status}`
    let hint = ''
    try {
      const payload = JSON.parse(await resp.text())
      msg = payload?.error || msg
      hint = payload?.hint || ''
    } catch {
      /* 非 JSON 就沿用状态码描述 */
    }
    throw new ApiError(msg, { status: resp.status, hint })
  }

  const blob = await resp.blob()
  const name = filename || filenameFromKey(key)
  triggerBlobDownload(blob, name)
  return { name, size: blob.size }
}

// filenameFromKey 从对象名里取文件名（后端生成的名字，不是用户输入）。
export function filenameFromKey(key) {
  const parts = String(key || '').split('/')
  const last = parts[parts.length - 1]
  return last || 'backup.tar.gz'
}

// triggerBlobDownload 触发浏览器下载。
//
// 单独抽出来是为了能在测试里替换掉（jsdom 没有真正的下载行为）。
function triggerBlobDownload(blob, name) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  // 立刻回收：备份文件可能几十 MB，留着会一直占内存。
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

// ---------------------------------------------------------------------------
// 载荷归一化
// ---------------------------------------------------------------------------
//
// normalizeTaskPayload / normalizeStoragePayload 的逻辑放在
// views/backupLogic.js 里（纯函数、可单测），本文件在顶部 import 进来直接用，
// 避免两处各写一份必然漂移。它们也在 views 层被直接引用。
