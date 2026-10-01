// 计划任务接口封装（阶段五 5.2）。
//
// 约定与 api/client.js、api/services.js、api/files.js、api/sites.js、
// api/ssl.js、api/store.js、api/firewall.js 保持一致：带超时、携带会话
// Cookie、失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// 超时取值。
//
// 读操作只读一个文件（或 fork 一次 crontab），给 15s 已经宽松。
// 写操作走「读 → 备份 → 写包装脚本 → 写 crontab → 失败回滚」整条链路，
// 后端的整条预算是 commandTimeout×4（默认 40s），因此前端给 60s：
// 必须**长于**后端，否则后端还在回滚时前端先报超时，
// 用户会以为没生效而重复提交——那才是真正的危险动作。
const CRON_READ_TIMEOUT_MS = 15000
const CRON_WRITE_TIMEOUT_MS = 60000

async function request(path, { timeout = CRON_READ_TIMEOUT_MS, ...init } = {}) {
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
      throw new ApiError(`请求超时（${timeout / 1000}s）：${path}`, { cause: err })
    }
    throw new ApiError(`无法连接后端：${err.message}`, { cause: err })
  } finally {
    clearTimeout(timer)
  }

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
    // 本模块有四处错误语义，光看 status 会让用户做出**错误的下一步动作**：
    //
    //   428 缺少确认     —— 该去点确认框，不是重试
    //   409 并发冲突     —— 必须「刷新后重新编辑」，直接重试会覆盖别人的改动
    //   409 不可接管     —— 该去 crontab -e，刷新也没用
    //   502 且 rolled_back —— 改动已自动回滚，crontab 还是旧的；
    //                         而 rollback_error 非空时**必须**把备份路径
    //                         顶到用户脸上，那是唯一的恢复手段
    //
    // kind / field 是后端给出的分类与字段名，直接展示或挂到表单项即可。
    err.kind = payload?.kind || ''
    err.field = payload?.field || ''
    err.confirmRequired = resp.status === 428 ||
      resp.headers?.get?.('X-Lipanel-Confirm-Required') === 'true'
    err.editConflict = resp.status === 409 && payload?.kind === '任务已被外部修改'
    err.notAdoptable = resp.status === 409 && payload?.kind === '任务不可由面板接管'
    err.unavailable = resp.status === 503
    err.rolledBack = payload?.rolled_back === true
    err.rollbackError = payload?.rollback_error || ''
    err.backupPath = payload?.backup_path || ''
    err.restoreHint = payload?.restore_hint || ''
    throw err
  }

  return payload
}

function postJSON(path, body, timeout = CRON_WRITE_TIMEOUT_MS) {
  return request(path, {
    method: 'POST',
    timeout,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
}

// ---------------------------------------------------------------------------
// 读操作
// ---------------------------------------------------------------------------

// fetchCronStatus 查询模块状态（面板在改谁的 crontab、是否可用、备份、权限）。
export function fetchCronStatus() {
  return request('/api/cron')
}

// fetchCronJobs 查询任务列表（含非面板添加的行与只读的全局设置行）。
export function fetchCronJobs() {
  return request('/api/cron/jobs')
}

// fetchCronLogs 查询某任务的执行日志。
//
// 只传 id：**没有任何参数能指定日志路径**（那是任意文件读取的入口）。
export function fetchCronLogs(id, lines = 200) {
  const qs = new URLSearchParams()
  qs.set('lines', String(lines))
  return request(`/api/cron/jobs/${encodeURIComponent(id)}/logs?${qs.toString()}`)
}

// fetchCronAudit 查询操作审计。
export function fetchCronAudit({ limit = 100, jobId = '', user = '', outcome = '' } = {}) {
  const qs = new URLSearchParams()
  qs.set('limit', String(limit))
  if (jobId) qs.set('job_id', jobId)
  if (user) qs.set('user', user)
  if (outcome) qs.set('outcome', outcome)
  return request(`/api/cron/audit?${qs.toString()}`)
}

// validateCronExpr 预校验表达式并取回中文描述与未来 5 次执行时间。
//
// 表达式非法时后端**仍返回 200**（valid=false + error），因为这是表单
// 实时校验：用户每敲一个字符就弹一次「请求失败」会淹没真正有用的提示。
export function validateCronExpr(expression) {
  return postJSON('/api/cron/validate', { expression }, CRON_READ_TIMEOUT_MS)
}

// ---------------------------------------------------------------------------
// 写操作
// ---------------------------------------------------------------------------

// createCronJob 新增任务。
export function createCronJob({ expression, command, comment = '', expectedIds = [] }) {
  return postJSON('/api/cron/jobs', {
    expression,
    command,
    comment,
    expected_ids: expectedIds,
  })
}

// updateCronJob 编辑任务（非面板行编辑即「收编」）。
export function updateCronJob(id, { expression, command, comment = '', expectedIds = [] }) {
  return request(`/api/cron/jobs/${encodeURIComponent(id)}`, {
    method: 'PUT',
    timeout: CRON_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      expression,
      command,
      comment,
      expected_ids: expectedIds,
    }),
  })
}

// deleteCronJob 删除任务。
//
// ########## confirm 必须为 true ##########
//
// 后端强制校验：不带 confirm 一律 **428 Precondition Required**。
// 前端弹窗只是体验，服务端强制才是边界——调用方忘了传，
// 后端也不会真的删掉任务。
export function deleteCronJob(id, { confirm = false, expectedIds = [] } = {}) {
  return request(`/api/cron/jobs/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    timeout: CRON_WRITE_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ confirm, expected_ids: expectedIds }),
  })
}
