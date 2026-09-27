// 软件商店接口封装（阶段四 4.5）。
//
// 约定与 api/client.js、api/services.js、api/files.js、api/sites.js、
// api/ssl.js 保持一致：所有请求带超时、携带会话 Cookie、
// 失败时抛出 ApiError，由调用方负责 Loading 与错误提示。
import { ApiError } from '@/api/client'

// ########## 这里的超时与其它模块**相反** ##########
//
// 其它模块的写接口是同步的（改配置、跑一次 certbot），因此超时要放宽。
// 软件商店的写接口是**异步**的：它创建任务后立刻返回 202，
// 真正的安装跑在后台，进度靠轮询 /api/store/tasks/{id}。
//
// 所以这里的写超时应该**很短**（10s）：一个创建任务的请求花 10 秒
// 还没回来，说明后端本身出了问题，而不是"安装还在进行"。
// 反过来，如果照搬 SSL 的 180s，用户在点击后会白白等三分钟
// 才看到错误——而此时任务可能早就创建好了，只是响应没回来。
const STORE_WRITE_TIMEOUT_MS = 10000

// 读取类请求的超时。
//
// 安装状态查询要遍历清单里的全部包名并**批量**执行一次
// dpkg-query/rpm（不是逐个包起进程），实测在几十毫秒级；
// 但机器负载高时可能到 1~2 秒，因此给到 20s。
const STORE_READ_TIMEOUT_MS = 20000

async function request(path, { timeout = STORE_READ_TIMEOUT_MS, ...init } = {}) {
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
    // ########## 状态码必须原样透传给界面 ##########
    //
    // 本模块的错误**必须按状态码分类处理**，因为用户的下一步动作
    // 完全取决于它：
    //
    //  409 已有任务在跑 / 版本冲突 → 重试没有意义，要先处理冲突
    //  503 本机没有包管理器        → 重试多少次都不会成功
    //  400/404 输入问题            → 改一下就能成功
    //  500 其它                    → 可以重试
    //
    // 只显示一句 error 会让用户对着"已有任务在跑"反复点安装，
    // 每次都被拒绝，而他不知道只要等一会儿就好。
    throw new ApiError(msg, {
      status: resp.status,
      hint: payload?.hint,
      // available 让界面能区分"这台机器装不了"与"这次装不了"。
      requeue: resp.status === 409,
    })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

function sendJSON(path, body, { timeout = STORE_WRITE_TIMEOUT_MS } = {}) {
  const init = { method: 'POST' }
  // 不带参数时省略 body：后端对"空请求体"（等价于用默认版本）
  // 与"畸形请求体"（400）的处理不同。
  if (body !== undefined && body !== null) {
    init.headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    }
    init.body = JSON.stringify(body)
  }
  return request(path, { ...init, timeout })
}

// 获取软件清单与安装状态。
//
// 返回 { software, counts, available, unavailable_reason, running,
//        dry_run, environment, scanned_at, audit, permissions }。
//
// available 为 false 表示装不了（没探测到包管理器），
// 此时界面应展示 unavailable_reason 并禁用安装按钮，
// **但清单本身仍然有效**，不该整页报错。
export function fetchStoreList() {
  return request('/api/store', { timeout: STORE_READ_TIMEOUT_MS })
}

// 获取环境能力探测。
export function fetchStoreCapabilities() {
  return request('/api/store/capabilities', { timeout: STORE_READ_TIMEOUT_MS })
}

// 获取软件商店操作审计。
// options 支持 { target, version, user, action, outcome, limit }。
export function fetchStoreAudit({
  target = '',
  version = '',
  user = '',
  action = '',
  outcome = '',
  limit = 100,
} = {}) {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (version) params.set('version', version)
  if (user) params.set('user', user)
  if (action) params.set('action', action)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/store/audit${query ? `?${query}` : ''}`)
}

// 获取最近的任务列表。
//
// 刷新页面后用它恢复"正在安装"的界面：不知道有任务在跑，
// 用户会再点一次安装（然后被 409 拒绝）。
export function fetchStoreTasks({ limit = 20 } = {}) {
  const params = new URLSearchParams()
  if (limit) params.set('limit', String(limit))
  return request(`/api/store/tasks?${params.toString()}`)
}

// 获取单个任务的进度与增量日志。
//
// since 是日志游标：传上一次响应的 next_since 即可只取新增日志。
export function fetchStoreTask(id, { since = 0 } = {}) {
  const params = new URLSearchParams()
  if (since) params.set('since', String(since))
  const query = params.toString()
  return request(
    `/api/store/tasks/${encodeURIComponent(id)}${query ? `?${query}` : ''}`,
    // 轮询请求要短超时：卡住的轮询比不轮询更糟（界面看起来"在动"，
    // 其实早就没进展了）。
    { timeout: 10000 },
  )
}

// 安装软件（返回 202 + 任务 ID）。
//
// 版本留空时后端使用清单里的默认版本。
export function installSoftware(name, { version = '', skipDependencies = false } = {}) {
  const body = {}
  if (version) body.version = version
  if (skipDependencies) body.skip_dependencies = true
  return sendJSON(`/api/store/${encodeURIComponent(name)}/install`, body)
}

// 卸载软件（返回 202 + 任务 ID）。
export function uninstallSoftware(name, { version = '' } = {}) {
  const body = {}
  if (version) body.version = version
  return sendJSON(`/api/store/${encodeURIComponent(name)}/uninstall`, body)
}

// 轮询任务直到结束。
//
// ########## 为什么把轮询封装在这里 ##########
//
// 轮询有三个容易写错的细节，散落在组件里必然出错：
//
//   ① 游标：必须用响应里的 next_since，而不是"最后一条日志的 seq"——
//      没有新日志时前端无从计算，写成 0 就会每轮全量拉取。
//   ② 终止条件：任务的 status 进入终态才停；只按 done 字段判断
//      也可以，但网络中断时 done 永远等不到，必须同时有次数上限。
//   ③ 清理：组件卸载时必须停止，否则留下一个永不停止的定时器。
//
// onUpdate 每轮都会被调用（传入最新的 { task, logs, done }），
// 由调用方决定怎么渲染。
export function pollStoreTask(
  id,
  { since = 0, intervalMs = 1500, maxRounds = 400, onUpdate, signal } = {},
) {
  let cursor = since
  let rounds = 0

  return new Promise((resolve, reject) => {
    let stopped = false

    const stop = () => {
      stopped = true
      clearTimeout(timer)
    }

    // 外部取消（组件卸载）：不是错误，安静地停。
    if (signal) {
      if (signal.aborted) {
        resolve(null)
        return
      }
      signal.addEventListener('abort', () => {
        stop()
        resolve(null)
      })
    }

    let timer = null

    const tick = async () => {
      if (stopped) return
      rounds += 1
      if (rounds > maxRounds) {
        // 次数上限：任务卡在 running 时不能让前端无限轮询下去
        // （每次 1.5s，400 轮约 10 分钟，已经远超正常安装时间）。
        stop()
        reject(
          new ApiError(
            `轮询任务 ${id} 超过 ${maxRounds} 次仍未结束，请刷新页面查看最新状态`,
          ),
        )
        return
      }

      let payload
      try {
        payload = await fetchStoreTask(id, { since: cursor })
      } catch (err) {
        // 单次失败不终止轮询：安装可能还在进行，一次网络抖动
        // 不该让用户看到"安装失败"。连续失败由 maxRounds 兜底。
        if (!stopped) timer = setTimeout(tick, intervalMs)
        return
      }
      if (stopped) return

      if (payload.next_since !== undefined) {
        cursor = payload.next_since
      }
      if (typeof onUpdate === 'function') {
        onUpdate({ task: payload.task, logs: payload.logs || [], done: payload.done })
      }

      if (payload.done) {
        stop()
        resolve(payload.task)
        return
      }
      timer = setTimeout(tick, intervalMs)
    }

    tick()
  })
}
