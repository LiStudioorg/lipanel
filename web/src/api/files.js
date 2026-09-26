// 文件管理接口封装（阶段四 4.2）。
//
// 约定与 api/services.js、api/plugins.js 保持一致：所有请求带超时、
// 携带会话 Cookie、失败时抛出 ApiError（含后端给的 hint），
// Loading 与错误提示由调用方负责。
import { ApiError } from '@/api/client'

// 上传/下载可能很慢（后端把这两个接口的读写超时放宽到 30 分钟），
// 因此前端也要给出足够宽的超时，否则会出现"后端还在传、前端已超时"的错判。
const TRANSFER_TIMEOUT_MS = 30 * 60 * 1000

// request 与 services.js 的同名函数保持同样的行为，
// 唯一的差别是**默认超时更宽**：列目录意味着可能扫描上万个条目。
async function request(path, { timeout = 30000, ...init } = {}) {
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
      throw new ApiError(`请求超时（${Math.round(timeout / 1000)}s）：${path}`, { cause: err })
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
    // hint 是后端给出的「怎么办」（越权路径提示调整 -file-root、
    // 二进制文件提示用下载等）。不带 hint 用户只知道失败了。
    throw new ApiError(msg, { status: resp.status, hint: payload?.hint })
  }
  if (payload === null) {
    throw new ApiError('后端返回了非 JSON 内容，请检查接口或反向代理配置')
  }
  return payload
}

// encodePath 把绝对路径安全地放进查询串。
//
// encodeURIComponent 会把 "/" 编成 %2F，而 Go 的 ServeMux 在
// 解析前会做一次规范化解码，%2F 会被还原——但为了不让路径在
// 各层出现"编了又解、解了又编"的歧义，这里只编码真正需要编码的字符。
// 路径里合法的字符（"/"、中文、空格）保持原样，交给 URLSearchParams 处理。
function withPath(path) {
  const params = new URLSearchParams()
  params.set('path', path ?? '')
  return params.toString()
}

// 列出目录内容。返回 DirListing（entries/parent/root/truncated...）。
export function fetchListing(path) {
  return request(`/api/files?${withPath(path)}`)
}

// 获取白名单根目录、生效限制与当前用户的权限。
//
// 返回 { roots, permissions, limits, audit }。
// 前端据此渲染"可访问区域"、上传大小上限，以及无权时置灰按钮。
export function fetchFileMeta() {
  return request('/api/files/roots')
}

// 读取文本文件内容。二进制/超限的文件后端会返回 415/413 并带 hint。
export function fetchFileContent(path) {
  return request(`/api/files/content?${withPath(path)}`)
}

// 保存文本文件内容。
//
// overwrite 必须显式为 true 才允许覆盖已有文件——后端的默认是拒绝，
// 前端也必须把这一层"确认覆盖"暴露给用户，而不是默默传 true。
export function saveFileContent(path, content, { overwrite = false } = {}) {
  return request('/api/files/content', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, content, overwrite }),
  })
}

// 新建目录。
export function createDirectory(path) {
  return request('/api/files/mkdir', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  })
}

// 重命名（只支持同目录改名：newName 是文件名，不是路径）。
export function renameEntry(path, newName, { overwrite = false } = {}) {
  return request('/api/files/rename', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, new_name: newName, overwrite }),
  })
}

// 删除。递归删除非空目录必须显式传 recursive=true——
// 后端默认拒绝（409），前端据此弹出"递归删除不可恢复"的二次确认。
export function deleteEntry(path, { recursive = false } = {}) {
  return request('/api/files/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, recursive }),
  })
}

// downloadURL 生成带鉴权的下载链接。
//
// 下载走浏览器原生导航（<a href>），而不是 fetch + Blob：
// 后者会把整个文件读进内存再触发保存，大文件下标签页直接崩掉。
// 会话 Cookie 会随导航自动带上，后端 ServeContent 也支持 Range 续传。
export function downloadURL(path) {
  return `/api/files/download?${withPath(path)}`
}

// uploadFile 用 XHR 上传单个文件，以便拿到**进度**。
//
// 为什么不用 fetch：fetch 至今没有可用的上传进度事件
// （ReadableStream 请求体在多数浏览器里仍受限），
// 而上传是最需要进度反馈的操作（用户要判断"是不是卡住了"）。
//
// 返回一个可取消的句柄：{ promise, abort }。
export function uploadFile({ dir, file, overwrite = false, onProgress } = {}) {
  const form = new FormData()
  form.append('path', dir)
  form.append('filename', file.name)
  if (overwrite) form.append('overwrite', 'true')
  // 注意字段名固定为 file，与后端 MultipartReader 的分支一致。
  form.append('file', file, file.name)

  const xhr = new XMLHttpRequest()
  const promise = new Promise((resolve, reject) => {
    xhr.open('POST', '/api/files/upload', true)
    xhr.withCredentials = true
    xhr.timeout = TRANSFER_TIMEOUT_MS
    xhr.setRequestHeader('Accept', 'application/json')

    xhr.upload.onprogress = (ev) => {
      if (onProgress && ev.lengthComputable) {
        onProgress(Math.round((ev.loaded / ev.total) * 100))
      }
    }

    xhr.onload = () => {
      let payload = null
      try {
        payload = JSON.parse(xhr.responseText)
      } catch {
        payload = null
      }
      if (xhr.status >= 200 && xhr.status < 300 && payload) {
        resolve(payload)
        return
      }
      const msg = payload?.error || xhr.responseText?.slice(0, 200) || `HTTP ${xhr.status}`
      reject(new ApiError(msg, { status: xhr.status, hint: payload?.hint }))
    }
    xhr.onerror = () => reject(new ApiError('上传失败：网络错误'))
    xhr.ontimeout = () => reject(new ApiError('上传超时，请重试或改用更小的文件'))
    xhr.onabort = () => reject(new ApiError('上传已取消'))

    xhr.send(form)
  })

  return { promise, abort: () => xhr.abort() }
}

// 查询文件操作审计（可选，设置页/排查用）。
export function fetchFileAudit({ user = '', action = '', path = '', outcome = '', limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (user) params.set('user', user)
  if (action) params.set('action', action)
  if (path) params.set('path', path)
  if (outcome) params.set('outcome', outcome)
  if (limit) params.set('limit', String(limit))
  const query = params.toString()
  return request(`/api/files/audit${query ? `?${query}` : ''}`)
}
