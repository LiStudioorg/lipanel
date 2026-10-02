// 日志查看页的纯逻辑（阶段五 5.4.1）。
//
// 与 servicesLogic / fileLogic 同样动机：把可判定逻辑抽成纯函数，
// 便于 node:test 锁住**真正被使用的代码**（组件不可在无 DOM 环境 import）。

// LEVEL_META 把日志级别映射为展示文案与标签类型。
// 仅 system 源支持级别过滤。
export const LEVELS = [
  { value: '', label: '全部' },
  { value: 'error', label: '错误', type: 'error' },
  { value: 'warn', label: '警告', type: 'warning' },
  { value: 'info', label: '信息', type: 'info' },
  { value: 'debug', label: '调试', type: 'default' },
]

// sourceTypeMeta 映射 source.type 的展示信息。
export const SOURCE_TYPE_META = {
  system: { text: '系统日志', tag: 'primary' },
  app: { text: '应用日志', tag: 'success' },
}

// sourceTypeMetaOf 安全回落。
export function sourceTypeMetaOf(type) {
  return SOURCE_TYPE_META[type] || { text: type || '未知', tag: 'default' }
}

// buildQuery 组装查询参数。lines 自动收敛到 [1, 2000]。
export function buildQuery({ source, lines = 100, filter = '', level = '' } = {}) {
  const q = { source }
  if (!source) return { ...q }
  let n = Number(lines)
  if (!Number.isFinite(n) || n <= 0) n = 100
  if (n > 2000) n = 2000
  q.lines = n
  if (filter && filter.trim()) q.filter = filter.trim()
  if (level) q.level = level
  return q
}

// normalizeQuery 把后端 query 结果归一化为前端可渲染的结构。
// 后端返回 { entries: [{line, timestamp}], truncated, scanned }。
export function normalizeQuery(res = {}) {
  return {
    entries: Array.isArray(res.entries) ? res.entries : [],
    truncated: !!res.truncated,
    scanned: res.scanned || 0,
  }
}

// escapeHtml 转义用户不可信的日志行文本（防 XSS）。
// 日志内容可能来自任意进程输出，绝不能作为 HTML 注入。
// 注意：后端原样返回日志行，转义必须在渲染层完成（这里是安全的 <pre> 文本）。
export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// safeLineHeight 估算日志行的展示高度（长行折叠提示用），与 UI 无关的纯计算。
export function estimateLineHeight(line) {
  // 假设每行最多显示 160 字符（CSS 里做截断），据此判断是否需要"展开"。
  return line ? Math.ceil(line.length / 160) : 0
}

// autoRefreshCheck 判断当前是否应自动刷新：仅在登录态且无未读错误时。
export function autoRefreshCheck({ hasError = false } = {}) {
  return !hasError
}

// levelLabel 返回级别在选项里的项，未知安全回落为「全部」。
export function levelOption(value) {
  return LEVELS.find((l) => l.value === value) || LEVELS[0]
}