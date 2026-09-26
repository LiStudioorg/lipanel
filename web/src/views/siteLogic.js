// 网站管理页的纯逻辑（阶段四 4.3）。
//
// 为什么单独一个模块而不是写在 SiteView.vue 里：
//
//   1. **可测**。本仓库前端测试用 node:test，没有 DOM（不引入 jsdom，
//      保持「轻量」约束），因此组件本身无法直接 import。
//      把可判定逻辑抽成纯函数，测试就能锁住**真正被使用的代码**——
//      如果测试里重述一遍逻辑，组件改了而测试没改也照样全绿，
//      那种测试是假的。
//
//   2. **可读**。组件专注于视图装配，这些"什么算合法站点名""按钮该不该禁用"
//      的判定集中在一处，比散落在模板与 render 函数里更好审查。
//
//   3. **与后端规则一致**。下面的校验规则逐条对应
//      internal/site/validate.go。**但前端校验只是体验优化**：
//      真正的强制点始终在后端（后端会独立再校验一遍）。
//      前端做校验的价值是让用户在提交前就看到问题，而不是等一次
//      往返 + 一个错误弹窗。

// ---------------------------------------------------------------------------
// 站点类型
// ---------------------------------------------------------------------------

// SITE_TYPES 是站点类型的展示元数据。
export const SITE_TYPES = {
  static: { label: '静态站', type: 'info', desc: '由 nginx 直接提供磁盘上的文件' },
  proxy: { label: '反向代理', type: 'warning', desc: '把请求转发给本机或内网的后端服务' },
}

// typeMeta 返回类型展示元数据，未知类型安全回落。
export function typeMeta(type) {
  return SITE_TYPES[type] || { label: type || '未知', type: 'default', desc: '' }
}

// ---------------------------------------------------------------------------
// 表单校验（与后端 internal/site/validate.go 保持一致）
// ---------------------------------------------------------------------------

// 站点名规则。
//
// 逐条对应后端 ValidSiteName：
//   - 长度 1~64
//   - 只允许字母、数字、点、下划线、短横线
//   - 必须以字母或数字开头结尾
//   - 不允许 ".."
//   - 保留名 default / audit / capabilities
//
// 域名与前缀的字符集与后端一致：任何 nginx 元字符（; { } $ ` ' " # 空白 换行）
// 都必须在前端就被拦下并给出解释，而不是让用户提交后收到一个 400。
const SITE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]$/
const SINGLE_CHAR_NAME_PATTERN = /^[A-Za-z0-9]$/

export const MAX_SITE_NAME_LEN = 64
export const MAX_DOMAIN_LEN = 253

// RESERVED_SITE_NAMES 对应后端的 reservedSiteNames。
//
// default 是发行版自带的默认站点，audit / capabilities 是接口路径段。
// 前端提前拦下能让用户立刻明白为什么不能用，而不是收到一个 400。
export const RESERVED_SITE_NAMES = ['default', 'audit', 'capabilities']

// DOMAIN_LABEL_PATTERN 对应后端 domainLabelPattern。
const DOMAIN_LABEL_PATTERN = /^[A-Za-z0-9_*][A-Za-z0-9_*-]*$/

// NGINX_METACHARACTERS 是能破坏 nginx 配置语法的字符。
//
// 单独列出并导出，是为了让错误提示能**指出具体是哪个字符**：
// 「含非法字符 ';'」比「格式不正确」有用得多，尤其在排查注入尝试时。
export const NGINX_METACHARACTERS = [
  ';', '{', '}', '$', '`', "'", '"', '#', '\n', '\r', '\t', ' ', '\\', '|', '&', '<', '>',
]

// findMetacharacter 返回字符串里第一个 nginx 元字符（没有则返回 ''）。
export function findMetacharacter(value) {
  for (const ch of NGINX_METACHARACTERS) {
    if (String(value ?? '').includes(ch)) return ch
  }
  return ''
}

// describeChar 把控制字符转成可读写法，便于在提示里显示。
export function describeChar(ch) {
  if (ch === '\n') return '\\n（换行）'
  if (ch === '\r') return '\\r（回车）'
  if (ch === '\t') return '\\t（制表符）'
  if (ch === ' ') return '空格'
  return ch
}

// validateSiteName 校验站点名，返回错误信息（合法时返回 ''）。
//
// 前端校验的定位是**体验**：真正的强制点在后端。
// 因此这里的规则宁可与后端逐条对齐、也不做"更宽松的猜测"——
// 前端放过而后端拒绝，用户体验是"点提交 → 转圈 → 报错"；
// 前端拦住而后端也拦，用户体验是"输入时就看到红字"。
export function validateSiteName(name, { isEdit = false } = {}) {
  const value = String(name ?? '')
  // 编辑时不校验站点名：它是配置文件名的来源，本站点不支持改名。
  if (isEdit) return ''

  if (!value) return '请填写站点名'
  if (value.length > MAX_SITE_NAME_LEN) {
    return `站点名不能超过 ${MAX_SITE_NAME_LEN} 个字符（当前 ${value.length}）`
  }

  const meta = findMetacharacter(value)
  if (meta) {
    return `站点名不能包含 ${describeChar(meta)}（会导致 nginx 配置注入）`
  }
  if (value.includes('/') || value.includes('\\')) {
    return '站点名不能包含路径分隔符 / 或 \\'
  }
  if (value.includes('..')) {
    return '站点名不能包含 ".."（路径穿越）'
  }
  if (RESERVED_SITE_NAMES.includes(value.toLowerCase())) {
    return `"${value}" 是系统或接口保留名，请换一个`
  }

  const ok = value.length === 1
    ? SINGLE_CHAR_NAME_PATTERN.test(value)
    : SITE_NAME_PATTERN.test(value)
  if (!ok) {
    return '站点名只允许字母、数字、点、下划线、短横线，且必须以字母或数字开头结尾'
  }
  return ''
}

// validateDomain 校验域名，返回错误信息。
//
// 逐条对应后端 ValidDomain：
//   - 长度不超过 253
//   - 只能是 ASCII 可见字符（不允许控制字符与空白）
//   - 支持 "_"（默认站点）与 "*.example.com"（通配）
//   - 每个标签不超过 63 字符，不能以短横线开头结尾
export function validateDomain(domain) {
  const value = String(domain ?? '')
  if (!value) return '请填写域名'

  const meta = findMetacharacter(value)
  if (meta) {
    return `域名不能包含 ${describeChar(meta)}（会导致 nginx 配置注入）`
  }
  if (value.length > MAX_DOMAIN_LEN) {
    return `域名不能超过 ${MAX_DOMAIN_LEN} 个字符`
  }
  // 默认站点占位符。
  if (value === '_') return ''

  let rest = value
  if (rest.startsWith('*.')) {
    rest = rest.slice(2)
    if (!rest) return '通配域名缺少后面的部分，应写成 *.example.com'
  }
  if (rest === '*') {
    return '不支持裸通配 "*"，通配请写成 *.example.com，默认站点请填 "_"'
  }
  if (rest.endsWith('.')) return '域名不能以 "." 结尾'
  if (rest.includes('..')) return '域名含有空的标签（连续的点）'

  for (const label of rest.split('.')) {
    if (label.length > 63) return `域名的标签 "${label}" 超过 63 个字符`
    if (!DOMAIN_LABEL_PATTERN.test(label)) {
      return `域名的标签 "${label}" 含有非法字符（只允许字母、数字、下划线、短横线与通配星号）`
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return `域名的标签 "${label}" 不能以短横线开头或结尾`
    }
  }
  return ''
}

// validateRoot 校验静态站根目录，返回错误信息。
//
// 逐条对应后端 ValidRoot：绝对路径、字符集白名单、已规范化、不允许 /。
//
// 这里**不检查目录是否真实存在**：前端无法知道服务器上的目录情况，
// 真正的存在性（与 4.2 白名单校验）由后端负责。前端只拦"形态明显不对"的输入。
export function validateRoot(root) {
  const value = String(root ?? '')
  if (!value) return '请填写站点根目录'

  if (!value.startsWith('/')) return '根目录必须是绝对路径（以 / 开头）'
  if (value === '/') return '不允许把 / 作为站点根目录（会让 nginx 暴露整个文件系统）'

  const meta = findMetacharacter(value)
  if (meta) {
    return `根目录不能包含 ${describeChar(meta)}（nginx 配置中需要转义）`
  }
  if (!/^\/[A-Za-z0-9._/-]*$/.test(value)) {
    return '根目录只允许字母、数字、点、下划线、短横线与 /'
  }
  // 路径穿越：判据是"存在 .. 路径段"，而不是"字符串里出现 .."
  // （后者会把合法目录名 my..site 也误杀）。与后端判据保持一致。
  if (value.split('/').includes('..')) {
    return '根目录不能包含 ".." 路径段（路径穿越）'
  }
  // 规范化：/var//www 或 /var/www/ 都应提示用户写成规范形式。
  if (normalizePath(value) !== value) {
    return `路径未规范化，请改用 ${normalizePath(value)}`
  }
  return ''
}

// normalizePath 做一个与后端 filepath.Clean 等价的简化规范化。
//
// 只处理前端能确定的两件事：折叠重复斜杠、去掉末尾斜杠。
// 刻意**不**实现完整的 Clean（不解析 ".."）——那需要更复杂的语义，
// 而含 ".." 的路径已被上面直接拒绝，不需要前端来"修正"。
export function normalizePath(p) {
  let out = String(p ?? '').replace(/\/{2,}/g, '/')
  if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1)
  return out
}

// validateUpstream 校验反向代理目标，返回错误信息。
//
// 逐条对应后端 ValidUpstream：
//   - 只支持 http / https
//   - 拒绝 unix socket（会让 nginx 访问本机任意 socket，属于越权面）
//   - 拒绝内嵌凭据、查询串、片段
//   - 端口 1~65535
//   - 路径部分字符集白名单
export function validateUpstream(upstream) {
  const raw = String(upstream ?? '')
  if (!raw.trim()) return '请填写后端地址，例如 http://127.0.0.1:3000'

  const meta = findMetacharacter(raw)
  if (meta) {
    return `后端地址不能包含 ${describeChar(meta)}（会导致 nginx 配置注入）`
  }

  // 补协议后再校验，与后端 "先归一化、再校验" 的链路一致。
  const value = raw.includes('://') ? raw : `http://${raw}`

  let url
  try {
    url = new URL(value)
  } catch {
    return `后端地址格式不正确：${raw}`
  }

  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme !== 'http' && scheme !== 'https') {
    return `不支持协议 ${scheme}（只允许 http 与 https）`
  }
  if (url.username || url.password) {
    return '后端地址不应包含用户名/密码（proxy_pass 不会使用它们）'
  }
  if (url.search || url.hash) {
    return '后端地址不应包含查询串或 # 片段'
  }
  // unix socket：URL 解析会把 "unix:/var/run/docker.sock" 的 host 解成 "unix"，
  // 必须点名拒绝（详见后端 validate.go 的说明）。
  if (url.hostname.toLowerCase() === 'unix') {
    return '不支持 unix socket 形式（unix:/path 会让 nginx 访问本机任意 socket）'
  }
  if (!url.hostname) return '后端地址缺少主机名'

  if (url.port !== '') {
    const port = Number(url.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return `端口 ${url.port} 非法（应为 1~65535）`
    }
  }
  // 路径部分字符集白名单（与后端 upstreamPathPattern 一致）。
  if (url.pathname && url.pathname !== '/') {
    if (!/^[A-Za-z0-9._~/-]*$/.test(url.pathname)) {
      return '后端地址的路径部分只允许字母、数字、点、下划线、短横线、波浪线与 /'
    }
    if (url.pathname.split('/').includes('..')) {
      return '后端地址的路径部分不能包含 ".." 段'
    }
  }
  return ''
}

// ---------------------------------------------------------------------------
// 表单组装与整体校验
// ---------------------------------------------------------------------------

// emptyForm 返回一个空的新建表单。
//
// 默认类型是 static、默认启用：绝大多数用户建站是为了立刻能访问。
export function emptyForm() {
  return {
    name: '',
    domain: '',
    type: 'static',
    root: '',
    upstream: '',
    enabled: true,
  }
}

// formFromSite 把站点对象转成表单对象（用于编辑）。
export function formFromSite(site) {
  return {
    name: site?.name || '',
    domain: site?.domain || '',
    type: site?.type || 'static',
    root: site?.root || '',
    upstream: site?.upstream || '',
    enabled: Boolean(site?.enabled),
  }
}

// validateForm 整体校验，返回 { field: message } 对象（无错误时为空对象）。
//
// 返回**全部**错误而不是遇到第一个就返回：表单应当一次性标出所有问题，
// 让用户改完一轮就能提交，而不是"改一个、提交、又发现一个"。
export function validateForm(form, { isEdit = false } = {}) {
  const errors = {}

  const nameErr = validateSiteName(form?.name, { isEdit })
  if (nameErr) errors.name = nameErr

  const domainErr = validateDomain(form?.domain)
  if (domainErr) errors.domain = domainErr

  if (form?.type === 'static') {
    const rootErr = validateRoot(form?.root)
    if (rootErr) errors.root = rootErr
    // 类型切换时残留的字段必须清空——后端会直接拒绝（不静默丢弃），
    // 前端提前提示能让用户明白为什么。
    if (String(form?.upstream ?? '').trim()) {
      errors.upstream = '静态站不需要后端地址，请清空该字段（或把类型改为反向代理）'
    }
  } else if (form?.type === 'proxy') {
    const upErr = validateUpstream(form?.upstream)
    if (upErr) errors.upstream = upErr
    if (String(form?.root ?? '').trim()) {
      errors.root = '反向代理不需要根目录，请清空该字段（或把类型改为静态站）'
    }
  } else {
    errors.type = '请选择站点类型'
  }

  return errors
}

// buildSitePayload 把表单转成后端请求体。
//
// 关键点：**只发送当前类型用得上的字段**，另一个字段显式置空。
// 后端的策略是"类型与字段不匹配时直接拒绝"（而不是静默丢弃），
// 因此这里必须把无关字段清干净，否则切换类型后会一直提交失败。
export function buildSitePayload(form) {
  const payload = {
    name: String(form?.name ?? '').trim(),
    domain: String(form?.domain ?? '').trim(),
    type: form?.type,
    root: '',
    upstream: '',
    enabled: Boolean(form?.enabled),
  }
  if (form?.type === 'static') {
    payload.root = String(form?.root ?? '').trim()
  } else if (form?.type === 'proxy') {
    payload.upstream = String(form?.upstream ?? '').trim()
  }
  return payload
}

// ---------------------------------------------------------------------------
// 展示辅助
// ---------------------------------------------------------------------------

// formatTarget 返回表格里"根目录 / 反代目标"那一列的文本。
//
// 两种类型的展示语义不同，集中在一处避免模板里写三元表达式
// （那样测试也覆盖不到）。
export function formatTarget(site) {
  if (!site) return '-'
  if (site.type === 'proxy') return site.upstream || '-'
  if (site.type === 'static') return site.root || '-'
  // 类型解析不出来（外部配置）：退回展示已知的字段，都没有就显示占位。
  return site.root || site.upstream || '-'
}

// targetLabel 返回该列的表头文案。
export function targetLabel(type) {
  if (type === 'proxy') return '反代目标'
  return '根目录'
}

// statusMeta 返回站点状态的展示元数据。
//
// 三种状态：
//   enabled   已启用（nginx 会加载它）
//   disabled  已禁用（配置仍在磁盘上，可随时重新启用）
//   external  非面板创建（只读，面板不会修改）
export function statusMeta(site) {
  if (site && !site.generated) {
    return { type: 'default', text: '外部配置', readonly: true }
  }
  if (site?.enabled) return { type: 'success', text: '已启用' }
  return { type: 'default', text: '已禁用' }
}

// canOperate 判断某个站点是否允许面板操作（编辑/删除/启停）。
//
// 外部配置（非面板生成）一律只读：面板会用模板**整体重写**配置文件，
// 那会把用户手写的配置彻底抹掉。
//
// 注意这只是**体验**（按钮置灰）；真正的强制点在后端
// （site.Manager 会返回 ErrExternal → 409）。
export function canOperate(site) {
  if (!site) return false
  return Boolean(site.generated)
}

// isSiteBusy 判断某站点是否有操作在途。
//
// 用对象而不是单个布尔量：操作 A 站点时不该让 B 站点的按钮也转圈。
export function isBusy(busyMap, name) {
  return Boolean(busyMap?.[name])
}

// actionDisabled 汇总某行某按钮的禁用条件。
//
// 禁用来源有四：nginx 不可用、无写权限、站点是外部配置、有操作在途。
// 集中在一处是为了让"为什么这个按钮点不动"只有一个答案来源。
export function actionDisabled({ available, canWrite, site, busy }) {
  if (!available) return true
  if (!canWrite) return true
  if (!canOperate(site)) return true
  return Boolean(busy)
}

// filterSites 按关键字与状态过滤站点列表。
//
// 纯函数：返回新数组，不修改入参（模板里直接绑定它，若原地修改
// 会破坏 Vue 的响应式比较，导致列表不更新）。
export function filterSites(sites, { keyword = '', onlyEnabled = false } = {}) {
  let list = Array.isArray(sites) ? sites : []
  if (onlyEnabled) {
    list = list.filter((s) => s.enabled)
  }
  const kw = String(keyword ?? '').trim().toLowerCase()
  if (kw) {
    list = list.filter((s) => {
      const haystack = [s.name, s.domain, s.root, s.upstream]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return haystack.includes(kw)
    })
  }
  return list
}

// deleteConfirmText 生成删除二次确认的文案。
//
// 计划明确要求"删除操作二次确认，写明域名"。
// 域名必须出现在正文里，而不是只显示站点名——用户对域名的记忆
// 远比对内部站点名清晰，写错名字的站点被误删是最难挽回的事故。
export function deleteConfirmText(site) {
  const domain = site?.domain || site?.name || '（未知域名）'
  return (
    `确定要删除站点「${domain}」吗？\n\n` +
    `站点名：${site?.name || '-'}\n` +
    `${targetLabel(site?.type)}：${formatTarget(site)}\n\n` +
    `该操作会删除服务器上的 nginx 配置文件并重新加载 nginx，` +
    `删除后无法在面板中恢复。`
  )
}

// toggleConfirmText 生成启用/禁用的确认文案。
export function toggleConfirmText(site, enabled) {
  const domain = site?.domain || site?.name || '（未知域名）'
  if (enabled) {
    return `确定要启用站点「${domain}」吗？启用后 nginx 会立即加载该配置。`
  }
  return (
    `确定要禁用站点「${domain}」吗？\n\n` +
    `配置内容会保留在服务器上，随时可以重新启用。`
  )
}

// summarize 统计站点数量，用于列表页头展示。
export function summarize(sites) {
  const list = Array.isArray(sites) ? sites : []
  let enabled = 0
  let external = 0
  for (const s of list) {
    if (s.enabled) enabled++
    if (!s.generated) external++
  }
  return { total: list.length, enabled, external }
}
