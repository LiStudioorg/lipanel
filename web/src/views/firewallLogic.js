// 防火墙页的纯逻辑（阶段四 4.6）。
//
// ########## 为什么逻辑要单独一个模块 ##########
//
// 这是本项目第 53 号坑位留下的纪律：前端逻辑若在测试文件里
// **照抄一遍**，组件改了测试也照样全绿——测试锁住的是副本，
// 不是真正运行的代码。
//
// 因此本文件被 FirewallView.vue 与 firewall.logic.test.mjs
// **共同 import**，测试断言的就是页面实际使用的那份实现。
//
// ########## 与后端的一致性 ##########
//
// 下面这些取值必须与 internal/firewall 完全一致，一旦漂移
// 界面就会显示出与真实情况相反的信息（例如把"拒绝"显示成"放行"——
// 那会让用户以为自己放行了端口，实际是被封的）：
//
//	BACKEND_LABEL / ACTION_META / KIND_META / OUTCOME_META
//	PROTECT_PANEL / PROTECT_SSH
//
// 因此测试会逐项断言这些常量。

// ---------------------------------------------------------------------------
// 后端
// ---------------------------------------------------------------------------

// BACKEND_LABEL 与 internal/firewall 的 BackendLabel 保持一致。
export const BACKEND_LABEL = {
  ufw: 'ufw',
  firewalld: 'firewalld',
  nftables: 'nftables',
  iptables: 'iptables',
  none: '未检测到',
}

// backendLabel 返回后端的展示名（未知值原样返回，便于排错）。
export function backendLabel(backend) {
  if (!backend) return '未知'
  return BACKEND_LABEL[backend] || backend
}

// BACKEND_HINT 是各后端的简短说明（展示在状态卡片里）。
export const BACKEND_HINT = {
  ufw: '规则按内容匹配，可直接删除',
  firewalld: '规则按内容匹配；带来源与拒绝规则以 rich rule 表达',
  nftables: '规则只能按句柄（handle）删除，解析不出句柄的规则不可删除',
  iptables: '规则按 iptables -S 解析出的精确规格删除',
}

// ---------------------------------------------------------------------------
// 动作与类别
// ---------------------------------------------------------------------------

// ACTION_META 与后端的 allow/deny 对齐。
export const ACTION_META = {
  allow: { label: '允许', type: 'success', icon: '✓' },
  deny: { label: '拒绝', type: 'error', icon: '✕' },
}

export function actionMeta(action) {
  return ACTION_META[action] || { label: action || '未知', type: 'default', icon: '?' }
}

// KIND_META 与后端的 port/ip 对齐。
export const KIND_META = {
  port: { label: '端口', type: 'info' },
  ip: { label: 'IP', type: 'warning' },
}

// ORIGIN_META 与后端的 panel/external 对齐。
export const ORIGIN_META = {
  panel: { label: '面板创建', type: 'success' },
  external: { label: '外部创建', type: 'default' },
}

export function originMeta(origin) {
  return ORIGIN_META[origin] || { label: '未知', type: 'default' }
}

// ---------------------------------------------------------------------------
// 保护端口
// ---------------------------------------------------------------------------

// PROTECT_PANEL / PROTECT_SSH 与 internal/firewall 对齐。
export const PROTECT_PANEL = 'panel'
export const PROTECT_SSH = 'ssh'

// PROTECT_META 描述两类保护的展示样式。
//
// SSH 用更重的警示色（error）：关掉它会直接失去远程登录，
// 而面板端口关掉至少还能通过 SSH 改回来（除非两个一起关）。
export const PROTECT_META = {
  [PROTECT_PANEL]: { label: '面板端口', type: 'warning', icon: '🔒' },
  [PROTECT_SSH]: { label: 'SSH 端口', type: 'error', icon: '🔐' },
}

export function protectMeta(kind) {
  return PROTECT_META[kind] || { label: '受保护', type: 'warning', icon: '🔒' }
}

// protectionIndex 把后端返回的保护列表转成端口 → 保护信息的映射。
export function protectionIndex(protection) {
  const map = {}
  const ports = protection?.ports || []
  for (const p of ports) {
    if (p && typeof p.port === 'number') map[p.port] = p
  }
  return map
}

// findProtection 查询某端口（或端口范围）是否受保护。
//
// ########## 必须处理端口范围 ##########
//
// 范围规则（如 8000-9000）若覆盖了受保护端口，关掉这个范围
// 同样会关掉 SSH。只做精确匹配会让用户在界面上看到
// "8000-9000 未受保护"从而放心删除，实际却断了自己的连接。
export function findProtection(index, portText) {
  const spec = parsePortSpec(portText)
  if (!spec) return null
  // 精确命中优先。
  if (!spec.isRange && index[spec.start]) return index[spec.start]
  // 范围：返回区间内第一个受保护端口。
  for (let p = spec.start; p <= spec.end; p++) {
    if (index[p]) return index[p]
  }
  return null
}

// ---------------------------------------------------------------------------
// 端口解析与校验（与后端 validate.go 同构）
// ---------------------------------------------------------------------------

// 后端只接受纯 ASCII 数字且**不允许前导零**。
//
// ########## 为什么前端也要禁前导零 ##########
//
// 后端的正则最初是 ^[0-9]{1,5}$，被测试抓出 "08080-08090"
// 被接受为 8080-8090 的缺陷。前端的校验必须与后端一致，
// 否则用户会看到"前端通过、后端报错"这种最令人困惑的组合。
const PORT_RE = /^(0|[1-9][0-9]{0,4})$/
const PORT_RANGE_RE = /^(0|[1-9][0-9]{0,4})-(0|[1-9][0-9]{0,4})$/

// parsePortSpec 解析 "8080" 或 "8080-8090"。
//
// 返回 null 表示格式非法。**不做任何修正**（不前导零补全、
// 不交换反写的范围）——与后端同一条纪律：
// 校验只回答"能不能用"，绝不悄悄改写用户输入。
export function parsePortSpec(text) {
  if (typeof text !== 'string') return null
  const s = text.trim() === text ? text : null
  if (s === null || s === '') return null

  const rangeMatch = PORT_RANGE_RE.exec(s)
  if (rangeMatch) {
    const start = Number(rangeMatch[1])
    const end = Number(rangeMatch[2])
    if (start < 1 || end > 65535 || start > end) return null
    return { start, end, isRange: start !== end }
  }
  if (!PORT_RE.test(s)) return null
  const n = Number(s)
  if (n < 1 || n > 65535) return null
  return { start: n, end: n, isRange: false }
}

// validatePort 面向表单：返回错误信息（null 表示通过）。
//
// 错误文案与后端保持一致的口径，但更简短（表单里空间有限）。
export function validatePort(text) {
  if (!text || !text.trim()) return '请输入端口或端口范围'
  if (text.trim() !== text) return '端口号前后不能有空格'
  if (text.includes('-')) {
    const m = PORT_RANGE_RE.exec(text)
    if (!m) return '端口范围格式应为 起始-结束，例如 8080-8090'
    const start = Number(m[1])
    const end = Number(m[2])
    if (start < 1 || start > 65535) return '端口范围起点必须是 1-65535'
    if (end < 1 || end > 65535) return '端口范围终点必须是 1-65535'
    if (start > end) {
      return `起始值不能大于结束值（你想输入的是 ${end}-${start} 吗？）`
    }
    return null
  }
  if (!PORT_RE.test(text)) {
    return '端口号必须是纯数字（不允许前导零、正负号或空格）'
  }
  const n = Number(text)
  if (n < 1 || n > 65535) return '端口号必须在 1-65535 之间'
  return null
}

// validateIP 校验 IP 或 CIDR。
//
// 与后端 netip 的判定对齐，覆盖三类常见错误：
//   · 把 "IP:端口" 填进 IP 字段
//   · 网段的主机位不为零（nft 会直接拒绝，iptables 会静默按掩码处理）
//   · 前导零（八进制歧义）
export function validateIP(text) {
  if (!text || !text.trim()) return '请输入 IP 地址或网段'
  const s = text.trim()
  if (s !== text) return 'IP 前后不能有空格'

  if (s.includes('/')) {
    const [addr, bitsText] = s.split('/')
    if (!addr || !bitsText || bitsText.includes('/')) return '网段格式应为 192.168.1.0/24'
    const bits = Number(bitsText)
    if (!Number.isInteger(bits) || String(bits) !== bitsText) return '掩码位数必须是整数'
    const parsed = parseIPv4(addr)
    if (parsed) {
      if (bits < 0 || bits > 32) return 'IPv4 掩码位数必须在 0-32 之间'
      const masked = maskIPv4(parsed, bits)
      if (masked !== addr) {
        return `${addr}/${bits} 的主机位不为零，请改写为规范网段 ${masked}/${bits}`
      }
      return null
    }
    // IPv6 网段：做基本形态检查（完整校验交给后端）。
    if (!isLikelyIPv6(addr)) return '不是合法的 IP 地址或网段'
    if (bits < 0 || bits > 128) return 'IPv6 掩码位数必须在 0-128 之间'
    return null
  }

  if (parseIPv4(s)) return null
  if (s.includes(':')) {
    // 形如 "1.2.3.4:22" —— 用户把端口填进了 IP 字段。
    const m = /^([^:]+):(\d+)$/.exec(s)
    if (m && parseIPv4(m[1])) {
      return `这看起来是「IP:端口」，IP 字段只接受地址本身（端口 ${m[2]} 请填在端口字段）`
    }
    if (isLikelyIPv6(s)) return null
  }
  return '不是合法的 IP 地址'
}

// parseIPv4 严格解析点分十进制 IPv4（拒绝前导零、越界、字段数不符）。
function parseIPv4(s) {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const nums = []
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    nums.push(n)
  }
  return nums
}

// maskIPv4 按掩码位数把地址规范化为网段地址。
function maskIPv4(nums, bits) {
  const value =
    ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3]
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  const masked = (value & mask) >>> 0
  return [
    (masked >>> 24) & 0xff,
    (masked >>> 16) & 0xff,
    (masked >>> 8) & 0xff,
    masked & 0xff,
  ].join('.')
}

// isLikelyIPv6 做 IPv6 的宽松形态检查（真正的校验在后端）。
function isLikelyIPv6(s) {
  if (!s.includes(':')) return false
  if (s.includes('%')) return false // zone 后缀不被支持
  return /^[0-9a-fA-F:.]+$/.test(s) && s.split(':').length >= 3
}

// validateComment 校验备注（与后端一致：拒绝换行与控制字符）。
//
// ########## 备注不是纯显示字段 ##########
//
// 备注在 ufw 后端会被写进 /etc/ufw/user.rules 的 comment= 字段，
// 那个文件由 ufw 自己逐行解析。一个换行就能插入一行伪造的规则条目。
export function validateComment(text) {
  if (!text) return null
  if (/[\n\r]/.test(text)) return '备注不能包含换行符'
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(text)) return '备注不能包含控制字符'
  if ([...text].length > 128) return '备注不能超过 128 个字符'
  return null
}

// ---------------------------------------------------------------------------
// 表单组装
// ---------------------------------------------------------------------------

// buildPortPayload 把表单值组装成后端需要的请求体。
//
// 注意字段名必须与后端 firewall.PortRequest 完全一致——
// 后端开了 DisallowUnknownFields，拼错会直接 400
// （这是有意的：静默忽略拼错的字段会让用户以为参数生效了）。
export function buildPortPayload(form) {
  return {
    port: (form.port || '').trim(),
    protocol: form.protocol || 'tcp',
    source: (form.source || '').trim(),
    action: form.action || 'allow',
    comment: (form.comment || '').trim(),
  }
}

// buildIPPayload 把表单值组装成 IP 规则请求体。
export function buildIPPayload(form) {
  return {
    ip: (form.ip || '').trim(),
    direction: form.direction || 'deny',
    comment: (form.comment || '').trim(),
  }
}

// ---------------------------------------------------------------------------
// 删除确认文案（本模块最重要的前端逻辑）
// ---------------------------------------------------------------------------

// deletePortConfirmText 生成删除端口的二次确认文案。
//
// ########## 为什么这段文案值得单独一个函数 + 单独测试 ##########
//
// 删除端口的后果可能是**不可逆的失联**。用户看到的这段字
// 是他做决定前唯一的信息来源，因此它必须：
//
//	① **写明具体端口与协议** —— 计划明确要求"写明具体端口"。
//	   只说"确定删除吗"没有信息量，用户无法核对是不是自己想删的那条；
//	② 受保护时**升级为红色警告**并说明后果；
//	③ 明确告诉用户"这个操作没有撤销"。
export function deletePortConfirmText(rule, protection) {
  const target = ruleTargetText(rule)
  const lines = []

  if (protection) {
    const meta = protectMeta(protection.kind)
    lines.push(`${meta.icon} 警告：${protection.reason}`)
    lines.push('')
    lines.push(`如果你继续，将删除规则：${target}`)
    lines.push('')
    lines.push(
      '删除后你可能立刻失去与这台服务器的连接。' +
        '若同时失去面板与 SSH 的访问，你只能通过物理控制台或云服务商的控制台恢复。',
    )
    return lines.join('\n')
  }

  lines.push(`即将删除规则：${target}`)
  if (rule.comment) lines.push(`备注：${rule.comment}`)
  if (rule.origin === 'external') {
    lines.push('')
    lines.push(
      '注意：这条规则不是由本面板创建的。它可能由 ufw、Docker ' +
        '或管理员手工维护，删除后可能影响其它服务的正常运行。',
    )
  }
  lines.push('')
  lines.push('删除操作没有撤销功能，删除后如需恢复必须重新添加。')
  return lines.join('\n')
}

// deleteIPConfirmText 生成删除 IP 规则的二次确认文案。
export function deleteIPConfirmText(rule) {
  const direction = rule.action === 'allow' ? '白名单' : '黑名单'
  const lines = [
    `即将从${direction}中删除：${rule.source || '（未知来源）'}`,
    '',
  ]
  if (direction === '白名单') {
    lines.push(
      '删除白名单条目后，该来源将不再被特别放行，' +
        '其访问将按防火墙的默认策略处理。',
    )
  } else {
    lines.push('删除黑名单条目后，该来源将可以重新访问这台服务器。')
  }
  lines.push('')
  lines.push('删除操作没有撤销功能。')
  return lines.join('\n')
}

// ruleTargetText 生成规则的简短描述（"8080/tcp 来自 1.2.3.4"）。
export function ruleTargetText(rule) {
  const port = rule.port_text || rule.port || ''
  const proto = rule.protocol || ''
  const source = rule.source ? ` 来自 ${rule.source}` : ' 来自任意来源'
  const action = actionMeta(rule.action).label
  let text = `${port}`
  if (proto) text += `/${proto}`
  text += source
  return `${text}（${action}）`
}

// ---------------------------------------------------------------------------
// 展示辅助
// ---------------------------------------------------------------------------

// RULE_STATUS_META 描述规则的展示属性。
export function ruleStatusMeta(rule) {
  const meta = {
    action: actionMeta(rule.action),
    origin: originMeta(rule.origin),
    protected: null,
    deletable: rule.deletable !== false,
  }
  return meta
}

// protocolLabel 返回协议的展示名。
export function protocolLabel(protocol) {
  switch (protocol) {
    case 'tcp':
      return 'TCP'
    case 'udp':
      return 'UDP'
    case 'any':
      return 'TCP + UDP'
    case '':
    case undefined:
    case null:
      return '—'
    default:
      return protocol
  }
}

// sourceLabel 返回来源的展示名（空 = 任意来源）。
export function sourceLabel(source) {
  return source && source.trim() ? source : '任意来源'
}

// portLabel 返回端口的展示名。
export function portLabel(rule) {
  const text = rule.port_text || rule.port || ''
  if (!text) return '—'
  return text.includes('-') ? `${text}（范围）` : text
}

// familyLabel 返回地址族展示名。
export function familyLabel(family) {
  switch (family) {
    case 'ipv4':
      return 'IPv4'
    case 'ipv6':
      return 'IPv6'
    default:
      return family || '—'
  }
}

// defaultPolicyText 生成默认策略的说明文字。
//
// ########## 为什么默认策略要显著展示 ##########
//
// 它是"没有匹配规则的流量会怎样"的答案。
// "默认放行"意味着**防火墙几乎不起作用**——用户看到一堆规则
// 会以为自己被保护着，实际所有端口本来就都开着。
// 这个误解必须能被界面上的文字直接破除。
export function defaultPolicyText(detail) {
  if (!detail) return ''
  const parts = []
  if (detail.default_incoming) parts.push(`入站 ${detail.default_incoming}`)
  if (detail.default_outgoing) parts.push(`出站 ${detail.default_outgoing}`)
  if (detail.default_policies) {
    for (const [chain, policy] of Object.entries(detail.default_policies)) {
      parts.push(`${chain} ${String(policy).toLowerCase()}`)
    }
  }
  return parts.join('、')
}

// firewallHealthMeta 生成防火墙整体健康状态的展示信息。
//
// ########## 三种状态必须区分开 ##########
//
//	未安装   —— 面板无法管理防火墙（用户需要安装）
//	未启用   —— 装了但规则不生效（**最危险的一种**：
//	           用户以为自己在被保护，实际所有规则都没生效）
//	默认放行 —— 启用了，但未匹配的流量全部放行（等于没有防护）
export function firewallHealthMeta(status) {
  if (!status) return { type: 'default', label: '未知', detail: '' }

  if (!status.available) {
    return {
      type: 'warning',
      label: '未检测到防火墙',
      detail: status.unavailable_reason || '系统中没有可用的防火墙后端',
    }
  }
  if (!status.detail?.enabled) {
    return {
      type: 'warning',
      label: '防火墙未启用',
      detail: '防火墙已安装但没有启用，当前所有规则都不会生效。',
    }
  }
  if (status.detail?.allow_all_incoming) {
    return {
      type: 'error',
      label: '默认放行入站',
      detail:
        '入站默认策略为「放行」，这意味着除显式拒绝的端口外，' +
        '所有端口都是开放的——防火墙实际上没有起到防护作用。',
    }
  }
  return { type: 'success', label: '防护中', detail: '防火墙已启用，默认拒绝未放行的入站流量。' }
}

// protectionSummary 生成保护端口的摘要文字。
//
// ########## 探测不到 SSH 时必须如实说明 ##########
//
// 后端在探测不到 SSH 端口时**绝不猜测**（宁可返回空，
// 也不错误地保护一个无关端口）。界面必须把这件事如实告诉用户，
// 否则他会以为"没有 SSH 端口被保护"= "没有 SSH 端口"。
export function protectionSummary(protection) {
  if (!protection) return ''
  const ports = protection.ports || []
  const labels = ports.map((p) => `${p.port}（${protectMeta(p.kind).label}）`)
  const parts = []
  if (labels.length) parts.push(`已保护端口：${labels.join('、')}`)
  if (!protection.ssh_detected) {
    parts.push(
      '未能确定 SSH 服务端口，因此面板无法对 SSH 端口施加保护——' +
        '请自行确认你要删除的端口不是 SSH 端口。',
    )
  }
  return parts.join('\n')
}

// ---------------------------------------------------------------------------
// 过滤与统计
// ---------------------------------------------------------------------------

// filterRules 按关键字与条件过滤规则。
//
// 关键字匹配端口、来源、备注与协议（用户在搜索框里
// 可能输入其中任何一种）。
export function filterRules(rules, { keyword = '', action = '', kind = '' } = {}) {
  const kw = keyword.trim().toLowerCase()
  return (rules || []).filter((r) => {
    if (action && r.action !== action) return false
    if (kind && r.kind !== kind) return false
    if (!kw) return true
    const haystack = [
      r.port_text,
      r.protocol,
      r.source,
      r.comment,
      r.action,
      r.raw,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    return haystack.includes(kw)
  })
}

// summarizeRules 汇总统计（用于页头展示）。
export function summarizeRules(result) {
  const counts = result?.counts || {}
  return {
    total: counts.total || 0,
    ports: counts.ports || 0,
    ips: counts.ips || 0,
    allow: counts.allow || 0,
    deny: counts.deny || 0,
    deletable: counts.deletable || 0,
    protected: counts.protected || 0,
    panel: counts.panel || 0,
    external: counts.external || 0,
    // 不可删除的条数 = 总数 - 可删除数。
    // 这个数字值得展示：它解释"为什么有些行没有删除按钮"。
    notDeletable: Math.max(0, (counts.total || 0) - (counts.deletable || 0)),
  }
}

// AUDIT_OUTCOME_META 与后端 audit.go 对齐。
export const AUDIT_OUTCOME_META = {
  allowed: { label: '成功', type: 'success' },
  denied: { label: '被拒绝', type: 'error' },
  failed: { label: '失败', type: 'warning' },
}

export function auditOutcomeMeta(outcome) {
  return AUDIT_OUTCOME_META[outcome] || { label: outcome || '未知', type: 'default' }
}

// AUDIT_ACTION_LABEL 与后端 permission.go 的动作常量对齐。
export const AUDIT_ACTION_LABEL = {
  status: '查询状态',
  list_rules: '查询规则',
  audit: '查询审计',
  capabilities: '能力探测',
  add_port: '放行端口',
  delete_port: '删除端口',
  add_ip: '添加 IP 规则',
  delete_ip: '删除 IP 规则',
  enable: '启用防火墙',
}

export function auditActionLabel(action) {
  return AUDIT_ACTION_LABEL[action] || action || '未知'
}

// formatAuditTime 把 RFC3339 时间转成可读形式。
export function formatAuditTime(time) {
  if (!time) return '—'
  const d = new Date(time)
  if (Number.isNaN(d.getTime())) return time
  const pad = (n) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  )
}

// commandTimeoutText 生成超时配置的展示文字。
export function commandTimeoutText(seconds) {
  if (!seconds || seconds <= 0) return '未设置'
  if (seconds < 60) return `${seconds} 秒`
  return `${Math.round(seconds / 60)} 分钟`
}
