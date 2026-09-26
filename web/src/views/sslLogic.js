// SSL 证书页的纯逻辑（阶段四 4.4）。
//
// 为什么单独一个模块而不是写在 SslView.vue 里：
//
//   1. **可测**。本仓库前端测试用 node:test，没有 DOM（不引入 jsdom，
//      保持「轻量」约束），因此组件本身无法直接 import。
//      把可判定逻辑抽成纯函数，测试就能锁住**真正被使用的代码**。
//
//   2. **与后端规则一致**。下面的状态分级、按钮禁用条件逐条对应
//      internal/ssl 里的实现。**但前端校验只是体验优化**——
//      真正的强制点始终在后端。
//
//   3. **一致性风险最高**。这里最容易出错的不是"逻辑写错"，
//      而是**与后端不一致**：前端把 expired 显示成绿色、
//      或者把 skipped 显示成"续期成功"，用户就会得到
//      一个与真实情况相反的信息。因此下面的常量与判定
//      都在测试里与后端取值逐一对齐。

// ---------------------------------------------------------------------------
// 证书状态
// ---------------------------------------------------------------------------

// RENEW_DAYS_DEFAULT 与后端 ssl.DefaultRenewDays 一致。
export const RENEW_DAYS_DEFAULT = 30

// STATUS_META 是状态展示元数据。
//
// 颜色选择的理由（按"需要用户采取行动的紧迫度"排序）：
//
//	expired  → error（红）  已经出问题了，必须马上处理
//	expiring → warning（橙）即将出问题，建议尽快处理
//	valid    → success（绿）一切正常
//	none     → default（灰）**没有证书不是坏事**，只是还没申请
//	unknown  → warning（橙）信息不完整，需要人工看一眼
//
// 特别注意 `none` 用灰色而不是红色：把"还没申请"显示成错误，
// 会让一个全新的、运行完全正常的机器看起来像坏了。
export const STATUS_META = {
  valid: { label: '有效', type: 'success', desc: '证书有效，距离到期还有充足时间' },
  expiring: { label: '即将过期', type: 'warning', desc: '证书即将到期，建议尽快续期' },
  expired: { label: '已过期', type: 'error', desc: '证书已过期，HTTPS 访问会报证书错误' },
  none: { label: '未申请', type: 'default', desc: '该站点尚未申请证书，目前仅提供 HTTP' },
  unknown: { label: '未知', type: 'warning', desc: '证书信息不完整或无法解析，需要人工检查' },
}

// statusMeta 返回状态元数据，未知状态安全回落。
export function statusMeta(status) {
  return (
    STATUS_META[status] || {
      label: status || '未知',
      type: 'default',
      desc: '',
    }
  )
}

// ---------------------------------------------------------------------------
// 剩余天数文案
// ---------------------------------------------------------------------------

// daysText 把剩余天数转成给用户看的一句话。
//
// ########## 为什么负数与 0 要分开说 ##########
//
// 后端已经按自然日粒度算好了天数（见 internal/ssl.DaysRemaining），
// 因此这里只需要把数字翻译成人话。但有一个边界不能含糊：
//
//	days < 0  → "已过期 N 天"
//	days = 0  → "今天到期"       ← 还**没**过期，只是今天
//	days = 1  → "剩余 1 天"
//	days > 1  → "剩余 N 天"
//
// 把 days=0 说成"已过期 0 天"是错的（还没过期）；
// 说成"剩余 0 天"也别扭。单独一句"今天到期"最准确。
export function daysText(days) {
  const n = Number(days)
  if (!Number.isFinite(n)) return '—'
  if (n < 0) return `已过期 ${Math.abs(n)} 天`
  if (n === 0) return '今天到期'
  return `剩余 ${n} 天`
}

// expiryText 把 RFC3339 时间转成简洁的本地展示。
//
// 只取到"日"：证书到期的语义是"哪一天到期"，
// 显示到秒既没有意义（用户不会掐着秒续期），
// 又会让表格列特别宽。
export function expiryText(expiry) {
  if (!expiry) return '—'
  const d = new Date(expiry)
  if (Number.isNaN(d.getTime())) return String(expiry)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

// ---------------------------------------------------------------------------
// 按钮可用性
// ---------------------------------------------------------------------------

// issueDisabled 判断"申请证书"按钮是否应当禁用。
//
// 返回 { disabled, reason }。reason 会作为按钮的 tooltip 展示——
// **禁用而不说原因是糟糕的体验**：用户只会觉得按钮坏了。
//
// 判定逐条对应后端的拒绝条件（internal/ssl.Manager.Issue）：
//   - 无 ssl.write 权限 → 403
//   - 后端不可用（没装 certbot）→ 503
//   - 站点没有 webroot（反代站）→ 400
//   - 站点域名是通配符 → 400（后端显式拒绝，因为需要 DNS-01）
//   - 已经有证书 → 后端允许（会走 renew 的语义），但前端应当
//     引导用户用"续期"而不是重复"申请"
export function issueDisabled(site, { canWrite = true, available = true } = {}) {
  if (!available) {
    return { disabled: true, reason: 'ACME 客户端不可用，请先安装 certbot' }
  }
  if (!canWrite) {
    return { disabled: true, reason: '当前账号没有 ssl.write 权限' }
  }
  if (!site) {
    return { disabled: true, reason: '站点不存在' }
  }
  // 通配符域名：后端会明确拒绝（需要 DNS-01），
  // 前端提前拦下并说清原因，比让用户点了才收到 400 友好得多。
  if (isWildcardDomain(site.domain)) {
    return {
      disabled: true,
      reason: '通配符域名需要 DNS 验证，本版本未支持（请改用具体域名）',
    }
  }
  if (!site.has_webroot) {
    return {
      disabled: true,
      reason: '该站点没有本地目录（反向代理站），无法用 HTTP-01 验证',
    }
  }
  return { disabled: false, reason: '' }
}

// renewDisabled 判断"续期"按钮是否应当禁用。
//
// 与申请不同，续期必须**已经有证书**才有意义。
export function renewDisabled(site, { canWrite = true, available = true } = {}) {
  if (!available) {
    return { disabled: true, reason: 'ACME 客户端不可用，请先安装 certbot' }
  }
  if (!canWrite) {
    return { disabled: true, reason: '当前账号没有 ssl.write 权限' }
  }
  if (!site) {
    return { disabled: true, reason: '站点不存在' }
  }
  if (!site.issued) {
    return { disabled: true, reason: '该站点尚未申请证书，请先点击「申请证书」' }
  }
  return { disabled: false, reason: '' }
}

// isWildcardDomain 判断是否为通配符域名。
//
// 与后端 ssl.ValidIssueDomain 的拒绝条件一致。
export function isWildcardDomain(domain) {
  return String(domain ?? '').includes('*')
}

// ---------------------------------------------------------------------------
// 二次确认文案
// ---------------------------------------------------------------------------

// issueConfirmText 生成申请证书的二次确认文案。
//
// ########## 为什么申请必须二次确认 ##########
//
// 这不是"改一个本地文件"——它会**向 Let's Encrypt 发起真实请求并消耗配额**。
// 同一组域名每周只有 5 次重复签发机会，误点几下就可能把配额打满，
// 之后整整一周都无法为这个域名签发证书（包括紧急续期）。
//
// 因此确认弹窗必须写清楚三件事：
//   ① 会做什么（向 CA 申请证书）
//   ② 会消耗什么（配额，且有限）
//   ③ 前置条件（域名要解析到本机、80 端口要可达）
//
// 只说"确定要申请吗？"等于没说——用户不知道自己即将付出什么代价。
export function issueConfirmText(site) {
  const domain = site?.domain || '(未知域名)'
  return [
    `即将为「${site?.site || '(未知站点)'}」（${domain}）向 Let's Encrypt 申请证书。`,
    '',
    "申请会消耗 Let's Encrypt 的签发配额（同一域名每周最多 5 次重复签发），请确认：",
    `· 域名 ${domain} 已解析到本机`,
    '· 本机 80 端口可从公网访问（HTTP-01 验证依赖它）',
    '',
    '申请成功后，面板会自动把证书写入站点配置并重载 nginx。',
  ].join('\n')
}

// renewConfirmText 生成续期确认文案。
//
// 与申请不同，续期默认**不会**重新签发（certbot 只在进入续期窗口时
// 才真正签发），因此代价小得多。但"强制续期"会真实消耗配额，
// 这一点必须在文案里说清楚。
export function renewConfirmText(site, { force = false } = {}) {
  const domain = site?.domain || '(未知域名)'
  const lines = [
    `即将为「${site?.site || '(未知站点)'}」（${domain}）续期证书。`,
    '',
    '若证书尚未进入续期窗口（默认剩余 30 天），certbot 会跳过签发，',
    '不会消耗配额——这是正常行为，不是失败。',
  ]
  if (force) {
    lines.push(
      '',
      '⚠️ 你选择了「强制续期」：即使证书仍然有效也会重新签发，',
      "会消耗 Let's Encrypt 的配额（同一域名每周最多 5 次）。",
    )
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 结果文案
// ---------------------------------------------------------------------------

// issueResultText 把申请结果转成提示文案。
//
// ########## 为什么必须区分"部分成功" ##########
//
// 后端在"证书已获取但写入 nginx 配置失败"时返回 422 且带 issued=true。
// 此时 CA 配额**已经消耗**。若前端只显示一句"申请失败"，
// 用户会直接重试——每次都再消耗一次配额，直到撞上速率限制。
//
// 因此这种情况必须明确告诉用户"证书已经拿到了，不要重复申请"。
export function issueResultText(res) {
  if (!res) return '申请完成'
  if (res.dry_run) {
    return '试运行完成（未写入证书，也未修改 nginx 配置）'
  }
  if (res.issued && !res.applied) {
    return '证书已获取，但写入 nginx 配置失败——请勿重复申请，修复后重试即可'
  }
  if (res.issued && res.applied) {
    return '证书申请成功，已写入 nginx 配置并重载'
  }
  return '申请已完成'
}

// renewResultText 把续期结果转成提示文案。
//
// ########## "跳过"绝不能显示成"成功" ##########
//
// `certbot renew` 对未进入续期窗口的证书会输出
// "not yet due for renewal" 并以 exit 0 退出。
// 若前端把它显示成"续期成功"，用户会看到一句成功提示，
// 但到期时间**一点没变**——他会立刻怀疑这个功能是假的，
// 或者更糟：以为已经续过了，实际并没有。
export function renewResultText(res) {
  if (!res) return '续期完成'
  if (res.dry_run) {
    return '试运行完成（未实际续期）'
  }
  if (res.skipped) {
    return '证书尚未进入续期窗口，本次未重新签发（这是正常行为）'
  }
  if (res.renewed) {
    return '证书续期成功'
  }
  // 既没跳过也没续期：输出无法识别，如实说明而不是乐观地说成功
  return '续期命令已执行，但未能确认是否重新签发，请查看证书到期时间'
}

// ---------------------------------------------------------------------------
// 统计与过滤
// ---------------------------------------------------------------------------

// summarize 汇总站点状态的统计数字。
//
// 与后端的 StatusCounts 语义一致，但**在前端重新计算**是有意为之：
// 后端的统计基于全量数据，而前端可能正在过滤展示。
// 两份数字不一致时，以"用户当前看到的列表"为准更不容易困惑。
export function summarize(sites) {
  const list = Array.isArray(sites) ? sites : []
  const acc = {
    total: list.length,
    issued: 0,
    valid: 0,
    expiring: 0,
    expired: 0,
    none: 0,
    unknown: 0,
  }
  for (const s of list) {
    if (s?.issued) acc.issued += 1
    switch (s?.status) {
      case 'valid':
        acc.valid += 1
        break
      case 'expiring':
        acc.expiring += 1
        break
      case 'expired':
        acc.expired += 1
        break
      case 'unknown':
        acc.unknown += 1
        break
      default:
        acc.none += 1
    }
  }
  return acc
}

// filterSites 按关键字与状态过滤站点。
//
// 关键字同时匹配站点名与域名：用户可能记得域名却不记得站点名
// （反之亦然），只匹配一个会让"明明有却搜不到"。
export function filterSites(sites, { keyword = '', status = '' } = {}) {
  const kw = String(keyword ?? '').trim().toLowerCase()
  const st = String(status ?? '').trim()
  return (Array.isArray(sites) ? sites : []).filter((s) => {
    if (st && s?.status !== st) return false
    if (!kw) return true
    const name = String(s?.site ?? '').toLowerCase()
    const domain = String(s?.domain ?? '').toLowerCase()
    return name.includes(kw) || domain.includes(kw)
  })
}

// ---------------------------------------------------------------------------
// 需要关注的站点
// ---------------------------------------------------------------------------

// attentionSites 返回需要用户关注的站点（已过期 / 即将过期 / 解析异常），
// 按紧迫度排序。
//
// 页面顶部据此展示一条醒目提示。理由：SSL 的问题有**延迟爆发**的特征——
// 今天没续上，30 天后站点突然打不开，而那时用户早就忘了这回事。
// 主动把最紧迫的几条摆到页面上方，是这个问题最有效的缓解手段。
export function attentionSites(sites) {
  const weights = { expired: 0, unknown: 1, expiring: 2 }
  return (Array.isArray(sites) ? sites : [])
    .filter((s) => Object.prototype.hasOwnProperty.call(weights, s?.status))
    .sort((a, b) => {
      const wa = weights[a.status]
      const wb = weights[b.status]
      if (wa !== wb) return wa - wb
      // 同一紧迫度内，剩余天数少的排前面
      return Number(a.days_remaining ?? 0) - Number(b.days_remaining ?? 0)
    })
}

// attentionText 生成顶部提示的一句话描述。
export function attentionText(sites) {
  const list = attentionSites(sites)
  if (list.length === 0) return ''
  const expired = list.filter((s) => s.status === 'expired').length
  const expiring = list.filter((s) => s.status === 'expiring').length
  const unknown = list.filter((s) => s.status === 'unknown').length

  const parts = []
  if (expired > 0) parts.push(`${expired} 个站点证书已过期`)
  if (expiring > 0) parts.push(`${expiring} 个站点证书即将过期`)
  if (unknown > 0) parts.push(`${unknown} 个站点证书状态异常`)
  return parts.join('，')
}

// ---------------------------------------------------------------------------
// 客户端信息
// ---------------------------------------------------------------------------

// clientText 把 ACME 客户端信息转成一句话。
//
// 没有客户端时**必须给出可操作的下一步**（装什么、怎么指定路径），
// 而不是只说"不可用"。
export function clientText(client) {
  if (!client || !client.available) {
    return {
      label: '不可用',
      type: 'error',
      detail:
        '未检测到 certbot 或 acme.sh。Debian/Ubuntu 可执行 apt install certbot；' +
        '已安装在非标准路径时，可用 -certbot-path 指定。',
    }
  }
  const kind = client.kind === 'acme.sh' ? 'acme.sh' : 'certbot'
  const version = client.version ? ` ${client.version}` : ''
  const source = client.source ? `（${client.source}）` : ''
  return {
    label: `${kind}${version}`,
    type: 'success',
    detail: client.path ? `${client.path}${source}` : '',
  }
}

// 导出给组件使用的常量别名，避免组件里散落魔法字符串。
export const STATUS_OPTIONS = [
  { label: '全部状态', value: '' },
  { label: '有效', value: 'valid' },
  { label: '即将过期', value: 'expiring' },
  { label: '已过期', value: 'expired' },
  { label: '未申请', value: 'none' },
  { label: '未知', value: 'unknown' },
]
