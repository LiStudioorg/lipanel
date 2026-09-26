// SSL 证书纯逻辑测试（阶段四 4.4）。
//
// 用 node:test（本仓库不引入 jsdom，保持轻量约束），
// 因此测的是 sslLogic.js 里的纯函数——也就是**组件真正使用的那份逻辑**。
//
// ########## 本文件最重要的目标：与后端保持一致 ##########
//
// SSL 页最容易出的错不是"逻辑写错"，而是**与后端不一致**：
//
//   - 前端把 expired 显示成绿色 → 用户以为一切正常
//   - 前端把 skipped 显示成"续期成功" → 用户以为到期时间延长了
//   - 前端把 issued=true, applied=false 显示成"申请失败"
//     → 用户不断重试，把 Let's Encrypt 的周配额打满
//
// 这三种都是"界面在说谎"，代价由用户承担。因此下面的用例
// 大量地逐条对齐 internal/ssl 里的取值与判定。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  RENEW_DAYS_DEFAULT,
  STATUS_META,
  STATUS_OPTIONS,
  attentionSites,
  attentionText,
  clientText,
  daysText,
  expiryText,
  filterSites,
  isWildcardDomain,
  issueConfirmText,
  issueDisabled,
  issueResultText,
  renewConfirmText,
  renewDisabled,
  renewResultText,
  statusMeta,
  summarize,
} from './sslLogic.js'

// ---------------------------------------------------------------------------
// 状态元数据：必须与后端取值一一对应
// ---------------------------------------------------------------------------

// TestStatusMetaCoversBackendStatuses 锁死状态常量与后端一致。
//
// 后端的取值定义在 internal/ssl/cert.go 的 Status* 常量里。
// 若这里少了一个，那个状态的站点会显示成灰色的原始英文串
// （如 "expiring"），用户看不懂。
test('状态元数据覆盖后端全部状态取值', () => {
  const backendStatuses = ['valid', 'expiring', 'expired', 'none', 'unknown']
  for (const s of backendStatuses) {
    const meta = STATUS_META[s]
    assert.ok(meta, `缺少后端状态 ${s} 的展示元数据`)
    assert.ok(meta.label, `状态 ${s} 缺少中文标签`)
    assert.ok(meta.type, `状态 ${s} 缺少颜色类型`)
    assert.ok(meta.desc, `状态 ${s} 缺少说明文案`)
  }
})

// TestStatusColorsAreIntuitive 锁死颜色语义。
//
// 这是最容易被"顺手改一下"破坏的东西，而破坏的后果是
// 界面传达与事实相反的信息。
test('状态颜色语义正确（过期必须是红色）', () => {
  assert.equal(STATUS_META.expired.type, 'error', '已过期必须是红色')
  assert.equal(STATUS_META.expiring.type, 'warning', '即将过期必须是橙色')
  assert.equal(STATUS_META.valid.type, 'success', '有效必须是绿色')
  // 关键：未申请**不能**是红色——那是全新机器的正常状态，
  // 显示成错误会让用户以为系统坏了。
  assert.equal(STATUS_META.none.type, 'default', '未申请应当是中性色而不是红色')
})

test('未知状态安全回落而不是抛错', () => {
  const meta = statusMeta('some-new-status-from-future-backend')
  assert.ok(meta.label)
  assert.equal(meta.type, 'default')
  // 空值也不能崩
  assert.ok(statusMeta('').label)
  assert.ok(statusMeta(null).label)
  assert.ok(statusMeta(undefined).label)
})

test('续期阈值默认值与后端一致', () => {
  // 对应 internal/ssl.DefaultRenewDays
  assert.equal(RENEW_DAYS_DEFAULT, 30)
})

test('状态筛选选项与状态元数据对齐', () => {
  const values = STATUS_OPTIONS.map((o) => o.value).filter(Boolean)
  for (const v of values) {
    assert.ok(STATUS_META[v], `筛选选项 ${v} 在状态元数据里不存在`)
  }
  // 第一项应当是"全部"
  assert.equal(STATUS_OPTIONS[0].value, '')
})

// ---------------------------------------------------------------------------
// 剩余天数文案
// ---------------------------------------------------------------------------

test('剩余天数文案正确', () => {
  // 对应 internal/ssl.DaysRemaining 的语义：
  //   days < 0 → 已过期
  //   days = 0 → 今天到期（**还没**过期）
  //   days > 0 → 剩余
  const cases = [
    [90, '剩余 90 天'],
    [30, '剩余 30 天'],
    [1, '剩余 1 天'],
    [0, '今天到期'],
    [-1, '已过期 1 天'],
    [-6, '已过期 6 天'],
    [-365, '已过期 365 天'],
  ]
  for (const [days, want] of cases) {
    assert.equal(daysText(days), want, `days=${days}`)
  }
})

// TestDaysTextZeroIsNotExpired 单独锁住这个边界。
//
// "剩余 0 天"和"已过期 0 天"都是错的：前者像是没剩时间了，
// 后者干脆与事实相反（还没过期）。必须单独说"今天到期"。
test('days=0 既不是"剩余 0 天"也不是"已过期 0 天"', () => {
  const text = daysText(0)
  assert.ok(!text.includes('已过期'), 'days=0 不能显示为已过期')
  assert.equal(text, '今天到期')
})

test('剩余天数非法输入不崩', () => {
  for (const v of [null, undefined, '', 'abc', NaN, {}]) {
    assert.equal(typeof daysText(v), 'string')
  }
})

// ---------------------------------------------------------------------------
// 到期时间展示
// ---------------------------------------------------------------------------

test('到期时间只展示到日', () => {
  assert.equal(expiryText('2026-12-24T14:30:32Z'), '2026-12-24')
  // 带时区偏移的也要能解析（后端输出 RFC3339）
  const withOffset = expiryText('2026-12-24T14:30:32+00:00')
  assert.ok(withOffset.startsWith('2026-12-2'), `实际: ${withOffset}`)
})

test('到期时间缺失或畸形时显示占位符而不是 Invalid Date', () => {
  for (const v of ['', null, undefined]) {
    assert.equal(expiryText(v), '—')
  }
  // 无法解析的字符串原样返回，至少让用户看到后端给了什么
  assert.equal(expiryText('not-a-date'), 'not-a-date')
})

// ---------------------------------------------------------------------------
// 通配符判定
// ---------------------------------------------------------------------------

test('通配符域名判定与后端一致', () => {
  // 后端 ValidIssueDomain 显式拒绝含 `*` 的域名（需要 DNS-01）
  assert.equal(isWildcardDomain('*.example.com'), true)
  assert.equal(isWildcardDomain('*.sub.example.com'), true)
  assert.equal(isWildcardDomain('*.example.com'), true)
  assert.equal(isWildcardDomain('example.com'), false)
  assert.equal(isWildcardDomain('sub.example.com'), false)
  // 非标准位置也应当被拦（后端同样拒绝）
  assert.equal(isWildcardDomain('exa*mple.com'), true)
  // 空值不崩
  assert.equal(isWildcardDomain(null), false)
  assert.equal(isWildcardDomain(undefined), false)
})

// ---------------------------------------------------------------------------
// 申请按钮可用性
// ---------------------------------------------------------------------------

// site 造一个默认健康的站点。
function site(overrides = {}) {
  return {
    site: 'demo',
    domain: 'demo.example.com',
    status: 'none',
    issued: false,
    has_webroot: true,
    ...overrides,
  }
}

test('健康站点可以申请', () => {
  const r = issueDisabled(site(), { canWrite: true, available: true })
  assert.equal(r.disabled, false)
  assert.equal(r.reason, '')
})

test('客户端不可用时禁用申请并说明原因', () => {
  const r = issueDisabled(site(), { canWrite: true, available: false })
  assert.equal(r.disabled, true)
  // 原因必须可操作：告诉用户装什么
  assert.ok(r.reason.includes('certbot'), `原因应当提到 certbot，实际: ${r.reason}`)
})

test('无写权限时禁用申请并说明原因', () => {
  const r = issueDisabled(site(), { canWrite: false, available: true })
  assert.equal(r.disabled, true)
  assert.ok(r.reason.includes('ssl.write'), `原因应当提到权限名，实际: ${r.reason}`)
})

test('通配符域名禁用申请并解释需要 DNS 验证', () => {
  const r = issueDisabled(site({ domain: '*.example.com' }), {
    canWrite: true,
    available: true,
  })
  assert.equal(r.disabled, true)
  // 必须解释"为什么"——只说"不支持"会让用户反复尝试
  assert.ok(r.reason.includes('DNS'), `原因应当说明需要 DNS 验证，实际: ${r.reason}`)
})

test('反代站（无 webroot）禁用申请并解释 HTTP-01 限制', () => {
  const r = issueDisabled(site({ has_webroot: false }), {
    canWrite: true,
    available: true,
  })
  assert.equal(r.disabled, true)
  assert.ok(
    r.reason.includes('HTTP-01') || r.reason.includes('本地目录'),
    `原因应当解释 HTTP-01 需要本地目录，实际: ${r.reason}`,
  )
})

test('禁用时总是给出非空原因（不能只置灰不说话）', () => {
  const cases = [
    [{ canWrite: false, available: true }, site()],
    [{ canWrite: true, available: false }, site()],
    [{ canWrite: true, available: true }, site({ domain: '*.a.com' })],
    [{ canWrite: true, available: true }, site({ has_webroot: false })],
  ]
  for (const [opts, s] of cases) {
    const r = issueDisabled(s, opts)
    assert.equal(r.disabled, true)
    assert.ok(r.reason.length > 0, `禁用却没有说明原因: ${JSON.stringify({ opts, s })}`)
  }
})

test('申请按钮判定不因缺少 site 而崩溃', () => {
  assert.equal(issueDisabled(null, {}).disabled, true)
  assert.equal(issueDisabled(undefined, {}).disabled, true)
})

// ---------------------------------------------------------------------------
// 续期按钮可用性
// ---------------------------------------------------------------------------

test('未申请证书时不能续期（应当先申请）', () => {
  const r = renewDisabled(site({ issued: false }), { canWrite: true, available: true })
  assert.equal(r.disabled, true)
  // 原因要给出**下一步动作**
  assert.ok(r.reason.includes('申请'), `原因应当引导用户先申请，实际: ${r.reason}`)
})

test('已申请证书可以续期', () => {
  const r = renewDisabled(site({ issued: true, status: 'valid' }), {
    canWrite: true,
    available: true,
  })
  assert.equal(r.disabled, false)
})

test('已过期证书仍可续期（这正是最需要续期的场景）', () => {
  const r = renewDisabled(site({ issued: true, status: 'expired' }), {
    canWrite: true,
    available: true,
  })
  assert.equal(r.disabled, false, '过期证书必须允许续期')
})

test('续期按钮同样受权限与客户端可用性约束', () => {
  const s = site({ issued: true })
  assert.equal(renewDisabled(s, { canWrite: false, available: true }).disabled, true)
  assert.equal(renewDisabled(s, { canWrite: true, available: false }).disabled, true)
  // 禁用时必须有原因
  assert.ok(renewDisabled(s, { canWrite: false, available: true }).reason.length > 0)
  assert.ok(renewDisabled(s, { canWrite: true, available: false }).reason.length > 0)
})

// ---------------------------------------------------------------------------
// 二次确认文案
// ---------------------------------------------------------------------------

// TestIssueConfirmWarnsAboutQuota 是本组最重要的一条。
//
// 申请会**消耗 Let's Encrypt 的签发配额**（同一域名每周 5 次）。
// 若确认弹窗不写清这一点，用户会把"申请"当成一个可以随便点的按钮，
// 几次误点之后整个域名一周内都无法签发证书——包括紧急续期。
test('申请确认文案必须写明配额代价与前置条件', () => {
  const text = issueConfirmText(site())
  assert.ok(text.includes('demo.example.com'), '必须包含域名')
  assert.ok(text.includes('demo'), '必须包含站点名')
  // 配额警告
  assert.ok(text.includes('配额'), '必须提到配额')
  assert.ok(text.includes('5 次'), '必须给出具体的配额上限')
  // 前置条件
  assert.ok(text.includes('解析'), '必须提醒域名解析')
  assert.ok(text.includes('80'), '必须提醒 80 端口')
})

test('申请确认文案在字段缺失时仍可读', () => {
  const text = issueConfirmText(null)
  assert.equal(typeof text, 'string')
  assert.ok(text.length > 0)
})

test('续期确认文案说明"跳过"是正常行为', () => {
  const text = renewConfirmText(site({ issued: true }))
  assert.ok(text.includes('跳过'), '必须说明未到窗口会跳过')
  assert.ok(text.includes('不会消耗配额'), '必须说明跳过不消耗配额')
  // 非强制续期时不该出现强制警告
  assert.ok(!text.includes('⚠️'), '非强制续期不该出现强制警告')
})

test('强制续期文案必须额外警告配额消耗', () => {
  const text = renewConfirmText(site({ issued: true }), { force: true })
  assert.ok(text.includes('⚠️'), '强制续期必须有醒目警告')
  assert.ok(text.includes('配额'), '强制续期必须提到配额')
  assert.ok(text.includes('5 次'), '强制续期必须给出配额上限')
})

// ---------------------------------------------------------------------------
// 结果文案
// ---------------------------------------------------------------------------

// TestIssueResultDistinguishesPartialSuccess 锁死"部分成功"的文案。
//
// 后端在"证书已获取但写入 nginx 配置失败"时返回 issued=true, applied=false。
// 此时 **CA 配额已经消耗**。若前端只说一句"申请失败"，用户会直接重试，
// 每次都再消耗一次配额，直到撞上速率限制——之后一周都无法签发。
//
// 因此这种情况的文案必须明确说"不要重复申请"。
test('部分成功（已签发但配置未生效）必须提示不要重复申请', () => {
  const text = issueResultText({ issued: true, applied: false })
  assert.ok(
    text.includes('请勿重复申请') || text.includes('不要重复申请'),
    `必须提示不要重复申请，实际: ${text}`,
  )
  // 必须说清证书其实已经到手了
  assert.ok(text.includes('已获取') || text.includes('已拿到'), `实际: ${text}`)
})

test('完全成功的文案说明配置已写入', () => {
  const text = issueResultText({ issued: true, applied: true })
  assert.ok(text.includes('成功'))
  assert.ok(text.includes('nginx'), '应当说明配置已写入 nginx')
})

test('试运行结果必须说明未写入任何东西', () => {
  const text = issueResultText({ issued: true, applied: true, dry_run: true })
  assert.ok(text.includes('试运行'), `实际: ${text}`)
  assert.ok(text.includes('未写入') || text.includes('未修改'), `实际: ${text}`)
})

test('申请结果为空时不崩', () => {
  assert.equal(typeof issueResultText(null), 'string')
  assert.equal(typeof issueResultText(undefined), 'string')
})

// TestRenewResultNeverLiesAboutSkipped 是本组最重要的一条。
//
// `certbot renew` 对未进入续期窗口的证书输出
// "not yet due for renewal" 并以 **exit 0** 退出。
// 若前端把它显示成"续期成功"，用户看到成功提示但到期时间毫无变化，
// 会立刻认为功能是假的；更糟的是他可能以为已经续过了而不再处理。
test('未到续期窗口必须显示为"跳过"而不是"成功"', () => {
  const text = renewResultText({ renewed: false, skipped: true })
  assert.ok(text.includes('跳过') || text.includes('未重新签发'), `实际: ${text}`)
  assert.ok(text.includes('正常'), '应当说明这是正常行为，避免用户以为出错')
  // **绝不能**出现"续期成功"
  assert.ok(!text.includes('续期成功'), `跳过被显示成了成功: ${text}`)
})

test('真正续期的文案才说成功', () => {
  const text = renewResultText({ renewed: true, skipped: false })
  assert.ok(text.includes('成功'))
})

test('结果未知时如实说明而不是乐观地说成功', () => {
  const text = renewResultText({ renewed: false, skipped: false })
  assert.ok(!text.includes('成功'), `无法确认时不该说成功: ${text}`)
  assert.ok(text.includes('未能确认') || text.includes('请查看'), `实际: ${text}`)
})

test('试运行的续期结果必须说明未实际续期', () => {
  const text = renewResultText({ renewed: true, dry_run: true })
  assert.ok(text.includes('试运行'), `实际: ${text}`)
  assert.ok(text.includes('未实际续期'), `实际: ${text}`)
})

test('续期结果为空时不崩', () => {
  assert.equal(typeof renewResultText(null), 'string')
  assert.equal(typeof renewResultText(undefined), 'string')
})

// ---------------------------------------------------------------------------
// 统计
// ---------------------------------------------------------------------------

test('统计各类状态数量', () => {
  const list = [
    site({ site: 'a', status: 'valid', issued: true }),
    site({ site: 'b', status: 'valid', issued: true }),
    site({ site: 'c', status: 'expiring', issued: true }),
    site({ site: 'd', status: 'expired', issued: true }),
    site({ site: 'e', status: 'none', issued: false }),
    site({ site: 'f', status: 'unknown', issued: true }),
  ]
  const s = summarize(list)
  assert.equal(s.total, 6)
  assert.equal(s.issued, 5)
  assert.equal(s.valid, 2)
  assert.equal(s.expiring, 1)
  assert.equal(s.expired, 1)
  assert.equal(s.none, 1)
  assert.equal(s.unknown, 1)
  // 各状态之和必须等于总数（不能漏掉任何一种）
  assert.equal(
    s.valid + s.expiring + s.expired + s.none + s.unknown,
    s.total,
    '状态分类之和应当等于总数',
  )
})

test('统计空列表与非法输入', () => {
  for (const v of [[], null, undefined, 'abc']) {
    const s = summarize(v)
    assert.equal(s.total, 0)
    assert.equal(s.issued, 0)
  }
})

test('统计不因缺失 status 字段而崩溃（计入未申请）', () => {
  const s = summarize([{ site: 'a' }, { site: 'b', status: null }])
  assert.equal(s.total, 2)
  assert.equal(s.none, 2)
})

// ---------------------------------------------------------------------------
// 过滤
// ---------------------------------------------------------------------------

test('按关键字过滤同时匹配站点名与域名', () => {
  const list = [
    site({ site: 'blog', domain: 'blog.example.com' }),
    site({ site: 'shop', domain: 'store.example.com' }),
    site({ site: 'api', domain: 'api.other.org' }),
  ]
  // 匹配站点名
  assert.equal(filterSites(list, { keyword: 'blog' }).length, 1)
  // 匹配域名（用户可能只记得域名）
  assert.equal(filterSites(list, { keyword: 'store' }).length, 1)
  // 匹配域名后缀
  assert.equal(filterSites(list, { keyword: 'example.com' }).length, 2)
  // 大小写不敏感
  assert.equal(filterSites(list, { keyword: 'BLOG' }).length, 1)
  // 无匹配
  assert.equal(filterSites(list, { keyword: 'nothing' }).length, 0)
  // 空关键字返回全部
  assert.equal(filterSites(list, {}).length, 3)
  assert.equal(filterSites(list, { keyword: '   ' }).length, 3)
})

test('按状态过滤', () => {
  const list = [
    site({ site: 'a', status: 'valid' }),
    site({ site: 'b', status: 'expiring' }),
    site({ site: 'c', status: 'expiring' }),
    site({ site: 'd', status: 'none' }),
  ]
  assert.equal(filterSites(list, { status: 'expiring' }).length, 2)
  assert.equal(filterSites(list, { status: 'valid' }).length, 1)
  assert.equal(filterSites(list, { status: 'expired' }).length, 0)
  // 空状态返回全部
  assert.equal(filterSites(list, { status: '' }).length, 4)
})

test('关键字与状态可以同时生效', () => {
  const list = [
    site({ site: 'blog', domain: 'blog.example.com', status: 'valid' }),
    site({ site: 'blog2', domain: 'blog2.example.com', status: 'expiring' }),
  ]
  assert.equal(filterSites(list, { keyword: 'blog', status: 'valid' }).length, 1)
  assert.equal(filterSites(list, { keyword: 'blog', status: 'expiring' }).length, 1)
})

test('过滤非法输入不崩', () => {
  assert.deepEqual(filterSites(null, {}), [])
  assert.deepEqual(filterSites(undefined, { keyword: 'a' }), [])
})

// ---------------------------------------------------------------------------
// 需要关注的站点
// ---------------------------------------------------------------------------

// TestAttentionSitesOrdering 验证排序：越紧迫越靠前。
//
// SSL 的问题有**延迟爆发**的特征：今天没续上，30 天后站点突然打不开，
// 而那时用户早就忘了这回事。把最紧迫的摆到页面顶部是这个问题的
// 最有效缓解手段，因此排序必须正确。
test('需要关注的站点按紧迫度排序（已过期最前）', () => {
  const list = [
    site({ site: 'ok', status: 'valid', issued: true, days_remaining: 80 }),
    site({ site: 'soon', status: 'expiring', issued: true, days_remaining: 10 }),
    site({ site: 'gone', status: 'expired', issued: true, days_remaining: -3 }),
    site({ site: 'weird', status: 'unknown', issued: true }),
    site({ site: 'fresh', status: 'none', issued: false }),
  ]
  const out = attentionSites(list)
  // valid / none 不该出现在关注列表里
  assert.equal(out.length, 3)
  assert.equal(out[0].site, 'gone', '已过期必须排第一')
  assert.equal(out[1].site, 'weird', '状态异常排第二')
  assert.equal(out[2].site, 'soon', '即将过期排第三')
  // 绝不能包含正常站点
  assert.ok(!out.some((s) => s.site === 'ok'))
  assert.ok(!out.some((s) => s.site === 'fresh'))
})

test('同一紧迫度内剩余天数少的排前面', () => {
  const list = [
    site({ site: 'b', status: 'expiring', days_remaining: 20 }),
    site({ site: 'a', status: 'expiring', days_remaining: 5 }),
    site({ site: 'c', status: 'expiring', days_remaining: 12 }),
  ]
  const out = attentionSites(list)
  assert.deepEqual(
    out.map((s) => s.site),
    ['a', 'c', 'b'],
  )
})

test('全部健康时关注列表为空', () => {
  const list = [site({ status: 'valid' }), site({ status: 'none' })]
  assert.deepEqual(attentionSites(list), [])
  assert.equal(attentionText(list), '')
})

test('关注提示文案分别计数', () => {
  const list = [
    site({ site: 'a', status: 'expired' }),
    site({ site: 'b', status: 'expired' }),
    site({ site: 'c', status: 'expiring' }),
    site({ site: 'd', status: 'unknown' }),
    site({ site: 'e', status: 'valid' }),
  ]
  const text = attentionText(list)
  assert.ok(text.includes('2 个站点证书已过期'), `实际: ${text}`)
  assert.ok(text.includes('1 个站点证书即将过期'), `实际: ${text}`)
  assert.ok(text.includes('1 个站点证书状态异常'), `实际: ${text}`)
})

test('关注列表非法输入不崩', () => {
  assert.deepEqual(attentionSites(null), [])
  assert.deepEqual(attentionSites(undefined), [])
  assert.equal(attentionText(null), '')
})

// ---------------------------------------------------------------------------
// 客户端信息
// ---------------------------------------------------------------------------

test('客户端可用时展示版本与路径', () => {
  const info = clientText({
    kind: 'certbot',
    path: '/usr/bin/certbot',
    version: '1.21.0',
    available: true,
    source: 'PATH',
  })
  assert.equal(info.type, 'success')
  assert.ok(info.label.includes('certbot'))
  assert.ok(info.label.includes('1.21.0'))
  assert.ok(info.detail.includes('/usr/bin/certbot'))
})

test('acme.sh 也能正确展示', () => {
  const info = clientText({ kind: 'acme.sh', path: '/root/.acme.sh/acme.sh', available: true })
  assert.equal(info.type, 'success')
  assert.ok(info.label.includes('acme.sh'))
})

// TestClientUnavailableIsActionable 验证不可用提示是可操作的。
//
// 只说"不可用"等于把排查工作丢给用户。必须告诉他装什么、
// 以及装在非标准路径时怎么办。
test('客户端不可用时给出可操作的下一步', () => {
  const info = clientText({ available: false, reason: '未找到 certbot' })
  assert.equal(info.type, 'error')
  assert.ok(info.label.includes('不可用'))
  // 必须包含安装指引
  assert.ok(info.detail.includes('apt install certbot'), `实际: ${info.detail}`)
  // 必须包含非标准路径的处理方式
  assert.ok(info.detail.includes('-certbot-path'), `实际: ${info.detail}`)
})

test('客户端信息缺失时不崩', () => {
  for (const v of [null, undefined, {}]) {
    const info = clientText(v)
    assert.equal(info.type, 'error')
    assert.ok(info.detail.length > 0)
  }
})
