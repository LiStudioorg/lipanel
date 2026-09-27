// 防火墙页逻辑测试（阶段四 4.6）。
//
// ########## 这些测试断言的是什么 ##########
//
// 它们 import 的 firewallLogic.js 就是 FirewallView.vue 实际使用的
// 那份实现（本项目第 53 号坑位：逻辑若在测试里照抄一遍，
// 组件改了测试照样全绿，锁住的是副本而不是真代码）。
//
// 重点覆盖三类**出错就有实际后果**的逻辑：
//
//	① 端口/IP 校验 —— 必须与后端 validate.go 同构。
//	   前端松了，用户会看到"提交成功但后端 400"；
//	   前端紧了，用户会被挡在合法的输入之外。
//	② 受保护端口判定 —— 含端口范围覆盖。漏判会让用户
//	   在界面上看到"未受保护"从而放心删掉 SSH 端口。
//	③ 删除确认文案 —— 计划明确要求"写明具体端口"。
//	   这段字是用户做决定前唯一的信息来源。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  BACKEND_LABEL,
  ACTION_META,
  PROTECT_PANEL,
  PROTECT_SSH,
  AUDIT_OUTCOME_META,
  AUDIT_ACTION_LABEL,
  backendLabel,
  actionMeta,
  originMeta,
  protectMeta,
  protectionIndex,
  findProtection,
  parsePortSpec,
  validatePort,
  validateIP,
  validateComment,
  buildPortPayload,
  buildIPPayload,
  deletePortConfirmText,
  deleteIPConfirmText,
  ruleTargetText,
  protocolLabel,
  sourceLabel,
  portLabel,
  familyLabel,
  defaultPolicyText,
  firewallHealthMeta,
  protectionSummary,
  filterRules,
  summarizeRules,
  auditOutcomeMeta,
  auditActionLabel,
  formatAuditTime,
  commandTimeoutText,
} from './firewallLogic.js'

// ---------------------------------------------------------------------------
// 常量与后端对齐
// ---------------------------------------------------------------------------

test('后端标签与 internal/firewall 对齐', () => {
  // 这些键必须与 Go 侧的 BackendUFW / BackendFirewalld 等一一对应。
  for (const k of ['ufw', 'firewalld', 'nftables', 'iptables', 'none']) {
    assert.ok(BACKEND_LABEL[k], `缺少后端标签: ${k}`)
  }
  assert.equal(backendLabel('ufw'), 'ufw')
  // 未知后端原样返回（便于排错，而不是显示成"未知"）。
  assert.equal(backendLabel('mystery'), 'mystery')
  assert.equal(backendLabel(''), '未知')
})

test('动作标签与后端 action 常量对齐', () => {
  assert.ok(ACTION_META.allow)
  assert.ok(ACTION_META.deny)
  // allow 用成功色、deny 用错误色——这一对颜色反了会让用户
  // 把"拒绝"看成"放行"。
  assert.equal(ACTION_META.allow.type, 'success')
  assert.equal(ACTION_META.deny.type, 'error')
  assert.equal(actionMeta('allow').label, '允许')
  assert.equal(actionMeta('deny').label, '拒绝')
})

test('来源标签与后端 origin 常量对齐', () => {
  assert.equal(originMeta('panel').label, '面板创建')
  assert.equal(originMeta('external').label, '外部创建')
})

test('保护类型与后端 protect 常量对齐', () => {
  assert.equal(PROTECT_PANEL, 'panel')
  assert.equal(PROTECT_SSH, 'ssh')
  // SSH 用 error 色（比面板端口更严重）。
  assert.equal(protectMeta(PROTECT_SSH).type, 'error')
  assert.equal(protectMeta(PROTECT_PANEL).type, 'warning')
})

test('审计标签与后端 audit/permission 常量对齐', () => {
  for (const o of ['allowed', 'denied', 'failed']) {
    assert.ok(AUDIT_OUTCOME_META[o], `缺少审计结果: ${o}`)
  }
  // 动作名必须与 permission.go 里的常量一致。
  for (const a of [
    'status', 'list_rules', 'audit', 'capabilities',
    'add_port', 'delete_port', 'add_ip', 'delete_ip', 'enable',
  ]) {
    assert.ok(AUDIT_ACTION_LABEL[a], `缺少审计动作标签: ${a}`)
  }
  assert.equal(auditActionLabel('delete_port'), '删除端口')
  assert.equal(auditOutcomeMeta('denied').label, '被拒绝')
})

// ---------------------------------------------------------------------------
// ① 端口校验（与后端 validate.go 同构）
// ---------------------------------------------------------------------------

test('parsePortSpec 接受合法端口与范围', () => {
  assert.deepEqual(parsePortSpec('8080'), { start: 8080, end: 8080, isRange: false })
  assert.deepEqual(parsePortSpec('8080-8090'), { start: 8080, end: 8090, isRange: true })
  assert.deepEqual(parsePortSpec('1'), { start: 1, end: 1, isRange: false })
  assert.deepEqual(parsePortSpec('65535'), { start: 65535, end: 65535, isRange: false })
  assert.deepEqual(parsePortSpec('1-65535'), { start: 1, end: 65535, isRange: true })
  // 起止相同的范围退化为单端口。
  assert.equal(parsePortSpec('8080-8080').isRange, false)
})

test('parsePortSpec 拒绝非法端口', () => {
  const bad = [
    '', ' ', '0', '65536', '999999999999999999999',
    '08080',            // 前导零（后端正则明确拒绝）
    '8080-', '-8080', '8080-8090-9000',
    '22;reboot',        // 注入
    '22$(id)',          // 命令替换
    '22`id`',           // 反引号
    '+22', '0x16', '2_2', '22.0', '2e1',
    ' 8080', '8080 ',   // 前后空格
    '８０８０',           // 全角数字
    '٢٢',               // 阿拉伯-印度数字
    '8090-8080',        // 反向范围
    '0-100',            // 起点为 0
    '100-65536',        // 终点越界
  ]
  for (const v of bad) {
    assert.equal(parsePortSpec(v), null, `parsePortSpec(${JSON.stringify(v)}) 应为 null`)
  }
})

test('validatePort 对非法输入给出可操作的中文提示', () => {
  assert.equal(validatePort('8080'), null)
  assert.equal(validatePort('8080-8090'), null)

  assert.match(validatePort(''), /请输入/)
  assert.match(validatePort('0'), /1-65535/)
  assert.match(validatePort('65536'), /1-65535/)
  assert.match(validatePort(' 8080'), /空格/)
  // 反向范围要提示"你想输入的是 X-Y 吗"——直接报"非法"用户不知道错在哪。
  assert.match(validatePort('8090-8080'), /8090-8080|起始值不能大于结束值/)
  assert.match(validatePort('08080'), /前导零|纯数字/)
  assert.match(validatePort('abc'), /纯数字/)
})

test('validatePort 与后端的边界完全一致', () => {
  // 后端 MinPort=1、MaxPort=65535。
  assert.equal(validatePort('1'), null)
  assert.equal(validatePort('65535'), null)
  assert.notEqual(validatePort('0'), null)
  assert.notEqual(validatePort('65536'), null)
  // 后端拒绝前导零——前端也必须拒绝，否则出现"前端通过后端报错"。
  assert.notEqual(validatePort('01'), null)
  assert.notEqual(validatePort('08080-08090'), null)
})

// ---------------------------------------------------------------------------
// ② IP 校验
// ---------------------------------------------------------------------------

test('validateIP 接受合法地址与网段', () => {
  for (const v of [
    '1.2.3.4', '0.0.0.0', '255.255.255.255',
    '192.168.1.0/24', '10.0.0.0/8', '0.0.0.0/0',
    '::1', '2001:db8::/32', 'fe80::1',
  ]) {
    assert.equal(validateIP(v), null, `validateIP(${v}) 应通过`)
  }
})

test('validateIP 拒绝非法地址', () => {
  assert.notEqual(validateIP(''), null)
  assert.notEqual(validateIP('not-an-ip'), null)
  assert.notEqual(validateIP('256.1.1.1'), null)
  assert.notEqual(validateIP('1.2.3'), null)
  assert.notEqual(validateIP('010.1.1.1'), null)   // 前导零（八进制歧义）
  assert.notEqual(validateIP('fe80::1%eth0'), null) // zone 后缀
  assert.notEqual(validateIP(' 1.2.3.4'), null)
  assert.notEqual(validateIP('192.168.1.0/33'), null)
})

test('validateIP 把「IP:端口」的误填说清楚', () => {
  // 这是用户最容易犯的错：把 "1.2.3.4:22" 整个粘进 IP 字段。
  // 光说"格式错误"没有帮助，要点明"端口应该填在端口字段"。
  const msg = validateIP('1.2.3.4:22')
  assert.notEqual(msg, null)
  assert.match(msg, /IP:端口|端口/)
  assert.match(msg, /22/)
})

test('validateIP 对主机位非零的网段给出规范形式', () => {
  // nft 会直接拒绝这种写法，iptables 会静默按掩码处理——
  // 两种结果都不是用户想要的，因此要在前端就拦下并给出正确写法。
  const msg = validateIP('192.168.1.5/24')
  assert.notEqual(msg, null)
  assert.match(msg, /192\.168\.1\.0\/24/)
})

// ---------------------------------------------------------------------------
// ③ 备注校验
// ---------------------------------------------------------------------------

test('validateComment 拒绝换行与控制字符', () => {
  assert.equal(validateComment(''), null)
  assert.equal(validateComment(undefined), null)
  assert.equal(validateComment('正常备注'), null)

  // ########## 换行必须拒绝 ##########
  // 备注在 ufw 后端会写进 /etc/ufw/user.rules 的 comment= 字段，
  // 那个文件由 ufw 逐行解析——一个换行就能插入伪造的规则行。
  assert.notEqual(validateComment('a\nb'), null)
  assert.notEqual(validateComment('a\rb'), null)
  assert.notEqual(validateComment('a\u0000b'), null)
  assert.notEqual(validateComment('a\tb'), null) // 制表符也是控制字符
})

test('validateComment 限制 128 个字符', () => {
  assert.equal(validateComment('a'.repeat(128)), null)
  assert.notEqual(validateComment('a'.repeat(129)), null)
  // 按字符数而不是字节数：128 个中文应当通过（后端用 rune 计数）。
  assert.equal(validateComment('中'.repeat(128)), null)
  assert.notEqual(validateComment('中'.repeat(129)), null)
})

// ---------------------------------------------------------------------------
// ④ 受保护端口判定（含范围覆盖）
// ---------------------------------------------------------------------------

test('protectionIndex 把保护列表转成端口映射', () => {
  const idx = protectionIndex({
    ports: [
      { port: 22, kind: 'ssh', reason: 'SSH 端口' },
      { port: 8080, kind: 'panel', reason: '面板端口' },
    ],
  })
  assert.equal(idx[22].kind, 'ssh')
  assert.equal(idx[8080].kind, 'panel')
  assert.equal(protectionIndex(null)[1], undefined)
  assert.deepEqual(protectionIndex({}), {})
})

test('findProtection 精确匹配', () => {
  const idx = protectionIndex({ ports: [{ port: 22, kind: 'ssh', reason: 'SSH' }] })
  assert.equal(findProtection(idx, '22').kind, 'ssh')
  assert.equal(findProtection(idx, '2222'), null)
})

test('findProtection 捕获覆盖受保护端口的范围', () => {
  // ########## 这是本组测试里最重要的一个 ##########
  //
  // 若用户删掉 "20-30" 这个范围，22 端口一并被关掉——
  // 只做精确匹配的界面会显示"未受保护"，用户毫无防备地删掉，
  // 然后失去 SSH 连接。
  const idx = protectionIndex({ ports: [{ port: 22, kind: 'ssh', reason: 'SSH' }] })
  const hit = findProtection(idx, '20-30')
  assert.notEqual(hit, null)
  assert.equal(hit.kind, 'ssh')

  // 边界：范围正好以受保护端口结尾 / 开头。
  assert.notEqual(findProtection(idx, '1-22'), null)
  assert.notEqual(findProtection(idx, '22-100'), null)
  // 不覆盖的返回 null。
  assert.equal(findProtection(idx, '100-200'), null)
  assert.equal(findProtection(idx, '1-21'), null)
})

test('findProtection 对非法端口返回 null', () => {
  const idx = protectionIndex({ ports: [{ port: 22, kind: 'ssh' }] })
  assert.equal(findProtection(idx, 'abc'), null)
  assert.equal(findProtection(idx, ''), null)
  assert.equal(findProtection(idx, '8090-8080'), null)
})

// ---------------------------------------------------------------------------
// ⑤ 删除确认文案（计划明确要求"写明具体端口"）
// ---------------------------------------------------------------------------

test('deletePortConfirmText 写明具体端口与协议', () => {
  const rule = { port_text: '8080', protocol: 'tcp', action: 'allow', source: '' }
  const text = deletePortConfirmText(rule, null)
  // 计划明确要求：文案必须写明**具体端口**。
  // 只说"确定删除吗"用户无法核对是不是他想删的那条。
  assert.match(text, /8080/)
  assert.match(text, /tcp/)
  assert.match(text, /删除/)
  // 必须告知"没有撤销"。
  assert.match(text, /撤销|恢复/)
})

test('deletePortConfirmText 对受保护端口升级为红色警告', () => {
  const rule = { port_text: '22', protocol: 'tcp', action: 'allow' }
  const protection = { port: 22, kind: 'ssh', reason: 'SSH 服务端口（来自 sshd 配置）' }
  const text = deletePortConfirmText(rule, protection)

  assert.match(text, /警告/)
  // 必须写出保护原因（用户据此判断"我是不是真的要删"）。
  assert.match(text, /SSH 服务端口/)
  // 必须写明端口号。
  assert.match(text, /22/)
  // 必须说明失联后果。
  assert.match(text, /失去|无法/)
  // 受保护时应当比普通删除**更长**（信息更多）。
  const plain = deletePortConfirmText(rule, null)
  assert.ok(text.length > plain.length)
})

test('deletePortConfirmText 提示外部创建的规则', () => {
  const rule = { port_text: '3306', protocol: 'tcp', action: 'allow', origin: 'external' }
  const text = deletePortConfirmText(rule, null)
  // 外部规则可能被 Docker 或管理员依赖，删掉会波及别的服务。
  assert.match(text, /不是由本面板创建|外部|Docker/)
})

test('deletePortConfirmText 带上备注（便于核对）', () => {
  const rule = { port_text: '8080', protocol: 'tcp', action: 'allow', comment: '生产 Web' }
  assert.match(deletePortConfirmText(rule, null), /生产 Web/)
})

test('deleteIPConfirmText 区分白名单与黑名单', () => {
  const white = deleteIPConfirmText({ source: '1.2.3.4', action: 'allow' })
  assert.match(white, /白名单/)
  assert.match(white, /1\.2\.3\.4/)
  assert.match(white, /默认策略/)

  const black = deleteIPConfirmText({ source: '5.6.7.8', action: 'deny' })
  assert.match(black, /黑名单/)
  // 删掉黑名单条目 = 该来源可以重新访问，这个后果必须说清楚。
  assert.match(black, /重新访问/)
})

test('ruleTargetText 组合端口、来源与动作', () => {
  assert.match(ruleTargetText({ port_text: '8080', protocol: 'tcp', action: 'allow' }), /8080\/tcp/)
  assert.match(ruleTargetText({ port_text: '8080', protocol: 'tcp', action: 'allow' }), /任意来源/)
  assert.match(
    ruleTargetText({ port_text: '8080', protocol: 'tcp', action: 'allow', source: '1.2.3.4' }),
    /来自 1\.2\.3\.4/,
  )
  assert.match(ruleTargetText({ port_text: '8080', action: 'deny' }), /拒绝/)
})

// ---------------------------------------------------------------------------
// ⑥ 表单组装（字段名必须与后端一致）
// ---------------------------------------------------------------------------

test('buildPortPayload 字段名与后端 PortRequest 一致', () => {
  // 后端开了 DisallowUnknownFields，字段名拼错会直接 400。
  const p = buildPortPayload({
    port: ' 8080 ', protocol: 'udp', source: ' 1.2.3.4 ', action: 'deny', comment: ' 备注 ',
  })
  assert.deepEqual(Object.keys(p).sort(), ['action', 'comment', 'port', 'protocol', 'source'])
  assert.equal(p.port, '8080')       // 首尾空格被去掉
  assert.equal(p.source, '1.2.3.4')
  assert.equal(p.comment, '备注')
  assert.equal(p.protocol, 'udp')
  assert.equal(p.action, 'deny')
})

test('buildPortPayload 使用后端默认值', () => {
  const p = buildPortPayload({ port: '8080' })
  assert.equal(p.protocol, 'tcp')
  assert.equal(p.action, 'allow')
  assert.equal(p.source, '')
  assert.equal(p.comment, '')
})

test('buildIPPayload 字段名与后端 IPRequest 一致', () => {
  const p = buildIPPayload({ ip: ' 1.2.3.4 ', direction: 'deny', comment: 'x' })
  assert.deepEqual(Object.keys(p).sort(), ['comment', 'direction', 'ip'])
  assert.equal(p.ip, '1.2.3.4')
  // 默认方向是 deny（黑名单）——这是更安全的默认值：
  // 误加一条黑名单最多挡住一个来源，误加白名单却会放行一个来源。
  assert.equal(buildIPPayload({ ip: '1.2.3.4' }).direction, 'deny')
})

// ---------------------------------------------------------------------------
// ⑦ 展示辅助
// ---------------------------------------------------------------------------

test('protocolLabel 与后端协议常量对齐', () => {
  assert.equal(protocolLabel('tcp'), 'TCP')
  assert.equal(protocolLabel('udp'), 'UDP')
  assert.equal(protocolLabel('any'), 'TCP + UDP')
  assert.equal(protocolLabel(''), '—')
  assert.equal(protocolLabel(undefined), '—')
})

test('sourceLabel 把空来源显示为任意来源', () => {
  assert.equal(sourceLabel(''), '任意来源')
  assert.equal(sourceLabel('  '), '任意来源')
  assert.equal(sourceLabel('1.2.3.4'), '1.2.3.4')
})

test('portLabel 标注端口范围', () => {
  assert.equal(portLabel({ port_text: '8080' }), '8080')
  // 范围要显式标注：用户需要知道这条规则影响的是一个区间。
  assert.match(portLabel({ port_text: '8080-8090' }), /范围/)
  assert.equal(portLabel({}), '—')
})

test('familyLabel 与后端族常量对齐', () => {
  assert.equal(familyLabel('ipv4'), 'IPv4')
  assert.equal(familyLabel('ipv6'), 'IPv6')
  assert.equal(familyLabel(''), '—')
})

// ---------------------------------------------------------------------------
// ⑧ 健康状态（三种状态必须区分）
// ---------------------------------------------------------------------------

test('firewallHealthMeta 区分未安装 / 未启用 / 默认放行 / 正常', () => {
  // 未安装。
  const missing = firewallHealthMeta({ available: false, unavailable_reason: '未找到 ufw' })
  assert.equal(missing.type, 'warning')
  assert.match(missing.label, /未检测到/)
  assert.match(missing.detail, /未找到 ufw/)

  // 未启用——**最危险的一种**：用户以为规则在生效，实际全都没生效。
  const inactive = firewallHealthMeta({
    available: true, detail: { enabled: false, allow_all_incoming: true },
  })
  assert.equal(inactive.type, 'warning')
  assert.match(inactive.label, /未启用/)
  assert.match(inactive.detail, /不会生效/)

  // 默认放行——启用了但等于没防护，必须用 error 色。
  const allowAll = firewallHealthMeta({
    available: true, detail: { enabled: true, allow_all_incoming: true },
  })
  assert.equal(allowAll.type, 'error')
  assert.match(allowAll.label, /默认放行/)
  assert.match(allowAll.detail, /所有端口都是开放/)

  // 正常。
  const ok = firewallHealthMeta({
    available: true, detail: { enabled: true, allow_all_incoming: false },
  })
  assert.equal(ok.type, 'success')

  assert.equal(firewallHealthMeta(null).type, 'default')
})

test('defaultPolicyText 汇总各来源的策略', () => {
  assert.equal(defaultPolicyText({ default_incoming: 'deny' }), '入站 deny')
  assert.equal(
    defaultPolicyText({ default_incoming: 'deny', default_outgoing: 'allow' }),
    '入站 deny、出站 allow',
  )
  assert.match(defaultPolicyText({ default_policies: { INPUT: 'DROP' } }), /INPUT drop/)
  assert.equal(defaultPolicyText(null), '')
})

test('protectionSummary 说明已保护端口', () => {
  const text = protectionSummary({
    ports: [
      { port: 22, kind: 'ssh' },
      { port: 8080, kind: 'panel' },
    ],
    ssh_detected: true,
  })
  assert.match(text, /22/)
  assert.match(text, /SSH 端口/)
  assert.match(text, /8080/)
  assert.match(text, /面板端口/)
})

test('protectionSummary 在探测不到 SSH 时如实说明（不假装已保护）', () => {
  // ########## 后端宁可返回空也不猜测 SSH 端口 ##########
  //
  // 界面必须把这件事如实告诉用户，否则他会把
  // "没有 SSH 端口被保护" 理解为 "这台机器没有 SSH"。
  const text = protectionSummary({
    ports: [{ port: 8080, kind: 'panel' }],
    ssh_detected: false,
  })
  assert.match(text, /未能确定 SSH/)
  assert.match(text, /自行确认/)
  // 不能凭空说出 22。
  assert.ok(!/保护端口：.*22/.test(text))
})

// ---------------------------------------------------------------------------
// ⑨ 过滤与统计
// ---------------------------------------------------------------------------

const sampleRules = [
  { port_text: '22', protocol: 'tcp', action: 'allow', source: '', comment: '', kind: 'port', raw: '22/tcp' },
  { port_text: '8080', protocol: 'tcp', action: 'allow', source: '1.2.3.4', comment: 'web', kind: 'port', raw: '8080' },
  { port_text: '3306', protocol: 'tcp', action: 'deny', source: '', comment: '', kind: 'port', raw: '3306' },
  { port_text: '', protocol: '', action: 'deny', source: '5.6.7.8', comment: '攻击者', kind: 'ip', raw: 'deny from 5.6.7.8' },
]

test('filterRules 按关键字匹配多个字段', () => {
  assert.equal(filterRules(sampleRules, { keyword: '8080' }).length, 1)
  assert.equal(filterRules(sampleRules, { keyword: 'web' }).length, 1)   // 备注
  assert.equal(filterRules(sampleRules, { keyword: '1.2.3.4' }).length, 1) // 来源
  assert.equal(filterRules(sampleRules, { keyword: '5.6.7.8' }).length, 1)
  assert.equal(filterRules(sampleRules, { keyword: '攻击者' }).length, 1)
  // 大小写不敏感。
  assert.equal(filterRules(sampleRules, { keyword: 'WEB' }).length, 1)
  assert.equal(filterRules(sampleRules, {}).length, 4)
  assert.equal(filterRules(sampleRules, { keyword: '不存在' }).length, 0)
  // 空数组安全。
  assert.deepEqual(filterRules(null, { keyword: 'x' }), [])
})

test('filterRules 按动作与类别过滤', () => {
  assert.equal(filterRules(sampleRules, { action: 'allow' }).length, 2)
  assert.equal(filterRules(sampleRules, { action: 'deny' }).length, 2)
  assert.equal(filterRules(sampleRules, { kind: 'ip' }).length, 1)
  assert.equal(filterRules(sampleRules, { kind: 'port' }).length, 3)
  // 组合条件。
  assert.equal(filterRules(sampleRules, { action: 'deny', kind: 'port' }).length, 1)
})

test('summarizeRules 汇总统计并算出不可删除数', () => {
  const s = summarizeRules({
    counts: {
      total: 10, ports: 7, ips: 3, allow: 6, deny: 4,
      deletable: 8, protected: 2, panel: 5, external: 5,
    },
  })
  assert.equal(s.total, 10)
  assert.equal(s.ports, 7)
  assert.equal(s.deletable, 8)
  // ########## 不可删除数 = 总数 - 可删除数 ##########
  // 这个数字解释"为什么有些行没有删除按钮"。
  assert.equal(s.notDeletable, 2)
})

test('summarizeRules 在缺少 counts 时不崩', () => {
  const s = summarizeRules(null)
  assert.equal(s.total, 0)
  assert.equal(s.deletable, 0)
  assert.equal(s.notDeletable, 0)
})

// ---------------------------------------------------------------------------
// ⑩ 时间与超时展示
// ---------------------------------------------------------------------------

test('formatAuditTime 格式化 RFC3339 时间', () => {
  assert.equal(formatAuditTime(''), '—')
  assert.equal(formatAuditTime(undefined), '—')
  const out = formatAuditTime('2025-01-15T09:30:45Z')
  assert.match(out, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
  // 无法解析时原样返回（不要在界面上显示出 "Invalid Date"）。
  assert.equal(formatAuditTime('not-a-time'), 'not-a-time')
})

test('commandTimeoutText 展示超时配置', () => {
  assert.equal(commandTimeoutText(0), '未设置')
  assert.equal(commandTimeoutText(15), '15 秒')
  assert.equal(commandTimeoutText(120), '2 分钟')
})
