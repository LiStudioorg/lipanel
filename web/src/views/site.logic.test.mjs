// 网站管理纯逻辑测试（阶段四 4.3）。
//
// 用 node:test（本仓库不引入 jsdom，保持轻量约束），
// 因此测的是 siteLogic.js 里的纯函数——也就是**组件真正使用的那份逻辑**。
//
// 这些用例的重点与后端 validate_test.go 一致：**穷举注入载荷**。
// 前端校验的定位是体验（让用户在提交前看到问题），但它必须是
// 后端规则的**忠实镜像**：前端放过后端拒绝，用户体验是
// "点提交 → 转圈 → 报错"；两者一致才是"输入时就看到红字"。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  NGINX_METACHARACTERS,
  RESERVED_SITE_NAMES,
  actionDisabled,
  buildSitePayload,
  canOperate,
  deleteConfirmText,
  emptyForm,
  filterSites,
  findMetacharacter,
  formFromSite,
  formatTarget,
  normalizePath,
  statusMeta,
  summarize,
  targetLabel,
  typeMeta,
  validateDomain,
  validateForm,
  validateRoot,
  validateSiteName,
  validateUpstream,
} from './siteLogic.js'

// ---------------------------------------------------------------------------
// 注入载荷穷举
// ---------------------------------------------------------------------------

// injectionPayloads 与后端 validate_test.go 的同名集合保持一致。
const injectionPayloads = [
  'a;b', 'a{b', 'a}b', 'a$b', 'a`b', "a'b", 'a"b', 'a#b',
  'a\nb', 'a\rb', 'a\tb', 'a b', 'a\\b', 'a/b', 'a..b', '../etc',
  '..', '/etc/passwd', 'a|b', 'a&b', 'a<b', 'a>b', 'a?b', 'a*b',
]

// lexicalMergeSafe 与后端 validate_test.go 的同名集合保持一致。
//
// 这些载荷本身是 /、..、? 这类**结构字符**。当前缀拼接后，结果在词法上
// 与一条正常输入完全一致：
//
//   /var/www      + /etc/passwd  →  /var/www/etc/passwd   （合法的绝对路径）
//   host:3000     + /a/b         →  host:3000/a/b        （合法的 proxy 路径）
//   example.com   + a*b          →  example.coma*b       （星号在标签内合法）
//
// 它们**没有任何可注入的内容**（不含分号、花括号、换行），
// 拒绝它们只会误伤正常功能。真正成立且真正重要的命题是
// "任何 nginx 元字符都不可能通过校验"，由文件末尾的穷举用例锁死。
const lexicalMergeSafe = new Set(['a/b', 'a..b', '..', '../etc', '/etc/passwd', 'a?b', 'a*b'])

test('findMetacharacter 能识别全部 nginx 元字符', () => {
  for (const ch of NGINX_METACHARACTERS) {
    assert.equal(findMetacharacter(`ab${ch}cd`), ch, `应识别出 ${JSON.stringify(ch)}`)
  }
  // 干净字符串不应误报。
  assert.equal(findMetacharacter('example.com'), '')
  assert.equal(findMetacharacter('/var/www/html'), '')
})

test('validateSiteName 拒绝全部注入载荷', () => {
  for (const payload of injectionPayloads) {
    for (const candidate of [payload, `site${payload}`]) {
      const err = validateSiteName(candidate)
      assert.notEqual(err, '', `站点名 ${JSON.stringify(candidate)} 应被拒绝`)
    }
  }
})

test('validateSiteName 接受合法命名', () => {
  for (const name of [
    'a', 'A', '0', 'example', 'example.com', 'api-v2', 'my_site',
    'site123', 'a.b.c.d', 'www.example.com', 'test-site_2.0',
  ]) {
    assert.equal(validateSiteName(name), '', `站点名 ${name} 应合法`)
  }
})

test('validateSiteName 拒绝边界与保留名', () => {
  assert.notEqual(validateSiteName(''), '')
  assert.notEqual(validateSiteName('a'.repeat(65)), '')
  assert.notEqual(validateSiteName('-leading'), '')
  assert.notEqual(validateSiteName('trailing-'), '')
  assert.notEqual(validateSiteName('.leading'), '')
  assert.notEqual(validateSiteName('_leading'), '')
  assert.notEqual(validateSiteName('..'), '')
  assert.notEqual(validateSiteName('a..b'), '')

  for (const reserved of RESERVED_SITE_NAMES) {
    assert.notEqual(validateSiteName(reserved), '', `保留名 ${reserved} 应被拒绝`)
    assert.notEqual(
      validateSiteName(reserved.toUpperCase()),
      '',
      `保留名 ${reserved} 的大写形式也应被拒绝`,
    )
  }
})

test('validateSiteName 在编辑模式下不校验（站点不支持改名）', () => {
  assert.equal(validateSiteName('anything', { isEdit: true }), '')
  assert.equal(validateSiteName('', { isEdit: true }), '')
})

test('validateDomain 拒绝全部注入载荷', () => {
  for (const payload of injectionPayloads) {
    if (lexicalMergeSafe.has(payload)) continue // 见 lexicalMergeSafe 的说明
    for (const candidate of [payload, `example.com;${payload}`]) {
      assert.notEqual(
        validateDomain(candidate),
        '',
        `域名 ${JSON.stringify(candidate)} 应被拒绝`,
      )
    }
  }
})

test('validateDomain 拒绝典型注入场景', () => {
  for (const p of [
    'example.com; root /etc;',
    'example.com; } server { listen 80; root /etc; server_name x; #',
    'example.com\n    root /etc;',
    'example.com {',
    'example.com }',
  ]) {
    assert.notEqual(validateDomain(p), '', `注入载荷 ${JSON.stringify(p)} 应被拒绝`)
  }
})

test('validateDomain 接受合法域名形态', () => {
  for (const d of [
    'example.com', 'www.example.com', 'api-v2.example.com', 'localhost',
    '_', '*.example.com', 'sub.domain.co.uk', 'a', '1.2.3.4', 'my_host.example.com',
  ]) {
    assert.equal(validateDomain(d), '', `域名 ${d} 应合法`)
  }
})

test('validateDomain 拒绝畸形形态', () => {
  for (const d of [
    '', '.example.com', 'example.com.', 'example..com', '-example.com',
    'example-.com', '*', 'exa mple.com', 'example.com:80', '中文.example.com',
  ]) {
    assert.notEqual(validateDomain(d), '', `域名 ${JSON.stringify(d)} 应被拒绝`)
  }
})

test('validateRoot 拒绝全部注入载荷', () => {
  for (const payload of injectionPayloads) {
    if (lexicalMergeSafe.has(payload)) continue // 见 lexicalMergeSafe 的说明
    for (const candidate of [`/var/www;${payload}`, `${payload}/var/www`]) {
      assert.notEqual(
        validateRoot(candidate),
        '',
        `根目录 ${JSON.stringify(candidate)} 应被拒绝`,
      )
    }
  }
})

test('validateRoot 接受合法路径', () => {
  for (const p of [
    '/var/www/html', '/var/www/example.com', '/home/user/site',
    '/srv/www/my-site', '/tmp/lipanel-e2e/www',
  ]) {
    assert.equal(validateRoot(p), '', `根目录 ${p} 应合法`)
  }
})

test('validateRoot 拒绝畸形路径', () => {
  for (const p of ['', '   ', 'var/www', './var/www', '/', '/var/www/', '/var//www', '/var/www/../etc', '/var/www html']) {
    assert.notEqual(validateRoot(p), '', `根目录 ${JSON.stringify(p)} 应被拒绝`)
  }
})

test('validateUpstream 拒绝全部注入载荷', () => {
  for (const payload of injectionPayloads) {
    if (lexicalMergeSafe.has(payload)) continue // 见 lexicalMergeSafe 的说明
    const candidates = [
      `http://127.0.0.1:3000;${payload}`,
      `http://127.0.0.1:3000/${payload}`,
    ]
    for (const candidate of candidates) {
      assert.notEqual(
        validateUpstream(candidate),
        '',
        `反代目标 ${JSON.stringify(candidate)} 应被拒绝`,
      )
    }
  }
})

test('validateUpstream 拒绝 unix socket 与其它协议', () => {
  for (const p of [
    'unix:/var/run/docker.sock',
    'http://unix:/var/run/docker.sock',
    'ftp://127.0.0.1:21',
    'file:///etc/passwd',
    'ws://127.0.0.1:3000',
  ]) {
    assert.notEqual(validateUpstream(p), '', `${p} 应被拒绝`)
  }
})

test('validateUpstream 接受合法目标', () => {
  for (const u of [
    'http://127.0.0.1:3000', '127.0.0.1:3000', 'https://backend.internal',
    'http://localhost:5000', 'http://192.168.1.10:8000', 'http://backend:3000',
    'http://backend.example.com:3000', 'http://127.0.0.1:3000/api',
  ]) {
    assert.equal(validateUpstream(u), '', `反代目标 ${u} 应合法`)
  }
})

test('validateUpstream 拒绝畸形目标', () => {
  for (const u of [
    '', 'http://', 'http://127.0.0.1:0', 'http://127.0.0.1:99999',
    'http://user:pass@127.0.0.1:3000', 'http://127.0.0.1:3000?a=b',
  ]) {
    assert.notEqual(validateUpstream(u), '', `反代目标 ${JSON.stringify(u)} 应被拒绝`)
  }
})

test('normalizePath 折叠重复斜杠并去掉末尾斜杠', () => {
  assert.equal(normalizePath('/var//www'), '/var/www')
  assert.equal(normalizePath('/var/www/'), '/var/www')
  assert.equal(normalizePath('/var/www'), '/var/www')
  assert.equal(normalizePath('/'), '/')
})

// ---------------------------------------------------------------------------
// 表单组装与整体校验
// ---------------------------------------------------------------------------

test('emptyForm 默认静态站且启用', () => {
  const form = emptyForm()
  assert.equal(form.type, 'static')
  assert.equal(form.enabled, true)
  assert.equal(form.name, '')
})

test('validateForm 一次性返回全部错误', () => {
  const form = { ...emptyForm(), name: '', domain: '', root: '' }
  const errors = validateForm(form)
  // 三个字段都应有错误，而不是只报第一个。
  assert.ok(errors.name, '应报告站点名错误')
  assert.ok(errors.domain, '应报告域名错误')
  assert.ok(errors.root, '应报告根目录错误')
})

test('validateForm 对合法静态站返回空对象', () => {
  const form = {
    name: 'demo', domain: 'demo.example.com', type: 'static',
    root: '/var/www/demo', upstream: '', enabled: true,
  }
  assert.deepEqual(validateForm(form), {})
})

test('validateForm 对合法反代站返回空对象', () => {
  const form = {
    name: 'api', domain: 'api.example.com', type: 'proxy',
    root: '', upstream: 'http://127.0.0.1:3000', enabled: true,
  }
  assert.deepEqual(validateForm(form), {})
})

test('validateForm 拒绝类型与字段不匹配（后端会 400）', () => {
  // 静态站残留 upstream。
  const staticWithUpstream = {
    name: 'a', domain: 'x.com', type: 'static',
    root: '/var/www', upstream: 'http://127.0.0.1:3000', enabled: true,
  }
  assert.ok(validateForm(staticWithUpstream).upstream, '静态站带 upstream 应报错')

  // 反代站残留 root。
  const proxyWithRoot = {
    name: 'a', domain: 'x.com', type: 'proxy',
    root: '/var/www', upstream: 'http://127.0.0.1:3000', enabled: true,
  }
  assert.ok(validateForm(proxyWithRoot).root, '反代站带 root 应报错')
})

test('validateForm 拒绝未知类型', () => {
  const form = { ...emptyForm(), name: 'a', domain: 'x.com', type: 'php' }
  assert.ok(validateForm(form).type, '未知类型应报错')
})

test('buildSitePayload 只发送当前类型用得上的字段', () => {
  // 这是关键契约：后端"类型与字段不匹配时直接拒绝"（不静默丢弃），
  // 因此前端必须把无关字段清空，否则切换类型后会一直提交失败。
  const staticForm = {
    name: ' demo ', domain: ' demo.example.com ', type: 'static',
    root: ' /var/www/demo ', upstream: 'http://127.0.0.1:3000', enabled: true,
  }
  const staticPayload = buildSitePayload(staticForm)
  assert.equal(staticPayload.root, '/var/www/demo')
  assert.equal(staticPayload.upstream, '')
  assert.equal(staticPayload.name, 'demo', '应去除首尾空白')

  const proxyForm = {
    name: 'api', domain: 'api.example.com', type: 'proxy',
    root: '/var/www', upstream: ' http://127.0.0.1:3000 ', enabled: false,
  }
  const proxyPayload = buildSitePayload(proxyForm)
  assert.equal(proxyPayload.upstream, 'http://127.0.0.1:3000')
  assert.equal(proxyPayload.root, '')
  assert.equal(proxyPayload.enabled, false)
})

test('formFromSite 与 buildSitePayload 可往返', () => {
  const site = {
    name: 'demo', domain: 'demo.example.com', type: 'static',
    root: '/var/www/demo', upstream: '', enabled: true,
  }
  const payload = buildSitePayload(formFromSite(site))
  assert.deepEqual(payload, {
    name: 'demo', domain: 'demo.example.com', type: 'static',
    root: '/var/www/demo', upstream: '', enabled: true,
  })
})

// ---------------------------------------------------------------------------
// 展示辅助
// ---------------------------------------------------------------------------

test('typeMeta 返回类型标签并安全回落', () => {
  assert.equal(typeMeta('static').label, '静态站')
  assert.equal(typeMeta('proxy').label, '反向代理')
  // 未知类型不应抛错。
  assert.ok(typeMeta('weird').label)
  assert.ok(typeMeta(undefined).label)
})

test('formatTarget 按类型返回对应字段', () => {
  assert.equal(formatTarget({ type: 'static', root: '/var/www' }), '/var/www')
  assert.equal(formatTarget({ type: 'proxy', upstream: 'http://127.0.0.1:3000' }), 'http://127.0.0.1:3000')
  // 字段缺失时返回占位符而不是 undefined。
  assert.equal(formatTarget({ type: 'static' }), '-')
  assert.equal(formatTarget(null), '-')
})

test('statusMeta 区分启用/禁用/外部配置', () => {
  assert.equal(statusMeta({ enabled: true, generated: true }).text, '已启用')
  assert.equal(statusMeta({ enabled: false, generated: true }).text, '已禁用')
  const external = statusMeta({ enabled: true, generated: false })
  assert.equal(external.text, '外部配置')
  assert.equal(external.readonly, true, '外部配置应标记为只读')
})

test('canOperate 只允许操作面板创建的站点', () => {
  assert.equal(canOperate({ generated: true }), true)
  assert.equal(canOperate({ generated: false }), false, '外部配置不可操作')
  assert.equal(canOperate(null), false)
})

test('actionDisabled 汇总全部禁用条件', () => {
  const site = { generated: true, enabled: true }
  assert.equal(actionDisabled({ available: true, canWrite: true, site, busy: false }), false)
  assert.equal(actionDisabled({ available: false, canWrite: true, site, busy: false }), true)
  assert.equal(actionDisabled({ available: true, canWrite: false, site, busy: false }), true)
  assert.equal(
    actionDisabled({ available: true, canWrite: true, site: { generated: false }, busy: false }),
    true,
    '外部配置应禁用按钮',
  )
  assert.equal(actionDisabled({ available: true, canWrite: true, site, busy: true }), true)
})

test('filterSites 按关键字与状态过滤且不修改入参', () => {
  const sites = [
    { name: 'a', domain: 'a.example.com', type: 'static', root: '/var/www/a', enabled: true, generated: true },
    { name: 'b', domain: 'b.example.com', type: 'proxy', upstream: 'http://127.0.0.1:3000', enabled: false, generated: true },
  ]
  const snapshot = JSON.stringify(sites)

  assert.equal(filterSites(sites).length, 2)
  assert.equal(filterSites(sites, { onlyEnabled: true }).length, 1)
  assert.equal(filterSites(sites, { onlyEnabled: true })[0].name, 'a')
  assert.equal(filterSites(sites, { keyword: 'b.ex' }).length, 1)
  assert.equal(filterSites(sites, { keyword: '3000' }).length, 1, '应能按反代目标搜索')
  assert.equal(filterSites(sites, { keyword: '/var/www/a' }).length, 1, '应能按根目录搜索')
  assert.equal(filterSites(sites, { keyword: 'nothing' }).length, 0)

  assert.equal(JSON.stringify(sites), snapshot, 'filterSites 不应修改入参')
})

test('filterSites 容忍非数组输入', () => {
  assert.deepEqual(filterSites(null), [])
  assert.deepEqual(filterSites(undefined), [])
})

test('deleteConfirmText 必须写明域名', () => {
  const text = deleteConfirmText({
    name: 'demo', domain: 'demo.example.com', type: 'static', root: '/var/www/demo',
  })
  // 计划明确要求"删除操作二次确认，写明域名"。
  assert.ok(text.includes('demo.example.com'), '确认文案必须包含域名')
  assert.ok(text.includes('/var/www/demo'), '确认文案应包含目标路径')
  assert.ok(text.includes('无法在面板中恢复') || text.includes('无法恢复'), '应说明不可恢复')
})

test('deleteConfirmText 兼容字段缺失', () => {
  // 不应抛错，且应有兜底文案。
  const text = deleteConfirmText({ name: 'onlyname' })
  assert.ok(text.includes('onlyname'))
  assert.ok(deleteConfirmText(null).length > 0)
})

test('summarize 统计总数/启用/外部配置', () => {
  const s = summarize([
    { enabled: true, generated: true },
    { enabled: false, generated: true },
    { enabled: true, generated: false },
  ])
  assert.deepEqual(s, { total: 3, enabled: 2, external: 1 })
  assert.deepEqual(summarize(null), { total: 0, enabled: 0, external: 0 })
})

test('targetLabel 按类型返回表头', () => {
  assert.equal(targetLabel('static'), '根目录')
  assert.equal(targetLabel('proxy'), '反代目标')
})

// ---------------------------------------------------------------------------
// 核心不变式：任何 nginx 元字符都不可能通过前端校验
// ---------------------------------------------------------------------------

test('任何 nginx 元字符都不会通过前端校验（与后端对齐）', () => {
  for (const ch of NGINX_METACHARACTERS) {
    for (const pos of ['prefix', 'middle', 'suffix']) {
      const wrap = (base) => {
        if (pos === 'prefix') return ch + base
        if (pos === 'suffix') return base + ch
        return base.slice(0, 2) + ch + base.slice(2)
      }
      assert.notEqual(validateSiteName(wrap('site')), '', `站点名含 ${JSON.stringify(ch)} 应被拒绝`)
      assert.notEqual(validateDomain(wrap('example.com')), '', `域名含 ${JSON.stringify(ch)} 应被拒绝`)
      assert.notEqual(validateRoot(wrap('/var/www')), '', `根目录含 ${JSON.stringify(ch)} 应被拒绝`)
      assert.notEqual(
        validateUpstream(ch === ' ' ? 'http://127.0.0.1:3000/' + ch : wrap('http://127.0.0.1:3000')),
        '',
        `反代目标含 ${JSON.stringify(ch)} 应被拒绝`,
      )
    }
  }
})
