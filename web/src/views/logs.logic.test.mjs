// 日志查看页纯逻辑的测试（阶段五 5.4.1）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  LEVELS,
  autoRefreshCheck,
  buildQuery,
  escapeHtml,
  normalizeQuery,
  sourceTypeMetaOf,
} from './logsLogic.js'

test('buildQuery 组装查询参数', () => {
  const q = buildQuery({ source: 'system', lines: 500, filter: 'panic', level: 'error' })
  assert.equal(q.source, 'system')
  assert.equal(q.lines, 500)
  assert.equal(q.filter, 'panic')
  assert.equal(q.level, 'error')
})

test('buildQuery 无源时只返回 source', () => {
  assert.deepEqual(buildQuery({}), { source: undefined })
})

test('buildQuery 收敛行数到 [1,2000]', () => {
  assert.equal(buildQuery({ source: 'x', lines: -5 }).lines, 100)
  assert.equal(buildQuery({ source: 'x', lines: 0 }).lines, 100)
  assert.equal(buildQuery({ source: 'x', lines: 999999 }).lines, 2000)
  assert.equal(buildQuery({ source: 'x', lines: 42 }).lines, 42)
  assert.equal(buildQuery({ source: 'x' }).lines, 100)
})

test('buildQuery 空关键词/空级别被剔除', () => {
  const q = buildQuery({ source: 'x', filter: '   ', level: '' })
  assert.ok(!('filter' in q))
  assert.ok(!('level' in q))
})

test('normalizeQuery 归一化后端结果', () => {
  const n = normalizeQuery({ entries: [{ line: 'a' }], truncated: true, scanned: 10 })
  assert.equal(n.entries.length, 1)
  assert.equal(n.truncated, true)
  assert.equal(n.scanned, 10)
  // 兼容缺失字段。
  const empty = normalizeQuery()
  assert.deepEqual(empty.entries, [])
  assert.equal(empty.truncated, false)
})

test('escapeHtml 转义注入内容（防 XSS）', () => {
  assert.equal(escapeHtml('<script>alert(1)</script>'),
    '&lt;script&gt;alert(1)&lt;/script&gt;')
  assert.equal(escapeHtml('a&b'), 'a&amp;b')
  assert.equal(escapeHtml(`"quoted"`), '&quot;quoted&quot;')
  assert.equal(escapeHtml(`it's`), 'it&#39;s')
  // 普通文本不受影响。
  assert.equal(escapeHtml('GET / 200 ok'), 'GET / 200 ok')
})

test('sourceTypeMetaOf 安全回落', () => {
  assert.equal(sourceTypeMetaOf('system').text, '系统日志')
  assert.equal(sourceTypeMetaOf('app').text, '应用日志')
  // 未知类型原样展示（而非 undefined），不报错。
  assert.equal(sourceTypeMetaOf('bogus').text, 'bogus')
  assert.equal(sourceTypeMetaOf(undefined).text, '未知')
})

test('LEVELS 定义完整且首个为全部', () => {
  assert.equal(LEVELS[0].value, '')
  const values = LEVELS.map((l) => l.value)
  for (const v of ['', 'error', 'warn', 'info', 'debug']) {
    assert.ok(values.includes(v), `缺少级别 ${v}`)
  }
})

test('autoRefreshCheck 在有错误时不自动刷新', () => {
  assert.equal(autoRefreshCheck({ hasError: false }), true)
  assert.equal(autoRefreshCheck({ hasError: true }), false)
  assert.equal(autoRefreshCheck(), true)
})