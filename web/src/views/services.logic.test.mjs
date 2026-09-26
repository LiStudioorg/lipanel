// 服务管理页纯逻辑的测试（阶段四 4.1）。
//
// 关键：这里 **import 真正被组件使用的那份实现**（servicesLogic.js），
// 而不是把逻辑重述一遍。重述的测试是假测试——
// 组件改了而测试没改，它照样全绿。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ACTION_TEXT,
  actionDisabled,
  filterServices,
  isPointless,
  stateMeta,
  unitFileLabel,
} from './servicesLogic.js'

// ---------- 状态展示 ----------

test('stateMeta 为后端每个状态都给出中文文案', () => {
  // 这些取值对应 internal/service 的 normalizeState。
  for (const s of ['running', 'stopped', 'failed', 'activating', 'unknown']) {
    const meta = stateMeta(s)
    assert.ok(meta.text, `${s} 缺少文案`)
    assert.notEqual(meta.text, undefined)
  }
})

test('stateMeta 对未知取值安全回落，不渲染 undefined', () => {
  assert.equal(stateMeta('some-future-state').text, '未知')
  assert.equal(stateMeta(undefined).text, '未知')
  assert.equal(stateMeta(null).text, '未知')
})

test('stateMeta 的标签类型符合语义', () => {
  assert.equal(stateMeta('running').type, 'success')
  assert.equal(stateMeta('failed').type, 'error')
  // 停止是正常状态，不该标红——否则满屏红色，真正的失败反而不显眼。
  assert.equal(stateMeta('stopped').type, 'default')
})

test('unitFileLabel 只翻译含义明确的取值，其余原样展示', () => {
  assert.equal(unitFileLabel('enabled'), '开机自启')
  assert.equal(unitFileLabel('disabled'), '未自启')
  // static/generated 强行说成「已禁用」是错的，会误导用户。
  assert.equal(unitFileLabel('static'), 'static')
  assert.equal(unitFileLabel('generated'), 'generated')
  // 空值（模板实例等没有 unit file 的单元）显示占位符。
  assert.equal(unitFileLabel(''), '-')
  assert.equal(unitFileLabel(undefined), '-')
})

// ---------- 过滤 ----------

const SAMPLE = [
  { name: 'nginx.service', state: 'running', description: 'A high performance web server' },
  { name: 'cron.service', state: 'running', description: 'Regular background program' },
  { name: 'docker.service', state: 'stopped', description: 'Docker Application Container Engine' },
  { name: 'lipanel-test.service', state: 'stopped', description: '测试服务' },
]

test('filterServices 默认返回全部', () => {
  assert.equal(filterServices(SAMPLE).length, 4)
})

test('filterServices 只看运行中', () => {
  const got = filterServices(SAMPLE, { onlyRunning: true })
  assert.equal(got.length, 2)
  assert.ok(got.every((s) => s.state === 'running'))
})

test('filterServices 按服务名匹配且不区分大小写', () => {
  assert.equal(filterServices(SAMPLE, { keyword: 'NGINX' }).length, 1)
  assert.equal(filterServices(SAMPLE, { keyword: 'nginx' })[0].name, 'nginx.service')
})

test('filterServices 也匹配描述', () => {
  const got = filterServices(SAMPLE, { keyword: 'container' })
  assert.equal(got.length, 1)
  assert.equal(got[0].name, 'docker.service')
})

test('filterServices 支持中文描述匹配', () => {
  assert.equal(filterServices(SAMPLE, { keyword: '测试' })[0].name, 'lipanel-test.service')
})

test('filterServices 忽略关键字首尾空白', () => {
  assert.equal(filterServices(SAMPLE, { keyword: '  nginx  ' }).length, 1)
})

test('filterServices 组合过滤：只看运行中 + 关键字', () => {
  const got = filterServices(SAMPLE, { onlyRunning: true, keyword: 'cron' })
  assert.equal(got.length, 1)
  assert.equal(got[0].name, 'cron.service')
})

test('filterServices 无匹配时返回空数组而非 null（模板要能迭代）', () => {
  assert.deepEqual(filterServices(SAMPLE, { keyword: 'nosuchservice' }), [])
})

test('filterServices 不修改原数组', () => {
  const before = JSON.parse(JSON.stringify(SAMPLE))
  filterServices(SAMPLE, { onlyRunning: true, keyword: 'cron' })
  assert.deepEqual(SAMPLE, before)
})

test('filterServices 容忍 null / undefined 输入', () => {
  assert.deepEqual(filterServices(null), [])
  assert.deepEqual(filterServices(undefined), [])
})

test('filterServices 容忍缺少 description 的服务', () => {
  const list = [{ name: 'x.service', state: 'running' }]
  assert.equal(filterServices(list, { keyword: 'x' }).length, 1)
  assert.equal(filterServices(list, { keyword: 'zzz' }).length, 0)
})

// ---------- 按钮禁用（防误操作）----------

test('isPointless 识别无意义的操作按钮', () => {
  // 运行中再点「启动」没有意义（systemctl 返回 0 却什么也没发生，
  // 用户会以为操作生效了）。
  assert.equal(isPointless('start', 'running'), true)
  assert.equal(isPointless('stop', 'stopped'), true)
  // 其余组合都应可点。
  assert.equal(isPointless('start', 'stopped'), false)
  assert.equal(isPointless('stop', 'running'), false)
  assert.equal(isPointless('restart', 'running'), false)
  assert.equal(isPointless('restart', 'stopped'), false)
})

test('失败状态的服务仍可操作（重启是常见修复手段）', () => {
  assert.equal(isPointless('start', 'failed'), false)
  assert.equal(isPointless('stop', 'failed'), false)
  assert.equal(isPointless('restart', 'failed'), false)
})

test('actionDisabled 汇总禁用条件', () => {
  // 正常情况：可用、有权限、操作有意义 → 可点。
  assert.equal(
    actionDisabled({ available: true, canWrite: true, action: 'start', state: 'stopped' }),
    false,
  )
  // 无 systemd → 全部禁用。
  assert.equal(
    actionDisabled({ available: false, canWrite: true, action: 'start', state: 'stopped' }),
    true,
  )
  // 无写权限 → 全部禁用（真正的强制点在后端，这里只是体验）。
  assert.equal(
    actionDisabled({ available: true, canWrite: false, action: 'stop', state: 'running' }),
    true,
  )
  // 操作无意义 → 禁用。
  assert.equal(
    actionDisabled({ available: true, canWrite: true, action: 'start', state: 'running' }),
    true,
  )
})

// ---------- 操作文案 ----------

test('ACTION_TEXT 覆盖三个受支持的操作', () => {
  for (const a of ['start', 'stop', 'restart']) {
    assert.ok(ACTION_TEXT[a], `缺少 ${a} 的文案`)
    assert.ok(ACTION_TEXT[a].label)
    assert.ok(ACTION_TEXT[a].verb)
  }
})

test('停止按钮用警告色，因为它是破坏性操作', () => {
  assert.equal(ACTION_TEXT.stop.type, 'warning')
  assert.equal(ACTION_TEXT.start.type, 'primary')
})
