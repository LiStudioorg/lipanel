// 通知渠道页纯逻辑的测试（阶段五 5.4.2）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CHANNEL_TYPES,
  channelToForm,
  describeTestResult,
  emptyForm,
  enabledMeta,
  formToPayload,
  typeLabel,
  typeMeta,
  validateForm,
} from './notifyLogic.js'

test('CHANNEL_TYPES 覆盖四类渠道', () => {
  const types = CHANNEL_TYPES.map((c) => c.value)
  for (const t of ['smtp', 'dingtalk', 'wecom', 'telegram']) {
    assert.ok(types.includes(t), `缺少渠道类型 ${t}`)
  }
})

test('typeMeta/typeLabel', () => {
  assert.equal(typeLabel('smtp'), '邮件 (SMTP)')
  assert.equal(typeLabel('telegram'), 'Telegram Bot')
  assert.equal(typeLabel('sms'), 'sms') // 未知回落
  assert.equal(typeMeta(undefined).label, '未知')
})

test('enabledMeta', () => {
  assert.equal(enabledMeta(true).text, '已启用')
  assert.equal(enabledMeta(false).text, '已停用')
})

test('emptyForm 生成对应类型的骨架', () => {
  const f = emptyForm('telegram')
  assert.equal(f.type, 'telegram')
  assert.equal(f.enabled, true)
  assert.ok('smtp_host' in f && 'telegram_chat_id' in f)
})

test('channelToForm 把脱敏渠道转成编辑表单，凭证字段置空', () => {
  const f = channelToForm({
    id: 'ch-1', name: '告警', type: 'dingtalk', enabled: true,
    smtp_host: '', smtp_port: 0, smtp_user: '', receivers: '',
    telegram_chat_id: '',
  })
  assert.equal(f.name, '告警')
  // 凭证字段必须为空（后端不回显明文）。
  assert.equal(f.webhook_url, '')
  assert.equal(f.telegram_token, '')
})

test('validateForm 基本校验', () => {
  assert.equal(validateForm({ name: '', type: 'smtp' }), '渠道名称不能为空')
  assert.equal(validateForm({ name: 'x', type: '' }), '请选择渠道类型')
  // SMTP 缺字段。
  assert.equal(validateForm({ name: 'x', type: 'smtp', smtp_host: '', smtp_user: 'a', receivers: 'b' }), 'SMTP 主机不能为空')
  // webhook 非 http(s)。
  assert.equal(validateForm({ name: 'x', type: 'dingtalk', webhook_url: 'file:///x' }), 'Webhook 必须以 http:// 或 https:// 开头')
  // 编辑时 webhook 可空。
  assert.equal(validateForm({ name: 'x', type: 'dingtalk', webhook_url: '' }, true), '')
  // 合法。
  assert.equal(validateForm({ name: 'x', type: 'dingtalk', webhook_url: 'https://a.com/x' }), '')
})

test('formToPayload 提交结构', () => {
  const p = formToPayload({ name: ' 告警 ', type: 'dingtalk', enabled: false, webhook_url: 'https://a.com' })
  assert.equal(p.name, '告警')
  assert.equal(p.type, 'dingtalk')
  assert.equal(p.enabled, false)
  assert.equal(p.webhook_url, 'https://a.com')
})

test('describeTestResult', () => {
  assert.equal(describeTestResult({ sent: 1 }).type, 'success')
  const fail = describeTestResult({ sent: 0, errors: { ch1: 'HTTP 500' } })
  assert.equal(fail.type, 'error')
  assert.ok(fail.text.includes('HTTP 500'))
})