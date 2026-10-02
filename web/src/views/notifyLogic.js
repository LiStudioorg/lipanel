// 通知渠道页的纯逻辑（阶段五 5.4.2）。
//
// 负责：渠道展示元数据、表单 schema（按类型渲染不同字段）、
// 参数校验、凭证脱敏展示、发送结果判定 —— 全部抽成纯函数便于 node:test。

// CHANNEL_TYPES 各渠道类型的基础元数据，供列表与弹窗共用。
export const CHANNEL_TYPES = [
  { value: 'smtp', label: '邮件 (SMTP)', icon: '📧', fields: ['SMTPHost', 'SMTPPort', 'SMTPUser', 'Receivers', 'SMTPPassword'] },
  { value: 'dingtalk', label: '钉钉机器人', icon: '🔔', fields: ['WebhookURL'] },
  { value: 'wecom', label: '企业微信机器人', icon: '💬', fields: ['WebhookURL'] },
  { value: 'telegram', label: 'Telegram Bot', icon: '✈️', fields: ['TelegramToken', 'TelegramChatID'] },
]

// typeMeta 返回渠道类型展示信息，未知回落。
export function typeMeta(type) {
  return CHANNEL_TYPES.find((c) => c.value === type) || { label: type || '未知', icon: '❔' }
}

// typeLabel 返回渠道类型中文名。
export function typeLabel(type) {
  return typeMeta(type).label
}

// channelEnabledTag 把 enabled 映射为展示标签。
export function enabledMeta(enabled) {
  return enabled
    ? { type: 'success', text: '已启用' }
    : { type: 'default', text: '已停用' }
}

// emptyForm 返回某个渠道类型在新建时的空表单骨架。
export function emptyForm(type = 'dingtalk') {
  return {
    name: '',
    type,
    enabled: true,
    smtp_host: '',
    smtp_port: type === 'smtp' ? 25 : 0,
    smtp_user: '',
    smtp_from: '',
    receivers: '',
    smtp_use_tls: false,
    telegram_chat_id: '',
    smtp_password: '',
    webhook_url: '',
    telegram_token: '',
  }
}

// channelToForm 把后端脱敏渠道转成编辑表单。
// 后端 has_secret 只告诉我们"有没有配"，不告诉我们值 ——
// 因此凭证字段置空（空 = 编辑时不改动），展示在别处标注「已配置」。
export function channelToForm(ch) {
  const f = emptyForm(ch.type || 'dingtalk')
  f.name = ch.name || ''
  f.enabled = ch.enabled
  f.smtp_host = ch.smtp_host || ''
  f.smtp_port = ch.smtp_port || 0
  f.smtp_user = ch.smtp_user || ''
  f.smtp_from = ch.smtp_from || ''
  f.receivers = ch.receivers || ''
  f.smtp_use_tls = !!ch.smtp_use_tls
  f.telegram_chat_id = ch.telegram_chat_id || ''
  return f
}

// validateForm 前端兜底校验（后端才是真正的边界）。返回错误文案或空。
export function validateForm(form, isEdit = false) {
  if (!form.name || !form.name.trim()) return '渠道名称不能为空'
  if (!form.type) return '请选择渠道类型'
  switch (form.type) {
    case 'smtp':
      if (!form.smtp_host) return 'SMTP 主机不能为空'
      if (!form.smtp_user) return 'SMTP 账号（登录邮箱）不能为空'
      if (!form.receivers) return '收件人不能为空'
      break
    case 'dingtalk':
    case 'wecom':
      if (!isEdit && !form.webhook_url) return 'Webhook 地址不能为空'
      if (form.webhook_url && !/^https?:\/\//i.test(form.webhook_url)) {
        return 'Webhook 必须以 http:// 或 https:// 开头'
      }
      break
    case 'telegram':
      if (!isEdit && !form.telegram_token) return 'Telegram token 不能为空'
      if (!form.telegram_chat_id) return 'Telegram chat_id 不能为空'
      break
    default:
      return '不支持的渠道类型'
  }
  return ''
}

// formToPayload 把表单转成提交给后端的 JSON。
// isEdit 时凭证空串原样提交（后端理解为"不改动"）。
export function formToPayload(form) {
  return {
    name: form.name?.trim(),
    type: form.type,
    enabled: form.enabled,
    smtp_host: form.smtp_host,
    smtp_port: form.smtp_port,
    smtp_user: form.smtp_user,
    smtp_from: form.smtp_from,
    receivers: form.receivers,
    smtp_use_tls: form.smtp_use_tls,
    telegram_chat_id: form.telegram_chat_id,
    smtp_password: form.smtp_password,
    webhook_url: form.webhook_url,
    telegram_token: form.telegram_token,
  }
}

// secretLabel 展示凭证已配置状态（后端只给布尔）。
export function secretLabel(hasSecret, isEdit) {
  if (!hasSecret) return '未配置'
  // 已配置不允许改值？允许覆盖；但列表只需显示"已配置"。
  return isEdit ? '已配置（留空则不修改）' : '已配置'
}

// describeTestResult 把测试发送结果转成可读文案。
export function describeTestResult(res = {}) {
  if (res && res.sent > 0) {
    return { type: 'success', text: `发送成功（${res.sent} 个渠道）` }
  }
  const err = res?.errors ? Object.values(res.errors)[0] : ''
  return { type: 'error', text: `发送失败${err ? `：${err}` : ''}` }
}