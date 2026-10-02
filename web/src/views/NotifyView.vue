<template>
  <n-card :bordered="false" class="notify-view">
    <div class="toolbar">
      <span class="title">通知渠道</span>
      <n-button type="primary" size="small" @click="openCreate">
        <template #icon>＋</template>新建渠道
      </n-button>
    </div>

    <n-data-table
      :columns="columns"
      :data="channels"
      :loading="loading"
      :pagination="false"
      :bordered="false"
    />

    <n-modal v-model:show="showForm" preset="card" :title="isEdit ? '编辑渠道' : '新建渠道'" style="width: 560px">
      <div class="form-row">
        <n-form-item label="渠道名称"><n-input v-model:value="form.name" placeholder="如：线上告警" /></n-form-item>
        <n-form-item label="渠道类型">
          <n-select v-model:value="form.type" :options="typeOptions" :disabled="isEdit" @update:value="onTypeChange" />
        </n-form-item>
      </div>
      <n-form-item label="启用"><n-switch v-model:value="form.enabled" /></n-form-item>

      <template v-if="form.type === 'smtp'">
        <n-form-item label="SMTP 主机"><n-input v-model:value="form.smtp_host" placeholder="smtp.example.com" /></n-form-item>
        <n-form-item label="SMTP 端口"><n-input-number v-model:value="form.smtp_port" :min="1" :max="65535" /></n-form-item>
        <n-form-item label="SMTP 账号（登录邮箱）"><n-input v-model:value="form.smtp_user" placeholder="alert@example.com" /></n-form-item>
        <n-form-item label="SMTP 密码"><n-input v-model:value="form.smtp_password" type="password" show-password-on="click" :placeholder="isEdit && existingHasSecret ? '留空则不修改' : ''" /></n-form-item>
        <n-form-item label="收件人"><n-input v-model:value="form.receivers" placeholder="a@x.com;b@x.com（分号/逗号分隔）" /></n-form-item>
        <n-form-item label="STARTTLS"><n-switch v-model:value="form.smtp_use_tls" /></n-form-item>
      </template>

      <template v-else-if="form.type === 'dingtalk' || form.type === 'wecom'">
        <n-alert type="info" class="field-hint">
          创建需要 Webhook 地址（含 access_token / key）。
          {{ isEdit ? '编辑时留空则不修改。' : '' }}
        </n-alert>
        <n-form-item label="Webhook 地址"><n-input v-model:value="form.webhook_url" type="textarea" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." /></n-form-item>
      </template>

      <template v-else-if="form.type === 'telegram'">
        <n-form-item label="Bot Token"><n-input v-model:value="form.telegram_token" type="password" show-password-on="click" placeholder="123456:ABC-..." /></n-form-item>
        <n-form-item label="Chat ID"><n-input v-model:value="form.telegram_chat_id" placeholder="-100123456789" /></n-form-item>
      </template>

      <template #footer>
        <div class="form-actions">
          <n-button @click="showForm = false">取消</n-button>
          <n-button type="primary" :loading="saving" @click="save">{{ isEdit ? '保存' : '创建' }}</n-button>
        </div>
      </template>
    </n-modal>
  </n-card>
</template>

<script setup>
import { h, ref } from 'vue'
import { NAlert, NButton, NCard, NDataTable, NFormItem, NInput, NInputNumber, NModal, NSelect, NSwitch, NTag, useMessage } from 'naive-ui'
import { createChannel, deleteChannel, listChannels, testChannel, updateChannel } from '@/api/notify'
import { channelToForm, describeTestResult, emptyForm, enabledMeta, formToPayload, typeLabel, typeMeta, validateForm } from '@/views/notifyLogic'

const message = useMessage()
const channels = ref([])
const loading = ref(false)
const saving = ref(false)
const showForm = ref(false)
const isEdit = ref(false)
const editingId = ref('')
const existingHasSecret = ref(false)
const form = ref(emptyForm('dingtalk'))

const typeOptions = [
  { label: '邮件 (SMTP)', value: 'smtp' },
  { label: '钉钉机器人', value: 'dingtalk' },
  { label: '企业微信机器人', value: 'wecom' },
  { label: 'Telegram Bot', value: 'telegram' },
]

async function load() {
  loading.value = true
  try {
    const res = await listChannels()
    channels.value = res.channels || []
  } catch (err) {
    message.error(`加载渠道失败：${err.message}`)
  } finally {
    loading.value = false
  }
}

function openCreate() {
  isEdit.value = false
  editingId.value = ''
  existingHasSecret.value = false
  form.value = emptyForm(channels.value.length ? 'dingtalk' : 'dingtalk')
  showForm.value = true
}

function openEdit(row) {
  isEdit.value = true
  editingId.value = row.id
  existingHasSecret.value = !!row.has_secret
  form.value = channelToForm(row)
  showForm.value = true
}

function onTypeChange(type) {
  form.value = emptyForm(type)
}

async function save() {
  const err = validateForm(form.value, isEdit.value)
  if (err) {
    message.warning(err)
    return
  }
  saving.value = true
  try {
    const payload = formToPayload(form.value)
    if (isEdit.value) {
      await updateChannel(editingId.value, payload)
      message.success('渠道已保存')
    } else {
      await createChannel(payload)
      message.success('渠道已创建')
    }
    showForm.value = false
    await load()
  } catch (e) {
    message.error(`保存失败：${e.message}`)
  } finally {
    saving.value = false
  }
}

async function onTest(row) {
  try {
    const res = await testChannel(row.id)
    const d = describeTestResult(res)
    if (d.type === 'success') {
      message.success(d.text)
    } else {
      message.error(d.text)
    }
  } catch (e) {
    message.error(`测试失败：${e.message}`)
  }
}

function askDelete(row) {
  // 用确认框展示（服务端无二次确认约束，前端明示危害）。
  if (window.confirm(`确定删除渠道「${row.name}」？此操作不可撤销。`)) {
    doDelete(row)
  }
}

async function doDelete(row) {
  try {
    await deleteChannel(row.id)
    message.success('已删除')
    await load()
  } catch (e) {
    message.error(`删除失败：${e.message}`)
  }
}

function renderType(row) {
  const m = typeMeta(row.type)
  return h(
    'span',
    null,
    `${m.icon} ${m.label}`,
  )
}

function renderEnabled(row) {
  const m = enabledMeta(row.enabled)
  return h(NTag, { type: m.type, size: 'small', bordered: true }, { default: () => m.text })
}

function renderActions(row) {
  return h(
    'div',
    { style: 'display:flex;gap:4px' },
    [
      h(NButton, { size: 'small', secondary: true, onClick: () => onTest(row) }, { default: () => '测试' }),
      h(NButton, { size: 'small', secondary: true, onClick: () => openEdit(row) }, { default: () => '编辑' }),
      h(NButton, { size: 'small', type: 'error', secondary: true, onClick: () => askDelete(row) }, { default: () => '删除' }),
    ],
  )
}

const columns = [
  { title: '名称', key: 'name', minWidth: 120, render: (row) => row.name },
  { title: '类型', key: 'type', width: 140, render: renderType },
  { title: '状态', key: 'enabled', width: 90, render: renderEnabled },
  { title: '目标', key: 'target', minWidth: 180, render: (row) => rowSummary(row) },
  { title: '凭证', key: 'has_secret', width: 100, render: (row) => (row.has_secret ? '已配置' : '未配置') },
  { title: '操作', key: 'actions', width: 180, render: renderActions },
]

function rowSummary(row) {
  if (row.type === 'smtp') {
    return row.smtp_host ? `${row.smtp_host} → ${row.receivers}` : '-'
  }
  if (row.type === 'telegram') {
    return row.telegram_chat_id ? `chat ${row.telegram_chat_id}` : '-'
  }
  return row.type === 'dingtalk' || row.type === 'wecom' ? 'Webhook' : '-'
}

load()
</script>

<style scoped>
.notify-view {
  min-height: calc(100vh - 120px);
}
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.title {
  font-size: 16px;
  font-weight: 600;
}
.form-row {
  display: flex;
  gap: 12px;
}
.field-hint {
  margin-bottom: 12px;
}
.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
</style>