<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authStore } from '@/stores/auth'

// 本组件位于 n-message-provider 之内，可安全使用 useMessage。
const message = useMessage()
const router = useRouter()
const route = useRoute()

const formRef = ref(null)
const loading = ref(false)
const error = ref('')

const form = ref({
  username: '',
  password: '',
})

// Naive UI 表单校验规则。
const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: ['input', 'blur'] },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: ['input', 'blur'] },
  ],
}

onMounted(() => {
  // 守卫跳转过来时可能带有后端不可达之类的错误，直接展示，避免用户不明所以。
  const queryError = route.query.error
  if (typeof queryError === 'string' && queryError) {
    error.value = queryError
  }
})

// submit 是登录的唯一入口：先做表单校验，再请求后端。
async function submit() {
  error.value = ''

  // 校验不通过时 Naive UI 会自动标红字段并弹出提示。
  try {
    await formRef.value?.validate()
  } catch {
    return
  }

  loading.value = true
  try {
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : ''
    const resp = await authStore.login(form.value.username, form.value.password, redirect)

    message.success(`欢迎回来，${resp.username}`)
    // redirect 已由后端清洗（非法值一律回落为 "/"），可安全使用。
    await router.replace(resp.redirect || '/')
  } catch (err) {
    // 失败必须可见：既弹提示，也在页面上保留错误，避免用户错过 toast。
    error.value = err?.message || '登录失败，请稍后重试'
    message.error(error.value)
    // 密码错误后清空密码框，减少误重试。
    form.value.password = ''
  } finally {
    // 无论成功失败都复位 Loading，防止按钮永久转圈。
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <n-card class="login-card" title="lipanel 登录">
      <template #header-extra>
        <n-tag size="small" type="info" :bordered="false">轻量 Linux 面板</n-tag>
      </template>

      <!-- 错误优先展示，保证任何失败都有可见原因 -->
      <n-alert v-if="error" type="error" title="登录失败" style="margin-bottom: 16px">
        {{ error }}
      </n-alert>

      <n-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-placement="top"
        size="large"
        @submit.prevent="submit"
      >
        <n-form-item label="用户名" path="username">
          <n-input
            v-model:value="form.username"
            placeholder="请输入用户名"
            :disabled="loading"
            autofocus
            @keyup.enter="submit"
          />
        </n-form-item>

        <n-form-item label="密码" path="password">
          <n-input
            v-model:value="form.password"
            type="password"
            show-password-on="click"
            placeholder="请输入密码"
            :disabled="loading"
            @keyup.enter="submit"
          />
        </n-form-item>

        <n-button
          type="primary"
          size="large"
          block
          :loading="loading"
          :disabled="loading"
          attr-type="submit"
          @click="submit"
        >
          登录
        </n-button>
      </n-form>

      <template #footer>
        <n-text depth="3" style="font-size: 12px">
          首次部署默认账号为 admin / admin123，请尽快通过启动参数修改。
        </n-text>
      </template>
    </n-card>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: #f5f7fa;
}

.login-card {
  width: 100%;
  max-width: 380px;
  /* 让卡片在灰底上有一点浮起感，保持极简。 */
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
}
</style>
