<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { authStore } from '@/stores/auth'
import { ApiError } from '@/api/client'
import SystemInfoPanel from '@/components/SystemInfoPanel.vue'

const message = useMessage()
const dialog = useDialog()
const router = useRouter()

const loggingOut = ref(false)

// confirmLogout 二次确认：登出会打断当前操作，值得一次确认。
function confirmLogout() {
  dialog.warning({
    title: '确认登出',
    content: '登出后需要重新输入账号密码，确定继续吗？',
    positiveText: '登出',
    negativeText: '取消',
    onPositiveClick: doLogout,
  })
}

async function doLogout() {
  loggingOut.value = true
  try {
    await authStore.logout()
    message.success('已登出')
    await router.replace({ name: 'login' })
  } catch (err) {
    // doLogout 内部已清本地状态，这里只提示后端可能未同步。
    message.warning(
      err instanceof ApiError
        ? `本地已登出，但通知后端失败：${err.message}`
        : '本地已登出，但通知后端失败',
    )
    await router.replace({ name: 'login' })
  } finally {
    loggingOut.value = false
  }
}
</script>

<template>
  <n-layout style="min-height: 100vh">
    <n-layout-header bordered class="app-header">
      <n-space align="center" :size="12">
        <n-h2 style="margin: 0">lipanel</n-h2>
        <n-tag size="small" :bordered="false" type="info">系统概览</n-tag>
      </n-space>

      <n-space align="center" :size="12">
        <n-text depth="3">
          当前用户：<strong>{{ authStore.state.username || '-' }}</strong>
        </n-text>
        <n-button size="small" :loading="loggingOut" @click="confirmLogout">登出</n-button>
      </n-space>
    </n-layout-header>

    <n-layout-content class="app-content">
      <SystemInfoPanel />
    </n-layout-content>
  </n-layout>
</template>

<style scoped>
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 24px;
  gap: 16px;
  flex-wrap: wrap;
}

.app-content {
  padding: 24px;
}
</style>
