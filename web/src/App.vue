<script setup>
// 根组件只负责提供 Naive UI 的全局 Provider 与路由出口。
//
// Provider 层级说明：useMessage/useDialog 只能在 Provider 的后代组件中调用，
// 因此 router-view 必须放在 Provider 内部（页面组件才能弹提示）。
</script>

<template>
  <n-config-provider>
    <n-message-provider>
      <n-dialog-provider>
        <router-view />
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>
