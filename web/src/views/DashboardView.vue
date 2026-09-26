<script setup>
// 系统概览页。
//
// 页面骨架（顶栏、菜单、登出）已抽到 AppLayout，本组件只负责内容区。
// 数据来自核心直连的 /api/system/info；
// 插件版的同类数据在「插件」菜单下（走 /api/plugins/sysinfo/info），
// 两者并存正好用于对照验证插件链路。
import SystemInfoPanel from '@/components/SystemInfoPanel.vue'
import AppLayout from '@/layouts/AppLayout.vue'
</script>

<template>
  <AppLayout>
    <SystemInfoPanel />
  </AppLayout>
</template>
