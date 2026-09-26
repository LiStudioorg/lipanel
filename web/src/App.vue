<script setup>
import HealthCard from '@/components/HealthCard.vue'
</script>

<template>
  <!--
    Provider 必须包在消费 useMessage 的组件之外：
    useMessage() 只能在其后代组件中调用，因此业务内容拆到 HealthCard。
  -->
  <n-config-provider>
    <n-message-provider>
      <n-layout style="min-height: 100vh">
        <n-layout-header bordered style="padding: 16px 24px">
          <n-h2 style="margin: 0">lipanel</n-h2>
        </n-layout-header>

        <n-layout-content style="padding: 24px">
          <HealthCard />
        </n-layout-content>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>
