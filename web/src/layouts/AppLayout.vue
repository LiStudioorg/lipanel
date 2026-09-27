<script setup>
// 应用通用布局：顶栏 + 菜单 + 内容区。
//
// 抽出来的原因：阶段三开始有了多个页面（概览 / 插件管理 / 插件页面），
// 继续把 header 写在每个页面里会迅速产生重复代码。
//
// 菜单是「插件前端挂载插槽」的一部分：
// builtinMenus 是核心功能，pluginMenus 由 /api/plugins 返回的
// Frontend 元数据动态生成——新增一个插件，菜单里就自动多一项，
// 本文件一行都不用改。
//
// 阶段三 3.2 起菜单项的判定不再是「静态表里有没有登记」，
// 而是「插件有没有声明 frontend.entry」：判定是同步的（不触发加载），
// 因此菜单渲染不会被插件前端的网络请求拖慢。
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authStore } from '@/stores/auth'
import { ApiError } from '@/api/client'
import { fetchPlugins } from '@/api/plugins'
import { applyPlugins, hasPluginView, resolveNavIcon } from '@/plugins/registry'

const route = useRoute()
const router = useRouter()
const message = useMessage()
const dialog = useDialog()

const loggingOut = ref(false)

// plugins 用于动态菜单。加载失败不阻断页面渲染：
// 插件系统不可用不该让整个面板无法使用，因此只记录错误、菜单少几项。
const plugins = ref([])
const pluginMenuError = ref('')

// builtinMenus 是核心自带的功能入口。
const builtinMenus = [
  { key: 'dashboard', label: '系统概览', icon: '📊', to: { name: 'dashboard' } },
  // 服务管理（阶段四 4.1）：内置页面而非插件——
  // systemd 服务是面板的基础运维能力，不该依赖插件机制是否可用。
  { key: 'service-list', label: '服务管理', icon: '⚙️', to: { name: 'service-list' } },
  // 文件管理（阶段四 4.2）：同样是内置页面而非插件——
  // 文件读写是面板最核心的运维能力之一。
  { key: 'file-manager', label: '文件管理', icon: '📁', to: { name: 'file-manager' } },
  // 网站管理（阶段四 4.3）：内置页面而非插件——
  // nginx 站点是面板对外提供服务的基础能力。
  { key: 'site-manager', label: '网站管理', icon: '🌐', to: { name: 'site-manager' } },
  // SSL 证书（阶段四 4.4）：内置页面而非插件——
  // 证书是面板对外提供服务的基础能力，且到期不处理会直接导致
  // 站点无法访问，必须始终可达。
  { key: 'ssl-cert', label: 'SSL 证书', icon: '🔒', to: { name: 'ssl-cert' } },
  // 软件商店（阶段四 4.5）：内置页面而非插件——
  // 一键安装运行环境是面板的核心能力，且它是最需要审计入口的能力
  // （以 root 运行发行版包管理器），必须始终可达。
  { key: 'software-store', label: '软件商店', icon: '🛒', to: { name: 'software-store' } },
  // 防火墙与端口管理（阶段四 4.6）：内置页面而非插件。
  // 它是本面板唯一可能让用户失联的页面（一条错误的规则可以
  // 同时切断 SSH 与面板），因此必须始终可达——放进插件就会出现
  // "插件挂了就进不去、想修也修不了"的死结。
  { key: 'firewall', label: '防火墙', icon: '🛡️', to: { name: 'firewall' } },
  { key: 'plugins', label: '插件管理', icon: '🧩', to: { name: 'plugin-list' } },
  // 审计页（阶段三 3.3）：权限声明是"拒绝对了没"的唯一可见证据，
  // 因此把它放在一级菜单，而不是藏进插件详情里。
  { key: 'plugin-audit', label: '插件审计', icon: '📋', to: { name: 'plugin-audit' } },
]

// pluginMenus 把「已运行 + 声明了前端入口」的插件转成菜单项。
//
// 只有 running 的插件才进菜单：插件没跑起来时点进去必然 503，
// 那是很差的体验；管理页才是启动插件的地方。
const pluginMenus = computed(() =>
  plugins.value
    .filter((p) => p.state === 'running' && p.frontend?.nav_title && hasPluginView(p.id))
    .map((p) => ({
      key: `plugin-${p.id}`,
      label: p.frontend.nav_title,
      icon: resolveNavIcon(p.frontend.nav_icon),
      to: { name: 'plugin-view', params: { id: p.id } },
    })),
)

// menuOptions 合并核心菜单与插件菜单。
const menuOptions = computed(() => [
  ...builtinMenus,
  ...(pluginMenus.value.length
    ? [{ key: 'plugin-group', label: '插件', icon: '🔌', children: pluginMenus.value }]
    : []),
])

// activeKey 决定哪个菜单项高亮。
const activeKey = computed(() => {
  if (route.name === 'plugin-view') return `plugin-${route.params.id}`
  return route.name
})

async function loadPlugins() {
  try {
    const data = await fetchPlugins()
    plugins.value = data.plugins || []
    // 把后端元数据登记进前端注册表：菜单项的同步判定依赖它。
    applyPlugins(plugins.value)
    pluginMenuError.value = ''
  } catch (err) {
    plugins.value = []
    // 401 交给全局处理（跳登录页），这里只提示其它错误。
    pluginMenuError.value =
      err instanceof ApiError && err.isUnauthorized ? '' : err?.message || '插件列表加载失败'
  }
}

onMounted(loadPlugins)

// 路由变化时刷新插件列表：
// 用户刚在管理页启动了插件，菜单应当立刻出现对应入口，
// 否则要刷新整页才能看到，体验很差。
watch(
  () => route.fullPath,
  () => {
    loadPlugins()
  },
)

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
      </n-space>

      <n-space align="center" :size="12">
        <n-text depth="3">
          当前用户：<strong>{{ authStore.state.username || '-' }}</strong>
        </n-text>
        <n-button size="small" :loading="loggingOut" @click="confirmLogout">登出</n-button>
      </n-space>
    </n-layout-header>

    <n-layout has-sider position="absolute" style="top: 65px">
      <n-layout-sider bordered :width="220" :native-scrollbar="false">
        <n-menu
          :value="activeKey"
          :options="menuOptions"
          :root-indent="18"
          :default-expand-all="true"
        />

        <!-- 插件列表加载失败时给出可见提示，而不是让菜单静默少几项 -->
        <n-alert
          v-if="pluginMenuError"
          type="warning"
          :bordered="false"
          style="margin: 12px; font-size: 12px"
        >
          插件菜单不可用：{{ pluginMenuError }}
        </n-alert>
      </n-layout-sider>

      <n-layout-content class="app-content">
        <slot />
      </n-layout-content>
    </n-layout>
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
