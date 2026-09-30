// 前端路由与路由守卫。
//
// 守卫的职责边界（重要）：
//   前端的守卫只负责“体验”——未登录时不渲染主页、已登录时不显示登录页。
//   真正的权限校验始终在后端中间件里（RequireAuth），
//   前端绕过守卫也拿不到任何数据，因此这里不承担安全职责。
import { createRouter, createWebHistory } from 'vue-router'
import { authStore } from '@/stores/auth'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    // public 标记公开页面，守卫据此放行。
    meta: { public: true, title: '登录' },
  },
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/DashboardView.vue'),
    // requiresAuth 是默认语义：未标记 public 的路由都要求登录，
    // 这样新增页面时忘记加标记也不会意外公开。
    meta: { title: '系统概览' },
  },
  {
    path: '/plugins',
    name: 'plugin-list',
    component: () => import('@/views/PluginListView.vue'),
    meta: { title: '插件管理' },
  },
  {
    // 服务管理页（阶段四 4.1）。
    //
    // 放在静态路由段（不是 /plugins/:id 那样的通配），因为它是核心内置能力，
    // 与服务无关的插件机制不应影响它的可达性。
    path: '/services',
    name: 'service-list',
    component: () => import('@/views/ServicesView.vue'),
    meta: { title: '服务管理' },
  },
  {
    // 文件管理页（阶段四 4.2）。
    //
    // 同样是核心内置能力 + 静态路由：文件读写是面板的基础运维功能，
    // 不该依赖插件机制是否可用（与 /services 同样的架构决定）。
    path: '/files',
    name: 'file-manager',
    component: () => import('@/views/FileView.vue'),
    meta: { title: '文件管理' },
  },
  {
    // 网站管理页（阶段四 4.3）。
    //
    // 同样是核心内置能力 + 静态路由（与 /services、/files 相同的架构决定）：
    // nginx 站点是面板的基础运维能力，不该依赖插件机制是否可用。
    path: '/sites',
    name: 'site-manager',
    component: () => import('@/views/SiteView.vue'),
    meta: { title: '网站管理' },
  },
  {
    // SSL 证书页（阶段四 4.4）。
    //
    // 同样是核心内置能力 + 静态路由（与 /services、/files、/sites
    // 相同的架构决定）：证书是面板对外提供服务的基础能力，
    // 不该依赖插件机制是否可用。
    //
    // 路径用 /ssl 而不是 /sites/ssl：证书是独立的一级概念
    // （它有自己的审计、权限与运行状态），挂在站点下会让人
    // 误以为"没有站点就没有证书"。后端的接口同样是独立的 /api/ssl。
    path: '/ssl',
    name: 'ssl-cert',
    component: () => import('@/views/SslView.vue'),
    meta: { title: 'SSL 证书' },
  },
  {
    // 软件商店（阶段四 4.5）。
    //
    // 核心内置能力 + 静态路由（与 /services、/files、/sites、/ssl
    // 相同的架构决定）：一键安装运行环境是面板的核心能力，
    // 不该依赖插件机制是否可用。
    //
    // 路径用 /store 而不是 /plugins/store：安装软件会以 root 身份
    // 运行发行版包管理器，是本面板**最高危**的能力，因此它的
    // 入口、权限（store.write）与审计都独立存在，不挂在插件下。
    path: '/store',
    name: 'software-store',
    component: () => import('@/views/StoreView.vue'),
    meta: { title: '软件商店' },
  },
  {
    // 防火墙与端口管理（阶段四 4.6）。
    //
    // 核心内置能力 + 静态路由（与 /services、/files、/sites、/ssl、/store
    // 相同的架构决定）：防火墙是服务器的安全底线，
    // 不该依赖插件机制是否可用。
    //
    // ########## 这一页为什么必须是静态路由 ##########
    //
    // 它是本面板**唯一可能让用户失联**的页面：一条错误的规则
    // 可以同时切断 SSH 与面板的访问，而这件事无法通过网络修好。
    // 把它放进插件，就出现了"插件挂了 → 用户无法管理防火墙 →
    // 想修却进不去"的死结。静态路由保证它永远可达。
    path: '/firewall',
    name: 'firewall',
    component: () => import('@/views/FirewallView.vue'),
    meta: { title: '防火墙' },
  },
  {
    // Web 终端（阶段五 5.1）。
    //
    // 核心内置能力 + 静态路由（与 /services、/files、/sites、/ssl、
    // /store、/firewall 相同的架构决定）。
    //
    // ########## 这一页为什么尤其必须静态可达 ##########
    //
    // 它是本面板**权限最高**的功能：一个无限制的命令行，
    // 能力覆盖文件管理、软件安装、防火墙等全部模块。
    // 当别的功能出问题时（nginx 配置写坏了、商店装包卡住了），
    // 终端往往是**唯一**能进去修的手段。
    //
    // 把它做成插件就会重现防火墙那个死结：
    // "插件挂了 → 用户进不去终端 → 想修却没工具"。
    path: '/terminal',
    name: 'terminal',
    component: () => import('@/views/TerminalView.vue'),
    meta: { title: '终端' },
  },
  {
    // 插件操作审计页（阶段三 3.3）。
    // 必须放在 "/plugins/:id" 之前：否则 "audit" 会被当成插件 ID
    // 命中了通配路由，打开审计页会变成"插件 audit 不存在"。
    path: '/plugins/audit',
    name: 'plugin-audit',
    component: () => import('@/views/PluginAuditView.vue'),
    meta: { title: '插件审计' },
  },
  {
    // 插件前端挂载点：:id 由 PluginHostView 交给前端注册表解析。
    //
    // 用 :id 通配而不是给每个插件写一条静态路由，是为了让「新增插件」
    // 完全不需要改动本文件——这正是「插件前端挂载插槽」的意义。
    path: '/plugins/:id',
    name: 'plugin-view',
    component: () => import('@/views/PluginHostView.vue'),
    meta: { title: '插件' },
  },
  {
    // 兜底：未匹配的路径一律回主页，由主页的守卫决定是否跳登录页。
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 全局前置守卫：登录态判断的唯一入口。
router.beforeEach(async (to) => {
  // 恢复登录态（刷新页面后内存状态为空，需要问一次后端）。
  // ensureLoaded 内部有缓存，正常跳转不会重复请求。
  let authenticated = false
  let backendError = null
  try {
    authenticated = await authStore.ensureLoaded()
  } catch (err) {
    // 后端不可达时不放行受保护页面，但也不能把用户困在死循环里，
    // 因此跳登录页并由登录页展示具体错误。
    backendError = err
    authenticated = false
  }

  if (to.meta.public) {
    // 已登录用户访问登录页：直接回主页，避免重复登录。
    if (authenticated && to.name === 'login') {
      return { path: '/' }
    }
    return true
  }

  if (!authenticated) {
    return {
      name: 'login',
      // 记录来源路径，登录成功后跳回，避免用户重新找入口。
      query: {
        redirect: to.fullPath,
        ...(backendError ? { error: backendError.message } : {}),
      },
    }
  }
  return true
})

// 同步页面标题，便于多标签页区分。
router.afterEach((to) => {
  const title = to.meta?.title
  document.title = title ? `${title} · lipanel` : 'lipanel'
})

export default router
