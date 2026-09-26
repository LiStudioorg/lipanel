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
