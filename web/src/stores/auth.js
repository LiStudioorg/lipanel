// 全局登录态。
//
// 为什么不用 Pinia：面板只有一个登录用户这一份状态，
// 用 Vue 自带的 reactive 即可，避免为几行代码引入额外依赖与打包体积。
//
// 关键设计：前端不保存 token（它在 HttpOnly Cookie 里，JS 读不到），
// 因此“是否已登录”只能通过向后端询问来确认。为保证路由守卫不会
// 每次跳转都发一次请求，这里用 checked 标记把结果缓存起来。
import { reactive, readonly } from 'vue'
import {
  fetchCurrentUser,
  login as apiLogin,
  logout as apiLogout,
} from '@/api/client'

const state = reactive({
  // 当前登录用户名；空串表示未登录。
  username: '',
  // 会话过期时间（后端返回的 RFC3339 字符串）。
  expiresAt: '',
  // 是否已向后端确认过登录态。未确认时路由守卫必须先调用 ensureLoaded。
  checked: false,
  // 会话是否有效。仅用于判断登录态，真正的权限校验始终由后端负责。
  authenticated: false,
})

// setSession 在登录成功或恢复会话后写入状态。
function setSession({ username, expiresAt }) {
  state.username = username || ''
  state.expiresAt = expiresAt || ''
  state.authenticated = Boolean(username)
  state.checked = true
}

// clearSession 清理本地状态。
// 注意：本地清理不能替代后端登出，两者必须都做。
function clearSession() {
  state.username = ''
  state.expiresAt = ''
  state.authenticated = false
  // 登出后仍是“已确认”状态，避免守卫立刻又去问一次后端。
  state.checked = true
}

// ensureLoaded 确保登录态已向后端确认过，返回是否已登录。
//
// 刷新页面后内存状态丢失，必须靠 /api/auth/me 恢复；
// 该接口很轻（不读 /proc），但也不该每次跳转都调用，故用 checked 缓存。
async function ensureLoaded({ force = false } = {}) {
  if (state.checked && !force) {
    return state.authenticated
  }

  try {
    const me = await fetchCurrentUser()
    setSession({ username: me.username, expiresAt: me.expires_at })
    return true
  } catch (err) {
    if (err?.status === 401) {
      // 未登录属于正常分支，不应向前端控制台抛错误。
      clearSession()
      return false
    }
    // 网络错误等异常：不能断定“未登录”，但也不能放行，
    // 因此按未登录处理并把 checked 保持为 false，下次再试。
    state.username = ''
    state.authenticated = false
    state.checked = false
    throw err
  }
}

// doLogin 执行登录并写入状态。
async function doLogin(username, password, redirect) {
  const resp = await apiLogin(username, password, redirect)
  setSession({ username: resp.username, expiresAt: resp.expires_at })
  return resp
}

// doLogout 通知后端清除 Cookie 并清理本地状态。
// 即使后端请求失败也要清本地：否则用户会卡在“看起来已登录但实际不可用”的状态。
async function doLogout() {
  try {
    await apiLogout()
  } finally {
    clearSession()
  }
}

export const authStore = {
  // readonly 防止组件直接改状态，所有变更必须走下面的方法。
  state: readonly(state),
  ensureLoaded,
  login: doLogin,
  logout: doLogout,
  clear: clearSession,
}
