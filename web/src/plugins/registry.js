// 插件前端注册表 —— 「为后续动态挂载插件前端留的插槽」。
//
// 设计意图（重要，后续阶段会在这里扩展）：
//
//   核心通过 GET /api/plugins 返回每个插件的 Frontend 元数据：
//       { entry: "sysinfo", nav_title: "系统信息（插件）", nav_icon: "dashboard" }
//   前端用 entry 作为 key 到本注册表中查找要渲染的组件。
//
// 本阶段（3.1）注册表是**静态**的：只有内置插件会在这里登记组件，
// 组件通过 () => import(...) 懒加载（Vite 会把它拆成独立 chunk）。
//
// 后续阶段要做「外部插件动态挂载」时，只需要改动本文件的 resolvePluginView：
// 把静态查表换成读取插件声明的 ESM 入口，例如
//
//   defineAsyncComponent(() => import(/* @vite-ignore */ plugin.frontend.entry))
//
// 路由（/plugins/:id）与菜单渲染**完全不需要改动**——
// 这正是把「入口标识」与「渲染方式」解耦的价值。
import { defineAsyncComponent } from 'vue'

// pluginViews 是 entry -> 组件的映射。
//
// key 必须与插件 Descriptor.Frontend.Entry 一致（后端在
// internal/plugin/builtin/sysinfo/plugin.go 中声明为 "sysinfo"）。
const pluginViews = {
  sysinfo: defineAsyncComponent(() => import('@/plugins/views/SysinfoPluginView.vue')),
}

// resolvePluginView 按 entry 解析插件前端组件。
// 返回 null 表示当前没有该插件的前端实现——
// 调用方应展示「该插件未提供前端界面」而不是渲染空白页。
export function resolvePluginView(entry) {
  if (!entry) return null
  return pluginViews[entry] || null
}

// hasPluginView 判断某个 entry 是否有前端实现。
// 插件管理页用它来决定「打开」按钮是否可点。
export function hasPluginView(entry) {
  return Boolean(entry && pluginViews[entry])
}

// registeredEntries 返回已注册的 entry 列表，便于调试。
export function registeredEntries() {
  return Object.keys(pluginViews)
}

// NavIcon 映射表：把后端给的 nav_icon 字符串转成图标组件名。
//
// 后端只传字符串而不传组件，是为了让插件系统与前端 UI 库解耦：
// 换 UI 库时只需改这张表，不必改动任何插件。
// 这里用 emoji 而非 Naive UI 图标组件，避免为一个菜单图标
// 引入 @vicons 依赖（工程约束：轻量、按需引入）。
const navIcons = {
  dashboard: '📊',
  terminal: '⌨️',
  folder: '📁',
  server: '🖥️',
  settings: '⚙️',
  plugin: '🧩',
}

// resolveNavIcon 解析菜单图标；未知标识回落到通用插件图标。
export function resolveNavIcon(icon) {
  return navIcons[icon] || navIcons.plugin
}
