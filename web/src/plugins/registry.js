// 插件前端注册表 —— 阶段三 3.2 起由「静态查表」改为「动态挂载」。
//
// 3.1 的做法是：插件在 frontend.entry 里声明一个字符串 key，前端在本文件
// 的 pluginViews 静态表里查对应的组件。它有两个根本限制：
//
//   1. **新增插件必须改主程序源码**（往表里加一行）——插件就不再是自包含的；
//   2. 插件的界面被编译进主包，用户自己写的插件**永远不可能**加进来。
//
// 3.2 把 Entry 的语义升级为「插件自带 ESM 模块的地址」，由 loader.js
// 动态 import 进来。于是：
//
//   后端（plugin.Frontend）                前端（本文件 + loader.js）
//   entry:  "/plugin-assets/x/plugin.js"  ──import()──▶  { component }
//   assets: "/plugin-assets/x/"           （加载失败时的兜底位置 plugin.js）
//   type:   "esm"
//
// 本文件只保留「注册表」该有的三件事：登记入口、同步判定、解析组件。
// 真正的加载细节（URL 解析、Blob 降级、契约校验）全在 loader.js 里。
//
// 宿主页（PluginHostView）与布局（AppLayout）**不需要知道任何具体插件**：
// 它们只做 hasPluginView(id) / resolvePluginView(id)，因此新增插件时
// 这两个文件一行都不用改——这正是把「入口标识」与「渲染方式」解耦的价值。
//
// 注意：这里的判定一律是**同步**的（只看清单里有没有登记入口），
// 因此在 onMounted 之前、在模板渲染期调用都是安全的。
export {
  applyPlugins,
  clearPluginView,
  clearViewCache,
  getPluginLoadError,
  listEntryIds,
} from '@/plugins/loader'

import {
  hasEntry,
  listEntryIds,
  resolvePluginView as loadPluginView,
} from '@/plugins/loader'

// resolvePluginView 按插件 ID 解析前端组件。
//
// 返回 null 表示该插件**没有声明前端入口**——调用方应展示
// 「该插件未提供前端界面」。声明了入口但加载失败的情况，
// 由 loader 的 onError 记录原因，调用方用 getPluginLoadError(id) 取详情。
export function resolvePluginView(id) {
  return loadPluginView(id)
}

// hasPluginView 判断某个插件是否有前端界面（同步，供菜单与按钮使用）。
export function hasPluginView(id) {
  return hasEntry(id)
}

// registeredEntries 返回已登记的插件 ID 列表，便于调试与排查。
export function registeredEntries() {
  return listEntryIds()
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
