# 插件前端

本目录是**插件前端源码目录**，构建时被 Vite 原样拷贝到 `web/dist/plugin-assets/`，
再经 `go:embed` 打进单二进制。

```
web/plugins/plugin-assets/<插件ID>/plugin.js   插件前端源码（原样分发）
web/plugins/plugin-assets/frame.html           插件沙箱页（宿主用 iframe 加载它）
web/plugins/plugin-assets/frame/*.js           沙箱内的引导与 Vue 运行时
internal/plugin/builtin/<插件ID>/              插件后端（Go，编译进主程序）
```

## 一、加载链路

```
internal/plugin/builtin/x/plugin.go
        Descriptor().Frontend = { Entry: "/plugin-assets/x/plugin.js",
                                  Assets: "/plugin-assets/x/",
                                  NavTitle: "…", NavIcon: "…" }
        Descriptor().Permissions = ["system.read", …]
                │
                │  GET /api/plugins（核心返回元数据）
                ▼
PluginHostView.vue
        └─ PluginFrame.vue ─ <iframe sandbox="allow-scripts" src="/plugin-assets/frame.html?id=x">
                │                                    ↑ 刻意不含 allow-same-origin
                │  postMessage 握手 → 下发入口地址
                ▼
        frame/plugin-frame.js → import(entry) → 挂载组件
```

## 二、入口规范

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `frontend.entry` | 前端入口地址（ESM 模块） | `/plugin-assets/x/plugin.js` |
| `frontend.assets` | 资源基址：相对入口的解析基准，也是加载失败时的兜底目录 | `/plugin-assets/x/` |
| `frontend.type` | 入口类型，缺省 `esm` | `esm` |
| `frontend.nav_title` | 菜单标题；为空则不进菜单 | `系统信息（插件）` |
| `frontend.nav_icon` | 菜单图标标识（前端映射，见 `resolveNavIcon`） | `dashboard` |
| `frontend.sandbox` | 设为 `false` 时**放弃沙箱**，回到共享 Realm 的兼容模式 | 缺省即隔离 |

`entry` 的三种形态与解析规则：

| 形态 | 解析方式 | 说明 |
| --- | --- | --- |
| `plugin.js` | 相对 `assets` 基址 | 短写法 |
| `/plugin-assets/x/plugin.js` | 站点绝对路径 | **推荐** |
| `https://…` | 仅同源时允许 | 跨源默认拒绝（安全策略） |

**兜底优先级**：`entry` 加载失败 → 尝试 `<assets>/plugin.js` → 仍失败则在沙箱内
显示可读的失败原因，并把错误上报给宿主页（宿主在 iframe 外也显示一遍）。
若 `entry` 为空，判定为「该插件未提供前端界面」。

## 三、模块契约

```js
import { h, ref, onMounted } from 'vue'

export default {
  meta: { id: 'x', title: '示例', version: '0.1.0' },  // 可选，仅供排查
  component: {                                          // 必需：Vue 组件
    props: { pluginId: String, plugin: Object },        // 宿主注入的两个 prop
    setup(props) { /* … */ },
  },
}
```

宿主注入的 prop（隔离模式与兼容模式**完全一致**）：

- `pluginId`：插件 ID；
- `plugin`：后端返回的该插件元数据（含 `state`、`frontend`、`permissions`）。

## 四、取数：必须用桥接 API

**隔离模式下插件读不到会话 Cookie，也无法直连 `/api/*`**（iframe 处于
opaque origin）。要数据请通过宿主代取：

```js
const data = await window.__LIPANEL__.api.get('/info')   // → /api/plugins/<自身id>/info
await window.__LIPANEL__.api.post('/action', { a: 1 })
```

规则与限制（全部由**宿主侧强制**，客户端校验只是体验）：

| 项 | 规则 |
| --- | --- |
| 路径 | 只能访问**本插件自己的**接口（宿主自动拼 `/api/plugins/<自身 id>` 前缀） |
| 方法 | `GET` / `POST` / `PUT` / `DELETE` / `HEAD` |
| 响应体 | 单次最大 1 MiB |
| 权限 | 受插件后端 `Permissions` 约束，未声明返回 **403** |

失败时 `await` 会抛错，`err.status` 是 HTTP 状态码，`err.body` 是响应体：

```js
try {
  await window.__LIPANEL__.api.get('/info')
} catch (err) {
  if (err.status === 403) show('权限不足：' + err.body?.required)  // 缺哪个权限
  if (err.status === 503) show('插件未运行，请先启动')
}
```

其他桥接能力：`ui.notify(text, level)`、`ui.resize(height)`、`ui.navigate('/path')`。

## 五、可以依赖什么

| 允许 | 说明 |
| --- | --- |
| `import { ref, h, computed, onMounted } from 'vue'` | 由沙箱页的 importmap 指向宿主**同一份** Vue（共享同一 runtime chunk） |
| `window.__LIPANEL__.api.*` | 经 postMessage 请宿主代取本插件数据 |
| `window.__LIPANEL__.frame` | `true` 表示运行在沙箱 iframe 中 |

| 不允许 | 原因 |
| --- | --- |
| `fetch('/api/*')` | 隔离模式下无会话 Cookie，必然 401。请用桥接 API |
| `document.cookie` | 沙箱下读不到（这正是隔离的目的） |
| `localStorage` / `sessionStorage` | opaque origin 下不可用 |
| `naive-ui` 组件 | 需要 `<n-config-provider>` 上下文；插件以非 `.vue` 源码原样加载，拿不到该上下文 |
| `.vue` 单文件、`@/` 别名 | 本目录不经过 Vite 打包，没有编译期处理 |
| `@/api/*`、`@/utils/*` 等宿主内部模块 | 插件一旦依赖宿主内部实现，宿主重构就会让插件集体损坏 |

界面请用 `h()` 手写 DOM（参考 `sysinfo/plugin.js`），只用继承色
（`color: inherit` / `opacity`）与半透明分隔线，以适配宿主明暗主题。

## 六、安全边界（**请务必读这一节**）

隔离模式保护的是**宿主页面**：

| 插件拿不到 | 原因 |
| --- | --- |
| 会话 Cookie | iframe 是 opaque origin，`document.cookie` 读不到 |
| 直接调用核心接口 | 无 Cookie 的 `fetch('/api/*')` 被后端 401 |
| 其它插件的接口 | 宿主桥接只放行 `/api/plugins/<自身 id>/` 前缀 |
| 宿主 DOM 与其它插件页面 | iframe 边界 |
| 任意站内跳转 | `ui.navigate` 只接受站内相对路径 |

**这个方案不能做什么**（不要误解）：

1. 它**不限制插件的后端进程**。插件进程能读什么文件、能执行什么命令由内核
   决定；面板的 `Permissions` 声明约束的是「核心转发给插件的调用」，
   同样**不是内核级沙箱**。要运行不可信的插件后端，必须使用操作系统级隔离
   （独立用户 + 只读挂载 + seccomp 等）。
2. 它**不限制算力**。插件前端仍会占用宿主标签页的 CPU（渲染、循环）；
   iframe 无法限制这点，只能靠宿主的超时与错误上报发现异常。
3. 兼容模式（`frontend.sandbox: false` 或 URL 加 `?legacy=1`）**没有上述任何
   保护**：插件与宿主共享 Realm，能读 `document.cookie`、能直连 `/api/*`。
   仅应在插件前端完全可信时使用。

## 七、写一个新插件前端的步骤

1. 建目录 `web/plugins/plugin-assets/<id>/plugin.js`，按第三节的契约导出组件；
2. 取数一律用 `window.__LIPANEL__.api.*`（第四节）；
3. 在插件后端 `Descriptor()` 里声明 `Frontend`（Entry/Assets/NavTitle/NavIcon）
   与 `Permissions`（如 `system.read`）；
4. 重新构建（`./build.sh`）——`plugin-assets/` 会被一起打包。

## 八、已知限制

- **旧浏览器不支持**：依赖 import maps（Firefox 108+ / Safari 16.4+）。
  更旧的浏览器会在沙箱内显示明确提示，而不是白屏。
- 插件前端暂不支持样式表与图片等静态资源；需要时再扩展 `assets` 基址的用法。
- 沙箱内的插件只能渲染在自己那块 iframe 里，**无法**使用宿主的 Naive UI
  组件与全局样式，界面上需要自行适配。
- 协议版本为 `1`（见 `frame/plugin-frame.js` 与 `src/plugins/bridge.js`）。
  两侧版本不一致时宿主会明确拒绝并提示，而不是静默半坏地运行。
