# lipanel 插件开发 API 参考

> 本文档面向**插件作者**，描述 lipanel（阶段三）当前**真实存在**的接口。
>
> **编写原则：诚实第一。** 本文只写代码里已经实现的接口，并明确标出
> 还不能做的事。凡是标注「❌ 当前不支持」的，都是查过 `internal/plugin/`
> 与 `web/plugins/plugin-assets/frame/` 的源码后确认的，不是猜测。

---

## 目录

- [零、五分钟上手](#零五分钟上手)
- [一、后端 Go API](#一后端-go-api)
  - [1.1 plugin.Handler 接口](#11-plughandler-接口)
  - [1.2 plugin.Descriptor 结构体](#12-plugindescriptor-结构体)
  - [1.3 关于 `PluginRouter` 与 `PluginManifest`](#13-关于-pluginrouter-与-pluginmanifest)
  - [1.4 插件能调用的系统能力](#14-插件能调用的系统能力)
  - [1.5 权限声明清单](#15-权限声明清单)
- [二、前端 JS API](#二前端-js-api)
  - [2.1 window.\_\_LIPANEL\_\_ 全部字段](#21-window__lipanel__-全部字段)
  - [2.2 api 代发请求](#22-api-代发请求)
  - [2.3 vue 里能拿到什么](#23-vue-里能拿到什么)
  - [2.4 ui 宿主配合](#24-ui-宿主配合)
  - [2.5 沙箱内的禁止行为](#25-沙箱内的禁止行为)
- [三、完整最小示例](#三完整最小示例)
- [四、常见问题](#四常见问题)
- [五、当前能力边界](#五当前能力边界)

---

## 零、五分钟上手

一个插件的完整生命周期：

```
你写的三个文件                          面板做的事
─────────────────────────────────────────────────────────────
internal/plugin/builtin/<id>/plugin.go   ── 编译期 ──▶ 主程序二进制
   ├─ 实现 Descriptor() + Routes()
   └─ init() 里 RegisterBuiltin()

web/plugins/plugin-assets/<id>/plugin.js ── 构建期 ──▶ dist/plugin-assets/
   └─ export default { component }                     ── go:embed ──▶ 二进制

                                           运行期
主程序拉起 <自身> __plugin_<id>  ──▶ 插件进程监听 Unix socket
浏览器 GET /api/plugins/<id>/info ─▶ 核心鉴权 ─▶ 转发到插件进程
```

**关键点：插件后端跑在独立进程里，通过 Unix socket 上的 HTTP 与核心通信。**
你的插件崩溃不会拖垮主面板（详见 [常见问题](#四常见问题)）。

> ⚠️ **重要前提**：本阶段的插件是**内置插件**——你的 `plugin.go` 会被编译进
> 主程序。也就是说，**改了 Go 后端就必须重新编译面板**。不需要重新编译的
> 「外部插件」机制尚未实现（详见 [5.3](#53-外部插件机制完成后才能做的)）。

---

## 一、后端 Go API

### 1.1 plugin.Handler 接口

位置：`internal/plugin/serve.go`

```go
type Handler interface {
    // Descriptor 返回插件的静态元数据。
    Descriptor() Descriptor
    // Routes 注册插件的业务路由。
    Routes(mux *http.ServeMux)
}
```

**就这两个方法。** 插件后端能做的事，全部通过 `Routes` 注册 HTTP 路由来实现。

#### 关于「Get/Post/Put/Delete」

不存在 `PluginRouter` 这个类型，也不存在 `router.Get()` / `router.Post()` 这类链式方法。
`Routes` 收到的是一个**标准库的 `*http.ServeMux`**，所以用法就是 Go 1.22+ 的标准写法：

```go
func (p *Plugin) Routes(mux *http.ServeMux) {
    // 语法： "METHOD /path"，方法名与路径之间有一个空格
    mux.HandleFunc("GET /info", p.handleInfo)
    mux.HandleFunc("POST /refresh", p.handleRefresh)
    mux.HandleFunc("PUT /setting", p.handleSetting)
    mux.HandleFunc("DELETE /cache", p.handleClearCache)
}
```

四种方法**都能用**，但注意下面这条：

> ### ⚠️ 权限规则表当前只覆盖部分路径
>
> 位置：`internal/plugin/permission.go` 的 `permissionRules`。
>
> 核心按「**HTTP 方法 + 插件子路径**」推断这次调用需要什么权限。
> 当前规则表里已钉死的组合是：
>
> | 方法 | 路径前缀 | 需要权限 |
> |---|---|---|
> | GET | `/runtime` | `process.read` |
> | GET | `/info`、`/echo`、`/metrics` | `system.read` |
> | GET | `/services` | `service.read` |
> | POST | `/services` | `service.write` |
> | GET | `/files` | `file.read` |
> | POST / PUT / DELETE | `/files` | `file.write` |
>
> **其它任何路径**（例如你自己起的 `GET /hello`）会落到 `fallbackPermission`，
> 即默认要求 **`system.read`**。
>
> 这是**默认拒绝**设计：宁可多要一个权限，也不放行未申报的调用。
> 所以你的插件如果用了自定义路径，manifest 里**至少声明 `system.read`**，
> 否则所有请求都会被核心以 403 拒绝。

#### 免权限的骨架路由

以下由 `plugin.Serve` 统一提供，**你不需要也不应该实现它们**：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康探测，核心用；返回 status/plugin/version/pid/time |
| GET | `/whoami` | 身份确认与排查；返回插件元数据 + 它收到的请求头 |
| GET | `/assets/` | 前端资源（由 `AssetProvider` 提供，见下） |

#### 可选接口：AssetProvider

想让插件自带前端资源，额外实现这个接口：

```go
type AssetProvider interface {
    // Assets 返回插件自带的前端资源文件系统（根下直接是 plugin.js 等文件）。
    Assets() fs.FS
}
```

标准做法是用 `go:embed`：

```go
//go:embed frontend
var frontendFS embed.FS

func (p *Plugin) Assets() fs.FS {
    sub, _ := fs.Sub(frontendFS, "frontend")
    return sub
}
```

单个资源上限 **8 MiB**（`assetMaxBytes`）。

---

### 1.2 plugin.Descriptor 结构体

位置：`internal/plugin/plugin.go`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ID` | string | ✅ | 插件唯一标识。必须匹配 `^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`（小写字母/数字/连字符，2~32 位，不能以连字符开头或结尾） |
| `Name` | string | ✅ | 展示名称 |
| `Version` | string | ✅ | 版本号 |
| `Description` | string | — | 用途说明 |
| `Builtin` | bool | ✅ | 是否内置插件。本阶段写 `true` |
| `Mode` | string | ✅ | `"managed"`（核心托管进程）或 `"external"`（外部自行启动，核心只拨号） |
| `Permissions` | []string | — | 权限声明清单，语法见 [1.5](#15-权限声明清单) |
| `Frontend` | Frontend | — | 前端挂载信息，见下表 |

#### Frontend 子结构

| 字段 | JSON 名 | 说明 |
|---|---|---|
| `Entry` | `entry` | 前端入口地址（ESM 模块），例如 `/plugin-assets/hello/plugin.js` |
| `Assets` | `assets` | 资源基址（以 `/` 结尾），也是入口加载失败时的兜底目录 |
| `Type` | `type` | 入口类型，目前只支持 `"esm"`（缺省即 esm） |
| `NavTitle` | `nav_title` | 菜单显示名。**为空则不进菜单** |
| `NavIcon` | `nav_icon` | 菜单图标标识（前端自行映射） |

> `Frontend.Valid()` 要求 `Entry` 与 `NavTitle` **都非空**才会进菜单。
> 只写 `Entry` 不写 `NavTitle`，插件会被注册但菜单里看不到。

#### 合法 ID 是安全边界，不只是格式问题

ID 会出现在三处：

- URL 路径 `/api/plugins/{id}/...`
- socket 文件名 `<sockDir>/<id>.sock`
- 日志字段

如果允许 `.` 或 `/`，攻击者就能用 `../../etc/passwd` 这样的 ID 构造目录穿越。
因此校验在注册阶段就执行，非法 ID 直接拒绝。

---

### 1.3 关于 `PluginRouter` 与 `PluginManifest`

这两个名字在**当前代码里不存在**，这里明确澄清，避免你按错误的名字去写代码：

| 你可能会找的名字 | 实际情况 |
|---|---|
| `PluginRouter` 接口 | ❌ 不存在。插件路由用标准库 `*http.ServeMux`，见 [1.1](#11-plughandler-接口) |
| `PluginManifest` 结构体 | ❌ 不存在。描述插件的结构体叫 **`plugin.Descriptor`**，见 [1.2](#12-plugindescriptor-结构体) |
| `descriptor.json` 文件 | ❌ 不存在。内置插件的元数据是 **Go 代码里的 `Descriptor` 字面量**，不是 JSON 文件 |
| `manifest.json` 文件 | ❌ 不存在（属于尚未实现的「外部插件」机制，见 [5.3](#53-外部插件机制完成后才能做的)） |

全项目搜索 `descriptor.json` 与 `manifest.json` 均无匹配（`node_modules` 除外）。

---

### 1.4 插件能调用的系统能力

#### 结论：**当前没有 Host 接口。**

我查了 `internal/plugin/` 下的 `plugin.go`、`serve.go`、`manager.go`、`process.go`、
`permission.go`、`registry.go`，**没有任何给插件使用的「宿主能力」接口**——
没有 `Host`、没有 `Executor`、没有注入的文件系统、也没有读取系统信息的回调。

插件进程启动时（`internal/plugin/serve.go` 的 `Serve`）**只拿到两样东西**：

```go
func Serve(h Handler, logger *slog.Logger) error
```

1. 你自己的 `Handler` 实现；
2. 一个 `*slog.Logger`。

工厂函数 `Factory` 也只多给一个 logger：

```go
type Factory func(logger *slog.Logger) Handler
```

**没有任何执行器、文件系统、配置或核心状态被注入。** 核心与插件之间唯一
的数据通道是那条 Unix socket 上的 HTTP（核心 → 插件方向）。

#### 但是——插件进程本身没有被沙箱限制

这一点非常重要，别被上面的结论误导：

> 插件是一个**独立的操作系统进程**，它以面板进程的权限运行（通常是 root）。
> 它可以 `import "os/exec"` 执行命令、可以 `os.ReadFile("/etc/shadow")`、
> 可以做任何这个用户能做的事。**没有任何内核级限制阻止它。**

那「权限声明」到底管什么？管的是**核心转发通道**：

```
浏览器 ──▶ 核心（鉴权 + 权限校验）──▶ 插件进程
                    ↑
          权限声明在这里生效：
          没声明的操作被 403 拒绝，请求根本到不了插件
```

所以准确的说法是：

| 说法 | 对错 |
|---|---|
| 「声明了 `process.exec` 我就能执行命令」 | ❌ 错。执行命令不需要任何声明，你本来就能做 |
| 「没声明 `process.exec` 我就不能执行命令」 | ❌ 错。没有任何东西会阻止你 |
| 「声明是**向用户申报** + 让核心能**拒绝越权调用**」 | ✅ 对 |

**请据此设计你的插件：** 声明权限是为了让用户在插件管理页看清楚你要什么、
让审计有据可查。**用户是信任你的**，不要把「没声明」当成安全边界。

#### 现在能做什么 / 不能做什么（后端）

| 能力 | 状态 | 说明 |
|---|---|---|
| 注册 HTTP 路由 | ✅ | 标准库 `*http.ServeMux` |
| 读系统信息（`/proc`、`runtime` 等） | ✅ | 插件进程自己读，如 sysinfo 插件 |
| 执行 shell 命令 | ⚠️ 技术上可以 | `os/exec` 直接用。但**必须声明** `process.exec` 并在文档里说明 |
| 读写任意文件 | ⚠️ 技术上可以 | `os.Open` 直接用。**必须声明**对应的 `file.read` / `file.write` |
| 持有自己的内存状态 | ✅ | 插件进程与核心不共享内存，状态要自己管 |
| 调用核心的内部接口 | ❌ | 核心没有给插件提供反向调用通道 |
| 访问核心的内存状态（配置、会话等） | ❌ | 独立进程，拿不到 |
| 访问其它插件 | ❌ | 无跨插件调用通道 |
| 让核心代为执行敏感操作 | ❌ | 无 Host 接口 |

---

### 1.5 权限声明清单

位置：`internal/plugin/permission.go`

#### 语法

```
<域>.<动作>[:<资源>]
```

- **域**（domain）：必须是已知域，否则解析失败。
  已知域：`system`、`process`、`file`、`network`、`http`、`service`
- **动作**（action）：小写字母开头，可含小写字母、数字、下划线
- **资源**（resource）：可选，须以 `/` 或字母数字开头，可含 `._/-`

整体字符集被严格限制为小写字母、数字、`.`、`-`、`_`、`:`、`/`
——这是为了防止控制字符/换行注入到日志与审计记录里（日志注入会让审计失真）。

```go
Permissions: []string{
    "system.read",                    // 不限资源
    "file.read:/etc/nginx",           // 限定资源（见下方警告）
    "process.exec",                   // "system.read,process.read" 逗号分隔也可以
}
```

#### 支持的权限与对应能力

| 权限串 | 实际拦截的能力 | 免声明路径 |
|---|---|---|
| `system.read` | 读系统信息类接口。**也是未匹配路径的兜底权限** | `/info`、`/echo`、`/metrics` |
| `process.read` | 读插件自身进程信息 | `/runtime` |
| `service.read` | 读服务状态 | `GET /services` |
| `service.write` | 启停服务 | `POST /services` |
| `file.read` | 读文件类接口 | `GET /files` |
| `file.write` | 写文件类接口 | `POST/PUT/DELETE /files` |
| `process.exec` | 当前**没有**对应的内置路径规则；声明它是「申报意图」 | — |
| `http.call` | 当前**没有**对应的内置路径规则；声明它是「申报意图」 | — |
| `network.*` | 同上，申报用 | — |

#### ⚠️ 资源段目前不参与校验

这是当前实现的一个**重要限制**，文档必须说清楚：

```go
// 位置：internal/plugin/permission.go
// Key 返回「域.动作」形式，用于粗粒度匹配。
//
// 资源段刻意不参与匹配：当前核心无法验证插件是否真的只用了资源段里的路径
func (p Permission) Key() string { return p.Domain + "." + p.Action }
```

也就是说：

- `file.read` 与 `file.read:/etc/nginx` 在**校验时完全等价**；
- `Has("file.read:/etc/shadow")` 会匹配到只声明了 `file.read:/etc/nginx` 的插件。

**所以不要把资源段当作安全约束。** 它目前只用于展示与审计留痕，
细粒度校验是将来才做的事。

#### 声明的其它规则

- **重复声明同一「域.动作」会报错**，不会静默去重。
  这是故意的：那通常是复制粘贴忘了改，静默去重会让「我明明声明了」的排查变困难。
- 未声明任何权限 = `PermissionSet` 零值，**一律拒绝**（fail-closed）。
  除 `/healthz`、`/whoami`、`/assets/` 外，所有转发调用都会 403。
- 权限在**注册阶段**就解析，写错的权限不会等到被点击时才暴露。

---

## 二、前端 JS API

插件前端跑在 `<iframe sandbox="allow-scripts">` 里（`PluginFrame.vue`）。
**没有 `allow-same-origin`，所以 iframe 是 opaque origin**，这决定了你能做什么。

### 2.1 `window.__LIPANEL__` 全部字段

位置：`web/plugins/plugin-assets/frame/plugin-frame.js`

宿主运行时对象。**完整字段清单如下**（就是这个，没有更多）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `protocol` | number | 协议版本，当前为 `1` |
| `frame` | boolean | 恒为 `true`，插件可据此判断自己跑在隔离 iframe 里 |
| `vue` | object\|null | Vue 模块命名空间。**由 `/assets/plugin-runtime.js` 注入**，骨架里初始为 `null` |
| `vueReady` | Promise | 在 vue 注入完成后 resolve。引导层会 `await` 它 |
| `api` | object | 代发 HTTP 请求，见 [2.2](#22-api-代发请求) |
| `ui` | object | 界面配合，见 [2.4](#24-ui-宿主配合) |

> **`mount` 不在 `window.__LIPANEL__` 上。** 挂载是你通过
> `export default { component }` 声明契约、由引导层完成的，不需要（也没有）
> 手动 mount 的 API。
>
> **`ready` 也不在 `__LIPANEL__` 上**——「就绪」是通过 `vueReady` 这个
> Promise 表达的。

#### 推荐用法

绝大多数插件**不需要直接碰 `window.__LIPANEL__`**，直接写组件就行：

```js
import { h, ref } from 'vue'

export default {
  component: {
    setup() {
      const msg = ref('hello')
      return () => h('div', msg.value)
    },
  },
}
```

### 2.2 api 代发请求

```js
window.__LIPANEL__.api = {
  get(path)               -> Promise<any>
  post(path, body)        -> Promise<any>
  request(path, options)  -> Promise<any>
}
```

> ### ⚠️ 没有 `put` 和 `delete` 方法
>
> `api` 上**只有 `get`、`post`、`request` 三个方法**。
> 需要 PUT/DELETE 时用 `request` 显式指定 method：
>
> ```js
> await window.__LIPANEL__.api.request('/files/x', { method: 'DELETE' })
> ```

#### 参数

`request(path, options)` 的 `options`：

| 字段 | 类型 | 缺省 | 说明 |
|---|---|---|---|
| `method` | string | `'GET'` | HTTP 方法 |
| `body` | any | — | 请求体，会被结构化克隆传给宿主 |

- **`path` 只能是本插件自己的子路径**，形如 `/info`、`/runtime`。
  宿主会自动拼上 `/api/plugins/<你的id>` 前缀。
- 你不能指定绝对路径去访问别的接口——**白名单由宿主侧强制**。
  客户端校验永远只是「体验」，不是安全边界。
- **超时 30 秒**，超时后 reject（错误信息：`插件桥接请求超时（宿主可能已关闭该插件页面）`）。
- 失败时 reject 一个 `Error`，上面挂有：
  - `err.status` — HTTP 状态码（可据此区分 403 权限不足、503 插件未运行、401 会话过期）
  - `err.body` — 响应体

```js
try {
  const data = await window.__LIPANEL__.api.get('/info')
} catch (err) {
  if (err.status === 403) console.warn('权限不足，检查 Descriptor 的 Permissions')
}
```

### 2.3 vue 里能拿到什么

`window.__LIPANEL__.vue` 是**完整的 Vue 模块命名空间**（等价于 `import * as vue from 'vue'`）。
里面就是 Vue 官方导出的全部内容，包括但不限于：

`h`、`ref`、`reactive`、`computed`、`watch`、`watchEffect`、`onMounted`、`onUnmounted`、
`nextTick`、`createApp`、`defineComponent`、`toRefs`、`provide`、`inject` 等。

#### 但更推荐直接 `import { ... } from 'vue'`

因为 iframe 内的 `importmap` 指向 `/assets/plugin-runtime.js`
（定义在 `web/plugins/plugin-assets/frame.html`），
它和 `__LIPANEL__.vue` 是**同一个模块实例**：

```
/assets/plugin-runtime.js        ──▶  window.__LIPANEL__.vue
插件 A 的 import 'vue'           ──▶  ┐
插件 B 的 import 'vue'           ──▶  ├─ iframe 的 importmap 都指向上面那个 URL
插件 C 的 import 'vue'           ──▶  ┘   → 浏览器模块表里是同一个实例
```

所以下面两种写法等价，**推荐第一种**：

```js
// ✅ 推荐
import { computed, h, onMounted, ref } from 'vue'

// ⚠️ 能用但不推荐（除非你在写不经过打包的裸 JS）
const { h, ref } = await window.__LIPANEL__.vueReady
```

> **别和主应用的 importmap 搞混**：`web/index.html` 里也有一份 importmap，
> 它把 `vue` 指向 `/assets/vue.js`。那是**主应用自己的**插件加载路径
> （非隔离模式与 Blob 降级用），和你在 iframe 里拿到的不是同一个 URL，
> 但两者最终指向同一个 Vue 模块实例。
>
> 你只需要记住一件事：**在插件里写 `import { h } from 'vue'` 总是对的。**

#### 组件导出契约

```js
// 你的 plugin.js 必须默认导出一个组件
export default {
  component: {
    props: ['pluginId', 'plugin'],   // 由宿主注入
    setup(props) { /* ... */ },
  },
}
```

- `pluginId` — 你的插件 ID（string）
- `plugin` — 插件元数据对象（可能为 `null`）

组件也可以是 `default` 导出本身（不包一层 `component`）。

> ❌ **不能用 `.vue` 单文件、不能用 `@` 别名、不能 import naive-ui。**
> 插件前端是**原样分发**的，不经 Vite 打包，所以没有模板编译器，
> 界面要用 `h()` 手写。
>
> 这是刻意的隔离：插件若依赖主程序内部模块，主程序一重构插件就集体损坏。

### 2.4 ui 宿主配合

```js
window.__LIPANEL__.ui = {
  resize(height),          // 上报内容高度，宿主会 clamp 后调整 iframe 高度
  notify(text, level),     // 请求宿主弹提示，text 截断 500 字符，level 缺省 'info'
  navigate(to),            // 请求站内跳转，白名单由宿主强制
}
```

高度通常**不需要手动上报**——引导层已经用 `ResizeObserver` 自动做了。

### 2.5 沙箱内的禁止行为

因为 iframe 是 `sandbox="allow-scripts"`（**不带** `allow-same-origin`），
它是 opaque origin，下面这些**做不到**：

| 禁止行为 | 后果 | 原因 |
|---|---|---|
| `document.cookie` | 读不到（空） | opaque origin 没有 cookie |
| `localStorage` / `sessionStorage` | **抛异常** | opaque origin 访问存储会抛 SecurityError |
| `fetch('/api/*')` | ❌ **不可靠** | 相对路径在 opaque origin 下解析不到面板源；且请求不带会话 Cookie |
| 直接 `import` 宿主的 `src/` 模块 | 加载失败 | 不经打包，路径不存在 |
| 使用 naive-ui、`@` 别名、`.vue` 文件 | 加载失败 | 同上 |
| 访问 `window.parent.document` | 抛异常（跨源） | 同源策略 |
| 读宿主的会话凭据 | ❌ 做不到 | 凭据始终留在宿主侧 |

**替代方案**：所有需要会话或跨域的请求，一律走
`window.__LIPANEL__.api.*` —— 由宿主代发，凭据不会进到 iframe。

---

## 三、完整最小示例

比 sysinfo 更简单的最小插件：一个显示「你好」并调用自己后端接口的插件。

### 文件结构

```
internal/plugin/builtin/hello/plugin.go        ← 后端
web/plugins/plugin-assets/hello/plugin.js      ← 前端
```

> **注意**：没有 `descriptor.json`。内置插件的元数据是 Go 代码里的
> `Descriptor` 字面量。

### 3.1 `internal/plugin/builtin/hello/plugin.go`

```go
// Package hello 是一个最小可用的示例插件。
//
// 它演示了写一个 lipanel 插件需要做的全部事情：
//  1. 实现 plugin.Handler（Descriptor + Routes）
//  2. 在 init 中调用 plugin.RegisterBuiltin 自我登记
//  3. （可选）提供前端界面
package hello

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "time"

    "lipanel/internal/plugin"
)

const (
    ID      = "hello"
    Version = "0.1.0"
)

// 包级变量：确保 Plugin 实现了 plugin.Handler 接口。
// 编译期就能发现「少写了方法」，而不是运行期才炸。
var _ plugin.Handler = (*Plugin)(nil)

type Plugin struct {
    logger *slog.Logger
    // 插件进程独立于核心，状态要自己持有。
    startedAt time.Time
}

func New(logger *slog.Logger) *Plugin {
    return &Plugin{logger: logger, startedAt: time.Now()}
}

func (p *Plugin) Descriptor() plugin.Descriptor {
    return plugin.Descriptor{
        ID:          ID,
        Name:        "Hello 示例",
        Version:     Version,
        Description: "最小示例插件：演示 Handler、路由、权限声明与前端挂载。",
        Builtin:     true,
        Mode:        plugin.ModeManaged,
        // 只读系统信息，因此只申请 system.read。
        // 注意：未匹配的路径会兜底要求 system.read，所以自定义路径
        // （如本示例的 GET /greet）必须声明它，否则会被核心 403。
        Permissions: []string{"system.read"},
        Frontend: plugin.Frontend{
            Entry:    "/plugin-assets/hello/plugin.js",
            Assets:   "/plugin-assets/hello/",
            Type:     plugin.FrontendTypeESM,
            NavTitle: "Hello 示例",
            NavIcon:  "smile",
        },
    }
}

func (p *Plugin) Routes(mux *http.ServeMux) {
    mux.HandleFunc("GET /greet", p.handleGreet)
}

func (p *Plugin) handleGreet(w http.ResponseWriter, r *http.Request) {
    // 统一用 JSON 响应，便于前端与测试脚本处理。
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    _ = json.NewEncoder(w).Encode(map[string]any{
        "message":    "你好，来自插件进程！",
        "plugin":     ID,
        "uptime_sec": int(time.Since(p.startedAt).Seconds()),
    })
}

// init 把自己登记到内置插件表。
// 根目录的 plugin_main.go 用匿名 import 触发本函数。
func init() {
    plugin.RegisterBuiltin(ID, func(logger *slog.Logger) plugin.Handler {
        return New(logger)
    })
}
```

**最后一步**：在 `plugin_main.go` 的 import 块里加一行，否则 `init` 不会执行：

```go
import (
    _ "lipanel/internal/plugin/builtin/hello"   // ← 加这一行
    _ "lipanel/internal/plugin/builtin/sysinfo"
)
```

### 3.2 `web/plugins/plugin-assets/hello/plugin.js`

```js
// hello 插件的前端界面。
//
// 契约：export default { component }
// 组件由宿主挂载，pluginId / plugin 作为 props 注入。
//
// 注意：这里刻意不用 .vue 单文件、不用 @ 别名、不引 naive-ui——
// 插件前端是原样分发的，不经 Vite 打包。
import { h, onMounted, ref } from 'vue'

export default {
  component: {
    // 宿主注入的 props。用不到可以省略整个 props 声明。
    props: {
      pluginId: { type: String, default: '' },
      plugin: { type: Object, default: null },
    },

    setup(props) {
      const message = ref('加载中…')
      const error = ref('')

      onMounted(async () => {
        try {
          // 走宿主桥接代发请求。
          // '/greet' 会被宿主拼成 /api/plugins/<id>/greet。
          const data = await window.__LIPANEL__.api.get('/greet')
          message.value = data.message
        } catch (err) {
          // err.status 可区分 403 权限不足 / 503 插件未运行 / 401 会话过期。
          error.value = '调用失败：' + (err.message || String(err)) +
            (err.status ? '（HTTP ' + err.status + '）' : '')
        }
      })

      return () => {
        const children = [
          h('h2', { style: 'margin: 0 0 8px' }, 'Hello 插件'),
          h('p', { style: 'margin: 0 0 4px' }, message.value),
          h('p', { style: 'margin: 0; color: #999; font-size: 12px' },
            '插件 ID：' + (props.pluginId || '(未知)')),
        ]
        if (error.value) {
          children.push(
            h('p', { style: 'color: #d03050; margin: 8px 0 0' }, error.value),
          )
        }
        return h('div', { style: 'padding: 16px' }, children)
      }
    },
  },
}
```

### 3.3 构建与验证

```bash
./build.sh                      # 构建前端 + 编译二进制
./lipanel -addr 127.0.0.1:8080  # 启动

# 另开一个终端验证：
# 1. 插件已注册
curl -s -b cookie.txt http://127.0.0.1:8080/api/plugins | grep hello

# 2. 启动插件
curl -s -b cookie.txt -X POST http://127.0.0.1:8080/api/plugins/hello/start

# 3. 调用你的接口
curl -s -b cookie.txt http://127.0.0.1:8080/api/plugins/hello/greet
# {"message":"你好，来自插件进程！","plugin":"hello","uptime_sec":3}
```

浏览器打开 `/plugins/hello` 应能看到页面。

---

## 四、常见问题

### 插件崩了会影响主面板吗？

**不会。** 这是本架构最重要的性质。

插件后端是**独立进程**（`internal/plugin/process.go` 用 `exec.Command` 拉起），
核心通过 Unix socket 与它通信。因此：

| 情况 | 结果 |
|---|---|
| 插件 panic / 崩溃退出 | 核心感知到进程退出，标记状态为 `failed`，**面板本身完全不受影响** |
| 插件响应很慢 | 转发请求有**超时上限**（默认 15 秒），超时返回错误；**一个卡死的插件不会拖垮面板** |
| 插件死循环 | 同上，被超时截断 |
| **插件前端 JS 报错** | 引导层装了 `errorHandler`，异常会通过 `lipanel:error` 上报，宿主显示错误提示而不是白屏 |

而且**插件崩溃后可被自动拉起**（`Restarts` 计数会递增），
状态可在插件管理页看到，也可以手动重启。

> ⚠️ 唯一的例外：插件前端与宿主页面在**同一个浏览器标签**里。如果插件前端
> 写的死循环阻塞了主线程，页面会卡住。所以**前端不要写同步死循环**。

### 权限声明错了会怎样？

分三种情况：

**① 拼写错误（未知域）** → **注册阶段就失败**，插件加载不进来。

```
权限声明 "sytem.read" 的域 "sytem" 未知（可用域：file|http|network|process|service|system）
```

这是故意的：静默接受拼写错误会掩盖真实问题，让你以为申请了权限其实没有。

**② 重复声明同一「域.动作」** → 注册阶段失败。

```
权限 "system.read" 与已声明的 "system.read:/proc" 重复（同一「域.动作」只能声明一次）
```

**③ 声明合法但不足** → 插件能加载，但**调用时被 403 拒绝**。

请求**根本到不了你的插件进程**——核心在转发前就拦掉了。响应形如
（位置：`internal/plugin/proxy.go` 的 `writePermissionDenied`）：

```json
{
  "error": "插件权限不足：插件未声明 system.read 权限",
  "code": "plugin_permission_denied",
  "plugin": "hello",
  "required": "system.read",
  "granted": ["process.read"],
  "hint": "...",
  "scope": "该限制作用于核心的转发通道，不是内核级沙箱；它无法阻止插件进程直接访问系统资源。"
}
```

响应头里还带 `X-Lipanel-Permission-Denied: <所需权限>`，
便于脚本与前端**程序化识别**权限拒绝，不必解析文案。

排查方法：看插件管理页的权限列表，或直接问核心要规则：

```
GET /api/plugins/<id>/permissions
```

### 怎么调试插件？

**后端（Go）**

1. 插件日志与核心**共用 stdout/stderr**，且带 `plugin=<id>` 前缀：
   ```
   time=... level=INFO msg=插件进程启动中 plugin=hello
   ```
2. `GET /api/plugins/<id>/whoami` 确认「这个 socket 后面到底跑的是谁」，
   它还会返回插件收到的请求头（可用于确认核心是否正确剥离了 Cookie）。
3. `GET /api/plugins/<id>/healthz` 探测存活。
4. 审计页（`/plugins/audit`）能看到每次调用及其权限判定结果，
   **这是排查「为什么被 403」最快的方式**。
5. 想看真实请求：`curl -b cookie.txt http://127.0.0.1:8080/api/plugins/<id>/<你的路径>`

**前端（JS）**

1. 浏览器 DevTools 里，插件的 console 输出在 **iframe 的上下文**中——
   在 Console 面板左上角的执行上下文下拉里选 `plugin-frame.html` 那个。
2. iframe 加载失败/引导失败时，宿主会显示明确错误，
   包括原始异常信息，而不是白屏。
3. 握手超时（iframe 加载了但脚本没跑起来）宿主会提示并给「重试」按钮。
4. `window.__LIPANEL__` 可在 iframe 上下文里直接查看：

   ```js
   // 在 iframe 上下文中执行
   window.__LIPANEL__.protocol   // 1
   window.__LIPANEL__.frame      // true
   ```

**常见症状速查**

| 症状 | 最可能的原因 |
|---|---|
| 菜单里看不到插件 | `Frontend.NavTitle` 为空，或 `Entry` 为空 |
| 页面白屏 | `plugin.js` 没有 `export default { component }` |
| 接口 403 | 权限没声明够（自定义路径需要 `system.read`） |
| 接口 503 | 插件没启动 → `POST /api/plugins/<id>/start` |
| 前端 import 失败 | 用了 `@` 别名 / `.vue` / naive-ui |
| `storage` 抛异常 | opaque origin 下不可用，改用插件后端的接口存数据 |

---

## 五、当前能力边界

### 5.1 现在能做的

| 能力 | 说明 |
|---|---|
| ✅ 提供前端页面 | `plugin.js` 导出组件，宿主自动挂载到 `/plugins/<id>` |
| ✅ 声明权限 | `Descriptor.Permissions`，注册阶段校验 |
| ✅ 注册后端路由 | 标准库 `*http.ServeMux`，四种 HTTP 方法都可用 |
| ✅ 读写自己的数据 | 插件进程内的内存状态；或自己在磁盘上建目录 |
| ✅ 读系统信息 | 直接读 `/proc` 等（sysinfo 插件就是这么做的） |
| ✅ 通过宿主代发请求 | `window.__LIPANEL__.api.*` |
| ✅ 崩溃自动恢复 | 独立进程 + 自动重启 + 超时保护 |
| ✅ 完整审计 | 每次调用都有记录（`/plugins/audit`） |

### 5.2 现在不能做的

| 不能做 | 说明 |
|---|---|
| ❌ **通过 Host 接口执行命令** | 没有 Host 接口。**但插件作为独立进程，可以自己 `os/exec`**（见 [1.4](#14-插件能调用的系统能力)） |
| ❌ **通过 Host 接口读写系统文件** | 同上，没有 Host 接口，但进程本身能直接读写 |
| ❌ 访问宿主 Cookie / 会话凭据 | iframe 是 opaque origin，凭据始终留在宿主侧 |
| ❌ 访问核心内部状态 | 独立进程，无共享内存 |
| ❌ 在沙箱里用 localStorage | opaque origin 抛异常 |
| ❌ 直接 `fetch('/api/*')` | 不可靠，必须走 `api.*` 桥接 |
| ❌ 使用 naive-ui / `.vue` / `@` 别名 | 前端不经打包 |
| ❌ 资源级细粒度权限 | `file.read:/etc/nginx` 与 `file.read` 校验时等价 |
| ❌ 让核心代为执行敏感操作 | 无 Host 接口 |
| ❌ 内核级沙箱 | 权限声明约束的是**转发通道**，不是进程行为 |

### 5.3 外部插件机制完成后才能做的

以下能力**当前完全不存在**，需要等「外部插件」机制实现。**现在写代码时不要依赖它们**：

| 将来的能力 | 现状 |
|---|---|
| `-plugin-dir` 扫描目录自动加载 | ❌ 无此参数 |
| `manifest.json` / `descriptor.json` | ❌ 不存在。元数据目前只能是 Go 代码 |
| 上传 zip 包安装（`POST /api/plugins/install`） | ❌ 无此接口 |
| 不重新编译面板就生效 | ❌ 必须重新 `./build.sh` |
| 独立二进制后端（`backend.exec`） | ❌ 无此字段 |
| 前端-only 插件（无 Go 后端） | ❌ 当前每个插件都必须有 Go 后端 |
| 跨插件调用 | ❌ 无通道 |
| 插件市场 / 从 URL 安装 | ❌ 未实现 |
| 插件签名校验 | ❌ 未实现 |

> 换句话说：**当前写一个插件，必须改三个地方**
> （`plugin.go`、`plugin_main.go` 的 import、可选的 `plugin.js`），
> **并重新编译面板**。外部插件机制的目标就是去掉这个约束。

---

## 附：相关源码位置

| 内容 | 文件 |
|---|---|
| `Handler` / `AssetProvider` / 骨架路由 | `internal/plugin/serve.go` |
| `Descriptor` / `Frontend` / ID 校验 | `internal/plugin/plugin.go` |
| 权限解析与规则表 | `internal/plugin/permission.go` |
| 插件注册与生命周期 | `internal/plugin/manager.go` |
| 进程拉起与回收 | `internal/plugin/process.go` |
| 内置插件登记 | `internal/plugin/registry.go` |
| 请求转发与凭据剥离 | `internal/plugin/proxy.go` |
| 参考实现 | `internal/plugin/builtin/sysinfo/plugin.go` |
| 插件的 HTTP 入口 | `internal/server/plugin_api.go` |
| iframe 引导与桥接 | `web/plugins/plugin-assets/frame/plugin-frame.js` |
| iframe 内 Vue 注入 | `web/plugins/plugin-assets/frame/plugin-runtime.js` |
| 宿主侧动态加载 | `web/src/plugins/loader.js` |
| 宿主侧通信桥 | `web/src/plugins/bridge.js` |
| iframe 组件 | `web/src/components/PluginFrame.vue` |
| 前端编写指南 | `web/plugins/plugin-assets/README.md` |
