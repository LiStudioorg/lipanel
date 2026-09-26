# 插件前端（阶段三 3.2）

本目录是**插件前端源码目录**，在构建时被 Vite 原样拷贝到
`web/dist/plugin-assets/`，再经 `go:embed` 打进单二进制。

```
web/plugins/plugin-assets/<插件ID>/plugin.js          ← 本目录（插件前端源码，原样分发）
internal/plugin/builtin/<插件ID>/        ← 插件后端（Go，编译进主程序）
```

两侧目录同名同构，一个插件因此是一个自包含的单元。

## 一、加载链路

```
internal/plugin/builtin/x/plugin.go
        Descriptor().Frontend = { Entry: "/plugin-assets/x/plugin.js",
                                  Assets: "/plugin-assets/x/",
                                  NavTitle: "…", NavIcon: "…" }
                │
                │  GET /api/plugins（核心返回元数据）
                ▼
web/src/plugins/loader.js
        applyPlugins() 登记入口 → resolvePluginView(id) → import(entry)
                │
                ▼
        { meta, component }  →  <component :is="component" :plugin-id="id" />
```

主程序里**没有任何一行代码提到具体插件的前端**：新增插件只改插件自己的
两个目录，`AppLayout.vue` / `router/index.js` / `registry.js` 都不用动。

## 二、入口规范

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `frontend.entry` | 前端入口地址（ESM 模块） | `/plugin-assets/x/plugin.js` |
| `frontend.assets` | 资源基址：相对入口的解析基准，也是加载失败时的兜底目录 | `/plugin-assets/x/` |
| `frontend.type` | 入口类型，缺省 `esm` | `esm` |
| `frontend.nav_title` | 菜单标题；为空则不进菜单 | `系统信息（插件）` |
| `frontend.nav_icon` | 菜单图标标识（前端映射，见 `resolveNavIcon`） | `dashboard` |

`entry` 的三种形态与解析规则：

| 形态 | 解析方式 | 说明 |
| --- | --- | --- |
| `plugin.js` | 相对 `assets` 基址 | 短写法 |
| `/plugin-assets/x/plugin.js` | 站点绝对路径 | **推荐**，内置插件用这个 |
| `https://…` | 原样 | 默认被禁用（安全策略，见 `loader.js` 的 `setAllowRemote`） |

**兜底优先级**：`entry` 声明的地址加载失败 → 尝试 `<assets>/plugin.js` →
仍失败则宿主页显示可读的失败原因与重试按钮（不会白屏）。
若 `entry` 为空，则直接判定为「该插件未提供前端界面」。

## 三、模块契约

```js
import { h } from 'vue'

export default {
  meta: { id: 'x', title: '示例', version: '0.1.0' },  // 可选，仅供排查
  component: {                                          // 必需：Vue 组件
    props: { pluginId: String, plugin: Object },        // 宿主注入的两个 prop
    setup(props) { /* … */ },
  },
}
```

宿主注入的 prop：

- `pluginId`：插件 ID（路由参数）；
- `plugin`：后端返回的该插件元数据（含 `state`、`frontend` 等）。

## 四、可以依赖什么

| 允许 | 说明 |
| --- | --- |
| `import { ref, h, computed, onMounted } from 'vue'` | 由 `index.html` 的 importmap 指向宿主**同一份** Vue 实例 |
| `fetch('/api/plugins/<id>/*')` | 核心会转发给插件进程（自动带会话 Cookie） |

| 不允许 | 原因 |
| --- | --- |
| `naive-ui` 组件 | 需要 `<n-config-provider>` 上下文，插件以非 `.vue` 源码原样加载，拿不到该上下文；且组件按需引入、未全局注册 |
| `.vue` 单文件、`@/` 别名 | 本目录不经过 Vite 打包，没有编译期处理 |
| `@/api/*`、`@/utils/*` 等宿主内部模块 | 插件一旦依赖宿主内部实现，宿主重构就会让插件集体损坏 |

界面请用 `h()` 手写 DOM（参考 `sysinfo/plugin.js`），只用继承色
（`color: inherit` / `opacity`）与半透明分隔线，以适配宿主明暗主题。

## 五、写一个新插件前端的步骤

1. 建目录 `web/plugins/plugin-assets/<id>/plugin.js`，按上面的契约导出组件；
2. 在插件后端 `Descriptor().Frontend` 里声明 `Entry` / `Assets` / `NavTitle` / `NavIcon`；
3. 重新构建（`npm run build` 或 `./build.sh`）——`plugin-assets/` 会被一起打包。

## 六、已知限制

- **旧浏览器不支持**：Blob 降级路径依赖 import maps（Firefox 108+ / Safari 16.4+）。
  更旧的浏览器会加载失败并给出明确提示，而不是白屏。
- **不是安全沙箱**：插件代码与宿主共享同一个 Realm，能访问 `document.cookie`
  与会话接口。因此**不要让不信任的插件前端跑在面板页面里**；
  强隔离（sandbox iframe + postMessage 桥）留待后续阶段。
- 插件前端暂不支持样式表与静态资源（图片等）；需要时再扩展 `assets` 基址的用法。
