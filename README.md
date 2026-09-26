# lipanel

轻量 Linux 面板。技术栈：Go + Vue3 + Vite + Naive UI。

## 架构约束

- **单二进制**：前端 `web/dist` 通过 `go:embed` 打包进 Go 二进制。运行时不需要任何外部文件。
- **纯静态编译**：`CGO_ENABLED=0`，产物为 statically linked，无动态依赖。
- **轻量**：后端仅用标准库 `net/http`（无 Web 框架、零第三方依赖）；前端 Naive UI 按需引入，构建产物不含任何 CSS 文件。

## 目录结构

```
cmd/lipanel/      程序入口（main）
internal/server/  HTTP 服务、路由、中间件、静态资源处理
web/              Vue3 + Vite 前端工程
webui.go          模块根包，承载 go:embed（见下方说明）
build.sh          一条命令完成「前端构建 → embed → 静态编译」
dist/             单二进制输出目录（git 忽略）
```

### ⚠️ 为什么 `go:embed` 放在模块根目录的 `webui.go`

`go:embed` 的路径是**相对声明该指令的包所在目录**解析的，且**不允许用 `../` 跨出包目录**。

因此 embed 指令不能写在 `internal/server/`（它会去找 `internal/server/web/dist`，不存在）。
必须放在模块根目录这一层的包里，再由 `internal/server` 通过 `import "lipanel"` 使用。

> 若后续把 `web/dist` 改到别处，请同步检查 `webui.go` 的相对路径。

## 开发

```bash
# 方式一：后端单独跑（前端未构建时，访问 / 会返回 503 并提示构建）
go run ./cmd/lipanel -addr 127.0.0.1:8080

# 方式二：前后端联调（Vite dev server 自动把 /api 代理到 8080）
cd web && npm install && npm run dev
```

可选参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | HTTP 监听地址 |
| `-static-dir` | 空 | 指定磁盘静态目录，留空则用内置 embed 资源 |
| `-log-level` | `info` | `debug\|info\|warn\|error` |
| `-version` | - | 打印版本号后退出 |

## 构建单二进制

```bash
./build.sh              # 产物：dist/lipanel（约 6.9 MB）
./dist/lipanel -addr 127.0.0.1:8080
```

## 已有接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 返回 `{status, version, time}`，供前端首屏探活 |

未注册的 `/api/*` 统一返回 JSON `404`（不会误返回前端 HTML）；
未命中的非 `/api` 路径回退到 `index.html`，交给前端路由。

## 第一阶段进度

- [x] 小目标 1：仓库与目录骨架
- [x] 小目标 2：Go 后端 HTTP 骨架 + `/api/health`
- [x] 小目标 3：Vue3 + Vite + Naive UI 前端骨架
- [x] 小目标 4：前端 embed 进 Go，打包单二进制
