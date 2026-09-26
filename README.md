# lipanel

轻量 Linux 面板。Go + Vue3 + Vite + Naive UI，前端 embed 进二进制，**单文件部署**。

- **单二进制**：`CGO_ENABLED=0` 静态编译，产物 `dist/lipanel` 一个文件同时提供面板、前端与内置插件。
- **轻量**：后端只用标准库 `net/http`；第三方依赖仅两个纯 Go 库（`golang.org/x/crypto` 的 bcrypt、`github.com/golang-jwt/jwt/v5` 的 JWT）。
- **插件系统**：插件是独立进程，经 Unix domain socket 上的 HTTP 与核心通讯。

## 快速开始

```bash
# 构建（前端构建 + 静态编译），产物在 dist/
./build.sh

# 首次启动：自动生成管理员密码与 JWT 密钥并写入配置文件（日志会打印一次密码）
./dist/lipanel -config /var/lib/lipanel/config.json

# 之后每次启动只需一个参数
./dist/lipanel -config /var/lib/lipanel/config.json
```

浏览器打开 `http://127.0.0.1:8080` 登录。未指定 `-config` 且未传密码时为纯内存模式，
使用开发默认口令 `admin` / `admin123` 并打印 WARN。

### 开发联调

```bash
# 后端（8080）
go run . -addr 127.0.0.1:8080

# 前端（5173，/api 自动代理到 8080）
cd web && npm install && npm run dev
```

### 常用启动参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-config` | 空 | 配置文件路径（JSON）。指定后首次启动自动生成凭据并落盘；留空为纯内存模式 |
| `-addr` | `127.0.0.1:8080` | HTTP 监听地址 |
| `-static-dir` | 空 | 使用磁盘静态目录，留空则用内置 embed 资源 |
| `-log-level` | `info` | `debug\|info\|warn\|error` |
| `-admin-user` | `admin` | 管理员用户名 |
| `-admin-password` | 空 | 管理员明文密码（≥ 6 位） |
| `-admin-password-hash` | 空 | 直接提供 bcrypt 哈希（推荐，避免明文出现在 `ps` 中） |
| `-jwt-secret` | 空 | JWT 签名密钥（≥ 16 字节） |
| `-token-ttl` | `2h` | 会话有效期 |
| `-secure-cookie` | `false` | 仅通过 HTTPS 传输会话 Cookie |
| `-plugin-socket-dir` | `<临时目录>/lipanel-plugins` | 插件 Unix socket 目录（自动创建并设为 `0700`） |
| `-gen-secret` / `-gen-password-hash` | - | 生成密钥 / 密码哈希后退出，便于手工写入配置 |
| `-version` | - | 打印版本号后退出 |

优先级：**CLI 参数 > 配置文件 > 内置默认值**。

## 构建说明

```bash
./build.sh
```

脚本做三件事：

1. 前端构建（`web/` → `web/dist/`）；
2. 同步插件前端源码到各自的 `go:embed` 目录；
3. `CGO_ENABLED=0` 静态编译，产物输出到 **`dist/`**。

可用环境变量：`VERSION`、`GOOS`、`GOARCH`、`OUT_DIR`（默认 `dist`）、`SKIP_FRONTEND`、`PACK_TARBALL`。

## 核心目录结构

```
main.go                 程序入口 + go:embed 前端资源 + 启动参数 + 优雅关闭
plugin_main.go          内置插件的匿名导入清单
internal/server/        HTTP 服务、路由、鉴权中间件、静态资源、插件接口与转发
internal/auth/          密码哈希（bcrypt）、JWT 签发校验、鉴权中间件
internal/sysinfo/       系统信息采集（/proc、statfs、/etc/os-release）
internal/plugin/        插件系统：类型定义、进程管理、Unix socket 代理、内置注册表
  builtin/<id>/         内置插件后端（当前：sysinfo）
web/                    Vue3 + Vite 前端工程
  src/plugins/          插件前端加载器与宿主桥
  plugins/plugin-assets/<id>/plugin.js   插件自带前端（原样分发，随构建进二进制）
build.sh                构建脚本：前端构建 → embed → 静态编译，产物进 dist/
dist/                   单二进制输出目录（git 忽略）
```

> `main.go` 必须在仓库根目录：`go:embed` 的路径相对声明它的包目录解析且不能用 `../`，
> 要 embed 的 `web/dist` 决定了承载 embed 的包只能待在根目录。

## 许可证

[AGPL-3.0](./LICENSE)。面板是网络服务，AGPL 第 13 条覆盖「部署成在线服务」的场景。
