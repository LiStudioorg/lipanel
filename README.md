# lipanel

轻量 Linux 面板。技术栈：Go + Vue3 + Vite + Naive UI。

## 架构约束

- **单二进制**：前端 `web/dist` 通过 `go:embed` 打包进 Go 二进制。运行时不需要任何外部文件。
- **纯静态编译**：`CGO_ENABLED=0`，产物为 statically linked，无动态依赖。
- **轻量**：后端仅用标准库 `net/http`（无 Web 框架）；第三方依赖只有两个纯 Go 库
  （`golang.org/x/crypto` 提供 bcrypt、`github.com/golang-jwt/jwt/v5` 提供 JWT），
  均不引入 CGO，静态编译不受影响。前端 Naive UI 按需引入。
- **系统信息只读 `/proc`**：不调用 `uname`/`df`/`lsblk` 等外部命令，避免依赖发行版差异，
  也缩小以 root 运行时的攻击面。

## 目录结构

```
cmd/lipanel/      程序入口（main）、启动参数校验、优雅关闭
internal/server/  HTTP 服务、路由、中间件、静态资源处理
internal/auth/    密码哈希（bcrypt）、JWT 签发校验、鉴权中间件
internal/sysinfo/ 系统信息采集（/proc、statfs、/etc/os-release）
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
| `-admin-user` | `admin` | 管理员用户名 |
| `-admin-password` | 空 | 管理员明文密码（≥ 6 位），启动时立即转为 bcrypt 哈希 |
| `-admin-password-hash` | 空 | 直接提供 bcrypt 哈希（**推荐**，避免明文出现在 `ps` 中） |
| `-jwt-secret` | 空 | JWT 签名密钥（≥ 16 字节）；留空则每次启动随机生成，**重启后需重新登录** |
| `-token-ttl` | `2h` | 会话有效期，如 `30m`、`12h` |
| `-secure-cookie` | `false` | 仅通过 HTTPS 传输会话 Cookie（反代启用 TLS 时开启） |
| `-gen-secret` | - | 生成一个随机密钥后退出，便于写入配置文件 |
| `-version` | - | 打印版本号后退出 |

> ⚠️ 未指定密码时使用开发默认口令 `admin` / `admin123`，并在启动日志打印 WARN。
> **生产环境务必用 `-admin-password` 或 `-admin-password-hash` 指定。**

生成密码哈希与签名密钥：

```bash
# 生成 bcrypt 哈希（交互式输入，不回显）
go run ./cmd/lipanel -gen-secret          # 生成 JWT 签名密钥

# 生产启动示例
./dist/lipanel -addr 0.0.0.0:8080 \
  -admin-user admin \
  -admin-password-hash '$2a$10$....' \
  -jwt-secret "$(./dist/lipanel -gen-secret)" \
  -secure-cookie
```

## 构建单二进制

```bash
./build.sh              # 产物：dist/lipanel（约 6.9 MB）
./dist/lipanel -addr 127.0.0.1:8080
```

## 已有接口

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/health` | 公开 | 返回 `{status, version, time, token_ttl_seconds, has_fixed_secret}`，供探活 |
| POST | `/api/login` | 公开 | 入参 `{username, password}`；成功经 HttpOnly Cookie 下发 JWT |
| POST | `/api/logout` | 公开 | 清除会话 Cookie（未登录调用也返回 200） |
| GET | `/api/auth/me` | 需登录 | 返回 `{username, expires_at}`，供前端路由守卫恢复登录态 |
| GET | `/api/system/info` | 需登录 | 返回 CPU / 内存 / 磁盘 / 系统版本等基础信息 |

未登录访问受保护接口统一返回 `401 {"error":"未登录或登录已过期，请重新登录"}`；
未注册的 `/api/*` 统一返回 JSON `404`（不会误返回前端 HTML）；
未命中的非 `/api` 路径回退到 `index.html`，交给前端路由。

### 鉴权设计

- **会话载体是 HttpOnly Cookie**（`lipanel_token`，`SameSite=Lax`，可选 `Secure`）。
  前端 JS 读不到 token，即使页面被注入 XSS 也无法直接窃取会话；
  `SameSite=Lax` 用于收敛 CSRF 面。
- **JWT 用 HS256**，解析时显式限定算法，拒绝 `alg=none` 与算法混淆攻击。
- **路由鉴权按白名单显式挂载**（`s.auth.RequireAuth`），新增接口不会因白名单漏配而意外裸奔。
- **防账号枚举**：用户不存在与密码错误返回完全一致的响应；用户名比较走常量时间函数，
  且失败时也执行一次 bcrypt，抹平耗时差异。
- **防开放重定向**：`?redirect=` 参数经 `SanitizeNext` 清洗，只允许站内相对路径。
- 登录失败日志只记录用户名，**绝不记录密码**。

### `/api/system/info` 响应示例

```json
{
  "hostname": "srv-01",
  "os": "Ubuntu 22.04.5 LTS",
  "kernel": "5.15.0-179-generic",
  "arch": "x86_64",
  "uptime_seconds": 103533,
  "collected_at": "2026-09-26T15:11:24+08:00",
  "cpu": {
    "model": "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz",
    "cores": 4,
    "usage_percent": 6.48,
    "load_avg": [0.45, 0.45, 0.53]
  },
  "memory": {
    "total_bytes": 4101312512,
    "used_bytes": 1965039616,
    "free_bytes": 2136272896,
    "cached_bytes": 2350669824,
    "usage_percent": 47.83
  },
  "swap": { "total_bytes": 0, "used_bytes": 0, "usage_percent": 0 },
  "disk": {
    "path": "/",
    "total_bytes": 52653826048,
    "used_bytes": 29015445504,
    "free_bytes": 21175885824,
    "usage_percent": 57.83
  }
}
```

**指标口径说明**（避免误读）：

- `cpu.usage_percent`：`/proc/stat` 两次时间片快照的差值，`steal` 计入「忙」
  （虚拟机里才准）。服务启动即取基线，首次请求无需等待。
- `memory.used_bytes` = `MemTotal - MemAvailable`（与 `free(1)`、`htop` 一致）。
  若改用 `MemFree`，page cache 会让面板长期显示 90%+，属于误导。
  老内核（< 3.14）无 `MemAvailable` 时退化为 `Free + Cached + Buffers`。
- `disk.usage_percent` 分母为「已用 + 可用」，与 `df` 的 `Use%` 口径一致
  （root 保留块不计入分母）。
- 任一子项采集失败只记入 `warnings` 数组并降级该字段，接口仍返回 200，
  不会因为「磁盘读不到」导致整页空白。

## 进度

### 第一阶段：骨架 Demo ✅

- [x] 小目标 1：仓库与目录骨架
- [x] 小目标 2：Go 后端 HTTP 骨架 + `/api/health`
- [x] 小目标 3：Vue3 + Vite + Naive UI 前端骨架
- [x] 小目标 4：前端 embed 进 Go，打包单二进制

### 第二阶段：登录鉴权 + 系统信息面板 ⏳

- [x] 2.1 登录接口（bcrypt + JWT HttpOnly Cookie）
- [x] 2.2 鉴权中间件 + 前端 401 拦截跳登录页
- [x] 2.3 前端登录页（Naive UI 表单校验 / Loading / 错误提示）
- [x] 2.4 系统信息接口（`/api/system/info`）
- [x] 2.5 前端系统信息面板（卡片 + 进度条 + Loading/Error 兜底）

详细进度与已知坑位见 [`开发计划.md`](./开发计划.md)。
