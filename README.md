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
cmd/lipanel/      程序入口（main）、启动参数校验、优雅关闭、插件子命令入口
internal/server/  HTTP 服务、路由、中间件、静态资源处理、插件路由与转发
internal/auth/    密码哈希（bcrypt）、JWT 签发校验、鉴权中间件
internal/sysinfo/ 系统信息采集（/proc、statfs、/etc/os-release）
internal/plugin/  插件系统：类型定义、进程管理、Unix socket 反向代理、内置注册表
  builtin/        内置插件实现（当前：sysinfo）
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
| `-config` | 空 | 配置文件路径（JSON）。**指定后首次启动会自动生成凭据并落盘**；留空则为纯内存模式（不落盘） |
| `-addr` | `127.0.0.1:8080` | HTTP 监听地址（覆盖配置文件） |
| `-static-dir` | 空 | 指定磁盘静态目录，留空则用内置 embed 资源 |
| `-log-level` | `info` | `debug\|info\|warn\|error`（覆盖配置文件） |
| `-admin-user` | `admin` | 管理员用户名（覆盖配置文件） |
| `-admin-password` | 空 | 管理员明文密码（≥ 6 位），启动时立即转为 bcrypt 哈希 |
| `-admin-password-hash` | 空 | 直接提供 bcrypt 哈希（**推荐**，避免明文出现在 `ps` 中） |
| `-jwt-secret` | 空 | JWT 签名密钥（≥ 16 字节）；留空则读取配置文件或自动生成 |
| `-token-ttl` | `2h` | 会话有效期，如 `30m`、`12h`（覆盖配置文件） |
| `-secure-cookie` | `false` | 仅通过 HTTPS 传输会话 Cookie（反代启用 TLS 时开启） |
| `-plugin-socket-dir` | `<临时目录>/lipanel-plugins` | 插件 Unix socket 存放目录（自动创建并设为 `0700`） |
| `-gen-secret` | - | 生成一个随机密钥后退出，便于写入配置 |
| `-gen-password-hash` | - | 把给定明文密码转成 bcrypt 哈希后退出，便于写入配置 |
| `-version` | - | 打印版本号后退出 |

**优先级：CLI 参数 > 配置文件 > 内置默认值。**

> ⚠️ 未指定 `-config` 且未传密码时，使用开发默认口令 `admin` / `admin123` 并打印 WARN。
> **生产环境请用 `-config`（推荐）或 `-admin-password-hash` 指定。**

## 配置文件与持久化

### 最简用法（推荐）

```bash
# 首次启动：自动生成 20 位随机密码与 JWT 密钥，写入配置文件
./dist/lipanel -config /var/lib/lipanel/config.json

# 日志会打印一次生成的密码，请立即抄录：
#   level=WARN msg=已自动生成管理员密码，请立即抄录保存（此密码不会再显示） password=NexXHQfuDitHkcn4YN5Q

# 之后每次启动只需一个参数，凭据自动读取，无需重复传参
./dist/lipanel -config /var/lib/lipanel/config.json
```

生成的 `config.json`（权限 `0600`，目录 `0700`）：

```json
{
  "version": 1,
  "addr": "127.0.0.1:8080",
  "log_level": "info",
  "secure_cookie": false,
  "auth": {
    "username": "admin",
    "password_hash": "$2a$10$f0fpkiQ2d2I0bwSfMM3hoOwkJ19.kCJqRvvl9EZ.cJwaZj8vxdxIS",
    "jwt_secret": "G7zZ2jZEPhfFULmlZlyPGjOZJpByR_cObAhFvRAD4_M",
    "token_ttl": "2h"
  }
}
```

### 设计要点

| 项 | 说明 |
| --- | --- |
| 格式 | **JSON**，用标准库 `encoding/json`，不引入 YAML 库，**依赖总数仍为 2** |
| 密码存储 | 只存 bcrypt 哈希，**文件中绝不出现明文**；明文仅在首次启动打印一次 |
| 权限 | 文件 `0600` / 目录 `0700`；发现已有文件权限过宽时告警但不阻断启动 |
| 写入安全 | 临时文件 + `fsync` + `rename` 原子替换，断电不会留下半个 JSON |
| 损坏保护 | 配置非法时**拒绝启动且不覆盖原文件**，避免用户配置被静默清空 |
| 幂等性 | 用相同参数重复启动不会重写文件（bcrypt 带随机 salt，需先比对再决定） |

### 手工配置

```bash
# 生成哈希与密钥，然后手工填入 config.json
./dist/lipanel -gen-password-hash 'my-password'
./dist/lipanel -gen-secret

# 或临时覆盖配置文件里的值（会被写回文件）
./dist/lipanel -config /var/lib/lipanel/config.json -addr 0.0.0.0:8080 -secure-cookie

# 完整生产启动示例
./dist/lipanel -config /etc/lipanel/config.json -secure-cookie
```

> **忘记密码怎么办**：配置里只有哈希，无法反推。直接指定新密码即可覆盖：
> `./dist/lipanel -config <路径> -admin-password '新密码'`（会写回文件）。

## 构建单二进制

```bash
./build.sh              # 产物：dist/lipanel（约 7.4 MB）
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
| GET | `/api/plugins` | 需登录 | 插件列表（含实时状态与前端插槽元数据） |
| GET | `/api/plugins/{id}` | 需登录 | 单个插件状态 |
| POST | `/api/plugins/{id}/start` | 需登录 | 启动插件（拉起进程并等 socket 就绪） |
| POST | `/api/plugins/{id}/stop` | 需登录 | 停止插件（SIGTERM → 超时 SIGKILL） |
| POST | `/api/plugins/{id}/restart` | 需登录 | 重启插件 |
| POST | `/api/plugins/{id}/health` | 需登录 | 主动健康探测 |
| ANY | `/api/plugins/{id}/*` | 需登录 | **转发给插件进程处理**（核心只做代理） |

未登录访问受保护接口统一返回 `401 {"error":"未登录或登录已过期，请重新登录"}`；
未注册的 `/api/*` 统一返回 JSON `404`（不会误返回前端 HTML）；
未命中的非 `/api` 路径回退到 `index.html`，交给前端路由。

### 插件系统

**通讯协议：Unix domain socket 上的 HTTP/1.1**（不使用 gRPC）。

- **插件形态是「单二进制 + 子命令」**：核心以自身可执行文件重新 exec，
  参数为 `__plugin_<id>`，该进程即进入插件模式。
  因此 `dist/lipanel` **一个文件**同时提供面板、前端与全部内置插件。
- **socket 权限**：文件 `0600`、目录 `0700`。Unix socket 的权限即访问控制，
  同机其他用户无法绕过面板鉴权直连插件。
- **两种运行模式**：`managed`（核心 fork/exec 托管，默认）与
  `external`（核心只拨号，进程由 systemd 或手工启动）。
- **转发时剥离 `Cookie` 与 `Authorization`**：插件拿不到面板会话凭据，
  即使插件被攻陷也无法冒充已登录用户。

```bash
# 列出插件 / 启动 / 调用插件自己的接口
curl -b cookie.txt http://127.0.0.1:8080/api/plugins
curl -b cookie.txt -X POST http://127.0.0.1:8080/api/plugins/sysinfo/start
curl -b cookie.txt http://127.0.0.1:8080/api/plugins/sysinfo/info
```

**新增插件的步骤**（当前仅支持内置插件）：

1. 新建 `internal/plugin/builtin/<id>/plugin.go`，实现 `plugin.Handler`
   （`Descriptor()` + `Routes(mux)`），并在 `init` 中调用 `plugin.RegisterBuiltin`。
2. 在 `cmd/lipanel/plugin_main.go` 的 import 块加一行匿名导入。
3. 如需前端界面，在 `web/src/plugins/registry.js` 里按 `frontend.entry` 登记组件。

> 前两步在**插件进程**侧生效（后端能力），第三步在**核心**侧生效（界面挂载）。
> 路由 `/plugins/:id` 与菜单渲染无需改动——这是「插件前端挂载插槽」的设计目的。

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

### 第二阶段：登录鉴权 + 系统信息面板 ✅

- [x] 2.1 登录接口（bcrypt + JWT HttpOnly Cookie）
- [x] 2.2 鉴权中间件 + 前端 401 拦截跳登录页
- [x] 2.3 前端登录页（Naive UI 表单校验 / Loading / 错误提示）
- [x] 2.4 系统信息接口（`/api/system/info`）
- [x] 2.5 前端系统信息面板（卡片 + 进度条 + Loading/Error 兜底）
- [x] 2.6 配置与持久化（`-config` + 凭据自动生成落盘）

### 第三阶段：插件系统 🔄

- [x] 3.1 插件系统骨架（Unix socket 通讯 + 进程管理 + 路由转发 + 内置 `sysinfo` 插件 + 前端挂载插槽）
- [x] 3.2 插件前端动态挂载（插件自带 ESM 入口 + importmap 共享宿主 Vue + `GET /assets/*`）
- [ ] 3.3 插件权限与审计

详细进度与已知坑位见 [`开发计划.md`](./开发计划.md)。

---

## 许可证

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）**，全文见 [`LICENSE`](./LICENSE)。

选择 AGPL-3.0 的原因：lipanel 是**通过网络提供服务**的面板软件（浏览器访问 `/api/*`）。
AGPL 第 13 条要求「通过网络交互使用的用户」也能获得对应源码，
这正好覆盖「把面板部署成在线服务」的场景——GPL 在这种场景下留有空档。

对你的实际影响：

| 场景 | 需要做什么 |
| --- | --- |
| 自己部署、自用 | 无额外义务，随便改 |
| 修改后分发给他人 | 必须按 AGPL 提供完整源码（含你的修改） |
| 修改后作为网络服务提供给他人使用 | 同上，且须向使用者提供获取源码的途径 |
| 仅原样部署、不作修改 | 无需公开任何东西（保留版权与许可声明即可） |

内置插件与插件前端属于主程序的一部分，随本项目一同以 AGPL-3.0 授权。
若你编写**独立**插件并以进程方式接入，其授权由你自行决定
（插件经 Unix socket 上的 HTTP 与本项目通讯，属于独立程序）。

**注意**：以上为摘要，不构成法律意见；实际以 [`LICENSE`](./LICENSE) 全文为准。
