# lipanel

轻量 Linux 面板。技术栈：Go + Vue3 + Vite + Naive UI。

## 架构约束

- **单二进制**：前端 `web/dist` 通过 `go:embed` 打包进 Go 二进制，运行时不需要任何外部文件。
- **纯静态编译**：`CGO_ENABLED=0`。
- **轻量**：后端仅用标准库 `net/http`，不引入 Web 框架；前端 Naive UI 按需引入，不引入重型全局 CSS。

## 目录结构

```
cmd/lipanel/     程序入口（main）
internal/server/ HTTP 服务与路由
web/             Vue3 + Vite 前端工程（构建产物 web/dist 被 embed）
dist/            单二进制输出目录（git 忽略）
```

## 开发

```bash
# 后端：前端未构建时也能编译，但页面只返回占位提示
go run ./cmd/lipanel -addr 127.0.0.1:8080

# 前端联调（Vite dev server 代理 /api 到后端）
cd web && pnpm install && pnpm dev
```

## 构建单二进制

```bash
./build.sh
./dist/lipanel -addr 127.0.0.1:8080
```

## 第一阶段进度

- [x] 小目标 1：仓库与目录骨架
- [ ] 小目标 2：Go 后端 HTTP 骨架 + `/api/health`
- [ ] 小目标 3：Vue3 + Vite + Naive UI 前端骨架
- [ ] 小目标 4：前端 embed 进 Go，打包单二进制
