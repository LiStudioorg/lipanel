#!/usr/bin/env bash
#
# 构建 lipanel 单二进制。
#
# 流程：前端 Vite 构建 → 产物写入 web/dist → go:embed 打包 → 静态编译。
# 产物：dist/lipanel（无任何运行时依赖，可直接 scp 到服务器执行）。
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/lipanel"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 1. 前端构建 ----------
command -v node >/dev/null 2>&1 || die "未找到 node，请先安装 Node.js"

log "构建前端 (web)"
cd web
if [ ! -d node_modules ]; then
  log "首次运行，安装前端依赖"
  npm install --no-audit --no-fund
fi
npm run build || die "前端构建失败"
cd ..

[ -f web/dist/index.html ] || die "web/dist/index.html 不存在，前端构建未产出预期文件"

# ---------- 2. 后端静态编译 ----------
log "编译后端 (CGO_ENABLED=0, version=${VERSION})"
mkdir -p "${OUT_DIR}"
CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${OUT_BIN}" \
  ./cmd/lipanel || die "后端编译失败"

# ---------- 3. 校验产物 ----------
log "构建完成: ${OUT_BIN} ($(du -h "${OUT_BIN}" | cut -f1))"
if command -v file >/dev/null 2>&1; then
  file "${OUT_BIN}"
fi
echo
log "运行: ./${OUT_BIN} -addr 127.0.0.1:8080"
