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

# ---------- 2. 同步插件自带前端 ----------
#
# 每个内置插件的前端有两份来源：
#   源    web/plugins/plugin-assets/<id>/plugin.js          （入库，原样分发）
#   → Vite publicDir 原样拷贝到 web/dist/plugin-assets/<id>/plugin.js
#   → 再同步到 internal/plugin/builtin/<id>/frontend/plugin.js（go:embed 源，不入库）
#
# 两份内容必须一致：前者是插件进程经 GET /assets 提供的版本，后者是编译进
# 二进制、随核心分发的版本。若不同步，就会出现「dev 下正常、单二进制里是
# 旧版」这种最难排查的偏差。
#
# 为什么 go:embed 不能直接指向 web/dist/plugin-assets：
#   go:embed 不能跨目录（不能用 ../），而这些代码位于 internal/ 下。
# 因此用本步骤做一次显式拷贝；缺失时直接失败，而不是产出「没有前端」的二进制。
log "同步插件自带前端 (plugin-assets → internal/.../frontend)"
synced=0
for src in web/plugins/plugin-assets/*/; do
  [ -d "${src}" ] || continue
  id="$(basename "${src}")"
  [ -f "${src}plugin.js" ] || continue
  dest="internal/plugin/builtin/${id}/frontend"
  [ -d "${dest}" ] || die "插件 ${id} 有前端源码 (${src}plugin.js)，但 ${dest} 目录不存在"
  mkdir -p "${dest}"
  cp -f "${src}plugin.js" "${dest}/plugin.js"
  synced=$((synced + 1))
done
[ "${synced}" -gt 0 ] || die "未同步到任何插件前端（web/plugins/plugin-assets/*/plugin.js 不存在？）"
log "已同步 ${synced} 个插件前端"

# ---------- 3. 后端静态编译 ----------
log "编译后端 (CGO_ENABLED=0, version=${VERSION})"
mkdir -p "${OUT_DIR}"
CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${OUT_BIN}" \
  . || die "后端编译失败"

# ---------- 4. 校验产物 ----------
log "构建完成: ${OUT_BIN} ($(du -h "${OUT_BIN}" | cut -f1))"
if command -v file >/dev/null 2>&1; then
  file "${OUT_BIN}"
fi
echo
log "运行: ./${OUT_BIN} -addr 127.0.0.1:8080"
