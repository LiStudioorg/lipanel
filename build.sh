#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ---------- 参数（本地和 CI 都能通过环境变量传入） ----------
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"   # CI 里设为 1 可跳过前端编译
OUT_DIR="${OUT_DIR:-dist}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 1. 前端构建（可跳过） ----------
if [ "$SKIP_FRONTEND" != "1" ]; then
  command -v node >/dev/null 2>&1 || die "未找到 node，请先安装 Node.js"
  log "构建前端 (web)"
  cd web
  [ -d node_modules ] || npm install --no-audit --no-fund
  npm run build || die "前端构建失败"
  cd ..
fi

[ -f web/dist/index.html ] || die "web/dist/index.html 不存在，请先构建前端"

# ---------- 2. 同步插件前端产物到 go:embed 目录 ----------
if [ -d "web/plugins/plugin-assets/sysinfo" ]; then
  mkdir -p internal/plugin/builtin/sysinfo/frontend
  cp -r web/plugins/plugin-assets/sysinfo/* internal/plugin/builtin/sysinfo/frontend/ 2>/dev/null || true
fi

# ---------- 3. 编译 Go 二进制 ----------
EXT=""
if [ "$GOOS" = "windows" ]; then EXT=".exe"; fi
OUT_NAME="lipanel_${VERSION}_${GOOS}_${GOARCH}${EXT}"

log "编译后端 (GOOS=${GOOS}, GOARCH=${GOARCH}, VERSION=${VERSION})"
mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${OUT_DIR}/${OUT_NAME}" \
  . || die "后端编译失败"

# ---------- 4. 打包 tar.gz（可选） ----------
if [ "${PACK_TARBALL:-1}" = "1" ]; then
  log "打包 tar.gz"
  tar -czvf "${OUT_DIR}/lipanel_${VERSION}_${GOOS}_${GOARCH}.tar.gz" -C "${OUT_DIR}" "${OUT_NAME}"
fi

log "构建完成！产物在 ${OUT_DIR}/"
