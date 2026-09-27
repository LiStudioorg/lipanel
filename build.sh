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

# ---------- 1.5 产物健全性校验（P0 白屏防线） ----------
#
# web/dist 被 .gitignore 排除（web/dist/*），因此它**完全不属于源码**，
# 而是上一次构建留下的产物。这意味着两种翻车方式：
#
#   a) SKIP_FRONTEND=1 复用了一个陈旧的 web/dist；
#   b) 前端构建步骤被跳过/失败但仍继续（历史上有过）。
#
# 两者都会把**旧的 bundle** embed 进二进制，而源码看起来毫无问题
# ——排查时会误以为是代码缺陷。
#
# 具体到本次发布事故：importmap 把裸说明符 "vue" 固定指向
# /assets/vue.js，而 Vite 产出的入口名是 assets/runtime.js，
# 靠 vite.config.js 的 lipanel-runtime-entry 插件改名 + 改引用。
# 若 embed 进旧的 runtime.js 产物，浏览器请求 /assets/runtime.js
# 会落到 SPA 兜底（200 + text/html），模块按 MIME 被拒绝执行：
#
#   Failed to load module script: Expected a JavaScript-or-Wasm module
#   script but the server responded with a MIME type of "text/html".
#
# **整个页面白屏**。因此这里在打包前强制断言产物是自洽的，
# 让「构建成功但运行时白屏」的二进制**根本无法产出**。
log "校验前端产物完整性"

[ -f web/dist/assets/vue.js ] || die \
  "web/dist/assets/vue.js 缺失：importmap 指向的 Vue 入口不存在。
   产物可能陈旧或构建被跳过。请执行: cd web && npm run build"

if grep -rqs "runtime\.js" web/dist/assets/; then
  # 只列出文件名与匹配次数。匹配行是压缩后的整行 JS（可达数百 KB），
  # 直接打印会把终端刷屏、真正的原因反而看不见。
  die "web/dist/assets/ 中仍存在对 runtime.js 的引用（应为 vue.js）：
$(grep -rcls "runtime\.js" web/dist/assets/ | sed 's/^/   /')
   这是 P0 白屏的成因。请执行: cd web && npm run build"
fi

# 断言入口 chunk 的动态 import 确实指向 ./vue.js。
# 只查文件存在是不够的：真正的白屏来自**代码里写死的旧引用**，
# 那正是 generateBundle 改名单独无法修复、必须靠 renderChunk 的地方。
if ! grep -qs 'import("\./vue\.js")' web/dist/assets/index-*.js 2>/dev/null; then
  die "web/dist/assets/index-*.js 未引用 ./vue.js：
   入口 chunk 的动态 import 仍指向旧路径，浏览器将白屏。
   请执行: cd web && npm run build"
fi

log "产物校验通过（vue.js 存在，且入口已引用 ./vue.js）"

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
