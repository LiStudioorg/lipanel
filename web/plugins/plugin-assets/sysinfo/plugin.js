// sysinfo 插件的**自带前端**（阶段三 3.2 动态挂载的第一个真实插件前端）。
//
// ============ 一、这个文件凭什么能被加载 ============
//
//   1. 它随插件一起分发：本目录（web/plugins/plugin-assets/sysinfo/）在构建时被 Vite
//      原样拷贝到 dist/plugin-assets/sysinfo/，再被 go:embed 打进单二进制；
//   2. 插件的 Descriptor 在 internal/plugin/builtin/sysinfo/plugin.go 里
//      声明 frontend.entry = "/plugin-assets/sysinfo/plugin.js"；
//   3. 核心经 GET /api/plugins 把该地址返回给前端，前端 loader.js 动态
//      import 它，取出默认导出的 component 挂到 /plugins/sysinfo 路由上。
//
// 关键点：主程序里**没有任何一行代码提到 sysinfo 的前端**。
// 换掉本文件的内容、甚至整包删除，主程序都不需要重新构建。
//
// ============ 二、为什么是 .js 而不是 .vue ============
//
// publicDir 的内容不经过 Vite 打包（这是有意的：插件前端应当「原样分发」，
// 用户自己写的插件不该被要求装一套前端工具链）。代价是不能用 .vue 单文件
// 和 @ 别名，界面要用 h() 手写。模板字符串也刻意避开反引号——
// 单二进制的 go:embed 会原样带上源码，反引号会在 Go 里造成阅读干扰，
// 且插件作者复制代码时容易出现转义问题。
//
// ============ 三、可以依赖什么 ============
//
//   ✅ import { ... } from 'vue'   —— 由 index.html 的 importmap 指向宿主同一份 Vue
//   ✅ fetch /api/plugins/<id>/*   —— 核心会把请求转发给本插件的进程
//   ✅ window.__LIPANEL__          —— 宿主运行时（正常情况下不需要用）
//   ❌ naive-ui 组件、@ 别名、.vue 单文件、宿主 src/ 下的任何模块
//
// 最后一条是刻意的隔离：插件若依赖主程序内部模块，主程序一重构插件就
// 集体损坏，插件生态会锁死在某个版本。插件要数据就走自己的进程接口。
import { computed, h, onMounted, ref } from 'vue'

// ---------- 展示辅助（插件自带，不依赖宿主 utils）----------
//
// 这几个函数原本在宿主的 src/utils/format.js 里。插件必须自带一份：
// 那属于宿主内部实现，插件引用它等于把两者绑死。

function formatBytes(bytes) {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const v = n / 1024 ** i
  return v.toFixed(v >= 100 || i === 0 ? 0 : 2) + ' ' + units[i]
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0))
  const d = Math.floor(s / 86400)
  const hh = Math.floor((s % 86400) / 3600)
  const mm = Math.floor((s % 3600) / 60)
  const ss = s % 60
  const pad = (x) => String(x).padStart(2, '0')
  if (d > 0) return d + ' 天 ' + pad(hh) + ':' + pad(mm) + ':' + pad(ss)
  if (hh > 0) return pad(hh) + ':' + pad(mm) + ':' + pad(ss)
  return pad(mm) + ':' + pad(ss)
}

function formatTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  return d.toLocaleString('zh-CN', { hour12: false })
}

// 使用率对应的状态色（Naive UI 语义色名在 <n-progress> 的 status 上生效）。
function percentStatus(percent) {
  const p = Number(percent) || 0
  if (p >= 90) return 'error'
  if (p >= 75) return 'warning'
  return 'success'
}

// ---------- 原生元素上的最小样式 ----------
//
// 插件不引入 CSS 文件：一是 publicDir 里加载 CSS 需要额外插入 <link>，
// 二是面板整体由宿主统一配色。这里只用内联样式表达「层级」与「间距」，
// 颜色一律继承宿主主题（color: inherit / opacity），避免出现突兀的色块。
const S = {
  muted: { opacity: 0.65, fontSize: '12px' },
  row: { display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' },
  stack: { display: 'flex', flexDirection: 'column', gap: '10px' },
  cols: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' },
  breakAll: { wordBreak: 'break-all' },
}

// 进度条：0~100 的百分比 + 语义色。
function progress(percent) {
  const p = Math.max(0, Math.min(100, Number(percent) || 0))
  const color = p >= 90 ? '#d03050' : p >= 75 ? '#f0a020' : '#18a058'
  return h('div', {
    style: {
      height: '14px',
      borderRadius: '4px',
      background: 'rgba(128,128,128,0.25)',
      overflow: 'hidden',
    },
  }, [
    h('div', {
      style: {
        width: p.toFixed(1) + '%',
        height: '100%',
        background: color,
        transition: 'width .3s ease',
      },
    }),
  ])
}

// 卡片：标题 + 右上角操作 + 内容。
function card(title, extra, children) {
  return h('section', {
    style: {
      border: '1px solid rgba(128,128,128,0.28)',
      borderRadius: '6px',
      padding: '14px 16px',
    },
  }, [
    h('header', {
      style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', marginBottom: '12px' },
    }, [
      h('strong', null, title),
      extra || null,
    ]),
    ...children,
  ])
}

// 按钮：不依赖 Naive UI，用原生 button + 宿主继承的字体色。
function button(text, onClick, disabled) {
  return h('button', {
    type: 'button',
    disabled: Boolean(disabled),
    onClick,
    style: {
      cursor: disabled ? 'not-allowed' : 'pointer',
      border: '1px solid rgba(128,128,128,0.4)',
      background: 'transparent',
      color: 'inherit',
      borderRadius: '4px',
      padding: '3px 12px',
      font: 'inherit',
      fontSize: '13px',
    },
  }, text)
}

// 提示条：tone ∈ info/warning/error，仅靠左边框与图标区分。
function alertBox(tone, title, children) {
  const color = tone === 'error' ? '#d03050' : tone === 'warning' ? '#f0a020' : '#2080f0'
  const mark = tone === 'error' ? '✖' : tone === 'warning' ? '⚠' : 'ℹ'
  return h('div', {
    style: {
      borderLeft: '3px solid ' + color,
      background: 'rgba(128,128,128,0.10)',
      borderRadius: '4px',
      padding: '10px 12px',
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
    },
  }, [
    h('strong', { style: { fontSize: '13px' } }, mark + ' ' + title),
    h('div', { style: { fontSize: '13px' } }, children),
  ])
}

// 键值对网格。
function descriptions(items) {
  return h('dl', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
      gap: '6px 16px',
      margin: 0,
      fontSize: '13px',
    },
  }, items.flatMap(([label, value]) => [
    h('dt', { style: { ...S.muted, margin: 0 } }, label),
    h('dd', { style: { margin: '0 0 6px' } }, value ?? '-'),
  ]))
}

// ============ 桥接取数（隔离模式与兼容模式统一入口） ============
//
// 为什么要有这一层：3.3 起插件前端默认跑在 sandbox iframe 里，
// 那里没有会话 Cookie，直接 fetch('/api/...') 会 401。
// 宿主在 window.__LIPANEL__.api 上提供了「代发请求」的能力，
// 本函数是对它的最小封装：把路径拼对、把状态码归一化。
//
// 插件作者应当始终用 apiGet/apiPost 取数，不要直接 fetch——
// 后者只在兼容模式下能用，且会把自己绑死在"共享 Realm"这种不安全形态上。
async function apiGet(path) {
  const host = window.__LIPANEL__
  if (!host || !host.api) {
    throw new Error(
      '插件运行环境不可用（window.__LIPANEL__.api 缺失）。' +
        '请确认插件前端是按 3.3 的契约加载的。',
    )
  }
  // 隔离模式下走 postMessage 桥；兼容模式下宿主也提供同样的 api 对象，
  // 因此这里无需区分模式。
  return host.api.get(path)
}

// ============ 组件本体 ============

const SysinfoPluginView = {
  name: 'SysinfoPluginView',
  props: {
    // 宿主（PluginHostView）注入的两个 prop，属于插件前端契约。
    pluginId: { type: String, required: true },
    plugin: { type: Object, default: null },
  },
  setup(props) {
    const loading = ref(false)
    const error = ref('')
    const payload = ref(null)

    // 数据全部来自**插件自己的进程**：/info 由核心转发给插件进程处理。
    // 这条链路能跑通，就证明「核心 → 插件进程」是通的。
    //
    // ============ 隔离模式下的取数方式（阶段三 3.3） ============
    //
    // 下面这行 apiGet('/info') 在两种模式下都能工作：
    //
    //   隔离模式（默认）：本文件跑在 sandbox iframe 里（opaque origin），
    //     没有会话 Cookie，fetch('/api/...') 会被后端 401。
    //     因此 apiGet 会经 postMessage 请宿主代取，宿主拿到响应后回传。
    //     插件里 **看不到也不接触任何凭据**。
    //
    //   兼容模式（?legacy=1）：本文件与宿主共享 Realm，
    //     apiGet 退化为宿主提供的 fetch（行为与 3.2 完全一致）。
    //
    // 插件作者因此不需要为「跑在哪种模式」写分支——桥接层吸收了这个差异。
    async function load() {
      loading.value = true
      error.value = ''
      try {
        const body = await apiGet('/info')
        if (!body) {
          error.value = '插件返回了非 JSON 内容'
          payload.value = null
          return
        }
        payload.value = body
      } catch (err) {
        payload.value = null
        // 503 = 插件未运行。这不是错误而是可操作的状态，单独给指引。
        // 状态码由桥接层挂在 error.status 上（见 bridge.js）。
        if (err?.status === 503) {
          error.value = '插件当前未运行。请到「插件管理」页启动后再回到此页面。'
        } else if (err?.status === 403) {
          // 权限不足：把「缺哪个权限」显示出来，用户才知道怎么修。
          const need = err?.body?.required
          error.value =
            '插件权限不足：' + (err?.body?.error || err.message) +
            (need ? '（需要权限 ' + need + '）' : '')
        } else if (err?.status === 401) {
          error.value = '登录已过期，请刷新页面重新登录。'
        } else {
          error.value = err?.message || '无法从插件获取数据'
        }
      } finally {
        loading.value = false
      }
    }

    onMounted(load)

    const info = computed(() => payload.value?.info || null)

    const cpuLoadText = computed(() => {
      const load = info.value?.cpu?.load_avg
      if (!Array.isArray(load) || load.length < 3) return '-'
      return load.map((v) => Number(v).toFixed(2)).join(' / ')
    })

    const swapEnabled = computed(() => (info.value?.swap?.total_bytes ?? 0) > 0)

    // 顶部工具条：刷新按钮 + 加载中提示。
    function toolbar() {
      return h('span', { style: { display: 'flex', alignItems: 'center', gap: '10px' } }, [
        h('span', { style: S.muted }, loading.value ? '加载中…' : '来自插件进程'),
        button('刷新', load, loading.value),
      ])
    }

    function overviewCard() {
      return card('系统概况（数据来自插件进程）', toolbar(), [
        descriptions([
          ['插件 ID', payload.value?.plugin],
          ['主机名', info.value?.hostname],
          ['操作系统', info.value?.os],
          ['内核版本', info.value?.kernel],
          ['架构', info.value?.arch],
          ['运行时长', formatDuration(info.value?.uptime_seconds)],
          ['采集时间', formatTime(info.value?.collected_at)],
        ]),
      ])
    }

    function cpuCard() {
      const cpu = info.value?.cpu || {}
      return card('CPU', null, [
        h('div', { style: { ...S.stack, ...S.breakAll } }, [
          h('div', { style: S.muted }, cpu.model || '未知型号'),
          progress(cpu.usage_percent),
          h('div', { style: S.row }, [
            h('span', { style: S.muted }, '核心数：' + (cpu.cores ?? '-')),
            h('span', { style: S.muted }, '负载(1/5/15m)：' + cpuLoadText.value),
            h('span', { style: S.muted }, '使用率：' + Number(cpu.usage_percent ?? 0).toFixed(1) + '%'),
          ]),
        ]),
      ])
    }

    function memoryCard() {
      const mem = info.value?.memory || {}
      const swap = info.value?.swap || {}
      return card('内存', null, [
        h('div', { style: S.stack }, [
          progress(mem.usage_percent),
          h('div', { style: S.muted },
            '已用 ' + formatBytes(mem.used_bytes) + ' / 总计 ' + formatBytes(mem.total_bytes)),
          h('div', { style: S.row }, [
            h('span', { style: S.muted }, '可用：' + formatBytes(mem.free_bytes)),
            h('span', { style: S.muted }, '缓存：' + formatBytes(mem.cached_bytes)),
          ]),
          h('hr', { style: { border: 'none', borderTop: '1px solid rgba(128,128,128,0.25)', margin: '4px 0' } }),
          swapEnabled.value
            ? h('div', { style: S.stack }, [
                h('div', { style: S.muted }, '交换分区'),
                progress(swap.usage_percent),
                h('div', { style: S.muted },
                  formatBytes(swap.used_bytes) + ' / ' + formatBytes(swap.total_bytes) +
                  '（' + Number(swap.usage_percent ?? 0).toFixed(1) + '%）'),
              ])
            : h('div', { style: S.muted }, '交换分区未启用'),
        ]),
      ])
    }

    function diskCard() {
      const disk = info.value?.disk || {}
      return card('磁盘 ' + (disk.path || '/'), null, [
        h('div', { style: S.stack }, [
          progress(disk.usage_percent),
          h('div', { style: S.row }, [
            h('span', { style: S.muted },
              '已用 ' + formatBytes(disk.used_bytes) + ' / 总计 ' + formatBytes(disk.total_bytes)),
            h('span', { style: S.muted }, '可用：' + formatBytes(disk.free_bytes)),
            h('span', { style: S.muted }, '使用率：' + Number(disk.usage_percent ?? 0).toFixed(1) + '%'),
          ]),
        ]),
      ])
    }

    // ---------- 隔离效果演示（阶段三 3.3） ----------
    //
    // 这张卡片的目的是把「沙箱到底隔离了什么」变成**用户看得见的结论**，
    // 而不是文档里的一句承诺。两个检测都是运行时实测：
    //
    //   1. 读 document.cookie —— 隔离模式下抛异常或为空；
    //   2. 直连 fetch('/api/...') —— 隔离模式下没有会话 Cookie，被后端 401。
    //
    // 在兼容模式（?legacy=1）下两项会失败，卡片会明确标红——
    // 这正好构成了两种模式的可视对照。
    const isolation = ref(null)

    function probeIsolation() {
      const result = { sandboxed: Boolean(window.__LIPANEL__?.frame) }

      // 1) cookie 可读性。
      // 沙箱（opaque origin）下访问 document.cookie 要么抛 SecurityError，
      // 要么返回空串——两种都说明「读不到宿主会话」。
      try {
        const c = document.cookie
        result.cookieReadable = Boolean(c && c.length)
        result.cookieDetail = c ? '读到了 ' + c.length + ' 字节' : '（空）'
      } catch (err) {
        result.cookieReadable = false
        result.cookieDetail = '访问被浏览器拒绝：' + (err?.name || err)
      }

      // 2) 直连核心接口。
      // 用 try/catch 包住：沙箱里 fetch 可能直接抛（CSP/origin 限制）。
      return fetch('/api/system/info', {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
      })
        .then((resp) => {
          result.directStatus = resp.status
          result.directBlocked = resp.status === 401
        })
        .catch((err) => {
          result.directStatus = 0
          result.directBlocked = true
          result.directDetail = String(err?.message || err)
        })
        .then(() => {
          result.done = true
          isolation.value = result
        })
    }

    onMounted(probeIsolation)

    function isolationCard() {
      const r = isolation.value
      if (!r || !r.done) {
        return card('隔离效果检测', null, [h('div', { style: S.muted }, '检测中…')])
      }

      const ok = r.cookieReadable === false && r.directBlocked === true
      const tone = ok ? 'info' : 'warning'
      const title = ok ? '✓ 沙箱隔离已生效' : '⚠ 未隔离（共享 Realm）'

      const rows = [
        h('div', { style: S.row }, [
          h('span', { style: S.muted }, '运行环境：'),
          h('code', null, r.sandboxed ? 'sandbox iframe（opaque origin）' : '宿主 Realm（兼容模式）'),
        ]),
        h('div', { style: S.row }, [
          h('span', { style: S.muted }, '读取 document.cookie：'),
          h('span', null,
            r.cookieReadable
              ? '✖ 可以读取（' + r.cookieDetail + '）—— 存在会话泄露风险'
              : '✓ 读不到（' + r.cookieDetail + '）'),
        ]),
        h('div', { style: S.row }, [
          h('span', { style: S.muted }, '直连 /api/system/info：'),
          h('span', null,
            r.directBlocked
              ? '✓ 被拒绝（HTTP ' + r.directStatus + '）—— 拿不到核心数据'
              : '✖ 成功（HTTP ' + r.directStatus + '）—— 插件可越权访问核心接口'),
        ]),
      ]

      return alertBox(tone, title, h('div', { style: S.stack }, [
        ...rows,
        h('div', { style: { ...S.muted, marginTop: '4px' } },
          ok
            ? '以上两项检测为本页在浏览器里实测的结果。插件要数据时会通过 postMessage ' +
              '请宿主代取，凭据始终留在宿主侧。'
            : '当前为兼容模式：插件与宿主共享 Realm。若插件前端不完全可信，' +
              '请去掉 URL 上的 legacy 参数回到隔离模式。'),
      ]))
    }

    return () => {
      const children = []

      if (error.value) {
        children.push(alertBox('error', '无法从插件获取数据', error.value))
      }

      const warnings = info.value?.warnings
      if (Array.isArray(warnings) && warnings.length) {
        children.push(
          alertBox('warning', '部分信息采集失败', h('ul', { style: { margin: 0, paddingLeft: '18px' } },
            warnings.map((w, i) => h('li', { key: i }, w)))),
        )
      }

      if (info.value) {
        children.push(overviewCard())
        children.push(h('div', { style: S.cols }, [cpuCard(), memoryCard()]))
        children.push(diskCard())
        children.push(
          alertBox('info', '这条数据是怎么来的',
            '本页数据取自插件进程 ' + String(payload.value?.plugin || props.pluginId) +
            '：核心收到 /api/plugins/' + props.pluginId + '/info 后，经 Unix socket 转发给插件处理。' +
            '可与「系统概览」页的核心直连接口对比。'),
        )
        children.push(isolationCard())
      }

      return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '16px' } }, children)
    }
  },
}

// ============ 插件前端的导出契约 ============
//
// 必须 default export 一个对象，其中 component 是挂载点（Vue 组件）。
// meta 可选，仅用于排查问题——loader 会拿它和注册 ID 做一致性告警。
export default {
  meta: {
    id: 'sysinfo',
    title: '系统信息（插件）',
    version: '0.2.0',
  },
  component: SysinfoPluginView,
}
