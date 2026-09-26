// 插件前端沙箱桥接的验证（阶段三 3.3）。
//
// 为什么用 Node 原生跑而不是引入 vitest/jest：
// 工程约束是「轻量、按需引入」，而 bridge.js 的协议逻辑是纯 JS——
// 不依赖 DOM、不依赖 Vue。用 node:test（Node 内置）+ 一个最小的事件/
// postMessage 桩就能把它完整覆盖，不必为几个断言引入一整套测试框架
// 与它的依赖树。
//
// 运行方式：node --test web/src/plugins/bridge.test.mjs
// 或者：   node web/src/plugins/bridge-verify.mjs   （独立可执行的自检脚本）
//
// 覆盖重点（这些都是**安全边界**，写错了不会有报错，只会静默失效）：
//   1. 路径白名单：插件不能借桥访问别的插件或核心接口
//   2. 路径穿越：../ 、%2e%2e、协议相对地址、带 scheme 的地址
//   3. 方法白名单
//   4. 来源窗口校验：别的窗口（哪怕是同样 "null" origin 的 iframe）发的消息必须被忽略
//   5. 协议版本不匹配必须明确拒绝
//   6. resize 值 clamp、notify 限流
//   7. 跳转目标白名单（防开放重定向）
//   8. 响应体大小上限
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildPluginAPIPath,
  clampFrameHeight,
  extractError,
  frameSrc,
  PluginFrameBridge,
  safeNavigateTarget,
} from './bridge.js'

// ---------- 测试替身 ----------

// fakeWindow 模拟一个窗口对象：只需要 postMessage。
function fakeWindow() {
  return {
    sent: [],
    postMessage(payload) {
      this.sent.push(payload)
    },
  }
}

// installWindow 在全局装一个极简的 window（bridge 只在 attach 时用到
// addEventListener / removeEventListener，发送时用 frameWindow.postMessage）。
function installWindow() {
  const listeners = new Set()
  const prev = globalThis.window
  globalThis.window = {
    addEventListener: (type, fn) => {
      if (type === 'message') listeners.add(fn)
    },
    removeEventListener: (type, fn) => {
      if (type === 'message') listeners.delete(fn)
    },
  }
  return {
    listeners,
    restore() {
      globalThis.window = prev
    },
    // dispatch 模拟一次消息到达。
    dispatch(event) {
      for (const fn of listeners) fn(event)
    },
  }
}

// makeBridge 构造一个已 attach 的桥，返回桥、iframe 窗口与测试环境。
function makeBridge(options = {}) {
  const env = installWindow()
  const frameWin = fakeWindow()
  const requests = []

  const bridge = new PluginFrameBridge({
    pluginId: options.pluginId || 'sysinfo',
    plugin: { id: options.pluginId || 'sysinfo', name: '系统信息' },
    frame: { entry: '/plugin-assets/sysinfo/plugin.js', assets: '/plugin-assets/sysinfo/' },
    request:
      options.request ||
      (async (path, init) => {
        requests.push({ path, init })
        return { status: 200, body: { ok: true, path } }
      }),
    onError: options.onError,
    onResize: options.onResize,
    onNotify: options.onNotify,
    onNavigate: options.onNavigate,
    onMounted: options.onMounted,
  })

  // attach 需要 frameEl.contentWindow；我们直接给一个假元素。
  bridge.attach({ contentWindow: frameWin })

  return { bridge, frameWin, requests, env }
}

// send 模拟 iframe → 宿主的一条消息。
function send(env, frameWin, msg, source) {
  env.dispatch({
    source: source === undefined ? frameWin : source,
    origin: 'null',
    data: msg,
  })
}

// waitResult 等桥把 api-result 发回 iframe。
async function waitResult(frameWin, id) {
  for (let i = 0; i < 100; i++) {
    const found = frameWin.sent.find((m) => m.type === 'lipanel:api-result' && m.id === id)
    if (found) return found
    await new Promise((r) => setTimeout(r, 5))
  }
  return null
}

// ---------- 1. 路径白名单 ----------

test('buildPluginAPIPath 只放行本插件的相对路径', () => {
  // 正常路径。
  assert.equal(buildPluginAPIPath('sysinfo', '/info'), '/api/plugins/sysinfo/info')
  assert.equal(buildPluginAPIPath('sysinfo', '/files/a.txt'), '/api/plugins/sysinfo/files/a.txt')

  // 必须以 / 开头：含糊的写法一律拒绝。
  assert.equal(buildPluginAPIPath('sysinfo', 'info'), null)
  assert.equal(buildPluginAPIPath('sysinfo', ''), null)

  // 协议相对与带 scheme 的绝对地址：拒绝（否则插件能把宿主当代理用）。
  assert.equal(buildPluginAPIPath('sysinfo', '//evil.com/x'), null)
  assert.equal(buildPluginAPIPath('sysinfo', 'https://evil.com/x'), null)
  assert.equal(buildPluginAPIPath('sysinfo', 'javascript:alert(1)'), null)

  // 路径穿越：拒绝（拼接后会被后端重新解析，多拦一层成本极低）。
  assert.equal(buildPluginAPIPath('sysinfo', '/../../api/system/info'), null)
  assert.equal(buildPluginAPIPath('sysinfo', '/a/../../b'), null)
  assert.equal(buildPluginAPIPath('sysinfo', '/.%2e/api/system/info'), null)
  assert.equal(buildPluginAPIPath('sysinfo', '/%2e%2e/api'), null)
  assert.equal(buildPluginAPIPath('sysinfo', '/a%2fb'), null)

  // 控制字符：拒绝。
  assert.equal(buildPluginAPIPath('sysinfo', '/a\nb'), null)
  assert.equal(buildPluginAPIPath('sysinfo', '/a\u0000b'), null)

  // 没有插件 ID 时一律拒绝（不该出现，但拒绝比放行安全）。
  assert.equal(buildPluginAPIPath('', '/info'), null)
})

test('桥接拒绝 /api/... 形式的路径（常见误解）', async () => {
  const { bridge, frameWin, requests, env } = makeBridge()
  try {
    // 插件作者常见误解：以为桥接是反向代理，直接写核心接口路径。
    // 这类路径不会造成逃逸（拼出来仍在自己命名空间内），
    // 但会被静默转发到一个不存在的路由，表现为语焉不详的 404。
    // 因此桥接应当在**客户端侧**就明确拒绝（宿主侧是安全边界，
    // 这里额外一层是为了给出可读的错误信息）。
    for (const [i, path] of ['/api/system/info', '/api/plugins/other/info', '/api/plugins'].entries()) {
      send(env, frameWin, { protocol: 1, type: 'lipanel:api', id: i, method: 'GET', path })
      const res = await waitResult(frameWin, i)
      assert.ok(res, `应当收到对 ${path} 的拒绝结果`)
      assert.equal(res.ok, false, `${path} 应当被拒绝`)
      assert.equal(res.status, 400)
    }
    assert.equal(requests.length, 0, '这些路径不该触发任何真实请求')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

test('桥接把 /api/plugins/<别的插件> 前缀当作普通相对路径处理（不逃逸）', async () => {
  // 说明清楚语义：桥接不是反向代理，path 是**本插件内的**子路径。
  // 因此 "…/api/plugins/other/x" 只会被拼成自己命名空间下的一个普通路径，
  // 绝不会变成对 other 插件的调用。
  const path = buildPluginAPIPath('sysinfo', '/api/plugins/other/info')
  assert.equal(path, null, '/api/ 前缀被显式拒绝，因此这里返回 null')
  // 换一个不含 /api 前缀的写法：确认前缀永远是自己。
  const ok = buildPluginAPIPath('sysinfo', '/plugins/other/info')
  assert.equal(ok, '/api/plugins/sysinfo/plugins/other/info')
  assert.ok(ok.startsWith('/api/plugins/sysinfo/'), '前缀必须始终是自身')
})

test('桥接拒绝非白名单方法', async () => {
  const { bridge, frameWin, requests, env } = makeBridge()
  try {
    for (const method of ['PATCH', 'OPTIONS', 'TRACE', 'CONNECT']) {
      send(env, frameWin, {
        protocol: 1,
        type: 'lipanel:api',
        id: method,
        method,
        path: '/info',
      })
      const res = await waitResult(frameWin, method)
      assert.equal(res.ok, false, `${method} 应当被拒绝`)
      assert.equal(res.status, 400)
    }
    assert.equal(requests.length, 0, '被拒方法不该触发任何真实请求')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 2. 来源窗口校验 ----------

test('忽略来自其它窗口的消息（即使 origin 同样是 null）', async () => {
  const { bridge, frameWin, requests, env } = makeBridge()
  try {
    // 攻击场景：另一个 sandbox iframe（或攻击者页面）也报 origin="null"，
    // 如果只比较 origin，它的请求就会被当成合法插件的请求。
    const attacker = fakeWindow()
    send(
      env,
      frameWin,
      { protocol: 1, type: 'lipanel:api', id: 'evil', method: 'GET', path: '/info' },
      attacker, // event.source 是攻击者窗口
    )

    await new Promise((r) => setTimeout(r, 30))
    assert.equal(requests.length, 0, '来自其它窗口的消息必须被忽略')
    assert.equal(
      frameWin.sent.filter((m) => m.type === 'lipanel:api-result').length,
      0,
      '不该给攻击者回消息',
    )
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 3. 协议版本 ----------

test('协议版本不匹配时明确拒绝并上报错误', async () => {
  const errors = []
  const { bridge, frameWin, requests, env } = makeBridge({
    onError: (m) => errors.push(m),
  })
  try {
    send(env, frameWin, {
      protocol: 99,
      type: 'lipanel:api',
      id: 1,
      method: 'GET',
      path: '/info',
    })

    await new Promise((r) => setTimeout(r, 20))
    assert.equal(requests.length, 0, '版本不匹配的请求不该被执行')
    assert.equal(errors.length, 1, '应当上报一条版本错误')
    assert.match(errors[0], /协议版本不匹配/)
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 4. 握手与元数据下发 ----------

test('收到 ready 后下发插件元数据，且元数据里不含凭据', async () => {
  const mounted = []
  const { bridge, frameWin, env } = makeBridge({ onMounted: (v) => mounted.push(v) })
  try {
    send(env, frameWin, { protocol: 1, type: 'lipanel:ready', mounted: true })

    const data = frameWin.sent.find((m) => m.type === 'lipanel:plugin-data')
    assert.ok(data, 'ready 之后必须下发 plugin-data')
    assert.equal(data.pluginId, 'sysinfo')
    assert.equal(data.entry, '/plugin-assets/sysinfo/plugin.js')
    assert.equal(data.assets, '/plugin-assets/sysinfo/')
    assert.equal(data.protocol, 1)
    assert.deepEqual(mounted, [true])

    // 元数据里绝不能出现会话相关内容（万一将来有人顺手塞进去，
    // iframe 就拿到了本不该给它的东西）。
    const json = JSON.stringify(data)
    for (const forbidden of ['cookie', 'token', 'jwt', 'secret', 'authorization']) {
      assert.ok(
        !json.toLowerCase().includes(forbidden),
        `下发给沙箱的元数据不该包含 ${forbidden}`,
      )
    }
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 5. 正常请求往返 ----------

test('合法请求被正常代发并把结果回传', async () => {
  const { bridge, frameWin, requests, env } = makeBridge()
  try {
    send(env, frameWin, {
      protocol: 1,
      type: 'lipanel:api',
      id: 7,
      method: 'GET',
      path: '/info',
    })

    const res = await waitResult(frameWin, 7)
    assert.equal(res.ok, true)
    assert.equal(res.status, 200)
    assert.equal(res.body.path, '/api/plugins/sysinfo/info')
    assert.equal(requests.length, 1)
    assert.equal(requests[0].path, '/api/plugins/sysinfo/info')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

test('403 与 503 的状态码与响应体会原样回传给插件', async () => {
  // 插件需要看到状态码本身才能给出正确提示（403 显示缺失权限、
  // 503 提示先启动插件），因此桥不能把失败统一成一句字符串。
  const { bridge, frameWin, env } = makeBridge({
    request: async () => ({
      status: 403,
      body: { error: '插件权限不足', required: 'file.write', hint: '请补充声明' },
    }),
  })
  try {
    send(env, frameWin, {
      protocol: 1,
      type: 'lipanel:api',
      id: 9,
      method: 'GET',
      path: '/files',
    })

    const res = await waitResult(frameWin, 9)
    assert.equal(res.ok, false)
    assert.equal(res.status, 403)
    assert.equal(res.body.required, 'file.write')
    // error 字段取后端的主文案；hint 保留在 body 里供插件按需展示。
    assert.equal(res.error, '插件权限不足')
    assert.equal(res.body.hint, '请补充声明')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 6. 响应体大小上限 ----------

test('超大响应被拒绝，不会传给插件前端', async () => {
  const huge = { data: 'x'.repeat(2 * 1024 * 1024) } // 2 MiB > 1 MiB 上限
  const { bridge, frameWin, env } = makeBridge({
    request: async () => ({ status: 200, body: huge }),
  })
  try {
    send(env, frameWin, {
      protocol: 1,
      type: 'lipanel:api',
      id: 11,
      method: 'GET',
      path: '/info',
    })

    const res = await waitResult(frameWin, 11)
    assert.equal(res.ok, false)
    assert.match(res.error, /响应过大/)
    assert.equal(res.body, undefined, '超大响应体不该被传过去')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 7. resize / notify ----------

test('resize 值被 clamp 到合法区间', () => {
  const heights = []
  const { bridge, frameWin, env } = makeBridge({ onResize: (h) => heights.push(h) })
  try {
    for (const h of [0, -5, 10, 500, 1e9, 'abc', NaN]) {
      send(env, frameWin, { protocol: 1, type: 'lipanel:resize', height: h })
    }
    for (const h of heights) {
      assert.ok(h >= 120 && h <= 20000, `高度 ${h} 应被 clamp 到 [120, 20000]`)
    }
    // 荒谬值不能被原样接受。
    assert.ok(!heights.includes(1e9), '超大高度必须被 clamp')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

test('clampFrameHeight 边界', () => {
  assert.equal(clampFrameHeight(0), 120)
  assert.equal(clampFrameHeight(-100), 120)
  assert.equal(clampFrameHeight(300), 300)
  assert.equal(clampFrameHeight(1e9), 20000)
  assert.equal(clampFrameHeight('abc'), 120)
})

test('notify 被限流，不能刷屏', () => {
  const notes = []
  const { bridge, frameWin, env } = makeBridge({ onNotify: (t, l) => notes.push({ t, l }) })
  try {
    for (let i = 0; i < 50; i++) {
      send(env, frameWin, { protocol: 1, type: 'lipanel:notify', text: 'spam ' + i, level: 'info' })
    }
    // 窗口内上限 5 条，超限时额外给一条「已限流」提示。
    assert.ok(notes.length <= 6, `通知数应当被限流，实际 ${notes.length}`)
    assert.ok(
      notes.some((n) => n.t.includes('限流')),
      '应当提示用户插件提示过于频繁',
    )
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 8. 跳转白名单 ----------

test('safeNavigateTarget 只接受站内相对路径', () => {
  assert.equal(safeNavigateTarget('/plugins'), '/plugins')
  assert.equal(safeNavigateTarget('/plugins/sysinfo'), '/plugins/sysinfo')

  // 开放重定向与钓鱼：全部拒绝。
  assert.equal(safeNavigateTarget('//evil.com'), null)
  assert.equal(safeNavigateTarget('https://evil.com'), null)
  assert.equal(safeNavigateTarget('http://evil.com/x'), null)
  assert.equal(safeNavigateTarget('javascript:alert(1)'), null)
  assert.equal(safeNavigateTarget('/a/../../b'), null)
  assert.equal(safeNavigateTarget(''), null)
  assert.equal(safeNavigateTarget('/a\nb'), null)
})

test('非法跳转请求会上报错误且不触发跳转', () => {
  const errors = []
  const navs = []
  const { bridge, frameWin, env } = makeBridge({
    onError: (m) => errors.push(m),
    onNavigate: (t) => navs.push(t),
  })
  try {
    send(env, frameWin, { protocol: 1, type: 'lipanel:navigate', to: 'https://evil.com' })
    assert.equal(navs.length, 0, '非法跳转不该被执行')
    assert.equal(errors.length, 1)
    assert.match(errors[0], /不被允许的地址/)
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 9. 生命周期 ----------

test('dispose 之后不再处理任何消息', async () => {
  const { bridge, frameWin, requests, env } = makeBridge()
  bridge.dispose()

  send(env, frameWin, {
    protocol: 1,
    type: 'lipanel:api',
    id: 1,
    method: 'GET',
    path: '/info',
  })
  await new Promise((r) => setTimeout(r, 20))

  assert.equal(requests.length, 0, '卸载后迟到的消息不该再被执行')
  env.restore()
})

test('未知消息类型被忽略（不报错）', () => {
  const errors = []
  const { bridge, frameWin, env } = makeBridge({ onError: (m) => errors.push(m) })
  try {
    send(env, frameWin, { protocol: 1, type: 'lipanel:whatever-future-thing', data: 1 })
    send(env, frameWin, null)
    send(env, frameWin, 'not an object')
    assert.equal(errors.length, 0, '未知类型应当被静默忽略，便于协议演进')
  } finally {
    bridge.dispose()
    env.restore()
  }
})

// ---------- 10. 其它 ----------

test('extractError 取到可读的失败原因', () => {
  // 优先 error（它是后端给出的主文案）。
  assert.equal(extractError({ error: 'e', hint: 'h' }, 403), 'e')
  // 只有 error 缺失时才退到 hint。
  assert.equal(extractError({ hint: 'h' }, 403), 'h')
  assert.equal(extractError('plain text', 500), 'plain text')
  assert.equal(extractError(null, 503), '请求失败（HTTP 503）')
})

test('frameSrc 只带插件 ID，不带任何入口地址', () => {
  const src = frameSrc('sysinfo')
  assert.equal(src, '/plugin-assets/frame.html?id=sysinfo')
  // 关键安全性质：src 里不能出现入口地址，否则伪造 URL 就能让
  // iframe 去加载别的插件前端。
  assert.ok(!src.includes('entry'))
  assert.ok(!src.includes('plugin.js'))
  // ID 必须被编码（防注入到 URL 结构里）。
  assert.equal(frameSrc('a b/c'), '/plugin-assets/frame.html?id=a%20b%2Fc')
})
