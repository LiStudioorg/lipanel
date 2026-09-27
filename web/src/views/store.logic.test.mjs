// 软件商店页纯逻辑测试（阶段四 4.5）。
//
// 运行方式：npm test（见 web/package.json 的 test 脚本）。
// 用 node:test，不引入 jsdom —— 与其它四个模块的前端测试一致。
//
// 这里锁定的重点是**与后端的一致性**：
// 策略名称、任务状态、日志级别这些取值一旦与 internal/store 不一致，
// 界面就会显示出与真实情况相反的信息。
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  STRATEGY_META,
  TASK_STATUS_META,
  STEP_STATUS_META,
  LOG_LEVEL_META,
  FAMILY_LABEL,
  PACKAGE_MANAGER_LABEL,
  strategyMeta,
  taskStatusMeta,
  stepStatusMeta,
  isTerminal,
  softwareStatusMeta,
  canInstall,
  canUninstall,
  defaultVersionOf,
  versionOptions,
  compareVersions,
  progressStatus,
  mergeLogs,
  logLevelMeta,
  formatLogLine,
  environmentText,
  uninstallConfirmText,
  installConfirmText,
} from './storeLogic.js'

// ---------------------------------------------------------------------------
// 与后端取值对齐
// ---------------------------------------------------------------------------

// Test1: 策略名称必须与 internal/store 的常量逐字相同。
//
// 这些字符串来自后端的 StrategySystem / StrategyOfficial / StrategyPrebuilt。
// 写错一个字母，界面就查不到元数据，回落成"未知"。
test('策略名称与后端常量一致', () => {
  assert.deepEqual(Object.keys(STRATEGY_META).sort(), ['official', 'prebuilt', 'system'])
  // 后端没有 "none" 这一档：失败的任务不设 strategy（空串）。
  assert.equal(STRATEGY_META.none, undefined)
})

// Test2: 任务状态必须与 internal/store 的 Task* 常量一致。
test('任务状态与后端常量一致', () => {
  assert.deepEqual(Object.keys(TASK_STATUS_META).sort(), [
    'failed',
    'pending',
    'running',
    'succeeded',
  ])
})

// Test3: 步骤状态必须与后端的 Step* 常量一致。
test('步骤状态与后端常量一致', () => {
  assert.deepEqual(Object.keys(STEP_STATUS_META).sort(), [
    'failed',
    'pending',
    'running',
    'skipped',
    'succeeded',
  ])
})

// Test4: 日志级别必须覆盖后端的 Log* 常量。
//
// 后端有 LogInfo/LogWarn/LogError/LogCommand/LogStdout/LogStderr/LogStep。
// agent 少写一个，那一类日志就会显示成默认灰色，排查时容易被忽略。
test('日志级别覆盖后端全部级别', () => {
  for (const level of ['info', 'warn', 'error', 'command', 'stdout', 'stderr', 'step']) {
    assert.ok(LOG_LEVEL_META[level], `缺少日志级别 ${level}`)
  }
  // 错误输出必须显示为红色 —— 排查失败时它就是关键证据。
  assert.equal(LOG_LEVEL_META.stderr.type, 'error')
  assert.equal(LOG_LEVEL_META.error.type, 'error')
})

// Test5: 包管理器与发行版家族的取值。
test('环境标签覆盖后端的取值', () => {
  for (const k of ['debian', 'rhel', 'unknown']) {
    assert.ok(FAMILY_LABEL[k], `缺少家族 ${k}`)
  }
  for (const k of ['apt', 'dnf', 'yum']) {
    assert.ok(PACKAGE_MANAGER_LABEL[k], `缺少包管理器 ${k}`)
  }
})

// Test6: 未知取值必须安全回落，不能抛异常。
//
// 后端将来新增一个策略时，旧版前端不能因此整页报错。
test('未知取值安全回落', () => {
  assert.equal(strategyMeta('future-strategy').label, 'future-strategy')
  assert.equal(strategyMeta(undefined).label, '未知')
  assert.equal(taskStatusMeta('').label, '未知')
  assert.equal(stepStatusMeta(null).label, '未知')
  assert.equal(logLevelMeta(undefined).label, '信息')
})

// ---------------------------------------------------------------------------
// 任务状态判定
// ---------------------------------------------------------------------------

// Test7: 终态判定 —— 界面据此停止轮询。
test('isTerminal 只认成功与失败', () => {
  assert.equal(isTerminal('succeeded'), true)
  assert.equal(isTerminal('failed'), true)
  assert.equal(isTerminal('running'), false)
  assert.equal(isTerminal('pending'), false)
  assert.equal(isTerminal(''), false)
  assert.equal(isTerminal(undefined), false)
})

// Test8: 进度条状态 —— 失败必须显红。
test('progressStatus 反映真实状态', () => {
  assert.equal(progressStatus({ status: 'running' }), 'info')
  assert.equal(progressStatus({ status: 'failed' }), 'error')
  assert.equal(progressStatus({ status: 'succeeded' }), 'success')
  assert.equal(progressStatus({ status: 'pending' }), 'info')
  assert.equal(progressStatus(null), 'default')
})

// ---------------------------------------------------------------------------
// 软件状态（最需要防错的一段）
// ---------------------------------------------------------------------------

const nginxInstalled = {
  id: 'nginx',
  name: 'Nginx',
  installed: true,
  installed_versions: ['1.26'],
  detected_version: '1.26.2-1~jammy',
  installed_via: 'system',
}

const nginxDetectedOnly = {
  id: 'nginx',
  name: 'Nginx',
  installed: true,
  installed_versions: [],
  detected_version: '1.18.0-6ubuntu14',
}

const nginxNone = {
  id: 'nginx',
  name: 'Nginx',
  installed: false,
  installed_versions: [],
  detected_version: '',
}

// Test9: 已安装（在清单内）。
test('softwareStatusMeta 识别清单内已安装', () => {
  const meta = softwareStatusMeta(nginxInstalled)
  assert.equal(meta.key, 'installed')
  assert.equal(meta.type, 'success')
  assert.match(meta.desc, /1\.26/)
})

// Test10: 已安装但不在清单里 —— 这是本模块最容易做错的一档。
//
// 若按 installed_versions 判断就会显示成"未安装"，
// 用户于是再装一个，两个版本争抢 /usr/bin 下的同名文件。
test('softwareStatusMeta 区分「已安装但不在列表里」', () => {
  const meta = softwareStatusMeta(nginxDetectedOnly)
  assert.equal(meta.key, 'detected')
  // 用 warning 而不是 error：它是信息，不是故障。
  assert.equal(meta.type, 'warning')
  assert.match(meta.label, /1\.18\.0-6ubuntu14/)
  // 提示必须解释"为什么不能装"，否则用户只会觉得按钮坏了。
  assert.match(meta.desc, /覆盖/)
  assert.match(meta.desc, /禁用|不能/)
})

// Test11: 未安装。
test('softwareStatusMeta 识别未安装', () => {
  const meta = softwareStatusMeta(nginxNone)
  assert.equal(meta.key, 'none')
  // 灰色而不是红色：没装不是坏事。
  assert.equal(meta.type, 'default')
})

// Test12: 空输入不崩。
test('softwareStatusMeta 对空输入安全', () => {
  assert.equal(softwareStatusMeta(null).key, 'unknown')
  assert.equal(softwareStatusMeta(undefined).key, 'unknown')
  // 字段缺失（后端旧版本或半截数据）。
  assert.equal(softwareStatusMeta({}).key, 'none')
})

// ---------------------------------------------------------------------------
// 按钮可用性
// ---------------------------------------------------------------------------

// Test13: 安装按钮的各条禁用理由。
test('canInstall 逐条给出禁用理由', () => {
  // 可用。
  assert.equal(canInstall(nginxNone, '1.26', { available: true, running: null }).ok, true)

  // 没有包管理器：重试多少次都没用，必须说清楚。
  const noPm = canInstall(nginxNone, '1.26', { available: false })
  assert.equal(noPm.ok, false)
  assert.match(noPm.reason, /包管理器/)

  // 已有任务在跑：同一时刻只允许一个。
  const busy = canInstall(nginxNone, '1.26', { available: true, running: { id: 't1' } })
  assert.equal(busy.ok, false)
  assert.match(busy.reason, /正在进行/)

  // 已安装。
  assert.equal(
    canInstall(nginxInstalled, '1.26', { available: true, running: null }).ok,
    false,
  )

  // 已装但不在列表里：必须与"已安装"给出不同的理由。
  const detected = canInstall(nginxDetectedOnly, '1.26', { available: true, running: null })
  assert.equal(detected.ok, false)
  assert.match(detected.reason, /1\.18/)

  // 没选版本。
  const noVer = canInstall(nginxNone, '', { available: true, running: null })
  assert.equal(noVer.ok, false)
  assert.match(noVer.reason, /版本/)
})

// Test14: 依赖未就绪**不**阻止安装（后端会自动补齐）。
test('canInstall 不因依赖未就绪而禁用', () => {
  const php = { id: 'php', name: 'PHP', installed: false, depends: ['nginx'] }
  const res = canInstall(php, '8.3', { available: true, running: null })
  assert.equal(res.ok, true, '依赖由后端自动补齐，不该禁用按钮')
})

// Test15: 卸载按钮。
test('canUninstall 的判定', () => {
  assert.equal(canUninstall(nginxInstalled, { available: true }).ok, true)
  // 发行版自带的版本也能卸（后端按实际已安装的包名清理）。
  assert.equal(canUninstall(nginxDetectedOnly, { available: true }).ok, true)
  // 没装就没什么可卸的。
  const none = canUninstall(nginxNone, { available: true })
  assert.equal(none.ok, false)
  assert.match(none.reason, /未安装/)
  assert.equal(canUninstall(nginxInstalled, { available: false }).ok, false)
  assert.equal(canUninstall(nginxInstalled, { available: true, running: { id: 't' } }).ok, false)
})

// ---------------------------------------------------------------------------
// 版本选择
// ---------------------------------------------------------------------------

const sw = {
  id: 'php',
  name: 'PHP',
  default_version: '8.3',
  versions: [
    { id: '8.2', label: 'PHP 8.2' },
    { id: '8.3', label: 'PHP 8.3', is_default: true },
    { id: '7.4', label: 'PHP 7.4' },
  ],
}

// Test16: 默认版本解析。
test('defaultVersionOf 解析默认版本', () => {
  assert.equal(defaultVersionOf(sw), '8.3')
})

// Test17: 默认版本在列表里不存在时必须回落，不能返回一个不存在的版本。
//
// 返回不存在的版本会让用户提交一个必然 404 的请求。
test('defaultVersionOf 的回落顺序', () => {
  // default_version 指向不存在的版本 → 用 is_default 标记的。
  assert.equal(
    defaultVersionOf({ default_version: '9.9', versions: sw.versions }),
    '8.3',
  )
  // 没有任何标记 → 用第一个。
  assert.equal(
    defaultVersionOf({
      default_version: '',
      versions: [{ id: '1.0' }, { id: '2.0' }],
    }),
    '1.0',
  )
  // 空输入 → 空串（界面据此显示"请选择版本"，而不是崩掉）。
  assert.equal(defaultVersionOf(null), '')
  assert.equal(defaultVersionOf({}), '')
})

// Test18: 版本下拉排序 —— 默认版本置顶，其余按版本号从新到旧。
test('versionOptions 把默认版本排在最前', () => {
  const opts = versionOptions(sw)
  assert.equal(opts.length, 3)
  assert.equal(opts[0].value, '8.3')
  assert.equal(opts[0].isDefault, true)
  // 其余按数字序：8.2 > 7.4。
  assert.equal(opts[1].value, '8.2')
  assert.equal(opts[2].value, '7.4')
})

// Test19: 版本号比较不能按字符串。
//
// "8.10" < "8.3" 在字符串序里成立，而这是版本号。
test('compareVersions 按数字段比较', () => {
  assert.ok(compareVersions('8.10', '8.3') > 0, '8.10 应大于 8.3')
  assert.ok(compareVersions('8.3', '8.10') < 0)
  assert.equal(compareVersions('8.3', '8.3'), 0)
  assert.ok(compareVersions('7.4', '8.0') < 0)
  // 段数不同。
  assert.ok(compareVersions('22', '20.11') > 0)
  assert.ok(compareVersions('1.26.2', '1.26') > 0)
  assert.equal(compareVersions('', ''), 0)
})

// Test20: 版本项携带的安装信息。
test('versionOptions 保留安装与来源信息', () => {
  const opts = versionOptions({
    default_version: '1.26',
    versions: [
      {
        id: '1.26',
        installed: true,
        installed_version: '1.26.2-1~jammy',
        via: 'system',
        official_available: true,
        prebuilt_available: false,
        notes: ['需要联网'],
      },
    ],
  })
  assert.equal(opts[0].installed, true)
  assert.equal(opts[0].installedVersion, '1.26.2-1~jammy')
  assert.equal(opts[0].via, 'system')
  assert.equal(opts[0].officialAvailable, true)
  assert.equal(opts[0].prebuiltAvailable, false)
  assert.deepEqual(opts[0].notes, ['需要联网'])
})

// Test21: 空版本列表。
test('versionOptions 对空输入返回空数组', () => {
  assert.deepEqual(versionOptions(null), [])
  assert.deepEqual(versionOptions({}), [])
  assert.deepEqual(versionOptions({ versions: null }), [])
})

// ---------------------------------------------------------------------------
// 日志合并
// ---------------------------------------------------------------------------

// Test22: 按 seq 去重并保持有序。
//
// 日志是排查失败的**唯一**依据，重复行会让人怀疑漏看了什么。
test('mergeLogs 按 seq 去重且有序', () => {
  const existing = [
    { seq: 1, text: 'a' },
    { seq: 2, text: 'b' },
  ]
  const incoming = [
    { seq: 2, text: 'b（重复）' },
    { seq: 3, text: 'c' },
  ]
  const merged = mergeLogs(existing, incoming)
  assert.equal(merged.length, 3)
  assert.deepEqual(merged.map((l) => l.seq), [1, 2, 3])
  // 重复的那条保留**原有**内容（先到先得）。
  assert.equal(merged[1].text, 'b')
})

// Test23: 乱序到达也要排好。
test('mergeLogs 对乱序输入排序', () => {
  const merged = mergeLogs([{ seq: 5 }], [{ seq: 1 }, { seq: 3 }])
  assert.deepEqual(merged.map((l) => l.seq), [1, 3, 5])
})

// Test24: 空输入安全。
test('mergeLogs 对空输入安全', () => {
  assert.deepEqual(mergeLogs(null, null), [])
  assert.deepEqual(mergeLogs([], [{ seq: 1 }]).length, 1)
  // incoming 里的 null 元素要被跳过（后端异常时的防御）。
  assert.deepEqual(mergeLogs([], [null, { seq: 1 }]).length, 1)
})

// Test25: 不改动入参 —— 组件会把它同时用于渲染与合并。
test('mergeLogs 不修改入参数组', () => {
  const existing = [{ seq: 1 }]
  const merged = mergeLogs(existing, [{ seq: 2 }])
  assert.equal(existing.length, 1, '不应修改原数组')
  assert.equal(merged.length, 2)
})

// Test26: 日志行格式化。
test('formatLogLine 带步骤前缀', () => {
  assert.equal(
    formatLogLine({ seq: 1, step: '系统源安装', text: '$ apt-get install -y nginx' }),
    '[系统源安装] $ apt-get install -y nginx',
  )
  assert.equal(formatLogLine({ seq: 1, text: '普通日志' }), '普通日志')
  assert.equal(formatLogLine(null), '')
})

// ---------------------------------------------------------------------------
// 环境展示
// ---------------------------------------------------------------------------

// Test27: 环境摘要。
test('environmentText 组合环境信息', () => {
  const text = environmentText({
    distro: 'Ubuntu 22.04.5 LTS',
    family: 'debian',
    package_manager: 'apt',
    arch: 'x64',
  })
  assert.match(text, /Ubuntu 22\.04/)
  assert.match(text, /apt/)
  assert.match(text, /x64/)
})

// Test28: 没有发行版名时用家族名兜底。
test('environmentText 的兜底', () => {
  assert.match(environmentText({ family: 'rhel' }), /RHEL/)
  assert.equal(environmentText(null), '未知环境')
  assert.equal(environmentText({}), '未知环境')
})

// ---------------------------------------------------------------------------
// 确认文案
// ---------------------------------------------------------------------------

// Test29: 卸载确认必须列出将要发生的事，并说明"什么不会被删"。
//
// 一句"确定卸载吗？"把判断责任推给用户，而他并不知道面板会做什么。
test('uninstallConfirmText 写清后果与边界', () => {
  const text = uninstallConfirmText(nginxInstalled, '1.26')
  assert.match(text, /Nginx/)
  assert.match(text, /1\.26/)
  // 会做什么。
  assert.match(text, /包管理器/)
  assert.match(text, /孤儿包/)
  // **不会**做什么：这一条最容易被忽略，也最重要。
  assert.match(text, /不会.*网站文件|不会.*数据/)
  assert.match(text, /不会.*撤销.*源/)
  // 影响面。
  assert.match(text, /停止工作/)
})

// Test30: 预编译安装的卸载要额外提示会删除 /usr/local 下的文件。
test('uninstallConfirmText 覆盖预编译安装', () => {
  const text = uninstallConfirmText(
    { id: 'nodejs', name: 'Node.js', installed_via: 'prebuilt', installed_versions: ['22'] },
    '22',
  )
  assert.match(text, /预编译/)
  assert.match(text, /\/usr\/local/)
})

// Test31: 安装确认要说明三级回退顺序与系统改动。
test('installConfirmText 说明回退顺序与系统改动', () => {
  const text = installConfirmText(
    { id: 'php', name: 'PHP', depends: ['nginx'] },
    '8.3',
    { officialAvailable: true },
  )
  assert.match(text, /PHP 8\.3/)
  assert.match(text, /依赖.*nginx/)
  // 三级回退必须逐条列出，尤其"可能写入 /etc"这件事。
  assert.match(text, /系统软件源/)
  assert.match(text, /官方源/)
  assert.match(text, /预编译/)
  assert.match(text, /\/etc\/apt|\/etc\/yum/)
})

// Test32: 官方源不可用时要如实标注。
test('installConfirmText 标注官方源不可用', () => {
  const text = installConfirmText({ id: 'redis', name: 'Redis' }, '7.2', {
    officialAvailable: false,
  })
  assert.match(text, /当前环境不可用/)
})

// Test33: 没有依赖时不出现"依赖"字样。
test('installConfirmText 无依赖时简洁', () => {
  const text = installConfirmText({ id: 'nginx', name: 'Nginx' }, '1.26')
  assert.doesNotMatch(text, /依赖/)
})

// Test34: 空输入的确认文案不崩。
test('确认文案对空输入安全', () => {
  assert.equal(uninstallConfirmText(null, ''), '确定要卸载吗？')
  assert.equal(installConfirmText(null, ''), '确定要安装吗？')
  assert.ok(uninstallConfirmText({ id: 'x' }, '').length > 0)
})
