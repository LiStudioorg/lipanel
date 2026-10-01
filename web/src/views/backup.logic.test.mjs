// 备份恢复纯逻辑的单测（阶段五 5.3）。
//
// 与 cron.logic.test.mjs、terminal.logic.test.mjs 同一纪律：
// 用 node --test 直接跑**组件真正 import 的那一份模块**，
// 而不是在测试里复制一份逻辑——复制出来的那份一定会在某次改动后漂移。
//
// ########## 这个文件最要紧的两组用例 ##########
//
//   ① 恢复确认的判定与载荷组装
//      —— 它是全前端唯一不可逆操作的"最后一公里"。
//         前端放宽一点，用户就会看到按钮亮着但提交拿到 428；
//         前端放宽太多（比如忽略大小写），就等于把服务端的门槛也绕过去了。
//
//   ② 存储载荷里"空密钥 = 不改动"
//      —— 弄错的后果是"改个名字就把凭证清空"，
//         而症状（下一次备份失败）与动作（改了个名字）之间毫无关联。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ACTION_LABELS,
  FALLBACK_STORAGE_TYPES,
  KEEP_COUNT,
  KEEP_DAYS,
  KEEP_NONE,
  MAX_KEEP_COUNT,
  SOURCE_FILE,
  STATUS_FAILED,
  STATUS_OK,
  STORAGE_LOCAL,
  STORAGE_S3,
  STORAGE_WEBDAV,
  actionLabel,
  archiveStampOf,
  auditRowOf,
  buildRestorePayload,
  canSubmitRestore,
  cronUnavailableHint,
  describeTask,
  emptyStorageForm,
  emptyTaskForm,
  fileRowOf,
  formatTime,
  hasErrors,
  historyRowOf,
  humanBytes,
  humanDuration,
  normalizeStoragePayload,
  normalizeTaskPayload,
  resolveKeepPolicies,
  resolveRestoreTarget,
  resolveStorageTypes,
  restoreConfirmHint,
  restoreConfirmMatches,
  restoreDangerLines,
  restoreRiskLevel,
  restoreRootsHint,
  sanitizePathSegment,
  secretOrNull,
  statusMeta,
  storageCredentialHint,
  storageToForm,
  storageTypeFields,
  storageTypeLabel,
  summarizeStorageUsage,
  taskToForm,
  validateStorageForm,
  validateTaskForm,
} from './backupLogic.js'

// ---------------------------------------------------------------------------
// ① 恢复：确认判定
// ---------------------------------------------------------------------------

test('确认文字必须逐字相等', () => {
  const name = 'nginx 配置备份'

  assert.equal(restoreConfirmMatches(name, 'nginx 配置备份'), true)
  // 大小写不同 → 不通过（后端是严格比对，前端不能自作聪明）
  assert.equal(restoreConfirmMatches(name, 'NGINX 配置备份'), false)
  // 只差一个字 → 不通过
  assert.equal(restoreConfirmMatches(name, 'nginx 配置备'), false)
  // 空 → 不通过
  assert.equal(restoreConfirmMatches(name, ''), false)
  assert.equal(restoreConfirmMatches(name, null), false)
  assert.equal(restoreConfirmMatches(name, undefined), false)
  // 带空白 → 不通过（按钮不能亮；去空白只发生在提交那一刻）
  assert.equal(restoreConfirmMatches(name, ' nginx 配置备份'), false)
  assert.equal(restoreConfirmMatches(name, 'nginx 配置备份 '), false)
  // 任务名为空时任何输入都不通过（不能有"空名字的空任务"通过）
  assert.equal(restoreConfirmMatches('', ''), false)
})

test('恢复按钮的启用条件', () => {
  const preview = { confirm_text: '任务A', total: 3, conflict_count: 1 }

  // 一切就绪
  assert.equal(canSubmitRestore({
    preview, confirmText: '任务A', targetDir: '/var/lib/lipanel/restore/a',
  }), true)

  // 没有预览 → 不能点（用户还没看到会发生什么）
  assert.equal(canSubmitRestore({
    confirmText: '任务A', targetDir: '/x',
  }), false)

  // 没有目标目录 → 不能点
  assert.equal(canSubmitRestore({
    preview, confirmText: '任务A', targetDir: '',
  }), false)

  // 确认文字不对 → 不能点
  assert.equal(canSubmitRestore({
    preview, confirmText: '任务B', targetDir: '/x',
  }), false)

  // 正在恢复中 → 不能重复点
  assert.equal(canSubmitRestore({
    preview, confirmText: '任务A', targetDir: '/x', restoring: true,
  }), false)
})

test('恢复载荷：提交前去掉首尾空白，但内容必须完全相等', () => {
  const p = buildRestorePayload({
    storageId: 'aaaaaaaaaaaa',
    key: 'p/aaaaaaaaaaaa/x.tar.gz',
    targetDir: '  /var/lib/lipanel/restore/a  ',
    confirmText: '  任务A  ',
  })
  assert.equal(p.storage_id, 'aaaaaaaaaaaa')
  assert.equal(p.key, 'p/aaaaaaaaaaaa/x.tar.gz')
  assert.equal(p.target_dir, '/var/lib/lipanel/restore/a')
  assert.equal(p.confirm, true)
  assert.equal(p.confirm_text, '任务A')
})

test('恢复载荷里 confirm 恒为 true', () => {
  // 这个函数只被"用户已经确认过"的路径调用；若它可能产出 false，
  // 后端会返回 428，而用户会以为是自己没点对。
  const p = buildRestorePayload({ storageId: 'a', key: 'k', targetDir: '/x', confirmText: 'n' })
  assert.equal(p.confirm, true)
})

// ---------------------------------------------------------------------------
// ② 恢复：危险文案与风险分档
// ---------------------------------------------------------------------------

test('危险提示必须包含后端文案与具体数字', () => {
  const preview = {
    danger: '恢复会覆盖目标目录里与归档同名的文件，且无法撤销。',
    total: 12,
    conflict_count: 3,
    unsafe_count: 1,
    target_dir: '/var/lib/lipanel/restore/x',
  }
  const lines = restoreDangerLines(preview, '/var/lib/lipanel/restore/x')
  const joined = lines.join('\n')

  // 后端文案必须在（它不能由前端自己编）
  assert.ok(joined.includes('恢复会覆盖目标目录里与归档同名的文件'))
  // 具体数字必须在，否则用户无法判断这次操作有多大影响
  assert.ok(joined.includes('12'))
  assert.ok(joined.includes('3'))
  assert.ok(joined.includes('覆盖'))
  assert.ok(joined.includes('无法撤销'))
  // 不安全条目要如实说会被跳过
  assert.ok(joined.includes('跳过'))
  // 目标目录要写出来
  assert.ok(joined.includes('/var/lib/lipanel/restore/x'))
})

test('没有冲突时要明确说明不会覆盖', () => {
  const lines = restoreDangerLines({ danger: 'd', total: 5, conflict_count: 0 }, '/x')
  const joined = lines.join('\n')
  assert.ok(joined.includes('不会覆盖'), `实际文案：${joined}`)
})

test('空预览不能崩', () => {
  assert.deepEqual(restoreDangerLines(null, ''), [])
  assert.deepEqual(restoreDangerLines({}, ''), [])
})

test('截断的预览要说明', () => {
  const lines = restoreDangerLines({ danger: 'd', total: 900, truncated: true }, '/x')
  assert.ok(lines.join('\n').includes('预览只列出了前一部分'))
})

test('风险分档：有冲突为 high，无冲突为 medium，无条目为 low', () => {
  assert.equal(restoreRiskLevel({ total: 10, conflict_count: 2 }), 'high')
  assert.equal(restoreRiskLevel({ total: 10, conflict_count: 0 }), 'medium')
  assert.equal(restoreRiskLevel({ total: 0 }), 'low')
  assert.equal(restoreRiskLevel(null), 'low')
})

test('确认输入框的提示要带上任务名', () => {
  const hint = restoreConfirmHint({ confirm_text: '任务A' })
  assert.ok(hint.includes('任务A'))
  assert.ok(hint.includes('逐字'))
  // 没有名字时也要给一句可读的提示，而不是空白
  assert.ok(restoreConfirmHint({}).length > 0)
})

// ---------------------------------------------------------------------------
// ③ 存储载荷：空密钥 = 不改动（关键退化防线）
// ---------------------------------------------------------------------------

test('空密钥必须转成 null（不改动），绝不能转成空串', () => {
  const cases = [null, undefined, '', '   ', '\t\n']
  for (const v of cases) {
    assert.equal(secretOrNull(v), null, `输入 ${JSON.stringify(v)} 应转成 null`)
    const p = normalizeStoragePayload({
      name: 's3', type: STORAGE_S3, endpoint: 'http://x', bucket: 'b',
      access_key: 'AKIA', secret_key: v, path_style: true,
    })
    assert.equal(p.secret_key, null,
      `输入 ${JSON.stringify(v)} 时 secret_key 必须是 null（表示不改动）`)
  }
})

test('填了新密钥要原样传上去（去空白）', () => {
  const p = normalizeStoragePayload({
    name: 's3', type: STORAGE_S3, endpoint: 'http://x', bucket: 'b',
    access_key: 'AKIA', secret_key: '  newsecret  ', path_style: true,
  })
  assert.equal(p.secret_key, 'newsecret')
})

test('编辑存储时留空密钥，载荷里仍是 null', () => {
  // 这是最容易出事的场景：改个名字。
  const p = normalizeStoragePayload({
    id: 'aaaaaaaaaaaa',
    name: '改过名字', type: STORAGE_S3, endpoint: 'http://x', bucket: 'b',
    access_key: 'AKIA', secret_key: null, path_style: true,
  })
  assert.equal(p.secret_key, null)
  assert.equal(p.name, '改过名字')
  assert.equal(p.id, 'aaaaaaaaaaaa')
})

test('只带上该类型用得到的字段', () => {
  // 本地存储不该带 endpoint/bucket/密钥
  const local = normalizeStoragePayload({
    name: '本地', type: STORAGE_LOCAL, path: '/data/backups',
    endpoint: 'http://should-not-appear', bucket: 'nope',
    access_key: 'AKIA', secret_key: 'leak',
  })
  assert.equal(local.path, '/data/backups')
  assert.equal(local.endpoint, '')
  assert.equal(local.bucket, '')
  assert.equal(local.access_key, '')
  assert.equal(local.secret_key, null)

  // WebDAV 不该带 bucket/access_key
  const dav = normalizeStoragePayload({
    name: 'dav', type: STORAGE_WEBDAV, endpoint: 'https://dav.example.com/dav',
    username: 'alice', password: 'pw', bucket: 'nope', access_key: 'AKIA',
  })
  assert.equal(dav.endpoint, 'https://dav.example.com/dav')
  assert.equal(dav.username, 'alice')
  assert.equal(dav.password, 'pw')
  assert.equal(dav.bucket, '')
  assert.equal(dav.access_key, '')
  assert.equal(dav.secret_key, null)
})

test('存储表单回填时密钥一律留空', () => {
  const form = storageToForm({
    id: 'aaaaaaaaaaaa', name: 's3', type: STORAGE_S3,
    endpoint: 'http://x', bucket: 'b', access_key: 'AKIA',
    secret_key: 'should-never-be-here',
    secret_tail: 'tail',
  })
  assert.equal(form.secret_key, null)
  // 尾号也不能被填进可编辑的输入框
  assert.notEqual(form.secret_key, 'tail')
})

test('凭证状态提示回答"我到底配没配"', () => {
  assert.ok(storageCredentialHint({ has_secret: true, secret_tail: 'abcd' }).includes('abcd'))
  assert.ok(storageCredentialHint({ has_secret: false }).includes('未设置'))
  assert.ok(storageCredentialHint({
    has_secret: true, secret_tail: 'abcd',
    has_password: true, password_tail: 'wxyz',
  }).includes('wxyz'))
})

// ---------------------------------------------------------------------------
// ④ 存储表单校验
// ---------------------------------------------------------------------------

test('本地存储必须有绝对路径', () => {
  assert.ok(validateStorageForm({ name: 'n', type: STORAGE_LOCAL, path: '' }).path)
  assert.ok(validateStorageForm({ name: 'n', type: STORAGE_LOCAL, path: 'relative/x' }).path)
  assert.equal(hasErrors(validateStorageForm({
    name: 'n', type: STORAGE_LOCAL, path: '/data/backups',
  })), false)
})

test('S3 必填项与地址格式', () => {
  const base = { name: 'n', type: STORAGE_S3, bucket: 'b', access_key: 'AKIA', secret_key: 's' }

  assert.ok(validateStorageForm({ ...base, endpoint: '' }).endpoint)
  assert.ok(validateStorageForm({ ...base, endpoint: 'ftp://x' }).endpoint)
  assert.ok(validateStorageForm({ ...base, endpoint: 'http://x', bucket: '' }).bucket)
  assert.ok(validateStorageForm({ ...base, endpoint: 'http://x', access_key: '' }).access_key)
  // 新建时必须有密钥
  assert.ok(validateStorageForm({ ...base, endpoint: 'http://x', secret_key: null }).secret_key)
  // 编辑时留空表示沿用旧的 → 不该报错
  assert.equal(hasErrors(validateStorageForm({
    id: 'aaaaaaaaaaaa', name: 'n', type: STORAGE_S3,
    endpoint: 'http://x', bucket: 'b', access_key: 'AKIA', secret_key: null,
  })), false)
})

test('WebDAV 必填项', () => {
  const base = { name: 'n', type: STORAGE_WEBDAV, endpoint: 'https://dav.example.com/dav' }
  assert.ok(validateStorageForm({ ...base, username: '' }).username)
  assert.ok(validateStorageForm({ ...base, username: 'alice', password: null }).password)
  assert.equal(hasErrors(validateStorageForm({
    ...base, username: 'alice', password: 'pw',
  })), false)
})

test('名字不能为空', () => {
  assert.ok(validateStorageForm({ name: '', type: STORAGE_LOCAL, path: '/x' }).name)
  assert.ok(validateStorageForm({ name: '   ', type: STORAGE_LOCAL, path: '/x' }).name)
})

// ---------------------------------------------------------------------------
// ⑤ 任务表单
// ---------------------------------------------------------------------------

test('任务表单默认值选了安全的一端', () => {
  const f = emptyTaskForm()
  // 默认要清理（不清理会让磁盘安静地涨到满）
  assert.equal(f.keep_policy, KEEP_COUNT)
  assert.ok(f.keep_count > 0)
  // 默认启用
  assert.equal(f.enabled, true)
  // 默认凌晨 3 点（业务低峰）
  assert.equal(f.expr, '0 3 * * *')
})

test('任务表单往返不失真', () => {
  const task = {
    id: 'aaaaaaaaaaaa', name: 'n', type: 'full', source_type: 'file',
    source_path: '/etc/nginx/nginx.conf', storage_id: 'bbbbbbbbbbbb',
    prefix: 'web', expr: '30 4 * * 1', comment: 'c',
    keep_policy: KEEP_DAYS, keep_days: 14, enabled: false,
  }
  const form = taskToForm(task)
  assert.equal(form.source_type, 'file')
  assert.equal(form.keep_policy, KEEP_DAYS)
  assert.equal(form.keep_days, 14)
  assert.equal(form.enabled, false)

  const payload = normalizeTaskPayload(form)
  assert.equal(payload.name, 'n')
  assert.equal(payload.source_type, 'file')
  assert.equal(payload.source_path, '/etc/nginx/nginx.conf')
  assert.equal(payload.keep_policy, KEEP_DAYS)
  assert.equal(payload.keep_days, 14)
  assert.equal(payload.keep_count, 0)
  assert.equal(payload.enabled, false)
})

test('任务载荷里 enabled 恒为布尔值（不能省略）', () => {
  // 后端用 *bool 承接：**省略 = 启用**。若前端漏掉这个字段，
  // 用户"停用任务"的操作就会被读成"启用"，而界面上它看起来已经停了。
  assert.equal(normalizeTaskPayload({ enabled: false }).enabled, false)
  assert.equal(normalizeTaskPayload({ enabled: true }).enabled, true)
  // 没给时按启用（与后端默认一致）
  assert.equal(normalizeTaskPayload({}).enabled, true)
})

test('保留策略只带相关的数值字段', () => {
  const byCount = normalizeTaskPayload({ keep_policy: KEEP_COUNT, keep_count: 5, keep_days: 999 })
  assert.equal(byCount.keep_count, 5)
  assert.equal(byCount.keep_days, 0, '选了按份数时不该塞天数')

  const byDays = normalizeTaskPayload({ keep_policy: KEEP_DAYS, keep_count: 999, keep_days: 7 })
  assert.equal(byDays.keep_days, 7)
  assert.equal(byDays.keep_count, 0, '选了按天数时不该塞份数')

  const none = normalizeTaskPayload({ keep_policy: KEEP_NONE, keep_count: 5, keep_days: 7 })
  assert.equal(none.keep_count, 0)
  assert.equal(none.keep_days, 0)
})

test('expected_ids 只在给出时才带上', () => {
  assert.equal(normalizeTaskPayload({}).expected_ids, undefined)
  const withIds = normalizeTaskPayload({ expected_ids: ['aaaaaaaaaaaa'] })
  assert.deepEqual(withIds.expected_ids, ['aaaaaaaaaaaa'])
})

test('任务表单校验：明显的格式问题要早点说', () => {
  assert.ok(validateTaskForm({}).name)
  assert.ok(validateTaskForm({ name: 'n' }).source_path)
  assert.ok(validateTaskForm({ name: 'n', source_path: 'relative' }).source_path)
  assert.ok(validateTaskForm({ name: 'n', source_path: '/x' }).storage_id)
  assert.ok(validateTaskForm({
    name: 'n', source_path: '/x', storage_id: 'aaaaaaaaaaaa', expr: '',
  }).expr)

  assert.equal(hasErrors(validateTaskForm({
    name: 'n', source_path: '/x', storage_id: 'aaaaaaaaaaaa',
    expr: '0 3 * * *', keep_policy: KEEP_COUNT, keep_count: 7,
  })), false)
})

test('保留份数的上下界', () => {
  const base = {
    name: 'n', source_path: '/x', storage_id: 'aaaaaaaaaaaa', expr: '0 3 * * *',
    keep_policy: KEEP_COUNT,
  }
  assert.ok(validateTaskForm({ ...base, keep_count: 0 }).keep_count)
  assert.ok(validateTaskForm({ ...base, keep_count: -1 }).keep_count)
  assert.ok(validateTaskForm({ ...base, keep_count: MAX_KEEP_COUNT + 1 }).keep_count)
  assert.equal(hasErrors(validateTaskForm({ ...base, keep_count: 1 })), false)
})

test('前缀不能越界成绝对路径', () => {
  const base = {
    name: 'n', source_path: '/x', storage_id: 'aaaaaaaaaaaa',
    expr: '0 3 * * *', keep_policy: KEEP_NONE,
  }
  assert.ok(validateTaskForm({ ...base, prefix: '/abs' }).prefix)
  assert.ok(validateTaskForm({ ...base, prefix: 'a/../b' }).prefix)
  assert.ok(validateTaskForm({ ...base, prefix: 'a//b' }).prefix)
  assert.equal(hasErrors(validateTaskForm({ ...base, prefix: 'a/b' })), false)
})

// ---------------------------------------------------------------------------
// ⑥ 状态描述
// ---------------------------------------------------------------------------

test('任务状态摘要覆盖四种"不会跑"的情况', () => {
  // 存储被删
  assert.equal(describeTask({ storage_missing: true }).type, 'error')
  // 源不存在
  assert.equal(describeTask({ source_exists: false }).type, 'error')
  // 表达式非法
  assert.equal(describeTask({ valid: false, invalid_reason: 'bad' }).type, 'error')
  // 未挂到 crontab
  assert.equal(describeTask({ valid: true, source_exists: true, cron_managed: false }).type, 'warning')
  // 已停用
  assert.equal(describeTask({
    valid: true, source_exists: true, cron_managed: false, enabled: false,
  }).type, 'warning')
})

test('上次失败要显示失败原因', () => {
  const d = describeTask({
    valid: true, source_exists: true, cron_managed: true, enabled: true,
    last_status: STATUS_FAILED,
    last: { error: '磁盘满了' },
  })
  assert.equal(d.type, 'error')
  assert.ok(d.text.includes('磁盘满了'))
})

test('从未执行过要提示', () => {
  const d = describeTask({
    valid: true, source_exists: true, cron_managed: true, enabled: true,
  })
  assert.equal(d.type, 'warning')
  assert.ok(d.text.includes('尚未执行'))
})

test('一切正常时是 success', () => {
  const d = describeTask({
    valid: true, source_exists: true, cron_managed: true, enabled: true,
    last_status: STATUS_OK, last: { status: STATUS_OK },
  })
  assert.equal(d.type, 'success')
})

test('执行中优先于其它状态显示', () => {
  const d = describeTask({
    valid: true, source_exists: true, cron_managed: true, enabled: true, running: true,
  })
  assert.equal(d.type, 'info')
})

// ---------------------------------------------------------------------------
// ⑦ 展示辅助
// ---------------------------------------------------------------------------

test('humanBytes 的边界', () => {
  assert.equal(humanBytes(0), '0 B')
  assert.equal(humanBytes(512), '512 B')
  assert.equal(humanBytes(1024), '1.00 KB')
  assert.equal(humanBytes(1536), '1.50 KB')
  assert.equal(humanBytes(1024 * 1024), '1.00 MB')
  assert.equal(humanBytes(10 * 1024 * 1024), '10.0 MB')
  assert.equal(humanBytes(150 * 1024 * 1024), '150 MB')
  assert.equal(humanBytes(1024 ** 3), '1.00 GB')
  // 非法输入不能变成 NaN
  assert.equal(humanBytes(-1), '—')
  assert.equal(humanBytes('abc'), '—')
  assert.equal(humanBytes(null), '0 B')
})

test('humanDuration 的边界', () => {
  assert.equal(humanDuration(500), '500 毫秒')
  assert.equal(humanDuration(1500), '1.5 秒')
  assert.equal(humanDuration(90000), '1 分 30 秒')
  assert.equal(humanDuration(3700000), '1 小时 1 分')
  assert.equal(humanDuration(-1), '—')
})

test('formatTime 同时给绝对与相对时间', () => {
  const now = Date.parse('2026-03-05T12:00:00+08:00')
  const out = formatTime('2026-03-05T10:00:00+08:00', now)
  assert.ok(out.includes('2026-03-05'), `实际：${out}`)
  assert.ok(out.includes('2 小时'), `实际：${out}`)
  assert.ok(out.includes('前'), `实际：${out}`)
  // 空值与非法值不能崩
  assert.equal(formatTime(''), '—')
  assert.equal(formatTime('not-a-date', now), 'not-a-date')
})

test('statusMeta 给出中文标签与颜色', () => {
  assert.equal(statusMeta(STATUS_OK).type, 'success')
  assert.equal(statusMeta(STATUS_FAILED).type, 'error')
  // 跳过不是错误：并发跳过是主动的自我保护，标红会误导
  assert.equal(statusMeta('skipped').type, 'warning')
  assert.equal(statusMeta('unknown-thing').label, 'unknown-thing')
})

// ---------------------------------------------------------------------------
// ⑧ 表格行
// ---------------------------------------------------------------------------

test('历史行：只有成功且有归档的才能下载', () => {
  const ok = historyRowOf({
    id: 'aaaaaaaaaaaa', status: STATUS_OK, archive_key: 'k/x.tar.gz',
    archive_bytes: 2048, started_at: '2026-03-05T10:00:00+08:00',
    duration_ms: 5000, file_count: 3, trigger: 'cron',
  })
  assert.equal(ok.downloadable, true)
  assert.equal(ok.status_type, 'success')
  assert.equal(ok.trigger, '定时')
  assert.equal(ok.size_text, '2.00 KB')
  assert.equal(ok.duration, '5.0 秒')

  // 失败的记录没有归档可下载
  const failed = historyRowOf({ status: STATUS_FAILED, error: 'boom' })
  assert.equal(failed.downloadable, false)
  assert.equal(failed.status_type, 'error')
  assert.equal(failed.error, 'boom')
  // 失败时也要有可读的大小占位，而不是 "null"
  assert.equal(failed.size_text, '—')

  // 空值不能崩
  assert.equal(historyRowOf(null), null)
})

test('文件行：任务被删掉时也要有可读的名字', () => {
  const row = fileRowOf({
    key: 'p/aaaaaaaaaaaa/aaaaaaaaaaaa-20260305-100000.tar.gz',
    name: 'aaaaaaaaaaaa-20260305-100000.tar.gz',
    size: 1024 * 1024, storage_id: 'bbbbbbbbbbbb',
  })
  assert.equal(row.task_name, '（任务已删除）')
  assert.equal(row.stamp, '2026-03-05 10:00:00')
  assert.equal(row.size_text, '1.00 MB')
})

test('archiveStampOf 解析不出就不猜', () => {
  assert.equal(archiveStampOf('p/a/a-20260305-100000.tar.gz'), '2026-03-05 10:00:00')
  assert.equal(archiveStampOf('p/a/manual-upload.tar.gz'), '')
  assert.equal(archiveStampOf(''), '')
  // 不能把别处的 8-6 位数字误当成时间戳
  assert.equal(archiveStampOf('p/a/12345678-901234.zip'), '')
})

test('审计行带上动作中文名与结果', () => {
  const row = auditRowOf({
    seq: 1, action: 'run', outcome: 'allowed', user: 'admin',
    client_ip: '127.0.0.1', archive_bytes: 4096, duration_ms: 1200,
    task_name: '备份', time: '2026-03-05T10:00:00+08:00',
  })
  assert.equal(row.action_label, '立即执行')
  assert.equal(row.outcome_label, '允许')
  assert.equal(row.outcome_type, 'success')
  assert.equal(row.size_text, '4.00 KB')
  assert.ok(actionLabel('restore').includes('恢复'))
  // 未知动作原样显示，不吞掉
  assert.equal(actionLabel('weird'), 'weird')
})

test('审计动作的中文名是完整的一张表', () => {
  // 后端每加一个动作，这里就该多一项；缺了会显示英文标识
  for (const key of ['run', 'restore', 'delete', 'download']) {
    assert.ok(ACTION_LABELS[key], `缺少动作 ${key} 的中文名`)
  }
})

// ---------------------------------------------------------------------------
// ⑨ 存储占用与恢复目标
// ---------------------------------------------------------------------------

test('summarizeStorageUsage 按存储汇总', () => {
  const s = summarizeStorageUsage([
    { storage_id: 'a', size: 100 },
    { storage_id: 'a', size: 200 },
    { storage_id: 'b', size: 50 },
  ])
  assert.equal(s.total, 3)
  assert.equal(s.totalBytes, 350)
  assert.equal(s.byStorage.get('a').count, 2)
  assert.equal(s.byStorage.get('a').bytes, 300)
  assert.equal(s.byStorage.get('b').count, 1)

  const empty = summarizeStorageUsage(null)
  assert.equal(empty.total, 0)
})

test('恢复目标默认值来自后端的白名单', () => {
  // 管理员改过白名单时，前端不能写死一个必然被拒的路径
  const target = resolveRestoreTarget({ restore_roots: ['/srv/restore'] }, '我的备份')
  assert.equal(target, '/srv/restore/我的备份')
  // 末尾斜杠不该产生双斜杠
  assert.equal(resolveRestoreTarget({ restore_roots: ['/srv/restore/'] }, 'x'), '/srv/restore/x')
  // 没有白名单时返回空（让用户自己填，而不是给一个错的默认值）
  assert.equal(resolveRestoreTarget({}, 'x'), '')
})

test('sanitizePathSegment 去掉路径分隔符', () => {
  assert.equal(sanitizePathSegment('a/b'), 'a-b')
  assert.equal(sanitizePathSegment('a\\b'), 'a-b')
  assert.equal(sanitizePathSegment('  x  '), 'x')
  assert.equal(sanitizePathSegment('..evil'), 'evil')
  assert.equal(sanitizePathSegment(''), '')
})

test('恢复根收紧状态要说清楚', () => {
  const narrow = restoreRootsHint({ restore_roots: ['/var/lib/lipanel/restore'], restore_root_narrow: true })
  assert.ok(narrow.includes('收紧'))
  assert.ok(narrow.includes('-backup-restore-root'))

  const wide = restoreRootsHint({ restore_roots: ['/', '/srv'], restore_root_narrow: false })
  assert.ok(!wide.includes('收紧'))
  assert.ok(wide.includes('/srv'))
})

test('crontab 不可用时给可操作的建议', () => {
  assert.equal(cronUnavailableHint({ cron_available: true }), '')
  const hint = cronUnavailableHint({
    cron_available: false, cron_install_hint: 'apt-get install -y cron',
  })
  assert.ok(hint.includes('apt-get'))
  // 后端没给建议时也要有一句兜底，而不是空白
  assert.ok(cronUnavailableHint({ cron_available: false }).length > 0)
})

// ---------------------------------------------------------------------------
// ⑩ 后端清单的解析
// ---------------------------------------------------------------------------

test('存储类型/保留策略优先用后端给的清单', () => {
  const types = resolveStorageTypes({
    storage_types: [{ type: 'oss', label: '阿里云 OSS', fields: ['endpoint'] }],
  })
  assert.equal(types.length, 1)
  assert.equal(types[0].label, '阿里云 OSS')
  // 后端没给时用兜底（表单仍要能渲染）
  assert.equal(resolveStorageTypes({}).length, FALLBACK_STORAGE_TYPES.length)
  assert.equal(resolveStorageTypes(null).length, FALLBACK_STORAGE_TYPES.length)

  const policies = resolveKeepPolicies({ keep_policies: [{ policy: 'x', label: 'X' }] })
  assert.equal(policies.length, 1)
  assert.ok(resolveKeepPolicies({}).length >= 3)
})

test('存储类型的字段清单能查', () => {
  const fields = storageTypeFields(FALLBACK_STORAGE_TYPES, STORAGE_S3)
  assert.ok(fields.includes('endpoint'))
  assert.ok(fields.includes('secret_key'))
  // 本地存储没有 endpoint
  assert.ok(!storageTypeFields(FALLBACK_STORAGE_TYPES, STORAGE_LOCAL).includes('endpoint'))
  assert.equal(storageTypeLabel(FALLBACK_STORAGE_TYPES, STORAGE_LOCAL), '本地目录')
  // 未知类型不能崩
  assert.deepEqual(storageTypeFields(FALLBACK_STORAGE_TYPES, 'unknown'), [])
})

test('空存储表单的默认值', () => {
  const f = emptyStorageForm()
  assert.equal(f.type, STORAGE_LOCAL)
  assert.equal(f.secret_key, null)
  assert.equal(f.password, null)
  assert.equal(f.path_style, false)
  assert.equal(f.insecure_skip_verify, false)
})

test('源类型常量与后端一致', () => {
  assert.equal(SOURCE_FILE, 'file')
  assert.equal(normalizeTaskPayload({ source_type: 'file' }).source_type, 'file')
  // 未知值兜底成 dir（更常见、也更安全：备份整个目录）
  assert.equal(normalizeTaskPayload({ source_type: 'weird' }).source_type, 'dir')
})
