// 计划任务页纯逻辑测试（阶段五 5.2）。
//
// ########## 为什么 import 真模块而不是照抄 ##########
//
// 这是本项目第 53 号坑位的纪律：测试若把逻辑照抄一遍，
// 组件改了测试照样全绿——锁住的是副本而不是真正运行的代码。
//
// 因此这里 import 的就是 CronView.vue 实际使用的那份实现。
//
// 本文件的另一条主线是**常量一致性**：ACTION_LABEL / OUTCOME_META /
// LOG_STATUS_META / 三个字节上限，这些值与 Go 侧一字不差才对得上。
// 界面把「失败的一次执行」显示成绿色，比少一个字段严重得多。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CRON_READ,
  CRON_WRITE,
  canWrite,
  MAX_COMMAND_BYTES,
  MAX_COMMENT_BYTES,
  MAX_EXPR_BYTES,
  byteLength,
  EXPR_EXAMPLES,
  looksLikeExpr,
  LOG_STATUS_META,
  logStatusMeta,
  exitText,
  ACTION_LABEL,
  actionLabel,
  OUTCOME_META,
  outcomeMeta,
  formatRunTime,
  formatTimeFull,
  relativeText,
  nextRunText,
  jobTagList,
  summarizeJobs,
  filterJobs,
  expectedIds,
  validateForm,
  commandPreview,
  deleteConfirmText,
  saveConfirmText,
  MODE_LABEL,
  modeLabel,
  healthAlert,
  targetWarning,
  backupsHint,
  errorText,
  resultNotice,
  restoreCommandOf,
} from './cronLogic.js'

// 固定时刻：所有相对时间的断言都必须注入时钟（逻辑里不读 Date.now）。
const NOW = new Date('2026-03-05T10:00:00')

// ---------------------------------------------------------------------------
// 常量与后端一致性
// ---------------------------------------------------------------------------

test('权限常量与 internal/cron/permission.go 一致', () => {
  assert.equal(CRON_READ, 'cron.read')
  assert.equal(CRON_WRITE, 'cron.write')
})

test('字节上限与 internal/cron/validate.go 一致', () => {
  assert.equal(MAX_COMMAND_BYTES, 900)
  assert.equal(MAX_COMMENT_BYTES, 200)
  assert.equal(MAX_EXPR_BYTES, 200)
})

test('操作名与 internal/cron/permission.go 的 Action 一致', () => {
  assert.deepEqual(Object.keys(ACTION_LABEL).sort(), ['create', 'delete', 'list', 'logs', 'update'])
  assert.equal(actionLabel('create'), '新增任务')
  assert.equal(actionLabel(''), '—')
  // 未知值原样返回：将来后端加动作时，界面要能看出"这是新东西"，
  // 而不是显示一个张冠李戴的中文名。
  assert.equal(actionLabel('future-thing'), 'future-thing')
})

test('审计三态与 internal/cron/audit.go 一致', () => {
  assert.deepEqual(Object.keys(OUTCOME_META).sort(), ['allowed', 'denied', 'failed'])
  assert.equal(outcomeMeta('denied').type, 'error')
  assert.equal(outcomeMeta('').type, 'default')
})

test('日志状态与 logtail.go 的四种 status 一致', () => {
  assert.deepEqual(Object.keys(LOG_STATUS_META).sort(), ['failed', 'ok', 'running', 'unknown'])
  // running 必须是 warning：它的真意是「没看到结束标记」，
  // 显示成正常会让人以为一个三天前被 OOM kill 的任务还在跑。
  assert.equal(logStatusMeta('running').type, 'warning')
  assert.equal(logStatusMeta('ok').type, 'success')
  assert.equal(logStatusMeta('failed').type, 'error')
  assert.equal(logStatusMeta(undefined).label, '无法判定')
})

test('exitText 不把「没取到结束标记」显示成退出码 -1', () => {
  assert.equal(exitText({ exit: 0 }), 'exit=0')
  assert.equal(exitText({ exit: 2 }), 'exit=2')
  assert.equal(exitText({ exit: -1 }), '无结束标记')
  assert.equal(exitText({}), '无结束标记')
  assert.equal(exitText(null), '—')
})

test('存取模式名与 ModeCrontab / ModeFile 一致', () => {
  assert.equal(MODE_LABEL.crontab, '系统 crontab')
  assert.equal(MODE_LABEL.file, '隔离文件模式')
  assert.equal(modeLabel('file'), '隔离文件模式')
  assert.equal(modeLabel(undefined), '未知')
})

// ---------------------------------------------------------------------------
// 权限与字节数
// ---------------------------------------------------------------------------

test('canWrite 只认 cron.write', () => {
  assert.equal(canWrite(['cron.read', 'cron.write']), true)
  assert.equal(canWrite(['cron.read']), false)
  assert.equal(canWrite([]), false)
  assert.equal(canWrite(undefined), false)
  assert.equal(canWrite(null), false)
  // 大小写不敏感（后端 Granted 的比对也是 EqualFold）
  assert.equal(canWrite(['CRON.WRITE']), true)
})

test('byteLength 按 UTF-8 字节而非字符计数', () => {
  assert.equal(byteLength('abc'), 3)
  // 中文 3 字节/字：用字符数判上限会放行 3 倍超限的内容
  assert.equal(byteLength('备份'), 6)
  assert.equal(byteLength(''), 0)
  assert.equal(byteLength(null), 0)
})

// ---------------------------------------------------------------------------
// 表达式：只做形态判断，不做语义校验
// ---------------------------------------------------------------------------

test('EXPR_EXAMPLES 每条都是 5 段式或 @ 别名', () => {
  assert.ok(EXPR_EXAMPLES.length >= 10, '示例太少不构成有效输入引导')
  const seen = new Set()
  for (const e of EXPR_EXAMPLES) {
    assert.ok(!seen.has(e.expr), `示例重复：${e.expr}`)
    seen.add(e.expr)
    assert.equal(looksLikeExpr(e.expr), true, `示例不合法：${e.expr}`)
    assert.ok(e.label, `示例缺少说明：${e.expr}`)
  }
})

test('looksLikeExpr 只做廉价形态检查', () => {
  assert.equal(looksLikeExpr('*/5 * * * *'), true)
  assert.equal(looksLikeExpr('  0 3 * * 0  '), true)
  assert.equal(looksLikeExpr('@daily'), true)
  assert.equal(looksLikeExpr('@daily x'), false) // @ 别名不带参数
  assert.equal(looksLikeExpr('*/'), false)       // 输入中途，不值得发请求
  assert.equal(looksLikeExpr('* * *'), false)
  assert.equal(looksLikeExpr(''), false)
  assert.equal(looksLikeExpr(null), false)
  // 注意：语义错误（0 99 * * *）它放行——那是后端的职责，
  // 这里抢着判断就会出现两份互相矛盾的校验器。
  assert.equal(looksLikeExpr('0 99 * * *'), true)
})

// ---------------------------------------------------------------------------
// 时间展示
// ---------------------------------------------------------------------------

test('formatRunTime 与 formatTimeFull 的降级路径', () => {
  const iso = '2026-03-05T18:30:00Z'
  assert.match(formatRunTime(iso), /^\d{2}-\d{2} \d{2}:\d{2}$/)
  assert.match(formatTimeFull(iso), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
  assert.equal(formatRunTime(''), '—')
  assert.equal(formatRunTime('not-a-date'), 'not-a-date') // 原样返回更易发现出错
})

test('relativeText 覆盖分钟/小时/天四档，且接受注入的时钟', () => {
  assert.equal(relativeText('2026-03-05T10:02:00', NOW), '2 分钟后')
  assert.equal(relativeText('2026-03-05T11:00:00', NOW), '1 小时后')
  assert.equal(relativeText('2026-03-05T11:30:00', NOW), '1 小时 30 分后')
  assert.equal(relativeText('2026-03-08T10:00:00', NOW), '3 天后')
  assert.equal(relativeText('2026-03-05T09:59:00', NOW), '即将执行')
  assert.equal(relativeText('', NOW), '')
  assert.equal(relativeText('x', NOW), '')
  assert.equal(relativeText('2026-03-05T10:02:00', 'nonsense'), '')
  // 数字传参也要能用（调用处可能拿的是 timestamp）
  assert.equal(relativeText('2026-03-05T10:05:00', NOW.getTime()), '5 分钟后')
})

test('nextRunText 区分三种「没有下次执行」的完全不同含义', () => {
  assert.equal(
    nextRunText({ reboot: true, valid: true }, NOW),
    '@reboot：仅系统启动时执行',
  )
  assert.equal(
    nextRunText({ valid: false, expression: 'bad' }, NOW),
    '表达式非法，不会被执行',
  )
  assert.equal(nextRunText({ valid: true, next_run_has: false }, NOW), '5 年内无匹配时间')
  // 绝对时间 + 相对时间一起给：用户真正想问的是「还有多久」。
  assert.equal(
    nextRunText({ valid: true, next_run_has: true, next_run: '2026-03-05T10:10:00' }, NOW),
    '03-05 10:10（10 分钟后）',
  )
  assert.equal(nextRunText(null), '—')
})

// ---------------------------------------------------------------------------
// 列表辅助
// ---------------------------------------------------------------------------

test('jobTagList 标出「外部添加」并如实标出异常', () => {
  const labels = (j) => jobTagList(j).map((t) => t.label)
  assert.deepEqual(labels({ managed: true, valid: true }), ['面板管理'])
  // 「外部添加」必须独立标记：编辑它即收编，不提前说清用户会以为只是改时间
  assert.deepEqual(labels({ managed: false, valid: true }), ['外部添加'])
  assert.deepEqual(labels({ managed: false, valid: false }), ['表达式非法', '外部添加'])
  assert.ok(labels({ managed: true, valid: true, command_missing: true }).includes('命令不可读'))
  assert.deepEqual(jobTagList(null), [])
})

test('summarizeJobs 的统计始终基于全量（不受过滤影响）', () => {
  const s = summarizeJobs([
    { managed: true, valid: true },
    { managed: false, valid: false },
    { managed: true, valid: true, reboot: true },
    null,
  ])
  // total 是列表长度（null 是后端不会产生的脏数据，只做防御性跳过，
  // 但不再伪造一条统计——脏数据本身就该在数字上露出一角）。
  assert.deepEqual(s, { total: 4, managed: 2, external: 1, invalid: 1, reboot: 1 })
  assert.deepEqual(summarizeJobs(undefined).total, 0)
})

test('filterJobs 只影响显示，空关键词放行全部', () => {
  const jobs = [
    { id: 'a1', expression: '*/5 * * * *', command: 'backup.sh', comment: '备份' },
    { id: 'b2', expression: '0 3 * * 0', command: 'cleanup.sh', comment: '' },
  ]
  assert.equal(filterJobs(jobs, {}).length, 2)
  assert.equal(filterJobs(jobs, { keyword: 'BACKUP' }).length, 1)
  assert.equal(filterJobs(jobs, { keyword: '备份' })[0].id, 'a1')
  assert.equal(filterJobs(jobs, { keyword: 'zzz' }).length, 0)
  assert.deepEqual(filterJobs(null, {}), [])
})

test('expectedIds 收集全部 id（乐观并发断言的输入）', () => {
  assert.deepEqual(expectedIds([{ id: 'a' }, { id: 'b' }, {}]), ['a', 'b'])
  assert.deepEqual(expectedIds([]), [])
  assert.deepEqual(expectedIds(null), [])
})

// ---------------------------------------------------------------------------
// 表单校验：只拦后端也会拦的问题
// ---------------------------------------------------------------------------

const writeStatus = { available: true, permissions: ['cron.read', 'cron.write'] }

test('validateForm 拦住空值、超限、换行与制表符', () => {
  assert.match(validateForm({ status: writeStatus }), /cron 表达式/)
  assert.match(
    validateForm({ expression: '* * * * *', status: writeStatus }),
    /执行的命令/,
  )
  assert.match(
    validateForm({ expression: '* * *', command: 'x', status: writeStatus }),
    /5 段/,
  )
  assert.match(
    validateForm({ expression: '* * * * *', command: 'a\nb', status: writeStatus }),
    /两条任务/,
  )
  assert.match(
    validateForm({ expression: '* * * * *', command: 'a\tb', status: writeStatus }),
    /制表符/,
  )
  assert.match(
    validateForm({
      expression: '* * * * *',
      command: 'x'.repeat(MAX_COMMAND_BYTES + 1),
      status: writeStatus,
    }),
    /静默忽略/,
  )
  assert.match(
    validateForm({
      expression: '* * * * *',
      command: 'ok',
      comment: 'c'.repeat(MAX_COMMENT_BYTES + 1),
      status: writeStatus,
    }),
    /备注超过/,
  )
  // 合法输入放行
  assert.equal(
    validateForm({ expression: '*/5 * * * *', command: 'backup.sh', comment: 'x', status: writeStatus }),
    '',
  )
})

test('validateForm 拦住「环境不可用」与「无写权限」', () => {
  assert.match(
    validateForm({
      expression: '* * * * *',
      command: 'x',
      status: { available: false, reason: '找不到 crontab 命令' },
    }),
    /找不到 crontab 命令/,
  )
  assert.match(
    validateForm({ expression: '* * * * *', command: 'x', status: { available: true, permissions: [] } }),
    /cron\.write/,
  )
})

// ---------------------------------------------------------------------------
// 确认文案：必须写明具体命令（计划明确要求）
// ---------------------------------------------------------------------------

test('deleteConfirmText 写明表达式与命令原文', () => {
  const text = deleteConfirmText({
    expression: '30 2 * * *',
    human: '每天定时执行',
    command: '/usr/local/bin/backup.sh --all',
    comment: '数据库备份',
    managed: true,
  })
  assert.match(text, /30 2 \* \* \*/)
  assert.match(text, /\/usr\/local\/bin\/backup\.sh --all/)
  assert.match(text, /数据库备份/)
  assert.match(text, /每天定时执行/)
  assert.match(text, /不可撤销/)
  assert.doesNotMatch(text, /外部添加/)
})

test('deleteConfirmText 对外部任务额外警告，且对空任务不崩', () => {
  assert.match(deleteConfirmText({ managed: false, command: 'x' }), /外部添加/)
  assert.equal(deleteConfirmText(null), '确定删除该任务吗？')
})

test('commandPreview 截断超长命令但保留总长信息', () => {
  assert.equal(commandPreview(''), '（空）')
  assert.equal(commandPreview('short'), 'short')
  const long = 'x'.repeat(300)
  const p = commandPreview(long, 200)
  assert.match(p, /共 300 字符/)
  assert.ok(p.length < 260)
})

test('saveConfirmText 列出后端算出的真实执行时间', () => {
  const text = saveConfirmText({
    expression: '0 3 * * 0',
    command: 'rmdir /tmp/x',
    preview: { expression: '0 3 * * 0', human: '每周定时执行', runs: ['2026-03-08T03:00:00+08:00'] },
  })
  assert.match(text, /每周定时执行/)
  assert.match(text, /接下来 1 次执行/)
  assert.match(text, /2026/)
  assert.match(text, /审计日志/)
})

test('saveConfirmText 说明 @ 别名会被展开，并解释收编的后果', () => {
  const text = saveConfirmText({
    expression: '@daily',
    command: 'x',
    preview: { expression: '0 0 * * *', runs: [] },
    adopt: true,
  })
  assert.match(text, /实际写入：0 0 \* \* \*/)
  assert.match(text, /收编/)
  assert.match(text, /标记注释/)
  assert.match(text, /原始行/)
})

test('saveConfirmText 如实交代 @reboot 与永不匹配的表达式', () => {
  assert.match(
    saveConfirmText({ expression: '@reboot', command: 'x', preview: { reboot: true, runs: [] } }),
    /系统启动时执行一次/,
  )
  assert.match(
    saveConfirmText({
      expression: '0 0 30 feb *',
      command: 'x',
      preview: { runs: [], reason: '表达式在 5 年内没有任何匹配时间' },
    }),
    /5 年内没有任何匹配时间/,
  )
})

// ---------------------------------------------------------------------------
// 状态卡片：隔离模式必须醒目
// ---------------------------------------------------------------------------

test('healthAlert 把隔离文件模式显示成警示而不是绿色就绪', () => {
  const h = healthAlert({ mode: 'file', available: true, target: '隔离文件 /tmp/x' })
  assert.equal(h.type, 'warning')
  assert.match(h.label, /隔离文件模式/)
  // 若这里显示成"已就绪"，用户会以为任务已生效，
  // 半夜备份没跑才发现面板一直在写临时文件。
  // 「不会改动系统 crontab」写在 label 上，detail 说明用途与出路。
  assert.match(h.label, /不会改动系统 crontab/)
  assert.match(h.detail, /仅用于开发、验证与 CI/)
  assert.match(h.detail, /-cron-file/)
})

test('healthAlert 区分不可用与就绪，缺状态时不崩', () => {
  const off = healthAlert({ mode: 'crontab', available: false, reason: '找不到 crontab' })
  assert.equal(off.type, 'warning')
  assert.match(off.detail, /找不到 crontab/)
  assert.match(off.detail, /其它功能不受影响/)
  assert.equal(healthAlert({ mode: 'crontab', available: true, target: 'root 的 crontab' }).type, 'success')
  assert.equal(healthAlert(null).type, 'default')
})

test('targetWarning 点明以什么身份执行，隔离模式下不重复警告', () => {
  assert.match(
    targetWarning({ mode: 'crontab', user: 'root', target: '用户 root 的 crontab' }),
    /root 身份/,
  )
  assert.equal(targetWarning({ mode: 'file', target: '隔离文件 x' }), '')
  assert.equal(targetWarning(null), '')
})

test('backupsHint 说明备份目录与恢复方法', () => {
  assert.match(backupsHint({ data_dir: '/var/lib/lipanel/cron', backups: [] }), /backups/)
  const withBak = backupsHint({ data_dir: '/d', backups: ['crontab.b1.bak', 'crontab.last.bak'] })
  assert.match(withBak, /crontab\.b1\.bak/)
  assert.match(withBak, /crontab <备份文件>/)
  assert.equal(backupsHint(null), '')
})

// ---------------------------------------------------------------------------
// 错误呈现：回滚失败必须把备份路径顶到脸上
// ---------------------------------------------------------------------------

test('errorText 在回滚失败时给出可执行的恢复命令', () => {
  const err = new Error('保存 crontab 失败：disk full')
  err.rollbackError = '回滚同样失败'
  err.backupPath = '/var/lib/lipanel/cron/backups/crontab.X.bak'
  const t = errorText(err)
  assert.match(t, /自动回滚也失败/)
  assert.match(t, /crontab \/var\/lib\/lipanel\/cron\/backups\/crontab\.X\.bak/)
  assert.match(t, /disk full/)
})

test('errorText 区分并发冲突、回滚成功与已回滚', () => {
  const conflict = new Error('任务已被外部修改')
  conflict.editConflict = true
  assert.match(errorText(conflict), /刷新列表/)

  const rolled = new Error('写入 crontab 失败')
  rolled.rolledBack = true
  assert.match(errorText(rolled), /改动已自动回滚，crontab 仍是改动前的内容/)

  const denied = new Error('权限不足')
  denied.hint = '需要 cron.write'
  assert.equal(errorText(denied), '权限不足（需要 cron.write）')

  assert.equal(errorText(null), '未知错误')
})

test('resultNotice 汇总备份路径与警告', () => {
  const n = resultNotice(
    { backup_path: '/b/c.bak', warning: '日志已截断', after_count: 3 },
    '任务已保存',
  )
  assert.match(n, /任务已保存/)
  assert.match(n, /\/b\/c\.bak/)
  assert.match(n, /日志已截断/)
  assert.match(n, /共 3 条/)
  assert.equal(resultNotice(null, '完成'), '完成')
})

test('restoreCommandOf 拼出可直接粘贴的恢复命令', () => {
  assert.equal(restoreCommandOf('/b/x.bak'), 'crontab /b/x.bak')
  assert.equal(restoreCommandOf(''), '')
})
