// 文件管理纯逻辑测试（阶段四 4.2）。
//
// 用 node:test，与 services.logic.test.mjs 同一套约定：
// **不重述实现**，直接 import 组件使用的那一份 fileLogic.js。
//
// 路径函数的用例刻意覆盖"/"根目录这一最容易出错的边界：
// 后端只接受绝对路径，前端拼错一个斜杠就会让整个页面点不动。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  breadcrumbs,
  canRead,
  canWrite,
  deleteConfirmText,
  deleteNeedsRecursive,
  displayTypeText,
  filterEntries,
  formatModTime,
  formatSize,
  isEditable,
  joinPath,
  parentPath,
  removeEntry,
  replaceEntryPath,
  sortEntries,
  typeMeta,
  uploadTooLarge,
  upsertEntry,
  validateNewName,
} from './fileLogic.js'

// ---------------------------------------------------------------------------
// 路径拼接与解析
// ---------------------------------------------------------------------------

test('joinPath 在根目录下不会拼出双斜杠', () => {
  // 这是最容易踩的一个：`${dir}/${name}` 在 dir="/" 时得到 "//etc"，
  // 与后端返回的 "/etc" 字符串不相等，会让"当前目录高亮"等比较全部失效。
  assert.equal(joinPath('/', 'etc'), '/etc')
  assert.equal(joinPath('/home/user', 'file.txt'), '/home/user/file.txt')
  assert.equal(joinPath('/home/user/', 'file.txt'), '/home/user/file.txt')
})

test('joinPath 容忍空值', () => {
  assert.equal(joinPath('', 'a'), 'a')
  assert.equal(joinPath('/a', ''), '/a')
  assert.equal(joinPath(null, undefined), '')
})

test('parentPath 正确处理根目录与普通路径', () => {
  assert.equal(parentPath('/'), '')
  assert.equal(parentPath(''), '')
  assert.equal(parentPath('/etc'), '/')
  assert.equal(parentPath('/etc/nginx'), '/etc')
  assert.equal(parentPath('/etc/nginx/'), '/etc')
  assert.equal(parentPath('/home/user/a/b'), '/home/user/a')
})

test('breadcrumbs 生成可点击的层级路径', () => {
  assert.deepEqual(breadcrumbs('/'), [{ label: '/', path: '/' }])
  assert.deepEqual(breadcrumbs(''), [{ label: '/', path: '/' }])
  assert.deepEqual(breadcrumbs('/etc/nginx'), [
    { label: '/', path: '/' },
    { label: 'etc', path: '/etc' },
    { label: 'nginx', path: '/etc/nginx' },
  ])
})

test('breadcrumbs 跳过重复分隔符产生的空段', () => {
  // 用户可能从别处粘贴来 "//etc///nginx"，不能生成点不动的空节点。
  const crumbs = breadcrumbs('//etc///nginx')
  assert.deepEqual(
    crumbs.map((c) => c.label),
    ['/', 'etc', 'nginx'],
  )
  // 每一段的 path 都必须是绝对路径（后端只接受绝对路径）。
  for (const c of crumbs) {
    assert.ok(c.path.startsWith('/'), `path 应为绝对路径: ${c.path}`)
  }
})

// ---------------------------------------------------------------------------
// 格式化
// ---------------------------------------------------------------------------

test('formatSize 覆盖各量级', () => {
  assert.equal(formatSize(0), '0 B')
  assert.equal(formatSize(512), '512 B')
  assert.equal(formatSize(1024), '1 KB')
  assert.equal(formatSize(1536), '1.5 KB')
  assert.equal(formatSize(1024 * 1024), '1 MB')
  assert.equal(formatSize(1024 * 1024 * 1024), '1 GB')
  assert.equal(formatSize(1024 ** 5), '1 PB')
})

test('formatSize 对非法值返回占位符而不是 NaN', () => {
  // 目录的 size 是 0，但元数据缺失时可能是 undefined：
  // 显示 "NaN B" 会让整列看起来很脏。
  assert.equal(formatSize(undefined), '-')
  assert.equal(formatSize(null), '-')
  assert.equal(formatSize('abc'), '-')
  assert.equal(formatSize(-1), '-')
})

test('formatModTime 处理合法与非法输入', () => {
  assert.equal(formatModTime(''), '-')
  assert.equal(formatModTime(null), '-')
  // 非法字符串原样返回，便于用户看到后端到底给了什么。
  assert.equal(formatModTime('not-a-date'), 'not-a-date')

  const formatted = formatModTime('2026-09-26T20:37:15+08:00')
  assert.match(formatted, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
})

// ---------------------------------------------------------------------------
// 类型与可编辑性
// ---------------------------------------------------------------------------

test('typeMeta 对未知类型安全回落', () => {
  assert.equal(typeMeta('dir').text, '目录')
  assert.equal(typeMeta('file').text, '文件')
  assert.equal(typeMeta('nonsense').text, '其它')
  assert.equal(typeMeta(undefined).text, '其它')
})

test('displayTypeText 明确标出失效链接', () => {
  // 列表里必须一眼看出"这个链接点不开"，否则用户会以为面板坏了。
  assert.equal(displayTypeText({ type: 'symlink', broken: true }), '链接（已失效）')
  assert.equal(displayTypeText({ type: 'symlink', is_dir: true, broken: false }), '链接（指向目录）')
  assert.equal(displayTypeText({ type: 'symlink' }), '链接')
  assert.equal(displayTypeText({ type: 'dir', is_dir: true }), '目录')
})

test('isEditable 直接采用后端的 editable 标记', () => {
  // 前端不重新实现阈值判断：两边阈值不一致会出现
  // "能点开但必然 415"的条目。
  assert.equal(isEditable({ editable: true }), true)
  assert.equal(isEditable({ editable: false }), false)
  assert.equal(isEditable({ editable: true, is_dir: true }), false)
  assert.equal(isEditable({ editable: true, broken: true }), false)
  assert.equal(isEditable(null), false)
})

// ---------------------------------------------------------------------------
// 排序与过滤
// ---------------------------------------------------------------------------

test('sortEntries 目录优先且名称不区分大小写', () => {
  const input = [
    { name: 'zebra.txt', is_dir: false },
    { name: 'Apple.txt', is_dir: false },
    { name: 'mmm', is_dir: true },
    { name: 'BBB', is_dir: true },
  ]
  const sorted = sortEntries(input).map((e) => e.name)
  assert.deepEqual(sorted, ['BBB', 'mmm', 'Apple.txt', 'zebra.txt'])
})

test('sortEntries 不修改原数组', () => {
  const input = [{ name: 'b' }, { name: 'a' }]
  const snapshot = JSON.stringify(input)
  sortEntries(input)
  assert.equal(JSON.stringify(input), snapshot)
})

test('sortEntries 容忍 null 与缺少字段', () => {
  assert.deepEqual(sortEntries(null), [])
  assert.equal(sortEntries([{ name: 'a' }]).length, 1)
})

test('filterEntries 支持关键字与只看目录', () => {
  const entries = [
    { name: 'nginx.conf', is_dir: false },
    { name: 'nginx', is_dir: true },
    { name: 'redis.conf', is_dir: false },
  ]
  assert.equal(filterEntries(entries).length, 3)
  assert.equal(filterEntries(entries, { keyword: 'nginx' }).length, 2)
  assert.equal(filterEntries(entries, { keyword: 'NGINX' }).length, 2)
  assert.equal(filterEntries(entries, { onlyDirs: true }).length, 1)
  assert.equal(filterEntries(entries, { onlyDirs: true, keyword: 'redis' }).length, 0)
  // 空关键字不应过滤掉任何东西。
  assert.equal(filterEntries(entries, { keyword: '   ' }).length, 3)
  assert.deepEqual(filterEntries(null), [])
})

// ---------------------------------------------------------------------------
// 名称校验
// ---------------------------------------------------------------------------

test('validateNewName 接受合法名称', () => {
  for (const name of ['a.txt', '.env', '中文 文件.txt', 'a-b_c.d', 'x'.repeat(255)]) {
    assert.equal(validateNewName(name), '', `应接受: ${name}`)
  }
})

test('validateNewName 拒绝路径与空名称', () => {
  assert.notEqual(validateNewName(''), '')
  assert.notEqual(validateNewName('.'), '')
  assert.notEqual(validateNewName('..'), '')
  assert.notEqual(validateNewName('a/b'), '')
  assert.notEqual(validateNewName('x'.repeat(256)), '')
  assert.notEqual(validateNewName(null), '')
})

test('validateNewName 对首尾空格给出提示', () => {
  // Linux 上合法，但几乎总是误输入。
  assert.notEqual(validateNewName(' name'), '')
  assert.notEqual(validateNewName('name '), '')
})

// ---------------------------------------------------------------------------
// 删除确认
// ---------------------------------------------------------------------------

test('deleteConfirmText 写明具体对象', () => {
  // 弹窗里必须出现被删对象的**名字与路径**，用户点错行时才能立刻发现。
  const fileText = deleteConfirmText({ name: 'a.txt', path: '/home/a.txt', is_dir: false })
  assert.ok(fileText.includes('a.txt'), '应包含文件名')
  assert.ok(fileText.includes('/home/a.txt'), '应包含完整路径')
  assert.ok(fileText.includes('无法恢复'), '应警告不可恢复')

  const dirText = deleteConfirmText({ name: 'data', path: '/home/data', is_dir: true, type: 'dir' })
  assert.ok(dirText.includes('目录'))
  assert.ok(dirText.includes('无法恢复'))

  // 删链接必须说清楚"不会删除它指向的文件"——
  // 否则用户会以为要连带删掉目标。
  const linkText = deleteConfirmText({ name: 'link', path: '/home/link', type: 'symlink' })
  assert.ok(linkText.includes('不会删除它指向的文件'))

  assert.ok(deleteConfirmText(null).length > 0)
})

test('deleteNeedsRecursive 对目录为真、链接为假', () => {
  assert.equal(deleteNeedsRecursive({ is_dir: true, type: 'dir' }), true)
  // 指向目录的链接：删的是链接，不能按"递归删目录"处理。
  assert.equal(deleteNeedsRecursive({ is_dir: true, type: 'symlink' }), false)
  assert.equal(deleteNeedsRecursive({ is_dir: false }), false)
  assert.equal(deleteNeedsRecursive(null), false)
})

// ---------------------------------------------------------------------------
// 本地列表更新
// ---------------------------------------------------------------------------

test('upsertEntry 插入后保持排序', () => {
  const list = [
    { name: 'a.txt', path: '/r/a.txt', is_dir: false },
    { name: 'z.txt', path: '/r/z.txt', is_dir: false },
  ]
  const next = upsertEntry(list, { name: 'm.txt', path: '/r/m.txt', is_dir: false })
  assert.deepEqual(
    next.map((e) => e.name),
    ['a.txt', 'm.txt', 'z.txt'],
  )
})

test('upsertEntry 同路径是替换而不是重复插入', () => {
  const list = [{ name: 'a.txt', path: '/r/a.txt', is_dir: false }]
  const next = upsertEntry(list, { name: 'a.txt', path: '/r/a.txt', is_dir: false, size: 99 })
  assert.equal(next.length, 1)
  assert.equal(next[0].size, 99)
})

test('upsertEntry 对缺 path 的输入不炸', () => {
  assert.deepEqual(upsertEntry(null, null), [])
  assert.deepEqual(upsertEntry([{ name: 'a', path: '/a' }], {}).length, 1)
})

test('removeEntry 按路径删除', () => {
  const list = [
    { name: 'a', path: '/r/a' },
    { name: 'b', path: '/r/b' },
  ]
  assert.deepEqual(removeEntry(list, '/r/a').map((e) => e.name), ['b'])
  assert.deepEqual(removeEntry(null, '/r/a'), [])
})

test('replaceEntryPath 改名后路径与名称同步更新', () => {
  const list = [
    { name: 'old.txt', path: '/home/old.txt', is_dir: false, size: 5 },
    { name: 'keep.txt', path: '/home/keep.txt', is_dir: false, size: 1 },
  ]
  const next = replaceEntryPath(list, '/home/old.txt', 'new.txt')
  const renamed = next.find((e) => e.name === 'new.txt')
  assert.ok(renamed, '应出现新名字')
  assert.equal(renamed.path, '/home/new.txt')
  // 其余元数据保持不变（改名不改大小与 mtime）。
  assert.equal(renamed.size, 5)
  assert.equal(next.some((e) => e.name === 'old.txt'), false)
  assert.deepEqual(replaceEntryPath(null, '/a', 'b'), [])
})

test('replaceEntryPath 在根目录下改名不会拼出双斜杠', () => {
  const list = [{ name: 'old', path: '/old' }]
  const next = replaceEntryPath(list, '/old', 'new')
  assert.equal(next[0].path, '/new')
})

// ---------------------------------------------------------------------------
// 权限与上传限制
// ---------------------------------------------------------------------------

test('canWrite / canRead 匹配权限集合', () => {
  assert.equal(canWrite(['file.read', 'file.write']), true)
  assert.equal(canWrite(['file.read']), false)
  assert.equal(canWrite([]), false)
  assert.equal(canWrite(null), false)
  // 大小写与空格容忍（权限来自后端，但配置可能写成别的形态）。
  assert.equal(canWrite([' File.Write ']), true)

  assert.equal(canRead(['file.read']), true)
  assert.equal(canRead(['file.write']), false)
})

test('uploadTooLarge 按上限判断', () => {
  assert.equal(uploadTooLarge(100, 200), false)
  assert.equal(uploadTooLarge(200, 200), false)
  assert.equal(uploadTooLarge(201, 200), true)
  // 上限未知（元信息还没加载）时不应误报"太大"。
  assert.equal(uploadTooLarge(999999, undefined), false)
  assert.equal(uploadTooLarge(undefined, 100), false)
})
