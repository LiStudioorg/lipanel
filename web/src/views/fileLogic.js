// 文件管理页的纯逻辑（阶段四 4.2）。
//
// 为什么单独一个模块而不是写在 FileView.vue 里：
//
//   1. **可测**。本仓库前端测试用 node:test、没有 DOM（不引入 jsdom，
//      保持「轻量」约束），组件本身无法直接 import。
//      把可判定逻辑抽成纯函数，测试就能锁住**真正被使用的代码**——
//      如果测试里重述一遍逻辑，组件改了测试也照样全绿（坑位 53）。
//
//   2. **可读**。路径拼接、大小格式化、可否编辑这些判定集中在
//      一处，比散落在模板与 render 函数里更好审查。
//
// 路径相关函数的语义必须与后端一致：后端只接受**绝对路径**
// （见 internal/file/root.go 的 ErrRelativePath），因此这里的
// 拼接结果也必须始终是绝对路径。

// joinPath 把目录与子项名拼成绝对路径。
//
// 为什么不直接用 `${dir}/${name}`：根目录是 "/" 时会拼出 "//file"，
// 虽然后端 Clean 之后能接受，但前端列表里会出现 "//file" 这种
// 与后端返回的绝对路径**字符串不相等**的值，导致「当前目录高亮」
// 之类的比较全部失效。统一走本函数，路径形态只有一个来源。
export function joinPath(dir, name) {
  const base = String(dir ?? '')
  const child = String(name ?? '')
  if (!base) return child
  if (!child) return base
  if (base.endsWith('/')) return base + child
  return `${base}/${child}`
}

// parentPath 返回上级目录；已到根（"/"）时返回空字符串。
//
// 返回空字符串而不是 "/"：调用方据此禁用「返回上级」按钮，
// 避免用户在根目录点一下却"原地跳转"，看起来像按钮坏了。
export function parentPath(path) {
  const p = String(path ?? '')
  if (!p || p === '/') return ''
  // 去掉结尾的 /（用户可能从别处粘贴来 "/home/user/"）。
  const trimmed = p.endsWith('/') ? p.slice(0, -1) : p
  if (trimmed === '') return ''
  const idx = trimmed.lastIndexOf('/')
  if (idx < 0) return ''
  if (idx === 0) return '/'
  return trimmed.slice(0, idx)
}

// breadcrumbs 把绝对路径拆成面包屑数组，供界面展示与点击跳转。
//
// 返回 [{ label, path }]，第一项固定是根 "/"。
// label 为空的部分（连续的 //）会被跳过，避免出现点不动的空节点。
export function breadcrumbs(path) {
  const p = String(path ?? '')
  const root = { label: '/', path: '/' }
  if (!p || p === '/') return [root]

  const parts = p.split('/').filter((seg) => seg !== '')
  const out = [root]
  let acc = ''
  for (const seg of parts) {
    acc += `/${seg}`
    out.push({ label: seg, path: acc })
  }
  return out
}

// formatSize 把字节数格式化成人类可读的大小。
//
// 用 1024 进制（KiB 语义但显示 KB）：面板上"文件多大"是给人看的，
// 与 `ls -h` / 浏览器下载提示的口径保持一致比严格用 KiB 更重要。
export function formatSize(bytes) {
  // null / undefined / '' 表示"这个条目没有大小"（目录被后端置 0，
  // 元数据缺失时也可能为空），统一显示 "-"。
  // 注意必须先排掉这类值：Number(null) 是 0、Number('') 也是 0，
  // 不特判就会显示成 "0 B"，让"取不到大小"看起来像"文件是空的"。
  if (bytes === null || bytes === undefined || bytes === '') return '-'

  const n = Number(bytes)
  // 其余非法值与负数同样显示 "-"，而不是 "NaN B"——后者会让整列看起来很脏。
  if (!Number.isFinite(n) || n < 0) return '-'
  if (n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let value = n
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  // 字节数不带小数（"512 B" 比 "512.0 B" 自然）；
  // 其余保留一位小数，但整数时省掉 ".0"。
  if (i === 0) return `${Math.round(value)} B`
  const rounded = Math.round(value * 10) / 10
  return `${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)} ${units[i]}`
}

// formatModTime 把 RFC3339 时间格式化成 "YYYY-MM-DD HH:mm"。
//
// 后端给的是带时区的 RFC3339；这里用本地时区展示——
// 用户关心的是"按我这边的表，这文件什么时候改的"。
export function formatModTime(raw) {
  if (!raw) return '-'
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return String(raw)
  const pad = (v) => String(v).padStart(2, '0')
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`
  )
}

// TYPE_META 把后端的类型分类映射为展示文案与标签颜色。
export const TYPE_META = {
  dir: { text: '目录', type: 'info' },
  file: { text: '文件', type: 'default' },
  symlink: { text: '链接', type: 'warning' },
  other: { text: '其它', type: 'default' },
}

// typeMeta 返回类型展示元数据，未知类型安全回落。
export function typeMeta(type) {
  return TYPE_META[type] || TYPE_META.other
}

// displayTypeText 生成类型列的展示文案。
//
// 失效链接单独说明：列表里必须一眼能看出"这个链接点不开"，
// 否则用户会反复点击并以为面板坏了。
export function displayTypeText(entry) {
  const meta = typeMeta(entry?.type)
  if (entry?.type === 'symlink') {
    const suffix = entry.broken ? '（已失效）' : entry.is_dir ? '（指向目录）' : ''
    return `${meta.text}${suffix}`
  }
  return meta.text
}

// isEditable 判断某条目能否用内置文本编辑器打开。
//
// 依据是后端在列目录时给出的 editable 标记（后端已经按
// MaxEditBytes 与"是否普通文件"判定过），前端不重复实现该规则——
// 否则两边阈值一旦不一致，就会出现"能点开但必然 415"的条目。
export function isEditable(entry) {
  return Boolean(entry?.editable) && !entry?.is_dir && !entry?.broken
}

// sortEntries 是**前端兜底排序**（后端已排好，这里只用于本地重新排序）。
//
// 规则与后端 sortEntries 一致：目录优先，再按名称不区分大小写。
// 保持一致很重要——否则"刷新前后顺序变了"会让用户困惑。
export function sortEntries(entries) {
  const list = Array.isArray(entries) ? [...entries] : []
  return list.sort((a, b) => {
    if (Boolean(a?.is_dir) !== Boolean(b?.is_dir)) return a?.is_dir ? -1 : 1
    const la = String(a?.name ?? '').toLowerCase()
    const lb = String(b?.name ?? '').toLowerCase()
    if (la !== lb) return la < lb ? -1 : 1
    const ra = String(a?.name ?? '')
    const rb = String(b?.name ?? '')
    if (ra === rb) return 0
    return ra < rb ? -1 : 1
  })
}

// filterEntries 按关键字与类型过滤条目。
//
// 过滤只影响**展示**，不影响任何操作路径：条目上的操作
// 始终使用后端返回的绝对路径。
export function filterEntries(entries, { keyword = '', onlyDirs = false } = {}) {
  let list = Array.isArray(entries) ? entries : []
  if (onlyDirs) list = list.filter((e) => e?.is_dir)
  const kw = String(keyword ?? '').trim().toLowerCase()
  if (kw) {
    list = list.filter((e) => String(e?.name ?? '').toLowerCase().includes(kw))
  }
  return list
}

// validateNewName 校验新建目录/重命名时输入的名称。
//
// 返回错误文案，合法时返回空字符串。
// 前端校验只是**体验**（立刻给出提示，不必等一次网络往返），
// 真正的强制点始终在后端 file.validateName。
export function validateNewName(name) {
  const raw = String(name ?? '')
  if (raw === '') return '名称不能为空'
  if (raw === '.' || raw === '..') return '名称不能是 . 或 ..'
  if (raw.includes('/')) return '名称不能包含 /'
  if (raw.includes('\0')) return '名称包含非法字符'
  if (raw.length > 255) return '名称过长（最多 255 个字符）'
  // 首尾空格在 Linux 上合法，但几乎总是误输入，这里给出提示而不是拒绝。
  if (raw !== raw.trim()) return '名称首尾不能有空格'
  return ''
}

// deleteConfirmText 生成删除确认文案。
//
// 必须写明**具体删的是什么**，并区分文件/空目录/非空目录：
//   - 点错行时用户能立刻从名字上发现；
//   - 非空目录要额外警告"递归删除不可恢复"，因为它会连带删掉子树。
export function deleteConfirmText(entry) {
  const name = String(entry?.name ?? '')
  const path = String(entry?.path ?? '')
  if (entry?.is_dir) {
    return (
      `即将删除目录「${name}」（${path}）。\n\n` +
      '目录内的全部内容会一并删除，且**无法恢复**。确定继续吗？'
    )
  }
  if (entry?.type === 'symlink') {
    return (
      `即将删除符号链接「${name}」（${path}）。\n\n` +
      '只会删除链接本身，不会删除它指向的文件。确定继续吗？'
    )
  }
  return `即将删除文件「${name}」（${path}）。\n\n删除后无法恢复，确定继续吗？`
}

// deleteNeedsRecursive 判断删除某条目是否需要先确认递归。
//
// 目录一律按"可能需要递归"处理：前端拿不到"目录是否为空"的可靠信息
// （列目录只给了当前层，且可能在用户确认期间变化）。
// 因此对目录统一走"递归删除"确认；后端仍会在目录为空且未传
// recursive 时自行处理，不会因此产生风险。
export function deleteNeedsRecursive(entry) {
  return Boolean(entry?.is_dir) && entry?.type !== 'symlink'
}

// upsertEntry 在本地列表里插入或替换一个条目，并保持排序。
//
// 用于「新建目录 / 重命名 / 上传」成功后的**局部更新**：
// 不必重新拉一次整目录（在慢速网络或大目录下那一步很慢），
// 用户的观感是"操作立刻生效"。
export function upsertEntry(entries, entry) {
  const list = Array.isArray(entries) ? entries : []
  if (!entry?.path) return sortEntries(list)
  const next = list.filter((e) => e?.path !== entry.path)
  next.push(entry)
  return sortEntries(next)
}

// removeEntry 从本地列表移除某路径（删除成功后使用）。
export function removeEntry(entries, path) {
  const list = Array.isArray(entries) ? entries : []
  return list.filter((e) => e?.path !== path)
}

// replaceEntryPath 在本地列表里把 oldPath 的条目改名（重命名成功后使用）。
//
// 只改 name 与 path：其余元数据（大小、mtime）在改名后不变，
// 重新 stat 一遍没有必要。
export function replaceEntryPath(entries, oldPath, newName) {
  const list = Array.isArray(entries) ? entries : []
  const parent = parentPath(oldPath)
  const newPath = joinPath(parent, newName)
  return sortEntries(
    list.map((e) =>
      e?.path === oldPath
        ? { ...e, name: newName, path: newPath }
        : e,
    ),
  )
}

// canWrite 判断当前用户是否能执行写操作（新建/上传/保存/重命名/删除）。
//
// 与 servicesLogic 的 canWrite 同样是**体验优化**：
// 真正的强制点在后端 file.CheckFilePermission。
export function canWrite(permissions) {
  const list = Array.isArray(permissions) ? permissions : []
  return list.some((p) => String(p).trim().toLowerCase() === 'file.write')
}

// canRead 判断当前用户是否有读取权限。
export function canRead(permissions) {
  const list = Array.isArray(permissions) ? permissions : []
  return list.some((p) => String(p).trim().toLowerCase() === 'file.read')
}

// uploadTooLarge 校验待上传文件是否超过后端上限。
//
// 前端先拦一道是为了省一次注定失败的大文件传输（可能是几百 MB
// 走完整个上行链路才被拒绝）。后端仍会独立校验（MaxBytesReader
// + LimitReader），前端这一层被绕过也不影响安全。
export function uploadTooLarge(fileSize, maxBytes) {
  const size = Number(fileSize)
  const limit = Number(maxBytes)
  if (!Number.isFinite(size) || !Number.isFinite(limit) || limit <= 0) return false
  return size > limit
}
