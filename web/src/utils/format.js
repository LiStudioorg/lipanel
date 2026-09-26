// 前端公共格式化函数。
//
// 抽出来的原因：这些函数原本内联在 SystemInfoPanel.vue 里，
// 而插件版系统信息视图（SysinfoPluginView.vue）需要完全相同的逻辑。
// 复制一份会导致「同一个数字在两处显示不一致」——
// 尤其是 formatBytes 的舍入规则，很容易改一处忘一处。

// formatBytes 把字节数转为人类可读单位（GiB/MiB）。
export function formatBytes(bytes) {
  if (typeof bytes !== 'number' || Number.isNaN(bytes) || bytes <= 0) {
    return '0 B'
  }
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let value = bytes
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  // 大于 10 时保留一位小数即可，避免数字太长不好读。
  return `${value >= 10 || i === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[i]}`
}

// formatUptime 把秒数转为「3 天 4 小时 5 分」。
export function formatUptime(seconds) {
  if (typeof seconds !== 'number' || seconds < 0) {
    return '-'
  }
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)

  const parts = []
  if (days > 0) parts.push(`${days} 天`)
  if (hours > 0) parts.push(`${hours} 小时`)
  // 天/小时都没有时才显示分钟，避免「0 分」这种无意义信息。
  if (parts.length === 0 || minutes > 0) parts.push(`${minutes} 分`)
  return parts.join(' ')
}

// formatDuration 把秒数转为紧凑形式（用于插件运行时长这类较短的区间）。
export function formatDuration(seconds) {
  if (typeof seconds !== 'number' || seconds < 0) {
    return '-'
  }
  if (seconds < 60) return `${seconds} 秒`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分 ${seconds % 60} 秒`
  const hours = Math.floor(minutes / 60)
  return `${hours} 小时 ${minutes % 60} 分`
}

// percentStatus 按使用率返回进度条颜色，让高负载一眼可见。
export function percentStatus(percent) {
  if (percent >= 90) return 'error'
  if (percent >= 75) return 'warning'
  return 'success'
}

// usageText 生成「已用 / 总量 (百分比)」形式的说明文字。
export function usageText(usedBytes, totalBytes, percent) {
  if (!totalBytes) {
    return '不可用'
  }
  return `${formatBytes(usedBytes)} / ${formatBytes(totalBytes)}（${percent}%）`
}

// formatTime 把 RFC3339 字符串转成本地可读时间。
export function formatTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString()
}
