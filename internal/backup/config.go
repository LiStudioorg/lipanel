package backup

import (
	"crypto/tls"
	"time"
)

// 默认超时常量。
const (
	// DefaultHTTPTimeout 是单次存储请求的超时。
	//
	// 60s 是刻意偏短的：它约束的是"单个 HTTP 请求"，
	// 不是"整个备份"（后者由 ExecTimeout 约束）。一次 PUT 超过
	// 一分钟还毫无进展，说明链路已经坏了，继续等只会拖长
	// 「备份失败」被发现的周期。
	DefaultHTTPTimeout = 60 * time.Second
	// DefaultExecTimeout 是单次备份执行的总超时。
	//
	// 30 分钟：足够传完几十 GB 的归档，又短到不会让一次
	// 卡死的备份永久占着锁（锁的陈旧判定也以此为据）。
	DefaultExecTimeout = 30 * time.Minute
	// DefaultMaxArchiveBytes 是单个归档的体积上限。
	//
	// 10 GiB。存在的意义不是"省磁盘"，而是防止用户把 `/` 整个
	// 配进来之后，面板安静地开始打包整个系统——那会打满 staging
	// 所在的分区，而那块分区上还住着面板自己的数据。
	DefaultMaxArchiveBytes int64 = 10 << 30
	// DefaultMaxSourceBytes 是源数据的总字节上限（打包前统计）。
	DefaultMaxSourceBytes int64 = 10 << 30
	// DefaultMaxEntries 是单次打包的条目数上限。
	//
	// 100 万。它防的是"一个有几百万小文件的目录"把 tar 的
	// 循环拖到以小时计，而用户只看到进度条不动。
	DefaultMaxEntries = 1_000_000
	// DefaultMaxHistoryEntries 是每个任务保留的历史条数。
	DefaultMaxHistoryEntries = 500
	// DefaultPreviewMaxEntries 是恢复预览最多列出的条目数。
	//
	// 预览是给人看的。一个几万条目的大归档全列出来既没人看得完，
	// 也会把一个 JSON 响应撑到几十 MB。超出部分只计数。
	DefaultPreviewMaxEntries = 500
	// DefaultKeepCount 是新建任务时的默认保留份数。
	DefaultKeepCount = 7
)

// insecureTLSConfig 返回跳过证书校验的 TLS 配置。
//
// 单独一个函数、且只有一处调用点：跳过校验是本模块里
// 最容易被顺手复制到别处的危险开关，把它围起来能让
// "哪里用了它"一眼可查。
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- 用户显式勾选，配置页有警示文案
}

// DefaultDataDir 是备份数据的默认目录。
const DefaultDataDir = "/var/lib/lipanel/backup"

// DefaultRestoreRoot 是恢复目标的默认白名单根目录。
//
// ########## 为什么默认**收紧**而不是 "/" ##########
//
// 恢复到错误的位置是本模块唯一不可逆的动作：它覆盖目标目录里
// 已有的文件。默认给 "/" 意味着一个误填的目标路径（比如手滑把
// /var/lib/mysql 填进了输入框）就可以覆盖掉正在运行的数据库。
//
// 因此默认只允许恢复到面板自己的目录下；要恢复到其它位置，
// 管理员必须显式用 -backup-restore-root 放开，并且 Status
// 会返回 restore_root_narrow=false，前端据此把警示文案换成
// "管理员已放开的目录"。
//
// 这与 -file-root 默认 "/" 的选择**方向相反**，是有意的：
// 文件管理是"能看能改"，任何一次操作的影响面都是用户当场可见的；
// 而恢复是批量覆盖，一次误操作可以抹掉一整天的数据。
const DefaultRestoreRoot = "/var/lib/lipanel/restore"

// DefaultSourceRoot 是备份源的默认白名单根目录（与 4.2 的 -file-root 一致）。
const DefaultSourceRoot = "/"
