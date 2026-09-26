// Package plugin 实现 lipanel 的插件系统骨架。
//
// 设计目标（阶段三 3.1）：打通「核心进程 → 插件进程」的通讯链路。
//
// 核心设计决策：
//
//  1. 通讯协议：**Unix domain socket 上的 HTTP/1.1**，不使用 gRPC。
//     相比 localhost TCP，Unix socket 不占用端口、无端口分配与冲突问题，
//     且能用文件权限（0600）做天然的访问隔离——同机其他用户无法连接。
//     协议本身仍是标准 HTTP，因此插件可以用任何语言编写
//     （一个几十行的 Python / Bash 脚本即可），不引入 protobuf 等重依赖。
//
//  2. 插件形态：**单二进制 + 子命令**。
//     工程约束要求「单二进制、CGO_ENABLED=0、scp 到服务器直接跑」，
//     因此内置插件不以独立可执行文件分发，而是让主程序以自身可执行文件
//     重新 exec，首个参数为 "__plugin_<id>" 进入插件模式（见 cmd/lipanel）。
//     这样产物始终是一个文件。
//
//  3. 进程归属：支持 managed（核心 fork/exec 拉起并托管）与
//     external（核心只拨号，插件由 systemd 或手工启动）两种模式。
//
//  4. 调用方向：本阶段只实现「核心 → 插件」单向调用。
//     插件反向调用核心、事件推送属于后续阶段（3.2/3.3），此处不做。
package plugin

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// 插件的两种运行模式。
const (
	// ModeManaged 表示插件进程由核心负责启动与停止。
	ModeManaged = "managed"
	// ModeExternal 表示插件进程由外部（systemd / 手工）管理，核心只按地址拨号。
	ModeExternal = "external"
)

// 插件的运行状态。
const (
	StateStopped = "stopped"
	StateRunning = "running"
	StateFailed  = "failed"
)

// idPattern 限定插件 ID 的合法形态。
//
// 这个正则是安全边界，不只是格式校验：插件 ID 会出现在
//   - URL 路径 /api/plugins/{id}/...
//   - socket 文件名 <runDir>/<id>.sock
//   - 日志字段
//
// 上。若允许 "." 或 "/"，攻击者就能用 "../../etc/passwd" 之类的 ID
// 构造出目录穿越（写/读任意 socket 路径）。因此这里只放行小写字母、
// 数字与内部连字符，长度 2~32，并且不允许以连字符开头/结尾。
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// ErrNotFound 表示指定 ID 的插件未注册。
var ErrNotFound = errors.New("plugin: 插件不存在")

// ErrNotRunning 表示插件当前未运行，无法转发请求。
var ErrNotRunning = errors.New("plugin: 插件未运行")

// ErrAlreadyRunning 表示插件已经在运行中。
var ErrAlreadyRunning = errors.New("plugin: 插件已在运行中")

// ErrUnsupported 表示插件不支持该操作（例如 external 模式无法由核心停止）。
var ErrUnsupported = errors.New("plugin: 该插件不支持此操作")

// Frontend 描述插件的前端挂载信息，是「为后续动态挂载插件前端留的插槽」。
//
// 本阶段核心只把这份元数据原样透传给前端，由前端静态注册表
// （web/src/plugins/registry.js）决定用什么组件渲染；
// 后续阶段可把 Entry 换成真正的远端 ESM 入口做动态加载，
// 而无需改动路由与菜单逻辑。
type Frontend struct {
	// Entry 是前端入口标识。当前约定为静态注册表的 key，
	// 后续可演进为 ESM 模块 URL。
	Entry string `json:"entry"`
	// NavTitle 是菜单中显示的名称；为空表示该插件不需要出现在菜单里。
	NavTitle string `json:"nav_title,omitempty"`
	// NavIcon 是菜单图标标识（前端自行映射到具体图标组件）。
	NavIcon string `json:"nav_icon,omitempty"`
}

// Valid 判断前端挂载信息是否可用于渲染菜单。
func (f Frontend) Valid() bool {
	return strings.TrimSpace(f.Entry) != "" && strings.TrimSpace(f.NavTitle) != ""
}

// Descriptor 是插件的静态元数据，用于注册与展示。
type Descriptor struct {
	// ID 是插件唯一标识，必须匹配 idPattern。
	ID string `json:"id"`
	// Name 是展示名称。
	Name string `json:"name"`
	// Version 是插件版本号。
	Version string `json:"version"`
	// Description 是插件用途说明。
	Description string `json:"description,omitempty"`
	// Builtin 表示是否为内置插件（编译进主程序）。
	// 本阶段只支持内置插件；外部插件安装能力留待后续。
	Builtin bool `json:"builtin"`
	// Mode 是运行模式，见 ModeManaged / ModeExternal。
	Mode string `json:"mode"`
	// Frontend 是前端挂载信息。
	Frontend Frontend `json:"frontend"`
}

// Validate 校验描述符的合法性。非法描述符在注册阶段就被拒绝，
// 而不是等到启动插件时才暴露。
func (d Descriptor) Validate() error {
	if !ValidID(d.ID) {
		return fmt.Errorf("plugin: 非法插件 ID %q（只允许小写字母/数字/连字符，2~32 位，且不能以连字符开头或结尾）", d.ID)
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("plugin: %s 缺少 Name", d.ID)
	}
	if strings.TrimSpace(d.Version) == "" {
		return fmt.Errorf("plugin: %s 缺少 Version", d.ID)
	}
	switch d.Mode {
	case ModeManaged, ModeExternal:
	case "":
		return fmt.Errorf("plugin: %s 缺少 Mode", d.ID)
	default:
		return fmt.Errorf("plugin: %s 的 Mode = %q 非法，可选 %s|%s", d.ID, d.Mode, ModeManaged, ModeExternal)
	}
	return nil
}

// ValidID 判断插件 ID 是否合法。
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Status 是插件的运行时状态，会作为 /api/plugins 的列表项返回给前端。
type Status struct {
	Descriptor
	// State 是运行状态，见 StateStopped / StateRunning / StateFailed。
	State string `json:"state"`
	// PID 是插件进程号；external 模式或未运行时为 0。
	PID int `json:"pid,omitempty"`
	// SocketPath 是插件监听的 Unix socket 路径（仅核心与管理员可见）。
	SocketPath string `json:"socket_path,omitempty"`
	// StartedAt 是本次启动时间（RFC3339）；未运行时为空。
	StartedAt string `json:"started_at,omitempty"`
	// UptimeSeconds 是本次运行的时长（秒）；未运行时为 0。
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Restarts 是累计重启次数（崩溃后被自动拉起或人工重启）。
	Restarts int `json:"restarts"`
	// LastError 是最近一次启动/运行失败的描述，供前端提示。
	LastError string `json:"last_error,omitempty"`
	// Healthy 表示最近一次健康探测是否通过。nil 表示尚未探测。
	Healthy *bool `json:"healthy,omitempty"`
}

// Running 是 State == StateRunning 的便捷判断。
func (s Status) Running() bool { return s.State == StateRunning }

// DefaultStopTimeout 是停止插件时的默认等待时长：
// 先发 SIGTERM 让插件优雅退出，超时后再 SIGKILL。
const DefaultStopTimeout = 5 * time.Second

// DefaultStartTimeout 是启动插件后等待其 socket 就绪的最长时间。
// 超时视为启动失败，核心会回收进程，避免留下「僵尸插件」。
const DefaultStartTimeout = 10 * time.Second

// DefaultRequestTimeout 是转发单个请求到插件的超时上限。
// 必须设置：一个卡死的插件不能拖垮整个面板。
const DefaultRequestTimeout = 15 * time.Second
