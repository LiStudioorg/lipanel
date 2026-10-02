package logs

import (
	"context"
	"log/slog"
	"time"
)

// ============================================================================
// 日志查看管理器（阶段五 5.4.1）
// ============================================================================
//
// Manager 负责：
//   - 登记/探测日志源白名单（启动时一次探测）；
//   - 对外提供 Sources() 列表与 Query() 查询；
//   - 查询超时（-logs-timeout）。
//
// 它为 nil 时（server 未注入）相关接口返回 503，与其它核心模块降级策略一致。

// ManagerOptions 是构造 Manager 的配置。
type ManagerOptions struct {
	// NginxLogsDir 是 Nginx 应用日志目录（<nginx prefix>/logs）。
	// 为空表示未配置 nginx（可来自 site 模块的 prefix），
	// 此时 nginx 相关日志源不可用。
	NginxLogsDir string
	// QueryTimeout 是单次日志查询的超时；<=0 时用 DefaultQueryTimeout。
	QueryTimeout time.Duration
	// Auditor 为 nil 时新建一个仅内存的审计器。
	Auditor *Auditor
	// Logger 为 nil 时用 slog.Default()。
	Logger *slog.Logger
}

// DefaultQueryTimeout 是默认查询超时。
const DefaultQueryTimeout = 15 * time.Second

// Manager 是日志查看管理器。
type Manager struct {
	nginxLogsDir string
	queryTimeout time.Duration
	logger       *slog.Logger
	auditor      *Auditor
	// defs 是白名单内的日志源定义。
	defs []sourceDef
	// probes 保存每个源启动时的探测结论。
	probes map[string]probeResult
}

// New 构造日志管理器，并探测全部日志源的可用性。
func New(opts ManagerOptions) (*Manager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := opts.QueryTimeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}

	auditor := opts.Auditor
	if auditor == nil {
		audit, err := NewAuditor(AuditOptions{Logger: logger})
		if err != nil {
			return nil, err
		}
		auditor = audit
	}

	m := &Manager{
		nginxLogsDir: opts.NginxLogsDir,
		queryTimeout: timeout,
		logger:       logger,
		auditor:      auditor,
		defs:         registeredSources(opts.NginxLogsDir),
		probes:       make(map[string]probeResult, 1),
	}
	for _, d := range m.defs {
		m.probes[d.id] = d.probe()
		if !m.probes[d.id].available {
			logger.Warn("日志源不可用",
				"source", d.id, "reason", m.probes[d.id].reason)
		}
	}
	return m, nil
}

// Auditor 返回操作审计器。
func (m *Manager) Auditor() *Auditor { return m.auditor }

// Options 返回构造参数（供测试与状态输出）。
func (m *Manager) Options() ManagerOptions {
	return ManagerOptions{
		NginxLogsDir: m.nginxLogsDir,
		QueryTimeout: m.queryTimeout,
	}
}

// Sources 返回全部日志源（含可用性），供前端列表渲染。
func (m *Manager) Sources() []Source {
	out := make([]Source, 0, len(m.defs))
	for _, d := range m.defs {
		p := m.probes[d.id]
		src := Source{
			ID:          d.id,
			Type:        d.typ,
			Name:        d.name,
			Description: d.description,
			Available:   p.available,
			Capability:  d.cap,
		}
		if !p.available {
			src.UnavailableReason = p.reason
		}
		out = append(out, src)
	}
	return out
}

// findDef 返回日志源定义；不存在返回 false。
func (m *Manager) findDef(id string) (sourceDef, bool) {
	for _, d := range m.defs {
		if d.id == id {
			return d, true
		}
	}
	return sourceDef{}, false
}

// SourceAvailable 判断某日志源是否可用（供接口快速判定）。
func (m *Manager) SourceAvailable(id string) bool {
	p, ok := m.probes[id]
	return ok && p.available
}

// Query 查询日志。sourceID 必须在白名单内；lines 自动收敛到 [1, MaxLines]。
// 源不可用返回 ErrSourceUnavailable。
func (m *Manager) Query(ctx context.Context, q Query) (Result, error) {
	def, ok := m.findDef(q.SourceID)
	if !ok {
		return Result{}, ErrSourceNotFound
	}
	p, ok := m.probes[q.SourceID]
	if !ok || !p.available {
		return Result{}, ErrSourceUnavailable
	}

	limit := clampLines(q.Lines)
	ctx, cancel := context.WithTimeout(ctx, m.queryTimeout)
	defer cancel()

	// 系统源：journald 或 syslog/messages 文件。
	if def.typ == SourceSystem {
		if p.useJournald {
			return readJournald(ctx, p.journalCtl, limit, q.Level, q.Filter), nil
		}
		if p.filePath != "" {
			return readFile(ctx, p.filePath, limit, q.Filter, q.Level), nil
		}
		return Result{SourceID: q.SourceID}, nil
	}

	// 应用源：固定文件（access.log / error.log 之一）。
	if p.filePath != "" {
		return readFile(ctx, p.filePath, limit, q.Filter, ""), nil
	}
	return Result{SourceID: q.SourceID}, nil
}
