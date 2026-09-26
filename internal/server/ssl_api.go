package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"lipanel/internal/auth"
	"lipanel/internal/ssl"
)

// ============================================================================
// SSL 证书接口（阶段四 4.4，核心自带）
// ============================================================================
//
// 路由一览（全部要求登录）：
//
//	GET  /api/ssl                     所有站点的 SSL 状态
//	GET  /api/ssl/capabilities        能力探测（客户端、验证方式、续期策略）
//	GET  /api/ssl/audit               SSL 操作审计
//	POST /api/ssl/{name}/issue        为站点申请证书
//	POST /api/ssl/{name}/renew        为站点续期证书
//
// ⚠️ 注册顺序（有实际后果，不是风格问题）：
// "/api/ssl/capabilities" 与 "/api/ssl/audit" 必须在 "/api/ssl/{name}/..."
// **之前**注册。否则它们会被通配吃掉——查询审计会变成
// "查看名为 audit 的站点的证书状态"，返回 404 或一个错误的结果。
//
// 这是 4.1（/api/plugins/audit）、4.2（/api/files/audit）、
// 4.3（/api/sites/audit）**连续踩过三次**的同一个坑，因此本次
// 从一开始就写测试锁死（TestSSLAuditRouteNotShadowedByWildcard）。
//
// 与前四个核心模块的接口一致性：
//   - 全部接口挂 RequireAuth（按路由显式挂载）；
//   - 写操作顺序固定：**校验 → 权限判定 → 执行 → 无论成败都审计**；
//   - 未注入管理器时返回 JSON 503，绝不落到前端 HTML 兜底。
func (s *Server) registerSSLRoutes(mux *http.ServeMux) {
	if s.sslMgr == nil {
		// 未注入 SSL 管理器时返回明确的 JSON 503，
		// 而不是让请求落到前端 HTML 兜底（那会变成难以理解的解析错误）。
		mux.Handle("/api/ssl/", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLUnavailable)))
		mux.Handle("/api/ssl", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLUnavailable)))
		return
	}

	mux.Handle("GET /api/ssl", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLStatus)))

	// ⚠️ 这两个**固定段**路由必须先于 /{name}/... 通配注册（见上方说明）。
	mux.Handle("GET /api/ssl/capabilities", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLCapabilities)))
	mux.Handle("GET /api/ssl/audit", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLAudit)))

	// 站点维度的操作。
	mux.Handle("POST /api/ssl/{name}/issue", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLIssue)))
	mux.Handle("POST /api/ssl/{name}/renew", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLRenew)))

	// 前缀兜底：未注册的 /api/ssl/* 子路径返回 **JSON 404**，
	// 而不是落到前端 SPA 兜底（那会返回 200 + text/html）。
	// 这是 4.2 实测发现的真实缺陷，这里从一开始就补上。
	mux.Handle("/api/ssl/", s.auth.RequireAuth(http.HandlerFunc(s.handleSSLNotFound)))
}

// handleSSLUnavailable 在 SSL 管理器未注入时给出明确提示。
func (s *Server) handleSSLUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusServiceUnavailable, map[string]string{
		"error": "SSL 证书管理未启用（服务启动时未注入管理器）",
	})
}

// handleSSLNotFound 处理 /api/ssl/* 下未注册的子路径。
//
// 返回 JSON 404 并**列出可用接口**——这类 404 多半是调用方路径写错了，
// 把正确的接口清单摆在响应里，比让人去翻源码快得多。
func (s *Server) handleSSLNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.logger, http.StatusNotFound, map[string]any{
		"error": "SSL 接口不存在: " + r.URL.Path,
		"hint":  "可用接口见下方 available 列表。",
		"available": []string{
			"GET  /api/ssl",
			"GET  /api/ssl/capabilities",
			"GET  /api/ssl/audit",
			"POST /api/ssl/{name}/issue",
			"POST /api/ssl/{name}/renew",
		},
	})
}

// ---------------------------------------------------------------------------
// 审计脚手架
// ---------------------------------------------------------------------------

// sslAudit 收口一次 SSL 操作的审计写入。
//
// 与 4.2 的 fileAudit、4.3 的 siteAudit 同构：每个接口都要填
// user/action/target/client_ip 这几个固定字段，
// 散落各处必然出现"某个接口忘了填 client_ip"这种不一致。
type sslAudit struct {
	srv     *Server
	user    string
	action  string
	target  string
	domain  string
	certNam string
	ip      string
	started time.Time
}

// beginSSLAudit 构造一次操作的审计上下文。
func (s *Server) beginSSLAudit(r *http.Request, action, target string) *sslAudit {
	user, _ := auth.UsernameFrom(r.Context())
	return &sslAudit{
		srv:     s,
		user:    user,
		action:  action,
		target:  target,
		ip:      clientIPOf(r),
		started: time.Now(),
	}
}

// record 写入一条审计（outcome 见 ssl.AuditAllowed/Denied/Failed/Pending）。
//
// 额外参数说明（SSL 模块特有）：
//
//	issued  —— CA 是否已签发（**配额是否已被消耗**）
//	applied —— 配置是否已成功写入 nginx 并 reload
//
// 这两个字段的组合是运维最需要检索的信息：
// `Issued=true, Applied=false` 等于"配额花了但 HTTPS 没起来"。
func (a *sslAudit) record(ev ssl.AuditEvent) {
	ev.User = a.user
	ev.Action = a.action
	ev.Target = a.target
	ev.ClientIP = a.ip
	ev.DurationMS = time.Since(a.started).Milliseconds()
	if ev.Domain == "" {
		ev.Domain = a.domain
	}
	if ev.CertName == "" {
		ev.CertName = a.certNam
	}
	if ev.Required == "" {
		ev.Required = ssl.RequiredPermission(a.action)
	}
	a.srv.sslMgr.Auditor().Record(ev)
}

// ---------------------------------------------------------------------------
// 权限判定
// ---------------------------------------------------------------------------

// requireSSLPermission 判定当前用户能否执行某 SSL 动作。
//
// 顺序与 4.1/4.2/4.3 一致且不可调换：**先判权限，再碰外部命令**。
// 被拒绝的请求绝不能产生任何副作用（尤其是不能消耗 CA 配额），
// 这样审计里 denied 的含义才是确定的（"没有任何外部调用发生"）。
//
// 返回值 true 表示已放行；false 表示已写出 403 响应，调用方直接 return。
func (s *Server) requireSSLPermission(w http.ResponseWriter, a *sslAudit) bool {
	grantee := ssl.AdminGrantee(a.user)
	decision := ssl.CheckSSLPermission(grantee, a.action)
	if decision.Allowed {
		return true
	}

	a.record(ssl.AuditEvent{
		Outcome:  ssl.AuditDenied,
		Status:   http.StatusForbidden,
		Reason:   decision.Reason,
		Required: decision.Required,
	})
	// 响应头与前四个模块的权限拦截保持一致，便于统一排查与告警规则复用。
	w.Header().Set("X-Lipanel-Permission-Denied", decision.Required)
	s.logger.Warn("SSL 操作被权限校验拒绝",
		"user", a.user, "action", a.action, "target", a.target, "required", decision.Required)
	writeJSON(w, s.logger, http.StatusForbidden, map[string]any{
		"error":    decision.Reason,
		"hint":     decision.Hint,
		"required": decision.Required,
		"granted":  decision.Granted,
	})
	return false
}

// ---------------------------------------------------------------------------
// GET /api/ssl —— 状态
// ---------------------------------------------------------------------------

// sslStatusResponse 是 GET /api/ssl 的响应体。
type sslStatusResponse struct {
	// Sites 是全部站点的 SSL 状态。
	Sites []ssl.SiteStatus `json:"sites"`
	// Client 是探测到的 ACME 客户端。
	Client ssl.ClientInfo `json:"client"`
	// Available 为 false 表示无法申请证书（无客户端或未注入站点提供器）。
	//
	// 注意：这与 "nginx 不可用" 不同——即使无法申请证书，
	// 站点列表与已有证书的状态**仍然会正常返回**。
	// 前端据此禁用"申请"按钮并展示原因，而不是整页报错。
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// RenewDays 是"即将过期"阈值。
	RenewDays int `json:"renew_days"`
	// DryRun 表示是否处于试运行模式。
	DryRun bool `json:"dry_run"`
	// Counts 是按状态分组的统计，前端直接展示不必自己遍历。
	Counts ssl.StatusCounts `json:"counts"`
	// ScannedAt 是本次扫描时间。
	ScannedAt string `json:"scanned_at,omitempty"`
	// Scheduler 是自动续期调度器的运行状态。
	Scheduler ssl.RenewSchedulerStats `json:"scheduler"`
	// Audit 是审计器状态，供页面展示"操作是否在留痕"。
	Audit ssl.AuditStats `json:"audit"`
	// Permissions 是当前用户被授予的 SSL 权限。
	//
	// 注意：这只是**体验优化**。真正的强制点始终在后端
	// （见 requireSSLPermission），前端拿到的标记被篡改也没用。
	Permissions []string `json:"permissions"`
}

// handleSSLStatus 返回所有站点的 SSL 状态。
//
// 即使 certbot 不可用也返回 200：这样前端能拿到 available=false 与原因，
// 从而渲染出"为什么不可用"的说明，而不是一个红色错误框
// （与 4.1 服务管理、4.3 站点管理同样的降级策略）。
func (s *Server) handleSSLStatus(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := ssl.AdminGrantee(user)

	result, err := s.sslMgr.Status(r.Context())
	if err != nil {
		s.logger.Error("读取 SSL 状态失败", "err", err)
		writeJSON(w, s.logger, http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
			"hint":  "请检查站点配置与 certbot 是否正常。",
		})
		return
	}

	writeJSON(w, s.logger, http.StatusOK, sslStatusResponse{
		Sites:             result.Sites,
		Client:            result.Client,
		Available:         result.Available,
		UnavailableReason: result.UnavailableReason,
		RenewDays:         result.RenewDays,
		DryRun:            result.DryRun,
		Counts:            result.Counts,
		ScannedAt:         result.ScannedAt,
		Scheduler:         s.sslSchedulerStats(),
		Audit:             s.sslMgr.Auditor().Stats(),
		Permissions:       grantee.Granted,
	})
}

// sslSchedulerStats 返回调度器状态（未注入时返回零值）。
func (s *Server) sslSchedulerStats() ssl.RenewSchedulerStats {
	if s.sslScheduler == nil {
		return ssl.RenewSchedulerStats{}
	}
	return s.sslScheduler.Stats()
}

// ---------------------------------------------------------------------------
// GET /api/ssl/capabilities —— 能力探测
// ---------------------------------------------------------------------------

// handleSSLCapabilities 返回 SSL 能力探测结果。
//
// 前端据此：
//   - 在 certbot 不可用时展示原因与安装建议并禁用按钮；
//   - 提示"证书会不会自动写入 nginx 配置"；
//   - 提示试运行模式（不消耗配额，适合先验证流程）。
func (s *Server) handleSSLCapabilities(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UsernameFrom(r.Context())
	grantee := ssl.AdminGrantee(user)

	cap := s.sslMgr.Capabilities(r.Context())
	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"available":         cap.Available,
		"reason":            cap.Reason,
		"client":            cap.Client,
		"challenge_type":    cap.ChallengeType,
		"webroot_required":  cap.WebrootRequired,
		"email":             cap.Email,
		"email_configured":  cap.EmailConfigured,
		"renew_days":        cap.RenewDays,
		"dry_run":           cap.DryRun,
		"can_rewrite_nginx": cap.CanRewriteNginx,
		"notes":             cap.Notes,
		"scheduler":         s.sslSchedulerStats(),
		"permissions":       grantee.Granted,
		"audit":             s.sslMgr.Auditor().Stats(),
		// scope_note 说明面板能碰到什么、不能碰到什么。
		// SSL 会调用外部程序并改写 nginx 配置，用户有权知道确切范围。
		"scope_note": "面板通过 certbot 的 certonly 子命令申请证书" +
			"（HTTP-01 验证，复用站点的 80 端口，不中断服务）。" +
			"证书由 certbot 保存在其自己的目录中；" +
			"面板只把证书路径写入站点的 nginx 配置，并走" +
			"「nginx -t 校验 + 失败自动回滚」链路，不会直接改写其它配置。" +
			"本版本不支持通配符域名（需要 DNS 验证）。",
	})
}

// ---------------------------------------------------------------------------
// GET /api/ssl/audit —— 审计
// ---------------------------------------------------------------------------

// handleSSLAudit 返回 SSL 操作审计。
func (s *Server) handleSSLAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	events := s.sslMgr.Auditor().Query(ssl.AuditFilter{
		Target:  strings.TrimSpace(q.Get("target")),
		User:    strings.TrimSpace(q.Get("user")),
		Action:  strings.TrimSpace(q.Get("action")),
		Outcome: strings.TrimSpace(q.Get("outcome")),
		Limit:   parseIntDefault(q.Get("limit"), ssl.DefaultAuditQueryLimit),
	})

	writeJSON(w, s.logger, http.StatusOK, map[string]any{
		"events": events,
		"total":  len(events),
		"stats":  s.sslMgr.Auditor().Stats(),
	})
}

// ---------------------------------------------------------------------------
// POST /api/ssl/{name}/issue —— 申请
// ---------------------------------------------------------------------------

// sslIssueRequest 是申请请求体。
type sslIssueRequest struct {
	// Force 为 true 时即使证书仍有效也强制重新签发。
	//
	// ⚠️ 默认 false 且**前端必须二次确认**：Let's Encrypt 对同一组域名
	// 有"每周 5 次重复签发"的速率限制，无脑 force 很容易把配额打满，
	// 之后整整一周都申请不了（连正常续期都会失败）。
	Force bool `json:"force"`
}

// handleSSLIssue 为站点申请证书。
//
// 执行顺序（顺序本身就是安全设计，不能调换）：
//
//  1. 解析请求体 → 失败直接 400，**不触碰任何外部命令**；
//  2. 权限判定   → 无权直接 403，**不触碰任何外部命令**（不消耗配额）；
//  3. 执行申请（含 certbot 调用与 nginx 配置写入）；
//  4. 无论成功、失败还是被拒绝，**都写一条审计**。
//
// ########## 这个接口为什么必须记审计 ##########
//
// 它是本面板唯一会**消耗外部资源配额**的操作。一次申请失败
// 也可能已经消耗了 Let's Encrypt 的签发配额，因此"谁在什么时候
// 申请了什么"必须有据可查。
func (s *Server) handleSSLIssue(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	// 请求体可选（无 body 等价于 force=false），因此解析失败
	// 只在真的传了畸形内容时才报错。
	var req sslIssueRequest
	if r.ContentLength > 0 {
		if err := decodeJSONBody(w, r, 4*1024, &req); err != nil {
			writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
				"error": err.Error(),
				"hint":  "请求体必须是 JSON，例如 {\"force\": false}；也可以不带请求体。",
			})
			return
		}
	}

	audit := s.beginSSLAudit(r, ssl.ActionIssue, name)
	if !s.requireSSLPermission(w, audit) {
		return
	}

	// 先取一次站点信息，让审计里能带上域名（即便申请失败也有据可查）。
	if st, err := s.sslMgr.Status(r.Context()); err == nil {
		for _, item := range st.Sites {
			if item.Site == name {
				audit.domain = item.Domain
				audit.certNam = item.CertName
				break
			}
		}
	}

	res, err := s.sslMgr.Issue(r.Context(), name, req.Force)
	status, reason := s.writeSSLOperationError(w, err, res)
	audit.record(ssl.AuditEvent{
		Domain:        res.Domain,
		Outcome:       sslOutcome(err),
		Status:        status,
		Reason:        reason,
		Command:       res.Command,
		DryRun:        res.DryRun,
		Issued:        res.Issued,
		Applied:       res.Applied,
		Expiry:        certExpiry(res.Certificate),
		DaysRemaining: certDays(res.Certificate),
	})
}

// ---------------------------------------------------------------------------
// POST /api/ssl/{name}/renew —— 续期
// ---------------------------------------------------------------------------

// handleSSLRenew 为站点续期证书。
//
// 与申请同一套顺序与审计策略。
//
// 特别注意：`certbot renew` 对未进入续期窗口的证书会输出
// "not yet due for renewal" 并以 exit 0 退出。**这不是失败，
// 但也不是成功**——响应里用 renewed/skipped 两个字段区分，
// 前端据此显示"尚未到续期时间"而不是"续期成功"。
// 把跳过显示成成功，用户会看到"成功"但到期时间毫无变化，
// 从而怀疑功能是假的。
func (s *Server) handleSSLRenew(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req sslIssueRequest
	if r.ContentLength > 0 {
		if err := decodeJSONBody(w, r, 4*1024, &req); err != nil {
			writeJSON(w, s.logger, http.StatusBadRequest, map[string]any{
				"error": err.Error(),
				"hint":  "请求体必须是 JSON，例如 {\"force\": false}；也可以不带请求体。",
			})
			return
		}
	}

	audit := s.beginSSLAudit(r, ssl.ActionRenew, name)
	if !s.requireSSLPermission(w, audit) {
		return
	}

	if st, err := s.sslMgr.Status(r.Context()); err == nil {
		for _, item := range st.Sites {
			if item.Site == name {
				audit.domain = item.Domain
				audit.certNam = item.CertName
				break
			}
		}
	}

	res, err := s.sslMgr.Renew(r.Context(), name, req.Force)
	status, reason := s.writeSSLRenewError(w, err, res)
	audit.record(ssl.AuditEvent{
		Domain:        res.Domain,
		CertName:      res.CertName,
		Outcome:       sslRenewOutcome(err, res),
		Status:        status,
		Reason:        reason,
		Command:       res.Command,
		DryRun:        res.DryRun,
		Issued:        res.Renewed,
		Applied:       res.Applied,
		Renewed:       res.Renewed,
		Expiry:        certExpiry(res.Certificate),
		DaysRemaining: certDays(res.Certificate),
	})
}

// ---------------------------------------------------------------------------
// 错误映射
// ---------------------------------------------------------------------------

// writeSSLOperationError 把申请错误映射为 HTTP 响应。
//
// 返回 (状态码, 审计原因)，供调用方写入审计。
//
// ########## 状态码的选择理由 ##########
//
//	503 —— 环境不具备能力（没装 certbot），不是请求写错了
//	400 —— 请求本身有问题（通配符域名、非法域名、缺 webroot）
//	404 —— 站点不存在
//	403 —— 权限不足（在 requireSSLPermission 里已处理）
//	504 —— 超时（网关超时语义：上游 CA 没在预期时间内响应）
//	422 —— 证书已获取但配置写入失败（**部分成功**，需要用户处理）
//	502 —— certbot 执行失败（上游失败语义）
//
// 422 的选择尤其重要：它不是"服务端错误"，也不是"请求错误"，
// 而是"请求被理解了、部分完成了、但需要你介入"。
// 用 502 会让用户以为是临时故障从而直接重试——
// 而重试会重复消耗 CA 配额。
func (s *Server) writeSSLOperationError(w http.ResponseWriter, err error, res ssl.IssueResult) (int, string) {
	if err == nil {
		writeJSON(w, s.logger, http.StatusOK, res)
		return http.StatusOK, ""
	}

	status, body := sslErrorStatus(err)
	s.logger.Warn("证书申请未成功",
		"site", res.Site, "domain", res.Domain, "status", status, "err", err)
	writeJSON(w, s.logger, status, body)
	return status, err.Error()
}

// writeSSLRenewError 把续期错误映射为 HTTP 响应。
func (s *Server) writeSSLRenewError(w http.ResponseWriter, err error, res ssl.RenewResult) (int, string) {
	if err == nil {
		writeJSON(w, s.logger, http.StatusOK, res)
		return http.StatusOK, ""
	}

	status, body := sslErrorStatus(err)
	s.logger.Warn("证书续期未成功",
		"site", res.Site, "domain", res.Domain, "status", status, "err", err)
	writeJSON(w, s.logger, status, body)
	return status, err.Error()
}

// sslErrorStatus 把 ssl 包的哨兵错误映射为 HTTP 状态码与响应体。
func sslErrorStatus(err error) (int, map[string]any) {
	switch {
	case errors.Is(err, ssl.ErrNotFound):
		return http.StatusNotFound, map[string]any{
			"error": err.Error(),
			"hint":  "请检查站点名是否正确（可在「网站管理」页查看全部站点）。",
		}
	case errors.Is(err, ssl.ErrWildcardNotSupported):
		return http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint": "HTTP-01 验证无法为通配符域名签发证书。" +
				"请改用具体域名（如 example.com 或 www.example.com）。" +
				"通配符需要 DNS-01 验证，本版本未支持。",
		}
	case errors.Is(err, ssl.ErrInvalidDomain),
		errors.Is(err, ssl.ErrInvalidWebroot),
		errors.Is(err, ssl.ErrInvalidEmail),
		errors.Is(err, ssl.ErrInvalidCertName),
		errors.Is(err, ssl.ErrNoWebroot):
		return http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"hint": "请检查站点的域名与根目录配置。" +
				"注意：HTTP-01 验证需要站点有可写入的本地目录，" +
				"反向代理站暂不支持一键申请。",
		}
	case errors.Is(err, ssl.ErrClientUnavailable):
		return http.StatusServiceUnavailable, map[string]any{
			"error": err.Error(),
			"hint": "请在服务器上安装 certbot（Debian/Ubuntu: apt install certbot），" +
				"或用 -certbot-path 指定其可执行文件路径。",
		}
	case errors.Is(err, ssl.ErrTimeout):
		return http.StatusGatewayTimeout, map[string]any{
			"error": err.Error(),
			"hint": "申请/续期超时。**超时不代表没有签发**——" +
				"Let's Encrypt 可能已完成签发并计入配额。" +
				"请稍后点击「刷新」查看证书是否已存在，不要立即重试。",
			"maybe_issued": true,
		}
	case errors.Is(err, ssl.ErrAppliedFailed):
		return http.StatusUnprocessableEntity, map[string]any{
			"error": err.Error(),
			"hint": "证书已成功获取（CA 配额已消耗），但写入 nginx 配置失败。" +
				"请先修复配置问题，然后直接重试——已存在的证书不会重复签发。",
			"issued":  true,
			"applied": false,
		}
	case errors.Is(err, ssl.ErrClientFailed):
		return http.StatusBadGateway, map[string]any{
			"error": err.Error(),
			"hint": "certbot 执行失败。常见原因：域名未解析到本机、" +
				"80 端口不可达、webroot 目录不可写、或已触发 CA 速率限制。" +
				"完整日志见 /var/log/letsencrypt/letsencrypt.log。",
		}
	default:
		return http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
		}
	}
}

// sslOutcome 把申请错误映射为审计结果。
func sslOutcome(err error) string {
	switch {
	case err == nil:
		return ssl.AuditAllowed
	case errors.Is(err, ssl.ErrTimeout):
		// 超时的结果**未知**：CA 那边可能已经签发成功。
		// 记成 failed 会与真实情况不符，而配额恰恰可能已被消耗。
		return ssl.AuditPending
	case errors.Is(err, ssl.ErrWildcardNotSupported),
		errors.Is(err, ssl.ErrInvalidDomain),
		errors.Is(err, ssl.ErrInvalidWebroot),
		errors.Is(err, ssl.ErrInvalidEmail),
		errors.Is(err, ssl.ErrInvalidCertName),
		errors.Is(err, ssl.ErrNoWebroot):
		// 输入校验失败 = 未到达任何外部命令，因此是 denied
		// 而不是 failed。这个区分让审计能回答
		// "有没有人在探测注入载荷"。
		return ssl.AuditDenied
	default:
		return ssl.AuditFailed
	}
}

// sslRenewOutcome 把续期结果映射为审计结果。
//
// 与申请不同的是：续期有一个"跳过"的状态（未到续期窗口）。
// 跳过是**正常结果**，记为 allowed；它不算失败，
// 也不该被当成"续期成功"（renewed 字段单独区分）。
func sslRenewOutcome(err error, res ssl.RenewResult) string {
	if err == nil {
		return ssl.AuditAllowed
	}
	return sslOutcome(err)
}

// certExpiry 从证书信息里取到期时间（nil 安全）。
func certExpiry(c *ssl.Certificate) string {
	if c == nil {
		return ""
	}
	return c.Expiry
}

// certDays 从证书信息里取剩余天数（nil 安全）。
func certDays(c *ssl.Certificate) int {
	if c == nil {
		return 0
	}
	return c.DaysRemaining
}

// parseIntDefault 解析整数，失败时返回默认值。
func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return def
		}
	}
	return n
}
