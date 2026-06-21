package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KnAWLeDGE/flashaccess/internal/mysql"
	"github.com/KnAWLeDGE/flashaccess/internal/session"
	"github.com/KnAWLeDGE/flashaccess/internal/stats"
)

// ── Root ───────────────────────────────────────────────────────────────────

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.mgr.ActiveSession() == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, ok := s.auth.Validate(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/gate", http.StatusSeeOther)
}

// ── Setup wizard ───────────────────────────────────────────────────────────

type setupData struct {
	Error      string
	Defaults   setupDefaults
	DetectedIP string
}

type setupDefaults struct {
	Duration string
	CIDR     string
}

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	if s.mgr.ActiveSession() != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	detectedIP := ""
	if ip := RealIP(r); ip != nil {
		detectedIP = ip.String()
	}
	cidr := s.cfg.Defaults.AllowedCIDR
	if cidr == "" && detectedIP != "" {
		if net.ParseIP(detectedIP).To4() != nil {
			cidr = detectedIP + "/32"
		} else {
			cidr = detectedIP + "/128"
		}
	}
	s.render(w, "setup", setupData{
		Defaults:   setupDefaults{Duration: s.cfg.Defaults.Duration, CIDR: cidr},
		DetectedIP: detectedIP,
	})
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if s.mgr.ActiveSession() != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, "setup", setupData{Error: "invalid form data"})
		return
	}
	adminPw := r.FormValue("admin_password")
	if s.cfg.AdminPasswordHash == "" {
		s.render(w, "setup", setupData{Error: "admin password not configured — run `flashaccess connect` first"})
		return
	}
	if !VerifyAdminPassword(s.cfg.AdminPasswordHash, adminPw) {
		time.Sleep(500 * time.Millisecond)
		s.render(w, "setup", setupData{Error: "incorrect admin password"})
		return
	}
	cidr := strings.TrimSpace(r.FormValue("allowed_ip"))
	if cidr == "" {
		s.render(w, "setup", setupData{Error: "an allowed IP or CIDR is required"})
		return
	}
	durStr := r.FormValue("duration")
	if durStr == "" {
		durStr = "4h"
	}
	dur, err := time.ParseDuration(durStr)
	if err != nil {
		s.render(w, "setup", setupData{Error: fmt.Sprintf("invalid duration %q", durStr)})
		return
	}
	if dur < time.Minute || dur > 48*time.Hour {
		s.render(w, "setup", setupData{Error: "duration must be between 1m and 48h"})
		return
	}
	sess, rawKey, err := s.mgr.New(session.NewParams{
		AllowedCIDR: cidr,
		Database:    fmt.Sprintf("%s:%d", s.cfg.DB.Host, s.cfg.DB.Port),
		Duration:    dur,
	})
	if err != nil {
		s.render(w, "setup", setupData{Error: "failed to start session: " + err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "fa_newkey", Value: rawKey + ":" + sess.ID,
		Path: "/keyshow", MaxAge: 120,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/keyshow", http.StatusSeeOther)
}

// ── Key reveal ─────────────────────────────────────────────────────────────

type keyshowData struct {
	Key       string
	SessionID string
	IP        string
	Duration  string
	ExpiresAt string
}

func (s *Server) handleKeyShow(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("fa_newkey")
	if err != nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	parts := strings.SplitN(cookie.Value, ":", 2)
	if len(parts) != 2 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	rawKey, sessionID := parts[0], parts[1]
	http.SetCookie(w, &http.Cookie{Name: "fa_newkey", Value: "", Path: "/keyshow", MaxAge: -1})
	sess, ok := s.mgr.Get(sessionID)
	if !ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, "keyshow", keyshowData{
		Key:       rawKey,
		SessionID: sessionID,
		IP:        sess.AllowedCIDR,
		Duration:  sess.ExpiresAt.Sub(time.Now()).Round(time.Minute).String(),
		ExpiresAt: sess.ExpiresAt.Format("2006-01-02 15:04 UTC"),
	})
}

// ── Gate ───────────────────────────────────────────────────────────────────

type gateData struct {
	Error      string
	DetectedIP string
}

func (s *Server) handleGateGet(w http.ResponseWriter, r *http.Request) {
	if s.mgr.ActiveSession() == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, ok := s.auth.Validate(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, "gate", gateData{})
}

func (s *Server) handleGatePost(w http.ResponseWriter, r *http.Request) {
	active := s.mgr.ActiveSession()
	if active == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, "gate", gateData{Error: "invalid form"})
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	clientIP := RealIP(r)
	_, err := s.mgr.VerifyAccess(active.ID, key, clientIP)
	if err != nil {
		time.Sleep(400 * time.Millisecond)
		detectedIP := ""
		if clientIP != nil {
			detectedIP = clientIP.String()
		}
		errMsg := "invalid key or IP not allowed"
		if errors.Is(err, session.ErrIPRejected) {
			errMsg = fmt.Sprintf(
				"IP not allowed — server sees your IP as %s, but the session allows %s",
				detectedIP, active.AllowedCIDR,
			)
		}
		s.render(w, "gate", gateData{Error: errMsg, DetectedIP: detectedIP})
		return
	}
	s.auth.IssueToken(w, active.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// ── Dashboard ──────────────────────────────────────────────────────────────

type dashBase struct {
	Session      *session.Session
	Remaining    string
	Databases    []string
	CurrentDB    string
	Mode         string // "strict" or "unrestricted"
	Section      string // active sidebar section: "db", "stats", "users", "playground"
	PlaygroundDB string // name of active playground DB, if any
}

type dashboardData struct{ dashBase }

func (s *Server) buildDashBase(r *http.Request, currentDB string) (dashBase, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	active := s.mgr.ActiveSession()
	dbs, err := s.db.ListDatabases(ctx)
	if err != nil {
		return dashBase{}, err
	}
	rem := active.Remaining(time.Now())
	remStr := fmt.Sprintf("%dh %02dm", int(rem.Hours()), int(rem.Minutes())%60)
	return dashBase{
		Session:      active,
		Remaining:    remStr,
		Databases:    dbs,
		CurrentDB:    currentDB,
		Mode:         s.cfg.EffectiveMode(),
		PlaygroundDB: active.PlaygroundDB,
	}, nil
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	base, err := s.buildDashBase(r, "")
	if err != nil {
		http.Error(w, "failed to list databases: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderDash(w, "dashboard", dashboardData{base})
}

// ── DB page ────────────────────────────────────────────────────────────────

type dbPageData struct {
	dashBase
	Tables []mysql.TableInfo
}

func (s *Server) handleDBPage(w http.ResponseWriter, r *http.Request) {
	db := r.PathValue("db")
	base, err := s.buildDashBase(r, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tables, err := s.db.ListTables(ctx, db)
	if err != nil {
		http.Error(w, "list tables: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderDash(w, "db", dbPageData{base, tables})
}

// ── Browse ─────────────────────────────────────────────────────────────────

type browseData struct {
	dashBase
	Table    string
	Columns  []mysql.ColumnInfo
	Result   *mysql.QueryResult
	Total    int64
	Limit    int
	Offset   int
	OrderBy  string
	OrderDir string
	Pages    []pageLink
}

type pageLink struct {
	Label  string
	Offset int
	Active bool
}

func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	db := r.PathValue("db")
	table := r.PathValue("table")
	q := r.URL.Query()
	limit := queryInt(q.Get("limit"), 50)
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset := queryInt(q.Get("offset"), 0)
	orderBy := q.Get("order")
	orderDir := q.Get("dir")

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	base, err := s.buildDashBase(r, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cols, err := s.db.ListColumns(ctx, db, table)
	if err != nil {
		http.Error(w, "list columns: "+err.Error(), http.StatusInternalServerError)
		return
	}
	total, err := s.db.Count(ctx, db, table)
	if err != nil {
		http.Error(w, "count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	result, err := s.db.BrowseTable(ctx, db, table, limit, offset, orderBy, orderDir)
	if err != nil {
		http.Error(w, "browse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var pages []pageLink
	for i := 0; i*limit < int(total); i++ {
		off := i * limit
		pages = append(pages, pageLink{Label: strconv.Itoa(i + 1), Offset: off, Active: off == offset})
		if len(pages) > 20 {
			break
		}
	}
	s.renderDash(w, "browse", browseData{
		dashBase: base, Table: table, Columns: cols, Result: result,
		Total: total, Limit: limit, Offset: offset, OrderBy: orderBy, OrderDir: orderDir, Pages: pages,
	})
}

// ── Structure ──────────────────────────────────────────────────────────────

type structureData struct {
	dashBase
	Table   string
	Columns []mysql.ColumnInfo
	Indexes []mysql.IndexInfo
}

func (s *Server) handleStructure(w http.ResponseWriter, r *http.Request) {
	db := r.PathValue("db")
	table := r.PathValue("table")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	base, err := s.buildDashBase(r, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cols, err := s.db.ListColumns(ctx, db, table)
	if err != nil {
		http.Error(w, "columns: "+err.Error(), http.StatusInternalServerError)
		return
	}
	idxs, err := s.db.ListIndexes(ctx, db, table)
	if err != nil {
		http.Error(w, "indexes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderDash(w, "structure", structureData{base, table, cols, idxs})
}

// ── Query ──────────────────────────────────────────────────────────────────

type queryData struct {
	dashBase
	SQL    string
	Result *mysql.QueryResult
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	db := r.PathValue("db")
	base, err := s.buildDashBase(r, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Accept SQL from POST body, form field "sql", or "q" query param (used by AI links).
	sql := strings.TrimSpace(r.FormValue("sql"))
	if sql == "" {
		sql = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	if sql == "" {
		s.renderDash(w, "query", queryData{dashBase: base})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result := s.db.RunUserQuery(ctx, db, sql)
	s.renderDash(w, "query", queryData{base, sql, result})
}

// ── Stats ──────────────────────────────────────────────────────────────────

type statsPageData struct {
	dashBase
	Snap        *stats.Snapshot
	SnapErr     string
	ProcessList *mysql.QueryResult
	FmtBytes    func(uint64) string
	FmtUptime   func(time.Duration) string
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	base, err := s.buildDashBase(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	base.Section = "stats"

	snap, snapErr := stats.Collect()
	snapErrStr := ""
	if snapErr != nil {
		snapErrStr = snapErr.Error()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pl := s.db.RunUserQuery(ctx, "", "SHOW PROCESSLIST")

	s.renderDash(w, "stats", statsPageData{
		dashBase:    base,
		Snap:        snap,
		SnapErr:     snapErrStr,
		ProcessList: pl,
		FmtBytes:    stats.FmtBytes,
		FmtUptime:   stats.FmtUptime,
	})
}

// GET /api/stats — JSON for live polling
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	snap, err := stats.Collect()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"cpu":          snap.CPU,
		"mem_used":     snap.MemUsed,
		"mem_total":    snap.MemTotal,
		"mem_pct":      snap.MemPercent,
		"disk_used":    snap.DiskUsed,
		"disk_total":   snap.DiskTotal,
		"disk_pct":     snap.DiskPercent,
		"uptime_sec":   int64(snap.Uptime.Seconds()),
		"mem_used_fmt": stats.FmtBytes(snap.MemUsed),
		"mem_total_fmt": stats.FmtBytes(snap.MemTotal),
		"disk_used_fmt": stats.FmtBytes(snap.DiskUsed),
		"disk_total_fmt": stats.FmtBytes(snap.DiskTotal),
		"uptime_fmt":   stats.FmtUptime(snap.Uptime),
	})
}

// ── Users (unrestricted only) ──────────────────────────────────────────────

type usersPageData struct {
	dashBase
	Users  []mysql.UserInfo
	Error  string
	Notice string
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EffectiveMode() != "unrestricted" {
		http.Error(w, "403 — user management is disabled in strict mode", http.StatusForbidden)
		return
	}
	base, err := s.buildDashBase(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	users, err := s.db.ListUsers(ctx)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	notice := r.URL.Query().Get("notice")
	base.Section = "users"
	s.renderDash(w, "users", usersPageData{dashBase: base, Users: users, Error: errStr, Notice: notice})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EffectiveMode() != "unrestricted" {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	host := strings.TrimSpace(r.FormValue("host"))
	pass := strings.TrimSpace(r.FormValue("password"))
	privLevel := r.FormValue("privs")

	if host == "" {
		host = "%"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := s.db.CreateAdminUser(ctx, user, host, pass, privLevel); err != nil {
		base, _ := s.buildDashBase(r, "")
		dbUsers, _ := s.db.ListUsers(ctx)
		s.renderDash(w, "users", usersPageData{dashBase: base, Users: dbUsers, Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/users?notice=User+created+successfully", http.StatusSeeOther)
}

func (s *Server) handleUserDrop(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EffectiveMode() != "unrestricted" {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := r.FormValue("username")
	host := r.FormValue("host")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.db.DropAdminUser(ctx, user, host); err != nil {
		base, _ := s.buildDashBase(r, "")
		dbUsers, _ := s.db.ListUsers(ctx)
		s.renderDash(w, "users", usersPageData{dashBase: base, Users: dbUsers, Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/users?notice=User+dropped+successfully", http.StatusSeeOther)
}

// ── Database management ────────────────────────────────────────────────────

func (s *Server) handleDBCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.db.CreateDatabase(ctx, name); err != nil {
		http.Error(w, "create database: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/dashboard/"+name, http.StatusSeeOther)
}

func (s *Server) handleDBDrop(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EffectiveMode() != "unrestricted" {
		http.Error(w, "403 — dropping databases is disabled in strict mode", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.db.DropDatabase(ctx, name); err != nil {
		http.Error(w, "drop database: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// ── Session end ────────────────────────────────────────────────────────────

func (s *Server) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
	active := s.mgr.ActiveSession()
	if active == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.auth.RevokeSession(active.ID)
	if err := s.mgr.End(active.ID); err != nil {
		http.Error(w, "end session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ClearCookie(w)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}


// ── Playground ────────────────────────────────────────────────────────────

type playgroundPageData struct {
	dashBase
	Error  string
	Notice string
}

func (s *Server) handlePlayground(w http.ResponseWriter, r *http.Request) {
	base, err := s.buildDashBase(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	base.Section = "playground"
	notice := r.URL.Query().Get("notice")
	errMsg := r.URL.Query().Get("error")
	s.renderDash(w, "playground", playgroundPageData{dashBase: base, Notice: notice, Error: errMsg})
}

func (s *Server) handlePlaygroundCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	active := s.mgr.ActiveSession()
	if active == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	mode := r.FormValue("mode") // "generate" or "clone"
	srcDB := r.FormValue("source_db")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	pgName := mysql.PlaygroundDBName(active.ID)

	// Drop existing playground first (idempotent).
	if active.PlaygroundDB != "" {
		_ = s.db.DropPlaygroundDB(ctx, active.PlaygroundDB)
	}

	if err := s.db.CreatePlaygroundDB(ctx, pgName); err != nil {
		http.Redirect(w, r, "/playground?error="+err.Error(), http.StatusSeeOther)
		return
	}

	var cloneErr error
	switch mode {
	case "clone":
		if srcDB == "" {
			http.Redirect(w, r, "/playground?error=source+database+required+for+clone", http.StatusSeeOther)
			return
		}
		cloneErr = s.db.CloneDatabase(ctx, srcDB, pgName)
	default: // "generate"
		cloneErr = s.db.GenerateSampleDatabase(ctx, pgName)
	}

	if cloneErr != nil {
		_ = s.db.DropPlaygroundDB(ctx, pgName) // rollback
		http.Redirect(w, r, "/playground?error="+cloneErr.Error(), http.StatusSeeOther)
		return
	}

	if err := s.mgr.SetPlaygroundDB(active.ID, pgName); err != nil {
		http.Redirect(w, r, "/playground?error="+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard/"+pgName+"?notice=Playground+ready", http.StatusSeeOther)
}

func (s *Server) handlePlaygroundDrop(w http.ResponseWriter, r *http.Request) {
	active := s.mgr.ActiveSession()
	if active == nil || active.PlaygroundDB == "" {
		http.Redirect(w, r, "/playground", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_ = s.db.DropPlaygroundDB(ctx, active.PlaygroundDB)
	_ = s.mgr.SetPlaygroundDB(active.ID, "")
	http.Redirect(w, r, "/playground?notice=Playground+dropped", http.StatusSeeOther)
}

// ── AI Settings page ──────────────────────────────────────────────────────

func (s *Server) handleAISettings(w http.ResponseWriter, r *http.Request) {
	base, err := s.buildDashBase(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	base.Section = "ai-settings"
	s.renderDash(w, "ai_settings", base)
}

// ── Query Preview API ─────────────────────────────────────────────────────

// handleAPIQueryPreview analyses a SQL statement without executing it.
// POST /api/query/preview  body: {"db":"name","sql":"..."}
func (s *Server) handleAPIQueryPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DB  string `json:"db"`
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SQL == "" {
		http.Error(w, "sql is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	preview := s.db.PreviewQuery(ctx, req.DB, req.SQL)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(preview)
}

// ── AI API ────────────────────────────────────────────────────────────────

// handleAPISchema returns the full schema of a database as JSON.
// GET /api/schema/{db}
func (s *Server) handleAPISchema(w http.ResponseWriter, r *http.Request) {
	dbName := r.PathValue("db")
	if dbName == "" {
		http.Error(w, "missing database name", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	tables, err := s.db.ListTables(ctx, dbName)
	if err != nil {
		http.Error(w, "list tables: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type columnJSON struct {
		Field   string `json:"field"`
		Type    string `json:"type"`
		Null    string `json:"null"`
		Key     string `json:"key"`
		Default string `json:"default"`
		Extra   string `json:"extra"`
		Comment string `json:"comment"`
	}
	type indexJSON struct {
		Name    string   `json:"name"`
		Unique  bool     `json:"unique"`
		Type    string   `json:"type"`
		Columns []string `json:"columns"`
	}
	type tableJSON struct {
		Name    string       `json:"name"`
		Engine  string       `json:"engine"`
		Rows    int64        `json:"rows"`
		Columns []columnJSON `json:"columns"`
		Indexes []indexJSON  `json:"indexes"`
	}

	out := make([]tableJSON, 0, len(tables))
	for _, t := range tables {
		cols, err := s.db.ListColumns(ctx, dbName, t.Name)
		if err != nil {
			http.Error(w, "list columns: "+err.Error(), http.StatusInternalServerError)
			return
		}
		idxs, err := s.db.ListIndexes(ctx, dbName, t.Name)
		if err != nil {
			http.Error(w, "list indexes: "+err.Error(), http.StatusInternalServerError)
			return
		}

		colsJSON := make([]columnJSON, len(cols))
		for i, c := range cols {
			def := ""
			if c.Default.Valid {
				def = c.Default.String
			}
			colsJSON[i] = columnJSON{
				Field: c.Field, Type: c.Type, Null: c.Null,
				Key: c.Key, Default: def, Extra: c.Extra, Comment: c.Comment,
			}
		}
		idxsJSON := make([]indexJSON, len(idxs))
		for i, ix := range idxs {
			idxsJSON[i] = indexJSON{Name: ix.Name, Unique: ix.Unique, Type: ix.Type, Columns: ix.Columns}
		}
		out = append(out, tableJSON{Name: t.Name, Engine: t.Engine, Rows: t.Rows, Columns: colsJSON, Indexes: idxsJSON})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"database": dbName, "tables": out})
}

// handleAIExecute runs a DDL/DML statement submitted by the AI feature layer.
// POST /api/ai/execute   body: {"db":"name","sql":"..."}
// This endpoint requires session auth (enforced by requireAuth middleware).
// The AI JS layer must have already obtained user confirmation before calling this.
func (s *Server) handleAIExecute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DB  string `json:"db"`
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SQL == "" {
		http.Error(w, "sql is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result := s.db.RunUserQuery(ctx, req.DB, req.SQL)
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"affected":  result.Affected,
		"elapsed":   result.Elapsed.Milliseconds(),
		"columns":   result.Columns,
		"rows":      result.Rows,
		"is_select": result.IsSelect,
	}
	if result.Err != "" {
		resp["error"] = result.Err
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Helpers ────────────────────────────────────────────────────────────────

func queryInt(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
