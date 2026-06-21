package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KnAWLeDGE/flashaccess/internal/mysql"
	"github.com/KnAWLeDGE/flashaccess/internal/session"
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
	DetectedIP string // IP the server sees for this request (helps user fill in CIDR)
}

type setupDefaults struct {
	Duration string
	CIDR     string
}

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	// If a session is already active, send to dashboard
	if s.mgr.ActiveSession() != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Auto-detect the client IP so the user knows what to put in the CIDR field.
	detectedIP := ""
	if ip := RealIP(r); ip != nil {
		detectedIP = ip.String()
	}

	// Pre-fill CIDR with detected IP if there's no saved default.
	cidr := s.cfg.Defaults.AllowedCIDR
	if cidr == "" && detectedIP != "" {
		cidr = detectedIP + "/32"
	}

	s.render(w, "setup", setupData{
		Defaults: setupDefaults{
			Duration: s.cfg.Defaults.Duration,
			CIDR:     cidr,
		},
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
		time.Sleep(500 * time.Millisecond) // slow brute-force
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
		s.render(w, "setup", setupData{Error: fmt.Sprintf("invalid duration %q (try 4h, 30m, 1h30m)", durStr)})
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

	// Stash key in a short-lived, server-side display cookie (shown once on /keyshow).
	http.SetCookie(w, &http.Cookie{
		Name:     "fa_newkey",
		Value:    rawKey + ":" + sess.ID,
		Path:     "/keyshow",
		MaxAge:   120, // 2 minutes to read it
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/keyshow", http.StatusSeeOther)
}

// ── Key reveal (shown once after setup) ────────────────────────────────────

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

	// Clear the one-time cookie
	http.SetCookie(w, &http.Cookie{
		Name: "fa_newkey", Value: "", Path: "/keyshow", MaxAge: -1,
	})

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

// ── Gate (key verification) ─────────────────────────────────────────────────

type gateData struct {
	Error      string
	DetectedIP string // shown when IP is rejected, to help the user debug
}

func (s *Server) handleGateGet(w http.ResponseWriter, r *http.Request) {
	if s.mgr.ActiveSession() == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	// Already authenticated?
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

// ── Dashboard ───────────────────────────────────────────────────────────────

// dashBase carries fields common to every dashboard page.
type dashBase struct {
	Session   *session.Session
	Remaining string // pre-formatted "2h 41m"
	Databases []string
	CurrentDB string
}

type dashboardData struct {
	dashBase
}

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
		Session:   active,
		Remaining: remStr,
		Databases: dbs,
		CurrentDB: currentDB,
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

// ── DB page (list tables for a database) ───────────────────────────────────

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

// ── Browse table ───────────────────────────────────────────────────────────

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

	// Build pagination
	var pages []pageLink
	for i := 0; i*limit < int(total); i++ {
		off := i * limit
		pages = append(pages, pageLink{
			Label:  strconv.Itoa(i + 1),
			Offset: off,
			Active: off == offset,
		})
		if len(pages) > 20 { // cap at 20 page links
			break
		}
	}

	s.renderDash(w, "browse", browseData{
		dashBase: base,
		Table:    table,
		Columns:  cols,
		Result:   result,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
		OrderBy:  orderBy,
		OrderDir: orderDir,
		Pages:    pages,
	})
}

// ── Table structure ─────────────────────────────────────────────────────────

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

// ── SQL query editor ────────────────────────────────────────────────────────

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

	sql := strings.TrimSpace(r.FormValue("sql"))
	if sql == "" {
		s.renderDash(w, "query", queryData{dashBase: base})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result := s.db.RunUserQuery(ctx, db, sql)
	s.renderDash(w, "query", queryData{base, sql, result})
}

// ── API ─────────────────────────────────────────────────────────────────────

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

// ── Helpers ─────────────────────────────────────────────────────────────────

func queryInt(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
