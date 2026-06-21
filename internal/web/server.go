// Package web provides the HTTP server for the FlashAccess dashboard.
// It is embedded into the main binary alongside the CLI; "flashaccess serve"
// starts it.  Templates and static files are embedded at compile time.
package web

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/davidvos/flashaccess/internal/config"
	"github.com/davidvos/flashaccess/internal/mysql"
	"github.com/davidvos/flashaccess/internal/session"
)

// Server holds shared state for the HTTP layer.
type Server struct {
	cfg   *config.Config
	store *config.Store
	mgr   *session.Manager
	db    *mysql.Manager
	auth  *authStore
	pages map[string]*template.Template
}

// New builds a Server and pre-parses all HTML templates.
// Fatal errors (bad templates) are returned; the caller should log and exit.
func New(cfg *config.Config, mgr *session.Manager, db *mysql.Manager, store *config.Store) *Server {
	s := &Server{
		cfg:   cfg,
		store: store,
		mgr:   mgr,
		db:    db,
		auth:  newAuthStore(),
	}
	var err error
	s.pages, err = parseTemplates()
	if err != nil {
		panic(fmt.Sprintf("flashaccess: parse templates: %v", err))
	}
	return s
}

// ListenAndServe wires up the router and starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

// Handler returns the top-level http.Handler for the web server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static assets (embedded)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	// ── Pre-session routes (no auth required) ──────────────────────────────
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /keyshow", s.handleKeyShow)

	// ── Gate (key entry, session must be active) ────────────────────────────
	mux.HandleFunc("GET /gate", s.handleGateGet)
	mux.HandleFunc("POST /gate", s.handleGatePost)

	// ── Dashboard (full auth required) ─────────────────────────────────────
	mux.Handle("GET /dashboard", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /dashboard/{db}", s.requireAuth(http.HandlerFunc(s.handleDBPage)))
	mux.Handle("GET /dashboard/{db}/{table}", s.requireAuth(http.HandlerFunc(s.handleBrowse)))
	mux.Handle("GET /dashboard/{db}/{table}/structure", s.requireAuth(http.HandlerFunc(s.handleStructure)))
	mux.Handle("GET /dashboard/{db}/query", s.requireAuth(http.HandlerFunc(s.handleQuery)))
	mux.Handle("POST /dashboard/{db}/query", s.requireAuth(http.HandlerFunc(s.handleQuery)))

	// ── API ─────────────────────────────────────────────────────────────────
	mux.Handle("POST /api/session/end", s.requireAuth(http.HandlerFunc(s.handleSessionEnd)))

	// Root: redirect based on state
	mux.HandleFunc("GET /", s.handleRoot)

	return mux
}

// render executes a named page template, writing to w.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderDash renders a dashboard-layout page.
func (s *Server) renderDash(w http.ResponseWriter, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "dash_layout", data); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
	}
}
