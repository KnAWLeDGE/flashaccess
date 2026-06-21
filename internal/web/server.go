package web

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/KnAWLeDGE/flashaccess/internal/config"
	"github.com/KnAWLeDGE/flashaccess/internal/mysql"
	"github.com/KnAWLeDGE/flashaccess/internal/session"
)

type Server struct {
	cfg   *config.Config
	store *config.Store
	mgr   *session.Manager
	db    *mysql.Manager
	auth  *authStore
	pages map[string]*template.Template
}

func New(cfg *config.Config, mgr *session.Manager, db *mysql.Manager, store *config.Store) *Server {
	s := &Server{cfg: cfg, store: store, mgr: mgr, db: db, auth: newAuthStore()}
	var err error
	s.pages, err = parseTemplates()
	if err != nil {
		panic(fmt.Sprintf("flashaccess: parse templates: %v", err))
	}
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	// Pre-session
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /keyshow", s.handleKeyShow)

	// Gate
	mux.HandleFunc("GET /gate", s.handleGateGet)
	mux.HandleFunc("POST /gate", s.handleGatePost)

	// Dashboard
	mux.Handle("GET /dashboard", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /dashboard/{db}", s.requireAuth(http.HandlerFunc(s.handleDBPage)))
	mux.Handle("GET /dashboard/{db}/{table}", s.requireAuth(http.HandlerFunc(s.handleBrowse)))
	mux.Handle("GET /dashboard/{db}/{table}/structure", s.requireAuth(http.HandlerFunc(s.handleStructure)))
	mux.Handle("GET /dashboard/{db}/query", s.requireAuth(http.HandlerFunc(s.handleQuery)))
	mux.Handle("POST /dashboard/{db}/query", s.requireAuth(http.HandlerFunc(s.handleQuery)))

	// Stats
	mux.Handle("GET /stats", s.requireAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("GET /api/stats", s.requireAuth(http.HandlerFunc(s.handleAPIStats)))

	// User management (unrestricted mode only — handler enforces this)
	mux.Handle("GET /users", s.requireAuth(http.HandlerFunc(s.handleUsers)))
	mux.Handle("POST /users/create", s.requireAuth(http.HandlerFunc(s.handleUserCreate)))
	mux.Handle("POST /users/drop", s.requireAuth(http.HandlerFunc(s.handleUserDrop)))

	// Database management
	mux.Handle("POST /databases/create", s.requireAuth(http.HandlerFunc(s.handleDBCreate)))
	mux.Handle("POST /databases/drop", s.requireAuth(http.HandlerFunc(s.handleDBDrop)))

	// Playground
	mux.Handle("GET /playground", s.requireAuth(http.HandlerFunc(s.handlePlayground)))
	mux.Handle("POST /playground/create", s.requireAuth(http.HandlerFunc(s.handlePlaygroundCreate)))
	mux.Handle("POST /playground/drop", s.requireAuth(http.HandlerFunc(s.handlePlaygroundDrop)))

	// AI
	mux.Handle("GET /ai/settings", s.requireAuth(http.HandlerFunc(s.handleAISettings)))
	mux.Handle("GET /api/schema/{db}", s.requireAuth(http.HandlerFunc(s.handleAPISchema)))
	mux.Handle("POST /api/ai/execute", s.requireAuth(http.HandlerFunc(s.handleAIExecute)))
	mux.Handle("POST /api/query/preview", s.requireAuth(http.HandlerFunc(s.handleAPIQueryPreview)))

	// API
	mux.Handle("POST /api/session/end", s.requireAuth(http.HandlerFunc(s.handleSessionEnd)))

	// Root
	mux.HandleFunc("GET /", s.handleRoot)

	return mux
}

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
