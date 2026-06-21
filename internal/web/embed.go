package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"time"
)

//go:embed templates static
var webFS embed.FS

// staticFS is a sub-filesystem rooted at "static/" for the file server.
var staticFS, _ = fs.Sub(webFS, "static")

// templateFuncs are helper functions available in all templates.
var templateFuncs = template.FuncMap{
	"fmtDuration": func(d time.Duration) string {
		d = d.Round(time.Second)
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		sc := int(d.Seconds()) % 60
		if h > 0 {
			return fmt.Sprintf("%dh %02dm %02ds", h, m, sc)
		}
		return fmt.Sprintf("%dm %02ds", m, sc)
	},
	"fmtElapsed": func(d time.Duration) string {
		if d < time.Millisecond {
			return fmt.Sprintf("%dµs", d.Microseconds())
		}
		return fmt.Sprintf("%.3fs", d.Seconds())
	},
	"join": strings.Join,
	"add":  func(a, b int) int { return a + b },
	"sub":  func(a, b int) int { return a - b },
	"mul":  func(a, b int) int { return a * b },
	"seq": func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	},
	"trimSpace": strings.TrimSpace,
	"lower":     strings.ToLower,
}

// parseTemplates builds one *template.Template per page.  Each is parsed
// together with its layout so {{template "title" .}} / {{template "body" .}}
// resolve correctly within that set.
func parseTemplates() (map[string]*template.Template, error) {
	pages := map[string]struct {
		layout string
		page   string
	}{
		// Simple layout (gate, setup, keyshow)
		"gate":    {"templates/layout.html", "templates/gate.html"},
		"setup":   {"templates/layout.html", "templates/setup.html"},
		"keyshow": {"templates/layout.html", "templates/keyshow.html"},
		// Dashboard layout
		"dashboard": {"templates/dash_layout.html", "templates/dashboard.html"},
		"db":        {"templates/dash_layout.html", "templates/db.html"},
		"browse":    {"templates/dash_layout.html", "templates/browse.html"},
		"structure": {"templates/dash_layout.html", "templates/structure.html"},
		"query":     {"templates/dash_layout.html", "templates/query.html"},
	}

	out := make(map[string]*template.Template, len(pages))
	for name, p := range pages {
		t, err := template.New(name).Funcs(templateFuncs).ParseFS(webFS, p.layout, p.page)
		if err != nil {
			return nil, fmt.Errorf("parse template %q: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}
