package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"time"

	"github.com/KnAWLeDGE/flashaccess/internal/mysql"
)

//go:embed templates static
var webFS embed.FS

var staticFS, _ = fs.Sub(webFS, "static")

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
	"fmtPct": func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"join":      strings.Join,
	"add":       func(a, b int) int { return a + b },
	"sub":       func(a, b int) int { return a - b },
	"mul":       func(a, b int) int { return a * b },
	"seq": func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	},
	"trimSpace": strings.TrimSpace,
	"lower":     strings.ToLower,
	"hasPfx":    strings.HasPrefix,
	"jsonRow": func(row []string, cols []string) template.JS {
		m := make(map[string]string, len(row))
		for i, v := range row {
			if i < len(cols) {
				m[cols[i]] = v
			}
		}
		b, _ := json.Marshal(m)
		return template.JS(b)
	},
	"jsonColumns": func(cols []mysql.ColumnInfo) template.JS {
		type colJS struct {
			Field string `json:"field"`
			Type  string `json:"type"`
		}
		out := make([]colJS, len(cols))
		for i, c := range cols {
			out[i] = colJS{Field: c.Field, Type: c.Type}
		}
		b, _ := json.Marshal(out)
		return template.JS(b)
	},
}

func parseTemplates() (map[string]*template.Template, error) {
	pages := map[string]struct {
		layout string
		page   string
	}{
		"gate":      {"templates/layout.html", "templates/gate.html"},
		"setup":     {"templates/layout.html", "templates/setup.html"},
		"keyshow":   {"templates/layout.html", "templates/keyshow.html"},
		"dashboard": {"templates/dash_layout.html", "templates/dashboard.html"},
		"db":        {"templates/dash_layout.html", "templates/db.html"},
		"browse":    {"templates/dash_layout.html", "templates/browse.html"},
		"structure": {"templates/dash_layout.html", "templates/structure.html"},
		"query":     {"templates/dash_layout.html", "templates/query.html"},
		"stats":       {"templates/dash_layout.html", "templates/stats.html"},
		"users":       {"templates/dash_layout.html", "templates/users.html"},
		"ai_settings": {"templates/dash_layout.html", "templates/ai_settings.html"},
		"playground":  {"templates/dash_layout.html", "templates/playground.html"},
		"permanent":   {"templates/dash_layout.html", "templates/permanent.html"},
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
