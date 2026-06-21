package web

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/davidvos/flashaccess/internal/session"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenCookie   = "fa_token"
	tokenLen      = 32 // bytes
	tokenMaxAge   = 12 * time.Hour
)

// authStore holds in-memory web tokens (token → sessionID).
// Tokens are issued after the user passes gate verification, and are cleared
// when the underlying session ends.  They survive for at most tokenMaxAge or
// until the server restarts.
type authStore struct {
	mu     sync.RWMutex
	tokens map[string]tokenEntry
}

type tokenEntry struct {
	sessionID string
	issuedAt  time.Time
}

func newAuthStore() *authStore {
	return &authStore{tokens: make(map[string]tokenEntry)}
}

// IssueToken mints a new web token for the given session and sets it as a
// Secure, HttpOnly, SameSite=Strict cookie on the response.
func (a *authStore) IssueToken(w http.ResponseWriter, sessionID string) {
	b := make([]byte, tokenLen)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)

	a.mu.Lock()
	a.tokens[tok] = tokenEntry{sessionID: sessionID, issuedAt: time.Now()}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    tok,
		Path:     "/",
		MaxAge:   int(tokenMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Validate returns the sessionID bound to the cookie token, and whether the
// entry is still fresh.  Returns ("", false) if invalid.
func (a *authStore) Validate(r *http.Request) (sessionID string, ok bool) {
	cookie, err := r.Cookie(tokenCookie)
	if err != nil {
		return "", false
	}
	a.mu.RLock()
	entry, exists := a.tokens[cookie.Value]
	a.mu.RUnlock()
	if !exists {
		return "", false
	}
	if time.Since(entry.issuedAt) > tokenMaxAge {
		a.Revoke(cookie.Value)
		return "", false
	}
	return entry.sessionID, true
}

// RevokeSession removes all tokens associated with a session.
func (a *authStore) RevokeSession(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for tok, entry := range a.tokens {
		if entry.sessionID == sessionID {
			delete(a.tokens, tok)
		}
	}
}

// Revoke removes a single token.
func (a *authStore) Revoke(tok string) {
	a.mu.Lock()
	delete(a.tokens, tok)
	a.mu.Unlock()
}

// ClearCookie clears the auth cookie on the response.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})
}

// VerifyAdminPassword checks a plaintext password against the stored bcrypt hash.
func VerifyAdminPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// HashAdminPassword generates a bcrypt hash suitable for storing in config.
func HashAdminPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// requireAuth is middleware that gates access to a handler.
//
// Flow:
//  1. Find active session via manager.  If none → redirect /setup.
//  2. Check client IP against session's AllowedCIDR.  If rejected → 403.
//  3. Validate web token cookie.  If missing/invalid → redirect /gate.
//  4. Forward.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active := s.mgr.ActiveSession()
		if active == nil {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

		clientIP := RealIP(r)
		if !active.IPAllowed(clientIP) {
			http.Error(w, "403 Forbidden — your IP is not permitted for this session", http.StatusForbidden)
			return
		}

		sessionID, ok := s.auth.Validate(r)
		if !ok || sessionID != active.ID {
			http.Redirect(w, r, "/gate", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RealIP extracts the originating client IP, honouring Cloudflare and standard
// reverse-proxy headers before falling back to RemoteAddr.
func RealIP(r *http.Request) net.IP {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

// activeSession is a convenience that fetches the live session and verifies
// the current request's IP.  Returns nil if there's no session or IP mismatch.
func (s *Server) activeSession(r *http.Request) *session.Session {
	sess := s.mgr.ActiveSession()
	if sess == nil {
		return nil
	}
	if !sess.IPAllowed(RealIP(r)) {
		return nil
	}
	return sess
}
