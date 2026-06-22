package session

import (
	"net"
	"strings"
	"time"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// Session is the time-boxed, IP-locked grant of root access.
type Session struct {
	ID          string    `json:"id"`
	KeyHash     string    `json:"key_hash"`
	AllowedCIDR string    `json:"allowed_cidr"`
	Database    string    `json:"database"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Status      Status    `json:"status"`

	// Provisioned by the access.Activator. DBPassword is a live credential,
	// which is why the session store is encrypted (see EncryptedPersister).
	DBUser     string `json:"db_user,omitempty"`
	DBPassword string `json:"db_password,omitempty"`
	DBHost     string `json:"db_host,omitempty"`

	// PlaygroundDB is the name of a _fa_playground_ database created for this session.
	// Empty if no playground has been set up.
	PlaygroundDB string `json:"playground_db,omitempty"`

	FailedAttempts int       `json:"failed_attempts"`
	LastAttempt    time.Time `json:"last_attempt"`
}

func (s *Session) IsLive(now time.Time) bool {
	return s.Status == StatusActive && now.Before(s.ExpiresAt)
}

func (s *Session) Remaining(now time.Time) time.Duration {
	if d := s.ExpiresAt.Sub(now); d > 0 {
		return d
	}
	return 0
}

// IPAllowed enforces the session's bound CIDR at the application layer
// (defense in depth — the firewall enforces it again at the network layer).
func (s *Session) IPAllowed(ip net.IP) bool {
	if _, ipnet, err := net.ParseCIDR(s.AllowedCIDR); err == nil {
		return ipnet.Contains(ip)
	}
	if bare := net.ParseIP(s.AllowedCIDR); bare != nil {
		return bare.Equal(ip)
	}
	return false
}

// normalizeCIDR upgrades a bare IP to a /32 (or /128) so storage is uniform.
func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return s + "/32"
		}
		return s + "/128"
	}
	return s
}
