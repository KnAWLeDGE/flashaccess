package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/KnAWLeDGE/flashaccess/internal/config"
	_ "github.com/go-sql-driver/mysql"
)

// userPattern guards against injection in the (non-parameterizable) CREATE USER
// statement. We only ever build usernames as tmp_<hexid>, so this must hold.
var userPattern = regexp.MustCompile(`^tmp_[a-f0-9]{6,32}$`)

type Manager struct{ db *sql.DB }

// Open connects as the local admin. On Ubuntu, root@localhost uses auth_socket,
// so prefer the unix socket with an empty password.
func Open(c config.DBConfig) (*Manager, error) {
	db, err := sql.Open("mysql", dsn(c))
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect to mysql admin: %w", err)
	}
	return &Manager{db: db}, nil
}

func (m *Manager) Close() error { return m.db.Close() }

// CreateUser provisions a temporary superuser scoped to a MySQL host pattern.
// password MUST be from a safe alphabet (alphanumeric) — it is inlined, since
// CREATE USER does not accept bind parameters.
func (m *Manager) CreateUser(user, host, password string) error {
	if !userPattern.MatchString(user) {
		return fmt.Errorf("refusing to create user with unsafe name %q", user)
	}
	if !safePassword(password) {
		return fmt.Errorf("generated password contains unsafe characters")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stmts := []string{
		fmt.Sprintf("CREATE USER '%s'@'%s' IDENTIFIED BY '%s'", user, host, password),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%s' WITH GRANT OPTION", user, host),
		"FLUSH PRIVILEGES",
	}
	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx, s); err != nil {
			// best-effort cleanup so a half-created user doesn't linger
			_, _ = m.db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s'", user, host))
			return fmt.Errorf("grant: %w", err)
		}
	}
	return nil
}

func (m *Manager) DropUser(user, host string) error {
	if !userPattern.MatchString(user) {
		return fmt.Errorf("refusing to drop user with unsafe name %q", user)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := m.db.ExecContext(ctx,
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s'", user, host)); err != nil {
		return fmt.Errorf("drop user: %w", err)
	}
	_, _ = m.db.ExecContext(ctx, "FLUSH PRIVILEGES")
	return nil
}

// CIDRToHost converts a stored CIDR into a MySQL host pattern.
//   - /32 or /128  -> bare IP
//   - IPv4 range   -> "ip/netmask" form (MySQL-supported)
//   - IPv6 range   -> rejected (MySQL has no netmask form for v6)
func CIDRToHost(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		if bare := net.ParseIP(cidr); bare != nil {
			return bare.String(), nil
		}
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		return ip.String(), nil
	}
	if ip.To4() == nil {
		// MySQL has no subnet notation for IPv6. Fall back to '%' and rely on the
		// UFW firewall rule (which does support IPv6 CIDRs) for network enforcement.
		return "%", nil
	}
	return fmt.Sprintf("%s/%s", ipnet.IP.String(), net.IP(ipnet.Mask).String()), nil
}

func dsn(c config.DBConfig) string {
	if c.Socket != "" {
		return fmt.Sprintf("%s:%s@unix(%s)/?timeout=5s", c.AdminUser, c.AdminPassword, c.Socket)
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=5s", c.AdminUser, c.AdminPassword, c.Host, c.Port)
}

func safePassword(p string) bool {
	if len(p) == 0 {
		return false
	}
	for _, r := range p {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}