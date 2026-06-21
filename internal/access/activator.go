package access

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/davidvos/flashaccess/internal/firewall"
	"github.com/davidvos/flashaccess/internal/mysql"
	"github.com/davidvos/flashaccess/internal/session"
)

// Activator wires the security spine to real MySQL + firewall side effects.
// Its Provision/Revoke methods are registered as the Manager's hooks.
type Activator struct {
	DB   *mysql.Manager
	FW   firewall.Manager
	Port int // typically 3306
	Log  *log.Logger
}

// Provision creates the temp superuser and opens the firewall for the bound IP.
// On success it stamps the generated credentials onto the session.
func (a *Activator) Provision(s *session.Session) error {
	host, err := mysql.CIDRToHost(s.AllowedCIDR)
	if err != nil {
		return err
	}
	pw, err := genPassword(24)
	if err != nil {
		return err
	}
	user := "tmp_" + s.ID

	if err := a.DB.CreateUser(user, host, pw); err != nil {
		return fmt.Errorf("provision db user: %w", err)
	}
	if err := a.FW.Allow(s.AllowedCIDR, a.Port, "flashaccess:"+s.ID); err != nil {
		_ = a.DB.DropUser(user, host) // roll back the grant
		return fmt.Errorf("provision firewall: %w", err)
	}

	s.DBUser = user
	s.DBPassword = pw
	s.DBHost = host
	a.logf("provisioned session %s: user %s@%s, port %d open to %s",
		s.ID, user, host, a.Port, s.AllowedCIDR)
	return nil
}

// Revoke tears everything down. It attempts both steps even if one fails,
// so a stuck firewall rule never leaves a live DB grant (or vice versa).
func (a *Activator) Revoke(s *session.Session) error {
	var errs []error
	if s.DBUser != "" {
		if err := a.DB.DropUser(s.DBUser, s.DBHost); err != nil {
			errs = append(errs, fmt.Errorf("drop user: %w", err))
		}
	}
	if err := a.FW.Deny(s.AllowedCIDR, a.Port); err != nil {
		errs = append(errs, fmt.Errorf("close firewall: %w", err))
	}
	if len(errs) > 0 {
		a.logf("revoke session %s had errors: %v", s.ID, errs)
		return errors.Join(errs...)
	}
	a.logf("revoked session %s cleanly", s.ID)
	return nil
}

func (a *Activator) logf(format string, args ...any) {
	if a.Log != nil {
		a.Log.Printf(format, args...)
	}
}

// genPassword returns an alphanumeric password (~142 bits at n=24). Alphanumeric
// keeps it injection-safe for the inlined CREATE USER and Navicat-friendly.
func genPassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}