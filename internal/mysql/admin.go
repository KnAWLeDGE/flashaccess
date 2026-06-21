package mysql

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// userNamePattern allows human-chosen usernames (alphanumeric + underscore, 1–32 chars).
var userNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)

// hostPattern allows IPs, wildcards, and MySQL subnet patterns.
// Examples: %, 192.168.1.%, 10.0.0.1, localhost
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9_.%:/\-]{1,60}$`)

// dbNamePattern allows standard database names.
var dbNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

// UserInfo represents a MySQL account.
type UserInfo struct {
	User   string
	Host   string
	Plugin string
}

// ListUsers returns all accounts from mysql.user.
func (m *Manager) ListUsers(ctx context.Context) ([]UserInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT User, Host, plugin
		FROM mysql.user
		ORDER BY User, Host`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		if err := rows.Scan(&u.User, &u.Host, &u.Plugin); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CreateAdminUser creates a permanent MySQL user with the given privilege level.
// Supported privLevel values: "all", "readwrite", "read"
func (m *Manager) CreateAdminUser(ctx context.Context, user, host, password, privLevel string) error {
	if !userNamePattern.MatchString(user) {
		return fmt.Errorf("invalid username %q (alphanumeric + underscore, 1–32 chars)", user)
	}
	if !hostPattern.MatchString(host) {
		return fmt.Errorf("invalid host pattern %q", host)
	}
	if !safePassword(password) || len(password) < 8 {
		return fmt.Errorf("password must be at least 8 alphanumeric characters")
	}

	var grantSQL string
	switch privLevel {
	case "read":
		grantSQL = fmt.Sprintf("GRANT SELECT ON *.* TO '%s'@'%s'", user, host)
	case "readwrite":
		grantSQL = fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO '%s'@'%s'", user, host)
	default: // "all"
		grantSQL = fmt.Sprintf("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%s' WITH GRANT OPTION", user, host)
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stmts := []string{
		fmt.Sprintf("CREATE USER '%s'@'%s' IDENTIFIED BY '%s'", user, host, password),
		grantSQL,
		"FLUSH PRIVILEGES",
	}
	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx2, s); err != nil {
			_, _ = m.db.ExecContext(ctx2, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s'", user, host))
			return fmt.Errorf("create user: %w", err)
		}
	}
	return nil
}

// DropAdminUser drops a MySQL user. Refuses to touch tmp_ session users.
func (m *Manager) DropAdminUser(ctx context.Context, user, host string) error {
	// Session temp users are managed by the session lifecycle — don't touch them here.
	if userPattern.MatchString(user) {
		return fmt.Errorf("cannot drop session user %q via UI — end the session instead", user)
	}
	if !userNamePattern.MatchString(user) {
		return fmt.Errorf("invalid username %q", user)
	}
	if !hostPattern.MatchString(host) {
		return fmt.Errorf("invalid host %q", host)
	}
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := m.db.ExecContext(ctx2,
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s'", user, host)); err != nil {
		return fmt.Errorf("drop user: %w", err)
	}
	_, _ = m.db.ExecContext(ctx2, "FLUSH PRIVILEGES")
	return nil
}

// CreateDatabase creates a new schema if it doesn't already exist.
func (m *Manager) CreateDatabase(ctx context.Context, name string) error {
	if !dbNamePattern.MatchString(name) {
		return fmt.Errorf("invalid database name %q (alphanumeric, underscore, hyphen)", name)
	}
	_, err := m.db.ExecContext(ctx,
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", escIdent(name)))
	return err
}

// DropDatabase permanently drops a schema. Refuses system schemas.
func (m *Manager) DropDatabase(ctx context.Context, name string) error {
	if !dbNamePattern.MatchString(name) {
		return fmt.Errorf("invalid database name %q", name)
	}
	switch strings.ToLower(name) {
	case "mysql", "information_schema", "performance_schema", "sys":
		return fmt.Errorf("refusing to drop system database %q", name)
	}
	_, err := m.db.ExecContext(ctx,
		fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", escIdent(name)))
	return err
}
