package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davidvos/flashaccess/internal/access"
	"github.com/davidvos/flashaccess/internal/config"
	"github.com/davidvos/flashaccess/internal/firewall"
	"github.com/davidvos/flashaccess/internal/mysql"
	"github.com/davidvos/flashaccess/internal/session"
	"github.com/davidvos/flashaccess/internal/web"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Commands that don't require a pre-existing config or DB connection.
	switch os.Args[1] {
	case "version":
		fmt.Println("FlashAccess", version)
		return
	case "connect":
		cmdConnect()
		return
	}

	// All other commands need config + DB.
	store := config.NewStore(config.DefaultDir)
	cfg, err := store.Load()
	if err != nil {
		fatal(fmt.Errorf("config not found — run `flashaccess connect` first: %w", err))
	}

	db, err := mysql.Open(cfg.DB)
	if err != nil {
		fatal(fmt.Errorf("cannot connect to MySQL: %w", err))
	}
	defer db.Close()

	var fw firewall.Manager = firewall.NewUFW()
	if os.Getenv("FLASHACCESS_NOFW") == "1" {
		fw = firewall.Noop{}
	}

	act := &access.Activator{
		DB:   db,
		FW:   fw,
		Port: cfg.DB.Port,
		Log:  log.New(os.Stderr, "[flashaccess] ", log.LstdFlags),
	}
	if act.Port == 0 {
		act.Port = 3306
	}

	persister := &session.EncryptedPersister{
		Path:    filepath.Join(config.DefaultDir, "sessions.enc"),
		Crypter: store,
	}
	mgr, err := session.NewManager(persister, session.Hooks{
		OnProvision: act.Provision,
		OnRevoke:    act.Revoke,
	})
	if err != nil {
		fatal(err)
	}
	mgr.Start()
	defer mgr.Stop()

	switch os.Args[1] {
	case "serve":
		cmdServe(cfg, mgr, db, store)
	case "session":
		cmdSession(mgr, cfg, os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

// ── connect ───────────────────────────────────────────────────
// Interactive wizard: DB config + admin password setup.
func cmdConnect() {
	fmt.Println("FlashAccess — initial configuration")
	fmt.Println(strings.Repeat("─", 44))

	r := bufio.NewReader(os.Stdin)

	host := prompt(r, "MySQL host", "127.0.0.1")
	portStr := prompt(r, "MySQL port", "3306")
	socket := prompt(r, "MySQL socket (leave blank to use TCP)", "")
	user := prompt(r, "MySQL user", "root")

	fmt.Print("MySQL password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		// Fallback for non-terminal (e.g. piped input)
		line, _ := r.ReadString('\n')
		pwBytes = []byte(strings.TrimRight(line, "\r\n"))
	}
	dbPassword := string(pwBytes)

	listenAddr := prompt(r, "Dashboard listen address", "127.0.0.1:7432")

	fmt.Println()
	fmt.Println("Set an admin password to protect the session-creation UI.")
	fmt.Print("Admin password: ")
	adminPwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		line, _ := r.ReadString('\n')
		adminPwBytes = []byte(strings.TrimRight(line, "\r\n"))
	}

	if len(adminPwBytes) < 8 {
		fatal(fmt.Errorf("admin password must be at least 8 characters"))
	}

	adminHash, err := bcrypt.GenerateFromPassword(adminPwBytes, bcrypt.DefaultCost)
	if err != nil {
		fatal(fmt.Errorf("hash admin password: %w", err))
	}

	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		port = 3306
	}

	cfg := &config.Config{
		DB: config.DBConfig{
			Host:          host,
			Port:          port,
			Socket:        socket,
			AdminUser:     user,
			AdminPassword: dbPassword,
		},
		ListenAddr:        listenAddr,
		AdminPasswordHash: string(adminHash),
		Defaults: config.SessionDefaults{
			Duration:    "30m",
			AllowedCIDR: "",
		},
	}

	// Verify connection before saving.
	fmt.Print("\nVerifying MySQL connection… ")
	db, err := mysql.Open(cfg.DB)
	if err != nil {
		fmt.Println("FAILED")
		fatal(fmt.Errorf("cannot connect to MySQL: %w", err))
	}
	db.Close()
	fmt.Println("OK")

	store := config.NewStore(config.DefaultDir)
	if err := store.Save(cfg); err != nil {
		fatal(fmt.Errorf("save config: %w", err))
	}

	fmt.Println("Config saved to", config.DefaultDir)
	fmt.Println()
	fmt.Println("Run `flashaccess serve` to start the dashboard.")
}

// ── serve ─────────────────────────────────────────────────────
func cmdServe(cfg *config.Config, mgr *session.Manager, db *mysql.Manager, store *config.Store) {
	addr := cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:7432"
	}
	// Override from env for container / systemd overrides.
	if v := os.Getenv("FLASHACCESS_ADDR"); v != "" {
		addr = v
	}

	srv := web.New(cfg, mgr, db, store)
	fmt.Printf("FlashAccess dashboard listening on http://%s\n", addr)
	if err := srv.ListenAndServe(addr); err != nil {
		fatal(err)
	}
}

// ── session ───────────────────────────────────────────────────
func cmdSession(mgr *session.Manager, cfg *config.Config, args []string) {
	if len(args) == 0 {
		fmt.Println("usage: flashaccess session new|activate|end")
		return
	}
	switch args[0] {
	case "new":
		dur, _ := time.ParseDuration(orDefault(cfg.Defaults.Duration, "30m"))
		s, key, err := mgr.New(session.NewParams{
			AllowedCIDR: orDefault(cfg.Defaults.AllowedCIDR, "0.0.0.0/0"),
			Database:    fmt.Sprintf("%s:%d", orDefault(cfg.DB.Host, "localhost"), cfg.DB.Port),
			Duration:    dur,
		})
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Session:  %s\n", s.ID)
		fmt.Printf("Bound IP: %s\n", s.AllowedCIDR)
		fmt.Printf("Expires:  %s\n", s.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Key (shown once): %s\n", key)
		fmt.Println("DB user provisioned and firewall rule opened.")

	case "activate":
		if len(args) < 4 {
			fmt.Println("usage: flashaccess session activate <id> <key> <ip>")
			return
		}
		s, err := mgr.VerifyAccess(args[1], args[2], net.ParseIP(args[3]))
		if err != nil {
			fmt.Printf("DENIED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("GRANTED — session %s, %s remaining\n", s.ID, s.Remaining(time.Now()).Round(time.Second))
		fmt.Println("Connect with:")
		fmt.Printf("  host:     %s:%d\n", cfg.DB.Host, cfg.DB.Port)
		fmt.Printf("  user:     %s\n", s.DBUser)
		fmt.Printf("  password: %s\n", s.DBPassword)

	case "end":
		if len(args) < 2 {
			fmt.Println("usage: flashaccess session end <id>")
			return
		}
		if err := mgr.End(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("Session ended; temp user dropped and firewall rule removed.")

	default:
		fmt.Println("usage: flashaccess session new|activate|end")
		os.Exit(1)
	}
}

// ── helpers ───────────────────────────────────────────────────
func prompt(r *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def
	}
	return line
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func usage() {
	fmt.Printf(`FlashAccess %s — temporary IP-locked MySQL access

Usage:
  flashaccess connect                            Configure DB connection and admin password
  flashaccess serve                              Start the web dashboard
  flashaccess session new                        Create a session (CLI)
  flashaccess session activate <id> <key> <ip>  Verify and reveal credentials (Navicat etc.)
  flashaccess session end <id>                   Terminate a session early
  flashaccess version                            Print version
`, version)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
