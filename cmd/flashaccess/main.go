package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KnAWLeDGE/flashaccess/internal/access"
	"github.com/KnAWLeDGE/flashaccess/internal/config"
	"github.com/KnAWLeDGE/flashaccess/internal/firewall"
	"github.com/KnAWLeDGE/flashaccess/internal/mysql"
	"github.com/KnAWLeDGE/flashaccess/internal/session"
	"github.com/KnAWLeDGE/flashaccess/internal/web"

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
	case "mode":
		cmdMode(os.Args[2:])
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
		cmdServe(cfg, mgr, db, store, fw)
	case "session":
		cmdSession(mgr, cfg, os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

// ── connect ───────────────────────────────────────────────────
func cmdConnect() {
	fmt.Println("FlashAccess — initial configuration")
	fmt.Println(strings.Repeat("─", 44))

	r := bufio.NewReader(os.Stdin)

	// ── Fresh install option ──────────────────────────────────────
	store := config.NewStore(config.DefaultDir)
	if _, err := store.Load(); err == nil {
		// Config already exists — offer to wipe and start fresh.
		fmt.Println()
		fmt.Println("⚠  Existing configuration found.")
		fmt.Println("   A fresh install will delete all existing data (config, sessions,")
		fmt.Println("   master key) from", config.DefaultDir)
		fmt.Println("   The flashaccess service will be stopped if it is running.")
		fmt.Println()
		if promptYN(r, "Start fresh (delete existing data)?", false) {
			// Stop the service if it is running.
			_ = stopService()
			if err := os.RemoveAll(config.DefaultDir); err != nil {
				fatal(fmt.Errorf("remove data dir: %w", err))
			}
			fmt.Println("Wiped", config.DefaultDir)
		} else {
			fmt.Println("Keeping existing data — re-running configuration will overwrite settings.")
		}
		fmt.Println()
	}

	host := prompt(r, "MySQL host", "127.0.0.1")
	portStr := prompt(r, "MySQL port", "3306")
	socket := prompt(r, "MySQL socket (leave blank to use TCP)", "")
	user := prompt(r, "MySQL user", "root")

	fmt.Print("MySQL password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
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

	fmt.Println()
	fmt.Println("Installation mode:")
	fmt.Println("  unrestricted — full CRUD: manage MySQL users, create/drop databases,")
	fmt.Println("                 configure remote access. Default and recommended for")
	fmt.Println("                 experienced operators.")
	fmt.Println("  strict       — browse and query only; dangerous operations are hidden.")
	modeAns := promptYN(r, "Enable strict (safe) mode?", false)
	mode := config.ModeUnrestricted
	if modeAns {
		mode = config.ModeStrict
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
		Mode:              mode,
		Defaults: config.SessionDefaults{
			Duration: "30m",
		},
	}

	// Verify DB connection before saving.
	db, err := mysql.Open(cfg.DB)
	if err != nil {
		fatal(fmt.Errorf("cannot connect to MySQL with the provided credentials: %w", err))
	}
	db.Close()

	if err := store.Save(cfg); err != nil {
		fatal(fmt.Errorf("save config: %w", err))
	}

	fmt.Println()
	fmt.Printf("Configuration saved to %s (mode: %s)\n", config.DefaultDir, mode)
	fmt.Println("Run `flashaccess serve` to start the dashboard.")
}

// ── mode ──────────────────────────────────────────────────────
func cmdMode(args []string) {
	store := config.NewStore(config.DefaultDir)
	cfg, err := store.Load()
	if err != nil {
		fatal(fmt.Errorf("config not found — run `flashaccess connect` first: %w", err))
	}

	if len(args) == 0 {
		fmt.Printf("Current mode: %s\n", cfg.EffectiveMode())
		fmt.Println()
		fmt.Println("Usage: flashaccess mode <strict|unrestricted>")
		return
	}

	switch args[0] {
	case config.ModeStrict:
		cfg.Mode = config.ModeStrict
	case config.ModeUnrestricted:
		cfg.Mode = config.ModeUnrestricted
	default:
		fatal(fmt.Errorf("unknown mode %q — use 'strict' or 'unrestricted'", args[0]))
	}

	if err := store.Save(cfg); err != nil {
		fatal(fmt.Errorf("save config: %w", err))
	}
	fmt.Printf("Mode set to: %s\n", cfg.Mode)
	fmt.Println("Restart flashaccess serve for changes to take effect.")
}

// ── serve ─────────────────────────────────────────────────────
func cmdServe(cfg *config.Config, mgr *session.Manager, db *mysql.Manager, store *config.Store, fw firewall.Manager) {
	addr := cfg.ListenAddr
	if a := os.Getenv("FLASHACCESS_ADDR"); a != "" {
		addr = a
	}
	if addr == "" {
		addr = "127.0.0.1:7432"
	}
	fmt.Printf("FlashAccess dashboard listening on http://%s (mode: %s)\n", addr, cfg.EffectiveMode())
	srv := web.New(cfg, mgr, db, store, fw)
	if err := srv.ListenAndServe(addr); err != nil {
		fatal(err)
	}
}

// ── session ───────────────────────────────────────────────────
func cmdSession(mgr *session.Manager, cfg *config.Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: flashaccess session <new|activate|end> [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "new":
		dur := cfg.Defaults.Duration
		if dur == "" {
			dur = "30m"
		}
		d, err := time.ParseDuration(dur)
		if err != nil {
			fatal(fmt.Errorf("invalid default duration %q: %w", dur, err))
		}
		cidr := ""
		if len(args) > 1 {
			cidr = args[1]
		}
		sess, key, err := mgr.New(session.NewParams{Duration: d, AllowedCIDR: cidr})
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Session ID : %s\n", sess.ID)
		fmt.Printf("Key        : %s\n", key)
		fmt.Printf("Expires    : %s\n", sess.ExpiresAt.Format(time.RFC3339))

	case "activate":
		if len(args) < 4 {
			fatal(fmt.Errorf("usage: flashaccess session activate <id> <key> <ip>"))
		}
		id, key, ipStr := args[1], args[2], args[3]
		clientIP := net.ParseIP(ipStr)
		if clientIP == nil {
			fatal(fmt.Errorf("invalid IP address %q", ipStr))
		}
		sess, err := mgr.VerifyAccess(id, key, clientIP)
		if err != nil {
			fatal(err)
		}
		fmt.Println("Key verified.")
		fmt.Printf("  Host     : %s\n", cfg.DB.Host)
		fmt.Printf("  Port     : %d\n", cfg.DB.Port)
		fmt.Printf("  User     : %s\n", sess.DBUser)
		fmt.Printf("  Password : %s\n", sess.DBPassword)
		fmt.Printf("  Expires  : %s\n", sess.ExpiresAt.Format(time.RFC3339))

	case "end":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: flashaccess session end <id>"))
		}
		if err := mgr.End(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("Session ended.")

	default:
		fatal(fmt.Errorf("unknown session subcommand: %s", args[0]))
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `FlashAccess %s — temporary MySQL access portal

Usage:
  flashaccess connect           Configure MySQL credentials and admin password
  flashaccess serve             Start the web dashboard
  flashaccess mode <mode>       Get or set operation mode (strict|unrestricted)
  flashaccess session new       Create a new session (CLI)
  flashaccess session end <id>  End a session (CLI)
  flashaccess version           Print version

`, version)
}

func promptYN(r *bufio.Reader, question string, def bool) bool {
	yn := "y/N"
	if def {
		yn = "Y/n"
	}
	fmt.Printf("%s [%s]: ", question, yn)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func stopService() error {
	p, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return exec.Command(p, "stop", "flashaccess").Run()
}
