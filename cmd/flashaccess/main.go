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
	