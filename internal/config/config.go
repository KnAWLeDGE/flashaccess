package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	DefaultDir = "/var/lib/flashaccess"
	configFile = "config.enc"
	keyFile    = "master.key"
)

// Mode controls which operations are available in the web UI.
const (
	ModeUnrestricted = "unrestricted" // full CRUD, user management, remote access
	ModeStrict       = "strict"       // read-only-ish; no user mgmt, no DB drops
)

// DBConfig describes how FlashAccess reaches the local MySQL admin interface.
type DBConfig struct {
	Socket        string `json:"socket,omitempty"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password,omitempty"`
}

type SessionDefaults struct {
	Duration    string `json:"duration"`     // e.g. "30m"
	AllowedCIDR string `json:"allowed_cidr"` // last-used / default bound IP
}

type Config struct {
	DB                DBConfig        `json:"db"`
	ListenAddr        string          `json:"listen_addr"`
	AdminPasswordHash string          `json:"admin_password_hash"`
	Defaults          SessionDefaults `json:"defaults"`
	// Mode is "unrestricted" (default) or "strict".
	// Unrestricted: full MySQL CRUD, user management, remote access control.
	// Strict: browse/query only; dangerous ops are hidden/disabled.
	Mode string `json:"mode,omitempty"`
}

// EffectiveMode returns Mode, falling back to ModeUnrestricted if unset.
func (c *Config) EffectiveMode() string {
	if c.Mode == ModeStrict {
		return ModeStrict
	}
	return ModeUnrestricted
}

func (s *Store) path() string { return filepath.Join(s.dir, "config.enc") }

// Store reads/writes the encrypted config under a directory (0700).
type Store struct{ dir string }

func NewStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{dir: dir}
}

// Save seals the config with the machine master key and writes it atomically.
func (s *Store) Save(c *Config) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	sealed, err := s.Encrypt(data)
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

func (s *Store) Load() (*Config, error) {
	gcm, err := s.cipher()
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(filepath.Join(s.dir, configFile))
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("config corrupt: too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt config (wrong master key or tampered): %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Store) cipher() (cipher.AEAD, error) {
	key, err := s.masterKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// masterKey loads the 32-byte AES key, generating it on first run.
func (s *Store) masterKey() ([]byte, error) {
	path := filepath.Join(s.dir, keyFile)
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, errors.New("master key corrupt: expected 32 bytes")
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt seals plaintext with the machine master key (AES-256-GCM).
func (s *Store) Encrypt(plain []byte) ([]byte, error) {
	gcm, err := s.cipher()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// Decrypt opens data produced by Encrypt.
func (s *Store) Decrypt(sealed []byte) ([]byte, error) {
	gcm, err := s.cipher()
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
