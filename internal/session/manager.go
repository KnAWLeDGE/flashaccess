package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"
	"fmt"
)

const (
	maxFailedAttempts = 5
	lockoutWindow     = 5 * time.Minute
	reapInterval      = 2 * time.Second
)

var (
	ErrNotFound   = errors.New("session not found")
	ErrNotLive    = errors.New("session not live")
	ErrLockedOut  = errors.New("too many failed attempts; temporarily locked")
	ErrIPRejected = errors.New("client IP not permitted for this session")
	ErrBadKey     = errors.New("invalid session key")
)

// Persister abstracts session storage so the daemon can survive restarts.
type Persister interface {
	SaveAll([]*Session) error
	LoadAll() ([]*Session, error)
}

// Hooks let the access layer attach real side effects to the lifecycle.
type Hooks struct {
	OnProvision func(*Session) error // create DB user + open firewall
	OnRevoke    func(*Session) error // drop DB user + close firewall
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	store    Persister
	hooks    Hooks
	now      func() time.Time
	stop     chan struct{}
}

func NewManager(store Persister, hooks Hooks) (*Manager, error) {
	m := &Manager{
		sessions: make(map[string]*Session),
		store:    store,
		hooks:    hooks,
		now:      time.Now,
		stop:     make(chan struct{}),
	}
	if store != nil {
		list, err := store.LoadAll()
		if err != nil {
			return nil, err
		}
		for _, s := range list {
			m.sessions[s.ID] = s
		}
	}
	return m, nil
}

type NewParams struct {
	AllowedCIDR string
	Database    string
	Duration    time.Duration
}

func (m *Manager) New(p NewParams) (s *Session, rawKey string, err error) {
	rawKey, err = GenerateKey()
	if err != nil {
		return nil, "", err
	}
	hash, err := HashKey(rawKey)
	if err != nil {
		return nil, "", err
	}
	id, err := newID()
	if err != nil {
		return nil, "", err
	}

	now := m.now()
	s = &Session{
		ID:          id,
		KeyHash:     hash,
		AllowedCIDR: normalizeCIDR(p.AllowedCIDR),
		Database:    p.Database,
		CreatedAt:   now,
		ExpiresAt:   now.Add(p.Duration),
		Status:      StatusActive,
	}

	// Provision real resources BEFORE we register/persist the session, so a
	// failed grant never leaves a phantom "active" session behind.
	if m.hooks.OnProvision != nil {
		if err := m.hooks.OnProvision(s); err != nil {
			return nil, "", fmt.Errorf("provision: %w", err)
		}
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	if err := m.persist(); err != nil {
		// undo the provisioned resources if we can't durably record them
		if m.hooks.OnRevoke != nil {
			_ = m.hooks.OnRevoke(s)
		}
		m.mu.Lock()
		delete(m.sessions, id)
		m.mu.Unlock()
		return nil, "", err
	}
	return s, rawKey, nil
}

// VerifyAccess gates both the web dashboard login and the SSH activate command.
func (m *Manager) VerifyAccess(id, candidateKey string, clientIP net.IP) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	now := m.now()
	if !s.IsLive(now) {
		return nil, ErrNotLive
	}
	if s.FailedAttempts >= maxFailedAttempts && now.Sub(s.LastAttempt) < lockoutWindow {
		return nil, ErrLockedOut
	}

	// IP gate first — cheap, and a wrong IP shouldn't even reach key checking.
	if !s.IPAllowed(clientIP) {
		s.FailedAttempts++
		s.LastAttempt = now
		return nil, ErrIPRejected
	}

	good, err := VerifyKey(candidateKey, s.KeyHash)
	if err != nil {
		return nil, err
	}
	if !good {
		s.FailedAttempts++
		s.LastAttempt = now
		return nil, ErrBadKey
	}

	s.FailedAttempts = 0
	return s, nil
}

// End revokes a session immediately (the dashboard "End now" button / CLI).
func (m *Manager) End(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	s.Status = StatusRevoked
	m.mu.Unlock()

	if m.hooks.OnRevoke != nil {
		if err := m.hooks.OnRevoke(s); err != nil {
			return err
		}
	}
	return m.persist()
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// SetPlaygroundDB records the playground database name for the active session.
func (m *Manager) SetPlaygroundDB(id, dbName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	s.PlaygroundDB = dbName
	return m.persist()
}

// Start launches the background reaper that expires + revokes sessions.
func (m *Manager) Start() {
	go func() {
		t := time.NewTicker(reapInterval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				m.reap()
			}
		}
	}()
}

func (m *Manager) Stop() { close(m.stop) }

func (m *Manager) reap() {
	now := m.now()
	var expired []*Session

	m.mu.Lock()
	for _, s := range m.sessions {
		if s.Status == StatusActive && !now.Before(s.ExpiresAt) {
			s.Status = StatusExpired
			expired = append(expired, s)
		}
	}
	m.mu.Unlock()

	for _, s := range expired {
		if m.hooks.OnRevoke != nil {
			_ = m.hooks.OnRevoke(s) // best-effort; revoke errors get audit-logged later
		}
	}
	if len(expired) > 0 {
		_ = m.persist()
	}
}

func (m *Manager) persist() error {
	if m.store == nil {
		return nil
	}
	m.mu.RLock()
	m.mu.RLock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		cp := *s
		list = append(list, &cp)
	}
	m.mu.RUnlock()
	return m.store.SaveAll(list)
}

func newID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil // e.g. "a91f3c2d7b40"
}
