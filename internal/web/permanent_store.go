package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PermanentGrant is a permanently-open MySQL user + optional firewall rule.
type PermanentGrant struct {
	ID          string    `json:"id"`
	DBUser      string    `json:"db_user"`
	DBHost      string    `json:"db_host"`
	AllowedCIDR string    `json:"allowed_cidr"`
	Port        int       `json:"port"`
	PrivLevel   string    `json:"priv_level"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type permanentStore struct {
	mu     sync.RWMutex
	path   string
	grants []*PermanentGrant
}

func newPermanentStore(path string) *permanentStore {
	ps := &permanentStore{path: path}
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &ps.grants)
	}
	return ps
}

func (ps *permanentStore) save() error {
	data, _ := json.MarshalIndent(ps.grants, "", "  ")
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ps.path)
}

func (ps *permanentStore) List() []*PermanentGrant {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*PermanentGrant, len(ps.grants))
	copy(out, ps.grants)
	return out
}

func (ps *permanentStore) Add(g *PermanentGrant) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.grants = append(ps.grants, g)
	return ps.save()
}

func (ps *permanentStore) Remove(id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, g := range ps.grants {
		if g.ID == id {
			ps.grants = append(ps.grants[:i], ps.grants[i+1:]...)
			return ps.save()
		}
	}
	return nil
}

func (ps *permanentStore) Get(id string) *PermanentGrant {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, g := range ps.grants {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func newGrantID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
