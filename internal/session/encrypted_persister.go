package session

import (
	"encoding/json"
	"os"
)

// Crypter is satisfied by config.Store (AES-256-GCM with the machine master key).
type Crypter interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(sealed []byte) ([]byte, error)
}

// EncryptedPersister stores sessions encrypted at rest, because sessions now
// hold live DB passwords (not just key hashes).
type EncryptedPersister struct {
	Path    string
	Crypter Crypter
}

func (e *EncryptedPersister) SaveAll(list []*Session) error {
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	sealed, err := e.Crypter.Encrypt(data)
	if err != nil {
		return err
	}
	tmp := e.Path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.Path)
}

func (e *EncryptedPersister) LoadAll() ([]*Session, error) {
	sealed, err := os.ReadFile(e.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data, err := e.Crypter.Decrypt(sealed)
	if err != nil {
		return nil, err
	}
	var list []*Session
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}