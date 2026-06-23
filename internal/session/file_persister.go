package session

import (
	"encoding/json"
	"os"
)

// FilePersister stores session metadata as JSON (0600). Key hashes only —
// no raw keys ever land on disk.
type FilePersister struct{ Path string }

func (f *FilePersister) SaveAll(list []*Session) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}

func (f *FilePersister) LoadAll() ([]*Session, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []*Session
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}