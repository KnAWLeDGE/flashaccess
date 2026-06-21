package session

import "time"

// ActiveSession returns the first live session (typically only one exists at a time).
func (m *Manager) ActiveSession() *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	for _, s := range m.sessions {
		if s.IsLive(now) {
			return s
		}
	}
	return nil
}

// ActiveSessions returns copies of all currently live sessions.
func (m *Manager) ActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	var out []*Session
	for _, s := range m.sessions {
		if s.IsLive(now) {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out
}

// RemainingFor returns the remaining duration for a session given its ID, or 0.
func (m *Manager) RemainingFor(id string, now time.Time) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.sessions[id]; ok {
		return s.Remaining(now)
	}
	return 0
}
