package security

import (
	"sync"
	"time"

	"network-auth-service/internal/domain"
)

// PortalSessionStore keeps portal session state for a short time window.
type PortalSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*domain.PortalSession
}

func NewPortalSessionStore() *PortalSessionStore {
	return &PortalSessionStore{sessions: make(map[string]*domain.PortalSession)}
}

func (s *PortalSessionStore) Get(id string) (*domain.PortalSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	return session, ok
}

func (s *PortalSessionStore) Set(id string, session *domain.PortalSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

func (s *PortalSessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *PortalSessionStore) PruneExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.IsExpired(now) {
			delete(s.sessions, id)
		}
	}
}
