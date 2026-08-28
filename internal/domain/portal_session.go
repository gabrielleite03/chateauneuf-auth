package domain

import "time"

// PortalSession stores the client context captured during the Omada portal redirect.
type PortalSession struct {
	ID        string
	Client    Client
	CreatedAt time.Time
	ExpiresAt time.Time
	SourceIP  string
	Used      bool
}

func (s PortalSession) IsExpired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}
