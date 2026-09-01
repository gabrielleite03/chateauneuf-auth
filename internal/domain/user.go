package domain

import "time"

// User represents the account used for captive portal authentication.
type User struct {
	ID             string
	AccountType    string
	Name           string
	Apartment      string
	Username       string
	PasswordHash   string
	Enabled        bool
	ExpiresAt      time.Time
	MaxConnections int
	DownloadKbps   int
	UploadKbps     int
	Devices        []AuthorizedDevice
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type AuthorizedDevice struct {
	MAC          string    `json:"mac"`
	IP           string    `json:"ip,omitempty"`
	AuthorizedAt time.Time `json:"authorized_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (u User) CanAuthenticate(now time.Time) bool {
	return u.Enabled && !u.ExpiresAt.IsZero() && now.Before(u.ExpiresAt)
}
