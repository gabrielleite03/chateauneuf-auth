package domain

import "time"

// User represents the account used for captive portal authentication.
type User struct {
	Username     string
	PasswordHash string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
