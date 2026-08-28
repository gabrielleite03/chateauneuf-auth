package ports

import (
	"context"

	"network-auth-service/internal/domain"
)

// UserRepository validates a username/password pair and returns the matching user.
type UserRepository interface {
	ValidateCredentials(ctx context.Context, username string, password string) (*domain.User, error)
}
