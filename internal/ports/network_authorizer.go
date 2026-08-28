package ports

import (
	"context"
	"time"

	"network-auth-service/internal/domain"
)

// NetworkAuthorizer authorizes the client that initiated the captive portal authentication.
type NetworkAuthorizer interface {
	Authorize(ctx context.Context, client domain.Client, duration time.Duration) error
}
