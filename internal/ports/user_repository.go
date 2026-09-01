package ports

import (
	"context"
	"time"

	"network-auth-service/internal/domain"
)

// UserRepository validates a username/password pair and returns the matching user.
type UserRepository interface {
	ValidateCredentials(ctx context.Context, username string, password string) (*domain.User, error)
}

type DeviceRepository interface {
	FindByMAC(ctx context.Context, mac string, now time.Time) (*domain.User, error)
	RegisterDevice(ctx context.Context, username string, device domain.AuthorizedDevice, now time.Time) (newDevice bool, err error)
	RemoveDevice(ctx context.Context, username, mac string) error
}

type AccountRepository interface {
	UserRepository
	DeviceRepository
	List(ctx context.Context) ([]domain.User, error)
	Get(ctx context.Context, id string) (*domain.User, error)
	Create(ctx context.Context, account domain.User) error
	Update(ctx context.Context, account domain.User) error
	ReplacePasswordAndClearDevices(ctx context.Context, id, passwordHash string, now time.Time) error
	Delete(ctx context.Context, id string) error
}

type ResidentDirectory interface {
	ApartmentExists(ctx context.Context, apartment string) (bool, error)
}
