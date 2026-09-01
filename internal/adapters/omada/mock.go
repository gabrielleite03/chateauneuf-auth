package omada

import (
	"context"
	"time"

	"network-auth-service/internal/domain"
)

// MockNetwork is only for local integrated tests without an Omada Controller.
type MockNetwork struct{}

func (MockNetwork) Authorize(context.Context, domain.Client, time.Duration) error { return nil }
func (MockNetwork) Revoke(context.Context, domain.Client) error                   { return nil }
