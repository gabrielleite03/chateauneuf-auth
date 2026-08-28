package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"network-auth-service/internal/domain"
)

type stubUserRepo struct {
	user *domain.User
	err  error
}

func (s *stubUserRepo) ValidateCredentials(ctx context.Context, username string, password string) (*domain.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.user == nil {
		return nil, errors.New("user not found")
	}
	if username != s.user.Username {
		return nil, errors.New("user not found")
	}
	return s.user, nil
}

type stubNetworkAuthorizer struct {
	err error
}

func (s *stubNetworkAuthorizer) Authorize(ctx context.Context, client domain.Client, duration time.Duration) error {
	return s.err
}

func TestAuthService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	t.Run("valid user", func(t *testing.T) {
		repo := &stubUserRepo{user: &domain.User{Username: "apto72", Enabled: true}}
		authorizer := &stubNetworkAuthorizer{}
		svc := NewService(repo, authorizer, logger, time.Minute, time.Hour)
		session := svc.CreatePortalSession(domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.5", RedirectURL: "/"}, "127.0.0.1", time.Minute)
		result, err := svc.Authenticate(context.Background(), session.ID, "apto72", "senha123")
		if err != nil || !result.Authenticated {
			t.Fatalf("expected authentication success, err=%v, result=%+v", err, result)
		}
	})

	t.Run("invalid password", func(t *testing.T) {
		repo := &stubUserRepo{err: errors.New("invalid password")}
		svc := NewService(repo, &stubNetworkAuthorizer{}, logger, time.Minute, time.Hour)
		session := svc.CreatePortalSession(domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.5", RedirectURL: "/"}, "127.0.0.1", time.Minute)
		_, err := svc.Authenticate(context.Background(), session.ID, "apto72", "bad")
		if err == nil {
			t.Fatal("expected auth failure")
		}
	})

	t.Run("session expired", func(t *testing.T) {
		repo := &stubUserRepo{user: &domain.User{Username: "apto72", Enabled: true}}
		svc := NewService(repo, &stubNetworkAuthorizer{}, logger, time.Minute, time.Hour)
		session := &domain.PortalSession{ID: "bad", Client: domain.Client{MAC: "AA", IP: "1.1.1.1"}, CreatedAt: time.Now().Add(-2 * time.Minute), ExpiresAt: time.Now().Add(-1 * time.Minute), SourceIP: "127.0.0.1"}
		svc.portalSessions.sessions[session.ID] = session
		_, err := svc.Authenticate(context.Background(), session.ID, "apto72", "senha123")
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("expected session expired, got %v", err)
		}
	})

	t.Run("authorizer failed", func(t *testing.T) {
		repo := &stubUserRepo{user: &domain.User{Username: "apto72", Enabled: true}}
		svc := NewService(repo, &stubNetworkAuthorizer{err: errors.New("reject")}, logger, time.Minute, time.Hour)
		session := svc.CreatePortalSession(domain.Client{MAC: "AA", IP: "1.1.1.1"}, "127.0.0.1", time.Minute)
		_, err := svc.Authenticate(context.Background(), session.ID, "apto72", "senha123")
		if err == nil {
			t.Fatal("expected authorizer failure")
		}
	})
}
