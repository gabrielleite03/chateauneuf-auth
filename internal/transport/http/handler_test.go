package transporthttp

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"network-auth-service/internal/application/auth"
	"network-auth-service/internal/domain"
)

type fakeUserRepo struct{}

type fakeAuthorizer struct{}

func (f *fakeUserRepo) ValidateCredentials(ctx context.Context, username string, password string) (*domain.User, error) {
	if username == "apto72" && password == "senha123" {
		return &domain.User{Username: username, Enabled: true}, nil
	}
	return nil, auth.ErrSessionExpired
}

func (f *fakeAuthorizer) Authorize(ctx context.Context, client domain.Client, duration time.Duration) error {
	return nil
}

func TestPortalHandlerAndAuthenticate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	service := auth.NewService(&fakeUserRepo{}, &fakeAuthorizer{}, logger, 5*time.Minute, 24*time.Hour)
	h := NewHandler(service, logger, 5*time.Minute)
	t.Run("portal returns login page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/portal?clientMac=AA:BB:CC:DD:EE:FF&clientIp=192.168.10.10&redirectUrl=https://example.com", nil)
		res := httptest.NewRecorder()
		h.Portal(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 got %d", res.Code)
		}
		if !bytes.Contains(res.Body.Bytes(), []byte("CONECTAR")) {
			t.Fatal("expected portal login form")
		}
	})

	t.Run("authenticate success", func(t *testing.T) {
		session := service.CreatePortalSession(domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.10", RedirectURL: "/"}, "127.0.0.1", 5*time.Minute)
		form := bytes.NewBufferString("session_id=" + session.ID + "&username=apto72&password=senha123")
		req := httptest.NewRequest(http.MethodPost, "/portal/authenticate", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		h.Authenticate(res, req)
		if res.Code != http.StatusFound {
			t.Fatalf("expected redirect status 302 got %d", res.Code)
		}
	})
}
