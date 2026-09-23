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

	t.Run("gateway portal accepts redirect without client IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/portal?clientMac=AA:BB:CC:DD:EE:10&gatewayMac=11:22:33:44:55:66&vid=20&site=Chateauneuf", nil)
		res := httptest.NewRecorder()
		h.Portal(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 got %d", res.Code)
		}
	})

	t.Run("portal accepts alternate Omada parameter spelling", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/portal?client_mac=AA:BB:CC:DD:EE:11&gateway_mac=11:22:33:44:55:66&vlan_id=20", nil)
		res := httptest.NewRecorder()
		h.Portal(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 got %d: %s", res.Code, res.Body.String())
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
		if res.Header().Get("Location") != "/portal/success" {
			t.Fatalf("unexpected redirect %q", res.Header().Get("Location"))
		}
	})

	t.Run("authenticate uses safe local landing page for external URL", func(t *testing.T) {
		session := service.CreatePortalSession(domain.Client{MAC: "AA:BB:CC:DD:EE:20", IP: "192.168.10.20", RedirectURL: "http://neverssl.com/"}, "127.0.0.1", 5*time.Minute)
		form := bytes.NewBufferString("session_id=" + session.ID + "&username=apto72&password=senha123")
		req := httptest.NewRequest(http.MethodPost, "/portal/authenticate", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		h.Authenticate(res, req)
		if res.Header().Get("Location") != "/portal/success" {
			t.Fatalf("unexpected redirect %q", res.Header().Get("Location"))
		}
	})

	t.Run("authenticate uses local landing page for relative probe URL", func(t *testing.T) {
		session := service.CreatePortalSession(domain.Client{MAC: "AA:BB:CC:DD:EE:21", RedirectURL: "/generate_204"}, "127.0.0.1", 5*time.Minute)
		form := bytes.NewBufferString("session_id=" + session.ID + "&username=apto72&password=senha123")
		req := httptest.NewRequest(http.MethodPost, "/portal/authenticate", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		h.Authenticate(res, req)
		if res.Header().Get("Location") != "/portal/success" {
			t.Fatalf("unexpected redirect %q", res.Header().Get("Location"))
		}
	})
}

func TestPortalRouterAcceptsOmadaURLVariants(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	service := auth.NewService(&fakeUserRepo{}, &fakeAuthorizer{}, logger, 5*time.Minute, 24*time.Hour)
	router := NewRouter(NewHandler(service, logger, 5*time.Minute))

	for _, path := range []string{"/?clientMac=AA:BB:CC:DD:EE:31", "/portal/?clientMac=AA:BB:CC:DD:EE:32"} {
		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
		if res.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, res.Code)
		}
	}

	res := httptest.NewRecorder()
	router.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if res.Code != http.StatusNotFound {
		t.Errorf("unknown path: expected 404, got %d", res.Code)
	}
}
