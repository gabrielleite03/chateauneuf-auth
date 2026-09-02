package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"network-auth-service/internal/domain"
	"network-auth-service/internal/ports"
)

var (
	ErrSessionExpired = errors.New("portal session expired")
	ErrSessionUsed    = errors.New("portal session already used")
	ErrInvalidClient  = errors.New("client identity mismatch")
)

// Service handles portal authentication and authorization decisions.
type Service struct {
	userRepo           ports.UserRepository
	networkAuthorizer  ports.NetworkAuthorizer
	portalSessions     *PortalSessionStore
	logger             *slog.Logger
	clientAuthDuration time.Duration
}

// PortalSessionStore is the runtime authority for portal session and replay checks.
type PortalSessionStore struct {
	sessions map[string]*domain.PortalSession
	mu       sync.Mutex
}

func NewService(userRepo ports.UserRepository, networkAuthorizer ports.NetworkAuthorizer, logger *slog.Logger, portalTTL time.Duration, clientAuthDuration time.Duration) *Service {
	return &Service{
		userRepo:           userRepo,
		networkAuthorizer:  networkAuthorizer,
		portalSessions:     &PortalSessionStore{sessions: make(map[string]*domain.PortalSession)},
		logger:             logger,
		clientAuthDuration: clientAuthDuration,
	}
}

func (s *Service) CreatePortalSession(client domain.Client, sourceIP string, ttl time.Duration) *domain.PortalSession {
	id := randomToken()
	now := time.Now()
	session := &domain.PortalSession{
		ID:        id,
		Client:    client.Normalized(),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		SourceIP:  sourceIP,
	}
	s.sessionStore().set(id, session)
	s.logger.Info("portal_session_created",
		"event", "portal_session_created",
		"client_mac", session.Client.MAC,
		"client_ip", session.Client.IP,
		"gateway_mac", session.Client.GatewayMAC,
		"vid", session.Client.VLAN,
		"site", session.Client.Site,
		"ap_mac", session.Client.APMAC,
		"ssid", session.Client.SSID,
	)
	return session
}

func (s *Service) GetPortalSession(sessionID string) (*domain.PortalSession, bool) {
	return s.sessionStore().get(sessionID)
}

func (s *Service) Authenticate(ctx context.Context, sessionID string, username string, password string) (AuthResult, error) {
	if sessionID == "" {
		return AuthResult{}, errors.New("missing session id")
	}

	session, ok := s.sessionStore().get(sessionID)
	if !ok {
		return AuthResult{}, ErrSessionExpired
	}
	if session.Used {
		return AuthResult{}, ErrSessionUsed
	}
	if session.IsExpired(time.Now()) {
		s.sessionStore().delete(sessionID)
		return AuthResult{}, ErrSessionExpired
	}

	user, err := s.userRepo.ValidateCredentials(ctx, username, password)
	if err != nil {
		s.logger.Info("authentication_failed", "event", "authentication_failed", "username", username, "client_mac", session.Client.MAC)
		return AuthResult{}, err
	}
	if user == nil || !user.Enabled {
		s.logger.Info("authentication_failed", "event", "authentication_failed", "username", username, "client_mac", session.Client.MAC)
		return AuthResult{}, errors.New("user not enabled")
	}
	var registeredNew bool
	devices, hasDevices := s.userRepo.(ports.DeviceRepository)
	if hasDevices {
		now := time.Now()
		// The trusted-device record lasts for the credential lifetime. Omada's
		// network authorization itself remains short-lived and is renewed here.
		expiresAt := user.ExpiresAt
		registeredNew, err = devices.RegisterDevice(ctx, user.Username, domain.AuthorizedDevice{MAC: session.Client.MAC, IP: session.Client.IP, AuthorizedAt: now, ExpiresAt: expiresAt}, now)
		if err != nil {
			return AuthResult{}, err
		}
	}

	if err := s.networkAuthorizer.Authorize(ctx, session.Client, s.clientAuthDuration); err != nil {
		if hasDevices && registeredNew {
			_ = devices.RemoveDevice(context.Background(), user.Username, session.Client.MAC)
		}
		s.logger.Error("omada_authorization_failed", "err", err.Error(), "client_mac", session.Client.MAC, "client_ip", session.Client.IP)
		return AuthResult{}, err
	}

	session.Used = true
	s.sessionStore().set(sessionID, session)
	if session.Client.RedirectURL == "" {
		session.Client.RedirectURL = "/"
	}
	if !isSafeRedirect(session.Client.RedirectURL) {
		session.Client.RedirectURL = "/"
	}

	s.logger.Info("authentication_success", "event", "authentication_success", "username", username, "client_mac", session.Client.MAC, "client_ip", session.Client.IP)
	s.logger.Info("omada_authorization_success",
		"event", "omada_authorization_success",
		"client_mac", session.Client.MAC,
		"client_ip", session.Client.IP,
		"gateway_mac", session.Client.GatewayMAC,
		"vid", session.Client.VLAN,
		"site", session.Client.Site,
		"ap_mac", session.Client.APMAC,
		"ssid", session.Client.SSID,
	)

	return AuthResult{Authenticated: true, ClientMAC: session.Client.MAC, ClientIP: session.Client.IP, RedirectURL: session.Client.RedirectURL, Message: "Acesso autorizado."}, nil
}

// AutoAuthenticate reconnects a previously authenticated MAC without asking for credentials again.
func (s *Service) AutoAuthenticate(ctx context.Context, client domain.Client) (AuthResult, bool) {
	devices, ok := s.userRepo.(ports.DeviceRepository)
	if !ok {
		return AuthResult{}, false
	}
	user, err := devices.FindByMAC(ctx, client.MAC, time.Now())
	if err != nil || user == nil {
		return AuthResult{}, false
	}
	if err := s.networkAuthorizer.Authorize(ctx, client.Normalized(), s.clientAuthDuration); err != nil {
		return AuthResult{}, false
	}
	redirect := client.RedirectURL
	if !isSafeRedirect(redirect) {
		redirect = "/"
	}
	return AuthResult{Authenticated: true, ClientMAC: client.MAC, ClientIP: client.IP, RedirectURL: redirect, Message: "Acesso reconectado automaticamente."}, true
}

func (s *Service) sessionStore() *PortalSessionStore {
	return s.portalSessions
}

func randomToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func isSafeRedirect(target string) bool {
	if target == "" {
		return false
	}
	if len(target) > 2048 {
		return false
	}
	if target[0] == '/' {
		return true
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	if strings.Contains(strings.ToLower(parsed.Host), "javascript:") {
		return false
	}
	return true
}

func (s *PortalSessionStore) get(id string) (*domain.PortalSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[id]
	return v, ok
}

func (s *PortalSessionStore) set(id string, session *domain.PortalSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

func (s *PortalSessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
