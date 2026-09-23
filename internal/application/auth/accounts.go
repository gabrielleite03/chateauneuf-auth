package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"network-auth-service/internal/domain"
	"network-auth-service/internal/ports"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultMaxConnections   = 5
	DefaultBandwidthKbps    = 30000
	EmployeeBandwidthKbps   = 10000
	ResidentAccountDuration = 90 * 24 * time.Hour
	EmployeeAccountDuration = 30 * 24 * time.Hour
)

type AccountService struct {
	repo                       ports.AccountRepository
	revoker                    ports.NetworkRevoker
	residents                  ports.ResidentDirectory
	notifier                   ports.ResidentCredentialNotifier
	employeeEnrollmentPassword string
}

func NewAccountService(repo ports.AccountRepository, revoker ports.NetworkRevoker, residents ...ports.ResidentDirectory) *AccountService {
	var directory ports.ResidentDirectory
	if len(residents) > 0 {
		directory = residents[0]
	}
	return &AccountService{repo: repo, revoker: revoker, residents: directory}
}
func (s *AccountService) SetEmployeeEnrollmentPassword(password string) {
	s.employeeEnrollmentPassword = password
}
func (s *AccountService) SetResidentCredentialNotifier(notifier ports.ResidentCredentialNotifier) {
	s.notifier = notifier
}
func (s *AccountService) List(ctx context.Context) ([]domain.User, error) { return s.repo.List(ctx) }
func (s *AccountService) Create(ctx context.Context, apartment string) (domain.User, string, error) {
	apartment = strings.TrimSpace(apartment)
	if apartment == "" || s.residents == nil {
		return domain.User{}, "", errors.New("a registered apartment is required")
	}
	exists, err := s.residents.ApartmentExists(ctx, apartment)
	if err != nil {
		return domain.User{}, "", err
	}
	if !exists {
		return domain.User{}, "", errors.New("apartment is not registered in residents")
	}
	username := "apto" + regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(apartment, "")
	if username == "apto" {
		return domain.User{}, "", errors.New("invalid apartment")
	}
	password, err := randomPassword()
	if err != nil {
		return domain.User{}, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return domain.User{}, "", err
	}
	now := time.Now()
	idBytes := make([]byte, 12)
	if _, err = rand.Read(idBytes); err != nil {
		return domain.User{}, "", err
	}
	u := domain.User{ID: base64.RawURLEncoding.EncodeToString(idBytes), AccountType: "resident", Apartment: apartment, Username: username, PasswordHash: string(hash), Enabled: true, ExpiresAt: now.Add(ResidentAccountDuration), MaxConnections: DefaultMaxConnections, DownloadKbps: DefaultBandwidthKbps, UploadKbps: DefaultBandwidthKbps, CreatedAt: now, UpdatedAt: now}
	if err = s.repo.Create(ctx, u); err != nil {
		return domain.User{}, "", err
	}
	if s.notifier == nil {
		_ = s.repo.Delete(context.Background(), u.ID)
		return domain.User{}, "", errors.New("servico de e-mail residencial nao configurado")
	}
	if err = s.notifier.NotifyInternetCredential(ctx, u.Apartment, u.Username, password, u.ExpiresAt); err != nil {
		_ = s.repo.Delete(context.Background(), u.ID)
		return domain.User{}, "", err
	}
	return u, password, nil
}

func (s *AccountService) CreateEmployee(ctx context.Context, name, username, password, enrollmentPassword string) (domain.User, error) {
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	if s.employeeEnrollmentPassword == "" || len(enrollmentPassword) != len(s.employeeEnrollmentPassword) || subtle.ConstantTimeCompare([]byte(enrollmentPassword), []byte(s.employeeEnrollmentPassword)) != 1 {
		return domain.User{}, errors.New("invalid employee enrollment password")
	}
	if name == "" || username == "" || password == "" {
		return domain.User{}, errors.New("name, username and password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return domain.User{}, err
	}
	idBytes := make([]byte, 12)
	if _, err = rand.Read(idBytes); err != nil {
		return domain.User{}, err
	}
	now := time.Now()
	u := domain.User{ID: base64.RawURLEncoding.EncodeToString(idBytes), AccountType: "employee", Name: name, Username: username, PasswordHash: string(hash), Enabled: true, ExpiresAt: now.Add(EmployeeAccountDuration), MaxConnections: 1, DownloadKbps: EmployeeBandwidthKbps, UploadKbps: EmployeeBandwidthKbps, CreatedAt: now, UpdatedAt: now}
	if err = s.repo.Create(ctx, u); err != nil {
		return domain.User{}, err
	}
	return u, nil
}
func (s *AccountService) Update(ctx context.Context, id, apartment, username string, enabled bool, expiresAt time.Time) (domain.User, error) {
	u, err := s.repo.Get(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	if strings.TrimSpace(apartment) != u.Apartment || strings.TrimSpace(username) != u.Username {
		return domain.User{}, errors.New("apartment and username are managed by residents and cannot be changed here")
	}
	u.Enabled = enabled
	u.ExpiresAt = expiresAt
	u.MaxConnections = DefaultMaxConnections
	u.DownloadKbps = DefaultBandwidthKbps
	u.UploadKbps = DefaultBandwidthKbps
	u.UpdatedAt = time.Now()
	if u.Apartment == "" || u.Username == "" {
		return domain.User{}, errors.New("apartment and username are required")
	}
	if (!enabled || (!expiresAt.IsZero() && !expiresAt.After(time.Now()))) && len(u.Devices) > 0 {
		if err = s.revokeAll(ctx, u); err != nil {
			return domain.User{}, err
		}
		if err = s.repo.ReplacePasswordAndClearDevices(ctx, id, u.PasswordHash, time.Now()); err != nil {
			return domain.User{}, err
		}
		u.Devices = nil
	}
	if err = s.repo.Update(ctx, *u); err != nil {
		return domain.User{}, err
	}
	return *u, nil
}
func (s *AccountService) ChangePassword(ctx context.Context, id string) (string, bool, error) {
	u, err := s.repo.Get(ctx, id)
	if err != nil {
		return "", false, err
	}
	if err = s.revokeAll(ctx, u); err != nil {
		return "", false, err
	}
	password, err := randomPassword()
	if err != nil {
		return "", false, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", false, err
	}
	if u.AccountType == "resident" {
		if s.notifier == nil {
			return "", false, errors.New("servico de e-mail residencial nao configurado")
		}
		if err = s.notifier.NotifyInternetCredential(ctx, u.Apartment, u.Username, password, u.ExpiresAt); err != nil {
			return "", false, err
		}
		if err = s.repo.ReplacePasswordAndClearDevices(ctx, id, string(hash), time.Now()); err != nil {
			return "", false, err
		}
		return "", true, nil
	}
	if err = s.repo.ReplacePasswordAndClearDevices(ctx, id, string(hash), time.Now()); err != nil {
		return "", false, err
	}
	return password, false, nil
}
func (s *AccountService) Delete(ctx context.Context, id string) error {
	u, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err = s.revokeAll(ctx, u); err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}
func (s *AccountService) revokeAll(ctx context.Context, u *domain.User) error {
	for _, d := range u.Devices {
		if err := s.revoker.Revoke(ctx, domain.Client{MAC: d.MAC, IP: d.IP}); err != nil {
			return err
		}
	}
	return nil
}
func randomPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 6)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}
