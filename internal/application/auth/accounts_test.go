package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"network-auth-service/internal/adapters/repository/local"
	"network-auth-service/internal/domain"
)

type recordingRevoker struct{ clients []domain.Client }

func (r *recordingRevoker) Revoke(_ context.Context, c domain.Client) error {
	r.clients = append(r.clients, c)
	return nil
}

type residentDirectoryStub struct{ exists bool }

func (s residentDirectoryStub) ApartmentExists(context.Context, string) (bool, error) {
	return s.exists, nil
}

type credentialNotifierStub struct{ password string }

func (s *credentialNotifierStub) NotifyInternetCredential(_ context.Context, _, _, password string, _ time.Time) error {
	s.password = password
	return nil
}

func TestAccountDefaultsAndPasswordRotation(t *testing.T) {
	repo, err := local.NewRepository(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	revoker := &recordingRevoker{}
	svc := NewAccountService(repo, revoker, residentDirectoryStub{exists: true})
	notifier := &credentialNotifierStub{}
	svc.SetResidentCredentialNotifier(notifier)
	u, password, err := svc.Create(context.Background(), "72")
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 6 || u.MaxConnections != 5 || u.DownloadKbps != 30000 || u.UploadKbps != 30000 {
		t.Fatalf("unexpected defaults: %+v password length=%d", u, len(password))
	}
	if u.ExpiresAt.Before(time.Now().Add(89 * 24 * time.Hour)) {
		t.Fatal("expected a 90-day validity")
	}
	if _, err = repo.ValidateCredentials(context.Background(), u.Username, password); err != nil {
		t.Fatalf("generated password must authenticate: %v", err)
	}
	_, err = repo.RegisterDevice(context.Background(), u.Username, domain.AuthorizedDevice{MAC: "AA:BB:CC:DD:EE:FF", ExpiresAt: u.ExpiresAt}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	newPassword, emailSent, err := svc.ChangePassword(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newPassword != "" || !emailSent || notifier.password == password || len(revoker.clients) != 1 {
		t.Fatal("password rotation must revoke the registered device")
	}
	if _, err = repo.FindByMAC(context.Background(), "AA:BB:CC:DD:EE:FF", time.Now()); err == nil {
		t.Fatal("device trust must be cleared")
	}
}

func TestEmployeeAccountRules(t *testing.T) {
	repo, err := local.NewRepository(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewAccountService(repo, &recordingRevoker{})
	svc.SetEmployeeEnrollmentPassword("gate-secret")
	if _, err = svc.CreateEmployee(context.Background(), "Ana", "ana.func", "livre123", "wrong"); err == nil {
		t.Fatal("expected invalid enrollment password")
	}
	u, err := svc.CreateEmployee(context.Background(), "Ana", "ana.func", "livre123", "gate-secret")
	if err != nil {
		t.Fatal(err)
	}
	if u.AccountType != "employee" || u.DownloadKbps != 10000 || u.UploadKbps != 10000 || u.MaxConnections != 1 {
		t.Fatalf("unexpected employee defaults: %+v", u)
	}
	if u.ExpiresAt.Before(time.Now().Add(29*24*time.Hour + 23*time.Hour)) {
		t.Fatal("expected 30-day validity")
	}
	if _, err = repo.ValidateCredentials(context.Background(), "ana.func", "livre123"); err != nil {
		t.Fatalf("free password must authenticate: %v", err)
	}
}
