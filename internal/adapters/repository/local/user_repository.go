package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"network-auth-service/internal/domain"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrNotFound = errors.New("account not found")

type UserRecord struct {
	ID             string                    `json:"id"`
	AccountType    string                    `json:"account_type,omitempty"`
	Name           string                    `json:"name,omitempty"`
	Apartment      string                    `json:"apartment"`
	Username       string                    `json:"username"`
	PasswordHash   string                    `json:"password_hash"`
	Enabled        bool                      `json:"enabled"`
	ExpiresAt      time.Time                 `json:"expires_at"`
	MaxConnections int                       `json:"max_connections"`
	DownloadKbps   int                       `json:"download_kbps"`
	UploadKbps     int                       `json:"upload_kbps"`
	Devices        []domain.AuthorizedDevice `json:"devices,omitempty"`
	CreatedAt      time.Time                 `json:"created_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
}
type Repository struct {
	mu      sync.RWMutex
	path    string
	records map[string]UserRecord
}

func NewRepository(path string) (*Repository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("users file path is required")
	}
	r := &Repository{path: path, records: map[string]UserRecord{}}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Repository) ValidateCredentials(ctx context.Context, username, password string) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, v := range r.records {
		if v.Username != strings.TrimSpace(username) {
			continue
		}
		u := toDomain(v)
		if !u.CanAuthenticate(time.Now()) {
			return nil, errors.New("account disabled or expired")
		}
		if bcrypt.CompareHashAndPassword([]byte(v.PasswordHash), []byte(password)) != nil {
			return nil, errors.New("invalid credentials")
		}
		return &u, nil
	}
	return nil, ErrNotFound
}
func (r *Repository) FindByMAC(ctx context.Context, mac string, now time.Time) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mac = normalizeMAC(mac)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, v := range r.records {
		u := toDomain(v)
		if !u.CanAuthenticate(now) {
			continue
		}
		for _, d := range v.Devices {
			if normalizeMAC(d.MAC) == mac && now.Before(d.ExpiresAt) {
				return &u, nil
			}
		}
	}
	return nil, ErrNotFound
}
func (r *Repository) RegisterDevice(ctx context.Context, username string, device domain.AuthorizedDevice, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.records {
		if v.Username != username {
			continue
		}
		active := make([]domain.AuthorizedDevice, 0, len(v.Devices)+1)
		found := false
		for _, d := range v.Devices {
			if now.Before(d.ExpiresAt) {
				if normalizeMAC(d.MAC) == normalizeMAC(device.MAC) {
					d = device
					found = true
				}
				active = append(active, d)
			}
		}
		if !found {
			if len(active) >= v.MaxConnections {
				return false, fmt.Errorf("maximum of %d simultaneous connections reached", v.MaxConnections)
			}
			active = append(active, device)
		}
		v.Devices = active
		v.UpdatedAt = now
		r.records[id] = v
		return !found, r.persistLocked()
	}
	return false, ErrNotFound
}

func (r *Repository) RemoveDevice(ctx context.Context, username, mac string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.records {
		if v.Username != username {
			continue
		}
		kept := v.Devices[:0]
		for _, d := range v.Devices {
			if normalizeMAC(d.MAC) != normalizeMAC(mac) {
				kept = append(kept, d)
			}
		}
		v.Devices = kept
		r.records[id] = v
		return r.persistLocked()
	}
	return ErrNotFound
}
func (r *Repository) List(ctx context.Context) ([]domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.User, 0, len(r.records))
	for _, v := range r.records {
		out = append(out, toDomain(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Apartment < out[j].Apartment })
	return out, nil
}
func (r *Repository) Get(ctx context.Context, id string) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.records[id]
	if !ok {
		return nil, ErrNotFound
	}
	u := toDomain(v)
	return &u, nil
}
func (r *Repository) Create(ctx context.Context, u domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.records[u.ID]; ok {
		return errors.New("account already exists")
	}
	for _, v := range r.records {
		if v.Username == u.Username || (u.Apartment != "" && v.Apartment == u.Apartment) {
			return errors.New("username or apartment already exists")
		}
	}
	r.records[u.ID] = fromDomain(u)
	if err := r.persistLocked(); err != nil {
		delete(r.records, u.ID)
		return err
	}
	return nil
}
func (r *Repository) Update(ctx context.Context, u domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.records[u.ID]
	if !ok {
		return ErrNotFound
	}
	u.PasswordHash = old.PasswordHash
	u.Devices = old.Devices
	u.CreatedAt = old.CreatedAt
	r.records[u.ID] = fromDomain(u)
	return r.persistLocked()
}
func (r *Repository) ReplacePasswordAndClearDevices(ctx context.Context, id, hash string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.records[id]
	if !ok {
		return ErrNotFound
	}
	v.PasswordHash = hash
	v.Devices = nil
	v.UpdatedAt = now
	r.records[id] = v
	return r.persistLocked()
}
func (r *Repository) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.records[id]; !ok {
		return ErrNotFound
	}
	delete(r.records, id)
	return r.persistLocked()
}
func (r *Repository) load() error {
	b, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rows []UserRecord
	if err = json.Unmarshal(b, &rows); err != nil {
		return fmt.Errorf("parse users file: %w", err)
	}
	now := time.Now()
	for _, v := range rows {
		if v.ID == "" {
			v.ID = v.Username
		}
		if v.Apartment == "" {
			if v.AccountType != "employee" {
				v.Apartment = v.Username
			}
		}
		if v.AccountType == "" {
			v.AccountType = "resident"
		}
		if v.AccountType == "resident" {
			v.MaxConnections = 5
		} else if v.MaxConnections == 0 {
			v.MaxConnections = 1
		}
		if v.DownloadKbps == 0 {
			v.DownloadKbps = 30000
		}
		if v.UploadKbps == 0 {
			v.UploadKbps = 30000
		}
		if v.ExpiresAt.IsZero() {
			v.ExpiresAt = now.Add(90 * 24 * time.Hour)
		}
		r.records[v.ID] = v
	}
	return nil
}
func (r *Repository) persistLocked() error {
	rows := make([]UserRecord, 0, len(r.records))
	for _, v := range r.records {
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Apartment < rows[j].Apartment })
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), "users-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, r.path); err != nil {
		_ = os.Remove(r.path)
		return os.Rename(name, r.path)
	}
	return nil
}
func toDomain(v UserRecord) domain.User {
	return domain.User{ID: v.ID, AccountType: v.AccountType, Name: v.Name, Apartment: v.Apartment, Username: v.Username, PasswordHash: v.PasswordHash, Enabled: v.Enabled, ExpiresAt: v.ExpiresAt, MaxConnections: v.MaxConnections, DownloadKbps: v.DownloadKbps, UploadKbps: v.UploadKbps, Devices: v.Devices, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
func fromDomain(v domain.User) UserRecord {
	return UserRecord{ID: v.ID, AccountType: v.AccountType, Name: v.Name, Apartment: v.Apartment, Username: v.Username, PasswordHash: v.PasswordHash, Enabled: v.Enabled, ExpiresAt: v.ExpiresAt, MaxConnections: v.MaxConnections, DownloadKbps: v.DownloadKbps, UploadKbps: v.UploadKbps, Devices: v.Devices, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
func normalizeMAC(v string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), "-", ":"))
}
