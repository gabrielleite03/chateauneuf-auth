package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"network-auth-service/internal/domain"
)

// UserRecord matches the local development file.
type UserRecord struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Enabled      bool   `json:"enabled"`
}

// Repository validates credentials against a local JSON file.
type Repository struct {
	mu        sync.RWMutex
	path      string
	byUser    map[string]UserRecord
	loaded    bool
}

func NewRepository(path string) (*Repository, error) {
	if path == "" {
		return nil, errors.New("users file path is required")
	}
	repo := &Repository{path: path, byUser: map[string]UserRecord{}}
	if err := repo.load(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *Repository) ValidateCredentials(ctx context.Context, username string, password string) (*domain.User, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username is required")
	}

	r.mu.RLock()
	record, ok := r.byUser[strings.TrimSpace(username)]
	r.mu.RUnlock()
	if !ok {
		return nil, errors.New("user not found")
	}
	if !record.Enabled {
		return nil, errors.New("user disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}
	return &domain.User{
		Username:     record.Username,
		PasswordHash: record.PasswordHash,
		Enabled:      record.Enabled,
	}, nil
}

func (r *Repository) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("read users file %s: %w", r.path, err)
	}
	var records []UserRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("parse users file %s: %w", r.path, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.byUser = make(map[string]UserRecord, len(records))
	for _, record := range records {
		if record.Username == "" {
			continue
		}
		r.byUser[record.Username] = record
	}
	r.loaded = true
	return nil
}
