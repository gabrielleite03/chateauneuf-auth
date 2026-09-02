package transporthttp

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"network-auth-service/internal/application/auth"
	"network-auth-service/internal/domain"
	"strings"
	"time"
)

type AdminHandler struct {
	service *auth.AccountService
	token   string
}

func NewAdminHandler(s *auth.AccountService, token string) *AdminHandler {
	return &AdminHandler{service: s, token: token}
}

type accountInput struct {
	Apartment          string    `json:"apartment"`
	Username           string    `json:"username"`
	Name               string    `json:"name"`
	Password           string    `json:"password"`
	EnrollmentPassword string    `json:"enrollment_password"`
	Enabled            bool      `json:"enabled"`
	ExpiresAt          time.Time `json:"expires_at"`
}
type accountOutput struct {
	ID                string    `json:"id"`
	AccountType       string    `json:"account_type"`
	Name              string    `json:"name,omitempty"`
	Apartment         string    `json:"apartment"`
	Username          string    `json:"username"`
	Enabled           bool      `json:"enabled"`
	ExpiresAt         time.Time `json:"expires_at"`
	MaxConnections    int       `json:"max_connections"`
	DownloadKbps      int       `json:"download_kbps"`
	UploadKbps        int       `json:"upload_kbps"`
	ActiveConnections int       `json:"active_connections"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	GeneratedPassword string    `json:"generated_password,omitempty"`
}

func output(u domain.User) accountOutput {
	return accountOutput{ID: u.ID, AccountType: u.AccountType, Name: u.Name, Apartment: u.Apartment, Username: u.Username, Enabled: u.Enabled, ExpiresAt: u.ExpiresAt, MaxConnections: u.MaxConnections, DownloadKbps: u.DownloadKbps, UploadKbps: u.UploadKbps, ActiveConnections: len(u.Devices), CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}
func (h *AdminHandler) authorized(r *http.Request) bool {
	if h.token == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return len(got) == len(h.token) && subtle.ConstantTimeCompare([]byte(got), []byte(h.token)) == 1
}
func (h *AdminHandler) Accounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/internet-accounts/")
	if id == r.URL.Path {
		id = ""
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := h.service.List(r.Context())
		if err != nil {
			writeAdminError(w, err)
			return
		}
		out := make([]accountOutput, len(rows))
		for i := range rows {
			out[i] = output(rows[i])
		}
		json.NewEncoder(w).Encode(out)
	case http.MethodPost:
		if id == "employees" {
			var in accountInput
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				http.Error(w, "invalid json", 400)
				return
			}
			u, err := h.service.CreateEmployee(r.Context(), in.Name, in.Username, in.Password, in.EnrollmentPassword)
			if err != nil {
				writeAdminError(w, err)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(output(u))
			return
		}
		if id != "" && strings.HasSuffix(id, "/password") {
			id = strings.TrimSuffix(id, "/password")
			password, emailSent, err := h.service.ChangePassword(r.Context(), id)
			if err != nil {
				writeAdminError(w, err)
				return
			}
			if emailSent {
				json.NewEncoder(w).Encode(map[string]bool{"email_sent": true})
			} else {
				json.NewEncoder(w).Encode(map[string]string{"generated_password": password})
			}
			return
		}
		var in accountInput
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		u, password, err := h.service.Create(r.Context(), in.Apartment)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		o := output(u)
		_ = password
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(o)
	case http.MethodPut:
		var in accountInput
		if id == "" || json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		u, err := h.service.Update(r.Context(), id, in.Apartment, in.Username, in.Enabled, in.ExpiresAt)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		json.NewEncoder(w).Encode(output(u))
	case http.MethodDelete:
		if id == "" {
			http.Error(w, "missing id", 400)
			return
		}
		if err := h.service.Delete(r.Context(), id); err != nil {
			writeAdminError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func writeAdminError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
