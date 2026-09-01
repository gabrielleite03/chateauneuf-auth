package transporthttp

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"network-auth-service/internal/application/auth"
	"network-auth-service/internal/domain"
)

// Handler exposes the portal endpoints.
type Handler struct {
	service *auth.Service
	logger  *slog.Logger
	ttl     time.Duration
}

func NewHandler(service *auth.Service, logger *slog.Logger, ttl time.Duration) *Handler {
	return &Handler{service: service, logger: logger, ttl: ttl}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = jsonNewEncoder(w).Encode(map[string]string{"status": "UP"})
}

func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = jsonNewEncoder(w).Encode(map[string]string{"status": "UP"})
}

func (h *Handler) Portal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client := domain.Client{
		MAC:          r.URL.Query().Get("clientMac"),
		IP:           r.URL.Query().Get("clientIp"),
		APMAC:        r.URL.Query().Get("apMac"),
		GatewayMAC:   r.URL.Query().Get("gatewayMac"),
		SSID:         r.URL.Query().Get("ssidName"),
		RadioID:      r.URL.Query().Get("radioId"),
		VLAN:         r.URL.Query().Get("vid"),
		Site:         r.URL.Query().Get("site"),
		RedirectURL:  r.URL.Query().Get("redirectUrl"),
		ControllerID: r.URL.Query().Get("controllerId"),
	}
	// Gateway portal redirects documented by Omada include clientMac,
	// gatewayMac and vid, but do not always include clientIp. The MAC is the
	// stable identity required to authorize and remember the device.
	if client.MAC == "" {
		http.Error(w, "missing required client information", http.StatusBadRequest)
		return
	}
	if result, ok := h.service.AutoAuthenticate(r.Context(), client); ok {
		redirectURL := result.RedirectURL
		if !isSafeRedirectURL(redirectURL) {
			redirectURL = "/portal/success"
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	session := h.service.CreatePortalSession(client, r.RemoteAddr, h.ttl)

	data := struct {
		SessionID string
		Title     string
		Subtitle  string
		Message   string
	}{
		SessionID: session.ID,
		Title:     "Condomínio Edifício Chateauneuf",
		Subtitle:  "Acesso à Internet",
	}

	if err := loginTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sessionID := strings.TrimSpace(r.FormValue("session_id"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if sessionID == "" || username == "" || password == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	result, err := h.service.Authenticate(context.Background(), sessionID, username, password)
	if err != nil {
		if err := errorTemplate.Execute(w, struct{ Message string }{Message: "Usuário ou senha inválidos."}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if !result.Authenticated {
		if err := errorTemplate.Execute(w, struct{ Message string }{Message: result.Message}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	redirectURL := result.RedirectURL
	if redirectURL == "" {
		redirectURL = "/portal/success"
	}
	if !isSafeRedirectURL(redirectURL) {
		redirectURL = "/portal/success"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) PortalSuccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acesso liberado</title><body style="font-family:Arial;background:#f3f6f9;text-align:center;padding:60px"><main style="max-width:420px;margin:auto;background:white;padding:32px;border-radius:16px"><h1>Acesso liberado</h1><p>Seu dispositivo foi conectado à internet.</p><p>Você já pode fechar esta página.</p></main></body></html>`))
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func isSafeRedirectURL(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host != "" && parsed.Host != "localhost" {
		return false
	}
	return true
}

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.Title}}</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f3f6f9; margin: 0; padding: 0; }
    .wrap { max-width: 420px; margin: 80px auto; padding: 24px; background: #fff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.08); }
    h1 { margin: 0 0 8px; font-size: 1.7rem; text-align: center; }
    h2 { margin: 0 0 20px; font-size: 1.1rem; color: #4a5568; text-align: center; }
    label { display: block; font-weight: bold; margin: 12px 0 8px; }
    input { width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1px solid #cbd5e0; border-radius: 10px; font-size: 1rem; }
    button { width: 100%; margin-top: 16px; background: #0f766e; color: white; border: none; border-radius: 10px; padding: 14px 16px; font-size: 1rem; font-weight: bold; }
    .meta { margin-top: 18px; text-align: center; color: #4a5568; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{{.Title}}</h1>
    <h2>{{.Subtitle}}</h2>
    <form method="post" action="/portal/authenticate">
      <input type="hidden" name="session_id" value="{{.SessionID}}" />
      <label for="username">Usuário</label>
      <input id="username" type="text" name="username" autocomplete="username" required />
      <label for="password">Senha</label>
      <input id="password" type="password" name="password" autocomplete="current-password" required />
      <button type="submit">CONECTAR</button>
    </form>
  </div>
</body>
</html>`))

var errorTemplate = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Erro</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f3f6f9; margin: 0; padding: 0; }
    .wrap { max-width: 420px; margin: 80px auto; padding: 24px; background: #fff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.08); }
    h1 { margin: 0 0 12px; font-size: 1.5rem; text-align: center; }
    p { margin: 0; color: #333; text-align: center; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Erro</h1>
    <p>{{.Message}}</p>
  </div>
</body>
</html>`))
