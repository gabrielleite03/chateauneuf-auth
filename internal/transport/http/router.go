package transporthttp

import (
	"encoding/json"
	"net/http"
	"time"
)

func NewRouter(h *Handler, admins ...*AdminHandler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/portal", h.Portal)
	mux.HandleFunc("/portal/success", h.PortalSuccess)
	mux.Handle("/portal/authenticate", RateLimitMiddleware(20, time.Minute)(http.HandlerFunc(h.Authenticate)))
	mux.HandleFunc("/logout", h.Logout)
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/ready", h.Ready)
	if len(admins) > 0 && admins[0] != nil {
		mux.HandleFunc("/admin/internet-accounts", admins[0].Accounts)
		mux.HandleFunc("/admin/internet-accounts/", admins[0].Accounts)
	}
	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none';")
		next.ServeHTTP(w, r)
	})
}

func jsonNewEncoder(w http.ResponseWriter) *json.Encoder {
	return json.NewEncoder(w)
}
