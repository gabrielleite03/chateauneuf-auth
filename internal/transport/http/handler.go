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
		MAC:          portalQueryValue(r, "clientMac", "client_mac", "client-mac", "mac"),
		IP:           portalQueryValue(r, "clientIp", "client_ip", "client-ip", "ip"),
		APMAC:        portalQueryValue(r, "apMac", "ap_mac", "ap-mac"),
		GatewayMAC:   portalQueryValue(r, "gatewayMac", "gateway_mac", "gateway-mac"),
		SSID:         portalQueryValue(r, "ssidName", "ssid_name", "ssid"),
		RadioID:      portalQueryValue(r, "radioId", "radio_id"),
		VLAN:         portalQueryValue(r, "vid", "vlan", "vlanId", "vlan_id"),
		Site:         portalQueryValue(r, "site", "siteId", "site_id"),
		RedirectURL:  portalQueryValue(r, "redirectUrl", "redirect_url", "redirect"),
		ControllerID: portalQueryValue(r, "controllerId", "controller_id"),
	}
	// Gateway portal redirects documented by Omada include clientMac,
	// gatewayMac and vid, but do not always include clientIp. The MAC is the
	// stable identity required to authorize and remember the device.
	if client.MAC == "" {
		http.Error(w, "missing required client information", http.StatusBadRequest)
		return
	}
	if _, ok := h.service.AutoAuthenticate(r.Context(), client); ok {
		http.Redirect(w, r, "/portal/success", http.StatusFound)
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

// portalQueryValue accepts the parameter spellings used by different Omada
// controller and gateway versions. Header-style casing must not turn a valid
// captive-portal request into a 400 response.
func portalQueryValue(r *http.Request, names ...string) string {
	query := r.URL.Query()
	for _, name := range names {
		if value := strings.TrimSpace(query.Get(name)); value != "" {
			return value
		}
	}
	for key, values := range query {
		for _, name := range names {
			if !strings.EqualFold(key, name) {
				continue
			}
			for _, value := range values {
				if value = strings.TrimSpace(value); value != "" {
					return value
				}
			}
		}
	}
	return ""
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

	// Captive-network probes often provide relative targets such as
	// /generate_204. Those paths do not belong to this service and used to end
	// in a misleading 404 after a successful login.
	http.Redirect(w, r, "/portal/success", http.StatusFound)
}

func (h *Handler) PortalSuccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(successPage))
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
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#102d3a">
  <title>{{.Title}}</title>
  <style>
    :root { color-scheme:light; --navy:#102d3a; --navy2:#17495b; --gold:#c9a45d; --ink:#172b35; --muted:#677981; --line:#dbe4e7; }
    * { box-sizing:border-box; }
    html,body { min-height:100%; }
    body { margin:0; min-height:100vh; min-height:100dvh; display:grid; place-items:center; padding:24px; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif; color:var(--ink); background:radial-gradient(circle at 15% 10%,rgba(201,164,93,.18),transparent 32%),linear-gradient(145deg,var(--navy),#081c25 72%); }
    body::before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.12; background:linear-gradient(30deg,transparent 48%,rgba(255,255,255,.16) 49%,transparent 51%); background-size:42px 42px; }
    .shell { position:relative; width:100%; max-width:460px; overflow:hidden; border:1px solid rgba(255,255,255,.32); border-radius:26px; background:#fff; box-shadow:0 28px 70px rgba(0,0,0,.34); }
    .hero { position:relative; padding:30px 32px 27px; color:#fff; text-align:center; background:linear-gradient(135deg,var(--navy2),var(--navy)); }
    .hero::after { content:""; position:absolute; left:50%; bottom:-1px; width:64px; height:3px; border-radius:3px 3px 0 0; background:var(--gold); transform:translateX(-50%); }
    .monogram { width:64px; height:64px; display:grid; place-items:center; margin:0 auto 15px; border:1px solid rgba(255,255,255,.45); border-radius:50%; color:var(--gold); font-family:Georgia,serif; font-size:25px; letter-spacing:-2px; background:rgba(255,255,255,.08); box-shadow:inset 0 0 0 5px rgba(255,255,255,.04); }
    h1 { margin:0; font-family:Georgia,"Times New Roman",serif; font-size:clamp(1.42rem,6vw,1.78rem); font-weight:500; line-height:1.18; }
    .subtitle { margin:8px 0 0; color:rgba(255,255,255,.72); font-size:.82rem; font-weight:600; letter-spacing:.15em; text-transform:uppercase; }
    .content { padding:29px 32px 30px; }
    .welcome { margin:0 0 23px; text-align:center; color:var(--muted); font-size:.94rem; line-height:1.5; }
    label { display:block; margin:0 0 7px; color:#314750; font-size:.82rem; font-weight:700; }
    .field { position:relative; margin-bottom:17px; }
    .field svg { position:absolute; left:14px; top:50%; width:19px; height:19px; color:#80939a; transform:translateY(-50%); pointer-events:none; }
    input { width:100%; min-height:50px; padding:13px 14px 13px 45px; border:1px solid var(--line); border-radius:12px; outline:none; color:var(--ink); background:#f9fbfb; font:inherit; transition:border-color .2s,box-shadow .2s,background .2s; }
    input::placeholder { color:#a0adb2; }
    input:focus { border-color:#28768d; background:#fff; box-shadow:0 0 0 4px rgba(40,118,141,.12); }
    button { width:100%; min-height:52px; margin-top:5px; border:0; border-radius:12px; color:#fff; background:linear-gradient(135deg,#1c6479,var(--navy)); box-shadow:0 9px 20px rgba(16,45,58,.22); font:700 .91rem/1 inherit; letter-spacing:.09em; cursor:pointer; transition:transform .15s,box-shadow .15s; }
    button:hover { box-shadow:0 12px 25px rgba(16,45,58,.3); transform:translateY(-1px); }
    button:active { transform:translateY(1px); }
    .security { display:flex; align-items:center; justify-content:center; gap:7px; margin:20px 0 0; color:#819097; font-size:.76rem; }
    .security svg { width:14px; height:14px; color:#4b8584; }
    @media(max-width:520px) { body { padding:0; place-items:stretch; background:#fff; } .shell { max-width:none; min-height:100vh; min-height:100dvh; border:0; border-radius:0; box-shadow:none; } .hero { padding-top:max(30px,env(safe-area-inset-top)); } .content { padding:28px 25px max(28px,env(safe-area-inset-bottom)); } }
    @media(prefers-reduced-motion:reduce) { * { transition:none!important; } }
  </style>
</head>
<body>
  <main class="shell">
    <header class="hero"><div class="monogram" aria-hidden="true">CH</div><h1>{{.Title}}</h1><p class="subtitle">{{.Subtitle}}</p></header>
    <section class="content">
      <p class="welcome">Bem-vindo. Informe as credenciais fornecidas pela administração para conectar este dispositivo.</p>
      <form method="post" action="/portal/authenticate">
        <input type="hidden" name="session_id" value="{{.SessionID}}">
        <label for="username">Usuário</label>
        <div class="field"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/></svg><input id="username" type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="Digite seu usuário" required autofocus></div>
        <label for="password">Senha</label>
        <div class="field"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><input id="password" type="password" name="password" autocomplete="current-password" placeholder="Digite sua senha" required></div>
        <button type="submit">CONECTAR À INTERNET</button>
      </form>
      <p class="security"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>Ambiente seguro e acesso controlado</p>
    </section>
  </main>
</body>
</html>`))

var errorTemplate = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#102d3a">
  <title>Não foi possível conectar</title>
  <style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;color:#172b35;background:linear-gradient(145deg,#102d3a,#081c25)}
    .wrap{width:100%;max-width:430px;padding:36px 30px;text-align:center;background:#fff;border-radius:24px;box-shadow:0 28px 70px rgba(0,0,0,.34)}
    .icon{width:62px;height:62px;display:grid;place-items:center;margin:0 auto 18px;border-radius:50%;color:#a8554b;background:#fbeeed;font-size:30px}h1{margin:0 0 10px;font-family:Georgia,serif;font-size:1.55rem;font-weight:500}p{margin:0;color:#687a82;line-height:1.5}.hint{margin-top:20px;padding-top:18px;border-top:1px solid #e4eaec;font-size:.82rem}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="icon" aria-hidden="true">!</div>
    <h1>Não foi possível conectar</h1>
    <p>{{.Message}}</p>
    <p class="hint">Volte à tela anterior para tentar novamente.</p>
  </div>
</body>
</html>`))

const successPage = `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#102d3a"><title>Acesso liberado</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;color:#172b35;background:linear-gradient(145deg,#102d3a,#081c25)}main{width:100%;max-width:430px;padding:38px 30px;text-align:center;background:#fff;border-radius:24px;box-shadow:0 28px 70px rgba(0,0,0,.34)}.check{width:68px;height:68px;display:grid;place-items:center;margin:0 auto 20px;border-radius:50%;color:#fff;background:#31806f;box-shadow:0 9px 22px rgba(49,128,111,.3);font-size:34px}h1{margin:0 0 10px;font-family:Georgia,serif;font-size:1.7rem;font-weight:500}p{margin:7px 0;color:#687a82;line-height:1.5}.hint{margin-top:20px;padding-top:18px;border-top:1px solid #e4eaec;font-size:.82rem}</style></head><body><main><div class="check" aria-hidden="true">✓</div><h1>Acesso liberado</h1><p>Seu dispositivo foi conectado à internet.</p><p class="hint">Você já pode fechar esta página e continuar navegando.</p></main></body></html>`
