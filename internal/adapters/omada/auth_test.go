package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network-auth-service/internal/domain"
)

func TestOmadaAuthorize(t *testing.T) {
	const controllerID = "controller-1"
	loginPath := "/" + controllerID + "/api/v2/hotspot/login"
	authPath := "/" + controllerID + "/api/v2/hotspot/extPortal/auth"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			var payload ControllerLoginRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode login payload: %v", err)
			}
			if payload.Name != "operator" || payload.Password != "pass" {
				t.Fatalf("unexpected login payload: %+v", payload)
			}
			http.SetCookie(w, &http.Cookie{Name: "TPOMADA_SESSIONID", Value: "session", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]string{"token": "csrf-token"}})
		case authPath:
			cookie, err := r.Cookie("TPOMADA_SESSIONID")
			if err != nil || cookie.Value != "session" {
				t.Fatalf("missing Omada session cookie: %v", err)
			}
			if r.Header.Get("Csrf-Token") != "csrf-token" {
				t.Fatalf("missing CSRF token")
			}
			var payload AuthorizeRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode authorization payload: %v", err)
			}
			if payload.ClientMAC == "" || payload.GatewayMAC == "" || payload.VID != "1" || payload.AuthType != 4 || payload.Time != 86400000 {
				t.Fatalf("unexpected authorization payload: %+v", payload)
			}
			_ = json.NewEncoder(w).Encode(AuthorizeResponse{ErrorCode: 0, Msg: "success"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "operator", "pass", "Chateauneuf", controllerID, "", http.MethodPost, true, 5*time.Second)
	if err := client.Authorize(context.Background(), domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.42", GatewayMAC: "BB:BB:BB:BB:BB:BB", VLAN: "1", Site: "Chateauneuf"}, 24*time.Hour); err != nil {
		t.Fatalf("authorize should succeed: %v", err)
	}
}

func TestOmadaAuthorizeRequiresEndpointConfig(t *testing.T) {
	client := NewClient("https://example.com", "user", "pass", "default", "", "", http.MethodPost, false, 5*time.Second)
	err := client.Authorize(context.Background(), domain.Client{MAC: "AA", IP: "10.0.0.1"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "configuration incomplete") {
		t.Fatalf("expected config error, got %v", err)
	}
}
