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
	path := "/portal/authorize"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		var payload AuthorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.ClientMAC == "" || payload.ClientIP == "" {
			t.Fatal("expected client identifiers")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthorizeResponse{Code: 0, Msg: "success"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "user", "pass", "default", "controller-1", path, http.MethodPost, true, 5*time.Second)
	if err := client.Authorize(context.Background(), domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.42", SSID: "Condominio", APMAC: "AA:AA:AA:AA:AA:AA", GatewayMAC: "BB:BB:BB:BB:BB:BB", RadioID: "0"}, 24*time.Hour); err != nil {
		t.Fatalf("authorize should succeed: %v", err)
	}
}

func TestOmadaAuthorizeRequiresEndpointConfig(t *testing.T) {
	client := NewClient("https://example.com", "user", "pass", "default", "controller-1", "", http.MethodPost, false, 5*time.Second)
	err := client.Authorize(context.Background(), domain.Client{MAC: "AA", IP: "10.0.0.1"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "OMADA_AUTHORIZATION_PATH") {
		t.Fatalf("expected config error, got %v", err)
	}
}
