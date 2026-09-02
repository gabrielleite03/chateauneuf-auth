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
			if payload.ClientMAC != "AA-BB-CC-DD-EE-FF" || payload.GatewayMAC != "BB-BB-BB-BB-BB-BB" {
				t.Fatalf("authorization must use Omada MAC format, got %+v", payload)
			}
			if payload.Site != "Chateauneuf" {
				t.Fatalf("authorization must use configured site name, got %q", payload.Site)
			}
			_ = json.NewEncoder(w).Encode(AuthorizeResponse{ErrorCode: 0, Msg: "success"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "operator", "pass", "Chateauneuf", controllerID, "", http.MethodPost, true, 5*time.Second)
	if err := client.Authorize(context.Background(), domain.Client{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.10.42", GatewayMAC: "BB:BB:BB:BB:BB:BB", VLAN: "1", Site: "6a95dd584b07545c9445ebd9"}, 24*time.Hour); err != nil {
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

func TestOmadaRevokeViaOpenAPI(t *testing.T) {
	const controllerID = "controller-1"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/controller-1/api/v2/hotspot/login":
			http.SetCookie(w, &http.Cookie{Name: "TPOMADA_SESSIONID", Value: "session", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]string{"token": "csrf-token"}})
		case "/controller-1/api/v2/hotspot/sites/site-1/clients":
			if r.Method != http.MethodGet || r.URL.Query().Get("currentPageSize") != "1000" || r.Header.Get("Csrf-Token") != "csrf-token" {
				t.Fatalf("unexpected Hotspot clients request: %s", r.URL.String())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"data": []map[string]any{{"id": "authorized-1", "mac": "AA-BB-CC-DD-EE-FF", "valid": true}}}})
		case "/controller-1/api/v2/hotspot/sites/site-1/cmd/clients/authorized-1/disconnect":
			if r.Method != http.MethodPost || r.Header.Get("Csrf-Token") != "csrf-token" {
				t.Fatalf("unexpected Hotspot disconnect request")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "msg": "success"})
		case "/openapi/authorize/token":
			if r.Method != http.MethodPost || r.URL.Query().Get("grant_type") != "client_credentials" {
				t.Fatalf("unexpected token request: %s %s", r.Method, r.URL.String())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"accessToken": "AT-test", "expiresIn": 7200}})
		case "/openapi/v1/controller-1/sites/site-1/clients/AA-BB-CC-DD-EE-FF":
			if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "AccessToken=AT-test" {
				t.Fatalf("unexpected disconnect request")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "msg": "success"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "operator", "pass", "Chateauneuf", controllerID, "", http.MethodPost, true, 5*time.Second)
	client.SetOpenAPI("client-id", "client-secret", controllerID, "site-1")
	if err := client.Revoke(context.Background(), domain.Client{MAC: "aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatalf("revoke should succeed: %v", err)
	}
}

func TestOmadaRevokeTreatsMissingClientAsSuccess(t *testing.T) {
	const controllerID = "controller-1"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/controller-1/api/v2/hotspot/login":
			http.SetCookie(w, &http.Cookie{Name: "TPOMADA_SESSIONID", Value: "session", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]string{"token": "csrf-token"}})
		case "/controller-1/api/v2/hotspot/sites/site-1/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"data": []any{}}})
		case "/openapi/authorize/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"accessToken": "AT-test", "expiresIn": 7200}})
		case "/openapi/v1/controller-1/sites/site-1/clients/AA-BB-CC-DD-EE-FF":
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": -41011, "msg": "This client does not exist."})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "operator", "pass", "Chateauneuf", controllerID, "", http.MethodPost, true, 5*time.Second)
	client.SetOpenAPI("client-id", "client-secret", controllerID, "site-1")
	if err := client.Revoke(context.Background(), domain.Client{MAC: "aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatalf("missing client should count as already revoked: %v", err)
	}
}

func TestOmadaRevokeStopsWhenHotspotDisconnectFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/controller-1/api/v2/hotspot/login":
			http.SetCookie(w, &http.Cookie{Name: "TPOMADA_SESSIONID", Value: "session", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]string{"token": "csrf-token"}})
		case "/controller-1/api/v2/hotspot/sites/site-1/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"data": []map[string]any{{"id": "authorized-1", "mac": "AA-BB-CC-DD-EE-FF", "valid": true}}}})
		case "/controller-1/api/v2/hotspot/sites/site-1/cmd/clients/authorized-1/disconnect":
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": -1, "msg": "disconnect failed"})
		case "/openapi/authorize/token":
			t.Fatal("general client disconnect must not run after Hotspot failure")
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "operator", "pass", "Chateauneuf", "controller-1", "", http.MethodPost, true, 5*time.Second)
	client.SetOpenAPI("client-id", "client-secret", "controller-1", "site-1")
	if err := client.Revoke(context.Background(), domain.Client{MAC: "AA:BB:CC:DD:EE:FF"}); err == nil {
		t.Fatal("expected Hotspot disconnect error")
	}
}
