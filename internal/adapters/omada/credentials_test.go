package omada

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"network-auth-service/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestRejectedHotspotCredentialStopsRevocation(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/controller/api/v2/hotspot/login" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"errorCode":-30109,"msg":"Invalid username or password."}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "operator", "secret-not-for-errors", "site", "controller", "", "POST", false, time.Second)
	client.SetOpenAPI("client", "openapi-secret", "controller", "site")
	err := client.Revoke(context.Background(), domain.Client{MAC: "AA:BB:CC:DD:EE:FF"})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != -30109 {
		t.Fatalf("expected typed Omada rejection: %v", err)
	}
	if !strings.Contains(err.Error(), "OMADA_USERNAME") || !strings.Contains(err.Error(), "OMADA_PASSWORD") {
		t.Fatalf("missing actionable configuration message: %v", err)
	}
	if strings.Contains(err.Error(), "secret-not-for-errors") || strings.Contains(err.Error(), "openapi-secret") {
		t.Fatal("credential leaked in error")
	}
	if calls != 1 {
		t.Fatalf("must stop before disconnecting clients: %d calls", calls)
	}
}
