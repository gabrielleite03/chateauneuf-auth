package residents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPNotifier struct {
	url, token string
	client     *http.Client
}

func NewHTTPNotifier(url, token string) *HTTPNotifier {
	return &HTTPNotifier{url: strings.TrimSpace(url), token: token, client: &http.Client{Timeout: 15 * time.Second}}
}
func (n *HTTPNotifier) NotifyInternetCredential(ctx context.Context, apartment, username, password string, expiresAt time.Time) error {
	if n.url == "" || n.token == "" {
		return fmt.Errorf("servico de e-mail residencial nao configurado")
	}
	body, err := json.Marshal(map[string]any{"apartment": apartment, "username": username, "password": password, "expires_at": expiresAt})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("enviar credencial residencial: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &payload)
	if strings.TrimSpace(payload.Error) != "" {
		return fmt.Errorf("%s", payload.Error)
	}
	return fmt.Errorf("servico de e-mail retornou HTTP %d", resp.StatusCode)
}
