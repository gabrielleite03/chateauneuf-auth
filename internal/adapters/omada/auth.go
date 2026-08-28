package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"network-auth-service/internal/domain"
)

// Client is the Omada-specific adapter for authorizing portal clients.
type Client struct {
	baseURL        string
	username       string
	password       string
	site           string
	controllerID   string
	tlsInsecure    bool
	httpClient     *http.Client
	csrfToken      string
	csrfMu         sync.Mutex
	authorizePath  string
	authorizeMethod string
}

func NewClient(baseURL string, username string, password string, site string, controllerID string, authPath string, authMethod string, tlsInsecure bool, timeout time.Duration) *Client {
	method := strings.ToUpper(strings.TrimSpace(authMethod))
	if method == "" {
		method = http.MethodPost
	}
	return &Client{
		baseURL:         strings.TrimRight(baseURL, "/"),
		username:        username,
		password:        password,
		site:            site,
		controllerID:    controllerID,
		tlsInsecure:     tlsInsecure,
		authorizePath:   strings.TrimSpace(authPath),
		authorizeMethod: method,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecure},
			},
		},
	}
}

func (c *Client) Authorize(ctx context.Context, client domain.Client, duration time.Duration) error {
	if strings.TrimSpace(c.authorizePath) == "" {
		return fmt.Errorf("omada authorization endpoint not configured: set OMADA_AUTHORIZATION_PATH")
	}
	payload := AuthorizeRequest{
		Site:         c.site,
		ControllerID: c.controllerID,
		ClientMAC:    client.MAC,
		ClientIP:     client.IP,
		SSID:         client.SSID,
		APMAC:        client.APMAC,
		GatewayMAC:   client.GatewayMAC,
		RadioID:      client.RadioID,
		VLAN:         client.VLAN,
		Duration:     int(duration / time.Second),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal authorize payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, c.authorizeMethod, c.baseURL+c.authorizePath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	if c.site != "" {
		req.Header.Set("Site", c.site)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("omada authorize request: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &Error{Code: resp.StatusCode, Body: string(b)}
	}

	var result AuthorizeResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return fmt.Errorf("decode authorize response: %w", err)
	}
	if result.Code != 0 && result.Code != 200 {
		return &Error{Code: result.Code, Message: result.Msg}
	}
	return nil
}

func (c *Client) ensureAuthenticated(ctx context.Context) error {
	if c.username == "" || c.password == "" {
		return nil
	}
	return nil
}
