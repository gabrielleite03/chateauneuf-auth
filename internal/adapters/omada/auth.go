package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"network-auth-service/internal/domain"
)

// Client is the Omada-specific adapter for authorizing portal clients.
type Client struct {
	baseURL         string
	username        string
	password        string
	site            string
	controllerID    string
	tlsInsecure     bool
	httpClient      *http.Client
	csrfToken       string
	csrfMu          sync.Mutex
	authorizePath   string
	authorizeMethod string
}

func NewClient(baseURL string, username string, password string, site string, controllerID string, authPath string, authMethod string, tlsInsecure bool, timeout time.Duration) *Client {
	method := strings.ToUpper(strings.TrimSpace(authMethod))
	if method == "" {
		method = http.MethodPost
	}
	jar, _ := cookiejar.New(nil)
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
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecure},
			},
		},
	}
}

func (c *Client) Authorize(ctx context.Context, client domain.Client, duration time.Duration) error {
	if c.baseURL == "" || c.controllerID == "" || c.username == "" || c.password == "" {
		return fmt.Errorf("omada controller configuration incomplete: base URL, controller ID, operator username and password are required")
	}

	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()

	if err := c.login(ctx); err != nil {
		return err
	}

	authorizePath := c.authorizePath
	if authorizePath == "" {
		authorizePath = fmt.Sprintf("/%s/api/v2/hotspot/extPortal/auth", strings.Trim(c.controllerID, "/"))
	}
	payload := AuthorizeRequest{
		Site:       firstNonEmpty(client.Site, c.site),
		ClientMAC:  client.MAC,
		SSIDName:   client.SSID,
		APMAC:      client.APMAC,
		GatewayMAC: client.GatewayMAC,
		RadioID:    client.RadioID,
		VID:        client.VLAN,
		Time:       duration.Milliseconds(),
		AuthType:   4,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal authorize payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, c.authorizeMethod, c.baseURL+authorizePath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Csrf-Token", c.csrfToken)

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
	if result.ErrorCode != 0 {
		return &Error{Code: result.ErrorCode, Message: result.Msg}
	}
	return nil
}

func (c *Client) login(ctx context.Context) error {
	payload, err := json.Marshal(ControllerLoginRequest{Name: c.username, Password: c.password})
	if err != nil {
		return fmt.Errorf("marshal omada login payload: %w", err)
	}
	path := fmt.Sprintf("/%s/api/v2/hotspot/login", strings.Trim(c.controllerID, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build omada login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("omada hotspot login request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &Error{Code: resp.StatusCode, Body: string(body)}
	}

	var result ControllerLoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode omada login response: %w", err)
	}
	if result.ErrorCode != 0 {
		return &Error{Code: result.ErrorCode, Message: result.Msg}
	}
	if result.Result.Token == "" {
		return fmt.Errorf("omada hotspot login response missing CSRF token")
	}
	c.csrfToken = result.Result.Token
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
