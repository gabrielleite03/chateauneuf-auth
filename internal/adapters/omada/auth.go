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
	"net/url"
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
	revokePath      string
	openAPIClientID string
	openAPISecret   string
	openAPIOmadacID string
	siteID          string
	accessToken     string
	tokenExpiresAt  time.Time
}

func (c *Client) SetRevokePath(path string) { c.revokePath = strings.TrimSpace(path) }

func (c *Client) SetOpenAPI(clientID, clientSecret, omadacID, siteID string) {
	c.openAPIClientID = strings.TrimSpace(clientID)
	c.openAPISecret = strings.TrimSpace(clientSecret)
	c.openAPIOmadacID = strings.TrimSpace(omadacID)
	c.siteID = strings.TrimSpace(siteID)
}

func (c *Client) Revoke(ctx context.Context, client domain.Client) error {
	if c.openAPIClientID != "" || c.openAPISecret != "" || c.siteID != "" {
		if err := c.revokeHotspotAuthorization(ctx, client.MAC); err != nil {
			return err
		}
		return c.revokeOpenAPI(ctx, client.MAC)
	}
	if c.revokePath == "" {
		return fmt.Errorf("Omada Open API is required to revoke active sessions: configure OMADA_OPENAPI_CLIENT_ID, OMADA_OPENAPI_CLIENT_SECRET and OMADA_SITE_ID")
	}
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	if err := c.login(ctx); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"clientMac": client.MAC, "site": firstNonEmpty(client.Site, c.site)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.revokePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Csrf-Token", c.csrfToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Code: resp.StatusCode, Body: string(b)}
	}
	return nil
}

type hotspotAuthorizedClient struct {
	ID    string `json:"id"`
	MAC   string `json:"mac"`
	Valid bool   `json:"valid"`
}

func (c *Client) revokeHotspotAuthorization(ctx context.Context, mac string) error {
	if c.baseURL == "" || c.controllerID == "" || c.siteID == "" || c.username == "" || c.password == "" {
		return fmt.Errorf("Omada Hotspot configuration incomplete: base URL, controller ID, site ID, operator username and password are required")
	}

	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	if err := c.login(ctx); err != nil {
		return err
	}

	listPath := fmt.Sprintf("/%s/api/v2/hotspot/sites/%s/clients?currentPage=1&currentPageSize=1000",
		url.PathEscape(strings.Trim(c.controllerID, "/")), url.PathEscape(c.siteID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+listPath, nil)
	if err != nil {
		return fmt.Errorf("build Omada Hotspot clients request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Csrf-Token", c.csrfToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Omada Hotspot clients request: %w", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read Omada Hotspot clients response: %w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &Error{Code: resp.StatusCode, Body: string(body)}
	}
	var result struct {
		ErrorCode int    `json:"errorCode"`
		Msg       string `json:"msg"`
		Result    struct {
			Data []hotspotAuthorizedClient `json:"data"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode Omada Hotspot clients response: %w", err)
	}
	if result.ErrorCode != 0 {
		return &Error{Code: result.ErrorCode, Message: result.Msg}
	}

	targetMAC := omadaMAC(mac)
	for _, authorized := range result.Result.Data {
		if omadaMAC(authorized.MAC) != targetMAC || !authorized.Valid {
			continue
		}
		if strings.TrimSpace(authorized.ID) == "" {
			return fmt.Errorf("Omada Hotspot authorized client %s is missing its internal ID", targetMAC)
		}
		disconnectPath := fmt.Sprintf("/%s/api/v2/hotspot/sites/%s/cmd/clients/%s/disconnect",
			url.PathEscape(strings.Trim(c.controllerID, "/")), url.PathEscape(c.siteID), url.PathEscape(authorized.ID))
		disconnectReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+disconnectPath, nil)
		if err != nil {
			return fmt.Errorf("build Omada Hotspot disconnect request: %w", err)
		}
		disconnectReq.Header.Set("Accept", "application/json")
		disconnectReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
		disconnectReq.Header.Set("Csrf-Token", c.csrfToken)
		disconnectResp, err := c.httpClient.Do(disconnectReq)
		if err != nil {
			return fmt.Errorf("Omada Hotspot disconnect request: %w", err)
		}
		disconnectBody, readErr := io.ReadAll(disconnectResp.Body)
		disconnectResp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read Omada Hotspot disconnect response: %w", readErr)
		}
		if disconnectResp.StatusCode < http.StatusOK || disconnectResp.StatusCode >= http.StatusMultipleChoices {
			return &Error{Code: disconnectResp.StatusCode, Body: string(disconnectBody)}
		}
		if len(disconnectBody) > 0 {
			var disconnectResult AuthorizeResponse
			if err := json.Unmarshal(disconnectBody, &disconnectResult); err != nil {
				return fmt.Errorf("decode Omada Hotspot disconnect response: %w", err)
			}
			if disconnectResult.ErrorCode != 0 {
				return &Error{Code: disconnectResult.ErrorCode, Message: disconnectResult.Msg}
			}
		}
		return nil
	}

	// No valid Hotspot authorization means this part of revocation is already complete.
	return nil
}

func (c *Client) revokeOpenAPI(ctx context.Context, mac string) error {
	if c.baseURL == "" || c.openAPIOmadacID == "" || c.openAPIClientID == "" || c.openAPISecret == "" || c.siteID == "" {
		return fmt.Errorf("Omada Open API configuration incomplete: base URL, Omada ID, client ID, client secret and site ID are required")
	}
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	if err := c.ensureOpenAPIToken(ctx); err != nil {
		return err
	}
	openAPIMAC := strings.ReplaceAll(strings.ToUpper(mac), ":", "-")
	path := fmt.Sprintf("/openapi/v1/%s/sites/%s/clients/%s", url.PathEscape(c.openAPIOmadacID), url.PathEscape(c.siteID), url.PathEscape(openAPIMAC))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build Omada client disconnect request: %w", err)
	}
	req.Header.Set("Authorization", "AccessToken="+c.accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Omada client disconnect request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Code: resp.StatusCode, Body: string(body)}
	}
	var result AuthorizeResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("decode Omada client disconnect response: %w", err)
		}
		// Disconnect is idempotent: an absent client has no active session left to revoke.
		if result.ErrorCode == -41011 {
			return nil
		}
		if result.ErrorCode != 0 {
			return &Error{Code: result.ErrorCode, Message: result.Msg}
		}
	}
	return nil
}

func (c *Client) ensureOpenAPIToken(ctx context.Context) error {
	if c.accessToken != "" && time.Now().Add(30*time.Second).Before(c.tokenExpiresAt) {
		return nil
	}
	payload, err := json.Marshal(map[string]string{
		"omadacId": c.openAPIOmadacID, "client_id": c.openAPIClientID, "client_secret": c.openAPISecret,
	})
	if err != nil {
		return err
	}
	endpoint := c.baseURL + "/openapi/authorize/token?grant_type=client_credentials"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build Omada Open API token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Omada Open API token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Code: resp.StatusCode, Body: string(body)}
	}
	var result struct {
		ErrorCode int    `json:"errorCode"`
		Msg       string `json:"msg"`
		Result    struct {
			AccessToken string `json:"accessToken"`
			ExpiresIn   int    `json:"expiresIn"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode Omada Open API token response: %w", err)
	}
	if result.ErrorCode != 0 {
		return &Error{Code: result.ErrorCode, Message: result.Msg}
	}
	if result.Result.AccessToken == "" {
		return fmt.Errorf("Omada Open API token response missing access token")
	}
	c.accessToken = result.Result.AccessToken
	expiresIn := result.Result.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 7200
	}
	c.tokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return nil
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
		// Omada External Portal API v5.0.15-v6.2.0 expects the configured
		// site name, even when the redirect query contains the internal site ID.
		Site:       firstNonEmpty(c.site, client.Site),
		ClientMAC:  omadaMAC(client.MAC),
		SSIDName:   client.SSID,
		APMAC:      omadaMAC(client.APMAC),
		GatewayMAC: omadaMAC(client.GatewayMAC),
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

func omadaMAC(value string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(value)), ":", "-")
}
