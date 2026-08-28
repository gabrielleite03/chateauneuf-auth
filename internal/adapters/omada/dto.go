package omada

// ControllerLoginRequest is the payload used when authenticating the service itself to Omada.
// This is intentionally kept generic because the controller API contract can vary across versions.
type ControllerLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ControllerLoginResponse represents the authentication response from Omada.
type ControllerLoginResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Token string `json:"token,omitempty"`
	} `json:"data,omitempty"`
}

// AuthorizeRequest describes the controller payload intended to authorize a specific client.
// Omada 5.0.15+ may additionally require controllerId, site, and CSRF token handling, which
// is isolated in the adapter and not assumed globally by the application layer.
type AuthorizeRequest struct {
	Site         string `json:"site,omitempty"`
	ControllerID string `json:"controllerId,omitempty"`
	ClientMAC    string `json:"clientMac,omitempty"`
	ClientIP     string `json:"clientIp,omitempty"`
	SSID         string `json:"ssid,omitempty"`
	APMAC        string `json:"apMac,omitempty"`
	GatewayMAC   string `json:"gatewayMac,omitempty"`
	RadioID      string `json:"radioId,omitempty"`
	VLAN         string `json:"vlan,omitempty"`
	Vid          string `json:"vid,omitempty"`
	Duration     int    `json:"duration,omitempty"`
}

// AuthorizeResponse encapsulates the success or failure payload returned by Omada.
type AuthorizeResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}
