package omada

// ControllerLoginRequest is the payload used when authenticating the service itself to Omada.
// This is intentionally kept generic because the controller API contract can vary across versions.
type ControllerLoginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// ControllerLoginResponse represents the authentication response from Omada.
type ControllerLoginResponse struct {
	ErrorCode int    `json:"errorCode"`
	Msg       string `json:"msg"`
	Result    struct {
		Token string `json:"token,omitempty"`
	} `json:"result,omitempty"`
}

// AuthorizeRequest describes the controller payload intended to authorize a specific client.
// Omada 5.0.15+ may additionally require controllerId, site, and CSRF token handling, which
// is isolated in the adapter and not assumed globally by the application layer.
type AuthorizeRequest struct {
	Site       string `json:"site"`
	ClientMAC  string `json:"clientMac"`
	SSIDName   string `json:"ssidName,omitempty"`
	APMAC      string `json:"apMac,omitempty"`
	GatewayMAC string `json:"gatewayMac,omitempty"`
	RadioID    string `json:"radioId,omitempty"`
	VID        string `json:"vid,omitempty"`
	Time       int64  `json:"time"`
	AuthType   int    `json:"authType"`
}

// AuthorizeResponse encapsulates the success or failure payload returned by Omada.
type AuthorizeResponse struct {
	ErrorCode int    `json:"errorCode"`
	Msg       string `json:"msg"`
}
