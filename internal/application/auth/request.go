package auth

// LoginRequest represents the submitted portal credentials and session token.
type LoginRequest struct {
	SessionID string
	Username  string
	Password  string
}

// PortalRequest captures the client data received from Omada redirect.
type PortalRequest struct {
	ClientMAC    string
	ClientIP     string
	APMAC        string
	GatewayMAC   string
	SSID         string
	RadioID      string
	VLAN         string
	Site         string
	RedirectURL  string
	ControllerID string
}
