package auth

// AuthResult holds the outcome of a portal authentication attempt.
type AuthResult struct {
	Authenticated bool
	ClientMAC     string
	ClientIP      string
	RedirectURL   string
	Message       string
}
