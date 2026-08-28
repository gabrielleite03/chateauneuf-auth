package omada

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// NewHTTPClient builds the Omada HTTP client with optional self-signed certificate acceptance.
func NewHTTPClient(baseURL string, tlsInsecure bool, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecure},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeBaseURL(raw string) string {
	return strings.TrimRight(raw, "/")
}
