package residents

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HTTPDirectory struct {
	url    string
	client *http.Client
}

func NewHTTPDirectory(url string) *HTTPDirectory {
	return &HTTPDirectory{url: strings.TrimSpace(url), client: &http.Client{Timeout: 5 * time.Second}}
}
func (d *HTTPDirectory) ApartmentExists(ctx context.Context, apartment string) (bool, error) {
	if d.url == "" {
		return false, fmt.Errorf("RESIDENTS_API_URL is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		return false, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("query residents: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("residents API returned HTTP %d", resp.StatusCode)
	}
	var rows []struct {
		Unit   string `json:"unit"`
		Owner  string `json:"owner"`
		Tenant string `json:"tenant"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return false, err
	}
	wanted := strings.TrimSpace(apartment)
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Unit), wanted) && (strings.TrimSpace(r.Owner) != "" || strings.TrimSpace(r.Tenant) != "") {
			return true, nil
		}
	}
	return false, nil
}
