package domain

import "strings"

// Client represents the network client being authorized by Omada.
type Client struct {
	MAC          string
	IP           string
	APMAC        string
	GatewayMAC   string
	SSID         string
	RadioID      string
	VLAN         string
	Site         string
	RedirectURL  string
	ControllerID string
}

func (c Client) Normalized() Client {
	c.MAC = normalizeMAC(c.MAC)
	c.APMAC = normalizeMAC(c.APMAC)
	c.GatewayMAC = normalizeMAC(c.GatewayMAC)
	c.SSID = strings.TrimSpace(c.SSID)
	c.RadioID = strings.TrimSpace(c.RadioID)
	c.VLAN = strings.TrimSpace(c.VLAN)
	c.Site = strings.TrimSpace(c.Site)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.ControllerID = strings.TrimSpace(c.ControllerID)
	return c
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "-", ":")
	value = strings.ToUpper(value)
	return value
}
