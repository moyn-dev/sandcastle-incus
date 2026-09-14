package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ensureCloudflareTunnel makes a remotely-managed Cloudflare tunnel serve the
// hostname (→ http://localhost:8080 at the connector) with a proxied CNAME, and
// returns the connector token — the fully automated variant of the manual
// dashboard steps. Idempotent: an existing tunnel with the same name is reused
// and the DNS record is repointed.
func ensureCloudflareTunnel(ctx context.Context, apiToken string, hostname string) (string, error) {
	return ensureCloudflareTunnelService(ctx, apiToken, hostname, "http://localhost:8080")
}

// ensureCloudflareTunnelService is the reusable tunnel provisioner. The
// connector token it returns is deliberately scoped to this one tunnel; the
// caller's account-level API token is never installed on an origin.
func ensureCloudflareTunnelService(ctx context.Context, apiToken string, hostname string, service string) (string, error) {
	cf := cloudflareAPI{token: strings.TrimSpace(apiToken)}
	zoneID, accountID, err := cf.findZone(ctx, hostname)
	if err != nil {
		return "", err
	}
	name := strings.ReplaceAll(hostname, ".", "-")
	tunnelID, err := cf.ensureTunnel(ctx, accountID, name)
	if err != nil {
		return "", err
	}
	if err := cf.setTunnelIngressService(ctx, accountID, tunnelID, hostname, service); err != nil {
		return "", err
	}
	if err := cf.ensureDNSRecord(ctx, zoneID, hostname, tunnelID+".cfargotunnel.com"); err != nil {
		return "", err
	}
	return cf.tunnelToken(ctx, accountID, tunnelID)
}

// ensureMachineCloudflareTunnel refuses to repurpose an existing DNS record.
// Machine Tunnels are additive: a Machine Public Hostname, a hand-managed
// record, or another service must be removed deliberately before its name can
// become a Cloudflare Tunnel hostname.
func ensureMachineCloudflareTunnel(ctx context.Context, apiToken, hostname string, port int) (string, error) {
	cf := cloudflareAPI{token: strings.TrimSpace(apiToken)}
	zoneID, accountID, err := cf.findZone(ctx, hostname)
	if err != nil {
		return "", err
	}
	var records []struct {
		ID string `json:"id"`
	}
	if err := cf.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?name="+hostname, nil, &records); err != nil {
		return "", err
	}
	if len(records) != 0 {
		return "", fmt.Errorf("%q already has a DNS record; remove it (and any Machine Public Hostname claim) before publishing a Machine Tunnel", hostname)
	}
	tunnelID, err := cf.ensureTunnel(ctx, accountID, strings.ReplaceAll(hostname, ".", "-"))
	if err != nil {
		return "", err
	}
	if err := cf.setTunnelIngressService(ctx, accountID, tunnelID, hostname, fmt.Sprintf("http://localhost:%d", port)); err != nil {
		return "", err
	}
	if err := cf.ensureDNSRecord(ctx, zoneID, hostname, tunnelID+".cfargotunnel.com"); err != nil {
		return "", err
	}
	return cf.tunnelToken(ctx, accountID, tunnelID)
}

// zoneCandidates lists the possible zone names for a hostname, most specific
// first: a.b.example.com → [b.example.com, example.com].
func zoneCandidates(hostname string) []string {
	labels := strings.Split(strings.TrimSuffix(strings.TrimSpace(hostname), "."), ".")
	candidates := []string{}
	for i := 1; i <= len(labels)-2; i++ {
		candidates = append(candidates, strings.Join(labels[i:], "."))
	}
	return candidates
}

type cloudflareAPI struct {
	token string
}

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

func (c cloudflareAPI) do(ctx context.Context, method string, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, cloudflareAPIBase+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.TrimSpace(string(data)))
	}
	if !envelope.Success {
		messages := []string{}
		for _, e := range envelope.Errors {
			messages = append(messages, e.Message)
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(messages, "; "))
	}
	if out != nil {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

func (c cloudflareAPI) findZone(ctx context.Context, hostname string) (zoneID string, accountID string, err error) {
	for _, candidate := range zoneCandidates(hostname) {
		var zones []struct {
			ID      string `json:"id"`
			Account struct {
				ID string `json:"id"`
			} `json:"account"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?name="+candidate, nil, &zones); err != nil {
			return "", "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, zones[0].Account.ID, nil
		}
	}
	return "", "", fmt.Errorf("no Cloudflare zone found for %q (checked %s) — is the API token scoped to the right zone?",
		hostname, strings.Join(zoneCandidates(hostname), ", "))
}

func (c cloudflareAPI) ensureTunnel(ctx context.Context, accountID string, name string) (string, error) {
	var existing []struct {
		ID        string  `json:"id"`
		DeletedAt *string `json:"deleted_at"`
	}
	if err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel?name="+name+"&is_deleted=false", nil, &existing); err != nil {
		return "", err
	}
	if len(existing) > 0 {
		return existing[0].ID, nil
	}
	var created struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/accounts/"+accountID+"/cfd_tunnel", map[string]string{
		"name":       name,
		"config_src": "cloudflare",
	}, &created)
	return created.ID, err
}

func (c cloudflareAPI) setTunnelIngress(ctx context.Context, accountID string, tunnelID string, hostname string) error {
	return c.setTunnelIngressService(ctx, accountID, tunnelID, hostname, "http://localhost:8080")
}

func (c cloudflareAPI) setTunnelIngressService(ctx context.Context, accountID string, tunnelID string, hostname string, service string) error {
	return c.do(ctx, http.MethodPut, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/configurations", map[string]any{
		"config": map[string]any{
			"ingress": []map[string]string{
				{"hostname": hostname, "service": service},
				{"service": "http_status:404"},
			},
		},
	}, nil)
}

func (c cloudflareAPI) ensureDNSRecord(ctx context.Context, zoneID string, hostname string, target string) error {
	var records []struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?name="+hostname, nil, &records); err != nil {
		return err
	}
	record := map[string]any{"type": "CNAME", "name": hostname, "content": target, "proxied": true}
	if len(records) > 0 {
		return c.do(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+records[0].ID, record, nil)
	}
	return c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", record, nil)
}

func (c cloudflareAPI) tunnelToken(ctx context.Context, accountID string, tunnelID string) (string, error) {
	var token string
	err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/token", nil, &token)
	return token, err
}
