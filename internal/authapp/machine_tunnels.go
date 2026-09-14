package authapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MachineTunnelRequest struct {
	Tenant   string `json:"tenant,omitempty"`
	Project  string `json:"project"`
	Machine  string `json:"machine"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}
type MachineTunnelResult struct {
	Hostname string `json:"hostname"`
	Token    string `json:"token"`
	Port     int    `json:"port"`
}

func (h handler) machineTunnelsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	u, e := h.requireBearerUser(r)
	if e != nil {
		writeAPIError(w, 401, e)
		return
	}
	var q MachineTunnelRequest
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		writeAPIError(w, 400, fmt.Errorf("invalid request body"))
		return
	}
	tenant, e := h.machineHostnameTenant(r.Context(), u, q.Tenant)
	if e != nil {
		writeAPIError(w, 403, e)
		return
	}
	n, e := NormalizeMachineHostname(q.Hostname)
	if e != nil || strings.TrimSpace(q.Project) == "" || strings.TrimSpace(q.Machine) == "" || (r.Method == http.MethodPost && (q.Port < 1 || q.Port > 65535)) {
		writeAPIError(w, 400, fmt.Errorf("invalid tunnel hostname or port"))
		return
	}
	zones, e := ListPublicDNSZones(r.Context(), h.db)
	if e != nil {
		writeAPIError(w, 500, e)
		return
	}
	var z PublicDNSZone
	for _, x := range zones {
		if n != x.Zone && strings.HasSuffix(n, "."+x.Zone) && len(x.Zone) > len(z.Zone) {
			z = x
		}
	}
	if z.Zone == "" {
		writeAPIError(w, 400, fmt.Errorf("no Public DNS Zone covers %s — ask your admin", n))
		return
	}
	token, e := PublicDNSZoneToken(r.Context(), h.db, z.Zone)
	if e != nil {
		writeAPIError(w, 500, e)
		return
	}
	_ = tenant
	if r.Method == http.MethodDelete {
		publication, found, err := GetMachineTunnelPublication(r.Context(), h.db, n)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		// Installations upgraded from before the registry have no durable
		// ownership row. Treat a repeat delete as done rather than guessing
		// ownership and risking another Machine's hostname.
		if !found {
			writeJSON(w, http.StatusOK, MachineTunnelResult{Hostname: n})
			return
		}
		if publication.Tenant != tenant || publication.Project != strings.TrimSpace(q.Project) || publication.Machine != strings.TrimSpace(q.Machine) {
			writeAPIError(w, http.StatusConflict, fmt.Errorf("Machine Tunnel hostname %q is not published by this Machine", n))
			return
		}
		if e := unprovisionTunnel(r.Context(), token, h.cloudflareBaseURL, z.CloudflareZoneID, n); e != nil {
			writeAPIError(w, 502, fmt.Errorf("Cloudflare tunnel cleanup: %w", e))
			return
		}
		if err := ReleaseMachineTunnelPublication(r.Context(), h.db, publication); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		if err := HoldMachinePublicationHostname(r.Context(), h.db, n); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, 200, MachineTunnelResult{Hostname: n})
		return
	}
	if err := h.preflightMachineTunnel(r.Context(), n, token, z.CloudflareZoneID); err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	publication, claimed, err := ClaimMachineTunnelPublication(r.Context(), h.db, MachineTunnelPublication{Hostname: n, Tenant: tenant, Project: q.Project, Machine: q.Machine, Port: q.Port})
	if err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	run, e := provisionTunnel(r.Context(), token, h.cloudflareBaseURL, z.CloudflareZoneID, n, q.Port)
	if e != nil {
		if claimed {
			if releaseErr := ReleaseMachineTunnelPublication(r.Context(), h.db, publication); releaseErr != nil {
				writeAPIError(w, http.StatusInternalServerError, releaseErr)
				return
			}
		}
		writeAPIError(w, 502, fmt.Errorf("Cloudflare tunnel setup: %w", e))
		return
	}
	writeJSON(w, 200, MachineTunnelResult{Hostname: n, Token: run, Port: q.Port})
}

// preflightMachineTunnel completes every non-mutating ownership check before
// Cloudflare can create a tunnel, alter its ingress configuration, or write
// DNS. Machine Tunnels are deliberately a separate publication kind, so they
// may not share a hostname with a Machine Public Hostname or Public Route.
func (h handler) preflightMachineTunnel(ctx context.Context, hostname, token, zoneID string) error {
	if err := RequireMachinePublicationHostnameAvailable(ctx, h.db, hostname); err != nil {
		return err
	}
	hostnames, err := ListMachineHostnames(ctx, h.db)
	if err != nil {
		return err
	}
	for _, existing := range hostnames {
		if existing.Hostname == hostname {
			return fmt.Errorf("%q is already claimed as a Machine Public Hostname", hostname)
		}
	}
	if route, found, err := GetRoute(ctx, h.db, hostname); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%q is already published as a Public Route by machine %q", hostname, route.Project+":"+route.Machine)
	}
	return (cf{token: token, baseURL: h.cloudflareBaseURL}).tunnelDNSPreflight(ctx, zoneID, hostname)
}

func provisionTunnel(ctx context.Context, token, baseURL, zoneID, host string, port int) (string, error) {
	c := cf{token: token, baseURL: baseURL}
	account, e := c.account(ctx, zoneID)
	if e != nil {
		return "", e
	}
	id, e := c.tunnel(ctx, account, strings.ReplaceAll(host, ".", "-"))
	if e != nil {
		return "", e
	}
	if e = c.do(ctx, "PUT", "/accounts/"+account+"/cfd_tunnel/"+id+"/configurations", map[string]any{"config": map[string]any{"ingress": []map[string]string{{"hostname": host, "service": fmt.Sprintf("http://localhost:%d", port)}, {"service": "http_status:404"}}}}, nil); e != nil {
		return "", e
	}
	if e = c.dns(ctx, zoneID, host, id+".cfargotunnel.com"); e != nil {
		return "", e
	}
	var out string
	e = c.do(ctx, "GET", "/accounts/"+account+"/cfd_tunnel/"+id+"/token", nil, &out)
	return out, e
}

// unprovisionTunnel removes a Machine Tunnel only after removing the CNAME
// that proves this tunnel owns the hostname. Other records are deliberately
// left alone: unpublish must never turn into a hostname replacement operation.
func unprovisionTunnel(ctx context.Context, token, baseURL, zoneID, host string) error {
	c := cf{token: token, baseURL: baseURL}
	account, err := c.account(ctx, zoneID)
	if err != nil {
		return err
	}
	return c.unprovisionTunnel(ctx, account, zoneID, host)
}

type cf struct {
	token   string
	baseURL string // test seam; production uses Cloudflare's v4 endpoint.
}

func (c cf) do(x context.Context, m, p string, b, out any) error {
	var r io.Reader
	if b != nil {
		v, _ := json.Marshal(b)
		r = bytes.NewReader(v)
	}
	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	q, e := http.NewRequestWithContext(x, m, baseURL+p, r)
	if e != nil {
		return e
	}
	q.Header.Set("Authorization", "Bearer "+c.token)
	q.Header.Set("Content-Type", "application/json")
	z, e := (&http.Client{Timeout: 30 * time.Second}).Do(q)
	if e != nil {
		return e
	}
	defer z.Body.Close()
	d, _ := io.ReadAll(z.Body)
	var v struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Message string `json:"message"`
		}
	}
	if json.Unmarshal(d, &v) != nil || !v.Success {
		return fmt.Errorf("Cloudflare request failed")
	}
	if out != nil {
		return json.Unmarshal(v.Result, out)
	}
	return nil
}
func (c cf) account(x context.Context, z string) (string, error) {
	var v struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	e := c.do(x, "GET", "/zones/"+z, nil, &v)
	return v.Account.ID, e
}
func (c cf) tunnel(x context.Context, a, n string) (string, error) {
	if id, found, e := c.existingTunnel(x, a, n); e != nil {
		return "", e
	} else if found {
		return id, nil
	}
	var o struct {
		ID string `json:"id"`
	}
	e := c.do(x, "POST", "/accounts/"+a+"/cfd_tunnel", map[string]string{"name": n, "config_src": "cloudflare"}, &o)
	return o.ID, e
}

func (c cf) existingTunnel(x context.Context, account, name string) (string, bool, error) {
	var tunnels []struct {
		ID string `json:"id"`
	}
	if err := c.do(x, "GET", "/accounts/"+account+"/cfd_tunnel?name="+url.QueryEscape(name)+"&is_deleted=false", nil, &tunnels); err != nil {
		return "", false, err
	}
	if len(tunnels) == 0 {
		return "", false, nil
	}
	return tunnels[0].ID, true, nil
}
func (c cf) dns(x context.Context, z, h, t string) error {
	var records []struct {
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	if err := c.do(x, "GET", "/zones/"+z+"/dns_records?name="+url.QueryEscape(h), nil, &records); err != nil {
		return err
	}
	for _, record := range records {
		if record.Type == "CNAME" && sameTunnelTarget(record.Content, t) {
			return nil
		}
		return fmt.Errorf("%q already has a DNS record; remove it before publishing a Machine Tunnel", h)
	}
	return c.do(x, "POST", "/zones/"+z+"/dns_records", map[string]any{"type": "CNAME", "name": h, "content": t, "proxied": true}, nil)
}

// tunnelDNSPreflight refuses a foreign DNS record before provisioning starts.
// An existing named tunnel is read only so its own CNAME remains idempotent.
func (c cf) tunnelDNSPreflight(ctx context.Context, zoneID, hostname string) error {
	account, err := c.account(ctx, zoneID)
	if err != nil {
		return err
	}
	id, found, err := c.existingTunnel(ctx, account, strings.ReplaceAll(hostname, ".", "-"))
	if err != nil {
		return err
	}
	var records []struct {
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	if err := c.do(ctx, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(hostname), nil, &records); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	if found {
		for _, record := range records {
			if record.Type != "CNAME" || !sameTunnelTarget(record.Content, id+".cfargotunnel.com") {
				return fmt.Errorf("%q already has a DNS record; remove it before publishing a Machine Tunnel", hostname)
			}
		}
		return nil
	}
	return fmt.Errorf("%q already has a DNS record; remove it before publishing a Machine Tunnel", hostname)
}

func (c cf) unprovisionTunnel(ctx context.Context, account, zoneID, hostname string) error {
	id, found, err := c.existingTunnel(ctx, account, strings.ReplaceAll(hostname, ".", "-"))
	if err != nil || !found {
		return err
	}
	target := id + ".cfargotunnel.com"
	var records []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	if err := c.do(ctx, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(hostname), nil, &records); err != nil {
		return err
	}
	for _, record := range records {
		if record.Type == "CNAME" && sameTunnelTarget(record.Content, target) {
			if err := c.do(ctx, "DELETE", "/zones/"+zoneID+"/dns_records/"+record.ID, nil, nil); err != nil {
				return err
			}
		}
	}
	return c.do(ctx, "DELETE", "/accounts/"+account+"/cfd_tunnel/"+id, nil, nil)
}

func sameTunnelTarget(got, want string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(got), "."), strings.TrimSuffix(strings.TrimSpace(want), "."))
}

func (c DeviceClient) ProvisionMachineTunnel(x context.Context, q MachineTunnelRequest) (MachineTunnelResult, error) {
	b, _ := json.Marshal(q)
	r, e := http.NewRequestWithContext(x, "POST", c.url("/api/machine-tunnels"), bytes.NewReader(b))
	if e != nil {
		return MachineTunnelResult{}, e
	}
	r.Header.Set("Authorization", "Bearer "+c.AuthToken)
	r.Header.Set("Content-Type", "application/json")
	v, e := c.client().Do(r)
	if e != nil {
		return MachineTunnelResult{}, e
	}
	defer v.Body.Close()
	d, _ := io.ReadAll(v.Body)
	if v.StatusCode != 200 {
		return MachineTunnelResult{}, fmt.Errorf("provision machine tunnel: %s", strings.TrimSpace(string(d)))
	}
	var o MachineTunnelResult
	e = json.Unmarshal(d, &o)
	return o, e
}

// UnprovisionMachineTunnel drives DELETE /api/machine-tunnels. Repeating it
// is safe: the Auth App treats an already-deleted Cloudflare tunnel as done.
func (c DeviceClient) UnprovisionMachineTunnel(x context.Context, q MachineTunnelRequest) (MachineTunnelResult, error) {
	b, _ := json.Marshal(q)
	r, e := http.NewRequestWithContext(x, http.MethodDelete, c.url("/api/machine-tunnels"), bytes.NewReader(b))
	if e != nil {
		return MachineTunnelResult{}, e
	}
	r.Header.Set("Authorization", "Bearer "+c.AuthToken)
	r.Header.Set("Content-Type", "application/json")
	v, e := c.client().Do(r)
	if e != nil {
		return MachineTunnelResult{}, e
	}
	defer v.Body.Close()
	d, _ := io.ReadAll(v.Body)
	if v.StatusCode != http.StatusOK {
		return MachineTunnelResult{}, fmt.Errorf("unpublish machine tunnel: %s", strings.TrimSpace(string(d)))
	}
	var o MachineTunnelResult
	e = json.Unmarshal(d, &o)
	return o, e
}
