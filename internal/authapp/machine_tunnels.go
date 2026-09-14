package authapp

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
	if r.Method != http.MethodPost {
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
	if e != nil || q.Port < 1 || q.Port > 65535 {
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
	run, e := provisionTunnel(r.Context(), token, z.CloudflareZoneID, n, q.Port)
	if e != nil {
		writeAPIError(w, 502, fmt.Errorf("Cloudflare tunnel setup: %w", e))
		return
	}
	_ = tenant
	writeJSON(w, 200, MachineTunnelResult{Hostname: n, Token: run, Port: q.Port})
}

func provisionTunnel(ctx context.Context, token, zoneID, host string, port int) (string, error) {
	c := cf{token}
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

type cf struct{ token string }

func (c cf) do(x context.Context, m, p string, b, out any) error {
	var r io.Reader
	if b != nil {
		v, _ := json.Marshal(b)
		r = bytes.NewReader(v)
	}
	q, e := http.NewRequestWithContext(x, m, "https://api.cloudflare.com/client/v4"+p, r)
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
	var v []struct {
		ID string `json:"id"`
	}
	if e := c.do(x, "GET", "/accounts/"+a+"/cfd_tunnel?name="+n+"&is_deleted=false", nil, &v); e != nil {
		return "", e
	}
	if len(v) > 0 {
		return v[0].ID, nil
	}
	var o struct {
		ID string `json:"id"`
	}
	e := c.do(x, "POST", "/accounts/"+a+"/cfd_tunnel", map[string]string{"name": n, "config_src": "cloudflare"}, &o)
	return o.ID, e
}
func (c cf) dns(x context.Context, z, h, t string) error {
	return c.do(x, "POST", "/zones/"+z+"/dns_records", map[string]any{"type": "CNAME", "name": h, "content": t, "proxied": true}, nil)
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
