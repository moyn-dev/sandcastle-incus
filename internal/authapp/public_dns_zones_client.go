package authapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Public DNS Zone client methods for `public-dns-zone …` on both CLI roots.
// They drive the admin-gated /api/public-dns-zones endpoints with the admin's
// CLI Auth Token. A refusal's `{error}` body is returned verbatim as the error
// text — the spec §2.1 messages are server-produced and printed unchanged.

// ListPublicDNSZones returns the registered zones.
func (c DeviceClient) ListPublicDNSZones(ctx context.Context) ([]PublicDNSZone, error) {
	var result PublicDNSZoneListResult
	if err := c.publicDNSZoneCall(ctx, http.MethodGet, "/api/public-dns-zones", nil, &result); err != nil {
		return nil, err
	}
	return result.Zones, nil
}

// AddPublicDNSZone registers a zone after the Auth App validated the token.
func (c DeviceClient) AddPublicDNSZone(ctx context.Context, zone, token string, dryRun bool) (PublicDNSZoneResult, error) {
	var result PublicDNSZoneResult
	err := c.publicDNSZoneCall(ctx, http.MethodPost, "/api/public-dns-zones",
		PublicDNSZoneRequest{Zone: zone, Token: token, DryRun: dryRun}, &result)
	return result, err
}

// SetPublicDNSZoneToken rotates a zone's token.
func (c DeviceClient) SetPublicDNSZoneToken(ctx context.Context, zone, token string, dryRun bool) (PublicDNSZoneResult, error) {
	var result PublicDNSZoneResult
	err := c.publicDNSZoneCall(ctx, http.MethodPut, "/api/public-dns-zones/"+url.PathEscape(zone)+"/token",
		PublicDNSZoneRequest{Token: token, DryRun: dryRun}, &result)
	return result, err
}

// RemovePublicDNSZone deletes a zone (refused while Project Domains are
// claimed under it).
func (c DeviceClient) RemovePublicDNSZone(ctx context.Context, zone string, dryRun bool) (PublicDNSZoneResult, error) {
	path := "/api/public-dns-zones/" + url.PathEscape(zone)
	if dryRun {
		path += "?dryRun=1"
	}
	var result PublicDNSZoneResult
	if err := c.publicDNSZoneCall(ctx, http.MethodDelete, path, nil, &result); err != nil {
		return PublicDNSZoneResult{}, err
	}
	if result.Zone == "" {
		result.Zone = zone
	}
	result.DryRun = dryRun
	return result, nil
}

func (c DeviceClient) publicDNSZoneCall(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, c.url(path), reader)
	if err != nil {
		return err
	}
	if body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &refusal) == nil && strings.TrimSpace(refusal.Error) != "" {
			return errors.New(refusal.Error)
		}
		return fmt.Errorf("public DNS zone %s %s: %s: %s", method, path, response.Status, strings.TrimSpace(string(payload)))
	}
	if out == nil || len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	return json.Unmarshal(payload, out)
}
