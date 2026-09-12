package authapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// /api/public-dns-zones (spec public-dns-zones §3.1) — the admin-only registry
// plane behind `public-dns-zone add|list|remove|set-token` on both CLI roots.
// Every verb is a thin call authenticated by the admin's CLI Auth Token, so it
// works through a tunnel and needs no appliance redeploy. Error bodies are
// `{"error": "<verbatim §2.1 text>"}`; the CLI prints `error` unchanged.

// PublicDNSZoneRequest is the body of POST /api/public-dns-zones and
// PUT /api/public-dns-zones/{zone}/token.
type PublicDNSZoneRequest struct {
	Zone   string `json:"zone,omitempty"`
	Token  string `json:"token"`
	DryRun bool   `json:"dryRun,omitempty"`
}

// PublicDNSZoneResult is the body of a successful add/set-token/remove (and
// of any dry run of them).
type PublicDNSZoneResult struct {
	Zone             string `json:"zone"`
	CloudflareZoneID string `json:"cloudflareZoneID,omitempty"`
	DryRun           bool   `json:"dryRun,omitempty"`
}

// PublicDNSZoneListResult is the body of GET /api/public-dns-zones.
type PublicDNSZoneListResult struct {
	Zones []PublicDNSZone `json:"zones"`
}

// requireAdminBearer is requireAdmin for the token-gated API: a CLI Auth Token
// whose user is a Sandcastle Admin. Session cookies are not accepted here —
// the endpoints exist for the CLI, and the browser admin pages have their own
// forms.
func (h handler) requireAdminBearer(r *http.Request) (User, int, error) {
	user, err := h.requireBearerUser(r)
	if err != nil {
		return User{}, http.StatusUnauthorized, err
	}
	if !user.SandcastleAdmin {
		return User{}, http.StatusForbidden, fmt.Errorf("Sandcastle Admin access is required")
	}
	return user, 0, nil
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// publicDNSZoneErrorStatus maps a registry refusal to its §3.1 status.
func publicDNSZoneErrorStatus(err error) int {
	var zoneErr *PublicDNSZoneError
	if errors.As(err, &zoneErr) {
		switch zoneErr.Kind {
		case "exists", "overlap", "claimed":
			return http.StatusConflict
		case "not-found":
			return http.StatusNotFound
		case "rejected":
			return http.StatusUnprocessableEntity
		}
	}
	return http.StatusInternalServerError
}

func (h handler) zoneValidator() CloudflareZoneValidator {
	if h.cloudflareZones != nil {
		return h.cloudflareZones
	}
	return CloudflareZoneClient{}
}

func (h handler) domainClaimSource() ProjectDomainClaimSource {
	if h.projectDomainClaims != nil {
		return h.projectDomainClaims
	}
	return sqlProjectDomainClaims{db: h.db}
}

// publicDNSZonesAPI serves the collection: GET (list) and POST (add).
func (h handler) publicDNSZonesAPI(w http.ResponseWriter, r *http.Request) {
	user, status, err := h.requireAdminBearer(r)
	if err != nil {
		writeAPIError(w, status, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		zones, err := ListPublicDNSZones(r.Context(), h.db)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		claims := h.domainClaimSource()
		for i := range zones {
			refs, err := claims.ClaimsUnderZone(r.Context(), zones[i].Zone)
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			zones[i].Claims = len(refs)
		}
		writeJSON(w, http.StatusOK, PublicDNSZoneListResult{Zones: zones})
	case http.MethodPost:
		var request PublicDNSZoneRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		zone, err := NormalizePublicDNSZone(request.Zone)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if err := CheckPublicDNSZoneAddable(r.Context(), h.db, zone); err != nil {
			writeAPIError(w, publicDNSZoneErrorStatus(err), err)
			return
		}
		zoneID, err := h.zoneValidator().ValidateZoneToken(r.Context(), zone, request.Token)
		if err != nil {
			writeAPIError(w, cloudflareErrorStatus(err), err)
			return
		}
		if request.DryRun {
			writeJSON(w, http.StatusOK, PublicDNSZoneResult{Zone: zone, CloudflareZoneID: zoneID, DryRun: true})
			return
		}
		if err := AddPublicDNSZone(r.Context(), h.db, zone, zoneID, request.Token, user.UserKey); err != nil {
			writeAPIError(w, publicDNSZoneErrorStatus(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, PublicDNSZoneResult{Zone: zone, CloudflareZoneID: zoneID})
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// cloudflareErrorStatus: a rejection is the caller's problem (422); anything
// else means the Auth App could not reach Cloudflare (502).
func cloudflareErrorStatus(err error) int {
	var zoneErr *PublicDNSZoneError
	if errors.As(err, &zoneErr) && zoneErr.Kind == "rejected" {
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadGateway
}

// publicDNSZoneAPI serves one zone: DELETE /api/public-dns-zones/{zone} and
// PUT /api/public-dns-zones/{zone}/token.
func (h handler) publicDNSZoneAPI(w http.ResponseWriter, r *http.Request) {
	if _, status, err := h.requireAdminBearer(r); err != nil {
		writeAPIError(w, status, err)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/public-dns-zones/")
	rawZone, action, _ := strings.Cut(rest, "/")
	zone, err := NormalizePublicDNSZone(rawZone)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	switch {
	case r.Method == http.MethodPut && action == "token":
		var request PublicDNSZoneRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		if _, found, err := GetPublicDNSZone(r.Context(), h.db, zone); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		} else if !found {
			writeAPIError(w, http.StatusNotFound, &PublicDNSZoneError{Zone: zone, Kind: "not-found"})
			return
		}
		zoneID, err := h.zoneValidator().ValidateZoneToken(r.Context(), zone, request.Token)
		if err != nil {
			writeAPIError(w, cloudflareErrorStatus(err), err)
			return
		}
		if request.DryRun {
			writeJSON(w, http.StatusOK, PublicDNSZoneResult{Zone: zone, CloudflareZoneID: zoneID, DryRun: true})
			return
		}
		if err := SetPublicDNSZoneToken(r.Context(), h.db, zone, zoneID, request.Token); err != nil {
			writeAPIError(w, publicDNSZoneErrorStatus(err), err)
			return
		}
		writeJSON(w, http.StatusOK, PublicDNSZoneResult{Zone: zone, CloudflareZoneID: zoneID})
	case r.Method == http.MethodDelete && action == "":
		dryRun := r.URL.Query().Get("dryRun") == "1" || r.URL.Query().Get("dryRun") == "true"
		if dryRun {
			existing, found, err := GetPublicDNSZone(r.Context(), h.db, zone)
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			if !found {
				writeAPIError(w, http.StatusNotFound, &PublicDNSZoneError{Zone: zone, Kind: "not-found"})
				return
			}
			if err := checkPublicDNSZoneRemovable(r.Context(), h.domainClaimSource(), zone); err != nil {
				writeAPIError(w, publicDNSZoneErrorStatus(err), err)
				return
			}
			writeJSON(w, http.StatusOK, PublicDNSZoneResult{Zone: zone, CloudflareZoneID: existing.CloudflareZoneID, DryRun: true})
			return
		}
		if err := RemovePublicDNSZone(r.Context(), h.db, h.domainClaimSource(), zone); err != nil {
			writeAPIError(w, publicDNSZoneErrorStatus(err), err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}
