// Package tlssign is the sidecar's tenant-CA leaf signer. It runs on the tenant
// sidecar (which holds the tenant CA key) and hands out per-machine TLS leaf
// certificates and the CA certificate over plain HTTP on the tenant bridge.
//
// Trust model (ADR-0011): unauthenticated, reachable only on the tenant bridge.
// Any machine in the tenant may obtain a cert for any name in the tenant's zone
// — blast radius is one tenant. Requests for names outside the tenant's DNS
// suffix are refused, so the (unconstrained) tenant CA is not tricked into
// vouching for public names.
package tlssign

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/certs"
)

// Handler serves the signer endpoints:
//
//	GET /tls/ca                → the tenant CA certificate (PEM)
//	GET /tls/leaf?fqdn=<name>  → a leaf key+cert for [<name>, *.<name>] (JSON)
//	GET /healthz               → "ok"
//
// suffix is the tenant DNS suffix (e.g. "idefix"); leaf requests for names not
// ending in it are rejected. now defaults to time.Now when nil.
func Handler(caCertPEM, caKeyPEM []byte, suffix string, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	suffix = strings.Trim(strings.TrimSpace(strings.ToLower(suffix)), ".")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/tls/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caCertPEM)
	})
	mux.HandleFunc("/tls/leaf", func(w http.ResponseWriter, r *http.Request) {
		fqdn := strings.Trim(strings.TrimSpace(strings.ToLower(r.URL.Query().Get("fqdn"))), ".")
		if fqdn == "" {
			http.Error(w, "fqdn query parameter is required", http.StatusBadRequest)
			return
		}
		if !nameInZone(fqdn, suffix) {
			http.Error(w, "fqdn is outside this tenant's DNS zone", http.StatusForbidden)
			return
		}
		// The machine gets its own name plus a wildcard for its subdomains, so an
		// app that vhosts on Host (foo.<machine>...) is covered by one leaf.
		sans := []string{fqdn, "*." + fqdn}
		leaf, err := certs.IssueMachineLeaf(caCertPEM, caKeyPEM, fqdn, sans, now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(leafResponse{
			FQDN: fqdn,
			Cert: string(leaf.CertificatePEM),
			Key:  string(leaf.PrivateKeyPEM),
		})
	})
	return mux
}

type leafResponse struct {
	FQDN string `json:"fqdn"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// nameInZone reports whether fqdn belongs to the tenant suffix. An empty suffix
// disables the check (sign anything) — used only when no suffix is configured.
func nameInZone(fqdn, suffix string) bool {
	if suffix == "" {
		return true
	}
	return fqdn == suffix || strings.HasSuffix(fqdn, "."+suffix)
}
