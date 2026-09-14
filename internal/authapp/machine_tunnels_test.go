package authapp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMachineTunnelDNS(t *testing.T) {
	tests := []struct {
		name     string
		records  string
		wantPost bool
		wantErr  string
	}{
		{name: "creates an absent record", records: `[]`, wantPost: true},
		{name: "reuses its own CNAME", records: `[{"type":"CNAME","content":"tunnel.cfargotunnel.com."}]`},
		{name: "refuses another record", records: `[{"type":"A","content":"192.0.2.1"}]`, wantErr: `"app.example.com" already has a DNS record; remove it before publishing a Machine Tunnel`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			posted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					fmt.Fprintf(w, `{"success":true,"result":%s}`, test.records)
				case http.MethodPost:
					posted = true
					fmt.Fprint(w, `{"success":true,"result":{}}`)
				default:
					t.Fatalf("unexpected method %s", r.Method)
				}
			}))
			defer server.Close()

			err := (cf{token: "test", baseURL: server.URL}).dns(context.Background(), "zone", "app.example.com", "tunnel.cfargotunnel.com")
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("dns error = %v, want %q", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if posted != test.wantPost {
				t.Fatalf("POST = %t, want %t", posted, test.wantPost)
			}
		})
	}
}

func TestMachineTunnelUnpublishRemovesOnlyOwnedCloudflareResources(t *testing.T) {
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/accounts/account/cfd_tunnel":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"tunnel"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone/dns_records":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"ours","type":"CNAME","content":"tunnel.cfargotunnel.com."},{"id":"theirs","type":"CNAME","content":"other.cfargotunnel.com"}]}`)
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			fmt.Fprint(w, `{"success":true,"result":{}}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	err := (cf{token: "test", baseURL: server.URL}).unprovisionTunnel(context.Background(), "account", "zone", "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(deleted), "[/zones/zone/dns_records/ours /accounts/account/cfd_tunnel/tunnel]"; got != want {
		t.Fatalf("deleted = %s, want %s", got, want)
	}
}

func TestMachineTunnelUnpublishIsIdempotentWhenTunnelIsAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/accounts/account/cfd_tunnel" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	defer server.Close()

	if err := (cf{token: "test", baseURL: server.URL}).unprovisionTunnel(context.Background(), "account", "zone", "app.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestMachineTunnelAPIUnpublishUsesConfiguredCloudflareEndpoint(t *testing.T) {
	var deleted []string
	cloudflare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/cf-hase.de":
			fmt.Fprint(w, `{"success":true,"result":{"account":{"id":"account"}}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/accounts/account/cfd_tunnel":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"tunnel"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/cf-hase.de/dns_records":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"record","type":"CNAME","content":"tunnel.cfargotunnel.com"}]}`)
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			fmt.Fprint(w, `{"success":true,"result":{}}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer cloudflare.Close()

	_, db, token, _ := projectDomainTestHandler(t, nil)
	if _, _, err := ClaimMachineTunnelPublication(context.Background(), db, MachineTunnelPublication{Hostname: "app.hase.de", Tenant: "acme", Project: "web", Machine: "app", Port: 3000}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{CloudflareBaseURL: cloudflare.URL})
	req := httptest.NewRequest(http.MethodDelete, "/api/machine-tunnels", strings.NewReader(`{"project":"web","machine":"app","hostname":"app.hase.de"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unpublish = %d %s", res.Code, res.Body.String())
	}
	if got, want := fmt.Sprint(deleted), "[/zones/cf-hase.de/dns_records/record /accounts/account/cfd_tunnel/tunnel]"; got != want {
		t.Fatalf("deleted = %s, want %s", got, want)
	}
	if _, found, err := GetMachineTunnelPublication(context.Background(), db, "app.hase.de"); err != nil || found {
		t.Fatalf("publication after unpublish = found %t, err %v", found, err)
	}
	if err := RequireMachinePublicationHostnameAvailable(context.Background(), db, "app.hase.de"); err == nil {
		t.Fatal("missing DNS propagation cooldown after unpublish")
	}
}

func TestMachineTunnelDNSPreflightRefusesForeignRecordWithoutMutation(t *testing.T) {
	var mutations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations = append(mutations, r.Method+" "+r.URL.Path)
		}
		switch r.URL.Path {
		case "/zones/zone":
			fmt.Fprint(w, `{"success":true,"result":{"account":{"id":"account"}}}`)
		case "/accounts/account/cfd_tunnel":
			fmt.Fprint(w, `{"success":true,"result":[]}`)
		case "/zones/zone/dns_records":
			fmt.Fprint(w, `{"success":true,"result":[{"type":"A","content":"192.0.2.1"}]}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	err := (cf{token: "test", baseURL: server.URL}).tunnelDNSPreflight(context.Background(), "zone", "app.example.com")
	if err == nil || !strings.Contains(err.Error(), "already has a DNS record") {
		t.Fatalf("preflight = %v", err)
	}
	if len(mutations) != 0 {
		t.Fatalf("mutations before conflict = %v", mutations)
	}
}

func TestMachineTunnelPreflightRefusesMachineHostnameAndRoute(t *testing.T) {
	_, db, _, _ := projectDomainTestHandler(t, nil)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO machine_hostnames (hostname, tenant, project, machine, zone, user_key, created_at) VALUES ('app.hase.de', 'acme', 'web', 'app', 'hase.de', '', '')`); err != nil {
		t.Fatal(err)
	}
	h := handler{db: db}
	if err := h.preflightMachineTunnel(ctx, "app.hase.de", "", ""); err == nil || !strings.Contains(err.Error(), "Machine Public Hostname") {
		t.Fatalf("hostname preflight = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM machine_hostnames`); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "app.hase.de", Tenant: "acme", Project: "web", Machine: "app", BackendPort: 3000}); err != nil {
		t.Fatal(err)
	}
	if err := h.preflightMachineTunnel(ctx, "app.hase.de", "", ""); err == nil || !strings.Contains(err.Error(), "Public Route") {
		t.Fatalf("route preflight = %v", err)
	}
}

func TestMachineTunnelAPIUnpublishRefusesAnotherMachine(t *testing.T) {
	_, db, token, _ := projectDomainTestHandler(t, nil)
	if _, _, err := ClaimMachineTunnelPublication(context.Background(), db, MachineTunnelPublication{Hostname: "app.hase.de", Tenant: "acme", Project: "web", Machine: "owner", Port: 3000}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{})
	req := httptest.NewRequest(http.MethodDelete, "/api/machine-tunnels", strings.NewReader(`{"project":"web","machine":"other","hostname":"app.hase.de"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "not published by this Machine") {
		t.Fatalf("unpublish = %d %s", res.Code, res.Body.String())
	}
}
