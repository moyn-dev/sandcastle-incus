package authapp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
