package domain

import "testing"

func TestCoveredByProjectCertificate(t *testing.T) {
	for _, tt := range []struct {
		name, host string
		want       bool
	}{
		{"derived", "x1.tod0s.tc42.uk", true},
		{"alias", "admin-x1.tod0s.tc42.uk", true},
		{"two labels", "admin.x1.tod0s.tc42.uk", false},
		{"outside", "web12.tc42.uk", false},
		{"zone apex", "tc42.uk", false},
		{"domain apex", "tod0s.tc42.uk", false},
		{"machine wildcard", "*.x1.tod0s.tc42.uk", false},
		{"normalization", " Admin-X1.TOD0S.TC42.UK. ", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := CoveredByProjectCertificate(tt.host, "tod0s.tc42.uk"); got != tt.want {
				t.Fatalf("%s: %v", tt.host, got)
			}
		})
	}
}
