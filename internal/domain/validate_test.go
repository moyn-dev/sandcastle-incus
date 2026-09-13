package domain

import "testing"

func TestValidateTenantDNSSuffixNormalizesLabel(t *testing.T) {
	suffix, err := ValidateTenantDNSSuffix("Acme.", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if suffix != "acme" {
		t.Fatalf("suffix = %q", suffix)
	}
}

func TestValidateTenantDNSSuffixRejectsMalformedSuffix(t *testing.T) {
	for _, candidate := range []string{"bad domain", "bad/name", "bad..name", "-bad.name", "bad-.name", "bad_name"} {
		t.Run(candidate, func(t *testing.T) {
			if _, err := ValidateTenantDNSSuffix(candidate, Policy{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateTenantDNSSuffixRejectsDeniedLabels(t *testing.T) {
	for _, candidate := range []string{"com", "local", "test", "alt"} {
		t.Run(candidate, func(t *testing.T) {
			if _, err := ValidateTenantDNSSuffix(candidate, Policy{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateTenantDNSSuffixAllowsExplicitLabSuffixes(t *testing.T) {
	suffix, err := ValidateTenantDNSSuffix("Test", Policy{
		AllowedSuffixes: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if suffix != "test" {
		t.Fatalf("suffix = %q", suffix)
	}
}

func TestValidateTenantDNSSuffixRejectsMalformedPolicySuffixes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy Policy
	}{
		{name: "allowed suffix", policy: Policy{AllowedSuffixes: []string{"bad suffix"}}},
		{name: "denied suffix", policy: Policy{DeniedSuffixes: []string{"bad/suffix"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateTenantDNSSuffix("acme", tc.policy); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNormalizePolicySuffix(t *testing.T) {
	suffix, err := NormalizePolicySuffix(".Lab.Example.")
	if err != nil {
		t.Fatal(err)
	}
	if suffix != "lab.example" {
		t.Fatalf("suffix = %q", suffix)
	}
	if _, err := NormalizePolicySuffix("bad_suffix"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateTenantDNSSuffixRejectsAdminDeniedSuffixes(t *testing.T) {
	_, err := ValidateTenantDNSSuffix("acme", Policy{
		DeniedSuffixes: []string{"acme"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeProjectDomain(t *testing.T) {
	if got, err := NormalizeProjectDomain(" Baum.Hase.DE. "); err != nil || got != "baum.hase.de" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", ".", "_x.hase.de", "a._x.hase.de", "*.hase.de", "-a.hase.de", "a-.hase.de", "a..hase.de", "ä.hase.de", "a/b.hase.de", "a b.hase.de"} {
		if _, err := NormalizeProjectDomain(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := NormalizeProjectDomain("_acme.hase.de"); err == nil || err.Error() != `invalid project domain "_acme.hase.de": labels may not start with "_"` {
		t.Fatalf("underscore label: %v", err)
	}
	// Single-label domains normalize (zone coverage is the Auth App's check).
	if got, err := NormalizeProjectDomain("hase"); err != nil || got != "hase" {
		t.Fatalf("single label: %q, %v", got, err)
	}
}
