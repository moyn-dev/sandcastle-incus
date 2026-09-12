package cli

import (
	"strings"
	"testing"
)

func TestResolveConnectTarget(t *testing.T) {
	// ADR-0021: one remote per install, named by the DNS suffix.
	enrolled := map[string]bool{"obelix": true}
	exists := func(name string) bool { return enrolled[name] }

	t.Run("no suffix is same-install (no switch)", func(t *testing.T) {
		got, err := resolveConnectTarget("", "castle", exists)
		if err != nil || got != "" {
			t.Fatalf("got %q, %v; want no switch", got, err)
		}
	})

	t.Run("suffix equal to current install is no switch", func(t *testing.T) {
		got, err := resolveConnectTarget("castle", "castle", exists)
		if err != nil || got != "" {
			t.Fatalf("got %q, %v; want no switch", got, err)
		}
	})

	t.Run("cross-install with an enrolled remote returns the install remote", func(t *testing.T) {
		got, err := resolveConnectTarget("obelix", "castle", exists)
		if err != nil {
			t.Fatal(err)
		}
		if got != "obelix" {
			t.Fatalf("switchTo = %q, want obelix", got)
		}
	})

	t.Run("install never logged into -> login guidance", func(t *testing.T) {
		_, err := resolveConnectTarget("newbox", "castle", exists)
		if err == nil {
			t.Fatal("expected an error for an unknown install")
		}
		for _, want := range []string{"newbox", "sc login"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q missing %q", err.Error(), want)
			}
		}
	})

	t.Run("tenantFromPinnedProject recovers the tenant", func(t *testing.T) {
		cases := []struct{ pinned, project, want string }{
			{"sc2-thieso2-web", "web", "thieso2"},
			{"sc2-e2edns-default", "default", "e2edns"},
			{"id-e2edns-default", "default", "e2edns"}, // non-default install prefix
			{"sc2-foo-bar-web", "web", "foo-bar"},      // dashed tenant
			{"sc2-t-web-app", "web-app", "t"},          // dashed project
			{"sc2-thieso2-web", "other", ""},           // project mismatch -> ""
			{"", "web", ""},
		}
		for _, c := range cases {
			if got := tenantFromPinnedProject(c.pinned, c.project); got != c.want {
				t.Errorf("tenantFromPinnedProject(%q,%q) = %q, want %q", c.pinned, c.project, got, c.want)
			}
		}
	})
}
