package cli

import (
	"slices"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// TestApplyRemoteSwitch verifies that switching the active remote re-points the
// auth hostname, broker, and token to the target install (from the maps recorded
// at login) — the shared logic behind `sc remote switch` and `sc config set remote`.
func TestApplyRemoteSwitch(t *testing.T) {
	base := func() scconfig.SandcastleConfig {
		return scconfig.SandcastleConfig{
			Remote:       "idefix",
			AuthHostname: "https://idefix.thieso2.dev",
			AuthToken:    "idefix-tok",
			Broker:       "https://10.124.0.1:9443",
			Installs: map[string]string{
				"idefix": "https://idefix.thieso2.dev",
				"obelix": "https://obelix.thieso2.dev",
				"julius": "https://home.thieso2.dev",
			},
			Brokers:    map[string]string{"https://obelix.thieso2.dev": "https://10.123.0.1:9443"},
			AuthTokens: map[string]string{"https://obelix.thieso2.dev": "obelix-tok"},
		}
	}

	t.Run("re-points everything for a fully-recorded install", func(t *testing.T) {
		cfg := base()
		fx := applyRemoteSwitch(&cfg, "obelix")
		if cfg.Remote != "obelix" {
			t.Fatalf("Remote = %q, want obelix", cfg.Remote)
		}
		if cfg.AuthHostname != "https://obelix.thieso2.dev" || fx.AuthHostname != "https://obelix.thieso2.dev" {
			t.Fatalf("AuthHostname = %q (fx %q)", cfg.AuthHostname, fx.AuthHostname)
		}
		if cfg.Broker != "https://10.123.0.1:9443" || fx.Broker != "https://10.123.0.1:9443" {
			t.Fatalf("Broker = %q (fx %q)", cfg.Broker, fx.Broker)
		}
		if cfg.AuthToken != "obelix-tok" || !fx.TokenSynced {
			t.Fatalf("AuthToken = %q (synced %v)", cfg.AuthToken, fx.TokenSynced)
		}
	})

	t.Run("clears stale broker+token when nothing recorded for the target", func(t *testing.T) {
		cfg := base()
		fx := applyRemoteSwitch(&cfg, "julius") // in installs, but no broker/token recorded
		if cfg.Remote != "julius" || cfg.AuthHostname != "https://home.thieso2.dev" {
			t.Fatalf("switch to julius: remote=%q host=%q", cfg.Remote, cfg.AuthHostname)
		}
		if cfg.Broker != "" || !fx.BrokerCleared {
			t.Fatalf("stale broker not cleared: %q (cleared %v)", cfg.Broker, fx.BrokerCleared)
		}
		if cfg.AuthToken != "" || !fx.TokenCleared {
			t.Fatalf("stale token not cleared: %q (cleared %v)", cfg.AuthToken, fx.TokenCleared)
		}
	})

	t.Run("unknown remote sets name but leaves auth plane untouched", func(t *testing.T) {
		cfg := base()
		fx := applyRemoteSwitch(&cfg, "not-an-install")
		if cfg.Remote != "not-an-install" {
			t.Fatalf("Remote = %q", cfg.Remote)
		}
		if cfg.AuthHostname != "https://idefix.thieso2.dev" || fx.AuthHostname != "" {
			t.Fatalf("auth hostname changed for unknown remote: %q (fx %q)", cfg.AuthHostname, fx.AuthHostname)
		}
	})
}

// TestSandcastleRemoteRows filters system incus remotes out of `sc remote list`
// and keeps the Sandcastle installs (project-pinned or in the installs map), sorted.
func TestSandcastleRemoteRows(t *testing.T) {
	remotes := []localRemote{
		{Name: "local"},
		{Name: "images"},
		{Name: "obelix", Project: "obelix-thieso2-work"},
		{Name: "idefix", Project: "idefix-thieso2-home"},
		{Name: "julius"}, // no project pin, but recorded in installs
	}
	cfg := scconfig.SandcastleConfig{Installs: map[string]string{
		"julius": "https://home.thieso2.dev",
		"idefix": "https://idefix.thieso2.dev",
	}}
	rows := sandcastleRemoteRows(remotes, cfg)
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, r.Name)
	}
	if want := []string{"idefix", "julius", "obelix"}; !slices.Equal(got, want) {
		t.Fatalf("rows = %v, want %v (system remotes excluded, sorted)", got, want)
	}
	if rows[0].AuthHostname != "https://idefix.thieso2.dev" {
		t.Fatalf("idefix auth hostname = %q", rows[0].AuthHostname)
	}
	if !remoteNameKnown(remotes, "obelix") || remoteNameKnown(remotes, "nope") {
		t.Fatalf("remoteNameKnown wrong")
	}
}

// TestRepinProjectForRemote checks the short-project derivation used to re-pin
// the project when switching installs (obelix-thieso2-work -> work).
func TestRepinProjectForRemote(t *testing.T) {
	if got := shortProjectName("obelix-thieso2-work", "thieso2"); got != "work" {
		t.Fatalf("shortProjectName = %q, want work", got)
	}
	if got := shortProjectName("idefix-thieso2-home", "thieso2"); got != "home" {
		t.Fatalf("shortProjectName = %q, want home", got)
	}
	// A pin whose tenant segment doesn't match yields "" (leave the pin untouched).
	if got := shortProjectName("obelix-other-work", "thieso2"); got != "" {
		t.Fatalf("shortProjectName mismatch tenant = %q, want empty", got)
	}
}

// TestRebindForReferenceLeavesNonRemoteReferences ensures the universal
// [[remote:]project:]machine parsing is backward compatible: a reference whose
// leading segment is NOT an enrolled remote (project:machine, or a bare name) is
// returned untouched and the command config/remote is unchanged.
func TestRebindForReferenceLeavesNonRemoteReferences(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no enrolled remotes in a fresh home
	base := commandConfig{adminConfig: scconfig.Admin{Remote: "idefix"}}
	for _, ref := range []string{"work:test2", "test2", ""} {
		cfg, rest, restore, err := rebindForReference(base, ref)
		if err != nil {
			t.Fatalf("rebindForReference(%q) error: %v", ref, err)
		}
		restore()
		if rest != ref {
			t.Fatalf("rebindForReference(%q) rest = %q, want unchanged", ref, rest)
		}
		if cfg.adminConfig.Remote != "idefix" {
			t.Fatalf("remote changed to %q for %q", cfg.adminConfig.Remote, ref)
		}
	}
}

// TestSplitListReference covers `sc ls` addressing: "[remote:]project[:machine]".
// The two-part form is ambiguous, so a leading part counts as a remote only
// when it names an enrolled one — the same rule rebindForReference applies
// everywhere else. Here "obelix" is enrolled and "gbrain"/"g*" are not.
func TestSplitListReference(t *testing.T) {
	enrolled := func(name string) bool { return name == "obelix" }
	cases := []struct{ in, remote, project, machine string }{
		{"obelix:home", "obelix", "home", ""},
		{"obelix:", "obelix", "", ""},
		{"home", "", "home", ""},
		{"", "", "", ""},
		{" obelix : home ", "obelix", "home", ""},
		// Not an enrolled remote → project:machine.
		{"gbrain:web", "", "gbrain", "web"},
		{"gbrain:*", "", "gbrain", "*"},
		{"g*:d*", "", "g*", "d*"},
		// Three parts are unambiguously remote:project:machine.
		{"obelix:gbrain:d*", "obelix", "gbrain", "d*"},
	}
	for _, c := range cases {
		remote, project, machine := splitListReference(c.in, enrolled)
		if remote != c.remote || project != c.project || machine != c.machine {
			t.Fatalf("splitListReference(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.in, remote, project, machine, c.remote, c.project, c.machine)
		}
	}
}

// Two tenants of ONE install share an Auth Hostname, so the hostname-keyed
// maps hold only the LAST login's token/broker — switching between their
// remotes must prefer the per-remote records so the bearer identity follows
// the remote (#112).
func TestApplyRemoteSwitchPrefersPerRemoteIdentity(t *testing.T) {
	base := func() scconfig.SandcastleConfig {
		return scconfig.SandcastleConfig{
			Remote:       "octo",
			AuthHostname: "https://a.example.dev",
			AuthToken:    "octo-tok",
			Broker:       "https://10.61.1.1:9443",
			Installs: map[string]string{
				"castle": "https://a.example.dev",
				"octo":   "https://a.example.dev",
			},
			// hostname-keyed maps: last login (octo) won
			AuthTokens: map[string]string{"https://a.example.dev": "octo-tok"},
			Brokers:    map[string]string{"https://a.example.dev": "https://10.61.1.1:9443"},
			RemoteAuthTokens: map[string]string{
				"castle": "castle-tok",
				"octo":   "octo-tok",
			},
			RemoteBrokers: map[string]string{
				"castle": "https://10.61.0.1:9443",
				"octo":   "https://10.61.1.1:9443",
			},
		}
	}

	t.Run("switch to the other tenant of the same install swaps token+broker", func(t *testing.T) {
		cfg := base()
		fx := applyRemoteSwitch(&cfg, "castle")
		if cfg.AuthToken != "castle-tok" || !fx.TokenSynced {
			t.Fatalf("AuthToken = %q (synced %v), want castle-tok", cfg.AuthToken, fx.TokenSynced)
		}
		if cfg.Broker != "https://10.61.0.1:9443" || fx.Broker == "" {
			t.Fatalf("Broker = %q (fx %q), want castle's gateway", cfg.Broker, fx.Broker)
		}
		if cfg.AuthHostname != "https://a.example.dev" {
			t.Fatalf("AuthHostname = %q", cfg.AuthHostname)
		}
	})

	t.Run("falls back to the hostname-keyed maps for pre-migration logins", func(t *testing.T) {
		// Unambiguous: castle is the ONLY remote on its hostname, so the
		// hostname-keyed record is that tenant's own. (Two remotes on one
		// hostname is the ambiguous case — see
		// TestApplyRemoteSwitchAmbiguousFallbackClears.)
		cfg := base()
		cfg.RemoteAuthTokens = nil
		cfg.RemoteBrokers = nil
		delete(cfg.Installs, "octo")
		fx := applyRemoteSwitch(&cfg, "castle")
		_ = fx
		if cfg.AuthToken != "octo-tok" {
			t.Fatalf("AuthToken = %q, want the hostname-map fallback octo-tok", cfg.AuthToken)
		}
	})
}

// Login must record the token and broker under the enrolled remote's name (in
// addition to the Auth Hostname), or the per-remote preference has nothing to
// read (#112).
func TestSaveAuthDefaultsRecordsPerRemoteToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveAuthDefaults("https://a.example.dev", "castle-tok", "castle", "e2edns"); err != nil {
		t.Fatal(err)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.AuthTokenForRemote("castle"); got != "castle-tok" {
		t.Fatalf("AuthTokenForRemote(castle) = %q, want castle-tok", got)
	}
	if got := cfg.AuthTokenForAuthHostname("https://a.example.dev"); got != "castle-tok" {
		t.Fatalf("hostname map not written: %q", got)
	}
}

func TestSaveBrokerDefaultRecordsPerRemoteBroker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveBrokerDefault("https://a.example.dev", "https://10.61.0.1:9443", "castle"); err != nil {
		t.Fatal(err)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.BrokerForRemote("castle"); got != "https://10.61.0.1:9443" {
		t.Fatalf("BrokerForRemote(castle) = %q", got)
	}
}

// The route/project/token-backed commands resolve the TENANT from cfg.Tenant,
// so switching between two tenants of one install must re-point it too — the
// right token with the wrong tenant is still a 403 (#112, caught live).
func TestApplyRemoteSwitchRepointsTenant(t *testing.T) {
	cfg := scconfig.SandcastleConfig{
		Tenant:       "e2edns",
		Remote:       "castle",
		AuthHostname: "https://a.example.dev",
		Installs: map[string]string{
			"castle": "https://a.example.dev",
			"octo":   "https://a.example.dev",
		},
		RemoteTenants: map[string]string{"castle": "e2edns", "octo": "octocat"},
	}
	fx := applyRemoteSwitch(&cfg, "octo")
	if cfg.Tenant != "octocat" || fx.Tenant != "octocat" {
		t.Fatalf("Tenant = %q (fx %q), want octocat", cfg.Tenant, fx.Tenant)
	}
	// no record → leave the tenant alone (pre-migration logins)
	cfg.RemoteTenants = nil
	cfg.Tenant = "octocat"
	fx = applyRemoteSwitch(&cfg, "castle")
	if cfg.Tenant != "octocat" || fx.Tenant != "" {
		t.Fatalf("unrecorded remote must not change the tenant: %q (fx %q)", cfg.Tenant, fx.Tenant)
	}
}

func TestSaveAuthDefaultsRecordsPerRemoteTenant(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveAuthDefaults("https://a.example.dev", "tok", "castle", "e2edns"); err != nil {
		t.Fatal(err)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TenantForRemote("castle"); got != "e2edns" {
		t.Fatalf("TenantForRemote(castle) = %q, want e2edns", got)
	}
}

// Pre-migration configs have no per-remote records. For a SINGLE tenant per
// install the hostname-keyed fallback is correct — but when two remotes share
// the install's hostname the fallback would present the OTHER tenant's token
// (the very bug of #112), so the ambiguous case must clear instead of guess.
func TestApplyRemoteSwitchAmbiguousFallbackClears(t *testing.T) {
	base := func() scconfig.SandcastleConfig {
		return scconfig.SandcastleConfig{
			Remote:       "octo",
			AuthHostname: "https://a.example.dev",
			AuthToken:    "octo-tok",
			Broker:       "https://10.61.1.1:9443",
			Installs: map[string]string{
				"castle": "https://a.example.dev",
				"octo":   "https://a.example.dev",
			},
			AuthTokens: map[string]string{"https://a.example.dev": "octo-tok"},
			Brokers:    map[string]string{"https://a.example.dev": "https://10.61.1.1:9443"},
		}
	}

	t.Run("two remotes on one hostname, no per-remote record: clear, do not guess", func(t *testing.T) {
		cfg := base()
		fx := applyRemoteSwitch(&cfg, "castle")
		if cfg.AuthToken != "" || !fx.TokenCleared {
			t.Fatalf("ambiguous fallback must clear the token, got %q (cleared %v)", cfg.AuthToken, fx.TokenCleared)
		}
		if cfg.Broker != "" || !fx.BrokerCleared {
			t.Fatalf("ambiguous fallback must clear the broker, got %q (cleared %v)", cfg.Broker, fx.BrokerCleared)
		}
	})

	t.Run("single remote on the hostname keeps the fallback", func(t *testing.T) {
		cfg := base()
		delete(cfg.Installs, "castle")
		cfg.Remote = "castle"
		fx := applyRemoteSwitch(&cfg, "octo")
		if cfg.AuthToken != "octo-tok" || fx.TokenCleared {
			t.Fatalf("unambiguous fallback must keep working, got %q (cleared %v)", cfg.AuthToken, fx.TokenCleared)
		}
	})
}
