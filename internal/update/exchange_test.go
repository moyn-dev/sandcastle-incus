package update

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefuseCLI(t *testing.T) {
	cases := []struct {
		name      string
		cliHeader string
		minCLI    string
		want      bool
	}{
		{"no min set", "v0.1.0", "", false},
		{"cli current", "v0.3.0", "v0.3.0", false},
		{"cli newer", "v0.4.0", "v0.3.0", false},
		{"cli too old", "v0.2.0", "v0.3.0", true},
		{"pre-feature cli (no header)", "", "v0.3.0", true},
		{"dev build exempt", "0.0.0-dev", "v0.3.0", false},
	}
	for _, c := range cases {
		if got := RefuseCLI(c.cliHeader, c.minCLI); got != c.want {
			t.Errorf("%s: RefuseCLI(%q, %q) = %v, want %v", c.name, c.cliHeader, c.minCLI, got, c.want)
		}
	}
}

func TestExchangeTransportSendsAndObserves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderCLIVersion); got != "v0.1.0" {
			t.Errorf("request %s = %q", HeaderCLIVersion, got)
		}
		ApplyVersionHeaders(w.Header(), "0.2.0", "v0.1.5")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ex := &Exchange{}
	ex.SetCLIVersion("v0.1.0")
	client := &http.Client{Transport: ex.WrapTransport(nil)}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	appliance, minCLI := ex.Observed()
	if appliance != "v0.2.0" || minCLI != "v0.1.5" {
		t.Fatalf("Observed = %q, %q", appliance, minCLI)
	}
}

func TestSkewWarning(t *testing.T) {
	cases := []struct {
		name      string
		cli, appl string
		wantWarn  bool
		wantFix   string
	}{
		{"match", "v0.2.0", "v0.2.0", false, ""},
		{"cli behind", "v0.1.0", "v0.2.0", true, "run `sc update`"},
		{"cli ahead", "v0.3.0", "v0.2.0", true, "`sc-adm update`"},
		{"dev cli exempt", "0.0.0-dev", "v0.2.0", false, ""},
		{"no appliance observed", "v0.1.0", "", false, ""},
	}
	for _, c := range cases {
		msg, warn := SkewWarning(c.cli, c.appl)
		if warn != c.wantWarn {
			t.Errorf("%s: SkewWarning(%q, %q) = %v, want %v", c.name, c.cli, c.appl, warn, c.wantWarn)
		}
		if warn && !strings.Contains(msg, c.wantFix) {
			t.Errorf("%s: warning %q does not name %q", c.name, msg, c.wantFix)
		}
	}
}

// The opt-out env silences EVERY passive notice (#124 §2) — the skew note
// included. Caught live in Phase 10e: the note leaked through the opt-out.
func TestSkewWarningRespectsOptOut(t *testing.T) {
	t.Setenv(NoUpdateNotifierEnv, "1")
	if _, warn := SkewWarning("v0.1.0", "v0.2.0"); warn {
		t.Fatal("SkewWarning must be silent under SANDCASTLE_NO_UPDATE_NOTIFIER")
	}
}
