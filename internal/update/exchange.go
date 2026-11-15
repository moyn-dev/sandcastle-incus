package update

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Version exchange (#124 §6): the CLI sends its version on every
// auth-app/broker call; responses carry the appliance version and an
// optional minimum CLI version. Mismatch is a one-line warning, never a
// block — unless a known-breaking release sets MinCLIVersion.
const (
	HeaderCLIVersion    = "X-Sandcastle-CLI-Version"
	HeaderVersion       = "X-Sandcastle-Version"
	HeaderMinCLIVersion = "X-Sandcastle-Min-CLI-Version"
)

// MinCLIVersion is normally empty. A known-breaking release sets it to the
// oldest CLI version its protocol still supports; older CLIs then get a
// clean "run `sc update`" refusal instead of protocol errors. There is
// deliberately no per-release compat matrix beyond this one value.
const MinCLIVersion = ""

// NormalizeTag returns the version with a "v" prefix (the release-tag
// form), or "" for empty input. The one normalizer for version tags —
// stamping, headers, and display all share it.
func NormalizeTag(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// ApplyVersionHeaders stamps a service response with the appliance version
// and, when set, the minimum CLI version.
func ApplyVersionHeaders(h http.Header, serverVersion, minCLI string) {
	if v := NormalizeTag(serverVersion); v != "" {
		h.Set(HeaderVersion, v)
	}
	if m := NormalizeTag(minCLI); m != "" {
		h.Set(HeaderMinCLIVersion, m)
	}
}

// RefuseCLI decides the server-side skew gate: refuse only when a minimum
// is set and the calling CLI is older (a missing header means a CLI from
// before the version exchange existed — older than any minimum). Dev builds
// are exempt.
func RefuseCLI(cliHeader, minCLI string) bool {
	if NormalizeTag(minCLI) == "" {
		return false
	}
	if strings.TrimSpace(cliHeader) == "" {
		return true
	}
	if IsDevBuild(cliHeader) {
		return false
	}
	return IsNewer(minCLI, cliHeader)
}

// RefusalMessage is the clean refusal body sent with HTTP 426.
func RefusalMessage(minCLI string) string {
	return fmt.Sprintf("your CLI is too old for this deployment (minimum %s) — run `sc update`", NormalizeTag(minCLI))
}

// Exchange carries the client half of the version exchange: it stamps
// outgoing requests with the CLI version and remembers the appliance
// version (and minimum) seen on responses, so the CLI can print one skew
// warning after its normal output.
type Exchange struct {
	mu               sync.Mutex
	cliVersion       string
	applianceVersion string
	minCLI           string
	sidecarVersion   string
}

// DefaultExchange is the process-wide exchange used by the CLI's HTTP
// clients.
var DefaultExchange = &Exchange{}

// SetCLIVersion records the running CLI's version for outgoing requests.
func (e *Exchange) SetCLIVersion(v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cliVersion = NormalizeTag(v)
}

// CLIVersion returns the recorded CLI version (normalized).
func (e *Exchange) CLIVersion() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cliVersion
}

// Observed returns the appliance version and minimum CLI version seen on
// responses so far ("" when none).
func (e *Exchange) Observed() (applianceVersion, minCLI string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applianceVersion, e.minCLI
}

// RecordResponse captures version headers from a service response.
func (e *Exchange) RecordResponse(h http.Header) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v := h.Get(HeaderVersion); v != "" {
		e.applianceVersion = v
	}
	if m := h.Get(HeaderMinCLIVersion); m != "" {
		e.minCLI = m
	}
}

// RecordSidecarVersion captures the tenant sidecar's version (seen on
// sidecar signer responses — the §2 sidecar notice rides on this).
func (e *Exchange) RecordSidecarVersion(v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v != "" {
		e.sidecarVersion = NormalizeTag(v)
	}
}

// SidecarVersion returns the sidecar version observed this run ("" if none).
func (e *Exchange) SidecarVersion() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sidecarVersion
}

type exchangeTransport struct {
	base     http.RoundTripper
	exchange *Exchange
}

// WrapTransport returns a RoundTripper that performs the version exchange
// on every request through it. base nil means http.DefaultTransport.
func (e *Exchange) WrapTransport(base http.RoundTripper) http.RoundTripper {
	return exchangeTransport{base: base, exchange: e}
}

func (t exchangeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if v := t.exchange.CLIVersion(); v != "" {
		req.Header.Set(HeaderCLIVersion, v)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if resp != nil {
		t.exchange.RecordResponse(resp.Header)
	}
	return resp, err
}

// SkewWarning returns the one-line CLI↔deployment mismatch warning, or
// ok=false when versions match, nothing was observed, the CLI is a dev
// build, or the update-notifier opt-out is set — the env silences EVERY
// passive stderr notice (#124 §2), this one included (caught live in the
// Phase 10e validation: the skew note leaked through the opt-out).
func SkewWarning(cliVersion, applianceVersion string) (string, bool) {
	if os.Getenv(NoUpdateNotifierEnv) != "" {
		return "", false
	}
	cli := NormalizeTag(cliVersion)
	appliance := NormalizeTag(applianceVersion)
	if cli == "" || appliance == "" || IsDevBuild(cli) || cli == appliance {
		return "", false
	}
	switch {
	case IsNewer(appliance, cli):
		return fmt.Sprintf("note: CLI %s is older than deployment %s — run `sc update`", cli, appliance), true
	case IsNewer(cli, appliance):
		// `sc update` cannot raise the deployment, so pointing at it here
		// sends the user to a command that reports everything current.
		return fmt.Sprintf("note: deployment %s is older than CLI %s — an admin updates it with `sc-adm update`", appliance, cli), true
	}
	return fmt.Sprintf("note: CLI %s and deployment %s differ — `sc update` shows what is outdated", cli, appliance), true
}
