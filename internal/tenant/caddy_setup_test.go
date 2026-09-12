package tenant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Caddyfile caddy-setup writes must be, byte for byte, the one machines
// ran before zone mode existed (ADR-0027 §5.2: "handlers byte-identical").
// This is the heredoc from the pre-slice-4 script, verbatim.
const goldenCaddyfileHeredoc = `cat > /etc/caddy/Caddyfile <<EOF
$FQDN, *.$FQDN {
    tls /etc/sandcastle/tls/cert.pem /etc/sandcastle/tls/key.pem
    redir /_h /_h/
    redir /_w /_w/
    handle_path /_h/* {
        root * $HOME
        file_server browse
    }
    handle_path /_w/* {
        root * /workspace
        file_server browse
    }
    handle {
        reverse_proxy localhost:3000
    }
}
EOF
`

func TestCaddySetupScriptCaddyfileUnchanged(t *testing.T) {
	if !strings.HasSuffix(caddyfileHeredoc, goldenCaddyfileHeredoc) {
		t.Fatalf("Caddyfile heredoc drifted from the golden:\n%s", caddyfileHeredoc)
	}
	if !strings.Contains(caddyIngressSetupScript, goldenCaddyfileHeredoc) {
		t.Fatalf("caddy-setup no longer writes the golden Caddyfile:\n%s", caddyIngressSetupScript)
	}
	if strings.Count(caddyIngressSetupScript, "cat > /etc/caddy/Caddyfile") != 1 {
		t.Fatalf("caddy-setup must write exactly one Caddyfile, for both modes")
	}
}

// Text-level contract of the mode-aware script (spec §5.2–§5.4): the private
// branch is today's leaf fetch, the zone branch skips it, both trust the
// Tenant CA, the drop-in and the marker are exactly the spec's.
func TestCaddySetupScriptModeContract(t *testing.T) {
	script := caddyIngressSetupScript
	for _, want := range []string{
		"MODE=\"${MODE:-private}\"\n",
		"curl -fsS \"$SIGNER/tls/ca\" -o /usr/local/share/ca-certificates/sandcastle-tenant.crt && update-ca-certificates || true\n",
		"if [ \"$MODE\" = private ]; then\n",
		"  curl -fsS \"$SIGNER/tls/leaf?fqdn=$FQDN\" | python3 -c 'import json,sys;d=json.load(sys.stdin);open(\"/etc/sandcastle/tls/cert.pem\",\"w\").write(d[\"cert\"]);open(\"/etc/sandcastle/tls/key.pem\",\"w\").write(d[\"key\"])'\n  chmod 600 /etc/sandcastle/tls/key.pem\nfi\n",
		"printf '%s\\n' '[Service]' 'User=root' 'Group=root' 'AmbientCapabilities=' > /etc/systemd/system/caddy.service.d/override.conf\n",
		"if [ \"$MODE\" = zone ]; then\n",
		"  printf '%s\\n' '[Unit]' 'ConditionPathExists=/etc/sandcastle/tls/cert.pem' 'ConditionPathExists=/etc/sandcastle/tls/key.pem' > " + CaddyZoneDropInPath + "\n",
		"systemctl daemon-reload\nsystemctl enable caddy\n",
		"printf 'MODE=%s\\nFQDN=%s\\n' \"$MODE\" \"$FQDN\" > " + CaddySetupMarkerPath + "\n",
		"  systemctl start caddy || true",
		"else\n  systemctl restart caddy\nfi\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("caddy-setup missing %q:\n%s", want, script)
		}
	}
	// Order: Caddyfile, override, (zone drop-in), daemon-reload, enable,
	// marker, start/restart — the marker asserts everything before it.
	order := []string{"cat > /etc/caddy/Caddyfile", "override.conf", "sandcastle-zone.conf", "systemctl daemon-reload", "systemctl enable caddy", "> " + CaddySetupMarkerPath, "systemctl start caddy", "systemctl restart caddy"}
	last := -1
	for _, step := range order {
		idx := strings.Index(script, step)
		if idx <= last {
			t.Fatalf("caddy-setup step %q out of order (index %d after %d)", step, idx, last)
		}
		last = idx
	}
}

// caddySetupRun executes the real caddy-setup script under bash against a
// throwaway root, with the tools it calls stubbed on PATH. The absolute
// paths the script writes are rebased under root by textual substitution, so
// what lands on disk is what a machine would get — same Caddyfile, same
// marker, same drop-in — and the systemctl calls are recorded.
type caddySetupRun struct {
	root string
	log  string
}

func runCaddySetup(t *testing.T, machineEnv string) caddySetupRun {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "calls.log")
	stub := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \""+name+" $*\" >> \"$SC_TEST_LOG\"\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("caddy", "exit 0\n") // "already installed": skips the apt block
	stub("systemctl", "exit 0\n")
	stub("update-ca-certificates", "exit 0\n")
	stub("apt-get", "echo 'apt-get must not run when caddy is installed' >&2; exit 1\n")
	stub("curl", `case "$*" in
  *"/tls/leaf"*) printf '{"cert":"LEAF-CERT","key":"LEAF-KEY"}' ;;
  *"/tls/ca"*) out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done; printf 'TENANT-CA\n' > "$out" ;;
  *) exit 22 ;;
esac
`)
	if err := os.MkdirAll(filepath.Join(root, "etc", "sandcastle"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "sandcastle", "machine.env"), []byte(machineEnv), 0o644); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(caddyIngressSetupScript, "/etc/", root+"/etc/")
	script = strings.ReplaceAll(script, "/usr/local/share/", root+"/usr/local/share/")
	scriptPath := filepath.Join(root, "caddy-setup")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, scriptPath)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SC_TEST_LOG="+logPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("caddy-setup failed: %v\n%s", err, out)
	}
	calls, _ := os.ReadFile(logPath)
	return caddySetupRun{root: root, log: string(calls)}
}

func (r caddySetupRun) read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.root, path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// rebased is content as the rebased script writes it: every absolute /etc
// path inside a written file carries the throwaway root too.
func (r caddySetupRun) rebased(content string) string {
	return strings.ReplaceAll(content, "/etc/", r.root+"/etc/")
}

func (r caddySetupRun) absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(r.root, path)); err == nil {
		t.Fatalf("%s exists, want absent", path)
	}
}

// What a private-mode machine gets: today's behaviour. No MODE in machine.env
// (pre-feature machines), the leaf fetched from the signer, the golden
// Caddyfile, no zone drop-in, a private marker, and Caddy restarted.
func TestCaddySetupPrivateMode(t *testing.T) {
	run := runCaddySetup(t, "FQDN=web.zp.acme\nSIGNER=http://10.0.0.3:9443\nHOME=/home/dev\n")
	if got := run.read(t, "etc/caddy/Caddyfile"); got != run.rebased(renderGoldenCaddyfile("web.zp.acme", "/home/dev")) {
		t.Fatalf("private Caddyfile:\n%s", got)
	}
	if got := run.read(t, "etc/sandcastle/tls/cert.pem"); got != "LEAF-CERT" {
		t.Fatalf("leaf cert = %q", got)
	}
	if got := run.read(t, "etc/sandcastle/tls/key.pem"); got != "LEAF-KEY" {
		t.Fatalf("leaf key = %q", got)
	}
	if got := run.read(t, "usr/local/share/ca-certificates/sandcastle-tenant.crt"); got != "TENANT-CA\n" {
		t.Fatalf("tenant CA = %q", got)
	}
	if got := run.read(t, "etc/systemd/system/caddy.service.d/override.conf"); got != "[Service]\nUser=root\nGroup=root\nAmbientCapabilities=\n" {
		t.Fatalf("override.conf = %q", got)
	}
	run.absent(t, "etc/systemd/system/caddy.service.d/sandcastle-zone.conf")
	if got := run.read(t, "etc/sandcastle/caddy.ready"); got != "MODE=private\nFQDN=web.zp.acme\n" {
		t.Fatalf("marker = %q", got)
	}
	wantCalls := "curl -fsS http://10.0.0.3:9443/tls/ca -o " + run.root + "/usr/local/share/ca-certificates/sandcastle-tenant.crt\nupdate-ca-certificates \ncurl -fsS http://10.0.0.3:9443/tls/leaf?fqdn=web.zp.acme\nsystemctl daemon-reload\nsystemctl enable caddy\nsystemctl restart caddy\n"
	if run.log != wantCalls {
		t.Fatalf("calls:\n%s\nwant:\n%s", run.log, wantCalls)
	}
}

// What a zone-mode machine gets (spec §5.2–§5.4): the Tenant CA is still
// trusted, the leaf is NOT fetched, the same Caddyfile names the public
// hostname, the drop-in conditions Caddy's start on the pushed files, the
// marker names the mode and FQDN, and Caddy is enabled and started (a no-op
// start until the condition is met) rather than restarted.
func TestCaddySetupZoneMode(t *testing.T) {
	run := runCaddySetup(t, "FQDN=web.baum.hase.de\nMODE=zone\nSIGNER=http://10.0.0.3:9443\nHOME=/home/dev\n")
	if got := run.read(t, "etc/caddy/Caddyfile"); got != run.rebased(renderGoldenCaddyfile("web.baum.hase.de", "/home/dev")) {
		t.Fatalf("zone Caddyfile:\n%s", got)
	}
	run.absent(t, "etc/sandcastle/tls/cert.pem")
	run.absent(t, "etc/sandcastle/tls/key.pem")
	if got := run.read(t, "usr/local/share/ca-certificates/sandcastle-tenant.crt"); got != "TENANT-CA\n" {
		t.Fatalf("tenant CA = %q", got)
	}
	if got := run.read(t, "etc/systemd/system/caddy.service.d/sandcastle-zone.conf"); got != run.rebased("[Unit]\nConditionPathExists=/etc/sandcastle/tls/cert.pem\nConditionPathExists=/etc/sandcastle/tls/key.pem\n") {
		t.Fatalf("zone drop-in = %q", got)
	}
	marker := run.read(t, "etc/sandcastle/caddy.ready")
	if marker != "MODE=zone\nFQDN=web.baum.hase.de\n" {
		t.Fatalf("marker = %q", marker)
	}
	parsed, err := ParseCaddySetupMarker(marker)
	if err != nil || !parsed.ReadyFor("web.baum.hase.de") {
		t.Fatalf("marker does not clear the push gate: %+v, %v", parsed, err)
	}
	if strings.Contains(run.log, "/tls/leaf") {
		t.Fatalf("zone mode fetched a leaf from the signer:\n%s", run.log)
	}
	wantCalls := "curl -fsS http://10.0.0.3:9443/tls/ca -o " + run.root + "/usr/local/share/ca-certificates/sandcastle-tenant.crt\nupdate-ca-certificates \nsystemctl daemon-reload\nsystemctl enable caddy\nsystemctl start caddy\n"
	if run.log != wantCalls {
		t.Fatalf("calls:\n%s\nwant:\n%s", run.log, wantCalls)
	}
}

// renderGoldenCaddyfile is the Caddyfile a machine ends up with, with the two
// shell variables substituted — what curl/browsers actually hit.
func renderGoldenCaddyfile(fqdn, home string) string {
	return strings.ReplaceAll(strings.ReplaceAll(goldenCaddyfileRendered, "{FQDN}", fqdn), "{HOME}", home)
}

const goldenCaddyfileRendered = `{FQDN}, *.{FQDN} {
    tls /etc/sandcastle/tls/cert.pem /etc/sandcastle/tls/key.pem
    redir /_h /_h/
    redir /_w /_w/
    handle_path /_h/* {
        root * {HOME}
        file_server browse
    }
    handle_path /_w/* {
        root * /workspace
        file_server browse
    }
    handle {
        reverse_proxy localhost:3000
    }
}
`

func TestParseCaddySetupMarker(t *testing.T) {
	marker, err := ParseCaddySetupMarker("MODE=zone\nFQDN=web.baum.hase.de\n")
	if err != nil || marker != (CaddySetupMarker{Mode: "zone", FQDN: "web.baum.hase.de"}) {
		t.Fatalf("parse = %+v, %v", marker, err)
	}
	if !marker.ReadyFor("web.baum.hase.de") || !marker.ReadyFor("WEB.baum.hase.de.") {
		t.Fatalf("zone marker must clear the gate for its own FQDN")
	}
	if marker.ReadyFor("other.baum.hase.de") || marker.ReadyFor("") {
		t.Fatalf("zone marker must not clear the gate for another name")
	}
	private, err := ParseCaddySetupMarker("# written by caddy-setup\n\nMODE=private\nFQDN=web.zp.acme\n")
	if err != nil || private.Mode != "private" || private.FQDN != "web.zp.acme" {
		t.Fatalf("private parse = %+v, %v", private, err)
	}
	if private.ReadyFor("web.zp.acme") {
		t.Fatalf("a private marker is 'no marker' for the push gate")
	}
	for _, bad := range []string{"", "FQDN=web.baum.hase.de\n", "MODE zone\n", "garbage\nMODE=zone\n"} {
		if _, err := ParseCaddySetupMarker(bad); err == nil {
			t.Fatalf("ParseCaddySetupMarker(%q) accepted", bad)
		}
	}
}

// The bare document tracks the profile's Naming Mode (spec §5.1): private
// stays byte-identical to what --bare always rendered; zone adds MODE=zone in
// the same place the profile puts it.
func TestV2BareUserDataForMode(t *testing.T) {
	legacy := V2BareUserData("zp.acme", "http://10.0.0.3:9443")
	for _, mode := range []string{"", "private"} {
		if got := V2BareUserDataForMode("zp.acme", "http://10.0.0.3:9443", mode); got != legacy {
			t.Fatalf("mode %q drifted from the legacy bare document:\n%s", mode, got)
		}
	}
	if strings.Contains(legacy, "MODE=") {
		t.Fatalf("private bare document carries a MODE line:\n%s", legacy)
	}
	zone := V2BareUserDataForMode("baum.hase.de", "http://10.0.0.3:9443", "zone")
	wantEnv := "  - path: /etc/sandcastle/machine.env\n    permissions: '0644'\n    content: |\n      FQDN={{ v1.local_hostname }}.baum.hase.de\n      MODE=zone\n      SIGNER=http://10.0.0.3:9443\n      HOME=" + BareMachineHome + "\n"
	if !strings.Contains(zone, wantEnv) {
		t.Fatalf("zone bare machine.env:\n%s", zone)
	}
	if !strings.Contains(zone, "fqdn: {{ v1.local_hostname }}.baum.hase.de\n") {
		t.Fatalf("zone bare fqdn:\n%s", zone)
	}
	normalized := strings.ReplaceAll(strings.ReplaceAll(zone, ".baum.hase.de", ".zp.acme"), "      MODE=zone\n", "")
	if normalized != legacy {
		t.Fatalf("zone bare document differs beyond identity + MODE:\n%s\n---\n%s", normalized, legacy)
	}
}

// The payload ships the mode-aware script under the path the shims source.
func TestPlatformPayloadShipsCaddySetup(t *testing.T) {
	files, _ := PlatformPayload()
	for _, f := range files {
		if f.Path == SCPayloadCaddySetupPath {
			if f.Content != caddyIngressSetupScript {
				t.Fatalf("payload caddy-setup is not the script constant")
			}
			return
		}
	}
	t.Fatalf("payload lacks %s", SCPayloadCaddySetupPath)
}
