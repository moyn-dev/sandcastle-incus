package tenant

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// goldenSiteBlock is one Caddy site block as caddy-setup renders it, with
// the name, certificate paths and $HOME substituted. The handlers are the
// ones machines ran before public names existed (ADR-0027 §5.2 "handlers
// byte-identical") and are the same for every name (ADR-0028).
const goldenSiteBlock = `{NAME}, *.{NAME} {
    tls {CERT} {KEY}
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

func renderSiteBlock(name, cert, key, home string) string {
	r := strings.NewReplacer("{NAME}", name, "{CERT}", cert, "{KEY}", key, "{HOME}", home)
	return r.Replace(goldenSiteBlock)
}

// goldenCaddyfile is the whole Caddyfile: the private block first, then one
// block per rendered public name (in hostnames-file order: sorted), blank
// line separated.
func goldenCaddyfile(privateFQDN, home string, publicNames ...string) string {
	out := renderSiteBlock(privateFQDN, MachineTLSCertPath, MachineTLSKeyPath, home)
	for _, name := range publicNames {
		out += "\n" + renderSiteBlock(name, MachineTLSHostCertPath(name), MachineTLSHostKeyPath(name), home)
	}
	return out
}

// Text-level contract of the script: the private leaf is always fetched,
// Caddy is always enabled and restarted at first boot (no MODE, no
// conditional start, no zone drop-in), --refresh skips install/trust/leaf,
// the render is validated before it replaces the Caddyfile, and the marker
// is written last with the PRIVATE/PUBLIC/RENDERED lines.
func TestCaddySetupScriptContract(t *testing.T) {
	script := caddyIngressSetupScript
	for _, gone := range []string{"MODE", "ConditionPathExists", "sandcastle-zone.conf", "systemctl start caddy || true"} {
		if strings.Contains(script, gone) {
			t.Fatalf("caddy-setup still carries %q:\n%s", gone, script)
		}
	}
	for _, want := range []string{
		"if [ \"${1:-}\" = --refresh ]; then REFRESH=1; fi\n",
		"curl -fsS \"$SIGNER/tls/ca\" -o /usr/local/share/ca-certificates/sandcastle-tenant.crt && update-ca-certificates || true\n",
		"  curl -fsS \"$SIGNER/tls/leaf?fqdn=$FQDN\" | python3 -c 'import json,sys;d=json.load(sys.stdin);open(\"/etc/sandcastle/tls/cert.pem\",\"w\").write(d[\"cert\"]);open(\"/etc/sandcastle/tls/key.pem\",\"w\").write(d[\"key\"])'\n  chmod 600 /etc/sandcastle/tls/key.pem\n",
		"if [ ! -e " + MachineHostnamesPath + " ]; then\n  printf '%s\\n' \"${" + PublicHostnamesEnvKey + ":-}\" | hostnames_normalized > " + MachineHostnamesPath + "\nfi\n",
		"\"$CADDY\" validate --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null\nmv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile\n",
		"'ExecStart=/.sc/platform/sbin/caddy run --environ --config /etc/caddy/Caddyfile' 'ExecReload=' 'ExecReload=/.sc/platform/sbin/caddy reload --config /etc/caddy/Caddyfile --force' > /etc/systemd/system/caddy.service.d/override.conf\n",
		"  printf 'PRIVATE=%s\\n' \"$FQDN\"\n  for host in $RENDERED; do printf 'PUBLIC=%s\\n' \"$host\"; done\n  printf 'RENDERED=%s\\n' \"$(date +%s)\"\n} > " + CaddySetupMarkerPath + "\n",
		"if [ \"$REFRESH\" = 0 ]; then\n  systemctl restart caddy\nelif systemctl is-active --quiet caddy; then\n  systemctl reload caddy || systemctl restart caddy\nelse\n  systemctl start caddy\nfi\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("caddy-setup missing %q:\n%s", want, script)
		}
	}
	order := []string{"tls/leaf", "site_block()", "> /etc/caddy/Caddyfile.new", "\"$CADDY\" validate", "override.conf", "systemctl daemon-reload", "systemctl enable caddy", "> " + CaddySetupMarkerPath, "systemctl restart caddy"}
	last := -1
	for _, step := range order {
		idx := strings.Index(script, step)
		if idx <= last {
			t.Fatalf("caddy-setup step %q out of order (index %d after %d)", step, idx, last)
		}
		last = idx
	}
	if strings.Count(script, "cat <<EOF") != 1 {
		t.Fatalf("caddy-setup must render every site through the one site_block heredoc")
	}
}

// posixShell is the interpreter the goldens run the script with. The boot
// shim is `#!/bin/sh` and sources the payload body, so on a Debian machine
// the body executes under dash: run it with sh (dash when sh is something
// else), and only as a last resort with `bash --posix`, which still accepts
// most bashisms — TestPayloadScriptsArePOSIXSh covers that gap statically.
func posixShell(t *testing.T) []string {
	t.Helper()
	for _, name := range []string{"sh", "dash"} {
		if path, err := exec.LookPath(name); err == nil {
			return []string{path}
		}
	}
	if path, err := exec.LookPath("bash"); err == nil {
		return []string{path, "--posix"}
	}
	t.Skip("no POSIX shell available")
	return nil
}

// bashisms are constructs dash rejects (or silently misparses) that a
// payload script sourced by a /bin/sh shim must never carry. The live e2e
// run found `done < <(…)` in caddy-setup: dash failed with "Syntax error:
// redirection unexpected", no Caddyfile and no marker were written, and the
// issued certificate was never pushed.
var bashisms = []string{"<(", ">(", "[[", "pipefail", "declare ", "local -a", "local -n", "+=(", "read -a", "#!/bin/bash", "function ", "${", "&>", "|&"}

// bashismWordStart is ANSI-C quoting ($'…'), which only opens a word — a
// bare `$'` inside a regex like '…*$' is the anchor, not quoting.
var bashismWordStart = regexp.MustCompile(`(^|[\s=(])\$'`)

// bashismAllowed lists the `${` forms that are POSIX (the only ${…}
// expansions the scripts use); everything else under `${` is suspect
// (`${x//…}`, `${x^^}`, `${arr[@]}`, `${x:1:2}`).
var bashismAllowed = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*(:-[^}]*|#[^}]*)?\}|\$\{[0-9]+(:-[^}]*|#[^}]*)?\}`)

func assertPOSIXSh(t *testing.T, name, script string) {
	t.Helper()
	stripped := bashismAllowed.ReplaceAllString(script, "")
	for _, b := range bashisms {
		if strings.Contains(stripped, b) {
			t.Errorf("%s carries the bashism %q (must stay POSIX sh: dash runs it):\n%s", name, b, script)
		}
	}
	if loc := bashismWordStart.FindStringIndex(stripped); loc != nil {
		t.Errorf("%s carries ANSI-C quoting ($'…') at offset %d (must stay POSIX sh)", name, loc[0])
	}
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Errorf("%s does not start with #!/bin/sh", name)
	}
	if sh, err := exec.LookPath("dash"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: dash -n rejects the script: %v\n%s", name, err, out)
		}
	}
}

// Every boot-time script — the two payload bodies and the two shims that
// source them — is POSIX sh. The shims are `#!/bin/sh`; cloud-init runs them
// as such, and `.` inherits that interpreter for the body.
func TestPayloadScriptsArePOSIXSh(t *testing.T) {
	for name, script := range map[string]string{
		"caddy-setup":      caddyIngressSetupScript,
		"generalize":       machineGeneralizeScript,
		"caddy-setup shim": SCCaddySetupShim,
		"generalize shim":  SCGeneralizeShim,
	} {
		assertPOSIXSh(t, name, script)
	}
}

// caddySetupRoot executes the real caddy-setup script under sh (dash) against
// a throwaway root, with the tools it calls stubbed on PATH. The absolute
// paths the script writes are rebased under root by textual substitution, so
// what lands on disk is what a machine would get — same Caddyfile, same
// marker, same hostnames file — and the systemctl/curl calls are recorded.
// The same root can be run again (with --refresh) to exercise the reconciler's
// path.
type caddySetupRoot struct {
	t      *testing.T
	root   string
	script string
	shell  []string
	log    string
}

func newCaddySetupRoot(t *testing.T, machineEnv string) *caddySetupRoot {
	t.Helper()
	shell := posixShell(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \""+name+" $*\" >> \"$SC_TEST_LOG\"\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// "already installed": skips the apt block. validate insists the
	// rendered file is there and non-empty, like the real one would.
	stub("caddy", "if [ \"$1\" = validate ]; then [ -s \"$3\" ] || { echo \"validate: missing $3\" >&2; exit 1; }; fi\nexit 0\n")
	stub("systemctl", "if [ \"$1\" = is-active ]; then [ -e \"$SC_TEST_ACTIVE\" ]; exit $?; fi\nexit 0\n")
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
	return &caddySetupRoot{t: t, root: root, script: scriptPath, shell: shell}
}

// command builds the interpreter invocation the boot shim would make: sh
// running the body, with args.
func (r *caddySetupRoot) command(args ...string) *exec.Cmd {
	argv := append(append([]string{}, r.shell[1:]...), r.script)
	return exec.Command(r.shell[0], append(argv, args...)...)
}

// run executes the script with args and returns the calls it made (the log
// is reset per run). active makes the systemctl stub report Caddy active.
func (r *caddySetupRoot) run(active bool, args ...string) string {
	r.t.Helper()
	logPath := filepath.Join(r.root, "calls.log")
	os.Remove(logPath)
	activePath := filepath.Join(r.root, "caddy.active")
	os.Remove(activePath)
	if active {
		if err := os.WriteFile(activePath, nil, 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	cmd := r.command(args...)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(r.root, "bin")+":"+os.Getenv("PATH"), "SC_TEST_LOG="+logPath, "SC_TEST_ACTIVE="+activePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("caddy-setup %v failed: %v\n%s", args, err, out)
	}
	calls, _ := os.ReadFile(logPath)
	r.log = string(calls)
	return r.log
}

func (r *caddySetupRoot) read(path string) string {
	r.t.Helper()
	data, err := os.ReadFile(filepath.Join(r.root, path))
	if err != nil {
		r.t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func (r *caddySetupRoot) write(path, content string) {
	r.t.Helper()
	full := filepath.Join(r.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *caddySetupRoot) absent(path string) {
	r.t.Helper()
	if _, err := os.Stat(filepath.Join(r.root, path)); err == nil {
		r.t.Fatalf("%s exists, want absent", path)
	}
}

// rebased is content as the rebased script writes it: every absolute /etc
// path inside a written file carries the throwaway root too.
func (r *caddySetupRoot) rebased(content string) string {
	return strings.ReplaceAll(content, "/etc/", r.root+"/etc/")
}

// certDir drops a complete (or partial) certificate directory for a name.
func (r *caddySetupRoot) certDir(name string, cert, key string) {
	r.t.Helper()
	if cert != "" {
		r.write("etc/sandcastle/tls/"+name+"/cert.pem", cert)
	}
	if key != "" {
		r.write("etc/sandcastle/tls/"+name+"/key.pem", key)
	}
}

// expectCaddyfile compares the rendered Caddyfile with the golden.
func (r *caddySetupRoot) expectCaddyfile(privateFQDN, home string, publicNames ...string) {
	r.t.Helper()
	if got, want := r.read("etc/caddy/Caddyfile"), r.rebased(goldenCaddyfile(privateFQDN, home, publicNames...)); got != want {
		r.t.Fatalf("Caddyfile:\n%s\nwant:\n%s", got, want)
	}
	r.absent("etc/caddy/Caddyfile.new")
}

var renderedLine = regexp.MustCompile(`(?m)^RENDERED=(\d+)\n`)

// expectMarker checks the marker's PRIVATE/PUBLIC lines, that RENDERED is a
// recent unix timestamp, and that the parser agrees.
func (r *caddySetupRoot) expectMarker(privateFQDN string, publicNames ...string) CaddySetupMarker {
	r.t.Helper()
	content := r.read("etc/sandcastle/caddy.ready")
	want := "PRIVATE=" + privateFQDN + "\n"
	for _, name := range publicNames {
		want += "PUBLIC=" + name + "\n"
	}
	match := renderedLine.FindStringSubmatch(content)
	if match == nil {
		r.t.Fatalf("marker has no RENDERED line:\n%s", content)
	}
	if got := renderedLine.ReplaceAllString(content, ""); got != want {
		r.t.Fatalf("marker:\n%s\nwant:\n%s", got, want)
	}
	marker, err := ParseCaddySetupMarker(content)
	if err != nil {
		r.t.Fatalf("parse marker %q: %v", content, err)
	}
	if marker.Private != privateFQDN || strings.Join(marker.Public, ",") != strings.Join(publicNames, ",") {
		r.t.Fatalf("parsed marker = %+v", marker)
	}
	if age := time.Since(marker.Rendered); age < 0 || age > time.Hour {
		r.t.Fatalf("RENDERED %s is not recent", marker.Rendered)
	}
	return marker
}

const (
	testSigner   = "http://10.0.0.3:9443"
	testHome     = "/home/dev"
	privateEnv   = "FQDN=web.zp.acme\nPUBLIC_HOSTNAMES=\nSIGNER=" + testSigner + "\nHOME=" + testHome + "\n"
	derivedEnv   = "FQDN=web.zp.acme\nPUBLIC_HOSTNAMES=web.baum.hase.de,\nSIGNER=" + testSigner + "\nHOME=" + testHome + "\n"
	explicitEnv  = "FQDN=web.zp.acme\nPUBLIC_HOSTNAMES=web12.tc42.uk\nSIGNER=" + testSigner + "\nHOME=" + testHome + "\n"
	mixedEnv     = "FQDN=web.zp.acme\nPUBLIC_HOSTNAMES=web.baum.hase.de,Web12.TC42.uk.,shop.tc42.uk,web.baum.hase.de\nSIGNER=" + testSigner + "\nHOME=" + testHome + "\n"
	firstBootLog = "curl -fsS " + testSigner + "/tls/ca -o {ROOT}/usr/local/share/ca-certificates/sandcastle-tenant.crt\nupdate-ca-certificates \ncurl -fsS " + testSigner + "/tls/leaf?fqdn=web.zp.acme\ncaddy validate --config {ROOT}/etc/caddy/Caddyfile.new --adapter caddyfile\nsystemctl daemon-reload\nsystemctl enable caddy\nsystemctl restart caddy\n"
)

func (r *caddySetupRoot) expectFirstBootCalls() {
	r.t.Helper()
	if want := strings.ReplaceAll(firstBootLog, "{ROOT}", r.root); r.log != want {
		r.t.Fatalf("calls:\n%s\nwant:\n%s", r.log, want)
	}
}

// Private-only: a machine with no public name gets exactly what every
// machine got before public names existed — the sidecar leaf, the private
// site block, Caddy enabled + restarted — plus an empty hostnames file and a
// marker naming only the private FQDN. No drop-in, no MODE anywhere.
func TestCaddySetupPrivateOnly(t *testing.T) {
	r := newCaddySetupRoot(t, privateEnv)
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome)
	if got := r.read("etc/sandcastle/tls/cert.pem"); got != "LEAF-CERT" {
		t.Fatalf("leaf cert = %q", got)
	}
	if got := r.read("etc/sandcastle/tls/key.pem"); got != "LEAF-KEY" {
		t.Fatalf("leaf key = %q", got)
	}
	if got := r.read("usr/local/share/ca-certificates/sandcastle-tenant.crt"); got != "TENANT-CA\n" {
		t.Fatalf("tenant CA = %q", got)
	}
	if got := r.read("etc/systemd/system/caddy.service.d/override.conf"); got != "[Service]\nUser=root\nGroup=root\nAmbientCapabilities=\nExecStart=\nExecStart=/.sc/platform/sbin/caddy run --environ --config "+r.root+"/etc/caddy/Caddyfile\nExecReload=\nExecReload=/.sc/platform/sbin/caddy reload --config "+r.root+"/etc/caddy/Caddyfile --force\n" {
		t.Fatalf("override.conf = %q", got)
	}
	r.absent("etc/systemd/system/caddy.service.d/sandcastle-zone.conf")
	if got := r.read("etc/sandcastle/hostnames"); got != "" {
		t.Fatalf("hostnames = %q, want empty", got)
	}
	marker := r.expectMarker("web.zp.acme")
	if !marker.ReadyFor("anything.tc42.uk") || !marker.Serves("web.zp.acme") || marker.Serves("web.baum.hase.de") {
		t.Fatalf("marker gate: %+v", marker)
	}
	r.expectFirstBootCalls()
}

// A machine.env without a PUBLIC_HOSTNAMES line at all (a profile rendered
// by an older binary) is private-only too — the script must not trip on the
// unset variable.
func TestCaddySetupLegacyEnvWithoutPublicHostnames(t *testing.T) {
	r := newCaddySetupRoot(t, "FQDN=web.zp.acme\nSIGNER="+testSigner+"\nHOME="+testHome+"\n")
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome)
	if got := r.read("etc/sandcastle/hostnames"); got != "" {
		t.Fatalf("hostnames = %q, want empty", got)
	}
	r.expectMarker("web.zp.acme")
}

// Derived-only: a project with a Project Domain seeds the derived name. At
// first boot its certificate has not landed, so the Caddyfile carries only
// the private block and the marker lists no PUBLIC line — Caddy still
// starts (the private block has a certificate). The seed's trailing comma
// (an empty instance record, as profiles rendered before the tail-expression
// fix seeded it) is harmless.
func TestCaddySetupDerivedOnlyBeforeCert(t *testing.T) {
	r := newCaddySetupRoot(t, derivedEnv)
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome)
	if got := r.read("etc/sandcastle/hostnames"); got != "web.baum.hase.de\n" {
		t.Fatalf("hostnames = %q", got)
	}
	marker := r.expectMarker("web.zp.acme")
	if !marker.ReadyFor("web.baum.hase.de") || marker.Serves("web.baum.hase.de") {
		t.Fatalf("marker gate before the push: %+v", marker)
	}
	r.expectFirstBootCalls()
}

// Derived-only with the certificate already there (a recreate: the Auth App
// pushed while cloud-init ran, or a retained certificate landed first): the
// public block renders at first boot and the marker lists it.
func TestCaddySetupDerivedOnlyWithCert(t *testing.T) {
	r := newCaddySetupRoot(t, derivedEnv)
	r.certDir("web.baum.hase.de", "LE-CERT", "LE-KEY")
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome, "web.baum.hase.de")
	marker := r.expectMarker("web.zp.acme", "web.baum.hase.de")
	if !marker.Serves("web.baum.hase.de") {
		t.Fatalf("marker: %+v", marker)
	}
	r.expectFirstBootCalls()
}

// Explicit-only: a machine in a project WITHOUT a domain carrying one
// explicit hostname. The private block is unchanged; the explicit name is
// seeded and served once its certificate is complete — a directory with
// only one of the two files is not rendered.
func TestCaddySetupExplicitOnly(t *testing.T) {
	r := newCaddySetupRoot(t, explicitEnv)
	r.certDir("web12.tc42.uk", "LE-CERT", "") // key missing: not rendered
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome)
	if got := r.read("etc/sandcastle/hostnames"); got != "web12.tc42.uk\n" {
		t.Fatalf("hostnames = %q", got)
	}
	r.expectMarker("web.zp.acme")

	r.certDir("web12.tc42.uk", "", "LE-KEY")
	r.run(true, "--refresh")
	r.expectCaddyfile("web.zp.acme", testHome, "web12.tc42.uk")
	r.expectMarker("web.zp.acme", "web12.tc42.uk")
}

// Mixed: derived + explicit names, seeded with duplicates, mixed case and a
// trailing dot. The hostnames file is normalized and sorted; blocks render
// in that order for every name whose certificate is complete.
func TestCaddySetupMixed(t *testing.T) {
	r := newCaddySetupRoot(t, mixedEnv)
	r.certDir("web.baum.hase.de", "LE-CERT-1", "LE-KEY-1")
	r.certDir("web12.tc42.uk", "LE-CERT-2", "LE-KEY-2")
	r.run(false)
	if got := r.read("etc/sandcastle/hostnames"); got != "shop.tc42.uk\nweb.baum.hase.de\nweb12.tc42.uk\n" {
		t.Fatalf("hostnames = %q", got)
	}
	r.expectCaddyfile("web.zp.acme", testHome, "web.baum.hase.de", "web12.tc42.uk")
	marker := r.expectMarker("web.zp.acme", "web.baum.hase.de", "web12.tc42.uk")
	if marker.Serves("shop.tc42.uk") || !marker.ReadyFor("shop.tc42.uk") {
		t.Fatalf("marker: %+v", marker)
	}
	r.expectFirstBootCalls()
}

// --refresh after a new hostname appears: the reconciler pushes a hostnames
// file with an extra name (and its certificate), then execs --refresh. No
// install, no trust, no leaf fetch; the Caddyfile is validated and
// replaced, the marker rewritten, Caddy reloaded.
func TestCaddySetupRefreshAfterNewHostname(t *testing.T) {
	r := newCaddySetupRoot(t, derivedEnv)
	r.certDir("web.baum.hase.de", "LE-CERT-1", "LE-KEY-1")
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome, "web.baum.hase.de")

	r.write("etc/sandcastle/hostnames", "web.baum.hase.de\napi.tc42.uk\n")
	r.certDir("api.tc42.uk", "LE-CERT-2", "LE-KEY-2")
	log := r.run(true, "--refresh")
	r.expectCaddyfile("web.zp.acme", testHome, "api.tc42.uk", "web.baum.hase.de")
	r.expectMarker("web.zp.acme", "api.tc42.uk", "web.baum.hase.de")
	if want := "caddy validate --config " + r.root + "/etc/caddy/Caddyfile.new --adapter caddyfile\nsystemctl is-active --quiet caddy\nsystemctl reload caddy\n"; log != want {
		t.Fatalf("refresh calls:\n%s\nwant:\n%s", log, want)
	}
	// The hostnames file pushed by the Auth App is left as pushed — the
	// script reads it, never rewrites it.
	if got := r.read("etc/sandcastle/hostnames"); got != "web.baum.hase.de\napi.tc42.uk\n" {
		t.Fatalf("hostnames rewritten: %q", got)
	}
	// The private leaf and the CA are untouched by a refresh.
	if got := r.read("etc/sandcastle/tls/cert.pem"); got != "LEAF-CERT" {
		t.Fatalf("leaf cert after refresh = %q", got)
	}
}

// --refresh after a certificate lands for a name that was already listed:
// the block appears; a name removed from the file disappears even though
// its directory is still there.
func TestCaddySetupRefreshAfterCertLands(t *testing.T) {
	r := newCaddySetupRoot(t, mixedEnv)
	r.run(false)
	r.expectCaddyfile("web.zp.acme", testHome)
	r.expectMarker("web.zp.acme")

	r.certDir("shop.tc42.uk", "LE-CERT", "LE-KEY")
	r.run(true, "--refresh")
	r.expectCaddyfile("web.zp.acme", testHome, "shop.tc42.uk")
	r.expectMarker("web.zp.acme", "shop.tc42.uk")

	// The name is removed from the set (sc hostname remove): its block goes
	// with the next refresh, whatever is left in its directory.
	r.write("etc/sandcastle/hostnames", "web.baum.hase.de\nweb12.tc42.uk\n")
	r.run(true, "--refresh")
	r.expectCaddyfile("web.zp.acme", testHome)
	r.expectMarker("web.zp.acme")
}

// --refresh is idempotent: with nothing changed it re-renders the identical
// Caddyfile, rewrites the marker and reloads; run any number of times. When
// Caddy is inactive it is started instead of reloaded.
func TestCaddySetupRefreshIdempotent(t *testing.T) {
	r := newCaddySetupRoot(t, derivedEnv)
	r.certDir("web.baum.hase.de", "LE-CERT", "LE-KEY")
	r.run(false)
	first := r.read("etc/caddy/Caddyfile")
	for i := 0; i < 3; i++ {
		log := r.run(true, "--refresh")
		if got := r.read("etc/caddy/Caddyfile"); got != first {
			t.Fatalf("refresh %d changed the Caddyfile:\n%s", i, got)
		}
		r.expectMarker("web.zp.acme", "web.baum.hase.de")
		if !strings.HasSuffix(log, "systemctl reload caddy\n") || strings.Contains(log, "tls/leaf") || strings.Contains(log, "daemon-reload") {
			t.Fatalf("refresh %d calls:\n%s", i, log)
		}
	}
	log := r.run(false, "--refresh")
	if !strings.HasSuffix(log, "systemctl is-active --quiet caddy\nsystemctl start caddy\n") {
		t.Fatalf("inactive refresh must start caddy:\n%s", log)
	}
}

// A refresh that fails validation leaves the running Caddyfile and the old
// marker untouched (the .new render is what fails).
func TestCaddySetupRefreshKeepsCaddyfileOnValidateFailure(t *testing.T) {
	r := newCaddySetupRoot(t, privateEnv)
	r.run(false)
	before := r.read("etc/caddy/Caddyfile")
	marker := r.read("etc/sandcastle/caddy.ready")
	if err := os.WriteFile(filepath.Join(r.root, "bin", "caddy"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := r.command("--refresh")
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(r.root, "bin")+":"+os.Getenv("PATH"), "SC_TEST_LOG="+filepath.Join(r.root, "calls.log"), "SC_TEST_ACTIVE=/nonexistent")
	if err := cmd.Run(); err == nil {
		t.Fatal("refresh with a failing validate must exit nonzero")
	}
	if r.read("etc/caddy/Caddyfile") != before || r.read("etc/sandcastle/caddy.ready") != marker {
		t.Fatal("failed validate replaced the Caddyfile or the marker")
	}
}

func TestParseCaddySetupMarker(t *testing.T) {
	marker, err := ParseCaddySetupMarker("PRIVATE=web.zp.acme\nPUBLIC=web12.tc42.uk\nPUBLIC=Web.baum.hase.de.\nRENDERED=1757760000\n")
	if err != nil {
		t.Fatal(err)
	}
	if marker.Private != "web.zp.acme" || strings.Join(marker.Public, ",") != "web.baum.hase.de,web12.tc42.uk" || !marker.Rendered.Equal(time.Unix(1757760000, 0)) || marker.Legacy() {
		t.Fatalf("parse = %+v", marker)
	}
	if !marker.ReadyFor("web.baum.hase.de") || !marker.ReadyFor("api.tc42.uk") || marker.ReadyFor("") || marker.ReadyFor(" . ") {
		t.Fatalf("per-name marker must clear the gate for any named host")
	}
	if !marker.Serves("WEB.baum.hase.de.") || !marker.Serves("web.zp.acme") || marker.Serves("api.tc42.uk") {
		t.Fatalf("Serves")
	}
	if marker.String() != "PRIVATE=web.zp.acme PUBLIC=web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("String = %q", marker.String())
	}

	private, err := ParseCaddySetupMarker("# written by caddy-setup\n\nPRIVATE=web.zp.acme\nRENDERED=0\n")
	if err != nil || private.Private != "web.zp.acme" || len(private.Public) != 0 || !private.Rendered.IsZero() {
		t.Fatalf("private parse = %+v, %v", private, err)
	}
	if !private.ReadyFor("web.baum.hase.de") || private.Serves("web.baum.hase.de") || private.String() != "PRIVATE=web.zp.acme PUBLIC=-" {
		t.Fatalf("private-only marker: %+v", private)
	}

	// Legacy ADR-0027 markers parse (so the log can say what they are) but
	// never clear the gate: that machine has no per-name contract.
	for _, legacy := range []string{"MODE=zone\nFQDN=web.baum.hase.de\n", "MODE=private\nFQDN=web.zp.acme\n"} {
		m, err := ParseCaddySetupMarker(legacy)
		if err != nil || !m.Legacy() || m.LegacyFQDN == "" {
			t.Fatalf("legacy parse %q = %+v, %v", legacy, m, err)
		}
		if m.ReadyFor(m.LegacyFQDN) || m.ReadyFor("x") {
			t.Fatalf("legacy marker cleared the gate: %+v", m)
		}
		if !strings.HasSuffix(m.String(), "(legacy)") {
			t.Fatalf("legacy String = %q", m.String())
		}
	}
	for _, bad := range []string{"", "PUBLIC=web.baum.hase.de\n", "RENDERED=1\n", "PRIVATE web.zp.acme\n", "garbage\nPRIVATE=web.zp.acme\n"} {
		if _, err := ParseCaddySetupMarker(bad); err == nil {
			t.Fatalf("ParseCaddySetupMarker(%q) accepted", bad)
		}
	}
}

func TestMachineTLSHostPaths(t *testing.T) {
	if got := MachineTLSHostCertPath(" Web12.TC42.uk. "); got != "/etc/sandcastle/tls/web12.tc42.uk/cert.pem" {
		t.Fatalf("cert path = %q", got)
	}
	if got := MachineTLSHostKeyPath("web12.tc42.uk"); got != "/etc/sandcastle/tls/web12.tc42.uk/key.pem" {
		t.Fatalf("key path = %q", got)
	}
	if got := FormatMachineHostnamesFile([]string{"Web12.TC42.uk.", "", "api.tc42.uk", "web12.tc42.uk"}); got != "api.tc42.uk\nweb12.tc42.uk\n" {
		t.Fatalf("hostnames file = %q", got)
	}
	if got := FormatMachineHostnamesFile(nil); got != "" {
		t.Fatalf("empty hostnames file = %q", got)
	}
}

// The bare document tracks the profile's seed line (spec machine-hostnames
// §6): the PUBLIC_HOSTNAMES line is copied verbatim off the profile, and
// everything else is the bare document as before.
func TestV2BareUserDataWithPublicHostnames(t *testing.T) {
	plain := V2BareUserData("zp.acme", "http://10.0.0.3:9443")
	if got := V2BareUserDataWithPublicHostnames("zp.acme", "http://10.0.0.3:9443", ""); got != plain {
		t.Fatalf("empty seed drifted from the default bare document:\n%s", got)
	}
	wantEnv := "  - path: /etc/sandcastle/machine.env\n    permissions: '0644'\n    content: |\n      FQDN={{ v1.local_hostname }}.zp.acme\n      " + PublicHostnamesEnvLine("") + "\n      SIGNER=http://10.0.0.3:9443\n      HOME=" + BareMachineHome + "\n"
	if !strings.Contains(plain, wantEnv) {
		t.Fatalf("bare machine.env:\n%s", plain)
	}
	if strings.Contains(plain, "MODE=") {
		t.Fatalf("bare document carries a MODE line:\n%s", plain)
	}
	profile := V2ProfileUserData("dev", "ssh-ed25519 AAAA", "zp", "acme", "baum.hase.de", "http://10.0.0.3:9443")
	seed := PublicHostnamesEnvLineOf(profile)
	if seed != PublicHostnamesEnvLine("baum.hase.de") {
		t.Fatalf("seed read off the profile = %q", seed)
	}
	domain := V2BareUserDataWithPublicHostnames("zp.acme", "http://10.0.0.3:9443", seed)
	if !strings.Contains(domain, "      FQDN={{ v1.local_hostname }}.zp.acme\n      "+seed+"\n      SIGNER=") {
		t.Fatalf("domain bare machine.env:\n%s", domain)
	}
	if !strings.Contains(domain, "fqdn: {{ v1.local_hostname }}.zp.acme\n") {
		t.Fatalf("bare fqdn must stay the private name:\n%s", domain)
	}
	if strings.ReplaceAll(domain, seed, PublicHostnamesEnvLine("")) != plain {
		t.Fatalf("domain bare document differs beyond the seed line:\n%s\n---\n%s", domain, plain)
	}
}

// The payload ships the per-name script under the path the shims source.
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

// The generalize step drops a cloned image's public-name material too: the
// hostnames file and every per-hostname certificate directory, but not the
// tls directory itself.
func TestGeneralizeDropsPublicNameMaterial(t *testing.T) {
	for _, want := range []string{"/etc/sandcastle/hostnames", "find /etc/sandcastle/tls -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +"} {
		if !strings.Contains(machineGeneralizeScript, want) {
			t.Fatalf("generalize lacks %q:\n%s", want, machineGeneralizeScript)
		}
	}
}

func TestCaddySetupProjectCertificateSelection(t *testing.T) {
	r := newCaddySetupRoot(t, derivedEnv)
	r.run(false)
	r.write("etc/sandcastle/project-domain", "baum.hase.de\n")
	r.write("etc/sandcastle/hostnames", "web.baum.hase.de\nadmin-web.baum.hase.de\ndeep.web.baum.hase.de\n*.web.baum.hase.de\noutside.tc42.uk\n")
	r.certDir("baum.hase.de", "PROJECT-CERT", "PROJECT-KEY")
	r.certDir("web.baum.hase.de", "OLD-CERT", "OLD-KEY")
	r.certDir("*.web.baum.hase.de", "WILDCARD-CERT", "WILDCARD-KEY")
	r.certDir("outside.tc42.uk", "OUTSIDE-CERT", "OUTSIDE-KEY")
	r.run(true)
	got := r.read("etc/caddy/Caddyfile")
	for _, name := range []string{"web.baum.hase.de", "admin-web.baum.hase.de"} {
		want := r.rebased(name + " {\n    tls /etc/sandcastle/tls/baum.hase.de/cert.pem /etc/sandcastle/tls/baum.hase.de/key.pem")
		if !strings.Contains(got, want) {
			t.Fatalf("missing shared block %s: %s", name, got)
		}
	}
	if strings.Contains(got, "deep.web.baum.hase.de") || strings.Contains(got, "*.*.") {
		t.Fatalf("wildcard overreach: %s", got)
	}
	if !strings.Contains(got, "*.web.baum.hase.de {") || !strings.Contains(got, "/outside.tc42.uk/cert.pem") {
		t.Fatalf("missing explicit blocks: %s", got)
	}
	r.write("etc/sandcastle/project-domain", "")
	r.run(true)
	got = r.read("etc/caddy/Caddyfile")
	if strings.Contains(got, "/baum.hase.de/cert.pem") || strings.Contains(got, "admin-web.baum.hase.de") {
		t.Fatalf("released project cert still selected: %s", got)
	}
}
