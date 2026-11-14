package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/cliconfig"
	"gopkg.in/yaml.v2"
)

type mirrorFixture struct {
	native, dedicated string
	nativeCert        []byte
	scCert, scKey     []byte
}

func testKeypair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const nativeConfigYAML = `default-remote: big
remotes:
  big:
    addr: https://big.example:8443
    auth_type: tls
    project: default
    protocol: incus
    public: false
  images:
    addr: https://images.linuxcontainers.org
    protocol: simplestreams
    public: true
  local:
    addr: unix://
    public: false
aliases:
  ll: list -c ns4
custom_key: keep-me
`

// newMirrorFixture builds a temp HOME: a native ~/.config/incus with its own
// admin identity and remotes, and the dedicated Sandcastle dir with the given
// remotes (name -> addr) and a server pin for each.
func newMirrorFixture(t *testing.T, remotes map[string]string) mirrorFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv(NativeMirrorEnv, "")
	f := mirrorFixture{native: NativeIncusDir(), dedicated: DedicatedIncusDir()}
	var nativeKey []byte
	f.nativeCert, nativeKey = testKeypair(t, "admin")
	f.scCert, f.scKey = testKeypair(t, "sandcastle")
	writeTestFile(t, filepath.Join(f.native, "client.crt"), f.nativeCert)
	writeTestFile(t, filepath.Join(f.native, "client.key"), nativeKey)
	writeTestFile(t, filepath.Join(f.native, "config.yml"), []byte(nativeConfigYAML))
	writeTestFile(t, filepath.Join(f.dedicated, "client.crt"), f.scCert)
	writeTestFile(t, filepath.Join(f.dedicated, "client.key"), f.scKey)
	f.setDedicatedRemotes(t, remotes)
	return f
}

func (f mirrorFixture) setDedicatedRemotes(t *testing.T, remotes map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("default-remote: local\nremotes:\n  images:\n    addr: https://images.linuxcontainers.org\n    protocol: simplestreams\n    public: true\n  local:\n    addr: unix://\n    public: false\n")
	for name, addr := range remotes {
		b.WriteString("  " + name + ":\n    addr: " + addr + "\n    auth_type: tls\n    project: tc-" + name + "-default\n    protocol: incus\n    public: false\n")
		writeTestFile(t, filepath.Join(f.dedicated, "servercerts", name+".crt"), []byte("pin for "+addr+"\n"))
	}
	writeTestFile(t, filepath.Join(f.dedicated, "config.yml"), []byte(b.String()))
}

type nativeRemote struct {
	Addr               string `yaml:"addr"`
	AuthType           string `yaml:"auth_type"`
	Project            string `yaml:"project"`
	Protocol           string `yaml:"protocol"`
	Public             bool   `yaml:"public"`
	LastWorkingAddress string `yaml:"last_working_address"`
}

type nativeConfig struct {
	DefaultRemote string                  `yaml:"default-remote"`
	Remotes       map[string]nativeRemote `yaml:"remotes"`
	Aliases       map[string]string       `yaml:"aliases"`
	CustomKey     string                  `yaml:"custom_key"`
}

func (f mirrorFixture) nativeConfig(t *testing.T) nativeConfig {
	t.Helper()
	var cfg nativeConfig
	if err := yaml.Unmarshal([]byte(readTestFile(t, filepath.Join(f.native, "config.yml"))), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func syncMirror(t *testing.T) NativeMirrorReport {
	t.Helper()
	report, err := SyncNativeIncusMirror(false)
	if err != nil {
		t.Fatalf("SyncNativeIncusMirror: %v", err)
	}
	return report
}

func TestNativeMirrorCreatesRemotesWithPerRemoteIdentity(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443", "sc-b": "https://100.64.0.2:8443"})

	report := syncMirror(t)
	if !report.Active || strings.Join(report.Added, ",") != "sc-a,sc-b" {
		t.Fatalf("report = %+v, want active, added sc-a,sc-b", report)
	}
	cfg := f.nativeConfig(t)
	want := nativeRemote{Addr: "https://100.64.0.1:8443", AuthType: "tls", Project: "tc-sc-a-default", Protocol: "incus"}
	if got := cfg.Remotes["sc-a"]; got != want {
		t.Fatalf("native sc-a = %+v, want %+v", got, want)
	}
	if got := readTestFile(t, filepath.Join(f.native, "clientcerts", "sc-a.crt")); got != string(f.scCert) {
		t.Fatal("clientcerts/sc-a.crt is not the Sandcastle certificate")
	}
	if got := readTestFile(t, filepath.Join(f.native, "clientcerts", "sc-a.key")); got != string(f.scKey) {
		t.Fatal("clientcerts/sc-a.key is not the Sandcastle key")
	}
	if info, _ := os.Stat(filepath.Join(f.native, "clientcerts", "sc-a.key")); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", info.Mode().Perm())
	}
	if got := readTestFile(t, filepath.Join(f.native, "servercerts", "sc-b.crt")); got != "pin for https://100.64.0.2:8443\n" {
		t.Fatalf("servercerts/sc-b.crt = %q", got)
	}
	if got := readTestFile(t, filepath.Join(f.native, "client.crt")); got != string(f.nativeCert) {
		t.Fatal("native client.crt changed")
	}
	// Unknown keys, aliases, default-remote and admin remotes survive.
	if cfg.DefaultRemote != "big" || cfg.Aliases["ll"] != "list -c ns4" || cfg.CustomKey != "keep-me" {
		t.Fatalf("native config lost keys: %+v", cfg)
	}
	if cfg.Remotes["big"].Addr != "https://big.example:8443" || cfg.Remotes["images"].Protocol != "simplestreams" || cfg.Remotes["local"].Addr != "unix://" {
		t.Fatalf("native admin remotes changed: %+v", cfg.Remotes)
	}
}

// The incus Go client must use the mirrored keypair for the mirrored remote
// and the native identity for every other remote.
func TestNativeMirrorIncusClientPicksPerRemoteCertificate(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	syncMirror(t)

	loaded, err := cliconfig.LoadConfig(filepath.Join(f.native, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cert, key, _, err := loaded.GetClientCertificate("sc-a")
	if err != nil {
		t.Fatal(err)
	}
	if cert != string(f.scCert) || key != string(f.scKey) {
		t.Fatal("incus client does not use the Sandcastle keypair for sc-a")
	}
	cert, _, _, err = loaded.GetClientCertificate("big")
	if err != nil {
		t.Fatal(err)
	}
	if cert != string(f.nativeCert) {
		t.Fatal("incus client does not use the native identity for big")
	}
	if remote := loaded.Remotes["sc-a"]; remote.Addr != "https://100.64.0.1:8443" || remote.Project != "tc-sc-a-default" || remote.AuthType != "tls" {
		t.Fatalf("cliconfig sees sc-a as %+v", remote)
	}
}

func TestNativeMirrorSecondRunIsNoOp(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	syncMirror(t)
	paths := []string{"config.yml", "clientcerts/sc-a.crt", "clientcerts/sc-a.key", "servercerts/sc-a.crt"}
	before := map[string]os.FileInfo{}
	for _, p := range paths {
		info, err := os.Stat(filepath.Join(f.native, p))
		if err != nil {
			t.Fatal(err)
		}
		before[p] = info
	}
	past := time.Now().Add(-time.Hour)
	for _, p := range paths {
		_ = os.Chtimes(filepath.Join(f.native, p), past, past)
	}

	report := syncMirror(t)
	if report.Changed() || strings.Join(report.Mirrored, ",") != "sc-a" {
		t.Fatalf("second run report = %+v, want no change, mirrored sc-a", report)
	}
	for _, p := range paths {
		info, _ := os.Stat(filepath.Join(f.native, p))
		if !info.ModTime().Equal(past) {
			t.Fatalf("%s rewritten on second run", p)
		}
	}
}

// A hand-made mirror entry that already matches is adopted without a write.
func TestNativeMirrorAdoptsMatchingHandMadeEntry(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	cfg := strings.Replace(nativeConfigYAML, "remotes:\n", "remotes:\n  sc-a:\n    addr: https://100.64.0.1:8443\n    auth_type: tls\n    project: tc-sc-a-default\n    protocol: incus\n    public: false\n", 1)
	writeTestFile(t, filepath.Join(f.native, "config.yml"), []byte(cfg))
	writeTestFile(t, filepath.Join(f.native, "clientcerts", "sc-a.crt"), f.scCert)
	writeTestFile(t, filepath.Join(f.native, "clientcerts", "sc-a.key"), f.scKey)
	writeTestFile(t, filepath.Join(f.native, "servercerts", "sc-a.crt"), []byte("pin for https://100.64.0.1:8443\n"))

	report := syncMirror(t)
	if report.Changed() || len(report.Skipped) != 0 {
		t.Fatalf("report = %+v, want adoption without change", report)
	}
	if got := readTestFile(t, filepath.Join(f.native, "config.yml")); got != cfg {
		t.Fatalf("config.yml rewritten:\n%s", got)
	}
}

func TestNativeMirrorSkipsForeignRemoteOfSameName(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"big": "https://100.64.0.9:8443", "sc-a": "https://100.64.0.1:8443"})

	report := syncMirror(t)
	if len(report.Skipped) != 1 || !strings.HasPrefix(report.Skipped[0], "big:") {
		t.Fatalf("skipped = %v, want big", report.Skipped)
	}
	if got := f.nativeConfig(t).Remotes["big"]; got.Addr != "https://big.example:8443" || got.Project != "default" {
		t.Fatalf("foreign big modified: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(f.native, "clientcerts", "big.crt")); !os.IsNotExist(err) {
		t.Fatal("wrote a clientcert for the foreign big remote")
	}
	if strings.Join(report.Mirrored, ",") != "sc-a" {
		t.Fatalf("mirrored = %v, want sc-a", report.Mirrored)
	}
}

// A same-named native remote whose clientcert is a different keypair is not
// Sandcastle's, so it is neither updated nor removed.
func TestNativeMirrorLeavesRemoteWithOtherClientCert(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443", "sc-b": "https://100.64.0.2:8443"})
	syncMirror(t)
	other, _ := testKeypair(t, "other")
	writeTestFile(t, filepath.Join(f.native, "clientcerts", "sc-a.crt"), other)
	f.setDedicatedRemotes(t, map[string]string{"sc-a": "https://100.64.0.7:8443"})

	report := syncMirror(t)
	cfg := f.nativeConfig(t)
	if cfg.Remotes["sc-a"].Addr != "https://100.64.0.1:8443" {
		t.Fatalf("foreign-identity sc-a re-pointed: %+v", cfg.Remotes["sc-a"])
	}
	if len(report.Skipped) != 1 || !strings.HasPrefix(report.Skipped[0], "sc-a:") {
		t.Fatalf("skipped = %v, want sc-a", report.Skipped)
	}
	if _, ok := cfg.Remotes["sc-b"]; ok || strings.Join(report.Removed, ",") != "sc-b" {
		t.Fatalf("sc-b not removed: removed=%v remotes=%v", report.Removed, cfg.Remotes)
	}
}

func TestNativeMirrorRemovesOwnedRemoteDroppedFromDedicated(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443", "sc-b": "https://100.64.0.2:8443"})
	syncMirror(t)
	f.setDedicatedRemotes(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})

	report := syncMirror(t)
	if strings.Join(report.Removed, ",") != "sc-b" {
		t.Fatalf("removed = %v, want sc-b", report.Removed)
	}
	cfg := f.nativeConfig(t)
	if _, ok := cfg.Remotes["sc-b"]; ok {
		t.Fatal("sc-b still in native config")
	}
	if _, ok := cfg.Remotes["big"]; !ok {
		t.Fatal("big removed")
	}
	for _, p := range []string{"clientcerts/sc-b.crt", "clientcerts/sc-b.key", "servercerts/sc-b.crt"} {
		if _, err := os.Stat(filepath.Join(f.native, p)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", p)
		}
	}
}

func TestNativeMirrorKeepsRemovedRemoteThatIsNativeDefault(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	syncMirror(t)
	cfg := strings.Replace(readTestFile(t, filepath.Join(f.native, "config.yml")), "default-remote: big", "default-remote: sc-a", 1)
	writeTestFile(t, filepath.Join(f.native, "config.yml"), []byte(cfg))
	f.setDedicatedRemotes(t, map[string]string{})

	report := syncMirror(t)
	if len(report.Removed) != 0 || len(report.Skipped) != 1 {
		t.Fatalf("report = %+v, want sc-a kept and skipped", report)
	}
	if _, ok := f.nativeConfig(t).Remotes["sc-a"]; !ok {
		t.Fatal("removed the native default-remote")
	}
}

func TestNativeMirrorServerPin(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	syncMirror(t)
	nativePin := filepath.Join(f.native, "servercerts", "sc-a.crt")

	// Unchanged address: a pin refreshed in the native dir survives.
	writeTestFile(t, nativePin, []byte("refreshed native pin\n"))
	if report := syncMirror(t); report.Changed() {
		t.Fatalf("report = %+v, want no change", report)
	}
	if got := readTestFile(t, nativePin); got != "refreshed native pin\n" {
		t.Fatalf("native pin overwritten for unchanged address: %q", got)
	}

	// Changed address: the pin and the entry follow the dedicated config, and
	// a stale last_working_address goes.
	cfg := strings.Replace(readTestFile(t, filepath.Join(f.native, "config.yml")), "addr: https://100.64.0.1:8443", "addr: https://100.64.0.1:8443\n    last_working_address: https://100.64.0.1:8443", 1)
	writeTestFile(t, filepath.Join(f.native, "config.yml"), []byte(cfg))
	f.setDedicatedRemotes(t, map[string]string{"sc-a": "https://100.64.0.5:8443"})
	report := syncMirror(t)
	if strings.Join(report.Updated, ",") != "sc-a" {
		t.Fatalf("updated = %v, want sc-a", report.Updated)
	}
	if got := readTestFile(t, nativePin); got != "pin for https://100.64.0.5:8443\n" {
		t.Fatalf("native pin after address change = %q", got)
	}
	got := f.nativeConfig(t).Remotes["sc-a"]
	if got.Addr != "https://100.64.0.5:8443" || got.LastWorkingAddress != "" {
		t.Fatalf("native sc-a after address change = %+v", got)
	}
}

func TestNativeMirrorInactive(t *testing.T) {
	cases := map[string]func(t *testing.T, f mirrorFixture){
		"native has no identity": func(t *testing.T, f mirrorFixture) {
			_ = os.Remove(filepath.Join(f.native, "client.crt"))
			// Dedicated stays the shared dir because it has a config.yml.
		},
		"native carries the marker": func(t *testing.T, f mirrorFixture) {
			writeTestFile(t, filepath.Join(f.native, sharedIncusMarker), nil)
		},
		"env opt-out": func(t *testing.T, f mirrorFixture) {
			t.Setenv(NativeMirrorEnv, "0")
		},
		"config opt-out": func(t *testing.T, f mirrorFixture) {
			off := false
			if err := SaveSandcastleConfig(DefaultConfigPath(), SandcastleConfig{IncusNativeMirror: &off}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
			setup(t, f)
			before := readTestFile(t, filepath.Join(f.native, "config.yml"))
			report := syncMirror(t)
			if report.Active || report.Reason == "" {
				t.Fatalf("report = %+v, want inactive with a reason", report)
			}
			if got := readTestFile(t, filepath.Join(f.native, "config.yml")); got != before {
				t.Fatal("inactive mirror wrote the native config")
			}
		})
	}
}

// The env var wins over the config file in both directions.
func TestNativeMirrorEnvOverridesConfig(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	off := false
	if err := SaveSandcastleConfig(DefaultConfigPath(), SandcastleConfig{IncusNativeMirror: &off}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(NativeMirrorEnv, "1")
	if report := syncMirror(t); !report.Active {
		t.Fatalf("report = %+v, want active", report)
	}
	if _, ok := f.nativeConfig(t).Remotes["sc-a"]; !ok {
		t.Fatal("sc-a not mirrored")
	}
}

func TestNativeMirrorDryRunWritesNothing(t *testing.T) {
	f := newMirrorFixture(t, map[string]string{"sc-a": "https://100.64.0.1:8443"})
	before := readTestFile(t, filepath.Join(f.native, "config.yml"))
	report, err := SyncNativeIncusMirror(true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Added, ",") != "sc-a" {
		t.Fatalf("dry run added = %v, want sc-a", report.Added)
	}
	if got := readTestFile(t, filepath.Join(f.native, "config.yml")); got != before {
		t.Fatal("dry run wrote the native config")
	}
	if _, err := os.Stat(filepath.Join(f.native, "clientcerts")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote clientcerts")
	}
}
