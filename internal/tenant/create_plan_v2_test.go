package tenant

import (
	"encoding/base64"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"gopkg.in/yaml.v2"
)

func v2TestAdmin() config.Admin {
	return config.Admin{
		Remote:                "big",
		StoragePool:           "default",
		CIDRPool:              "10.249.0.0/16",
		IncusProjectPrefix:    "sc2",
		InfrastructureProject: "sc-infra",
		Images:                config.Images{Base: "base", AI: "ai", Dev: "dev"},
	}
}

// Re-provisioning an existing tenant must scope the enrollment token to EVERY
// existing app project, default first — only-the-default locked a fresh client
// certificate out of every project created since first login.
func TestPlanCreateV2RestrictedProjectsUnionExisting(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{
		Reference: "acme",
		// unsorted, with the default duplicated and a blank entry
		ExistingProjects: []string{"sc2-acme-work", "sc2-acme-default", "", "sc2-acme-builder"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sc2-acme-default", "sc2-acme-builder", "sc2-acme-work"}
	if !reflect.DeepEqual(plan.RestrictedProjects, want) {
		t.Fatalf("RestrictedProjects = %v, want %v", plan.RestrictedProjects, want)
	}
}

func TestPlanCreateV2Names(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.InfraProject != "sc2-acme" {
		t.Fatalf("InfraProject = %q", plan.InfraProject)
	}
	if plan.DefaultProject != "sc2-acme-default" {
		t.Fatalf("DefaultProject = %q", plan.DefaultProject)
	}
	if plan.Bridge != "sc2-acme" {
		t.Fatalf("Bridge = %q", plan.Bridge)
	}
	if plan.SidecarInstance != "sidecar" {
		t.Fatalf("SidecarInstance = %q", plan.SidecarInstance)
	}
	if plan.DNSSuffix != "acme" {
		t.Fatalf("DNSSuffix = %q", plan.DNSSuffix)
	}
	if len(plan.RestrictedProjects) != 1 || plan.RestrictedProjects[0] != "sc2-acme-default" {
		t.Fatalf("RestrictedProjects = %v", plan.RestrictedProjects)
	}
	if plan.StoragePool != "default" {
		t.Fatalf("StoragePool = %q, want default", plan.StoragePool)
	}
	// The Dev Image alias must sync into the project's local Incus image
	// aliases alongside Base and AI, so `--image <dev-alias>` resolves without
	// a fully-qualified <remote>:<fingerprint> reference.
	if want := []string{"base", "ai", "dev"}; !reflect.DeepEqual(plan.ImageAliases, want) {
		t.Fatalf("ImageAliases = %v, want %v", plan.ImageAliases, want)
	}
}

// A Dev Image alias that happens to match Base or AI's must not appear twice
// in the synced set — uniqueImageAliases dedupes the same way it always has.
func TestPlanCreateV2ImageAliasesDeduplicated(t *testing.T) {
	admin := v2TestAdmin()
	admin.Images.Dev = admin.Images.Base
	plan, err := PlanCreateV2(admin, CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"base", "ai"}; !reflect.DeepEqual(plan.ImageAliases, want) {
		t.Fatalf("ImageAliases = %v, want %v (deduplicated)", plan.ImageAliases, want)
	}
}

func TestPlanCreateV2PreferredCIDRReused(t *testing.T) {
	// Re-provisioning an existing tenant reuses its /24 rather than allocating
	// a fresh one from the pool.
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", PreferredCIDR: "10.249.7.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.PrivateCIDR != "10.249.7.0/24" {
		t.Fatalf("PrivateCIDR = %q, want 10.249.7.0/24 (reused)", plan.PrivateCIDR)
	}
	if plan.GatewayAddress != "10.249.7.1" || plan.DNSAddress != "10.249.7.3" {
		t.Fatalf("role addresses off the reused CIDR: gw=%q dns=%q", plan.GatewayAddress, plan.DNSAddress)
	}
}

func TestPlanCreateV2PreferredCIDROutsidePoolRejected(t *testing.T) {
	// A preferred CIDR outside the install's pool means the reuse scan picked
	// up a foreign install's tenant (e.g. a v1 bridge on the same host) — that
	// must fail at planning, not as a dnsmasq bind error at bridge creation.
	_, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", PreferredCIDR: "10.248.1.0/24"})
	if err == nil {
		t.Fatal("want error for preferred CIDR outside pool 10.249.0.0/16")
	}
	if !strings.Contains(err.Error(), "outside the tenant CIDR pool") {
		t.Fatalf("err = %v, want pool-containment error", err)
	}
}

func TestPlanCreateV2RoleAddresses(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(plan.GatewayAddress, ".1") {
		t.Fatalf("GatewayAddress = %q, want .1", plan.GatewayAddress)
	}
	if !strings.HasSuffix(plan.TailscaleAddress, ".2") {
		t.Fatalf("TailscaleAddress = %q, want .2", plan.TailscaleAddress)
	}
	if !strings.HasSuffix(plan.DNSAddress, ".3") {
		t.Fatalf("DNSAddress = %q, want .3", plan.DNSAddress)
	}
	if !strings.HasPrefix(plan.PrivateCIDR, "10.249.") {
		t.Fatalf("PrivateCIDR = %q, want 10.249.x", plan.PrivateCIDR)
	}
}

func TestPlanCreateV2FlatDNSZone(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	var corefile string
	for _, f := range plan.DNSFiles {
		if strings.HasSuffix(f.Path, "Corefile") {
			corefile = f.Content
		}
	}
	if corefile == "" {
		t.Fatal("no Corefile in plan")
	}
	// Zone named after the suffix; the zone is the ONLY authority (ADR-0018) —
	// no fallthrough and no gateway-dnsmasq forwarding.
	if !strings.Contains(corefile, "acme:53") {
		t.Fatalf("Corefile missing acme zone: %q", corefile)
	}
	if strings.Contains(corefile, "fallthrough") {
		t.Fatalf("Corefile must not fall through to dnsmasq: %q", corefile)
	}
	if strings.Contains(corefile, "forward . "+plan.GatewayAddress) {
		t.Fatalf("Corefile must not forward the zone to the gateway: %q", corefile)
	}
}

// The plan must describe the /.sc shared-scripts volume set (spec #127) as
// data: two layers with the correct per-layer writability — platform read-only
// to machines, local read-write — at the fixed mount paths.
func TestPlanCreateV2SCVolumes(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]SCVolume{}
	for _, v := range plan.SCVolumes {
		byPath[v.Path] = v
	}
	platform, ok := byPath[SCPlatformPath]
	if !ok {
		t.Fatalf("plan has no /.sc platform layer: %+v", plan.SCVolumes)
	}
	if !platform.ReadOnly || platform.Volume != V2SCPlatformVolumeName {
		t.Fatalf("platform layer must be read-only volume %q: %+v", V2SCPlatformVolumeName, platform)
	}
	local, ok := byPath[SCLocalPath]
	if !ok {
		t.Fatalf("plan has no /.sc local layer: %+v", plan.SCVolumes)
	}
	if local.ReadOnly || local.Volume != V2SCLocalVolumeName {
		t.Fatalf("local layer must be read-write volume %q: %+v", V2SCLocalVolumeName, local)
	}
	if len(plan.SCVolumes) != 2 {
		t.Fatalf("SCVolumes = %+v, want exactly the two layers", plan.SCVolumes)
	}
}

func TestPlanCreateV2GeneratesCA(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.TenantCA.CertificatePEM) == 0 || len(plan.TenantCA.PrivateKeyPEM) == 0 {
		t.Fatal("expected tenant CA material")
	}
}

func TestPlanCreateV2RejectsBadTenant(t *testing.T) {
	if _, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "Bad Name"}); err == nil {
		t.Fatal("expected error for invalid tenant")
	}
}

// The boot cloud-init generalizes per-instance identity BEFORE sshd starts, so a
// machine launched from an `sc image save` base gets fresh SSH host keys /
// machine-id rather than the source machine's. Order matters: generalize, then
// ssh enable, then caddy setup.
func TestV2DefaultProfileUserDataGeneralizesBeforeSSH(t *testing.T) {
	data := V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")

	for _, want := range []string{
		"/usr/local/sbin/sandcastle-generalize",
		"- [/usr/local/sbin/sandcastle-generalize]",
		"- [systemctl, enable, --now, ssh]",
		"- [/usr/local/sbin/sandcastle-caddy-setup]",
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("user-data missing %q:\n%s", want, data)
		}
	}

	genRun := strings.Index(data, "- [/usr/local/sbin/sandcastle-generalize]")
	sshRun := strings.Index(data, "- [systemctl, enable, --now, ssh]")
	caddyRun := strings.Index(data, "- [/usr/local/sbin/sandcastle-caddy-setup]")
	if !(genRun < sshRun && sshRun < caddyRun) {
		t.Fatalf("runcmd order wrong: generalize=%d ssh=%d caddy=%d", genRun, sshRun, caddyRun)
	}

	// The generalize script must regenerate host identity and drop the stale leaf.
	for _, want := range []string{"ssh-keygen -A", "/etc/machine-id", "/etc/ssh/ssh_host_", "/etc/sandcastle/tls/cert.pem"} {
		if !strings.Contains(machineGeneralizeScript, want) {
			t.Fatalf("generalize script missing %q", want)
		}
	}
}

// `sc create --bare`: the machine gets its canonical hostname and a Caddy
// serving the tenant-CA leaf, and NOTHING that lets anyone log in. Each absence
// below is a promise of the flag, so each is asserted separately.
func TestV2BareUserDataHasNoWayIn(t *testing.T) {
	data := V2BareUserData("default.acme", "http://10.0.0.3:9443")

	// An ABSENT users: key would make cloud-init create the distro default
	// user — the empty list is what makes "no user" true.
	if !strings.Contains(data, "\nusers: []\n") {
		t.Fatalf("bare user-data must pin users to the empty list:\n%s", data)
	}
	for _, forbidden := range []string{"ssh_authorized_keys", "openssh-server", "sudo", "systemctl, enable, --now, ssh"} {
		if strings.Contains(data, forbidden) {
			t.Fatalf("bare user-data must not carry %q:\n%s", forbidden, data)
		}
	}
	// The shell shims exist to serve interactive sessions there are none of.
	if strings.Contains(data, "/etc/ssh/sshrc") || strings.Contains(data, "/etc/bash.bashrc") {
		t.Fatalf("bare user-data must not bake the shell shims:\n%s", data)
	}

	// Identity + certificates, the two things it does promise.
	for _, want := range []string{
		"## template: jinja",
		"fqdn: {{ v1.local_hostname }}.default.acme",
		"prefer_fqdn_over_hostname: true",
		"FQDN={{ v1.local_hostname }}.default.acme",
		"SIGNER=http://10.0.0.3:9443",
		"HOME=" + BareMachineHome,
		"- [/usr/local/sbin/sandcastle-caddy-setup]",
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("bare user-data missing %q:\n%s", want, data)
		}
	}

	// caddy-setup apt-installs Caddy; without a warm cache its first
	// apt-get install fails and the machine serves no HTTPS at all.
	if !strings.Contains(data, "package_update: true") {
		t.Fatalf("bare user-data must refresh the package cache before caddy-setup:\n%s", data)
	}

	genRun := strings.Index(data, "- [/usr/local/sbin/sandcastle-generalize]")
	caddyRun := strings.Index(data, "- [/usr/local/sbin/sandcastle-caddy-setup]")
	if genRun < 0 || genRun > caddyRun {
		t.Fatalf("generalize must run before caddy-setup (it drops the stale leaf): gen=%d caddy=%d", genRun, caddyRun)
	}

	// The document is hand-rolled YAML; a syntax slip would only surface as a
	// machine that boots with nothing configured. Parse it, and read `users`
	// back as a list rather than trusting the string match above.
	rendered := strings.ReplaceAll(data, "{{ v1.local_hostname }}", "machine")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("bare user-data is not valid YAML: %v\n%s", err, data)
	}
	users, ok := doc["users"]
	if !ok {
		t.Fatalf("bare user-data has no users key — cloud-init would create the default user:\n%s", data)
	}
	if list, isList := users.([]any); !isList || len(list) != 0 {
		t.Fatalf("users must parse as an empty list, got %#v", users)
	}
}

// A bare machine bakes the same stable boot shims as every other machine, so a
// /.sc platform payload update reaches it too (ADR-0022) — never inline bodies.
func TestV2BareUserDataBakesBootShims(t *testing.T) {
	data := V2BareUserData("default.acme", "http://10.0.0.3:9443")

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/usr/local/sbin/sandcastle-generalize", SCGeneralizeShim},
		{"/usr/local/sbin/sandcastle-caddy-setup", SCCaddySetupShim},
	} {
		encoded := base64.StdEncoding.EncodeToString([]byte(tc.want))
		if !strings.Contains(data, "content: "+encoded) {
			t.Fatalf("bare user-data does not bake the %s shim:\n%s", tc.path, data)
		}
	}
	// The script bodies live in the payload, not in cloud-init.
	if strings.Contains(data, "apt-get install") || strings.Contains(data, "tls/leaf") {
		t.Fatalf("bare user-data must not inline the caddy-setup body:\n%s", data)
	}
}

// `sc create --image <dev-alias>`: unlike --bare, a Dev Image machine keeps
// its login user, SSH key and sshd — it is a full interactive dev
// environment reached over SSH — but (also unlike the default profile) has no
// HTTPS ingress at all.
func TestV2DevUserDataKeepsLoginDropsCaddy(t *testing.T) {
	data := V2DevUserData("dev", "ssh-ed25519 AAAA", "default.acme")

	// The login promise --bare withholds: a real user, its key, and sshd.
	for _, want := range []string{
		"- name: dev",
		"ssh_authorized_keys:\n      - ssh-ed25519 AAAA",
		"openssh-server",
		"- [systemctl, enable, --now, ssh]",
		"## template: jinja",
		"fqdn: {{ v1.local_hostname }}.default.acme",
		"prefer_fqdn_over_hostname: true",
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("dev user-data missing %q:\n%s", want, data)
		}
	}

	// The Caddy/TLS ingress promise the Dev Image withholds: no leaf fetch, no
	// reverse proxy, and — since generalize exists only to prep for that leaf
	// fetch — no generalize either (lines 64-87 of V2DefaultProfileUserData
	// drop as one unit).
	for _, forbidden := range []string{
		"sandcastle-caddy-setup",
		"sandcastle-generalize",
		"SIGNER=",
		"package_update: true",
	} {
		if strings.Contains(data, forbidden) {
			t.Fatalf("dev user-data must not carry %q:\n%s", forbidden, data)
		}
	}

	assertCloudConfigYAML(t, data)
}

// A Dev Image machine bakes the same stable /.sc boot shims as every other
// machine, so a platform payload update reaches it too (ADR-0022).
func TestV2DevUserDataBakesSCShims(t *testing.T) {
	data := V2DevUserData("dev", "ssh-ed25519 AAAA", "default.acme")

	for _, want := range []string{
		"path: /etc/ssh/sshrc",
		"path: /etc/zsh/zshrc",
		"path: /etc/bash.bashrc",
		SCShimMarker,
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("dev user-data missing %q:\n%s", want, data)
		}
	}
}

// Without a signer URL (identity unknown) there is no Caddy/generalize wiring —
// just ssh — so the fallback path stays minimal.
func TestV2DefaultProfileUserDataNoSignerIsMinimal(t *testing.T) {
	data := V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "", "", "")
	if strings.Contains(data, "sandcastle-generalize") || strings.Contains(data, "sandcastle-caddy-setup") {
		t.Fatalf("fallback user-data should not wire generalize/caddy:\n%s", data)
	}
	if !strings.Contains(data, "- [systemctl, enable, --now, ssh]") {
		t.Fatalf("fallback user-data should still enable ssh:\n%s", data)
	}
}

// Machines carry only stable /.sc shims (ADR-0022): both profile branches bake
// guarded sourcing stubs at the fixed OS paths — platform first, local second,
// each `-r`-guarded so a missing payload fails safe — and NO inline script
// bodies (those live in the platform payload and update centrally).
func TestV2DefaultProfileUserDataBakesSCShims(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"ingress", V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")},
		{"minimal", V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "", "", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range []string{
				"path: /etc/ssh/sshrc",
				"path: /etc/zsh/zshrc",
				"path: /etc/bash.bashrc",
				"append: true",
				SCShimMarker,
				"[ -r " + SCPlatformPath + "/" + SCPayloadSSHRCPath + " ] && . " + SCPlatformPath + "/" + SCPayloadSSHRCPath,
				"[ -r " + SCLocalPath + "/" + SCPayloadSSHRCPath + " ] && . " + SCLocalPath + "/" + SCPayloadSSHRCPath,
				"[ -r " + SCPlatformPath + "/" + SCPayloadShellRCPath + " ] && . " + SCPlatformPath + "/" + SCPayloadShellRCPath,
				"[ -r " + SCLocalPath + "/" + SCPayloadShellRCPath + " ] && . " + SCLocalPath + "/" + SCPayloadShellRCPath,
			} {
				if !strings.Contains(tc.data, want) {
					t.Fatalf("user-data missing %q:\n%s", want, tc.data)
				}
			}
			// The shims must source platform BEFORE local (local overrides).
			platform := strings.Index(tc.data, SCPlatformPath+"/"+SCPayloadSSHRCPath)
			local := strings.Index(tc.data, SCLocalPath+"/"+SCPayloadSSHRCPath)
			if !(platform >= 0 && platform < local) {
				t.Fatalf("sshrc shim must source platform before local:\n%s", tc.data)
			}
			// No inline script bodies: the agent-forwarding logic must NOT be
			// baked into the machine any more.
			for _, forbidden := range []string{
				`ln -sf "$SSH_AUTH_SOCK"`,
				`export SSH_AUTH_SOCK=`,
			} {
				if strings.Contains(tc.data, forbidden) {
					t.Fatalf("user-data must bake shims, not inline bodies (%q):\n%s", forbidden, tc.data)
				}
			}
			assertCloudConfigYAML(t, tc.data)
		})
	}
}

// The boot-time consumers (generalize + caddy-setup) are baked as stable /.sc
// shims too: the b64-embedded write_files carry the shim bodies, never the
// script bodies — those ship in the platform payload and update centrally.
func TestV2DefaultProfileUserDataBakesBootShims(t *testing.T) {
	data := V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")

	for name, shim := range map[string]string{
		"generalize":  SCGeneralizeShim,
		"caddy-setup": SCCaddySetupShim,
	} {
		if !strings.Contains(data, base64.StdEncoding.EncodeToString([]byte(shim))) {
			t.Fatalf("user-data does not embed the %s boot shim:\n%s", name, data)
		}
	}
	for name, body := range map[string]string{
		"generalize":  machineGeneralizeScript,
		"caddy-setup": caddyIngressSetupScript,
	} {
		if strings.Contains(data, base64.StdEncoding.EncodeToString([]byte(body))) {
			t.Fatalf("user-data must not inline the %s script body (it lives in the payload)", name)
		}
	}
	// The boot shims wait for the volume mount (VM virtiofs can lag early
	// cloud-init) before the fail-safe no-op.
	for _, shim := range []string{SCGeneralizeShim, SCCaddySetupShim} {
		if !strings.Contains(shim, "sleep 1") || !strings.Contains(shim, SCShimMarker) {
			t.Fatalf("boot shim lost its mount-wait or marker:\n%s", shim)
		}
	}
	// And the payload ships both bodies.
	files, _ := PlatformPayload()
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Content
	}
	if byPath[SCPayloadGeneralizePath] != machineGeneralizeScript {
		t.Fatalf("payload %s is not the generalize script", SCPayloadGeneralizePath)
	}
	if byPath[SCPayloadCaddySetupPath] != caddyIngressSetupScript {
		t.Fatalf("payload %s is not the caddy-setup script", SCPayloadCaddySetupPath)
	}
}

// The single most important /.sc unit test (spec #127): every /.sc/platform
// path a baked shim sources must be produced by the platform-payload builder,
// so a shim can never point at a script the payload doesn't ship.
func TestSCShimPayloadContract(t *testing.T) {
	produced := map[string]bool{}
	files, _ := PlatformPayload()
	for _, f := range files {
		produced[SCPlatformPath+"/"+f.Path] = true
	}
	sourced := regexp.MustCompile(regexp.QuoteMeta(SCPlatformPath) + `/[^\s\]]+`)
	shims := SCSSHRCShim + SCShellRCShim + SCGeneralizeShim + SCCaddySetupShim
	matches := sourced.FindAllString(shims, -1)
	if len(matches) == 0 {
		t.Fatalf("shims source no platform paths:\n%s", shims)
	}
	for _, path := range matches {
		if !produced[path] {
			t.Fatalf("shim sources %s but the payload builder does not produce it (payload: %v)", path, files)
		}
	}
}

// zsh is the default login shell (issue: "use zsh by default"): the profile
// must set /bin/zsh and install the zsh package so a fresh machine has it.
func TestV2DefaultProfileUserDataDefaultsToZsh(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"ingress", V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")},
		{"minimal", V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "", "", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.data, "shell: /bin/zsh") {
				t.Fatalf("login shell should be /bin/zsh:\n%s", tc.data)
			}
			if strings.Contains(tc.data, "shell: /bin/bash") {
				t.Fatalf("login shell should not be bash:\n%s", tc.data)
			}
			// zsh must be installed so /bin/zsh exists on a stock machine.
			pkgs := tc.data[strings.Index(tc.data, "packages:"):]
			if !strings.Contains(pkgs[:strings.Index(pkgs, "\nwrite_files:")], "- zsh") {
				t.Fatalf("packages must install zsh:\n%s", tc.data)
			}
		})
	}
}

// The `sc fix` backfill/check scripts must be built from the SAME shims the
// profile bakes and the SAME payload content the builder ships — one source of
// truth, so a repaired machine matches a fresh one. The two load-bearing
// agent-forwarding guards live in the payload and must survive there.
func TestSSHAgentForwardScriptsShareShimAndPayloadContent(t *testing.T) {
	backfill := SSHAgentForwardBackfillScript()
	check := SSHAgentForwardCheckScript()

	// The payload keeps the two load-bearing guards.
	files, _ := PlatformPayload()
	payload := ""
	for _, f := range files {
		payload += f.Content
	}
	if !strings.Contains(payload, `ln -sf "$SSH_AUTH_SOCK" "$HOME/.ssh/ssh_auth_sock"`) {
		t.Fatalf("payload lost the republish body:\n%s", payload)
	}
	if !strings.Contains(payload, `[ -h "$HOME/.ssh/ssh_auth_sock" ]`) {
		t.Fatalf("payload lost the -h consume guard:\n%s", payload)
	}

	// Backfill installs the same stable shims the profile bakes.
	for _, want := range []string{SCShimMarker, "/etc/ssh/sshrc", "/etc/zsh/zshrc", "/etc/bash.bashrc"} {
		if !strings.Contains(backfill, want) {
			t.Fatalf("backfill missing %q:\n%s", want, backfill)
		}
	}
	// Check is read-only (no writes to system files).
	if strings.Contains(check, "cat >") || strings.Contains(check, ">>") || strings.Contains(check, "ln -sf") {
		t.Fatalf("check script must not mutate:\n%s", check)
	}
	// Backfill detects (does not rewrite) the self-link trap; check flags it too.
	for _, s := range []string{backfill, check} {
		if !strings.Contains(s, "ssh_auth_sock_known") {
			t.Fatalf("script should account for the legacy self-link trap:\n%s", s)
		}
	}
	if !strings.Contains(check, "agent-forwarding: OK") || !strings.Contains(check, "agent-forwarding: NEEDS FIX") {
		t.Fatalf("check script must print a status verdict:\n%s", check)
	}
}

// assertCloudConfigYAML parses the rendered user-data as YAML to catch the
// indentation faults that make cloud-init silently drop write_files entries.
// The `## template: jinja` and `#cloud-config` comment lines are valid YAML
// comments, so the whole document parses as-is.
func assertCloudConfigYAML(t *testing.T, data string) {
	t.Helper()
	// `{{ v1.local_hostname }}` is a jinja expression cloud-init renders before
	// parsing; the literal `{{` is not valid YAML, so stand it in first.
	rendered := strings.ReplaceAll(data, "{{ v1.local_hostname }}", "machine")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("rendered user-data is not valid YAML: %v\n%s", err, data)
	}
	files, ok := doc["write_files"].([]any)
	if !ok {
		t.Fatalf("write_files missing or wrong type:\n%s", data)
	}
	want := map[string]bool{"/etc/ssh/sshrc": false, "/etc/zsh/zshrc": false, "/etc/bash.bashrc": false}
	for _, f := range files {
		if m, ok := f.(map[any]any); ok {
			if p, ok := m["path"].(string); ok {
				if _, tracked := want[p]; tracked {
					want[p] = true
				}
			}
		}
	}
	for path, seen := range want {
		if !seen {
			t.Fatalf("write_files did not parse an entry for %s:\n%s", path, data)
		}
	}
}

// ADR-0018: the Tenant DNS Suffix is tenant-chosen (default: tenant name) and
// immutable across re-provisioning.
func TestPlanCreateV2DNSSuffix(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", DNSSuffix: "corp"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DNSSuffix != "corp" {
		t.Fatalf("DNSSuffix = %q, want corp", plan.DNSSuffix)
	}

	// default: tenant name
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DNSSuffix != "acme" {
		t.Fatalf("DNSSuffix = %q, want acme", plan.DNSSuffix)
	}

	// re-provision reuses the stored suffix
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", ExistingDNSSuffix: "corp"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DNSSuffix != "corp" {
		t.Fatalf("DNSSuffix = %q, want the existing corp", plan.DNSSuffix)
	}

	// immutable: differing explicit suffix is rejected
	if _, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", DNSSuffix: "other", ExistingDNSSuffix: "corp"}); err == nil {
		t.Fatal("expected immutability error")
	}

	// multi-label still rejected (single label for now)
	if _, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", DNSSuffix: "corp.internal"}); err == nil {
		t.Fatal("expected single-label validation error")
	}

	// public TLDs stay denied
	if _, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", DNSSuffix: "dev"}); err == nil {
		t.Fatal("expected public-TLD denial")
	}
}

// #134: a blank unix user / SSH key on the request means "keep what the
// tenant has" — the stored values are the reuse fallback, and only an
// explicit request replaces them. Without this, an admin `tenant create`
// re-run without --unix-user/--ssh-key re-rendered every app project's
// default profile with user dev and an empty key, breaking SSH tenant-wide.
func TestPlanCreateV2ReusesStoredUserAndKey(t *testing.T) {
	// blank request reuses the stored values
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{
		Reference:        "acme",
		ExistingUnixUser: "sc",
		ExistingSSHKey:   "ssh-ed25519 AAAA me@box",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProfileUser != "sc" {
		t.Fatalf("DefaultProfileUser = %q, want the stored sc", plan.DefaultProfileUser)
	}
	if plan.SSHPublicKey != "ssh-ed25519 AAAA me@box" {
		t.Fatalf("SSHPublicKey = %q, want the stored key", plan.SSHPublicKey)
	}

	// an explicit request wins over the stored values
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{
		Reference:        "acme",
		UnixUser:         "alice",
		SSHPublicKey:     "ssh-ed25519 BBBB new@box",
		ExistingUnixUser: "sc",
		ExistingSSHKey:   "ssh-ed25519 AAAA me@box",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProfileUser != "alice" || plan.SSHPublicKey != "ssh-ed25519 BBBB new@box" {
		t.Fatalf("explicit request must win: user=%q key=%q", plan.DefaultProfileUser, plan.SSHPublicKey)
	}

	// nothing stored, nothing requested: the dev default still applies
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProfileUser != DefaultV2UnixUser {
		t.Fatalf("DefaultProfileUser = %q, want %q", plan.DefaultProfileUser, DefaultV2UnixUser)
	}
}

func TestPlanCreateV2InitialProject(t *testing.T) {
	// the chosen name replaces "default" everywhere it is derived (issue #93).
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", InitialProject: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProjectShort != "web" {
		t.Fatalf("DefaultProjectShort = %q, want web", plan.DefaultProjectShort)
	}
	if plan.DefaultProject != "sc2-acme-web" {
		t.Fatalf("DefaultProject = %q, want sc2-acme-web", plan.DefaultProject)
	}
	if len(plan.RestrictedProjects) != 1 || plan.RestrictedProjects[0] != "sc2-acme-web" {
		t.Fatalf("RestrictedProjects = %v, want [sc2-acme-web]", plan.RestrictedProjects)
	}

	// default: "default"
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProjectShort != "default" || plan.DefaultProject != "sc2-acme-default" {
		t.Fatalf("default plan short=%q full=%q", plan.DefaultProjectShort, plan.DefaultProject)
	}

	// re-provision reuses the stored name
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", ExistingDefaultProject: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProjectShort != "web" {
		t.Fatalf("DefaultProjectShort = %q, want the existing web", plan.DefaultProjectShort)
	}

	// NOT immutable: an explicit request wins over the stored value.
	plan, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", InitialProject: "api", ExistingDefaultProject: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProjectShort != "api" {
		t.Fatalf("DefaultProjectShort = %q, want api (request wins)", plan.DefaultProjectShort)
	}

	// invalid project name is rejected as terminal (no retry can fix bad input).
	if _, err = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "acme", InitialProject: "Bad Name"}); err == nil {
		t.Fatal("expected invalid-project-name error")
	} else if !IsTerminalProvisionError(err) {
		t.Fatalf("err = %v, want a terminal provision error", err)
	}
}

// ADR-0027 §5.1: a private project's profile is byte-identical to the
// pre-feature rendering — MODE is absent and every consumer defaults it to
// private, so pre-feature Machines and private projects share one contract.
func TestV2ProfileUserDataPrivateProjectUnchanged(t *testing.T) {
	legacy := V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")
	private := V2ProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "", "http://10.0.0.3:9443")
	if legacy != private {
		t.Fatalf("private project rendering drifted from the legacy profile:\n%s\n---\n%s", legacy, private)
	}
	if strings.Contains(private, "MODE=") {
		t.Fatalf("private profile carries a MODE line:\n%s", private)
	}
	if !strings.Contains(private, "fqdn: {{ v1.local_hostname }}.default.acme\n") || !strings.Contains(private, "      FQDN={{ v1.local_hostname }}.default.acme\n      SIGNER=http://10.0.0.3:9443\n      HOME=/home/dev\n") {
		t.Fatalf("private identity lines changed:\n%s", private)
	}
}

// A zone project's profile names the machine <machine>.<Project Domain> and
// hands caddy-setup MODE=zone; SIGNER stays for the Tenant CA trust step.
func TestV2ProfileUserDataZoneProject(t *testing.T) {
	data := V2ProfileUserData("dev", "ssh-ed25519 AAAA", "zp", "acme", " baum.hase.de ", "http://10.0.0.3:9443")
	if !strings.HasPrefix(data, "## template: jinja\n#cloud-config\nfqdn: {{ v1.local_hostname }}.baum.hase.de\nprefer_fqdn_over_hostname: true\n") {
		t.Fatalf("zone identity header:\n%s", data)
	}
	wantEnv := "  - path: /etc/sandcastle/machine.env\n    permissions: '0644'\n    content: |\n      FQDN={{ v1.local_hostname }}.baum.hase.de\n      MODE=zone\n      SIGNER=http://10.0.0.3:9443\n      HOME=/home/dev\n"
	if !strings.Contains(data, wantEnv) {
		t.Fatalf("zone machine.env:\n%s", data)
	}
	if strings.Contains(data, "zp.acme") {
		t.Fatalf("zone profile still carries the private name:\n%s", data)
	}
	// Everything else — shims, generalize, caddy-setup, runcmd — is the same
	// as the private profile once the identity lines are swapped back.
	private := V2ProfileUserData("dev", "ssh-ed25519 AAAA", "zp", "acme", "", "http://10.0.0.3:9443")
	normalized := strings.ReplaceAll(strings.ReplaceAll(data, ".baum.hase.de", ".zp.acme"), "      MODE=zone\n", "")
	if normalized != private {
		t.Fatalf("zone profile differs beyond identity + MODE:\n%s\n---\n%s", normalized, private)
	}
}

// A zone project without a signer (no sidecar address) still gets the zone
// identity: the Project Domain alone selects the jinja header.
func TestV2ProfileUserDataZoneProjectWithoutSigner(t *testing.T) {
	data := V2ProfileUserData("dev", "ssh-ed25519 AAAA", "", "", "baum.hase.de", "")
	if !strings.HasPrefix(data, "## template: jinja\n#cloud-config\nfqdn: {{ v1.local_hostname }}.baum.hase.de\n") {
		t.Fatalf("header:\n%s", data)
	}
	if strings.Contains(data, "machine.env") {
		t.Fatalf("no-signer profile wrote machine.env:\n%s", data)
	}
}
