package incusx

import (
	"context"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	authapp "github.com/moyn-dev/sandcastle-incus/internal/authapp"
)

// Publishing the Public Route SNI list to a shared front (Spec #111).
//
// With `--route-ingress acme-proxied` the host's :80/:443 belong to another
// appliance (an sc-edge), which forwards route traffic here by SNI. That front
// must know which hostnames to forward, and only the Auth App knows — so the
// list is generated and pushed, never hand-maintained.
//
// The transport is the Incus admin socket the auth-app already holds for
// per-Route proxy devices: write the fragment into the front instance, then
// reload its Caddy in place. No network path to the front, no admin API
// exposed, nothing for an operator to keep in sync.
const (
	// FrontFragmentDir is where fragments land inside the front instance. The
	// front imports the whole directory once, so an install appearing or
	// disappearing needs no edit there.
	FrontFragmentDir = "/etc/caddy/sandcastle"
	// frontCaddyfile is the front's own config, reloaded after each write.
	frontCaddyfile = "/etc/caddy/Caddyfile"
)

// applianceExecServer / applianceFileServer are the slices of the Incus client
// that pushing a file into an instance and running a command there actually
// need. Narrower than TenantResourceServer on purpose: the front is somebody
// else's appliance (an sc-edge), reached with a plain InstanceServer, and no
// image/profile rights are involved.
type applianceExecServer interface {
	ExecInstance(name string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

type applianceFileServer interface {
	applianceExecServer
	CreateInstanceFile(name string, path string, args incus.InstanceFileArgs) error
}

// FrontTarget locates the shared front: an Incus project + instance on the same
// daemon. Zero value means "no front configured" — the install owns the host
// ports itself and nothing is published.
type FrontTarget struct {
	Project  string
	Instance string
}

// ParseFrontTarget reads the --route-front value, "<project>/<instance>" (e.g.
// "infrastructure/sc-edge"). An empty value yields the zero target, which
// disables front publishing; a malformed one is an error rather than a silent
// no-op, because a typo would otherwise leave routes unreachable with nothing
// pointing at why.
func ParseFrontTarget(value string) (FrontTarget, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return FrontTarget{}, nil
	}
	project, instance, found := strings.Cut(value, "/")
	project = strings.TrimSpace(project)
	instance = strings.TrimSpace(instance)
	if !found || project == "" || instance == "" {
		return FrontTarget{}, fmt.Errorf("invalid route front %q: want <project>/<instance>, e.g. infrastructure/sc-edge", value)
	}
	return FrontTarget{Project: project, Instance: instance}, nil
}

// configured reports whether a front is set.
func (t FrontTarget) configured() bool {
	return strings.TrimSpace(t.Project) != "" && strings.TrimSpace(t.Instance) != ""
}

// UpdateFrontRoutes renders this install's caddy-l4 fragment from hostnames and
// publishes it to the configured front, then reloads the front's Caddy. No-op
// without a front.
//
// The upstream in the fragment is this appliance's own address on the shared
// bridge, read live from Incus — the front dials it directly, so a stale
// address would silently black-hole every route.
func (b RouteBackend) UpdateFrontRoutes(ctx context.Context, hostnames []string) error {
	if !b.Front.configured() {
		return nil
	}
	if b.Server == nil {
		return fmt.Errorf("route backend has no Incus connection")
	}
	upstream, err := b.selfAddress()
	if err != nil {
		return err
	}
	fragment := authapp.RenderFrontSNIFragment(
		authapp.FrontMatcherName(b.MachinePrefix),
		upstream+":443",
		hostnames,
	)

	front := b.Server.UseProject(b.Front.Project)
	path := FrontFragmentDir + "/" + frontFragmentName(b.MachinePrefix)
	if err := writeApplianceFile(front, b.Front.Instance, applianceFile{path, []byte(fragment), 0o644}); err != nil {
		return fmt.Errorf("write route fragment to %s/%s: %w", b.Front.Project, b.Front.Instance, err)
	}
	// `caddy reload` talks to the running Caddy's admin API, so this does not
	// restart the front or drop its connections. A config error in the front's
	// own Caddyfile surfaces here rather than being swallowed.
	reload := fmt.Sprintf("caddy reload --config %s --force", frontCaddyfile)
	if err := execSidecar(front, b.Front.Instance, reload); err != nil {
		return fmt.Errorf("reload caddy on %s/%s: %w", b.Front.Project, b.Front.Instance, err)
	}
	return nil
}

// frontFragmentName is the per-install file name, so several installs can share
// one front without overwriting each other.
func frontFragmentName(prefix string) string {
	prefix = strings.TrimSpace(strings.ToLower(prefix))
	if prefix == "" {
		prefix = "sandcastle"
	}
	return prefix + ".caddy"
}

// selfAddress resolves this appliance's own global IPv4 — the address the front
// proxies to.
func (b RouteBackend) selfAddress() (string, error) {
	server := b.Server.UseProject(b.AuthAppProject)
	instance, _, err := server.GetInstance(b.AuthAppInstance)
	if err != nil {
		return "", fmt.Errorf("read auth-app instance %q: %w", b.AuthAppInstance, err)
	}
	address := firstGlobalIPv4(server, b.AuthAppInstance, instance)
	if strings.TrimSpace(address) == "" {
		return "", fmt.Errorf("auth-app instance %q has no global IPv4 for the front to proxy to", b.AuthAppInstance)
	}
	return address, nil
}
