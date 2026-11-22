package incusx

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/certs"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// Broker appliance layout (mirrors v1's route-broker appliance).
const (
	BrokerProjectName    = "sc2-broker"
	BrokerInstanceName   = "sc2-broker"
	BrokerBinaryPath     = "/usr/local/bin/sandcastle-admin"
	BrokerCertPath       = "/etc/sandcastle/broker/tls.crt"
	BrokerKeyPath        = "/etc/sandcastle/broker/tls.key"
	BrokerEnvPath        = "/etc/sandcastle/broker/env"
	BrokerUnitPath       = "/etc/systemd/system/sandcastle-broker.service"
	BrokerIncusSocket    = "/var/lib/incus/unix.socket"
	BrokerListenInternal = "127.0.0.1:9443"
)

// BootstrapV2Request configures the one-time broker appliance deploy. It is
// meant to run on (or against) the Incus host: the appliance mounts the host's
// admin unix socket, so the broker itself talks to Incus over that socket with
// full rights — no TLS, no remote, no cert enrollment for the server side.
type BootstrapV2Request struct {
	BaseImage    string // system-container base image (alias or fingerprint)
	BinaryPath   string // host path to the sandcastle-admin binary to push
	Bridge       string // bridge the appliance's NIC attaches to (e.g. incusbr0)
	StoragePool  string // storage pool for the appliance root disk
	Hostname     string // DNS name for the self-signed broker cert SAN
	CIDRPool     string // v2 CIDR pool (e.g. 10.249.0.0/16)
	SidecarImage string // system-container base for tenant sidecars
	PublicPort   string // host port to expose (default 9443)
	// The broker is only deployed when it has a reachable host port (acme/none
	// ingress); Cloudflare-tunnel installs skip it entirely (the tenant plane is
	// the auth-app's /api/projects), so there is no "container-internal only"
	// mode here.
	ProjectPrefix string // installation prefix baked into the appliance env (default sc2)
	Project       string // Incus project for the appliance (default BrokerProjectName)
	Instance      string // appliance instance name (default BrokerInstanceName)
}

func (r BootstrapV2Request) project() string {
	if strings.TrimSpace(r.Project) != "" {
		return strings.TrimSpace(r.Project)
	}
	return BrokerProjectName
}

func (r BootstrapV2Request) instance() string {
	if strings.TrimSpace(r.Instance) != "" {
		return strings.TrimSpace(r.Instance)
	}
	return BrokerInstanceName
}

// BootstrapV2 deploys the broker as an appliance and starts it.
func (c TenantCreator) BootstrapV2(ctx context.Context, req BootstrapV2Request) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	if strings.TrimSpace(req.BinaryPath) == "" {
		return fmt.Errorf("binary path is required")
	}
	binary, err := os.ReadFile(req.BinaryPath)
	if err != nil {
		return fmt.Errorf("read binary %s: %w", req.BinaryPath, err)
	}
	port := strings.TrimSpace(req.PublicPort)
	if port == "" {
		port = "9443"
	}

	c.log("ensure broker project " + req.project())
	if err := ensureBrokerProject(server, req.project()); err != nil {
		return err
	}
	psrv := server.UseProject(req.project())

	c.log("launch broker appliance " + req.instance())
	if err := ensureBrokerInstance(psrv, req, port); err != nil {
		return err
	}

	tls, err := certs.GenerateSelfSignedServer("Sandcastle broker", []string{req.Hostname, req.instance(), "localhost"}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("generate broker TLS: %w", err)
	}

	c.log("install broker binary + config")
	files := []brokerFile{
		{BrokerBinaryPath, binary, 0o755},
		{BrokerCertPath, tls.CertificatePEM, 0o644},
		{BrokerKeyPath, tls.PrivateKeyPEM, 0o600},
		{BrokerEnvPath, []byte(brokerEnv(req)), 0o600},
		{BrokerUnitPath, []byte(brokerUnit(req.SidecarImage)), 0o644},
	}
	for _, f := range files {
		if err := writeBrokerFile(psrv, req.instance(), f); err != nil {
			return err
		}
	}
	if err := stampBinaryVersion(psrv, req.instance(), runningBinaryVersion); err != nil {
		return err
	}

	c.log("start broker service")
	start := applianceStartScript([]string{
		"install -d -m 0700 /etc/sandcastle/broker",
	}, "sandcastle-broker.service")
	if err := execSidecar(psrv, req.instance(), start); err != nil {
		return fmt.Errorf("start broker service: %w", err)
	}
	c.log("done — broker on :" + port)
	return nil
}

func ensureBrokerProject(server TenantCreateServer, name string) error {
	if strings.TrimSpace(name) == "" {
		name = BrokerProjectName
	}
	if _, _, err := server.GetProject(name); err == nil {
		return nil
	}
	return server.CreateProject(api.ProjectsPost{
		Name: name,
		ProjectPut: api.ProjectPut{
			Description: "Sandcastle v2 broker appliance",
			Config: api.ConfigMap{
				"features.networks": "false",
				"features.images":   "false",
				"features.profiles": "true",
				meta.KeyKind:        meta.KindBroker,
				meta.KeyVersion:     "2",
			},
		},
	})
}

func ensureBrokerInstance(server TenantResourceServer, req BootstrapV2Request, port string) error {
	if _, _, err := server.GetInstance(req.instance()); err == nil {
		return nil
	}
	source := imageInstanceSource(req.BaseImage)
	devices := api.DevicesMap{
		"root": {"type": "disk", "pool": req.StoragePool, "path": "/"},
		"eth0": {"type": "nic", "nictype": "bridged", "parent": req.Bridge},
		// mount the host admin socket → the broker uses it with full rights
		"incus-socket": {"type": "disk", "source": BrokerIncusSocket, "path": BrokerIncusSocket},
		// expose the broker on the host (the broker is only deployed at all when
		// a reachable host port is wanted — acme/none ingress)
		"broker": {"type": "proxy", "listen": "tcp:0.0.0.0:" + port, "connect": "tcp:" + BrokerListenInternal},
	}
	op, err := server.CreateInstance(api.InstancesPost{
		Name:   req.instance(),
		Type:   "container",
		Start:  true,
		Source: source,
		InstancePut: api.InstancePut{
			Description: "Sandcastle v2 broker",
			// Privileged so the container's root == host root and can use the
			// mounted admin unix socket (owned by host root), matching v1's
			// route-broker appliance.
			Config: api.ConfigMap{
				"security.privileged": "true",
				meta.KeyKind:          meta.KindBroker,
				meta.KeyVersion:       "2",
			},
			Devices:  devices,
			Profiles: []string{},
		},
	})
	if err != nil {
		return fmt.Errorf("create broker appliance: %w", err)
	}
	if err := op.Wait(); err != nil && !isAlreadyRunning(err) {
		return fmt.Errorf("wait for broker appliance: %w", err)
	}
	return waitInstanceRunning(server, req.instance(), 60*time.Second)
}

// isAlreadyRunning reports whether err is Incus's spurious "instance is
// already running" — it surfaces when CreateInstance{Start:true} creates from
// a CACHED image so fast the start op races itself. The instance is up, which
// is the goal, so it's benign.
func isAlreadyRunning(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already running")
}

type brokerFile struct {
	path    string
	content []byte
	mode    int
}

// writeBrokerFile pushes to a temp path and renames over the target — an
// in-place overwrite of a RUNNING executable (redeploy) dies with ETXTBSY
// mid-stream; rename() swaps the directory entry safely (see
// writeApplianceFile).
func writeBrokerFile(server TenantResourceServer, instance string, f brokerFile) error {
	if err := writeInstanceDir(server, instance, f.path); err != nil {
		return err
	}
	tmp := f.path + ".sandcastle-push"
	if err := server.CreateInstanceFile(instance, tmp, incus.InstanceFileArgs{
		Content:   strings.NewReader(string(f.content)),
		Type:      "file",
		Mode:      f.mode,
		WriteMode: "overwrite",
	}); err != nil {
		return err
	}
	return execSidecar(server, instance, fmt.Sprintf("mv -f '%s' '%s'", tmp, f.path))
}

func brokerEnv(req BootstrapV2Request) string {
	pool := req.CIDRPool
	if strings.TrimSpace(pool) == "" {
		pool = "10.249.0.0/16"
	}
	lines := []string{
		"SANDCASTLE_REMOTE=local", // the mounted unix socket
		"SANDCASTLE_STORAGE_POOL=" + req.StoragePool,
		"SANDCASTLE_CIDR_POOL=" + pool,
		"SANDCASTLE_INCUS_PROJECT_PREFIX=" + orDefaultStr(strings.TrimSpace(req.ProjectPrefix), "sc2"),
		"SANDCASTLE_INFRASTRUCTURE_PROJECT=" + req.project(),
		"SANDCASTLE_BASE_IMAGE=" + DefaultApplianceImage,
		"SANDCASTLE_AI_IMAGE=" + DefaultApplianceImage,
	}
	return strings.Join(lines, "\n") + "\n"
}

func brokerUnit(sidecarImage string) string {
	execStart := BrokerBinaryPath + " project broker-serve --listen " + BrokerListenInternal +
		" --cert " + BrokerCertPath + " --key " + BrokerKeyPath
	// Only append --sidecar-image when a value is set; a bare "--sidecar-image"
	// with no argument crash-loops the broker at startup ("flag needs an
	// argument"). Empty means broker-serve falls back to its own default.
	if strings.TrimSpace(sidecarImage) != "" {
		execStart += " --sidecar-image " + strings.TrimSpace(sidecarImage)
	}
	return "[Unit]\nDescription=Sandcastle broker\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nEnvironmentFile=" + BrokerEnvPath + "\n" +
		"ExecStart=" + execStart + "\n" +
		"Restart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
}

// (bootstrap string helpers are covered by broker_bootstrap_test.go)
