package images

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
)

// Image Builder appliance defaults. The Image Builder runs a neutral upstream
// image (not a Sandcastle Image it produces) in its own admin-managed Incus
// project, builds with rootless podman, and publishes to the Image Registry.
// See docs/adr/0010-image-builder-appliance.md.
const (
	DefaultBuildProject    = "sc-build"
	DefaultBuilderInstance = "sc-builder"
	DefaultBuilderVolume   = "sc-builder-cache"
	DefaultBuilderImage    = "images:debian/13"
	DefaultGHCRRemote      = "ghcr"
	DefaultGHCRRepo        = "ghcr.io/thieso2"

	ghcrRegistryHost = "ghcr.io"
	ghcrRegistryURL  = "https://ghcr.io"

	// In-appliance layout. The build runs rootless as builderUser; the cache
	// volume is mounted at the podman storage root so layers survive rebuilds.
	builderUser         = "build"
	builderHome         = "/home/build"
	builderStorageMount = "/home/build/.local/share/containers"
	builderBuildRoot    = "/home/build/build"
	builderTokenPath    = "/run/ghcr-token"
)

// BuilderAppliance describes the Image Builder instance and its placement.
type BuilderAppliance struct {
	Remote       string `json:"remote"`
	Project      string `json:"project"`
	Instance     string `json:"instance"`
	Volume       string `json:"volume"`
	StoragePool  string `json:"storagePool"`
	Image        string `json:"image"`
	StorageMount string `json:"storageMount"`
	BuildDir     string `json:"buildDir"`
}

// Qualified returns the remote:project-qualified instance reference for incus.
func (a BuilderAppliance) instanceRef() string {
	return a.Remote + ":" + a.Instance
}

type RemoteBuildRequest struct {
	Template       string
	Remote         string
	GHCRRepo       string // owner prefix, e.g. ghcr.io/thieso2
	GHCRUser       string
	Platform       string
	CodexVersion   string
	ClaudeVersion  string
	GeminiVersion  string
	RequireClean   bool
	NoPush         bool
	NoImport       bool
	RebuildBuilder bool

	// Version/Dirty are normally derived from git; tests may inject them.
	Version string
	Dirty   bool
}

type RemoteBuildPlan struct {
	Template        string           `json:"template"`
	Builder         BuilderAppliance `json:"builder"`
	GHCRRemote      string           `json:"ghcrRemote"`
	GHCRRepo        string           `json:"ghcrRepo"`
	GHCRUser        string           `json:"ghcrUser"`
	ImageLatestRef  string           `json:"imageLatestRef"`
	ImageVersncRef  string           `json:"imageVersionedRef"`
	BaseRef         string           `json:"baseRef,omitempty"`
	Version         string           `json:"version"`
	Dirty           bool             `json:"dirty"`
	Alias           string           `json:"alias"`
	ContextDir      string           `json:"contextDir"`
	WorkDir         string           `json:"workDir,omitempty"`
	Platform        string           `json:"platform,omitempty"`
	BuildArgs       []string         `json:"buildArgs"`
	BuildScript     string           `json:"buildScript"`
	ProvisionScript string           `json:"provisionScript"`
	NoPush          bool             `json:"noPush"`
	NoImport        bool             `json:"noImport"`
	RebuildBuilder  bool             `json:"rebuildBuilder"`
	ImportCommand   []string         `json:"importCommand,omitempty"`
	SyncSourceRef   string           `json:"syncSourceRef,omitempty"`
}

// RemoteImageBuilder executes remote builds and manages the Image Builder
// appliance lifecycle.
type RemoteImageBuilder interface {
	BuildRemote(context.Context, RemoteBuildPlan) (RemoteBuildResult, error)
	ProvisionBuilder(context.Context, BuilderAppliance) error
	BuilderStatus(context.Context, BuilderAppliance) (string, error)
	BuilderDestroy(context.Context, BuilderAppliance, bool) error
}

type RemoteBuildResult struct {
	RemoteBuildPlan
	Pushed   bool `json:"pushed"`
	Imported bool `json:"imported"`
}

// PlanBuilderAppliance returns the Image Builder appliance descriptor for
// lifecycle commands (status/destroy) that do not run a build.
func PlanBuilderAppliance(admin config.Admin, remote string) (BuilderAppliance, error) {
	if err := admin.Validate(); err != nil {
		return BuilderAppliance{}, err
	}
	resolved := firstNonEmpty(strings.TrimSpace(remote), strings.TrimSpace(admin.Remote))
	if resolved == "" {
		return BuilderAppliance{}, fmt.Errorf("remote is required")
	}
	return BuilderAppliance{
		Remote:       resolved,
		Project:      DefaultBuildProject,
		Instance:     DefaultBuilderInstance,
		Volume:       DefaultBuilderVolume,
		StoragePool:  firstNonEmpty(strings.TrimSpace(admin.StoragePool), "default"),
		Image:        DefaultBuilderImage,
		StorageMount: builderStorageMount,
		BuildDir:     builderBuildRoot,
	}, nil
}

// PlanRemoteBuild builds the deterministic parts of a remote image build:
// registry refs, build args, the in-appliance build script, and the import
// command. Appliance/remote provisioning is handled imperatively by the
// executor. See docs/adr/0010-image-builder-appliance.md.
func PlanRemoteBuild(admin config.Admin, request RemoteBuildRequest) (RemoteBuildPlan, error) {
	if err := admin.Validate(); err != nil {
		return RemoteBuildPlan{}, err
	}
	template := strings.ToLower(strings.TrimSpace(request.Template))
	if template != "base" && template != "ai" && template != "dev" {
		return RemoteBuildPlan{}, fmt.Errorf("unknown image template %q", request.Template)
	}

	remote := firstNonEmpty(strings.TrimSpace(request.Remote), strings.TrimSpace(admin.Remote))
	if remote == "" {
		return RemoteBuildPlan{}, fmt.Errorf("remote is required")
	}

	version := strings.TrimSpace(request.Version)
	dirty := request.Dirty
	if version == "" {
		version = gitOutput("describe", "--always", "--dirty")
		if version == "" {
			version = "unknown"
		}
		dirty = strings.HasSuffix(version, "-dirty") || gitOutput("status", "--porcelain") != ""
	}
	if request.RequireClean && dirty {
		return RemoteBuildPlan{}, fmt.Errorf("--require-clean: working tree is dirty (version %q); commit or stash before a canonical build", version)
	}

	repo := strings.TrimSpace(request.GHCRRepo)
	if repo == "" {
		repo = DefaultGHCRRepo
	}
	repo = strings.TrimRight(repo, "/")
	imageName := repo + "/sandcastle-" + template
	latestRef := imageName + ":latest"
	versionedRef := imageName + ":" + sanitizeTag(version)

	alias, err := aliasForTemplate(admin, template)
	if err != nil {
		return RemoteBuildPlan{}, err
	}

	commitDate := gitOutput("log", "-1", "--format=%cI")
	if commitDate == "" {
		commitDate = "unknown"
	}

	plan := RemoteBuildPlan{
		Template: template,
		Builder: BuilderAppliance{
			Remote:       remote,
			Project:      DefaultBuildProject,
			Instance:     DefaultBuilderInstance,
			Volume:       DefaultBuilderVolume,
			StoragePool:  firstNonEmpty(strings.TrimSpace(admin.StoragePool), "default"),
			Image:        DefaultBuilderImage,
			StorageMount: builderStorageMount,
			BuildDir:     builderBuildRoot,
		},
		GHCRRemote:     DefaultGHCRRemote,
		GHCRRepo:       repo,
		GHCRUser:       firstNonEmpty(strings.TrimSpace(request.GHCRUser), ghcrUserFromRepo(repo)),
		ImageLatestRef: latestRef,
		ImageVersncRef: versionedRef,
		Version:        version,
		Dirty:          dirty,
		Alias:          alias,
		ContextDir:     filepath.Join("images", template),
		WorkDir:        repoRoot(),
		Platform:       strings.TrimSpace(request.Platform),
		NoPush:         request.NoPush,
		NoImport:       request.NoImport,
		RebuildBuilder: request.RebuildBuilder,
	}

	// Common build args, mirroring the local Dockerfiles.
	plan.BuildArgs = []string{
		"SANDCASTLE_IMAGE_TEMPLATE=" + template,
		"SANDCASTLE_IMAGE_TAG=" + latestRef,
		"SANDCASTLE_IMAGE_VERSION=" + version,
		"SANDCASTLE_IMAGE_COMMIT_DATE=" + commitDate,
	}

	if template == "ai" {
		codex := strings.TrimSpace(request.CodexVersion)
		claude := strings.TrimSpace(request.ClaudeVersion)
		gemini := strings.TrimSpace(request.GeminiVersion)
		if codex == "" || claude == "" || gemini == "" {
			return RemoteBuildPlan{}, fmt.Errorf("AI image build requires --codex-version, --claude-version, and --gemini-version")
		}
		// AI is built FROM the immutable base tag of the same run (same git
		// version), never a racing :latest. `build-remote all` publishes the
		// base first; standalone `ai` requires that base tag to exist on GHCR.
		plan.BaseRef = repo + "/sandcastle-base:" + sanitizeTag(version)
		plan.BuildArgs = append([]string{
			"SANDCASTLE_BASE_IMAGE=" + plan.BaseRef,
			"CODEX_CLI_VERSION=" + codex,
			"CLAUDE_CODE_VERSION=" + claude,
			"GEMINI_CLI_VERSION=" + gemini,
		}, plan.BuildArgs...)
	}

	if template == "dev" {
		// Unlike ai, dev is FROM ubuntu:26.04 directly (not the Sandcastle base
		// image), so there is no BaseRef/SANDCASTLE_BASE_IMAGE build-arg here.
		codex := strings.TrimSpace(request.CodexVersion)
		claude := strings.TrimSpace(request.ClaudeVersion)
		if codex == "" || claude == "" {
			return RemoteBuildPlan{}, fmt.Errorf("dev image build requires --codex-version and --claude-version")
		}
		plan.BuildArgs = append([]string{
			"CODEX_CLI_VERSION=" + codex,
			"CLAUDE_CODE_VERSION=" + claude,
		}, plan.BuildArgs...)
	}

	plan.ProvisionScript = builderProvisionScript()
	plan.BuildScript = remoteBuildScript(plan)

	if !plan.NoImport {
		// Refresh the host alias from the immutable tag we just published. The
		// incus CLI resolves OCI manifests for the *client* architecture, so on
		// a non-amd64 workstation this copy cannot run locally; it runs on the
		// Incus host (target "local:"), reached over SSH by the executor.
		plan.SyncSourceRef = remote + ":" + alias
		plan.ImportCommand = []string{
			"incus", "image", "copy",
			plan.GHCRRemote + ":" + ghcrPath(versionedRef),
			"local:",
			"--alias", alias,
			"--reuse", "--copy-aliases",
		}
	}

	return plan, nil
}

// remoteBuildScript is the bash script run rootless inside the appliance. The
// GHCR token is read from a tmpfs file (written by a prior stdin step) so it is
// never on argv, in the environment, or persisted to an image layer.
func remoteBuildScript(plan RemoteBuildPlan) string {
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	// incus exec runs in /root (mode 700); cd to a build-readable dir so runuser
	// does not fail with "cannot chdir to /root", and set HOME/XDG_RUNTIME_DIR so
	// rootless podman finds its config and runtime dir.
	b.WriteString("cd " + builderBuildRoot + "\n")
	run := "runuser -u " + builderUser + " -- env HOME=" + builderHome + " XDG_RUNTIME_DIR=/run/user/1000"

	buildArgs := make([]string, 0, len(plan.BuildArgs)*2)
	for _, arg := range plan.BuildArgs {
		buildArgs = append(buildArgs, "--build-arg", shellQuoteArg(arg))
	}
	platform := ""
	if plan.Platform != "" {
		platform = " --platform " + shellQuoteArg(plan.Platform)
	}
	contextDir := builderBuildRoot + "/" + plan.Template
	dockerfile := contextDir + "/Dockerfile"

	if !plan.NoPush {
		b.WriteString(fmt.Sprintf(
			"%s podman login --username %s --password-stdin %s < %s\n",
			run, shellQuoteArg(plan.GHCRUser), ghcrRegistryHost, builderTokenPath,
		))
		b.WriteString("rm -f " + builderTokenPath + "\n")
	}

	// BUILDAH_LAYERS=true forces intermediate-layer caching so an unchanged layer
	// (e.g. the AI image's apt toolchain) is reused across builds on the warm
	// cache volume instead of rebuilt. Combined with the Dockerfile cache mounts,
	// a no-op rebuild is seconds rather than minutes.
	b.WriteString(fmt.Sprintf(
		"%s BUILDAH_LAYERS=true podman build%s -t %s -t %s -f %s %s %s\n",
		run, platform,
		shellQuoteArg(plan.ImageLatestRef),
		shellQuoteArg(plan.ImageVersncRef),
		shellQuoteArg(dockerfile),
		strings.Join(buildArgs, " "),
		shellQuoteArg(contextDir),
	))

	if !plan.NoPush {
		b.WriteString(run + " podman push " + shellQuoteArg(plan.ImageVersncRef) + "\n")
		b.WriteString(run + " podman push " + shellQuoteArg(plan.ImageLatestRef) + "\n")
		b.WriteString(run + " podman logout " + ghcrRegistryHost + " || true\n")
	}
	return b.String()
}

// builderProvisionScript prepares a neutral Debian instance to run rootless
// podman against the mounted cache volume. Idempotent; re-runnable.
func builderProvisionScript() string {
	return `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v podman >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends \
    podman fuse-overlayfs uidmap passt ca-certificates
  rm -rf /var/lib/apt/lists/*
fi
if ! id -u ` + builderUser + ` >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --uid 1000 ` + builderUser + `
fi
grep -q '^` + builderUser + `:' /etc/subuid || echo '` + builderUser + `:100000:65536' >>/etc/subuid
grep -q '^` + builderUser + `:' /etc/subgid || echo '` + builderUser + `:100000:65536' >>/etc/subgid
# install -d sets ownership/mode on each target (idempotent, non-recursive), so
# warm runs do not chown the whole podman cache volume under the storage mount.
install -d -o ` + builderUser + ` -g ` + builderUser + ` ` + builderHome + `/.config ` + builderHome + `/.config/containers
install -d -o ` + builderUser + ` -g ` + builderUser + ` ` + builderStorageMount + `
install -d -o ` + builderUser + ` -g ` + builderUser + ` ` + builderBuildRoot + `
install -d -o ` + builderUser + ` -g ` + builderUser + ` -m 700 /run/user/1000
if [ ! -f ` + builderHome + `/.config/containers/storage.conf ]; then
  cat >` + builderHome + `/.config/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
  chown ` + builderUser + `:` + builderUser + ` ` + builderHome + `/.config/containers/storage.conf
fi
loginctl enable-linger ` + builderUser + ` >/dev/null 2>&1 || true
`
}

// ghcrPath strips the registry host from a full image ref, leaving the
// repository:tag that an `incus image copy ghcr:<path>` expects.
func ghcrPath(ref string) string {
	return strings.TrimPrefix(ref, ghcrRegistryHost+"/")
}

func ghcrUserFromRepo(repo string) string {
	trimmed := strings.TrimPrefix(repo, ghcrRegistryHost+"/")
	if i := strings.Index(trimmed, "/"); i >= 0 {
		trimmed = trimmed[:i]
	}
	return trimmed
}

// shellQuoteArg single-quotes a value for safe embedding in the bash build
// script run inside the appliance.
func shellQuoteArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// sanitizeTag maps a git describe value to a valid OCI tag.
func sanitizeTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}
