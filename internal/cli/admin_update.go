package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// componentUnits maps a global component kind to the service units its
// update restarts.
var componentUnits = map[string][]string{
	meta.KindAuthApp: {"sandcastle-auth-app.service"},
	meta.KindBroker:  {"sandcastle-broker.service"},
}

// newAdminUpdateCommand is the operator-facing `sc-adm update` (#124 §4):
// by default it updates the global components (auth-app, broker) from the
// wanted GitHub release; --check shows the fleet table from the stamps;
// --tenants/--all-tenants force-roll tenant sidecars (operator override).
func newAdminUpdateCommand(config commandConfig) *cobra.Command {
	var check, yes, allTenants, all bool
	var pin, prefixFlag string
	var tenants []string
	command := &cobra.Command{
		Use:   "update",
		Short: "Update the deployment's global components (and optionally tenant sidecars) from a GitHub release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			creator := config.tenantCreator
			components, err := creator.ListBinaryVersions()
			if err != nil {
				return err
			}
			prefix, err := resolveUpdatePrefix(prefixFlag, config, components)
			if err != nil {
				return err
			}
			scoped := filterInstallComponents(components, prefix, config.adminConfig.InfrastructureProject)

			checker := &update.Checker{Token: update.TokenFromEnv()}
			release, releaseErr := checker.ResolveRelease(ctx, update.NormalizeTag(pin))

			if check {
				renderFleetTable(config, scoped, release.TagName, releaseErr)
				return nil
			}
			if releaseErr != nil {
				return fmt.Errorf("resolve release: %w", releaseErr)
			}

			if all {
				allTenants = true
			}
			targets, err := selectUpdateTargets(scoped, tenants, allTenants)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return fmt.Errorf("no updatable components found for install %q on this admin remote — "+
					"check the remote (SANDCASTLE_REMOTE) and the install (--prefix)", prefix)
			}
			fmt.Fprintf(config.stdout, "Updating to %s:\n", release.TagName)
			for _, t := range targets {
				fmt.Fprintf(config.stdout, "  %s %s/%s\n", t.Kind, t.Project, t.Instance)
			}
			if !yes {
				ok, err := confirmMissingYesNamed(config, "Proceed?",
					"refusing to update without confirmation; pass --yes to proceed non-interactively", "update canceled")
				if err != nil || !ok {
					return err
				}
			}

			// Download once per architecture (appliances are linux; the arch
			// comes from each instance, not from this workstation).
			binaries := map[string][]byte{}
			fetchFor := func(arch string) ([]byte, error) {
				if arch == "" {
					// Never guess: from a darwin/arm64 workstation a GOARCH
					// fallback would push an arm64 binary into an amd64 appliance.
					return nil, fmt.Errorf("instance architecture unknown — cannot pick a release asset")
				}
				if b, ok := binaries[arch]; ok {
					return b, nil
				}
				fmt.Fprintf(config.stdout, "Downloading %s...\n", update.AssetName("linux", arch))
				b, err := checker.FetchBinary(ctx, release, "linux", arch)
				if err != nil {
					return nil, err
				}
				binaries[arch] = b
				return b, nil
			}

			// Per-component apply; keep going on failure and report a summary —
			// the command is idempotent, so a re-run repairs a partial update.
			failed := 0
			for _, t := range targets {
				err := func() error {
					binary, err := fetchFor(t.Architecture)
					if err != nil {
						return err
					}
					if t.Kind == meta.KindSidecar {
						_, err = creator.UpdateTenantSidecar(prefix, t.Tenant, binary, release.TagName)
						return err
					}
					return creator.UpdateApplianceBinary(t.Project, t.Instance, binary, release.TagName, componentUnits[t.Kind]...)
				}()
				if err != nil {
					failed++
					fmt.Fprintf(config.stdout, "  FAIL %s %s/%s: %v\n", t.Kind, t.Project, t.Instance, err)
					continue
				}
				fmt.Fprintf(config.stdout, "  ok   %s %s/%s → %s\n", t.Kind, t.Project, t.Instance, release.TagName)
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d components failed to update — re-run to repair", failed, len(targets))
			}
			fmt.Fprintf(config.stdout, "All %d components updated to %s.\n", len(targets), release.TagName)
			if !all {
				return nil
			}
			return finishUpdateAll(ctx, config, prefix, targets, checker, release)
		},
	}
	command.Flags().StringVar(&prefixFlag, "prefix", "", "install to update when several share this Incus remote; auto-detected when only one is present")
	command.Flags().BoolVar(&check, "check", false, "show the fleet version table; change nothing")
	command.Flags().BoolVar(&yes, "yes", false, "apply without prompting")
	command.Flags().StringVar(&pin, "version", "", "release tag to install (vX.Y.Z; default: latest); an older tag rolls back")
	command.Flags().StringSliceVar(&tenants, "tenants", nil, "also force-roll these tenants' sidecars (normally tenant-managed via sc update)")
	command.Flags().BoolVar(&allTenants, "all-tenants", false, "also force-roll every tenant sidecar")
	command.Flags().BoolVar(&all, "all", false, "everything in one go: global components, every tenant sidecar, every tenant's project profiles re-rendered, then this CLI binary")
	return command
}

// resolveUpdatePrefix decides which install `sc-adm update` acts on. A single
// Incus remote can host several sandcastles (each under its own --prefix), so
// the install must be pinned down before scoping the fleet. Precedence:
//  1. the --prefix flag (explicit operator choice),
//  2. an explicit SANDCASTLE_*_PREFIX env var (back-compat),
//  3. auto-detection from the live fleet: exactly one install ⇒ use it; more
//     than one ⇒ refuse and list them (the operator must pass --prefix); none
//     ⇒ fall back to the configured/default prefix so the downstream
//     "no updatable components" error carries the usual guidance.
//
// Values are normalized to the v2 project prefix; discovered prefixes are
// already v2 (read off <prefix>-infra / <prefix>-broker project names).
func resolveUpdatePrefix(flagVal string, config commandConfig, components []incusx.ComponentVersion) (string, error) {
	if p := strings.TrimSpace(flagVal); p != "" {
		return naming.NormalizeV2Prefix(p), nil
	}
	if envPrefixExplicit() {
		return naming.NormalizeV2Prefix(config.adminConfig.IncusProjectPrefix), nil
	}
	installs := discoverInstallPrefixes(components)
	// The install the user CLI is on wins over "the only one here" when this
	// remote hosts it: `sc admin update` must act on the same deployment
	// `sc ls` lists, even on a remote that carries several.
	// Normalize only a non-empty value: NormalizeV2Prefix("") answers with the
	// default prefix, which would silently match an install actually named
	// that whenever no user CLI install is active.
	if raw := strings.TrimSpace(config.adminConfig.ActiveInstall); raw != "" {
		active := naming.NormalizeV2Prefix(raw)
		for _, install := range installs {
			if install == active {
				fmt.Fprintf(config.stderr, "targeting install %q (the one `sc ls` is on)\n", install)
				return install, nil
			}
		}
	}
	switch len(installs) {
	case 1:
		fmt.Fprintf(config.stderr, "targeting install %q (the only one on this remote)\n", installs[0])
		return installs[0], nil
	case 0:
		return naming.NormalizeV2Prefix(config.adminConfig.IncusProjectPrefix), nil
	default:
		return "", fmt.Errorf("this Incus remote hosts %d sandcastle installs (%s) — pass --prefix to choose one",
			len(installs), strings.Join(installs, ", "))
	}
}

// envPrefixExplicit reports whether the operator set an install prefix via env
// (the same keys config.LoadAdminFromEnv reads). Used to keep the pre-flag
// env-driven behaviour working while still allowing auto-detection when
// nothing was specified at all.
func envPrefixExplicit() bool {
	return strings.TrimSpace(os.Getenv("SANDCASTLE_INCUS_PROJECT_PREFIX")) != "" ||
		strings.TrimSpace(os.Getenv("SANDCASTLE_PROJECT_PREFIX")) != ""
}

// discoverInstallPrefixes reads the distinct install prefixes present in a
// fleet listing, anchored on the global appliances: an auth-app lives in
// "<prefix>-infra" and a broker in "<prefix>-broker". Legacy appliances in the
// unprefixed default projects carry no prefix in their name and are skipped —
// those installs must be targeted with an explicit --prefix.
func discoverInstallPrefixes(components []incusx.ComponentVersion) []string {
	set := map[string]bool{}
	for _, c := range components {
		switch c.Kind {
		case meta.KindAuthApp:
			if p := strings.TrimSuffix(c.Project, "-infra"); p != "" && p != c.Project {
				set[p] = true
			}
		case meta.KindBroker:
			if p := strings.TrimSuffix(c.Project, "-broker"); p != "" && p != c.Project {
				set[p] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// filterInstallComponents keeps the fleet rows belonging to THIS install:
// several sandcastles can share one Incus host (--prefix), and updating a
// neighbour install's appliances would be a surprise.
func filterInstallComponents(components []incusx.ComponentVersion, prefix, infraProject string) []incusx.ComponentVersion {
	infraProject = strings.TrimSpace(infraProject)
	authAppProjects := map[string]bool{
		prefix + "-infra": true,
		// Legacy deploys (sc-adm auth-app deploy without --project) live in
		// "infrastructure" regardless of prefix.
		incusx.AuthAppDefaultProject: true,
	}
	if infraProject != "" {
		authAppProjects[infraProject] = true
	}
	var scoped []incusx.ComponentVersion
	for _, c := range components {
		switch c.Kind {
		case meta.KindAuthApp:
			if authAppProjects[c.Project] {
				scoped = append(scoped, c)
			}
		case meta.KindBroker:
			if c.Project == prefix+"-broker" || c.Project == incusx.BrokerProjectName {
				scoped = append(scoped, c)
			}
		case meta.KindSidecar:
			if c.Tenant != "" && c.Project == prefix+"-"+c.Tenant {
				scoped = append(scoped, c)
			}
		}
	}
	return scoped
}

// selectUpdateTargets picks what a run touches: all global components, plus
// the requested sidecars (--tenants names must exist; --all-tenants takes
// every sidecar in the install).
func selectUpdateTargets(scoped []incusx.ComponentVersion, tenants []string, allTenants bool) ([]incusx.ComponentVersion, error) {
	wanted := map[string]bool{}
	for _, t := range tenants {
		if s := strings.TrimSpace(t); s != "" {
			wanted[s] = true
		}
	}
	var targets []incusx.ComponentVersion
	found := map[string]bool{}
	for _, c := range scoped {
		switch c.Kind {
		case meta.KindAuthApp, meta.KindBroker:
			targets = append(targets, c)
		case meta.KindSidecar:
			if allTenants || wanted[c.Tenant] {
				targets = append(targets, c)
				found[c.Tenant] = true
			}
		}
	}
	var missing []string
	for t := range wanted {
		if !found[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("no sidecar found for tenant(s): %s", strings.Join(missing, ", "))
	}
	return targets, nil
}

// renderFleetTable prints the stamp-based fleet table (#124 §4): one cheap
// listing, works for stopped instances; sidecars are marked tenant-managed.
func renderFleetTable(config commandConfig, components []incusx.ComponentVersion, latestTag string, releaseErr error) {
	if releaseErr != nil {
		fmt.Fprintf(config.stderr, "note: could not reach GitHub for the latest release: %v\n", releaseErr)
	}
	w := tabwriter.NewWriter(config.stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(w, "COMPONENT\tPROJECT/INSTANCE\tVERSION\tSTATE\tNOTES")
	for _, c := range components {
		notes := fleetNotes(c, latestTag)
		name := c.Kind
		if c.Kind == meta.KindSidecar {
			name = "sidecar (" + c.Tenant + ")"
		}
		fmt.Fprintf(w, "%s\t%s/%s\t%s\t%s\t%s\n", name, c.Project, c.Instance, orUnknown(c.BinaryVersion), c.Status, notes)
	}
	w.Flush()
	if latestTag != "" {
		fmt.Fprintf(config.stdout, "\nLatest release: %s\n", latestTag)
	}
	fmt.Fprintln(config.stdout, "The image-builder appliance carries no sandcastle binary (podman-based) — nothing to update there.")
}

func fleetNotes(c incusx.ComponentVersion, latestTag string) string {
	var notes []string
	if c.TenantManaged {
		notes = append(notes, "tenant-managed")
	}
	switch {
	case c.BinaryVersion == "":
		// Missing stamp (pre-#124 deploy): unknown, treated as outdated;
		// the first update self-heals the stamp.
		notes = append(notes, "outdated (no stamp)")
	case latestTag != "" && update.IsNewer(latestTag, c.BinaryVersion):
		notes = append(notes, "outdated")
	case latestTag != "":
		notes = append(notes, "current")
	}
	return strings.Join(notes, ", ")
}

// finishUpdateAll is the tail of `sc-adm update --all`, after the
// components: re-render every updated tenant's project profiles (the
// profile document changes with the release — login shell, packages, the
// RENDERED stamp — and nothing else re-renders it after an update), then
// replace this CLI binary, last, so the whole run is one command. Failures
// are reported per step and do not stop the next; the command stays
// idempotent, so a re-run repairs what failed.
func finishUpdateAll(ctx context.Context, config commandConfig, prefix string, targets []incusx.ComponentVersion, checker *update.Checker, release update.Release) error {
	failed := 0
	renderer, _ := config.tenantMembers.(interface {
		RenderTenantProfilesV2(ctx context.Context, installPrefix string, tenantName string) error
	})
	tenantNames := []string{}
	seen := map[string]bool{}
	for _, t := range targets {
		if t.Kind == meta.KindSidecar && t.Tenant != "" && !seen[t.Tenant] {
			seen[t.Tenant] = true
			tenantNames = append(tenantNames, t.Tenant)
		}
	}
	sort.Strings(tenantNames)
	if renderer == nil && len(tenantNames) > 0 {
		fmt.Fprintln(config.stdout, "  skip profiles: tenant profile renderer is not configured")
	} else {
		for _, tenantName := range tenantNames {
			if err := renderer.RenderTenantProfilesV2(ctx, prefix, tenantName); err != nil {
				failed++
				fmt.Fprintf(config.stdout, "  FAIL profiles %s: %v\n", tenantName, err)
				continue
			}
			fmt.Fprintf(config.stdout, "  ok   profiles %s re-rendered (new machines use the %s document)\n", tenantName, release.TagName)
		}
	}
	switch {
	case update.IsDevBuild(version):
		fmt.Fprintf(config.stdout, "  skip CLI: dev build %s is not replaced\n", version)
	case update.IsBrewManaged():
		fmt.Fprintln(config.stdout, "  skip CLI: installed by Homebrew — run `brew upgrade sandcastle`")
	case version == release.TagName || "v"+version == release.TagName:
		fmt.Fprintf(config.stdout, "  ok   CLI already %s\n", release.TagName)
	default:
		if err := selfUpdateCLI(ctx, config, checker, release); err != nil {
			failed++
			fmt.Fprintf(config.stdout, "  FAIL CLI: %v\n", err)
		} else {
			fmt.Fprintf(config.stdout, "  ok   CLI → %s\n", release.TagName)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d step(s) of --all failed — re-run to repair", failed)
	}
	fmt.Fprintln(config.stdout, "Everything updated. Existing machines keep the document they booted with; sc ls -l shows it under RENDERED.")
	return nil
}
