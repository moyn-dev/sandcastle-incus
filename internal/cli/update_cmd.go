package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/cidr"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// newUpdateCommand is the tenant-facing `sc update` (#124 §3): one status
// table covering the sc CLI (vs the GitHub latest release), the caller's
// tenant sidecar (vs the deployment's version), and each visible project's
// shared /.sc platform payload. Always user-initiated — never automatic.
func newUpdateCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var check, yes bool
	var pin string
	command := &cobra.Command{
		Use:   "update",
		Short: "Check for updates and apply them (CLI binary and your sidecar)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// CLI target: resolve the wanted release (latest, or a pinned tag —
			// rollback is just pinning an older tag).
			checker := &update.Checker{StatePath: updateStatePath(), Token: update.TokenFromEnv()}
			release, releaseErr := checker.ResolveRelease(ctx, update.NormalizeTag(pin))
			if releaseErr != nil {
				fmt.Fprintf(config.stderr, "note: could not reach GitHub for the latest release: %v\n", releaseErr)
			}
			cliCurrent := "v" + strings.TrimPrefix(version, "v")
			cliWanted := release.TagName
			brewManaged := update.IsBrewManaged()
			cliOutdated := releaseErr == nil && cliWanted != cliCurrent &&
				(pin != "" || update.IsNewer(cliWanted, version))
			if update.IsDevBuild(version) && pin == "" {
				// A dev/snapshot build has no release to compare against; only an
				// explicit --version pin updates it.
				cliOutdated = false
			}

			// Sidecar target: current from the signer's version header (a local
			// call), wanted = the deployment's version from the auth-app headers.
			// The row is shown whenever a deployment is configured — even when
			// probes fail it reads "unknown" rather than silently vanishing.
			deploymentConfigured := commandAuthHostname(config, "") != "" ||
				strings.TrimSpace(config.adminConfig.Broker) != ""
			deployment, deploymentReachable := probeDeploymentVersion(ctx, config)
			sidecarCurrent := probeSidecarVersion(ctx, config)
			sidecarKnown := deployment != ""
			sidecarOutdated := sidecarKnown && (sidecarCurrent == "" || update.IsNewer(deployment, sidecarCurrent))

			// Agent skill copies sc installed (`sc skill install`): compared
			// against the skill embedded in this binary. Only managed copies
			// are listed; a missing or hand-placed one is not sc's to touch.
			skillRows := skillUpdateRows(managedSkillTargets(config))
			skillsOutdated := false
			for _, r := range skillRows {
				skillsOutdated = skillsOutdated || r.outdated
			}

			// Project payloads are the central Machine update mechanism: one
			// versioned shared volume per project, mounted by every Machine. A
			// check is read-only and deliberately does not run `sc fix` or SSH to
			// individual Machines.
			payloadRows, payloadCheckErr := projectPayloadUpdateRows(ctx, config)
			payloadsOutdated := false
			for _, r := range payloadRows {
				payloadsOutdated = payloadsOutdated || r.outdated
			}

			// Status table.
			w := tabwriter.NewWriter(config.stdout, 2, 8, 2, ' ', 0)
			fmt.Fprintln(w, "TARGET\tCURRENT\tWANTED\tSTATUS")
			fmt.Fprintf(w, "sc CLI\t%s\t%s\t%s\n", cliCurrent, orUnknown(cliWanted),
				cliStatus(cliOutdated, brewManaged, update.IsDevBuild(version) && pin == "", releaseErr))
			if deploymentConfigured || sidecarCurrent != "" {
				fmt.Fprintf(w, "sidecar\t%s\t%s\t%s\n", orUnknown(sidecarCurrent), orUnknown(deployment), sidecarStatus(sidecarOutdated, sidecarKnown, deploymentReachable))
			}
			for _, r := range skillRows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.name(), r.current, r.wanted, r.status())
			}
			for _, r := range payloadRows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.name(), r.current, r.wanted, r.status())
			}
			if payloadCheckErr != nil {
				fmt.Fprintf(w, "project payloads\tunknown\tunknown\tunknown (%v)\n", payloadCheckErr)
			}
			w.Flush()
			if release.HTMLURL != "" && cliOutdated {
				fmt.Fprintf(config.stdout, "\nRelease notes: %s\n", release.HTMLURL)
			}

			if check {
				return nil
			}
			if !cliOutdated && !sidecarOutdated && !skillsOutdated && !payloadsOutdated {
				fmt.Fprintln(config.stdout, "\nEverything is up to date.")
				return nil
			}
			if !yes {
				ok, err := confirmMissingYesNamed(config, "\nApply the updates above?",
					"refusing to update without confirmation; pass --yes to proceed non-interactively", "update canceled")
				if err != nil || !ok {
					return err
				}
			}

			// Apply: CLI first (so a failed sidecar update still leaves a fresh
			// CLI), then the sidecar via the deployment (broker-delegated).
			if cliOutdated {
				if brewManaged {
					// Never self-replace a Homebrew install: the Caskroom would
					// desynchronize and the next `brew upgrade` silently downgrades.
					fmt.Fprintln(config.stdout, "\nThe CLI is Homebrew-managed. Update it with:\n\n    brew upgrade sandcastle")
				} else if err := selfUpdateCLI(ctx, config, checker, release); err != nil {
					return err
				}
			}
			if sidecarOutdated {
				if err := updateSidecarViaDeployment(ctx, config); err != nil {
					return err
				}
			}
			// Skill copies last and non-fatal: refreshed from the skill
			// embedded in the running binary (a just-replaced CLI brings its
			// own newer skill; the next `sc update` picks that up).
			if skillsOutdated {
				refreshManagedSkills(config.stdout, config.stderr, skillRows, skillHome(config))
			}
			if payloadsOutdated {
				if cliOutdated {
					// The payload is embedded in the executable. This process still
					// contains the old payload after a self-replacement, so never
					// write it while claiming to install the new one.
					fmt.Fprintln(config.stdout, "Project payload updates use the newly installed CLI; rerun `sc update` to apply them.")
				} else {
					statuses, err := config.tenantCreator.SyncVisiblePlatformPayload(ctx, strings.TrimSpace(config.adminConfig.Tenant), false)
					if err != nil {
						return fmt.Errorf("update project payloads: %w", err)
					}
					for _, status := range statuses {
						if status.Changed {
							fmt.Fprintf(config.stdout, "Project payload updated: %s (%s -> %s). All Machines observe it through /.sc.\n", status.IncusProject, orUnknown(status.Before), status.Target)
						}
					}
				}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&check, "check", false, "only show the status table; apply nothing")
	command.Flags().BoolVar(&yes, "yes", false, "apply without prompting")
	command.Flags().StringVar(&pin, "version", "", "pin the CLI to a release tag (vX.Y.Z); an older tag rolls back")
	return command
}

type projectPayloadUpdateRow struct {
	project  string
	current  string
	wanted   string
	outdated bool
}

func (r projectPayloadUpdateRow) name() string { return "platform payload (" + r.project + ")" }

func (r projectPayloadUpdateRow) status() string {
	if r.outdated {
		return "outdated (shared by project Machines)"
	}
	return "current"
}

// projectPayloadUpdateRows checks the current tenant's visible projects. An
// absent tenant is normal before login, so it simply contributes no row.
func projectPayloadUpdateRows(ctx context.Context, config commandConfig) ([]projectPayloadUpdateRow, error) {
	tenantName := strings.TrimSpace(config.adminConfig.Tenant)
	if tenantName == "" {
		return nil, nil
	}
	statuses, err := config.tenantCreator.SyncVisiblePlatformPayload(ctx, tenantName, true)
	if err != nil {
		return nil, err
	}
	rows := make([]projectPayloadUpdateRow, 0, len(statuses))
	for _, status := range statuses {
		rows = append(rows, projectPayloadUpdateRow{
			project:  status.IncusProject,
			current:  orUnknown(status.Before),
			wanted:   orUnknown(status.Target),
			outdated: status.Before != status.Target,
		})
	}
	return rows, nil
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

func cliStatus(outdated, brewManaged, devBuild bool, releaseErr error) string {
	switch {
	case releaseErr != nil:
		return "unknown (release check failed)"
	case outdated && brewManaged:
		return "outdated (brew-managed)"
	case outdated:
		return "outdated"
	case devBuild:
		return "dev build (pin with --version to replace)"
	default:
		return "current"
	}
}

func sidecarStatus(outdated, known, reachable bool) string {
	switch {
	case !known && reachable:
		// The deployment answered but advertised no X-Sandcastle-Version
		// header — an appliance built without a version stamp (a dev/snapshot
		// binary, or one predating the version-exchange feature). It is
		// reachable, so don't cry "unreachable"; say what actually happened.
		return "unknown (deployment reported no version)"
	case !known:
		return "unknown (deployment unreachable)"
	case outdated:
		return "outdated (tenant-managed)"
	default:
		return "current"
	}
}

// selfUpdateCLI downloads the release tarball for this platform, verifies it
// against checksums.txt, and atomically replaces the running binary keeping
// a .bak (#124 §3).
func selfUpdateCLI(ctx context.Context, config commandConfig, checker *update.Checker, release update.Release) error {
	fmt.Fprintf(config.stdout, "\nDownloading %s (%s)...\n", release.TagName, update.AssetName(runtime.GOOS, runtime.GOARCH))
	binary, err := checker.FetchBinary(ctx, release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	if err := update.Apply(exe, binary); err != nil {
		return err
	}
	fmt.Fprintf(config.stdout, "CLI updated to %s (previous kept as .bak).\n", release.TagName)
	return nil
}

// updateSidecarViaDeployment delegates the sidecar update, preferring the
// auth-app token plane (tunnel-friendly) and falling back to the broker's
// mTLS plane — the same routing as login provisioning.
func updateSidecarViaDeployment(ctx context.Context, config commandConfig) error {
	var updatedTo string
	if strings.TrimSpace(config.adminConfig.AuthToken) != "" && commandAuthHostname(config, "") != "" {
		client := authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
		result, err := client.UpdateSidecar(ctx)
		if err != nil {
			return err
		}
		updatedTo = result.BinaryVersion
	} else {
		conn, err := resolveBrokerConnection(config.adminConfig, "", "", "", "")
		if err != nil {
			return err
		}
		var result struct {
			BinaryVersion string `json:"binaryVersion"`
		}
		if err := brokerPost(ctx, conn.Broker, "/v2/sidecar/update", conn.CertFile, conn.KeyFile, struct{}{}, &result); err != nil {
			return err
		}
		updatedTo = result.BinaryVersion
	}
	fmt.Fprintf(config.stdout, "Sidecar updated to %s (sandcastle-tls-sign restarted).\n", orUnknown(updatedTo))
	return nil
}

// probeDeploymentVersion learns the deployment's version from the auth-app's
// response headers on a cheap unauthenticated /healthz call. It returns the
// observed version (or "" when the response carried no version header) and
// whether the deployment answered at all, so the caller can tell "reachable
// but not advertising a version" apart from a genuine connection failure.
// reachable is false when no auth hostname is recorded or the request never
// completes.
func probeDeploymentVersion(ctx context.Context, config commandConfig) (version string, reachable bool) {
	host := commandAuthHostname(config, "")
	if host == "" {
		return "", false
	}
	base := host
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: update.DefaultExchange.WrapTransport(nil)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/healthz", nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	resp.Body.Close()
	deployment, _ := update.DefaultExchange.Observed()
	return deployment, true
}

// probeSidecarVersion asks the tenant's own sidecar signer for its version
// header. The signer address is derived from the recorded Broker URL's
// gateway address (first host of the tenant /24 → the DNS/signer role
// address). "" when underivable or unreachable — shown as "unknown".
func probeSidecarVersion(ctx context.Context, config commandConfig) string {
	broker := strings.TrimSpace(config.adminConfig.Broker)
	if broker == "" {
		return ""
	}
	parsed, err := url.Parse(broker)
	if err != nil {
		return ""
	}
	gateway, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !gateway.Is4() {
		return ""
	}
	prefix, err := gateway.Prefix(24)
	if err != nil {
		return ""
	}
	signer, err := cidr.RoleAddress(prefix, cidr.DNSHostOctet)
	if err != nil {
		return ""
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s:%d/healthz", signer, incusx.SidecarTLSSignPort), nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get(update.HeaderVersion)
}
