package localtrust

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Store interface {
	InstallCA(context.Context, Plan, []byte) (Result, error)
	UninstallCA(context.Context, Plan) (Result, error)
}

func NewPlatformStore() Store {
	if dir := os.Getenv("SANDCASTLE_TRUST_DIR"); dir != "" {
		return FileStore{Dir: dir}
	}
	return CommandStore{GOOS: runtime.GOOS}
}

type FileStore struct {
	Dir string
}

func (s FileStore) InstallCA(ctx context.Context, plan Plan, certPEM []byte) (Result, error) {
	if len(certPEM) == 0 {
		return Result{}, fmt.Errorf("tenant CA certificate is empty")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return Result{}, err
	}
	target := filepath.Join(s.Dir, CertFilename(plan))
	if err := os.WriteFile(target, certPEM, 0o644); err != nil {
		return Result{}, err
	}
	return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "file", Action: "install", Target: target}, nil
}

func (s FileStore) UninstallCA(ctx context.Context, plan Plan) (Result, error) {
	target := filepath.Join(s.Dir, CertFilename(plan))
	removed := true
	if err := os.Remove(target); err != nil {
		if !os.IsNotExist(err) {
			return Result{}, err
		}
		removed = false
	}
	return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "file", Action: "uninstall", Target: target, Removed: removed}, nil
}

type CommandStore struct {
	GOOS string
	// LinuxDir and LinuxUpdate override the detected LinuxTrustLayout;
	// LinuxUpdate defaults to update-ca-certificates when only LinuxDir is set.
	LinuxDir     string
	LinuxUpdate  string
	RunCommand   func(context.Context, string, ...string) ([]byte, error)
	EffectiveUID func() int
}

func (s CommandStore) InstallCA(ctx context.Context, plan Plan, certPEM []byte) (Result, error) {
	if len(certPEM) == 0 {
		return Result{}, fmt.Errorf("tenant CA certificate is empty")
	}
	switch s.GOOS {
	case "darwin":
		return s.installDarwin(ctx, plan, certPEM)
	case "linux":
		return s.installLinux(ctx, plan, certPEM)
	default:
		return Result{}, fmt.Errorf("local trust install is not supported on %s", s.GOOS)
	}
}

func (s CommandStore) UninstallCA(ctx context.Context, plan Plan) (Result, error) {
	switch s.GOOS {
	case "darwin":
		keychain := s.darwinTrustKeychain()
		name, args := "security", []string{"delete-certificate", "-c", plan.TrustName, keychain}
		if output, err := s.runCommand(ctx, name, args...); err != nil {
			return Result{}, fmt.Errorf("remove macOS trust certificate: %w: %s", err, string(output))
		}
		// `security delete-certificate` fails when no such certificate exists, so
		// reaching here means one was removed.
		return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "darwin", Action: "uninstall", Target: keychain, Removed: true}, nil
	case "linux":
		target := s.linuxTrustPath(plan)
		escalated, removed, err := s.removeTrustFile(ctx, target)
		if err != nil {
			return Result{}, err
		}
		if err := s.runUpdateCACertificates(ctx, escalated); err != nil {
			return Result{}, err
		}
		return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "linux", Action: "uninstall", Target: target, Removed: removed}, nil
	default:
		return Result{}, fmt.Errorf("local trust uninstall is not supported on %s", s.GOOS)
	}
}

func (s CommandStore) installDarwin(ctx context.Context, plan Plan, certPEM []byte) (Result, error) {
	keychain := s.darwinTrustKeychain()
	installed, err := s.darwinCertificateInstalled(ctx, plan, certPEM, keychain)
	if err != nil {
		return Result{}, err
	}
	if installed {
		return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "darwin", Action: "install", Target: keychain}, nil
	}
	tmp, err := os.CreateTemp("", "sandcastle-ca-*.crt")
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(certPEM); err != nil {
		tmp.Close()
		return Result{}, err
	}
	if err := tmp.Close(); err != nil {
		return Result{}, err
	}
	name, args := "security", []string{"add-trusted-cert", "-r", "trustRoot", "-k", keychain, tmp.Name()}
	if output, err := s.runCommand(ctx, name, args...); err != nil {
		return Result{}, fmt.Errorf("install macOS trust certificate: %w: %s", err, string(output))
	}
	return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "darwin", Action: "install", Target: keychain}, nil
}

func (s CommandStore) darwinCertificateInstalled(ctx context.Context, plan Plan, certPEM []byte, keychain string) (bool, error) {
	output, err := s.commandOutput(ctx, "security", "find-certificate", "-a", "-p", keychain)
	if err != nil {
		return false, nil
	}
	return containsPEMCertificate(output, certPEM), nil
}

func (s CommandStore) darwinTrustKeychain() string {
	if path := strings.TrimSpace(os.Getenv("SANDCASTLE_DARWIN_TRUST_KEYCHAIN")); path != "" {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	}
	return "/Library/Keychains/System.keychain"
}

func (s CommandStore) installLinux(ctx context.Context, plan Plan, certPEM []byte) (Result, error) {
	target := s.linuxTrustPath(plan)
	escalated, err := s.writeTrustFile(ctx, target, certPEM)
	if err != nil {
		return Result{}, err
	}
	if err := s.runUpdateCACertificates(ctx, escalated); err != nil {
		return Result{}, err
	}
	return Result{Reference: plan.Reference, TrustName: plan.TrustName, Platform: "linux", Action: "install", Target: target}, nil
}

// writeTrustFile writes the CA into the system trust directory. The system
// directory is root-owned, but `sc` is a user command — so try the direct write
// first (it succeeds when running as root, or when LinuxDir points somewhere the
// user owns) and fall back to `sudo` only on a permission error. Escalating just
// this operation keeps the rest of the command running as the invoking user, so
// the Sandcastle login config in $HOME stays reachable (plain `sudo sc …` resets
// $HOME and loses it). Reports whether escalation was used, so the follow-up
// update-ca-certificates runs with the same privileges.
func (s CommandStore) writeTrustFile(ctx context.Context, target string, certPEM []byte) (bool, error) {
	err := writeFileDirect(target, certPEM)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, fs.ErrPermission) {
		return false, err
	}
	tmp, tmpErr := os.CreateTemp("", "sandcastle-ca-*.crt")
	if tmpErr != nil {
		return false, tmpErr
	}
	defer os.Remove(tmp.Name())
	if _, writeErr := tmp.Write(certPEM); writeErr != nil {
		tmp.Close()
		return false, writeErr
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return false, closeErr
	}
	output, sudoErr := s.runCommand(ctx, "sudo", "install", "-D", "-m", "0644", tmp.Name(), target)
	if sudoErr != nil {
		return false, fmt.Errorf("install tenant CA into %s needs root: %w: %s", filepath.Dir(target), sudoErr, string(output))
	}
	return true, nil
}

func writeFileDirect(target string, certPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, certPEM, 0o644)
}

// removeTrustFile deletes the CA, escalating only when the direct unlink is
// refused. Reports (escalated, removed): "removed" is false when there was
// nothing to remove, so the caller can say so instead of reporting success.
func (s CommandStore) removeTrustFile(ctx context.Context, target string) (bool, bool, error) {
	err := os.Remove(target)
	if err == nil {
		return false, true, nil
	}
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if !errors.Is(err, fs.ErrPermission) {
		return false, false, err
	}
	// A root-owned directory refuses the unlink before revealing whether the
	// file exists, so check before escalating: an absent CA is not "removed".
	if _, statErr := os.Stat(target); os.IsNotExist(statErr) {
		return false, false, nil
	}
	output, sudoErr := s.runCommand(ctx, "sudo", "rm", "-f", target)
	if sudoErr != nil {
		return false, false, fmt.Errorf("remove tenant CA from %s needs root: %w: %s", filepath.Dir(target), sudoErr, string(output))
	}
	return true, true, nil
}

// LinuxTrustLayout is where a distribution keeps locally added trust anchors and
// the command that folds them into the system bundle. The two families differ:
// Debian's ca-certificates reads /usr/local/share/ca-certificates via
// update-ca-certificates, while p11-kit based distros (Arch, Fedora/RHEL) read
// their own anchors directory via update-ca-trust — and on those, a file in the
// Debian directory is silently ignored.
type LinuxTrustLayout struct {
	Dir    string
	Update string
}

var linuxTrustLayouts = []LinuxTrustLayout{
	{Dir: "/etc/ca-certificates/trust-source/anchors", Update: "update-ca-trust"}, // Arch
	{Dir: "/etc/pki/ca-trust/source/anchors", Update: "update-ca-trust"},          // Fedora, RHEL
	{Dir: "/etc/pki/trust/anchors", Update: "update-ca-certificates"},             // openSUSE
}

var debianTrustLayout = LinuxTrustLayout{Dir: "/usr/local/share/ca-certificates", Update: "update-ca-certificates"}

// DetectLinuxTrustLayout picks the layout whose anchors directory exists,
// falling back to Debian's. Probe the anchors directory rather than the refresh
// command: update-ca-certificates sits in /usr/sbin, off an unprivileged PATH,
// and Debian's own directory can exist on other distros as a stray.
func DetectLinuxTrustLayout() LinuxTrustLayout {
	return detectLinuxTrustLayout(func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.IsDir()
	})
}

func detectLinuxTrustLayout(isDir func(string) bool) LinuxTrustLayout {
	for _, layout := range linuxTrustLayouts {
		if isDir(layout.Dir) {
			return layout
		}
	}
	return debianTrustLayout
}

func (s CommandStore) linuxLayout() LinuxTrustLayout {
	if s.LinuxDir != "" {
		update := s.LinuxUpdate
		if update == "" {
			update = debianTrustLayout.Update
		}
		return LinuxTrustLayout{Dir: s.LinuxDir, Update: update}
	}
	return DetectLinuxTrustLayout()
}

func (s CommandStore) linuxTrustPath(plan Plan) string {
	return filepath.Join(s.linuxLayout().Dir, CertFilename(plan))
}

// runUpdateCACertificates refreshes the system bundle. When the trust file
// itself needed root, so does this. Otherwise try it directly and escalate only
// if the direct call is refused — note that update-ca-certificates lives in
// /usr/sbin, which is absent from a non-root PATH, so "not found" is a
// privilege symptom here rather than a missing package.
func (s CommandStore) runUpdateCACertificates(ctx context.Context, escalated bool) error {
	if escalated {
		return s.updateCACertificates(ctx, true)
	}
	err := s.updateCACertificates(ctx, false)
	if err == nil || !needsRoot(err) {
		return err
	}
	return s.updateCACertificates(ctx, true)
}

func (s CommandStore) updateCACertificates(ctx context.Context, escalated bool) error {
	name, args := s.linuxLayout().Update, []string(nil)
	if escalated {
		name, args = "sudo", []string{name}
	}
	output, err := s.runCommand(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("update CA certificates: %w: %s", err, string(output))
	}
	return nil
}

// needsRoot reports whether an exec failure is explained by a lack of
// privileges: either the command was refused, or it was not found because the
// sbin directories holding it are not on an unprivileged PATH.
func needsRoot(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

func (s CommandStore) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.RunCommand != nil {
		return s.RunCommand(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return nil, cmd.Run()
}

func (s CommandStore) commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.RunCommand != nil {
		return s.RunCommand(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).Output()
}

func containsPEMCertificate(haystack []byte, needle []byte) bool {
	target, _ := pem.Decode(needle)
	if target == nil {
		return false
	}
	for {
		var block *pem.Block
		block, haystack = pem.Decode(haystack)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, target.Bytes) {
			return true
		}
	}
}
