package tenant

import (
	"strings"
	"testing"
)

// The platform payload is the single source of truth for platform scripts on
// /.sc: it must carry the agent-forwarding republish script and consume
// snippet — built from the SAME shared constants the profile and `sc fix` use,
// never duplicated literals — plus a stable version marker.
func TestPlatformPayloadFilesAndVersion(t *testing.T) {
	files, version := PlatformPayload()

	byPath := map[string]PlatformPayloadFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}

	sshrc, ok := byPath[SCPayloadSSHRCPath]
	if !ok {
		t.Fatalf("payload missing %s: %v", SCPayloadSSHRCPath, files)
	}
	if sshrc.Content != sshAgentRepublishScript {
		t.Fatalf("payload sshrc must be the shared republish script, got:\n%s", sshrc.Content)
	}
	if sshrc.Mode != 0o755 {
		t.Fatalf("payload sshrc mode = %o, want 0755", sshrc.Mode)
	}

	shellRC, ok := byPath[SCPayloadShellRCPath]
	if !ok {
		t.Fatalf("payload missing %s: %v", SCPayloadShellRCPath, files)
	}
	if shellRC.Content != sshAgentConsumeSnippet {
		t.Fatalf("payload shell rc must be the shared consume snippet, got:\n%s", shellRC.Content)
	}

	cloudflared, ok := byPath[SCPayloadCloudflaredPath]
	if !ok {
		t.Fatalf("payload missing %s: %v", SCPayloadCloudflaredPath, files)
	}

	caddy, ok := byPath[SCPayloadCaddyPath]
	if !ok || caddy.Mode != 0o755 || !strings.Contains(caddy.Content, "exec /usr/bin/caddy") {
		t.Fatalf("payload missing usable Caddy launcher %s: %#v", SCPayloadCaddyPath, caddy)
	}
	if cloudflared.Mode != 0o755 || !strings.Contains(cloudflared.Content, "cloudflared-linux-") {
		t.Fatalf("cloudflared payload launcher is not executable/download-capable: %#v", cloudflared)
	}

	if version == "" {
		t.Fatal("payload version is empty")
	}
	marker, ok := byPath[PlatformPayloadVersionFile]
	if !ok {
		t.Fatalf("payload missing the %s marker", PlatformPayloadVersionFile)
	}
	if strings.TrimSpace(marker.Content) != version {
		t.Fatalf("VERSION content %q != version %q", marker.Content, version)
	}
}

// The version is content-derived: identical payloads agree, so repeated calls
// (and two builds of the same scripts) can never disagree on the version.
func TestPlatformPayloadVersionStable(t *testing.T) {
	_, first := PlatformPayload()
	_, second := PlatformPayload()
	if first != second {
		t.Fatalf("version not stable: %q vs %q", first, second)
	}
	if PlatformPayloadVersion() != first {
		t.Fatalf("PlatformPayloadVersion() = %q, want %q", PlatformPayloadVersion(), first)
	}
}
