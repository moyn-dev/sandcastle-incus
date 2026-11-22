package images

import (
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
)

func testAdmin() config.Admin {
	admin := config.AdminDefaults()
	admin.Remote = "big"
	// The remote-build feature produces the custom Sandcastle images; the
	// package defaults are stock upstream images (no prebuilt image required).
	admin.Images = config.Images{Base: "sandcastle/base:latest", AI: "sandcastle/ai:latest", Dev: "sandcastle/dev:latest"}
	return admin
}

func TestPlanRemoteBuildBaseRefs(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template: "base",
		Version:  "0.1.0-5-gabc1234",
	})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	if plan.ImageLatestRef != "ghcr.io/thieso2/sandcastle-base:latest" {
		t.Errorf("latest ref = %q", plan.ImageLatestRef)
	}
	if plan.ImageVersncRef != "ghcr.io/thieso2/sandcastle-base:0.1.0-5-gabc1234" {
		t.Errorf("versioned ref = %q", plan.ImageVersncRef)
	}
	if plan.Alias != "sandcastle/base:latest" {
		t.Errorf("alias = %q", plan.Alias)
	}
	if plan.GHCRUser != "thieso2" {
		t.Errorf("ghcr user = %q", plan.GHCRUser)
	}
	if plan.BaseRef != "" {
		t.Errorf("base ref should be empty for base template, got %q", plan.BaseRef)
	}
	wantImport := []string{
		"incus", "image", "copy",
		"ghcr:thieso2/sandcastle-base:0.1.0-5-gabc1234",
		"local:", "--alias", "sandcastle/base:latest", "--reuse", "--copy-aliases",
	}
	if strings.Join(plan.ImportCommand, " ") != strings.Join(wantImport, " ") {
		t.Errorf("import command = %v", plan.ImportCommand)
	}
}

func TestPlanRemoteBuildAIFromImmutableBase(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template:      "ai",
		Version:       "0.2.0",
		CodexVersion:  "1.2.3",
		ClaudeVersion: "4.5.6",
		GeminiVersion: "7.8.9",
	})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	if plan.BaseRef != "ghcr.io/thieso2/sandcastle-base:0.2.0" {
		t.Errorf("AI base ref = %q (want immutable base of same version)", plan.BaseRef)
	}
	if !strings.Contains(plan.BuildScript, "SANDCASTLE_BASE_IMAGE=ghcr.io/thieso2/sandcastle-base:0.2.0") {
		t.Errorf("build script missing immutable base build-arg:\n%s", plan.BuildScript)
	}
	for _, want := range []string{"CODEX_CLI_VERSION=1.2.3", "CLAUDE_CODE_VERSION=4.5.6", "GEMINI_CLI_VERSION=7.8.9"} {
		if !strings.Contains(plan.BuildScript, want) {
			t.Errorf("build script missing %q", want)
		}
	}
}

func TestPlanRemoteBuildDevFromUbuntuNotBase(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template:      "dev",
		Version:       "0.2.0",
		CodexVersion:  "1.2.3",
		ClaudeVersion: "4.5.6",
	})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	if plan.BaseRef != "" {
		t.Errorf("dev is FROM ubuntu:26.04 directly, want empty BaseRef, got %q", plan.BaseRef)
	}
	if plan.Alias != "sandcastle/dev:latest" {
		t.Errorf("alias = %q", plan.Alias)
	}
	for _, want := range []string{"CODEX_CLI_VERSION=1.2.3", "CLAUDE_CODE_VERSION=4.5.6"} {
		if !strings.Contains(plan.BuildScript, want) {
			t.Errorf("build script missing %q", want)
		}
	}
	if strings.Contains(plan.BuildScript, "GEMINI_CLI_VERSION") {
		t.Errorf("dev image build should not pass GEMINI_CLI_VERSION:\n%s", plan.BuildScript)
	}
	if strings.Contains(plan.BuildScript, "SANDCASTLE_BASE_IMAGE") {
		t.Errorf("dev image build should not pass SANDCASTLE_BASE_IMAGE:\n%s", plan.BuildScript)
	}
}

func TestPlanRemoteBuildDevRequiresCodexAndClaudeButNotGemini(t *testing.T) {
	_, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{Template: "dev", Version: "0.2.0"})
	if err == nil {
		t.Fatal("expected error when dev versions are missing")
	}
	if !strings.Contains(err.Error(), "codex-version") || !strings.Contains(err.Error(), "claude-version") {
		t.Fatalf("error = %q", err)
	}
	if strings.Contains(err.Error(), "gemini-version") {
		t.Fatalf("dev image build should not require --gemini-version: %q", err)
	}
}

func TestPlanRemoteBuildAIRequiresVersions(t *testing.T) {
	_, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{Template: "ai", Version: "0.2.0"})
	if err == nil {
		t.Fatal("expected error when AI versions are missing")
	}
}

func TestPlanRemoteBuildRequireClean(t *testing.T) {
	_, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template:     "base",
		Version:      "0.1.0-dirty",
		Dirty:        true,
		RequireClean: true,
	})
	if err == nil {
		t.Fatal("expected --require-clean to reject a dirty tree")
	}
	if !strings.Contains(err.Error(), "require-clean") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPlanRemoteBuildScriptPushesBothTags(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{Template: "base", Version: "v9"})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	script := plan.BuildScript
	for _, want := range []string{
		"podman login --username 'thieso2' --password-stdin ghcr.io < " + builderTokenPath,
		"podman push 'ghcr.io/thieso2/sandcastle-base:v9'",
		"podman push 'ghcr.io/thieso2/sandcastle-base:latest'",
		"podman logout ghcr.io",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("build script missing %q:\n%s", want, script)
		}
	}
}

func TestPlanRemoteBuildNoPushOmitsLoginAndImport(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template: "base", Version: "v1", NoPush: true, NoImport: true,
	})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	if strings.Contains(plan.BuildScript, "podman login") {
		t.Errorf("--no-push should not log in:\n%s", plan.BuildScript)
	}
	if strings.Contains(plan.BuildScript, "podman push") {
		t.Errorf("--no-push should not push:\n%s", plan.BuildScript)
	}
	if plan.ImportCommand != nil {
		t.Errorf("--no-import should not produce an import command: %v", plan.ImportCommand)
	}
}

func TestPlanRemoteBuildCustomRepo(t *testing.T) {
	plan, err := PlanRemoteBuild(testAdmin(), RemoteBuildRequest{
		Template: "base", Version: "v1", GHCRRepo: "ghcr.io/acme/",
	})
	if err != nil {
		t.Fatalf("PlanRemoteBuild: %v", err)
	}
	if plan.ImageLatestRef != "ghcr.io/acme/sandcastle-base:latest" {
		t.Errorf("latest ref = %q", plan.ImageLatestRef)
	}
	if plan.GHCRUser != "acme" {
		t.Errorf("ghcr user = %q", plan.GHCRUser)
	}
	if plan.ImportCommand[3] != "ghcr:acme/sandcastle-base:v1" {
		t.Errorf("import source = %q", plan.ImportCommand[3])
	}
}

func TestSanitizeTag(t *testing.T) {
	cases := map[string]string{
		"0.1.0-5-gabc": "0.1.0-5-gabc",
		"feature/x":    "feature-x",
		"":             "unknown",
		"v1.2.3-dirty": "v1.2.3-dirty",
	}
	for in, want := range cases {
		if got := sanitizeTag(in); got != want {
			t.Errorf("sanitizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlanBuilderAppliance(t *testing.T) {
	app, err := PlanBuilderAppliance(testAdmin(), "")
	if err != nil {
		t.Fatalf("PlanBuilderAppliance: %v", err)
	}
	if app.Remote != "big" || app.Project != "sc-build" || app.Instance != "sc-builder" {
		t.Errorf("appliance = %+v", app)
	}
}
