package images

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
)

// customImageAdmin returns admin config whose base/AI images are the custom
// Sandcastle aliases the build/sync/import feature is meant to produce. The
// package defaults are stock upstream images (no prebuilt image required), so
// these tests set the custom names explicitly.
func customImageAdmin() config.Admin {
	cfg := config.LoadAdminFromEnv()
	cfg.Images = config.Images{Base: "sandcastle/base:latest", AI: "sandcastle/ai:latest", Dev: "sandcastle/dev:latest"}
	return cfg
}

func TestPlanSyncBaseImage(t *testing.T) {
	plan, err := PlanSync(customImageAdmin(), SyncRequest{SourceRef: "sandcastle/base:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template != "base" {
		t.Fatalf("Template = %q", plan.Template)
	}
	if plan.Alias != "sandcastle/base:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
	if !strings.Contains(plan.Description, "debian-13") {
		t.Fatalf("Description = %q", plan.Description)
	}
}

func TestPlanSyncAIImage(t *testing.T) {
	plan, err := PlanSync(customImageAdmin(), SyncRequest{SourceRef: "sandcastle/ai:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template != "ai" {
		t.Fatalf("Template = %q", plan.Template)
	}
	if plan.Alias != "sandcastle/ai:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
}

func TestPlanSyncRejectsUnknownImage(t *testing.T) {
	_, err := PlanSync(customImageAdmin(), SyncRequest{SourceRef: "other/image:latest"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "base or AI") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanBuildBaseImage(t *testing.T) {
	plan, err := PlanBuild(customImageAdmin(), BuildRequest{Template: "base", Tag: "sandcastle/base:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template != "base" || plan.Tag != "sandcastle/base:debian-13" {
		t.Fatalf("plan = %#v", plan)
	}
	command := strings.Join(plan.Command, " ")
	for _, want := range []string{
		"docker build",
		"-t sandcastle/base:debian-13",
		"-f images/base/Dockerfile",
		"--build-arg SANDCASTLE_IMAGE_TEMPLATE=base",
		"--build-arg SANDCASTLE_IMAGE_TAG=sandcastle/base:debian-13",
		"--build-arg SANDCASTLE_IMAGE_VERSION=",
		"--build-arg SANDCASTLE_IMAGE_COMMIT_DATE=",
		"images/base",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("Command = %q, want %q", command, want)
		}
	}
}

func TestPlanBuildAllowsDockerOrPodmanTools(t *testing.T) {
	for _, tool := range []string{"docker", "podman", "/usr/local/bin/podman"} {
		t.Run(tool, func(t *testing.T) {
			plan, err := PlanBuild(customImageAdmin(), BuildRequest{
				Template: "base",
				Tag:      "sandcastle/base:test",
				Tool:     tool,
			})
			if err != nil {
				t.Fatal(err)
			}
			if plan.Tool != tool {
				t.Fatalf("Tool = %q", plan.Tool)
			}
		})
	}
}

func TestPlanBuildAddsPlatformWhenRequested(t *testing.T) {
	plan, err := PlanBuild(customImageAdmin(), BuildRequest{
		Template: "base",
		Tag:      "sandcastle/base:test",
		Platform: "linux/amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(plan.Command, " ")
	for _, want := range []string{
		"docker build",
		"-t sandcastle/base:test",
		"-f images/base/Dockerfile",
		"--platform linux/amd64",
		"--build-arg SANDCASTLE_IMAGE_TAG=sandcastle/base:test",
		"images/base",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("Command = %q, want %q", command, want)
		}
	}
}

func TestPlanBuildRejectsUnsupportedTool(t *testing.T) {
	_, err := PlanBuild(customImageAdmin(), BuildRequest{
		Template: "base",
		Tag:      "sandcastle/base:test",
		Tool:     "sh",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanBuildAIImageRequiresPinnedToolVersions(t *testing.T) {
	_, err := PlanBuild(customImageAdmin(), BuildRequest{Template: "ai"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "codex-version") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanBuildAIImage(t *testing.T) {
	plan, err := PlanBuild(customImageAdmin(), BuildRequest{
		Template:      "ai",
		Tag:           "sandcastle/ai:debian-13",
		Tool:          "podman",
		CodexVersion:  "1.2.3",
		ClaudeVersion: "2.3.4",
		GeminiVersion: "3.4.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(plan.Command, " ")
	for _, want := range []string{
		"podman build",
		"-t sandcastle/ai:debian-13",
		"--build-arg SANDCASTLE_BASE_IMAGE=sandcastle/base:latest",
		"--build-arg CODEX_CLI_VERSION=1.2.3",
		"--build-arg SANDCASTLE_IMAGE_TEMPLATE=ai",
		"--build-arg SANDCASTLE_IMAGE_TAG=sandcastle/ai:debian-13",
		"images/ai",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("Command = %q, want %q", command, want)
		}
	}
}

func TestPlanSyncDevImage(t *testing.T) {
	plan, err := PlanSync(customImageAdmin(), SyncRequest{SourceRef: "sandcastle/dev:ubuntu-26.04"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template != "dev" {
		t.Fatalf("Template = %q", plan.Template)
	}
	if plan.Alias != "sandcastle/dev:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
}

func TestPlanBuildDevImageRequiresCodexAndClaudeButNotGemini(t *testing.T) {
	_, err := PlanBuild(customImageAdmin(), BuildRequest{Template: "dev"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "codex-version") || !strings.Contains(err.Error(), "claude-version") {
		t.Fatalf("error = %q", err)
	}
	if strings.Contains(err.Error(), "gemini-version") {
		t.Fatalf("dev image build should not require --gemini-version: %q", err)
	}
}

func TestPlanBuildDevImage(t *testing.T) {
	plan, err := PlanBuild(customImageAdmin(), BuildRequest{
		Template:      "dev",
		Tag:           "sandcastle/dev:ubuntu-26.04",
		Tool:          "podman",
		CodexVersion:  "1.2.3",
		ClaudeVersion: "2.3.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(plan.Command, " ")
	for _, want := range []string{
		"podman build",
		"-t sandcastle/dev:ubuntu-26.04",
		"-f images/dev/Dockerfile",
		"--build-arg CODEX_CLI_VERSION=1.2.3",
		"--build-arg CLAUDE_CODE_VERSION=2.3.4",
		"--build-arg SANDCASTLE_IMAGE_TEMPLATE=dev",
		"--build-arg SANDCASTLE_IMAGE_TAG=sandcastle/dev:ubuntu-26.04",
		"images/dev",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("Command = %q, want %q", command, want)
		}
	}
	if strings.Contains(command, "GEMINI_CLI_VERSION") {
		t.Fatalf("dev image build should not pass GEMINI_CLI_VERSION: %q", command)
	}
	if strings.Contains(command, "SANDCASTLE_BASE_IMAGE") {
		t.Fatalf("dev image is FROM ubuntu:26.04 directly, not the Sandcastle base image: %q", command)
	}
}

func TestLocalBuilderRunsPlannedCommand(t *testing.T) {
	runner := &fakeCommandRunner{}
	result, err := (LocalBuilder{Runner: runner}).BuildImage(context.Background(), BuildPlan{
		Template: "base",
		Tag:      "sandcastle/base:test",
		Command:  []string{"docker", "build", "-t", "sandcastle/base:test", "."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Built {
		t.Fatal("expected built result")
	}
	if runner.name != "docker" || strings.Join(runner.args, " ") != "build -t sandcastle/base:test ." {
		t.Fatalf("runner = %#v", runner)
	}
}

func TestPlanImportBaseImage(t *testing.T) {
	plan, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "base",
		SourceRef: "oci:sandcastle/base:debian-13",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Alias != "sandcastle/base:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
	if strings.Join(plan.Command, " ") != "incus image copy oci:sandcastle/base:debian-13 local: --alias sandcastle/base:latest --copy-aliases --reuse" {
		t.Fatalf("Command = %#v", plan.Command)
	}
}

func TestPlanImportAllowsIncusExecutablePath(t *testing.T) {
	plan, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "base",
		SourceRef: "oci:sandcastle/base:debian-13",
		Tool:      "/usr/local/bin/incus",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Command[0] != "/usr/local/bin/incus" {
		t.Fatalf("Command = %#v", plan.Command)
	}
}

func TestPlanImportRejectsUnsupportedTool(t *testing.T) {
	_, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "base",
		SourceRef: "oci:sandcastle/base:debian-13",
		Tool:      "docker",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanImportAIImage(t *testing.T) {
	plan, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "ai",
		SourceRef: "oci:sandcastle/ai:debian-13",
		Tool:      "incus",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Alias != "sandcastle/ai:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
}

func TestPlanImportDevImage(t *testing.T) {
	plan, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "dev",
		SourceRef: "oci:sandcastle/dev:ubuntu-26.04",
		Tool:      "incus",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Alias != "sandcastle/dev:latest" {
		t.Fatalf("Alias = %q", plan.Alias)
	}
}

func TestPlanImportRejectsUnknownTemplate(t *testing.T) {
	_, err := PlanImport(customImageAdmin(), ImportRequest{
		Template:  "unknown",
		SourceRef: "oci:sandcastle/base:debian-13",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLocalImporterRunsPlannedCommand(t *testing.T) {
	runner := &fakeCommandRunner{}
	result, err := (LocalImporter{Runner: runner}).ImportImage(context.Background(), ImportPlan{
		Template:  "base",
		SourceRef: "oci:sandcastle/base:debian-13",
		Remote:    "local",
		Alias:     "sandcastle/base:latest",
		Tool:      "incus",
		Command:   []string{"incus", "image", "copy", "oci:sandcastle/base:debian-13", "local:", "--alias", "sandcastle/base:latest", "--copy-aliases", "--reuse"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported {
		t.Fatal("expected imported result")
	}
	if runner.name != "incus" || strings.Join(runner.args, " ") != "image copy oci:sandcastle/base:debian-13 local: --alias sandcastle/base:latest --copy-aliases --reuse" {
		t.Fatalf("runner = %#v", runner)
	}
}

func TestPlanUploadBuiltDockerImage(t *testing.T) {
	plan, err := PlanUpload(customImageAdmin(), UploadRequest{
		Template:  "base",
		SourceRef: "sandcastle/base:latest",
		Alias:     "sandcastle/base:latest",
		Remote:    "big",
		Script:    "scripts/import-docker-image-to-incus.sh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Command, " ") != "bash scripts/import-docker-image-to-incus.sh sandcastle/base:latest sandcastle/base:latest big" {
		t.Fatalf("Command = %#v", plan.Command)
	}
}

func TestLocalUploaderRunsPlannedCommand(t *testing.T) {
	runner := &fakeCommandRunner{}
	result, err := (LocalUploader{Runner: runner}).UploadImage(context.Background(), UploadPlan{
		Template:  "base",
		SourceRef: "sandcastle/base:test",
		Alias:     "sandcastle/base:test",
		Remote:    "local",
		Command:   []string{"bash", "upload.sh", "sandcastle/base:test", "sandcastle/base:test", "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Uploaded {
		t.Fatal("expected uploaded result")
	}
	if runner.name != "bash" || strings.Join(runner.args, " ") != "upload.sh sandcastle/base:test sandcastle/base:test local" {
		t.Fatalf("runner = %#v", runner)
	}
}

type fakeCommandRunner struct {
	name string
	args []string
}

func (f *fakeCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	f.name = name
	f.args = args
	return nil
}
