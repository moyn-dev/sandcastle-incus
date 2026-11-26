package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/images"
)

func TestImageBuildBaseE2E(t *testing.T) {
	e2eConfig := loadImageBuildConfig(t)
	runID := e2eConfig.DisposableRunID()
	tag := "sandcastle/base:" + safeToken(runID)
	t.Cleanup(cleanupImageTag(t, e2eConfig, tag))

	adminConfig := imageBuildAdminConfig(e2eConfig, tag, config.DefaultAIImageAlias)
	plan, err := images.PlanBuild(adminConfig, images.BuildRequest{
		Template: "base",
		Tag:      tag,
		Tool:     e2eConfig.Images.BuildTool,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (images.LocalBuilder{}).BuildImage(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Built {
		t.Fatal("expected base image to be built")
	}
}

func TestImageBuildAIE2E(t *testing.T) {
	e2eConfig := loadImageBuildConfig(t)
	if strings.TrimSpace(e2eConfig.Images.CodexVersion) == "" ||
		strings.TrimSpace(e2eConfig.Images.ClaudeVersion) == "" ||
		strings.TrimSpace(e2eConfig.Images.GeminiVersion) == "" {
		t.Skip("set SANDCASTLE_E2E_CODEX_VERSION, SANDCASTLE_E2E_CLAUDE_CODE_VERSION, and SANDCASTLE_E2E_GEMINI_CLI_VERSION to build the AI image")
	}
	runID := e2eConfig.DisposableRunID()
	baseTag := "sandcastle/base:" + safeToken(runID) + "-ai-base"
	aiTag := "sandcastle/ai:" + safeToken(runID)
	t.Cleanup(cleanupImageTag(t, e2eConfig, aiTag))
	t.Cleanup(cleanupImageTag(t, e2eConfig, baseTag))

	adminConfig := imageBuildAdminConfig(e2eConfig, baseTag, aiTag)
	basePlan, err := images.PlanBuild(adminConfig, images.BuildRequest{
		Template: "base",
		Tag:      baseTag,
		Tool:     e2eConfig.Images.BuildTool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (images.LocalBuilder{}).BuildImage(context.Background(), basePlan); err != nil {
		t.Fatal(err)
	}

	aiPlan, err := images.PlanBuild(adminConfig, images.BuildRequest{
		Template:      "ai",
		Tag:           aiTag,
		Tool:          e2eConfig.Images.BuildTool,
		CodexVersion:  e2eConfig.Images.CodexVersion,
		ClaudeVersion: e2eConfig.Images.ClaudeVersion,
		GeminiVersion: e2eConfig.Images.GeminiVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (images.LocalBuilder{}).BuildImage(context.Background(), aiPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Built {
		t.Fatal("expected AI image to be built")
	}
}

func loadImageBuildConfig(t *testing.T) Config {
	t.Helper()
	e2eConfig := LoadConfig()
	if !e2eConfig.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real e2e tests")
	}
	if err := e2eConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	if !e2eConfig.Images.Build {
		t.Skip("set SANDCASTLE_E2E_IMAGE_BUILD=1 to run real image build e2e tests")
	}
	return e2eConfig
}

func imageBuildAdminConfig(e2eConfig Config, baseTag string, aiTag string) config.Admin {
	return config.Admin{
		Remote:                e2eConfig.Remote,
		StoragePool:           e2eConfig.StoragePool,
		CIDRPool:              e2eConfig.CIDRPool,
		IncusProjectPrefix:    config.DefaultIncusProjectPrefix,
		InfrastructureProject: config.DefaultInfrastructureProject,
		Images: config.Images{
			Base: baseTag,
			AI:   aiTag,
			// Required by Admin validation since the Dev Image; not built here.
			Dev: config.DefaultDevImageAlias,
		},
	}
}

func cleanupImageTag(t *testing.T, e2eConfig Config, tag string) func() {
	return func() {
		if e2eConfig.Keep {
			t.Logf("keeping disposable image %s", tag)
			return
		}
		if err := (images.ExecRunner{}).Run(context.Background(), e2eConfig.Images.BuildTool, "image", "rm", tag); err != nil {
			t.Logf("cleanup failed for image %s: %v", tag, err)
		}
	}
}
