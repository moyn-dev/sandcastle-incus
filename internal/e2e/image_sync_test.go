package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/images"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
)

func TestImageSyncBaseAliasE2E(t *testing.T) {
	e2eConfig := LoadConfig()
	if !e2eConfig.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real Incus e2e tests")
	}
	if err := e2eConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(e2eConfig.Images.BaseSource)
	if source == "" {
		t.Skip("set SANDCASTLE_E2E_BASE_IMAGE_SOURCE to an already-imported Sandcastle base image or alias")
	}
	testImageSyncAlias(t, e2eConfig, "base", source, "sandcastle/base:"+safeToken(e2eConfig.DisposableRunID()))
}

func TestImageSyncAIAliasE2E(t *testing.T) {
	e2eConfig := LoadConfig()
	if !e2eConfig.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real Incus e2e tests")
	}
	if err := e2eConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(e2eConfig.Images.AISource)
	if source == "" {
		t.Skip("set SANDCASTLE_E2E_AI_IMAGE_SOURCE to an already-imported Sandcastle AI image or alias")
	}
	testImageSyncAlias(t, e2eConfig, "ai", source, "sandcastle/ai:"+safeToken(e2eConfig.DisposableRunID()))
}

func testImageSyncAlias(t *testing.T, e2eConfig Config, template string, source string, alias string) {
	t.Helper()
	baseAlias := config.DefaultBaseImageAlias
	aiAlias := config.DefaultAIImageAlias
	switch template {
	case "base":
		baseAlias = alias
	case "ai":
		aiAlias = alias
	default:
		t.Fatalf("unknown image template %q", template)
	}
	adminConfig := config.Admin{
		Remote:                e2eConfig.Remote,
		StoragePool:           e2eConfig.StoragePool,
		CIDRPool:              e2eConfig.CIDRPool,
		IncusProjectPrefix:    config.DefaultIncusProjectPrefix,
		InfrastructureProject: config.DefaultInfrastructureProject,
		Images: config.Images{
			Base: baseAlias,
			AI:   aiAlias,
		},
	}
	server, err := e2eInstanceServer(e2eConfig.Remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e2eConfig.Keep {
			t.Logf("keeping disposable image alias %s", alias)
			return
		}
		if err := server.DeleteImageAlias(alias); err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
			t.Logf("cleanup failed for image alias %s: %v", alias, err)
		}
	})

	plan, err := images.PlanSync(adminConfig, images.SyncRequest{SourceRef: source})
	if err != nil {
		t.Fatal(err)
	}
	result, err := incusx.NewImageManager(e2eConfig.Remote).SyncImage(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint == "" {
		t.Fatal("synced image fingerprint is empty")
	}
	synced, _, err := server.GetImageAlias(alias)
	if err != nil {
		t.Fatal(err)
	}
	if synced.Target != result.Fingerprint {
		t.Fatalf("alias target = %q, want %q", synced.Target, result.Fingerprint)
	}
}
