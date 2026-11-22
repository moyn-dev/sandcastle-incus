package incusx

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/images"
)

type ImageServer interface {
	GetImage(ref string) (*api.Image, string, error)
	GetImageAlias(name string) (*api.ImageAliasesEntry, string, error)
	CreateImageAlias(alias api.ImageAliasesPost) error
	UpdateImageAlias(name string, alias api.ImageAliasesEntryPut, ETag string) error
}

type ImageManager struct {
	Remote     string
	ConfigPath string
	Server     ImageServer
}

func NewImageManager(remote string) ImageManager {
	return ImageManager{Remote: remote}
}

func (m ImageManager) SyncImage(ctx context.Context, plan images.SyncPlan) (images.SyncResult, error) {
	server, err := m.server()
	if err != nil {
		return images.SyncResult{}, err
	}
	image, err := resolveImage(server, plan.SourceRef)
	if err != nil {
		return images.SyncResult{}, err
	}
	action, err := ensureImageAlias(server, plan, image.Fingerprint)
	if err != nil {
		return images.SyncResult{}, err
	}
	return images.SyncResult{
		SyncPlan:    plan,
		Fingerprint: image.Fingerprint,
		Action:      action,
	}, nil
}

func resolveImage(server ImageServer, ref string) (*api.Image, error) {
	image, _, err := server.GetImage(ref)
	if err == nil {
		return image, nil
	}
	if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return nil, fmt.Errorf("get image %s: %w", ref, err)
	}
	alias, _, aliasErr := server.GetImageAlias(ref)
	if aliasErr != nil {
		return nil, fmt.Errorf("resolve image source %s: %w", ref, aliasErr)
	}
	image, _, err = server.GetImage(alias.Target)
	if err != nil {
		return nil, fmt.Errorf("get image %s target %s: %w", ref, alias.Target, err)
	}
	return image, nil
}

func ensureImageAlias(server ImageServer, plan images.SyncPlan, fingerprint string) (string, error) {
	existing, etag, err := server.GetImageAlias(plan.Alias)
	put := api.ImageAliasesEntryPut{
		Description: plan.Description,
		Target:      fingerprint,
	}
	if err == nil {
		if existing.Target == fingerprint && existing.Description == plan.Description {
			return "unchanged", nil
		}
		if err := server.UpdateImageAlias(plan.Alias, put, etag); err != nil {
			return "", fmt.Errorf("update image alias %s: %w", plan.Alias, err)
		}
		return "updated", nil
	}
	if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return "", fmt.Errorf("get image alias %s: %w", plan.Alias, err)
	}
	if err := server.CreateImageAlias(api.ImageAliasesPost{
		ImageAliasesEntry: api.ImageAliasesEntry{
			Name:                 plan.Alias,
			Type:                 "container",
			ImageAliasesEntryPut: put,
		},
	}); err != nil {
		return "", fmt.Errorf("create image alias %s: %w", plan.Alias, err)
	}
	return "created", nil
}

func (m ImageManager) server() (ImageServer, error) {
	if m.Server != nil {
		return m.Server, nil
	}
	loaded, err := LoadCLIConfig(m.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := m.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	server, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return server, nil
}
