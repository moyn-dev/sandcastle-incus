package incusx

import (
	"fmt"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/update"
)

// runningBinaryVersion is the version of the currently running fat binary,
// injected once at process start by internal/cli (which owns the
// ldflags-stamped version var). Every bootstrap path that pushes
// os.Executable() into an instance stamps this value.
var runningBinaryVersion string

// SetRunningBinaryVersion records the running binary's version for
// binary-version stamping. Called once from cli.Execute/ExecuteAdmin.
func SetRunningBinaryVersion(v string) { runningBinaryVersion = v }

// instanceConfigServer is the narrow slice of the Incus API needed to stamp
// instance config.
type instanceConfigServer interface {
	GetInstance(name string) (*api.Instance, string, error)
	UpdateInstance(name string, instance api.InstancePut, etag string) (incus.Operation, error)
}

// stampBinaryVersion writes user.sandcastle.binary-version=<vX.Y.Z> into the
// instance config after a binary push (#124 §7). An empty version (no
// version known) stamps nothing — the instance then reads as "unknown",
// which is treated as outdated. Never confuse this with meta.KeyVersion,
// the topology schema version.
func stampBinaryVersion(server instanceConfigServer, instance, version string) error {
	version = update.NormalizeTag(version)
	if version == "" {
		return nil
	}
	inst, etag, err := server.GetInstance(instance)
	if err != nil {
		return fmt.Errorf("read instance %s for version stamp: %w", instance, err)
	}
	put := inst.Writable()
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	if put.Config[meta.KeyBinaryVersion] == version {
		return nil
	}
	put.Config[meta.KeyBinaryVersion] = version
	op, err := server.UpdateInstance(instance, put, etag)
	if err != nil {
		return fmt.Errorf("stamp binary version on %s: %w", instance, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for binary version stamp on %s: %w", instance, err)
	}
	return nil
}
