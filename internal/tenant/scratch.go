package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lxc/incus/v6/shared/units"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// A Machine Scratch Volume is a per-machine custom volume mounted at /scratch
// that holds disposable data: /tmp, /var/tmp and the XDG cache are moved onto
// it inside the guest. It is never snapshotted or backed up (issue #210).
const (
	ScratchDeviceName  = "scratch"
	ScratchMountPath   = "/scratch"
	DefaultScratchSize = "100GiB"
)

const (
	scratchVolumeSuffix = "-scratch"
	// maxIncusVolumeName is Incus's API name limit (validate.IsAPIName).
	maxIncusVolumeName = 64
)

// MachineScratch is the scratch volume of one machine: which machine owns it,
// the storage pool it lives in, and its quota (an Incus size string).
type MachineScratch struct {
	Machine string
	Pool    string
	Size    string
}

// VolumeName is "<machine>-scratch". A machine name may be 63 characters, so
// the plain form can exceed Incus's 64-character volume name limit; such names
// keep a prefix of the machine name plus a short hash of the full name, which
// stays unique and deterministic.
func (s MachineScratch) VolumeName() string {
	name := s.Machine + scratchVolumeSuffix
	if len(name) <= maxIncusVolumeName {
		return name
	}
	sum := sha256.Sum256([]byte(s.Machine))
	hash := hex.EncodeToString(sum[:])[:8]
	keep := maxIncusVolumeName - len(scratchVolumeSuffix) - len(hash) - 1
	return strings.TrimRight(s.Machine[:keep], "-") + "-" + hash + scratchVolumeSuffix
}

// Description is the volume's Incus description.
func (s MachineScratch) Description() string {
	return "Scratch (/tmp, /var/tmp, caches) of Sandcastle machine " + s.Machine + "; not snapshotted or backed up"
}

// VolumeConfig is the custom volume's create-time config. The root stays
// root-owned 0755; the guest setup creates the world-writable subdirectories.
// snapshots.schedule is written empty so the intent is visible on the volume;
// a pool-level volume.snapshots.schedule still fills an empty key at create
// time, which the creator clears afterwards.
func (s MachineScratch) VolumeConfig(shifted bool) map[string]string {
	config := map[string]string{
		meta.KeyScratch:      "true",
		"snapshots.schedule": "",
		"size":               s.Size,
		"initial.uid":        "0",
		"initial.gid":        "0",
		"initial.mode":       "0755",
	}
	if shifted {
		config["security.shifted"] = "true"
	}
	return config
}

// Device is the instance-level disk device attaching the volume at /scratch.
// It is an instance device, not a profile device: a profile device names one
// volume, so every machine using the profile would share it.
func (s MachineScratch) Device() map[string]string {
	return map[string]string{
		"type":   "disk",
		"pool":   s.Pool,
		"source": s.VolumeName(),
		"path":   ScratchMountPath,
	}
}

// IsScratchVolume reports whether a custom volume's config carries the
// scratch marker. Only marked volumes are ever deleted as scratch.
func IsScratchVolume(config map[string]string) bool {
	return strings.TrimSpace(config[meta.KeyScratch]) == "true"
}

// ParseScratchSize validates a scratch quota in Incus size units ("100GiB",
// "50GB", "1TiB") and returns it trimmed; "" means DefaultScratchSize.
func ParseScratchSize(raw string) (string, error) {
	size := strings.TrimSpace(raw)
	if size == "" {
		return DefaultScratchSize, nil
	}
	bytes, err := units.ParseByteSizeString(size)
	if err != nil || bytes <= 0 {
		return "", fmt.Errorf("invalid scratch size %q: want a positive size such as %s, 50GB or 1TiB", raw, DefaultScratchSize)
	}
	return size, nil
}
