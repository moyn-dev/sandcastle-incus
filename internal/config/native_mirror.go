package config

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

// NativeMirrorEnv turns the Native Incus Mirror off when set to 0, false, off
// or no.
const NativeMirrorEnv = "SANDCASTLE_INCUS_NATIVE_MIRROR"

// NativeMirrorReport describes one reconcile of the Native Incus Mirror.
// Active is false when the mirror does not apply; Reason then says why.
type NativeMirrorReport struct {
	Active  bool
	Reason  string
	Native  string
	Added   []string
	Updated []string
	Removed []string
	// Skipped names a dedicated remote whose name is taken in the native dir
	// by a remote Sandcastle does not own, with the reason.
	Skipped []string
	// Mirrored lists every remote the native dir carries for Sandcastle after
	// the reconcile (or would carry, in a dry run).
	Mirrored []string
}

// Changed reports whether the reconcile wrote (or, dry, would write) anything.
func (r NativeMirrorReport) Changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

// mirrorRemote is the part of a dedicated remote the mirror copies.
type mirrorRemote struct {
	Addr    string `yaml:"addr"`
	Project string `yaml:"project"`
	Public  bool   `yaml:"public"`
}

// SyncNativeIncusMirror mirrors the Sandcastle remotes of the dedicated dir
// (~/.config/sandcastle/incus) into the native ~/.config/incus, so plain
// `incus` sees them while the native dir keeps its own client identity. Each
// mirrored remote carries the Sandcastle keypair as clientcerts/<name>.crt and
// .key, which Incus uses for that remote instead of the dir's client.crt.
//
// It acts only when the dedicated dir is the shared dir because the native dir
// holds a foreign client.crt; otherwise plain `incus` already sees the
// remotes, or there is nothing to mirror. A native remote is Sandcastle's iff
// its clientcerts/<name>.crt equals the dedicated client.crt; no other native
// remote, the native identity, default-remote or aliases are ever touched.
// With dryRun it reports what it would change and writes nothing.
func SyncNativeIncusMirror(dryRun bool) (NativeMirrorReport, error) {
	native := NativeIncusDir()
	dedicated := DedicatedIncusDir()
	report := NativeMirrorReport{Native: native}
	if reason := nativeMirrorInactiveReason(native, dedicated); reason != "" {
		report.Reason = reason
		return report, nil
	}
	report.Active = true

	clientCert, err := os.ReadFile(filepath.Join(dedicated, "client.crt"))
	if err != nil {
		return report, err
	}
	clientKey, err := os.ReadFile(filepath.Join(dedicated, "client.key"))
	if err != nil {
		return report, err
	}
	sources, err := readMirrorSources(filepath.Join(dedicated, "config.yml"))
	if err != nil {
		return report, err
	}

	configPath := filepath.Join(native, "config.yml")
	doc, err := readYAMLDoc(configPath)
	if err != nil {
		return report, err
	}
	remotes := mapSliceValue(doc, "remotes")
	owned := func(name string) bool {
		return sameCertificate(filepath.Join(native, "clientcerts", name+".crt"), clientCert)
	}
	defaultRemote, _ := lookupKey(doc, "default-remote")

	var files []mirrorFile
	var drop []string
	docChanged := false
	for _, name := range sortedKeys(sources) {
		src := sources[name]
		existing, exists := lookupKey(remotes, name)
		if exists && !owned(name) {
			report.Skipped = append(report.Skipped, name+": "+native+" already has a remote of that name")
			continue
		}
		entry, _ := existing.(yaml.MapSlice)
		oldAddr, _ := lookupKey(entry, "addr")
		addrChanged := !exists || oldAddr != src.Addr
		entryChanged := false
		for _, kv := range []yaml.MapItem{
			{Key: "addr", Value: src.Addr},
			{Key: "auth_type", Value: "tls"},
			{Key: "protocol", Value: "incus"},
			{Key: "public", Value: false},
		} {
			entryChanged = setKey(&entry, kv.Key.(string), kv.Value) || entryChanged
		}
		if src.Project != "" {
			entryChanged = setKey(&entry, "project", src.Project) || entryChanged
		} else {
			entryChanged = deleteKey(&entry, "project") || entryChanged
		}
		if addrChanged && exists {
			// A stale last_working_address would steer a newer incus CLI
			// back to the old address.
			entryChanged = deleteKey(&entry, "last_working_address") || entryChanged
		}
		if entryChanged {
			setKey(&remotes, name, entry)
			docChanged = true
		}

		remoteFiles := []mirrorFile{
			{path: filepath.Join(native, "clientcerts", name+".crt"), data: clientCert, mode: 0o644},
			{path: filepath.Join(native, "clientcerts", name+".key"), data: clientKey, mode: 0o600},
		}
		nativePin := filepath.Join(native, "servercerts", name+".crt")
		// Keep the native pin for an unchanged address: it may have been
		// refreshed there and must survive.
		if pin, err := os.ReadFile(filepath.Join(dedicated, "servercerts", name+".crt")); err == nil && (addrChanged || !fileExists(nativePin)) {
			remoteFiles = append(remoteFiles, mirrorFile{path: nativePin, data: pin, mode: 0o644})
		}
		filesChanged := false
		for _, f := range remoteFiles {
			filesChanged = f.differs() || filesChanged
		}
		files = append(files, remoteFiles...)
		switch {
		case !exists:
			report.Added = append(report.Added, name)
		case entryChanged || filesChanged:
			report.Updated = append(report.Updated, name)
		}
		report.Mirrored = append(report.Mirrored, name)
	}

	for _, item := range remotes {
		name, _ := item.Key.(string)
		if _, kept := sources[name]; kept || !owned(name) {
			continue
		}
		if name == defaultRemote {
			report.Skipped = append(report.Skipped, name+": no longer enrolled, but it is the native default-remote; switch away and it is removed on the next sync")
			report.Mirrored = append(report.Mirrored, name)
			continue
		}
		drop = append(drop, name)
	}
	for _, name := range drop {
		deleteKey(&remotes, name)
		docChanged = true
		report.Removed = append(report.Removed, name)
	}

	pending := docChanged
	for _, f := range files {
		pending = pending || f.differs()
	}
	if !pending || dryRun {
		return report, nil
	}

	// Client certificates first: a remote entry must never point at a
	// clientcerts pair that is not there yet, or incus would fall back to
	// the native identity for it.
	for _, f := range files {
		if err := f.write(); err != nil {
			return report, err
		}
	}
	if docChanged {
		setKey(&doc, "remotes", remotes)
		out, err := yaml.Marshal(doc)
		if err != nil {
			return report, err
		}
		mode := os.FileMode(0o600)
		if info, err := os.Stat(configPath); err == nil {
			mode = info.Mode().Perm()
		}
		if err := writeFileAtomic(configPath, out, mode); err != nil {
			return report, err
		}
	}
	for _, name := range drop {
		for _, p := range []string{"clientcerts/" + name + ".crt", "clientcerts/" + name + ".key", "servercerts/" + name + ".crt"} {
			if err := os.Remove(filepath.Join(native, p)); err != nil && !os.IsNotExist(err) {
				return report, err
			}
		}
	}
	return report, nil
}

// nativeMirrorInactiveReason returns why the mirror does not apply, or ""
// when it does.
func nativeMirrorInactiveReason(native, dedicated string) string {
	switch {
	case !NativeMirrorEnabled():
		return "turned off (" + NativeMirrorEnv + " or incus_native_mirror: false)"
	case SharedIncusDir() != dedicated:
		return "Sandcastle remotes already live in " + native
	case !fileExists(filepath.Join(native, "client.crt")):
		return native + " holds no client identity of its own"
	case !fileExists(filepath.Join(dedicated, "config.yml")), !fileExists(filepath.Join(dedicated, "client.crt")), !fileExists(filepath.Join(dedicated, "client.key")):
		return "no Sandcastle enrollment in " + dedicated
	}
	return ""
}

// NativeMirrorEnabled reports the opt-out: the env var wins, then
// incus_native_mirror in ~/.config/sandcastle/config.yml. Default on.
func NativeMirrorEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(NativeMirrorEnv))) {
	case "0", "false", "off", "no":
		return false
	case "1", "true", "on", "yes":
		return true
	}
	cfg, err := LoadSandcastleConfig(DefaultConfigPath())
	if err != nil || cfg.IncusNativeMirror == nil {
		return true
	}
	return *cfg.IncusNativeMirror
}

// readMirrorSources returns the dedicated remotes the mirror carries: every
// non-public https remote.
func readMirrorSources(path string) (map[string]mirrorRemote, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Remotes map[string]mirrorRemote `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	sources := map[string]mirrorRemote{}
	for name, remote := range cfg.Remotes {
		if remote.Public || !strings.HasPrefix(remote.Addr, "https://") {
			continue
		}
		sources[name] = remote
	}
	return sources, nil
}

// readYAMLDoc reads a YAML mapping as an ordered MapSlice so a rewrite keeps
// every key, including ones this code does not know. A missing file is an
// empty document.
func readYAMLDoc(path string) (yaml.MapSlice, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return yaml.MapSlice{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc yaml.MapSlice
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}

func lookupKey(m yaml.MapSlice, key string) (any, bool) {
	for _, item := range m {
		if item.Key == key {
			return item.Value, true
		}
	}
	return nil, false
}

func mapSliceValue(m yaml.MapSlice, key string) yaml.MapSlice {
	v, _ := lookupKey(m, key)
	ms, _ := v.(yaml.MapSlice)
	return ms
}

// setKey sets key to value, appending it when absent, and reports whether
// the slice changed. Only scalar values are compared; a MapSlice value is
// always written.
func setKey(m *yaml.MapSlice, key string, value any) bool {
	for i, item := range *m {
		if item.Key != key {
			continue
		}
		if _, nested := value.(yaml.MapSlice); !nested && item.Value == value {
			return false
		}
		(*m)[i].Value = value
		return true
	}
	*m = append(*m, yaml.MapItem{Key: key, Value: value})
	return true
}

func deleteKey(m *yaml.MapSlice, key string) bool {
	for i, item := range *m {
		if item.Key == key {
			*m = append((*m)[:i], (*m)[i+1:]...)
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]mirrorRemote) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sameCertificate reports whether the PEM certificate at path has the same
// DER bytes as want. Whitespace or PEM headers do not matter.
func sameCertificate(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	a, _ := pem.Decode(got)
	b, _ := pem.Decode(want)
	return a != nil && b != nil && a.Type == "CERTIFICATE" && bytes.Equal(a.Bytes, b.Bytes)
}

type mirrorFile struct {
	path string
	data []byte
	mode os.FileMode
}

func (f mirrorFile) differs() bool {
	got, err := os.ReadFile(f.path)
	if err != nil || !bytes.Equal(got, f.data) {
		return true
	}
	// A private file (the key) must not stay readable by others.
	info, err := os.Stat(f.path)
	return err != nil || (f.mode&0o077 == 0 && info.Mode().Perm()&0o077 != 0)
}

func (f mirrorFile) write() error {
	if !f.differs() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(f.path, f.data, f.mode)
}

// writeFileAtomic replaces path with data through a temp file and rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
