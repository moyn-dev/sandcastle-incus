// Package buildinfo exposes the release version of the running binary to
// every package that stamps it into Sandcastle metadata — the Auth App
// rendering a project profile, the CLI creating a machine — without those
// packages importing the CLI. The value is set by internal/cli from its
// ldflags-stamped version var at init; un-stamped builds keep the sentinel.
package buildinfo

// Version is the release version of this binary ("0.0.0-dev" when unstamped).
var Version = "0.0.0-dev"
