package cli

import (
	"fmt"
	"io"
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// syncNativeIncusMirror brings the Native Incus Mirror in line after a change
// to the dedicated remotes. A failure is a warning: the user's command has
// already done its job.
func syncNativeIncusMirror(w io.Writer) {
	if w == nil {
		w = io.Discard
	}
	report, err := scconfig.SyncNativeIncusMirror(false)
	if err != nil {
		fmt.Fprintf(w, "warning: could not mirror Sandcastle remotes into %s: %v\n", report.Native, err)
		return
	}
	if line := nativeMirrorChangeLine(report); line != "" {
		fmt.Fprintln(w, line)
	}
	for _, skipped := range report.Skipped {
		fmt.Fprintf(w, "Note: not mirroring %s\n", skipped)
	}
}

// nativeMirrorChangeLine summarizes what a reconcile changed, or "".
func nativeMirrorChangeLine(report scconfig.NativeMirrorReport) string {
	if !report.Changed() {
		return ""
	}
	var parts []string
	for _, group := range []struct {
		verb  string
		names []string
	}{{"added", report.Added}, {"updated", report.Updated}, {"removed", report.Removed}} {
		if len(group.names) > 0 {
			parts = append(parts, group.verb+" "+strings.Join(group.names, ", "))
		}
	}
	return fmt.Sprintf("Plain `incus` remotes in %s: %s.", report.Native, strings.Join(parts, "; "))
}

// nativeMirrorStatus is the `sc update` status cell for the mirror.
func nativeMirrorStatus(report scconfig.NativeMirrorReport, err error) string {
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	status := fmt.Sprintf("%d remote(s) current", len(report.Mirrored))
	if report.Changed() {
		status = fmt.Sprintf("outdated (%d to add, %d to update, %d to remove)", len(report.Added), len(report.Updated), len(report.Removed))
	}
	if len(report.Skipped) > 0 {
		status += fmt.Sprintf("; %d skipped", len(report.Skipped))
	}
	return status
}
