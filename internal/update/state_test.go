package update

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadStateMissingFileReturnsZeroState(t *testing.T) {
	st, err := LoadState(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("LoadState on missing file: %v", err)
	}
	if !st.CheckedAt.IsZero() || st.LatestTag != "" {
		t.Fatalf("expected zero state, got %+v", st)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "update-state.json")
	want := State{
		CheckedAt:   time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
		ETag:        `W/"abc123"`,
		LatestTag:   "v0.2.0",
		LatestURL:   "https://github.com/moyn-dev/sandcastle-incus/releases/tag/v0.2.0",
		PublishedAt: time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC),
		NoticedAt:   time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC),
	}
	if err := SaveState(path, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !got.CheckedAt.Equal(want.CheckedAt) || got.ETag != want.ETag ||
		got.LatestTag != want.LatestTag || got.LatestURL != want.LatestURL ||
		!got.PublishedAt.Equal(want.PublishedAt) || !got.NoticedAt.Equal(want.NoticedAt) {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadStateCorruptFileReturnsZeroState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-state.json")
	if err := writeFile(path, []byte("not json{")); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on corrupt file should self-heal, got: %v", err)
	}
	if !st.CheckedAt.IsZero() {
		t.Fatalf("expected zero state from corrupt file, got %+v", st)
	}
}
