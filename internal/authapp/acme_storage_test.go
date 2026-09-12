package authapp

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// TestSQLiteStorageContract exercises the certmagic.Storage contract the
// ACME account handling relies on: Store/Load round-trip, fs.ErrNotExist for
// missing keys, directory semantics for Exists/List/Stat/Delete.
func TestSQLiteStorageContract(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStorage(newClaimsTestDB(t))

	if _, err := store.Load(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load(missing) = %v, want fs.ErrNotExist", err)
	}
	if _, err := store.Stat(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(missing) = %v, want fs.ErrNotExist", err)
	}
	if store.Exists(ctx, "missing") {
		t.Fatal("Exists(missing) = true")
	}
	if _, err := store.List(ctx, "missing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("List(missing) = %v, want fs.ErrNotExist", err)
	}

	keys := map[string][]byte{
		"acme/ca/users/a@x/a@x.json": []byte(`{"status":"valid"}`),
		"acme/ca/users/a@x/a@x.key":  []byte("key"),
		"acme/ca/users/b@x/b@x.key":  []byte("key2"),
		"locks/acme_account.lock":    []byte(""),
	}
	for key, value := range keys {
		if err := store.Store(ctx, key, value); err != nil {
			t.Fatalf("Store(%s): %v", key, err)
		}
	}
	// Overwrite keeps one row.
	if err := store.Store(ctx, "acme/ca/users/a@x/a@x.key", []byte("rotated")); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(ctx, "acme/ca/users/a@x/a@x.key"); err != nil || string(got) != "rotated" {
		t.Fatalf("Load after overwrite = %q, %v", got, err)
	}
	if got, err := store.Load(ctx, "locks/acme_account.lock"); err != nil || len(got) != 0 {
		t.Fatalf("Load(empty value) = %q, %v; want empty, nil", got, err)
	}

	// Directories exist and stat as non-terminal; files as terminal.
	for _, dir := range []string{"acme", "acme/ca", "acme/ca/users/a@x"} {
		if !store.Exists(ctx, dir) {
			t.Fatalf("Exists(%s) = false", dir)
		}
		info, err := store.Stat(ctx, dir)
		if err != nil || info.IsTerminal || info.Key != dir {
			t.Fatalf("Stat(%s) = %+v, %v", dir, info, err)
		}
	}
	info, err := store.Stat(ctx, "acme/ca/users/a@x/a@x.key")
	if err != nil || !info.IsTerminal || info.Size != int64(len("rotated")) || info.Modified.IsZero() {
		t.Fatalf("Stat(file) = %+v, %v", info, err)
	}
	if time.Since(info.Modified) > time.Minute {
		t.Fatalf("Stat(file).Modified = %v, want recent", info.Modified)
	}

	// Non-recursive List returns immediate children (files and directories);
	// recursive List walks everything below.
	got, err := store.List(ctx, "acme/ca/users", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"acme/ca/users/a@x", "acme/ca/users/b@x"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List(non-recursive) = %v, want %v", got, want)
	}
	got, err = store.List(ctx, "acme/ca/users", true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"acme/ca/users/a@x", "acme/ca/users/a@x/a@x.json", "acme/ca/users/a@x/a@x.key",
		"acme/ca/users/b@x", "acme/ca/users/b@x/b@x.key",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List(recursive) = %v, want %v", got, want)
	}
	got, err = store.List(ctx, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"acme", "locks"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List(root) = %v, want %v", got, want)
	}
	// A LIKE wildcard in a key must be matched literally.
	if err := store.Store(ctx, "acme/ca/users/a%x/a%x.key", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.List(ctx, "acme/ca/users/a@x", false); len(got) != 2 {
		t.Fatalf("List(a@x) = %v, want the two a@x files only", got)
	}

	// Deleting a directory removes everything under it; deleting a missing key
	// is not an error.
	if err := store.Delete(ctx, "acme/ca/users/a@x"); err != nil {
		t.Fatal(err)
	}
	if store.Exists(ctx, "acme/ca/users/a@x") || store.Exists(ctx, "acme/ca/users/a@x/a@x.key") {
		t.Fatal("directory delete left keys behind")
	}
	if !store.Exists(ctx, "acme/ca/users/b@x/b@x.key") {
		t.Fatal("directory delete removed a sibling")
	}
	if err := store.Delete(ctx, "acme/ca/users/a@x"); err != nil {
		t.Fatalf("Delete(missing) = %v", err)
	}
	if err := store.Delete(ctx, "locks/acme_account.lock"); err != nil {
		t.Fatal(err)
	}
	if store.Exists(ctx, "locks") {
		t.Fatal("empty directory still exists")
	}
}

func TestSQLiteStorageLocks(t *testing.T) {
	ctx := context.Background()
	store := newSQLiteStorage(newClaimsTestDB(t))

	if err := store.Lock(ctx, "issue_web.baum.hase.de"); err != nil {
		t.Fatal(err)
	}
	// A second Lock blocks until Unlock — or until its context ends.
	shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := store.Lock(shortCtx, "issue_web.baum.hase.de"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Lock = %v, want context deadline", err)
	}
	// Other names are independent.
	if err := store.Lock(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if err := store.Unlock(ctx, "other"); err != nil {
		t.Fatal(err)
	}

	acquired := make(chan error, 1)
	go func() { acquired <- store.Lock(ctx, "issue_web.baum.hase.de") }()
	select {
	case err := <-acquired:
		t.Fatalf("Lock acquired while held: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := store.Unlock(ctx, "issue_web.baum.hase.de"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("waiting Lock = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting Lock never acquired after Unlock")
	}
	if err := store.Unlock(ctx, "issue_web.baum.hase.de"); err != nil {
		t.Fatal(err)
	}
	if err := store.Unlock(ctx, "issue_web.baum.hase.de"); err == nil {
		t.Fatal("Unlock of a released lock must fail")
	}
}

// The storage must satisfy certmagic's interface statically and be usable
// as the Config's Storage.
func TestSQLiteStorageIsCertmagicStorage(t *testing.T) {
	var storage certmagic.Storage = newSQLiteStorage(newClaimsTestDB(t))
	cfg := certmagic.Config{Storage: storage}
	if cfg.Storage == nil {
		t.Fatal("storage not assignable")
	}
}
