package cli

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// A wildcard resolves to every matching machine, in project-then-name order.
func TestLifecycleTargetsFromWildcard(t *testing.T) {
	_, store := selectorFixture()
	selector, err := parseMachineSelector("gbrain:d*", "")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := lifecycleTargets(context.Background(), selectorConfig(store, ""), singleRemoteFanout(), selector)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(matchTargets(selectorConfig(store, ""), targets), ","); got != "/sc-acme/acme/gbrain/dev,/sc-acme/acme/gbrain/docker" {
		t.Fatalf("targets = %s, want /sc-acme/acme/gbrain/dev,/sc-acme/acme/gbrain/docker", got)
	}
}

// A wildcard that matches nothing is an error, not a silent no-op: the user
// asked for machines to be acted on and none were.
func TestLifecycleTargetsWildcardMatchingNothingIsAnError(t *testing.T) {
	_, store := selectorFixture()
	selector, err := parseMachineSelector("gbrain:zzz*", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lifecycleTargets(context.Background(), selectorConfig(store, ""), singleRemoteFanout(), selector)
	if err == nil || !strings.Contains(err.Error(), "no machines match") {
		t.Fatalf("error = %v, want a no-match error", err)
	}
}

func TestApplyMachineActionRunsConcurrentlyAndKeepsOrder(t *testing.T) {
	targets := []meta.Machine{
		{Project: "gbrain", Name: "dev"},
		{Project: "gbrain", Name: "docker"},
		{Project: "work", Name: "web"},
	}
	var mu sync.Mutex
	inFlight, peak := 0, 0
	results := applyMachineAction(context.Background(), targets, func(ctx context.Context, target meta.Machine) error {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		if target.Name == "docker" {
			return errors.New("boom")
		}
		return nil
	})
	if peak < 2 {
		t.Fatalf("peak concurrency = %d, want the targets fanned out", peak)
	}
	if len(results) != 3 || results[0].Machine != "dev" || results[1].Machine != "docker" || results[2].Machine != "web" {
		t.Fatalf("results = %+v, want target order preserved", results)
	}
	// One machine's failure must not take the others down with it.
	if results[0].Error != "" || results[2].Error != "" {
		t.Fatalf("healthy machines reported errors: %+v", results)
	}
	if results[1].Error != "boom" {
		t.Fatalf("failed machine error = %q, want %q", results[1].Error, "boom")
	}
	err := machineActionError(machine.ActionStop, results)
	if err == nil || !strings.Contains(err.Error(), "failed on 1 of 3 machines") {
		t.Fatalf("summary error = %v, want a 1-of-3 failure", err)
	}
	if machineActionError(machine.ActionStop, results[:1]) != nil {
		t.Fatal("an all-successful run must not report an error")
	}
}

// A cross-install wildcard resolves to machines on every matching install, and
// each result names the install it belongs to.
func TestLifecycleTargetsAcrossInstalls(t *testing.T) {
	fake := newMultiInstallFanout()
	selector, err := parseMachineSelector("*:*:dev", "")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := lifecycleTargets(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err != nil {
		t.Fatal(err)
	}
	want := "/idefix/acme/gbrain/dev,/idefix/acme/work/dev,/obelix/acme/gbrain/dev"
	if got := strings.Join(matchTargets(fake.configFor("obelix"), targets), ","); got != want {
		t.Fatalf("targets = %s, want %s", got, want)
	}
}

// An install that cannot be reached must abort a lifecycle run rather than let
// it act on the partial sweep — the opposite of `sc ls`, which warns and shows
// what it found. Acting on "every dev machine" minus the ones we could not see
// is not what was asked for, and for delete it is unrecoverable.
func TestLifecycleTargetsRefuseAPartialSweep(t *testing.T) {
	fake := newMultiInstallFanout()
	fake.failing["idefix"] = errors.New("connection refused")
	selector, err := parseMachineSelector("*:*:dev", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lifecycleTargets(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err == nil || !strings.Contains(err.Error(), "idefix: connection refused") {
		t.Fatalf("error = %v, want the run refused, naming the unreachable install", err)
	}
}
