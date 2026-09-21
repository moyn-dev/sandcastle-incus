package cli

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/incusx"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

var (
	dnsReconcilerOnce sync.Once
	dnsReconciler     *incusx.V2DNSReconciler
)

// authAppDNSReconciler returns the process-wide stateful DNS reconciler, so the
// unchanged-zone cache is shared between the periodic loop and event-triggered
// passes (ADR-0018).
func authAppDNSReconciler(server incus.InstanceServer, store tenant.IncusTenantStore, prefix string) *incusx.V2DNSReconciler {
	dnsReconcilerOnce.Do(func() {
		dnsReconciler = &incusx.V2DNSReconciler{Server: server, Store: store, Prefix: prefix}
	})
	return dnsReconciler
}

// dnsRelevantLifecycleActions are the only instance lifecycle actions that can
// change what DNS (or a route) should resolve to: an instance appearing,
// disappearing, changing run state, or changing name. Triggering on every
// "instance-*" action is a proven feedback loop: the reconciler's own sidecar
// zone-file reads emit instance-file-retrieved, and anything exec-polling a
// container (monitoring) emits instance-exec, so the "reconcile within
// seconds" path degenerated into reconciling continuously (~10% CPU on a busy
// host). Anything DNS-relevant that hides behind an excluded action (e.g. a
// NIC swap via instance-updated) is still converged by the periodic ticker.
var dnsRelevantLifecycleActions = map[string]struct{}{
	api.EventLifecycleInstanceCreated:   {},
	api.EventLifecycleInstanceDeleted:   {},
	api.EventLifecycleInstanceRenamed:   {},
	api.EventLifecycleInstanceRestarted: {},
	api.EventLifecycleInstanceRestored:  {},
	api.EventLifecycleInstanceResumed:   {},
	api.EventLifecycleInstanceShutdown:  {},
	api.EventLifecycleInstanceStarted:   {},
	api.EventLifecycleInstanceStopped:   {},
}

// subscribeInstanceLifecycleEvents watches Incus lifecycle events across all
// projects and calls notify() on instance events that can affect DNS — the
// trigger half of ADR-0018's event-driven DNS registration. It blocks until
// ctx is done, reconnecting with backoff when the event socket drops.
func subscribeInstanceLifecycleEvents(ctx context.Context, server incus.InstanceServer, notify func()) {
	subscribeProjectLifecycleEvents(ctx, server, func(string) { notify() })
}

// subscribeProjectLifecycleEvents is subscribeInstanceLifecycleEvents with
// the event's project handed to notify, so the DNS loop re-reads only that
// project (HANDOFF incusd-polling).
func subscribeProjectLifecycleEvents(ctx context.Context, server incus.InstanceServer, notify func(project string)) {
	for ctx.Err() == nil {
		listener, err := server.GetEventsAllProjects()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		_, err = listener.AddHandler([]string{api.EventTypeLifecycle}, func(event api.Event) {
			var lifecycle api.EventLifecycle
			if json.Unmarshal(event.Metadata, &lifecycle) != nil {
				return
			}
			if _, ok := dnsRelevantLifecycleActions[lifecycle.Action]; ok {
				notify(event.Project)
			}
		})
		if err != nil {
			listener.Disconnect()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				listener.Disconnect()
			case <-done:
			}
		}()
		_ = listener.Wait()
		close(done)
	}
}
