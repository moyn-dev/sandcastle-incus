package cli

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/hostkeys"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
)

const pinnedAddressProbeBudget = 3 * time.Second

var connectLookupIPv4 = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
}

type pinnedAddressProbe struct {
	stop    context.CancelFunc
	done    chan struct{}
	ip      string
	pinned  bool
	elapsed time.Duration
}

func startPinnedAddressProbe(ctx context.Context, recorded []hostkeys.Key, name string) *pinnedAddressProbe {
	ctx, cancel := context.WithTimeout(ctx, pinnedAddressProbeBudget)
	probe := &pinnedAddressProbe{stop: cancel, done: make(chan struct{})}
	if name == "" || len(recorded) == 0 {
		close(probe.done)
		return probe
	}
	started := time.Now()
	go func() {
		defer close(probe.done)
		defer func() { probe.elapsed = time.Since(started) }()
		addrs, err := connectLookupIPv4(ctx, name)
		if err != nil {
			return
		}
		for _, addr := range addrs {
			if addr = addr.Unmap(); addr.Is4() && addr.IsPrivate() {
				probe.ip = addr.String()
				break
			}
		}
		if probe.ip == "" {
			return
		}
		pin, _ := checkHostKeyPin(ctx, recorded, probe.ip)
		probe.pinned = pin == pinConfirmed
	}()
	return probe
}

func (p *pinnedAddressProbe) result() (ip string, pinned bool) {
	<-p.done
	return p.ip, p.pinned
}

// pinnedAddressOfRunningMachine returns the address at which a machine that
// was already up presents the host key known_hosts pins, or ok=false when no
// address does. It fills ensured's address from Incus only when the probe of
// the Machine Private Hostname did not settle it.
func pinnedAddressOfRunningMachine(ctx context.Context, config commandConfig, probe *pinnedAddressProbe, recorded []hostkeys.Key, ensured *incusx.EnsureMachineV2Result) (string, bool) {
	ip, pinned := probe.result()
	if ip != "" {
		verboseCLI(config, "host key: probed %s for the pinned key in %s (confirmed %t)", ip, probe.elapsed.Round(time.Millisecond), pinned)
	}
	if pinned {
		return ip, true
	}
	ensured.PrivateIP, ensured.PrivateCIDR = config.tenantCreator.MachineAddressV2(ctx, *ensured)
	if ensured.PrivateIP == "" || ensured.PrivateIP == ip {
		return "", false
	}
	pin, _ := checkHostKeyPin(ctx, recorded, ensured.PrivateIP)
	return ensured.PrivateIP, pin == pinConfirmed
}
