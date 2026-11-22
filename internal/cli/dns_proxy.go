package cli

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/localdns"
	"github.com/spf13/cobra"
)

// newDNSProxyCommand is the hidden daemon behind the per-suffix
// sandcastle-dns-<suffix>.service unit on Linux. systemd-resolved binds a link
// scope's UDP sockets to the scope's interface, and the Sandcastle scope lives
// on a dummy link — so resolved could never reach the tenant CoreDNS over UDP
// and silently fell back to a fragile TCP degradation that failed one lookup
// after every idle period. This daemon owns the dummy link, listens on the
// link's own 169.254 address (where bound-to-link delivery IS local), pins the
// resolved scope to that address, and forwards every query (UDP and TCP) to
// the tenant CoreDNS over normal routing.
func newDNSProxyCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	var link, address, domain, upstream string
	cmd := &cobra.Command{
		Use:    "dns-proxy",
		Short:  "Run the per-suffix tenant DNS forwarder (used by the systemd unit)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if link == "" || address == "" || domain == "" || upstream == "" {
				return fmt.Errorf("--link, --address, --domain, and --upstream are required")
			}
			run := func(name string, args ...string) error {
				out, err := exec.CommandContext(cmd.Context(), name, args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
				}
				return nil
			}
			// The dummy link + its 169.254/32: resolved only activates a
			// link's DNS scope once the link carries an address.
			if err := run("sh", "-c", "ip link show "+link+" >/dev/null 2>&1 || ip link add "+link+" type dummy"); err != nil {
				return err
			}
			if err := run("ip", "link", "set", link, "up"); err != nil {
				return err
			}
			if err := run("ip", "addr", "replace", address+"/32", "dev", link); err != nil {
				return err
			}
			listen := net.JoinHostPort(address, "53")
			serveErr := make(chan error, 1)
			go func() { serveErr <- localdns.ServeDNSProxy(cmd.Context(), listen, upstream) }()
			// Pin the resolved scope only once the forwarder accepts — a scope
			// pointing at a dead address would fail lookups during startup.
			for i := 0; i < 50; i++ {
				conn, err := net.DialTimeout("tcp", listen, 200*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					break
				}
				select {
				case err := <-serveErr:
					return fmt.Errorf("dns proxy failed to start: %w", err)
				case <-time.After(100 * time.Millisecond):
				}
			}
			if err := run("resolvectl", "dns", link, address); err != nil {
				return err
			}
			if err := run("resolvectl", "domain", link, "~"+domain); err != nil {
				return err
			}
			fmt.Fprintf(config.stderr, "dns-proxy: *.%s → %s via %s on %s\n", domain, upstream, listen, link)
			return <-serveErr
		},
	}
	cmd.Flags().StringVar(&link, "link", "", "dummy link name (scdns-<hash>)")
	cmd.Flags().StringVar(&address, "address", "", "listen IP on the dummy link (169.254.x.y)")
	cmd.Flags().StringVar(&domain, "domain", "", "Tenant DNS Suffix served by the scope")
	cmd.Flags().StringVar(&upstream, "upstream", "", "tenant CoreDNS endpoint (IP:port)")
	return cmd
}
