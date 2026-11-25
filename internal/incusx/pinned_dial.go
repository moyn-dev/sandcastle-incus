package incusx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	incus "github.com/lxc/incus/v6/client"
	localtls "github.com/lxc/incus/v6/shared/tls"
)

// pinnedDialBackoff is the wait before each retry of a pinned-remote TLS dial.
var pinnedDialBackoff = []time.Duration{100 * time.Millisecond, 300 * time.Millisecond}

// installPinnedDial replaces the Incus client's TLS dial for a remote reached
// through its pinned server certificate.
//
// The client dials twice on any failed handshake, the second time with the
// ServerName reset to the dialed address. A pinned Sandcastle remote is
// reached at a tailnet IP its certificate does not name, so that second dial
// always fails with "x509: certificate is valid for 127.0.0.1, ::1, not
// <ip>", which hides the real error. The real error is usually the Incus
// Reach (`tailscale serve --tcp`) dropping a connection it accepted. This
// dial uses only the pinned name, retries such drops (no HTTP bytes have been
// sent yet), and returns the real error once retries run out.
//
// A remote without a pinned name (ServerName empty) needs the client's
// reset-name dial to verify at all, so it keeps that dial.
func installPinnedDial(server incus.InstanceServer) {
	client, err := server.GetHTTPClient()
	if err != nil || client == nil {
		return
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return
	}
	config := transport.TLSClientConfig
	if config.InsecureSkipVerify || config.ServerName == "" {
		return
	}
	handshakeTimeout := transport.TLSHandshakeTimeout
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialPinnedTLS(ctx, network, addr, config, handshakeTimeout)
		for _, wait := range pinnedDialBackoff {
			if err == nil || isTLSVerdict(err) {
				break
			}
			select {
			case <-ctx.Done():
				return nil, err
			case <-time.After(wait):
			}
			conn, err = dialPinnedTLS(ctx, network, addr, config, handshakeTimeout)
		}
		return conn, err
	}
}

func dialPinnedTLS(ctx context.Context, network, addr string, config *tls.Config, handshakeTimeout time.Duration) (net.Conn, error) {
	raw, err := localtls.RFC3493Dialer(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	handshakeCtx := ctx
	if handshakeTimeout > 0 {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
	}
	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// isTLSVerdict reports whether err is a decision about the certificates
// (ours or the server's) rather than a lost connection, so a retry cannot
// change it.
func isTLSVerdict(err error) bool {
	var verification *tls.CertificateVerificationError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var alert tls.AlertError
	return errors.As(err, &verification) || errors.As(err, &hostname) ||
		errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &alert)
}
