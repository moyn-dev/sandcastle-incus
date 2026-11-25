package incusx

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/cliconfig"
)

// apiTraceSink is the VERBOSE-mode destination for wire-level Incus REST
// logging. It is installed once at CLI startup and read from every goroutine
// that performs an Incus request, hence the atomic.
var apiTraceSink atomic.Pointer[traceWriter]

type traceWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (t *traceWriter) printf(format string, values ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.w, format, values...)
}

// SetAPITrace makes every Incus REST call issued through a server connected by
// this package log one line to w. Passing a nil writer disables tracing.
//
// This is the wire-level companion to the per-operation logs (`incus op: …`,
// `ensure app project …`): it captures calls no hand-placed log statement
// covers. Two things stay invisible. The `GET /1.0` handshake runs inside
// ConnectIncus, before the transport is swapped in, and is covered instead by
// the "connect remote … done" line. Websocket traffic — instance exec streams
// and the event stream behind operation waits — bypasses the round-tripper;
// the request that *creates* an operation is traced.
func SetAPITrace(w io.Writer) {
	if w == nil {
		apiTraceSink.Store(nil)
		return
	}
	apiTraceSink.Store(&traceWriter{w: w})
}

// connectInstanceServer dials remote and, when tracing is enabled, installs the
// tracing transport on the returned server. Every Incus connection this package
// makes must go through here so VERBOSE mode sees the whole conversation.
func connectInstanceServer(loaded *cliconfig.Config, remote string) (incus.InstanceServer, error) {
	server, err := loaded.GetInstanceServer(remote)
	if err != nil {
		return nil, err
	}
	installPinnedDial(server)
	return TraceInstanceServer(server), nil
}

// TraceInstanceServer installs the tracing transport on an already-connected
// server (for connections not made via connectInstanceServer, such as the
// admin unix socket). It returns server unchanged when tracing is off.
func TraceInstanceServer(server incus.InstanceServer) incus.InstanceServer {
	sink := apiTraceSink.Load()
	if sink == nil || server == nil {
		return server
	}
	client, err := server.GetHTTPClient()
	if err != nil || client == nil {
		return server
	}
	// UseProject and friends hand back servers sharing one *http.Client, so
	// the same transport can be offered for wrapping many times over.
	switch inner := client.Transport.(type) {
	case *tracingTransport:
	case *http.Transport:
		client.Transport = &tracingTransport{inner: inner, base: inner, sink: sink}
	case incus.HTTPTransporter:
		client.Transport = &tracingTransport{inner: inner, base: inner.Transport(), sink: sink}
	}
	return server
}

// tracingTransport logs each Incus REST call. It implements incus.HTTPTransporter
// so the client's getUnderlyingHTTPTransport keeps working: Incus reaches past
// the wrapper for the concrete *http.Transport when it clones it for image
// transfers.
type tracingTransport struct {
	inner http.RoundTripper
	base  *http.Transport
	sink  *traceWriter
}

func (t *tracingTransport) Transport() *http.Transport { return t.base }

func (t *tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	label := req.Method + " " + req.URL.RequestURI()
	start := time.Now()
	response, err := t.inner.RoundTrip(req)
	elapsed := formatVerboseDuration(time.Since(start))
	if err != nil {
		t.sink.printf("[verbose] incus api: %s failed (%s): %v\n", label, elapsed, err)
		return response, err
	}
	t.sink.printf("[verbose] incus api: %s -> %s (%s)\n", label, response.Status, elapsed)
	return response, nil
}
