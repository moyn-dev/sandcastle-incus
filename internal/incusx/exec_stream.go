package incusx

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/ws"
)

// ExecStreamServer is the slice of incus.InstanceServer that ExecStream drives.
type ExecStreamServer interface {
	RawOperation(method string, path string, data any, etag string) (incus.Operation, string, error)
	GetOperationWebsocket(uuid string, secret string) (*websocket.Conn, error)
}

// ExecStreams are the local ends of a non-interactive exec. Signals, when set,
// are forwarded to the command over the control websocket.
type ExecStreams struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Signals <-chan os.Signal
}

// ExecStream runs a non-interactive command in an instance and returns its
// exit status once every byte of stdout and stderr has been written locally.
//
// It wires the exec websockets itself instead of calling ExecInstance, because
// the stock wiring loses the end of the output on a link with any latency
// (issue #250). incusd pings every exec websocket as soon as it connects (and
// every 10s after), and closes them the moment the command exits. The stock
// client answers each ping with a pong; when that pong reaches incusd after the
// socket was closed, the kernel answers with a TCP RST and drops whatever
// output was still queued to send. The client then treats the reset as the end
// of the stream and the command "succeeds" with a short stdout.
//
// So here, nothing is ever written on the output websockets: their ping
// handlers do not reply, which keeps incusd's close a clean FIN that delivers
// the queued data. stdin, the only socket the client writes on, connects last,
// and a reset on it can lose no output. A stream that still ends with an error
// is reported, never passed off as a complete result.
func ExecStream(server ExecStreamServer, instance string, req api.InstanceExecPost, streams ExecStreams) (int, error) {
	req.WaitForWS = true
	req.Interactive = false
	req.RecordOutput = false

	op, _, err := server.RawOperation("POST", "/instances/"+url.PathEscape(instance)+"/exec", req, "")
	if err != nil {
		return -1, err
	}
	fds := execFds(op.Get().Metadata)
	for _, fd := range []string{"0", "1", "2"} {
		if fds[fd] == "" {
			_ = op.Cancel()
			return -1, fmt.Errorf("incus exec: server did not offer websocket %s", fd)
		}
	}

	var conns []*websocket.Conn
	closeAll := func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
	dial := func(fd string) (*websocket.Conn, error) {
		conn, err := server.GetOperationWebsocket(op.Get().ID, fds[fd])
		if err != nil {
			return nil, fmt.Errorf("incus exec: connect websocket %s: %w", fd, err)
		}
		conn.SetPingHandler(func(string) error { return nil })
		conn.SetCloseHandler(func(int, string) error { return nil })
		conns = append(conns, conn)
		return conn, nil
	}

	// Order matters: control and the output sockets first, stdin last.
	var control *websocket.Conn
	if fds[api.SecretNameControl] != "" {
		if control, err = dial(api.SecretNameControl); err != nil {
			closeAll()
			return -1, err
		}
	}
	stdoutConn, err := dial("1")
	if err != nil {
		closeAll()
		return -1, err
	}
	stderrConn, err := dial("2")
	if err != nil {
		closeAll()
		return -1, err
	}
	stdinConn, err := dial("0")
	if err != nil {
		closeAll()
		return -1, err
	}

	stdout, stderr, stdin := streams.Stdout, streams.Stderr, streams.Stdin
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}

	stdoutDone := ws.MirrorWrite(stdoutConn, stdout)
	stderrDone := ws.MirrorWrite(stderrConn, stderr)
	go drainWebsocket(stdinConn)
	_ = ws.MirrorRead(stdinConn, stdin) // not waited on: a terminal stdin may never reach EOF

	finished := make(chan struct{})
	defer close(finished)
	if control != nil {
		go drainWebsocket(control)
		if streams.Signals != nil {
			go forwardExecSignals(control, streams.Signals, finished)
		}
	}

	waitErr := op.Wait()
	status := -1
	if raw, ok := op.Get().Metadata["return"].(float64); ok {
		status = int(raw)
	}
	if waitErr != nil {
		closeAll()
		return status, waitErr
	}

	stdoutErr := <-stdoutDone
	stderrErr := <-stderrDone
	closeAll()
	if stdoutErr != nil {
		return status, fmt.Errorf("incus exec: stdout stream from %s ended early, output is incomplete: %w", instance, stdoutErr)
	}
	if stderrErr != nil {
		return status, fmt.Errorf("incus exec: stderr stream from %s ended early, output is incomplete: %w", instance, stderrErr)
	}
	return status, nil
}

// ExecSignals returns the signals a non-interactive exec forwards to the remote
// command (the set the incus CLI forwards, minus the terminal-only ones) and a
// stop function that restores default handling.
func ExecSignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	return ch, func() { signal.Stop(ch) }
}

func forwardExecSignals(control *websocket.Conn, signals <-chan os.Signal, finished <-chan struct{}) {
	for {
		select {
		case <-finished:
			return
		case sig := <-signals:
			number, ok := sig.(syscall.Signal)
			if !ok {
				continue
			}
			msg := api.InstanceExecControl{Command: "signal", Signal: int(number)}
			if control.WriteJSON(msg) != nil {
				return
			}
		}
	}
}

// drainWebsocket reads (and drops) everything the server sends on a socket the
// client does not otherwise read, so pings are consumed — without a reply.
func drainWebsocket(conn *websocket.Conn) {
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}

func execFds(metadata map[string]any) map[string]string {
	fds := map[string]string{}
	values, _ := metadata["fds"].(map[string]any)
	for key, value := range values {
		if secret, ok := value.(string); ok {
			fds[key] = secret
		}
	}
	return fds
}

// RunExec connects to remote through the Incus config in configDir and runs a
// non-interactive command via ExecStream, forwarding termination signals.
func RunExec(configDir, remote, project, instance string, req api.InstanceExecPost, streams ExecStreams) (int, error) {
	loaded, err := LoadCLIConfig(filepath.Join(configDir, "config.yml"))
	if err != nil {
		return -1, err
	}
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	server, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return -1, err
	}
	if project != "" {
		server = server.UseProject(project)
	}
	if streams.Signals == nil {
		signals, stop := ExecSignals()
		defer stop()
		streams.Signals = signals
	}
	return ExecStream(server, instance, req, streams)
}
