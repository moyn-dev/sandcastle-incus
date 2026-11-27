package incusx

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/ws"
)

// fakeExecd mimics the parts of incusd's exec endpoint that issue #250 turns
// on: it pings every websocket the moment it connects, starts the command once
// stdin, stdout and stderr are all connected, and closes every socket as soon
// as the command is done. Over a real network, any frame the client sends on
// an output socket around that close is what made the kernel reset the
// connection and drop the tail of the output, so the fake records every frame
// (pongs included) a client sends on the control, stdout and stderr sockets.
type fakeExecd struct {
	t       *testing.T
	stdout  []byte
	stderr  []byte
	status  int
	breakFd string // when set, that output socket is cut mid-stream, without a barrier

	server *httptest.Server

	mu           sync.Mutex
	order        []string
	conns        map[string]*websocket.Conn
	outputWrites map[string]int
	stdinGot     bytes.Buffer
	stdinDone    chan struct{}
	started      bool
	done         chan struct{}
	path         string
	req          api.InstanceExecPost
}

func newFakeExecd(t *testing.T, stdout, stderr []byte, status int) *fakeExecd {
	t.Helper()
	f := &fakeExecd{
		t: t, stdout: stdout, stderr: stderr, status: status,
		conns:        map[string]*websocket.Conn{},
		outputWrites: map[string]int{},
		stdinDone:    make(chan struct{}),
		done:         make(chan struct{}),
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveWebsocket))
	t.Cleanup(f.server.Close)
	return f
}

var fakeExecdSecrets = map[string]string{"control": "s-control", "0": "s-0", "1": "s-1", "2": "s-2"}

func (f *fakeExecd) serveWebsocket(w http.ResponseWriter, r *http.Request) {
	fd := r.URL.Query().Get("fd")
	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		f.t.Errorf("upgrade %s: %v", fd, err)
		return
	}
	countWrite := func() {
		f.mu.Lock()
		f.outputWrites[fd]++
		f.mu.Unlock()
	}
	conn.SetPongHandler(func(string) error { countWrite(); return nil })
	_ = conn.WriteControl(websocket.PingMessage, []byte("keepalive"), time.Now().Add(time.Second))

	f.mu.Lock()
	f.order = append(f.order, fd)
	f.conns[fd] = conn
	ready := !f.started && f.conns["0"] != nil && f.conns["1"] != nil && f.conns["2"] != nil
	if ready {
		f.started = true
	}
	f.mu.Unlock()

	go func() {
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if fd != "0" {
				countWrite()
				continue
			}
			if mt == websocket.TextMessage {
				close(f.stdinDone)
				continue
			}
			f.mu.Lock()
			f.stdinGot.Write(data)
			f.mu.Unlock()
		}
	}()
	if ready {
		go f.runCommand()
	}
}

func (f *fakeExecd) runCommand() {
	// The command reads all of stdin (like `cat`), then writes. The short pause
	// gives a client's pong to the connect-time ping room to arrive, so it is
	// counted rather than lost in the close race this fake does not reproduce.
	select {
	case <-f.stdinDone:
	case <-time.After(5 * time.Second):
		f.t.Error("stdin barrier never arrived")
	}
	time.Sleep(50 * time.Millisecond)

	f.mu.Lock()
	conns := f.conns
	f.mu.Unlock()
	for fd, data := range map[string][]byte{"1": f.stdout, "2": f.stderr} {
		conn := conns[fd]
		if fd == f.breakFd {
			_ = conn.WriteMessage(websocket.BinaryMessage, data[:len(data)/2])
			_ = conn.UnderlyingConn().Close()
			continue
		}
		for start := 0; start < len(data); start += 32 * 1024 {
			end := min(start+32*1024, len(data))
			if err := conn.WriteMessage(websocket.BinaryMessage, data[start:end]); err != nil {
				f.t.Errorf("write fd %s: %v", fd, err)
				return
			}
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte{}) // barrier
	}
	time.Sleep(20 * time.Millisecond)
	for _, conn := range conns {
		_ = conn.Close()
	}
	close(f.done)
}

func (f *fakeExecd) RawOperation(method, path string, data any, _ string) (incus.Operation, string, error) {
	f.path = method + " " + path
	f.req, _ = data.(api.InstanceExecPost)
	return &fakeExecOp{execd: f}, "", nil
}

func (f *fakeExecd) GetOperationWebsocket(_ string, secret string) (*websocket.Conn, error) {
	for fd, s := range fakeExecdSecrets {
		if s == secret {
			url := "ws" + strings.TrimPrefix(f.server.URL, "http") + "/ws?fd=" + fd
			conn, _, err := websocket.DefaultDialer.Dial(url, nil)
			return conn, err
		}
	}
	return nil, io.ErrUnexpectedEOF
}

type fakeExecOp struct {
	incus.Operation
	execd *fakeExecd
}

func (o *fakeExecOp) Get() api.Operation {
	fds := map[string]any{}
	for fd, secret := range fakeExecdSecrets {
		fds[fd] = secret
	}
	metadata := map[string]any{"fds": fds}
	select {
	case <-o.execd.done:
		metadata["return"] = float64(o.execd.status)
	default:
	}
	return api.Operation{ID: "op-exec", Metadata: metadata}
}

func (o *fakeExecOp) Wait() error {
	select {
	case <-o.execd.done:
		return nil
	case <-time.After(10 * time.Second):
		return io.ErrNoProgress
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExecStreamDeliversAllOutputWithoutWritingOnOutputSockets(t *testing.T) {
	stdout, stderr, stdin := randomBytes(t, 1_000_000), randomBytes(t, 300_000), randomBytes(t, 100_000)
	execd := newFakeExecd(t, stdout, stderr, 7)

	var gotStdout, gotStderr bytes.Buffer
	status, err := ExecStream(execd, "web", api.InstanceExecPost{Command: []string{"cat"}}, ExecStreams{
		Stdin: bytes.NewReader(stdin), Stdout: &gotStdout, Stderr: &gotStderr,
	})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	if status != 7 {
		t.Fatalf("status = %d, want 7", status)
	}
	if !bytes.Equal(gotStdout.Bytes(), stdout) {
		t.Fatalf("stdout: got %d bytes, want %d", gotStdout.Len(), len(stdout))
	}
	if !bytes.Equal(gotStderr.Bytes(), stderr) {
		t.Fatalf("stderr: got %d bytes, want %d", gotStderr.Len(), len(stderr))
	}

	execd.mu.Lock()
	defer execd.mu.Unlock()
	if !bytes.Equal(execd.stdinGot.Bytes(), stdin) {
		t.Fatalf("stdin: server got %d bytes, want %d", execd.stdinGot.Len(), len(stdin))
	}
	for _, fd := range []string{"control", "1", "2"} {
		if n := execd.outputWrites[fd]; n != 0 {
			t.Fatalf("client sent %d frame(s) on the %s websocket; anything sent there can reset the connection and cut the output", n, fd)
		}
	}
	if got := strings.Join(execd.order, ","); got != "control,1,2,0" {
		t.Fatalf("connect order = %s, want control,1,2,0 (stdin last)", got)
	}
	if execd.path != "POST /instances/web/exec" {
		t.Fatalf("request = %q", execd.path)
	}
	if !execd.req.WaitForWS || execd.req.Interactive {
		t.Fatalf("exec request = %+v, want WaitForWS and non-interactive", execd.req)
	}
}

// The detection above is only meaningful if a client with stock websocket
// handlers — what ExecInstance and the incus CLI use — does get counted.
func TestFakeExecdCountsStockClientPongs(t *testing.T) {
	execd := newFakeExecd(t, nil, nil, 0)
	conn, err := execd.GetOperationWebsocket("op-exec", fakeExecdSecrets["1"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = ws.MirrorWrite(conn, io.Discard)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		execd.mu.Lock()
		n := execd.outputWrites["1"]
		execd.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a stock client's pong on the stdout websocket was not counted")
}

func TestExecStreamReportsCutOutputStream(t *testing.T) {
	execd := newFakeExecd(t, randomBytes(t, 200_000), nil, 0)
	execd.breakFd = "1"
	_, err := ExecStream(execd, "web", api.InstanceExecPost{Command: []string{"cat"}}, ExecStreams{
		Stdin: bytes.NewReader(nil), Stdout: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "stdout stream from web ended early") {
		t.Fatalf("err = %v, want a stdout stream error", err)
	}
}
