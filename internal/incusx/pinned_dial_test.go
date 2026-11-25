package incusx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
)

// pinnedRemote serves a minimal Incus API with a certificate that, like the
// host Incus behind the Incus Reach, names neither the address the client
// dials nor anything but its own loopback. Only the pinned server certificate
// can make it verify. drop closes that many accepted connections before the
// TLS handshake, the way the Reach drops one whose upstream dial failed.
type pinnedRemote struct {
	configPath string
	drop       atomic.Int32
}

func startPinnedRemote(t *testing.T) *pinnedRemote {
	t.Helper()
	pemCert, pemKey := selfSignedPEM(t, x509.ExtKeyUsageServerAuth, []string{"incus-host"}, []net.IP{net.ParseIP("::1")})
	serverCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := &pinnedRemote{}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			metadata := `[]`
			if r.URL.Path == "/1.0" {
				metadata = `{"api_extensions":["container_full","instances"],"auth":"trusted","environment":{}}`
			}
			fmt.Fprintf(w, `{"type":"sync","status":"Success","status_code":200,"metadata":%s}`, metadata)
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go server.Serve(tls.NewListener(dropListener{Listener: listener, drop: &remote.drop}, &tls.Config{Certificates: []tls.Certificate{serverCert}}))
	t.Cleanup(func() { _ = server.Close() })

	dir := t.TempDir()
	clientCert, clientKey := selfSignedPEM(t, x509.ExtKeyUsageClientAuth, nil, nil)
	config := fmt.Sprintf("remotes:\n  castle:\n    addr: https://%s\n    protocol: incus\n    auth_type: tls\n", listener.Addr())
	for path, data := range map[string][]byte{
		"config.yml":             []byte(config),
		"client.crt":             clientCert,
		"client.key":             clientKey,
		"servercerts/castle.crt": pemCert,
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remote.configPath = filepath.Join(dir, "config.yml")
	return remote
}

type dropListener struct {
	net.Listener
	drop *atomic.Int32
}

func (l dropListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.drop.Add(-1) < 0 {
			l.drop.Store(0)
			return conn, nil
		}
		_ = conn.Close()
	}
}

func selfSignedPEM(t *testing.T, usage x509.ExtKeyUsage, names []string, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "pinned-dial-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// A connection the Reach drops mid-handshake is retried with the pinned
// certificate; it used to surface as "x509: certificate is valid for ...".
func TestPinnedRemoteSurvivesADroppedConnection(t *testing.T) {
	remote := startPinnedRemote(t)
	server, err := connectConfiguredRemote(nil, remote.configPath, "castle")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	remote.drop.Store(1)
	if _, err := server.UseProject("web7").GetInstancesFull(api.InstanceTypeAny); err != nil {
		t.Fatalf("list after one dropped connection: %v", err)
	}
}

// When every retry is dropped, the error names the lost connection, not a
// certificate mismatch the pinned certificate never had.
func TestPinnedRemoteReportsTheRealDialError(t *testing.T) {
	remote := startPinnedRemote(t)
	server, err := connectConfiguredRemote(nil, remote.configPath, "castle")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	remote.drop.Store(1000)
	_, err = server.UseProject("web7").GetInstancesFull(api.InstanceTypeAny)
	if err == nil {
		t.Fatal("list succeeded although every connection was dropped")
	}
	if strings.Contains(err.Error(), "x509") {
		t.Fatalf("error blames the certificate instead of the dropped connection: %v", err)
	}
	if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("error does not name the dropped connection: %v", err)
	}
}
