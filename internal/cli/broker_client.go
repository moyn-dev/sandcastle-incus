package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/update"
)

// brokerPost performs an mTLS POST to the Sandcastle Broker. The caller's
// identity is the client certificate (tenant or admin); the broker's TLS
// identity is pinned out-of-band, so the connection skips CA verification and
// authorizes purely by the presented client cert.
func brokerPost(ctx context.Context, brokerURL string, path string, certFile string, keyFile string, body any, out any) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load client certificate: %w", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Minute,
		// Wrapped for the version exchange (#124 §6): sends the CLI version,
		// records the broker's version/minimum from the response headers.
		Transport: update.DefaultExchange.WrapTransport(&http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		}),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(brokerURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contact broker: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("broker rejected request (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode broker response: %w", err)
		}
	}
	return nil
}

// adminClientCert returns the admin client cert/key paths, defaulting to the
// isolated admin Incus config dir ($INCUS_CONF or ~/.config/incus-admin).
func adminClientCert(certFlag string, keyFlag string) (string, string) {
	cert, key := strings.TrimSpace(certFlag), strings.TrimSpace(keyFlag)
	if cert != "" && key != "" {
		return cert, key
	}
	dir := strings.TrimSpace(os.Getenv("INCUS_CONF"))
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".config", "incus-admin")
		}
	}
	if cert == "" {
		cert = filepath.Join(dir, "client.crt")
	}
	if key == "" {
		key = filepath.Join(dir, "client.key")
	}
	return cert, key
}
