package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"strconv"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
)

func assertMachineIngressFiles(t *testing.T, server incus.InstanceServer, instanceName string, hostname string, appPort int) {
	t.Helper()
	caddyfile := readInstanceFile(t, server, instanceName, machine.CaddyfilePath)
	if !strings.Contains(caddyfile, hostname) {
		t.Fatalf("machine Caddyfile missing hostname %q: %q", hostname, caddyfile)
	}
	expectedProxy := "reverse_proxy 127.0.0.1:" + strconv.Itoa(appPort)
	if !strings.Contains(caddyfile, expectedProxy) {
		t.Fatalf("machine Caddyfile missing proxy %q: %q", expectedProxy, caddyfile)
	}
	certPEM := readInstanceFile(t, server, instanceName, machine.MachineCertPath)
	keyPEM := readInstanceFile(t, server, instanceName, machine.MachineCertKeyPath)
	assertCertificateForHost(t, certPEM, hostname)
	assertPrivateKeyPEM(t, keyPEM)
}

func readInstanceFile(t *testing.T, server incus.InstanceServer, instanceName string, path string) string {
	t.Helper()
	content, response, err := server.GetInstanceFile(instanceName, path)
	if err != nil {
		t.Fatalf("read %s from %s: %v", path, instanceName, err)
	}
	defer content.Close()
	if response.Type != "file" {
		t.Fatalf("%s in %s type = %q, want file", path, instanceName, response.Type)
	}
	data, err := io.ReadAll(content)
	if err != nil {
		t.Fatalf("read %s content from %s: %v", path, instanceName, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("%s in %s is empty", path, instanceName)
	}
	return string(data)
}

func assertCertificateForHost(t *testing.T, certPEM string, hostname string) {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("machine certificate is not a CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse machine certificate: %v", err)
	}
	if err := certificate.VerifyHostname(hostname); err != nil {
		t.Fatalf("machine certificate does not verify hostname %q: %v", hostname, err)
	}
}

func assertPrivateKeyPEM(t *testing.T, keyPEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		t.Fatalf("machine private key is not a private key PEM block")
	}
}
