package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	softHSMTestPIN   = "123456"
	softHSMTestLabel = "yubivault-test"
	softHSMTestID    = "01"
	softHSMTestCN    = "softHSM-integration"
)

func TestCreateYubikeyVaultClient_SoftHSM(t *testing.T) {
	const childEnv = "YUBIVAULT_SOFTHSM_TEST_CHILD"
	if token := os.Getenv(childEnv); token != "" && os.Args[len(os.Args)-1] == token {
		testSoftHSMLoginAndClose(t)
		return
	}

	module := findSoftHSMModule()
	if module == "" {
		skipOrFailSoftHSM(t, "SoftHSM module not installed")
	}
	softhsmUtil, err := exec.LookPath("softhsm2-util")
	if err != nil {
		skipOrFailSoftHSM(t, "softhsm2-util not installed")
	}
	pkcs11Tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		skipOrFailSoftHSM(t, "pkcs11-tool not installed")
	}

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokenDir)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	runSoftHSMCommand(t, softhsmUtil, "--module", module, "--init-token", "--free", "--label", softHSMTestLabel,
		"--so-pin", "12345678", "--pin", softHSMTestPIN)
	serialOutput := runSoftHSMCommand(t, softhsmUtil, "--module", module, "--show-slots")
	serial := softHSMTokenSerial(t, string(serialOutput))

	clientCert := selfSignedCert(t, softHSMTestCN)
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "client-key.pem")
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "client-cert.der")
	if err := os.WriteFile(certPath, clientCert.Leaf.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runSoftHSMCommand(t, softhsmUtil, "--module", module, "--import", privatePath, "--token", softHSMTestLabel,
		"--pin", softHSMTestPIN, "--id", softHSMTestID, "--label", softHSMTestCN)
	runSoftHSMCommand(t, pkcs11Tool, "--module", module, "--login", "--pin", softHSMTestPIN, "--token-label", softHSMTestLabel,
		"--write-object", certPath, "--type", "cert", "--id", softHSMTestID, "--label", softHSMTestCN)

	// Isolate TLS so this test can set SSL_CERT_FILE before Go caches system roots.
	helperToken := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	cmd := exec.Command(os.Args[0], "-test.run=^TestCreateYubikeyVaultClient_SoftHSM$", helperToken)
	cmd.Env = append(os.Environ(),
		childEnv+"="+helperToken,
		"YUBIVAULT_SOFTHSM_MODULE="+module,
		"YUBIVAULT_SOFTHSM_SERIAL="+serial,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("SoftHSM lifecycle child failed: %v\n%s", err, output)
	}
}

func skipOrFailSoftHSM(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("YUBIVAULT_REQUIRE_SOFTHSM") == "1" {
		t.Fatalf("SoftHSM required by CI but %s", reason)
	}
	t.Skip(reason)
}

func testSoftHSMLoginAndClose(t *testing.T) {
	t.Helper()
	module := os.Getenv("YUBIVAULT_SOFTHSM_MODULE")
	serial := os.Getenv("YUBIVAULT_SOFTHSM_SERIAL")

	var loginCalls, lookupCalls, clientCertCalls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != softHSMTestCN {
			http.Error(w, "missing SoftHSM client certificate", http.StatusUnauthorized)
			return
		}
		clientCertCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/cert/login":
			loginCalls.Add(1)
			io.WriteString(w, `{"data":{},"auth":{"client_token":"client-token"}}`)
		case "/v1/auth/token/lookup-self":
			lookupCalls.Add(1)
			if r.Header.Get("X-Vault-Token") != "client-token" {
				http.Error(w, "missing Vault token", http.StatusUnauthorized)
				return
			}
			io.WriteString(w, `{"data":{"id":"lookup-id"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()

	serverRoot := filepath.Join(t.TempDir(), "server-root.pem")
	serverRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(serverRoot, serverRootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", serverRoot)

	config := &AppConfig{
		VaultAddr:        server.URL,
		CertAuthName:     "integration",
		CertAuthMount:    "cert",
		OpenScPath:       module,
		YubikeyPivSerial: serial,
		YubikeyCertCN:    softHSMTestCN,
	}
	authClient, err := CreateYubikeyVaultClient(config, softHSMTestPIN)
	if err != nil {
		t.Fatalf("CreateYubikeyVaultClient: %v", err)
	}
	tracked := &closeCountingYubikeyClient{YubikeyVaultClient: authClient}
	token, err := loginAndClose(context.Background(), tracked, config)
	if err != nil {
		t.Fatalf("loginAndClose: %v", err)
	}
	if token != "lookup-id" {
		t.Errorf("token = %q, want lookup-id", token)
	}
	if got := tracked.closeCalls; got != 1 {
		t.Errorf("Close calls = %d, want 1", got)
	}
	if got := loginCalls.Load(); got != 1 {
		t.Errorf("cert login requests = %d, want 1", got)
	}
	if got := lookupCalls.Load(); got != 1 {
		t.Errorf("lookup-self requests = %d, want 1", got)
	}
	if got := clientCertCalls.Load(); got != 2 {
		t.Errorf("requests with client certificate = %d, want 2", got)
	}
}

type closeCountingYubikeyClient struct {
	*YubikeyVaultClient
	closeCalls int
}

func (c *closeCountingYubikeyClient) Close() error {
	c.closeCalls++
	return c.YubikeyVaultClient.Close()
}

func findSoftHSMModule() string {
	if module := os.Getenv("SOFTHSM2_MODULE"); module != "" {
		if info, err := os.Stat(module); err == nil && !info.IsDir() {
			return module
		}
		return ""
	}
	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	}
	multiarch, _ := filepath.Glob("/usr/lib/*/softhsm/libsofthsm2.so")
	candidates = append(candidates, multiarch...)
	for _, module := range candidates {
		if info, err := os.Stat(module); err == nil && !info.IsDir() {
			return module
		}
	}
	return ""
}

func runSoftHSMCommand(t *testing.T, executable string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", executable, strings.Join(args, " "), err, output)
	}
	return output
}

func softHSMTokenSerial(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Serial number:") {
			if serial := strings.TrimSpace(strings.TrimPrefix(line, "Serial number:")); serial != "" {
				return serial
			}
		}
	}
	t.Fatalf("SoftHSM token serial not found in slot output:\n%s", output)
	return ""
}
