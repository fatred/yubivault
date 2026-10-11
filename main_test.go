package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type MockVaultClient struct {
	CertLoginResp       *vault.Response[map[string]interface{}]
	CertLoginErr        error
	SetTokenErr         error
	TokenLookUpSelfResp *vault.Response[map[string]interface{}]
	TokenLookUpSelfErr  error
}

func (m *MockVaultClient) CertLogin(ctx context.Context, req schema.CertLoginRequest, opts ...vault.RequestOption) (*vault.Response[map[string]interface{}], error) {
	return m.CertLoginResp, m.CertLoginErr
}
func (m *MockVaultClient) SetToken(token string) error {
	return m.SetTokenErr
}
func (m *MockVaultClient) TokenLookUpSelf(ctx context.Context) (*vault.Response[map[string]interface{}], error) {
	return m.TokenLookUpSelfResp, m.TokenLookUpSelfErr
}

func TestAuthenticateAndGetToken_Success(t *testing.T) {
	mock := &MockVaultClient{
		CertLoginResp: &vault.Response[map[string]interface{}]{
			Auth: &vault.ResponseAuth{ClientToken: "test-token"},
		},
		TokenLookUpSelfResp: &vault.Response[map[string]interface{}]{
			Data: map[string]interface{}{"id": "my-id"},
		},
	}
	appConfig := &AppConfig{CertAuthName: "foo", CertAuthMount: "bar"}
	id, err := AuthenticateAndGetToken(mock, appConfig, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "my-id" {
		t.Errorf("expected id 'my-id', got %q", id)
	}
}

func TestAuthenticateAndGetToken_NoAuth(t *testing.T) {
	mock := &MockVaultClient{
		CertLoginResp: &vault.Response[map[string]interface{}]{Auth: nil},
	}
	appConfig := &AppConfig{CertAuthName: "foo", CertAuthMount: "bar"}
	_, err := AuthenticateAndGetToken(mock, appConfig, nil)
	if err == nil || !strings.Contains(err.Error(), "auth field not found") {
		t.Errorf("expected auth field error, got %v", err)
	}
}

func TestAuthenticateAndGetToken_EmptyToken(t *testing.T) {
	mock := &MockVaultClient{
		CertLoginResp: &vault.Response[map[string]interface{}]{
			Auth: &vault.ResponseAuth{ClientToken: ""},
		},
	}
	appConfig := &AppConfig{CertAuthName: "foo", CertAuthMount: "bar"}
	_, err := AuthenticateAndGetToken(mock, appConfig, nil)
	if err == nil || !strings.Contains(err.Error(), "client_token not found") {
		t.Errorf("expected client_token error, got %v", err)
	}
}

func TestAuthenticateAndGetToken_TokenLookUpSelfError(t *testing.T) {
	mock := &MockVaultClient{
		CertLoginResp: &vault.Response[map[string]interface{}]{
			Auth: &vault.ResponseAuth{ClientToken: "test-token"},
		},
		TokenLookUpSelfErr: fmt.Errorf("lookup error"),
	}
	appConfig := &AppConfig{CertAuthName: "foo", CertAuthMount: "bar"}
	_, err := AuthenticateAndGetToken(mock, appConfig, nil)
	if err == nil || !strings.Contains(err.Error(), "lookup error") {
		t.Errorf("expected lookup error, got %v", err)
	}
}

func TestAuthenticateAndGetToken_NoID(t *testing.T) {
	mock := &MockVaultClient{
		CertLoginResp: &vault.Response[map[string]interface{}]{
			Auth: &vault.ResponseAuth{ClientToken: "test-token"},
		},
		TokenLookUpSelfResp: &vault.Response[map[string]interface{}]{
			Data: map[string]interface{}{},
		},
	}
	appConfig := &AppConfig{CertAuthName: "foo", CertAuthMount: "bar"}
	_, err := AuthenticateAndGetToken(mock, appConfig, nil)
	if err == nil || !strings.Contains(err.Error(), "token id not found") {
		t.Errorf("expected token id error, got %v", err)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	homeDir := "/tmp/nonexistent"
	_, err := LoadConfig(homeDir)
	if err == nil {
		t.Errorf("expected error for missing config file, got nil")
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	// Setup: create a temp config file
	dir := t.TempDir()
	configPath := dir + "/.yubivault"
	os.Mkdir(configPath, 0755)
	file := configPath + "/config.yml"
	content := []byte(`vaultAddr: "https://localhost:8200"
certAuthName: "test"
certAuthMount: "cert"
`)
	os.WriteFile(file, content, 0644)

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.VaultAddr != "https://localhost:8200" {
		t.Errorf("expected VaultAddr to be https, got %v", cfg.VaultAddr)
	}
	if cfg.CertAuthName != "test" {
		t.Errorf("expected CertAuthName to be 'test', got %v", cfg.CertAuthName)
	}
}

func TestLoadConfig_RejectsMissingAuthFields(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/.yubivault"
	os.Mkdir(configPath, 0755)
	// vaultAddr present but certAuth fields missing
	os.WriteFile(configPath+"/config.yml", []byte(`vaultAddr: "https://localhost:8200"`+"\n"), 0644)

	_, err := LoadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected required-fields error, got %v", err)
	}
}

// writeConfig writes content to <tmp>/.yubivault/config.yml and returns <tmp>.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(dir+"/.yubivault", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/.yubivault/config.yml", []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadConfig_Rejects(t *testing.T) {
	const base = "vaultAddr: https://localhost:8200\ncertAuthName: web\ncertAuthMount: cert\n"
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"retired key", base + "yubikeyPivIndex: 1\n", "field yubikeyPivIndex not found"},
		{"misspelled key", base + "certAuthKeyfile: client-cert.key\n", "field certAuthKeyfile not found"},
		{"empty file", "", "is empty"},
		{"unknown key in second document", base + "---\nunknownLaterDocument: true\n", "single YAML document"},
		{"empty second document", base + "---\n", "single YAML document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadConfig_RejectsNonHTTPSVaultAddr(t *testing.T) {
	const base = "vaultAddr: https://localhost:8200\ncertAuthName: web\ncertAuthMount: cert\n"
	tests := []struct {
		name string
		addr string
	}{
		{"http", "http://localhost:8200"},
		{"unix", "unix:///run/vault.sock"},
		{"other scheme", "ftp://vault.example.com"},
		{"missing scheme", "localhost:8200"},
		{"opaque https URI", "https:localhost:8200"},
		{"missing host", "https:///v1"},
		{"invalid port", "https://localhost:bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := strings.Replace(base, "https://localhost:8200", tt.addr, 1)
			_, err := LoadConfig(writeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), "vaultAddr must be an absolute HTTPS URL") {
				t.Errorf("expected HTTPS-only validation error, got %v", err)
			}
		})
	}
}

func TestLoadConfig_NormalizesHTTPScheme(t *testing.T) {
	const content = "vaultAddr: HTTPS://localhost:8200\ncertAuthName: web\ncertAuthMount: cert\n"
	cfg, err := LoadConfig(writeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.VaultAddr != "https://localhost:8200" {
		t.Errorf("VaultAddr = %q, want normalized HTTPS URL", cfg.VaultAddr)
	}
}

func TestRequireForMode(t *testing.T) {
	full := AppConfig{
		CertAuthPemFile: "client-cert.pem", CertAuthKeyFile: "client-cert.key",
		OpenScPath: "/usr/lib/opensc-pkcs11.so", YubikeyPivSerial: "1234567890123456",
	}
	tests := []struct {
		name    string
		local   bool
		clear   func(*AppConfig)
		wantErr string
	}{
		{"local complete", true, func(*AppConfig) {}, ""},
		{"local without key file", true, func(c *AppConfig) { c.CertAuthKeyFile = "" }, "required for -local"},
		{"local without pem file", true, func(c *AppConfig) { c.CertAuthPemFile = "" }, "required for -local"},
		{"local ignores yubikey fields", true, func(c *AppConfig) { c.OpenScPath, c.YubikeyPivSerial = "", "" }, ""},
		{"yubi complete", false, func(*AppConfig) {}, ""},
		{"yubi without opensc path", false, func(c *AppConfig) { c.OpenScPath = "" }, "required for -yubi"},
		{"yubi without piv serial", false, func(c *AppConfig) { c.YubikeyPivSerial = "" }, "required for -yubi"},
		{"yubi ignores local files", false, func(c *AppConfig) { c.CertAuthPemFile, c.CertAuthKeyFile = "", "" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := full
			tt.clear(&cfg)
			err := cfg.requireForMode(tt.local)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCreateLocalVaultClient_RejectsWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	dotDir := dir + "/.yubivault"
	os.Mkdir(dotDir, 0700)
	os.Chmod(dotDir, 0700) // match documented ~/.yubivault perms, defeat umask
	keyPath := dotDir + "/client-cert.key"
	os.WriteFile(keyPath, []byte("dummy"), 0644)
	os.Chmod(keyPath, 0644) // defeat umask so the test actually exercises the rejection path

	appConfig := &AppConfig{
		VaultAddr:       "https://localhost:8200",
		CertAuthPemFile: "client-cert.pem",
		CertAuthKeyFile: "client-cert.key",
	}
	_, err := CreateLocalVaultClient(appConfig, dir)
	if err == nil || !strings.Contains(err.Error(), "group/other") {
		t.Fatalf("expected permissions error, got %v", err)
	}
	// The configured key path must not leak into the error (it ends up in logs).
	if strings.Contains(err.Error(), keyPath) || strings.Contains(err.Error(), appConfig.CertAuthKeyFile) {
		t.Errorf("error leaks key file path: %v", err)
	}
}

func TestCreateLocalVaultClient_KeyErrorsDoNotLeakPath(t *testing.T) {
	const keyName = "private-secret-name.key"
	tests := []struct {
		name   string
		setup  func(t *testing.T, keyPath string)
		wantIs error
	}{
		{"missing", func(*testing.T, string) {}, fs.ErrNotExist},
		{"unreadable (mode 000)", func(t *testing.T, keyPath string) {
			if os.Geteuid() == 0 {
				t.Skip("root can read mode 000 files")
			}
			if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, 0); err != nil {
				t.Fatal(err)
			}
		}, fs.ErrPermission},
		{"directory", func(t *testing.T, keyPath string) {
			if err := os.Mkdir(keyPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeConfig(t, "")
			keyPath := dir + "/.yubivault/" + keyName
			tt.setup(t, keyPath)
			_, err := CreateLocalVaultClient(&AppConfig{
				VaultAddr:       "https://localhost:8200",
				CertAuthPemFile: "client-cert.pem",
				CertAuthKeyFile: keyName,
			}, dir)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.wantIs)
			}
			if strings.Contains(err.Error(), keyName) {
				t.Errorf("error leaks key file path: %v", err)
			}
		})
	}
}

func TestReadPin_Mock(t *testing.T) {
	input := bytes.NewBufferString("123456\n")
	var prompt bytes.Buffer
	pin, stdout := captureStdout(t, func() (string, error) { return ReadPin("1234567", input, &prompt) })
	if pin != "123456" {
		t.Errorf("expected pin '123456\\n', got %q", pin)
	}
	// stdout carries only the token (`TOKEN=$(yubivault -yubi)`); the prompt
	// must go to the supplied writer (stderr in main).
	if stdout != "" {
		t.Errorf("ReadPin wrote to stdout: %q", stdout)
	}
	if !strings.Contains(prompt.String(), "1234567") {
		t.Errorf("prompt not written to writer, got %q", prompt.String())
	}
}

// captureStdout runs fn with os.Stdout redirected and returns fn's result and
// whatever it printed to stdout.
func captureStdout(t *testing.T, fn func() (string, error)) (string, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	got, fnErr := fn()
	os.Stdout = orig
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	if fnErr != nil {
		t.Fatalf("unexpected error: %v", fnErr)
	}
	return got, string(out)
}

func TestYubikeyVaultClient_CloseNil(t *testing.T) {
	// Edge case: Close with nil context should not panic
	client := &YubikeyVaultClient{cryptoCtx: nil}
	if err := client.Close(); err != nil {
		t.Errorf("Close with nil context failed: %v", err)
	}
}

func TestResolvePin(t *testing.T) {
	t.Run("TOKEN_PIN wins over prompt", func(t *testing.T) {
		t.Setenv("TOKEN_PIN", "654321")
		pin, err := resolvePin(&AppConfig{YubikeySerial: "12345"}, strings.NewReader("999999\n"), io.Discard)
		if err != nil || pin != "654321" {
			t.Errorf("got %q, %v; want TOKEN_PIN value", pin, err)
		}
	})
	t.Run("no TOKEN_PIN and empty input", func(t *testing.T) {
		t.Setenv("TOKEN_PIN", "")
		if _, err := resolvePin(&AppConfig{YubikeySerial: "12345"}, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "need to enter PIN") {
			t.Errorf("expected empty-PIN error, got %v", err)
		}
	})
}

func TestCreateYubikeyVaultClient_InvalidModule(t *testing.T) {
	client, err := CreateYubikeyVaultClient(&AppConfig{
		OpenScPath:       "/nonexistent/path.so",
		YubikeyPivSerial: "invalid",
		YubikeySerial:    "12345",
	}, "123456")
	if err == nil {
		client.Close()
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not configure crypto11") {
		t.Errorf("expected crypto11 configure error, got %q", err)
	}
}

func pairWithCN(cn string) tls.Certificate {
	return tls.Certificate{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: cn}}}
}

func TestSelectCertificate(t *testing.T) {
	tests := []struct {
		name    string
		pairs   []tls.Certificate
		wantCN  string
		wantErr string // substring; "" means expect success
		gotCN   string // expected CN of the returned cert on success
	}{
		{name: "no pairs", pairs: nil, wantErr: "no paired credentials"},
		{name: "single pair, no CN", pairs: []tls.Certificate{pairWithCN("admin")}, gotCN: "admin"},
		{name: "single pair, matching CN", pairs: []tls.Certificate{pairWithCN("admin")}, wantCN: "admin", gotCN: "admin"},
		{name: "single pair, mismatched CN", pairs: []tls.Certificate{pairWithCN("admin")}, wantCN: "nope", wantErr: "no credential with CN"},
		{name: "multiple pairs, no CN", pairs: []tls.Certificate{pairWithCN("a"), pairWithCN("b")}, wantErr: "set yubikeyCertCN"},
		{name: "multiple pairs, unique match", pairs: []tls.Certificate{pairWithCN("a"), pairWithCN("b")}, wantCN: "b", gotCN: "b"},
		{name: "multiple pairs, duplicate CN", pairs: []tls.Certificate{pairWithCN("dup"), pairWithCN("dup")}, wantCN: "dup", wantErr: "cannot disambiguate"},
		{name: "multiple pairs, CN matches none", pairs: []tls.Certificate{pairWithCN("a"), pairWithCN("b")}, wantCN: "c", wantErr: "no credential with CN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCertificate(tt.pairs, tt.wantCN)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Leaf == nil || got.Leaf.Subject.CommonName != tt.gotCN {
				t.Errorf("expected returned CN %q, got %+v", tt.gotCN, got.Leaf)
			}
		})
	}
}

// closeRecorder is a VaultAuthClient backed by a real vault.Client that
// records whether Close was called.
type closeRecorder struct {
	client *vault.Client
	closed bool
}

func (c *closeRecorder) GetVaultClient() *vault.Client { return c.client }
func (c *closeRecorder) Close() error                  { c.closed = true; return nil }

func TestLoginAndClose_ClosesOnFailure(t *testing.T) {
	// Vault rejects the login with a 400, as it does for an unknown cert role.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"errors":["failed to match all constraints for this login certificate"]}`)
	}))
	defer srv.Close()
	client, err := vault.New(vault.WithAddress(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	appConfig := &AppConfig{CertAuthName: "nope", CertAuthMount: "cert"}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, ctx := range map[string]context.Context{"vault rejects login": context.Background(), "context cancelled": cancelled} {
		t.Run(name, func(t *testing.T) {
			auth := &closeRecorder{client: client}
			if _, err := loginAndClose(ctx, auth, appConfig); err == nil {
				t.Fatal("expected login error")
			}
			if !auth.closed {
				t.Error("auth client not closed after failed login")
			}
		})
	}
}

// TestNewHTTPClient_UsesProxyFromEnvironment runs the request in a child test
// process: ProxyFromEnvironment reads HTTPS_PROXY once per process, so the
// variable must be set before the first lookup for the result to be
// independent of test order.
func TestNewHTTPClient_UsesProxyFromEnvironment(t *testing.T) {
	if os.Getenv("YUBIVAULT_PROXY_TEST_CHILD") == "1" {
		// The proxy refuses the tunnel, so an error is expected; the parent
		// checks what reached the proxy.
		_, _ = newHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12}).Get("https://vault.invalid:8200/v1/sys/health")
		return
	}
	connects := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			select {
			case connects <- r.Host:
			default:
			}
		}
		http.Error(w, "no upstream", http.StatusBadGateway)
	}))
	defer proxy.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestNewHTTPClient_UsesProxyFromEnvironment$")
	cmd.Env = append(os.Environ(),
		"YUBIVAULT_PROXY_TEST_CHILD=1",
		"HTTPS_PROXY="+proxy.URL, "https_proxy="+proxy.URL,
		"NO_PROXY=", "no_proxy=",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child test failed: %v\n%s", err, out)
	}
	select {
	case host := <-connects:
		if host != "vault.invalid:8200" {
			t.Errorf("proxy got CONNECT %q, want vault.invalid:8200", host)
		}
	default:
		t.Error("request did not go through HTTPS_PROXY")
	}
}

// selfSignedCert returns a throwaway self-signed certificate (key included).
func selfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// A server that advertises CA names not including our issuer must still get
// our certificate: Vault's cert auth checks the CA itself, after the handshake.
func TestClientTLSConfig_PresentsCertDespiteAdvertisedCAs(t *testing.T) {
	client := selfSignedCert(t, "alice")
	unrelated := selfSignedCert(t, "Some Other CA")
	advertised := x509.NewCertPool()
	advertised.AddCert(unrelated.Leaf)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, len(r.TLS.PeerCertificates))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, ClientCAs: advertised}
	srv.StartTLS()
	defer srv.Close()

	cfg := clientTLSConfig(client)
	cfg.RootCAs = x509.NewCertPool()
	cfg.RootCAs.AddCert(srv.Certificate())
	resp, err := newHTTPClient(cfg).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "1" {
		t.Errorf("server received %s client certificates, want 1", body)
	}
}

// An unreachable or failing Vault must cost two attempts, not the library
// default of three: that stacking is what made v1.4.0 hang for 60s.
func TestNewVaultClient_RetriesOnce(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, `{"errors":["unavailable"]}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	client, err := newVaultClient(srv.URL, selfSignedCert(t, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Auth.CertLogin(context.Background(), schema.CertLoginRequest{Name: "admin"}, vault.WithMountPath("cert")); err == nil {
		t.Fatal("expected login error")
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("Vault saw %d attempts, want 2 (one retry)", got)
	}
}
