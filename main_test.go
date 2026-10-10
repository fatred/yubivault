package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
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
	content := []byte(`vaultAddr: "http://localhost:8200"
certAuthName: "test"
certAuthMount: "cert"
`)
	os.WriteFile(file, content, 0644)

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.VaultAddr != "http://localhost:8200" {
		t.Errorf("expected VaultAddr to be set, got %v", cfg.VaultAddr)
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

func TestCancelOnSignal(t *testing.T) {
	ctx, stop := cancelOnSignal()
	defer stop()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(os.Interrupt); err != nil {
		t.Skipf("cannot signal self on this platform: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context not cancelled by SIGINT")
	}
	var sigErr signalError
	if !errors.As(context.Cause(ctx), &sigErr) || sigErr.sig != syscall.SIGINT {
		t.Errorf("cause = %v, want signalError{SIGINT}", context.Cause(ctx))
	}
}
