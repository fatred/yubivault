package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

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

func TestReadPin_Mock(t *testing.T) {
	input := bytes.NewBufferString("123456\n")
	pin, err := ReadPin("1234567", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pin != "123456\n" {
		t.Errorf("expected pin '123456\\n', got %q", pin)
	}
}

func TestLocalVaultClient_Interface(t *testing.T) {
	// Verify LocalVaultClient satisfies VaultAuthClient
	var _ VaultAuthClient = (*LocalVaultClient)(nil)

	client := &LocalVaultClient{VaultClient: &vault.Client{}}

	if client.GetVaultClient() == nil {
		t.Error("GetVaultClient returned nil")
	}

	if err := client.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}
