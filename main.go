package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

var Version = "dev"

type AppConfig struct {
	VaultAddr        string `yaml:"vaultAddr"`
	CertAuthName     string `yaml:"certAuthName"`
	CertAuthMount    string `yaml:"certAuthMount"`
	CertAuthPemFile  string `yaml:"certAuthPemFile"`
	CertAuthKeyFile  string `yaml:"certAuthKeyFile"`
	OpenScPath       string `yaml:"openscPath"`
	YubikeySerial    string `yaml:"yubikeySerial"`
	YubikeyPivSerial string `yaml:"yubikeyPivSerial"`
	YubikeyPivLabel  string `yaml:"yubikeyPivLabel"`
	YubikeyPivIndex  int    `yaml:"yubikeyPivIndex"`
}

// VaultAuthClient provides a unified interface for both local and YubiKey auth modes
type VaultAuthClient interface {
	GetVaultClient() *vault.Client
	io.Closer
}

// LocalVaultClient wraps a Vault client for filesystem-based certificate auth
type LocalVaultClient struct {
	VaultClient *vault.Client
}

func (c *LocalVaultClient) GetVaultClient() *vault.Client {
	return c.VaultClient
}

func (c *LocalVaultClient) Close() error {
	return nil // no resources to clean up for local auth
}

// YubikeyVaultClient wraps both Vault client and crypto11.Context
// ensuring PKCS#11 resources are properly cleaned up
type YubikeyVaultClient struct {
	VaultClient *vault.Client
	cryptoCtx   *crypto11.Context // unexported, owned by this struct
}

func (c *YubikeyVaultClient) GetVaultClient() *vault.Client {
	return c.VaultClient
}

func (c *YubikeyVaultClient) Close() error {
	if c.cryptoCtx != nil {
		return c.cryptoCtx.Close()
	}
	return nil
}

type VaultClient interface {
	CertLogin(ctx context.Context, req schema.CertLoginRequest, opts ...vault.RequestOption) (*vault.Response[map[string]interface{}], error)
	SetToken(token string) error
	TokenLookUpSelf(ctx context.Context) (*vault.Response[map[string]interface{}], error)
}

type RealVaultClient struct {
	Client *vault.Client
}

func (c *RealVaultClient) CertLogin(ctx context.Context, req schema.CertLoginRequest, opts ...vault.RequestOption) (*vault.Response[map[string]interface{}], error) {
	return c.Client.Auth.CertLogin(ctx, req, opts...)
}
func (c *RealVaultClient) SetToken(token string) error {
	return c.Client.SetToken(token)
}
func (c *RealVaultClient) TokenLookUpSelf(ctx context.Context) (*vault.Response[map[string]interface{}], error) {
	return c.Client.Auth.TokenLookUpSelf(ctx)
}

func LoadConfig(homeDir string) (*AppConfig, error) {
	appConfig := &AppConfig{}
	file, err := os.Open(homeDir + "/.yubivault/config.yml")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&appConfig); err != nil {
		return nil, err
	}
	return appConfig, nil
}

func CreateLocalVaultClient(appConfig *AppConfig, homeDir string) (*LocalVaultClient, error) {
	tlsConfig := vault.TLSConfiguration{}
	tlsConfig.ClientCertificate.FromFile = homeDir + "/.yubivault/" + appConfig.CertAuthPemFile
	tlsConfig.ClientCertificateKey.FromFile = homeDir + "/.yubivault/" + appConfig.CertAuthKeyFile
	client, err := vault.New(
		vault.WithAddress(appConfig.VaultAddr),
		vault.WithTLS(tlsConfig),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &LocalVaultClient{VaultClient: client}, nil
}

func CreateYubikeyVaultClient(appConfig *AppConfig) (*YubikeyVaultClient, error) {
	var err error
	var cryptoCtx *crypto11.Context

	tokenPin := os.Getenv("TOKEN_PIN")
	if tokenPin == "" {
		tokenPin, err = ReadPin(appConfig.YubikeySerial, os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("could not read PIN code: %w", err)
		}
		tokenPin = strings.TrimSpace(tokenPin)
		if tokenPin == "" {
			return nil, fmt.Errorf("need to enter PIN or set via $TOKEN_PIN")
		}
	}

	cryptoCtx, err = crypto11.Configure(&crypto11.Config{
		Path:        appConfig.OpenScPath,
		TokenSerial: appConfig.YubikeyPivSerial,
		Pin:         tokenPin,
	})
	if err != nil {
		return nil, fmt.Errorf("could not configure crypto11: %w", err)
	}

	// CRITICAL: Deferred cleanup ensures crypto11.Context is closed on ANY error path.
	// On success, the context is transferred to YubikeyVaultClient which owns it.
	// This prevents resource leaks that can lock the YubiKey.
	defer func() {
		if err != nil && cryptoCtx != nil {
			cryptoCtx.Close()
		}
	}()

	kps, err := cryptoCtx.FindAllKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("failed to find key pairs: %w", err)
	}
	if len(kps) == 0 {
		return nil, fmt.Errorf("no key pairs found on YubiKey")
	}
	if appConfig.YubikeyPivIndex >= len(kps) {
		return nil, fmt.Errorf("yubikeyPivIndex %d out of range (found %d key pairs)", appConfig.YubikeyPivIndex, len(kps))
	}
	signer := kps[appConfig.YubikeyPivIndex]

	certs, err := cryptoCtx.FindAllPairedCertificates()
	if err != nil {
		return nil, fmt.Errorf("could not search for certificates: %w", err)
	}
	// Array bounds check: prevent panic if no certificates found
	if len(certs) == 0 {
		return nil, fmt.Errorf("no paired certificates found on YubiKey")
	}
	cert := certs[0]

	tlsCert := tls.Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  signer,
		Leaf:        cert.Leaf,
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	customClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	client, err := vault.New(
		vault.WithAddress(appConfig.VaultAddr),
		vault.WithHTTPClient(customClient),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Success: return wrapped client with context ownership transferred
	return &YubikeyVaultClient{VaultClient: client, cryptoCtx: cryptoCtx}, nil
}

func ReadPin(yubikeySerial string, r io.Reader) (string, error) {
	fmt.Print("PIN for " + yubikeySerial + ": ")
	if r == os.Stdin {
		bPin, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(bPin), nil
	}
	bPin := make([]byte, 64)
	n, err := r.Read(bPin)
	fmt.Println()
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(bPin[:n]), nil
}

func AuthenticateAndGetToken(client VaultClient, appConfig *AppConfig, ctx context.Context) (string, error) {
	resp, err := client.CertLogin(ctx, schema.CertLoginRequest{Name: appConfig.CertAuthName}, vault.WithMountPath(appConfig.CertAuthMount))
	if err != nil {
		return "", err
	}
	if resp.Auth == nil {
		return "", fmt.Errorf("auth field not found in response")
	}
	clientToken := resp.Auth.ClientToken
	if clientToken == "" {
		return "", fmt.Errorf("client_token not found or empty")
	}
	if err := client.SetToken(clientToken); err != nil {
		return "", err
	}
	tokenResp, err := client.TokenLookUpSelf(ctx)
	if err != nil {
		return "", err
	}
	id, ok := tokenResp.Data["id"].(string)
	if !ok {
		return "", fmt.Errorf("token id not found or not a string")
	}
	return id, nil
}

func main() {
	ctx := context.Background()
	localFlag := flag.Bool("local", false, "Use cert and key found in ~/.yubivault/client-cert.pem|key")
	yubikeyFlag := flag.Bool("yubi", false, "User cert and key stored in a yubikey only")
	versionFlag := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		os.Exit(0)
	}

	homeDir, _ := os.UserHomeDir()
	appConfig, err := LoadConfig(homeDir)
	if err != nil {
		log.Fatal(err)
	}
	if (!*localFlag && !*yubikeyFlag) || (*localFlag && *yubikeyFlag) {
		log.Fatal("Pick -local or -yubi next time")
		os.Exit(-1)
	}

	var client *vault.Client
	var cryptoCtx *crypto11.Context
	if *localFlag {
		client, err = CreateLocalVaultClient(appConfig, homeDir)
		if err != nil {
			log.Fatal(err)
		}
	} else if *yubikeyFlag {
		client, cryptoCtx, err = CreateYubikeyVaultClient(appConfig)
		if err != nil {
			log.Fatal(err)
		}
		defer cryptoCtx.Close()
	}

	vaultClient := &RealVaultClient{Client: client}
	token, err := AuthenticateAndGetToken(vaultClient, appConfig, ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
}
