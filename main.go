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
	file, err := os.Open(homeDir + "/.vault/config.yml")
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

func CreateLocalVaultClient(appConfig *AppConfig, homeDir string) (*vault.Client, error) {
	tlsConfig := vault.TLSConfiguration{}
	tlsConfig.ClientCertificate.FromFile = homeDir + "/.vault/" + appConfig.CertAuthPemFile
	tlsConfig.ClientCertificateKey.FromFile = homeDir + "/.vault/" + appConfig.CertAuthKeyFile
	client, err := vault.New(
		vault.WithAddress(appConfig.VaultAddr),
		vault.WithTLS(tlsConfig),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func CreateYubikeyVaultClient(appConfig *AppConfig) (*vault.Client, *crypto11.Context, error) {
	tokenPin := os.Getenv("TOKEN_PIN")
	if tokenPin == "" {
		var err error
		tokenPin, err = ReadPin(appConfig.YubikeySerial, os.Stdin)
		if err != nil {
			return nil, nil, fmt.Errorf("could not read PIN code: %w", err)
		}
		tokenPin = strings.TrimSpace(tokenPin)
		if tokenPin == "" {
			return nil, nil, fmt.Errorf("need to enter PIN or set via $TOKEN_PIN")
		}
	}

	cryptoCtx, err := crypto11.Configure(&crypto11.Config{
		Path:        appConfig.OpenScPath,
		TokenSerial: appConfig.YubikeyPivSerial,
		Pin:         tokenPin,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not configure crypto11: %w", err)
	}

	kps, err := cryptoCtx.FindAllKeyPairs()
	if err != nil || len(kps) == 0 {
		return nil, cryptoCtx, fmt.Errorf("failed to find key pairs: %v", err)
	}
	if appConfig.YubikeyPivIndex >= len(kps) {
		return nil, cryptoCtx, fmt.Errorf("yubikeyPivIndex %d out of range", appConfig.YubikeyPivIndex)
	}
	signer := kps[appConfig.YubikeyPivIndex]

	certs, err := cryptoCtx.FindAllPairedCertificates()
	if err != nil {
		return nil, cryptoCtx, fmt.Errorf("could not search for certificates: %w", err)
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
		return nil, cryptoCtx, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return client, cryptoCtx, nil
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
	localFlag := flag.Bool("local", false, "Use cert and key found in ~/.vault/client-cert.pem|key")
	yubikeyFlag := flag.Bool("yubi", false, "User cert and key stored in a yubikey only")
	flag.Parse()

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
