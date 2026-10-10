package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-keypont/crypto11"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
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
	YubikeyCertCN    string `yaml:"yubikeyCertCN"`
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
	// Reject incomplete config up front rather than producing confusing
	// downstream errors. Scheme is not enforced: cert-login needs a TLS
	// handshake, so an http:// endpoint fails safely on its own, and local
	// dev Vault (http://localhost:8200) stays usable.
	if appConfig.VaultAddr == "" {
		return nil, fmt.Errorf("vaultAddr is required")
	}
	if appConfig.CertAuthName == "" || appConfig.CertAuthMount == "" {
		return nil, fmt.Errorf("certAuthName and certAuthMount are required")
	}
	return appConfig, nil
}

func CreateLocalVaultClient(appConfig *AppConfig, homeDir string) (*LocalVaultClient, error) {
	tlsConfig := vault.TLSConfiguration{}
	tlsConfig.ClientCertificate.FromFile = homeDir + "/.yubivault/" + appConfig.CertAuthPemFile
	keyPath := homeDir + "/.yubivault/" + appConfig.CertAuthKeyFile
	tlsConfig.ClientCertificateKey.FromFile = keyPath
	// Refuse to use a private key that group/other can read (fail-secure).
	// The error names the config field rather than echoing the path: the value
	// comes from CertAuthKeyFile and must not reach logs (CodeQL go/clear-text-logging).
	if info, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("could not stat key file: %w", err)
	} else if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file (certAuthKeyFile in ~/.yubivault/config.yml) is accessible by group/other (mode %#o); run chmod 600 on it", info.Mode().Perm())
	}
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

// selectCertificate picks one paired credential from the card. With no wantCN and exactly
// one pair, that pair is used. Otherwise the pair whose certificate Subject CommonName
// equals wantCN is used. Ambiguity or no match is an error that names the fix. Selection is
// on the parsed x509 cert (reliable), never on PKCS#11 labels.
func selectCertificate(pairs []tls.Certificate, wantCN string) (tls.Certificate, error) {
	if len(pairs) == 0 {
		return tls.Certificate{}, fmt.Errorf("no paired credentials found on YubiKey")
	}
	if wantCN == "" {
		if len(pairs) == 1 {
			return pairs[0], nil
		}
		return tls.Certificate{}, fmt.Errorf("multiple credentials on card; set yubikeyCertCN to one of: %s", certCNs(pairs))
	}
	var matches []tls.Certificate
	for _, p := range pairs {
		if p.Leaf != nil && p.Leaf.Subject.CommonName == wantCN {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return tls.Certificate{}, fmt.Errorf("no credential with CN %q; available: %s", wantCN, certCNs(pairs))
	default:
		return tls.Certificate{}, fmt.Errorf("multiple credentials with CN %q on card; cannot disambiguate", wantCN)
	}
}

// certCNs renders the Subject CommonNames of the paired certs for error messages.
func certCNs(pairs []tls.Certificate) string {
	names := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p.Leaf == nil {
			names = append(names, "<no leaf>")
			continue
		}
		names = append(names, fmt.Sprintf("%q", p.Leaf.Subject.CommonName))
	}
	return strings.Join(names, ", ")
}

// resolvePin returns $TOKEN_PIN, or prompts for the PIN on the terminal.
func resolvePin(appConfig *AppConfig) (string, error) {
	if tokenPin := os.Getenv("TOKEN_PIN"); tokenPin != "" {
		return tokenPin, nil
	}
	tokenPin, err := ReadPin(appConfig.YubikeySerial, os.Stdin, os.Stderr)
	if err != nil {
		return "", fmt.Errorf("could not read PIN code: %w", err)
	}
	tokenPin = strings.TrimSpace(tokenPin)
	if tokenPin == "" {
		return "", fmt.Errorf("need to enter PIN or set via $TOKEN_PIN")
	}
	return tokenPin, nil
}

func CreateYubikeyVaultClient(appConfig *AppConfig, tokenPin string) (*YubikeyVaultClient, error) {
	var err error
	var cryptoCtx *crypto11.Context

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

	// crypto11 pairs each private key with its certificate by CKA_ID (the PIV slot),
	// so every returned tls.Certificate already has the correct key+cert bound together.
	pairs, err := cryptoCtx.FindAllPairedCertificates()
	if err != nil {
		return nil, fmt.Errorf("could not search for certificates: %w", err)
	}
	tlsCert, err := selectCertificate(pairs, appConfig.YubikeyCertCN)
	if err != nil {
		return nil, err
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

// ReadPin prompts on w and reads the PIN from r. Callers pass os.Stderr for w:
// stdout carries only the token, so `TOKEN=$(yubivault -yubi)` stays clean.
func ReadPin(yubikeySerial string, r io.Reader, w io.Writer) (string, error) {
	fmt.Fprint(w, "PIN for "+yubikeySerial+": ")
	if r == os.Stdin {
		bPin, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(w)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bPin)), nil
	}
	bPin := make([]byte, 64)
	n, err := r.Read(bPin)
	fmt.Fprintln(w)
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(string(bPin[:n])), nil
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
	err := run(os.Args[1:])
	var sigErr signalError
	if errors.As(err, &sigErr) {
		// Cleanup has already run; exit like the shell would have for this signal.
		fmt.Fprintln(os.Stderr, sigErr)
		os.Exit(128 + int(sigErr.sig))
	}
	if err != nil {
		log.Fatal(err)
	}
}

// run holds the program body so deferred cleanup (notably closing the
// crypto11/PKCS#11 context) runs on every error path; log.Fatal in main only
// executes after run has returned and its defers have completed.
func run(args []string) error {
	fs := flag.NewFlagSet("yubivault", flag.ExitOnError)
	localFlag := fs.Bool("local", false, "Use cert and key found in ~/.yubivault/client-cert.pem|key")
	yubikeyFlag := fs.Bool("yubi", false, "User cert and key stored in a yubikey only")
	versionFlag := fs.Bool("version", false, "Show version")
	fs.Parse(args)

	if *versionFlag {
		fmt.Println(Version)
		return nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	appConfig, err := LoadConfig(homeDir)
	if err != nil {
		return err
	}
	if *localFlag == *yubikeyFlag {
		return errors.New("Pick -local or -yubi")
	}

	// Read the PIN before catching signals: the prompt blocks in
	// term.ReadPassword and must stay killable by Ctrl-C.
	var tokenPin string
	if *yubikeyFlag {
		if tokenPin, err = resolvePin(appConfig); err != nil {
			return err
		}
	}

	// From here on a PKCS#11 context may be open, so SIGINT/SIGTERM cancel ctx
	// instead of killing the process; every path below closes the client.
	ctx, stop := cancelOnSignal()
	defer stop()

	var authClient VaultAuthClient
	if *localFlag {
		authClient, err = CreateLocalVaultClient(appConfig, homeDir)
	} else {
		// Not ctx-aware, but local and short; its own defer closes the
		// context on error, and a signal received meanwhile is acted on below.
		authClient, err = CreateYubikeyVaultClient(appConfig, tokenPin)
	}
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return err
	}
	// A pre-cancelled ctx fails the login immediately; the client is still closed.
	token, err := loginAndClose(ctx, authClient, appConfig)
	// A signal that raced a successful login still wins: no token, 128+signo.
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// loginAndClose authenticates with authClient and always closes it, whatever
// the outcome, so the PKCS#11 session is released before the process exits.
func loginAndClose(ctx context.Context, authClient VaultAuthClient, appConfig *AppConfig) (string, error) {
	defer func() {
		if cerr := authClient.Close(); cerr != nil {
			log.Printf("closing auth client: %v", cerr)
		}
	}()
	return AuthenticateAndGetToken(&RealVaultClient{Client: authClient.GetVaultClient()}, appConfig, ctx)
}

// signalError is the cancellation cause when SIGINT/SIGTERM stops a login.
type signalError struct{ sig syscall.Signal }

func (e signalError) Error() string { return "interrupted by " + e.sig.String() }

// cancelOnSignal returns a context that is cancelled with a signalError on
// SIGINT or SIGTERM, so in-flight Vault requests abort and deferred cleanup
// runs. After the first signal the default action is restored, so a second one
// terminates immediately. stop releases the handler.
func cancelOnSignal() (ctx context.Context, stop func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case s := <-sigs:
			signal.Stop(sigs)
			cancel(signalError{s.(syscall.Signal)})
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(sigs)
		cancel(nil)
	}
}
