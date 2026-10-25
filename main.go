package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
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

// YubikeyVaultClient wraps the Vault client and crypto11.Context
// to close the PKCS#11 context after authentication.
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
	CertLogin(ctx context.Context, req schema.CertLoginRequest, opts ...vault.RequestOption) (*vault.Response[map[string]any], error)
	SetToken(token string) error
	TokenLookUpSelf(ctx context.Context) (*vault.Response[map[string]any], error)
}

type RealVaultClient struct {
	Client *vault.Client
}

func (c *RealVaultClient) CertLogin(ctx context.Context, req schema.CertLoginRequest, opts ...vault.RequestOption) (*vault.Response[map[string]any], error) {
	return c.Client.Auth.CertLogin(ctx, req, opts...)
}
func (c *RealVaultClient) SetToken(token string) error {
	return c.Client.SetToken(token)
}
func (c *RealVaultClient) TokenLookUpSelf(ctx context.Context) (*vault.Response[map[string]any], error) {
	return c.Client.Auth.TokenLookUpSelf(ctx)
}

// configDirName holds config.yml and, for -local, the client cert and key.
const configDirName = ".yubivault"

func LoadConfig(homeDir string) (*AppConfig, error) {
	path := filepath.Join(homeDir, configDirName, "config.yml")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	// Unknown keys are errors: a typo or a retired setting (yubikeyPivIndex,
	// yubikeyPivLabel) would otherwise be silently ignored.
	decoder.KnownFields(true)
	appConfig := &AppConfig{}
	if err := decoder.Decode(appConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s is empty", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// KnownFields only applies to documents that are decoded, so a second
	// `---` document would escape the unknown-key check: allow exactly one.
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s must contain a single YAML document", path)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain a single YAML document: %w", path, err)
	}
	// TLS is required for certificate authentication; accept only absolute
	// HTTPS URLs.
	if appConfig.VaultAddr == "" {
		return nil, errors.New("vaultAddr is required")
	}
	vaultURL, err := url.Parse(appConfig.VaultAddr)
	if err != nil || !strings.EqualFold(vaultURL.Scheme, "https") || vaultURL.Opaque != "" || vaultURL.Hostname() == "" {
		return nil, errors.New("vaultAddr must be an absolute HTTPS URL")
	}
	vaultURL.Scheme = "https"
	appConfig.VaultAddr = vaultURL.String()
	if appConfig.CertAuthName == "" || appConfig.CertAuthMount == "" {
		return nil, errors.New("certAuthName and certAuthMount are required")
	}
	return appConfig, nil
}

// requireForMode checks the fields that only one auth mode needs, so a missing
// value fails with the field name rather than a confusing downstream error
// (an empty certAuthKeyFile used to resolve to the ~/.yubivault directory).
func (c *AppConfig) requireForMode(local bool) error {
	if local {
		if c.CertAuthPemFile == "" || c.CertAuthKeyFile == "" {
			return errors.New("certAuthPemFile and certAuthKeyFile are required for -local")
		}
		return nil
	}
	if c.OpenScPath == "" || c.YubikeyPivSerial == "" {
		return errors.New("openscPath and yubikeyPivSerial are required for -yubi")
	}
	return nil
}

func CreateLocalVaultClient(appConfig *AppConfig, homeDir string) (*LocalVaultClient, error) {
	// Key first: its permission check must fail closed even if the cert is missing.
	keyPEM, err := readPrivateKey(filepath.Join(homeDir, configDirName, appConfig.CertAuthKeyFile))
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(homeDir, configDirName, appConfig.CertAuthPemFile))
	if err != nil {
		return nil, fmt.Errorf("could not read certificate file (certAuthPemFile): %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("could not load client certificate and key: %w", err)
	}
	client, err := newVaultClient(appConfig.VaultAddr, cert)
	if err != nil {
		return nil, err
	}
	return &LocalVaultClient{VaultClient: client}, nil
}

// keyFileField names the key in errors. Errors never echo the path: it comes
// from CertAuthKeyFile and must not reach logs (CodeQL go/clear-text-logging).
const keyFileField = "private key file (certAuthKeyFile in ~/.yubivault/config.yml)"

// readPrivateKey returns the client key, refusing one that group/other can
// read (fail-secure). The mode is checked on the opened file, so the file that
// is checked is the file that is read.
func readPrivateKey(keyPath string) ([]byte, error) {
	f, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", keyFileField, pathErrCause(err))
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not stat %s: %w", keyFileField, pathErrCause(err))
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by group/other (mode %#o); run chmod 600 on it", keyFileField, perm)
	}
	keyPEM, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", keyFileField, pathErrCause(err))
	}
	return keyPEM, nil
}

// pathErrCause drops the path from an *fs.PathError and keeps its cause
// (e.g. "no such file or directory"), so errors.Is still matches.
func pathErrCause(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// selectCertificate picks one paired credential from the card. With no wantCN and exactly
// one pair, that pair is used. Otherwise the pair whose certificate Subject CommonName
// equals wantCN is used. Ambiguity or no match is an error that names the fix. Selection is
// on the parsed x509 cert (reliable), never on PKCS#11 labels.
func selectCertificate(pairs []tls.Certificate, wantCN string) (tls.Certificate, error) {
	if len(pairs) == 0 {
		return tls.Certificate{}, errors.New("no paired credentials found on YubiKey")
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

// resolvePin returns $TOKEN_PIN, or prompts on prompt and reads the PIN from
// in (os.Stdin gets no-echo terminal input; see ReadPin).
func resolvePin(appConfig *AppConfig, in io.Reader, prompt io.Writer) (string, error) {
	if tokenPin := strings.TrimSpace(os.Getenv("TOKEN_PIN")); tokenPin != "" {
		return tokenPin, nil
	}
	tokenPin, err := ReadPin(appConfig.YubikeySerial, in, prompt)
	if err != nil {
		return "", fmt.Errorf("could not read PIN code: %w", err)
	}
	// ReadPin already trims.
	if tokenPin == "" {
		return "", errors.New("need to enter PIN or set via $TOKEN_PIN")
	}
	return tokenPin, nil
}

func CreateYubikeyVaultClient(appConfig *AppConfig, tokenPin string) (_ *YubikeyVaultClient, err error) {
	cryptoCtx, err := crypto11.Configure(&crypto11.Config{
		Path:        appConfig.OpenScPath,
		TokenSerial: appConfig.YubikeyPivSerial,
		Pin:         tokenPin,
	})
	if err != nil {
		return nil, fmt.Errorf("could not configure crypto11: %w", err)
	}

	// CRITICAL: close the context on ANY error path (the card can lock); on success the client owns it.
	defer func() {
		if err != nil {
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

	client, err := newVaultClient(appConfig.VaultAddr, tlsCert)
	if err != nil {
		return nil, err
	}

	// Success: return wrapped client with context ownership transferred
	return &YubikeyVaultClient{VaultClient: client, cryptoCtx: cryptoCtx}, nil
}

// Timeouts for talking to Vault. An unreachable address must fail within
// seconds rather than after a minute of silence: each attempt gets dialTimeout
// to connect, and a failed attempt is retried once (see newVaultClient).
const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 30 * time.Second
)

// newVaultClient returns a Vault client that presents cert for TLS client
// auth. -local and -yubi both use it, so they share transport, timeouts and
// retries.
func newVaultClient(addr string, cert tls.Certificate) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(addr),
		vault.WithHTTPClient(newHTTPClient(clientTLSConfig(cert))),
		vault.WithRequestTimeout(requestTimeout),
		// One retry for a transient failure; the library default of two,
		// stacked on connect timeouts, is what made an unreachable Vault hang.
		vault.WithRetryConfiguration(vault.RetryConfiguration{
			RetryMax:     1,
			RetryWaitMin: 1 * time.Second,
			RetryWaitMax: 1500 * time.Millisecond,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return client, nil
}

// clientTLSConfig returns cert whenever the server requests client auth, ignoring the CA names it
// advertises. With the plain Certificates field, Go sends no certificate when the advertised names
// do not include its issuer, and cert auth then fails.
func clientTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}
}

// newHTTPClient starts from a clone of http.DefaultTransport rather than a
// bare http.Transport, which has no Proxy func (HTTPS_PROXY/NO_PROXY ignored),
// no dial/handshake/idle timeouts and, with a custom TLSClientConfig, no
// HTTP/2. The connect timeout is shortened to dialTimeout, and redirects are
// left to vault-client-go, as its own default client does.
func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ReadPin prompts on w and reads the PIN from r. Callers pass os.Stderr for w:
// stdout carries only the token, so `TOKEN=$(yubivault -yubi)` stays clean.
func ReadPin(yubikeySerial string, r io.Reader, w io.Writer) (string, error) {
	fmt.Fprint(w, "PIN for "+yubikeySerial+": ")
	if r == os.Stdin {
		bPin, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(w)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bPin)), nil
	}
	// ReadString loops until a newline, so a short read cannot truncate the PIN.
	line, err := bufio.NewReader(r).ReadString('\n')
	fmt.Fprintln(w)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func AuthenticateAndGetToken(ctx context.Context, client VaultClient, appConfig *AppConfig) (string, error) {
	resp, err := client.CertLogin(ctx, schema.CertLoginRequest{Name: appConfig.CertAuthName}, vault.WithMountPath(appConfig.CertAuthMount))
	if err != nil {
		return "", fmt.Errorf("cert login: %w", err)
	}
	if resp == nil {
		return "", errors.New("cert login response not found")
	}
	if resp.Auth == nil {
		return "", errors.New("auth field not found in response")
	}
	clientToken := resp.Auth.ClientToken
	if clientToken == "" {
		return "", errors.New("client_token not found or empty")
	}
	if err := client.SetToken(clientToken); err != nil {
		return "", fmt.Errorf("set token: %w", err)
	}
	tokenResp, err := client.TokenLookUpSelf(ctx)
	if err != nil {
		return "", fmt.Errorf("token lookup-self: %w", err)
	}
	if tokenResp == nil {
		return "", errors.New("token lookup-self response not found")
	}
	id, ok := tokenResp.Data["id"].(string)
	if !ok {
		return "", errors.New("token id not found or not a string")
	}
	if id == "" {
		return "", errors.New("token id is empty")
	}
	return id, nil
}

func main() {
	log.SetFlags(0) // a CLI error needs no timestamp
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// run holds the program body so deferred cleanup (notably closing the
// crypto11/PKCS#11 context) runs on every error path; log.Fatal in main only
// executes after run has returned and its defers have completed.
func run(args []string) error {
	flags := flag.NewFlagSet("yubivault", flag.ExitOnError)
	localFlag := flags.Bool("local", false, "Use the client cert and key files named in ~/.yubivault/config.yml")
	yubikeyFlag := flags.Bool("yubi", false, "Use the cert and key stored on a YubiKey only")
	versionFlag := flags.Bool("version", false, "Show version")
	flags.Parse(args) // ExitOnError: Parse never returns an error

	if *versionFlag {
		fmt.Println(Version)
		return nil
	}

	if *localFlag == *yubikeyFlag {
		return errors.New("pick -local or -yubi")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	appConfig, err := LoadConfig(homeDir)
	if err != nil {
		return err
	}
	if err := appConfig.requireForMode(*localFlag); err != nil {
		return err
	}

	// Read the PIN before catching signals: the prompt blocks in
	// term.ReadPassword and must stay killable by Ctrl-C.
	var tokenPin string
	if *yubikeyFlag {
		if tokenPin, err = resolvePin(appConfig, os.Stdin, os.Stderr); err != nil {
			return err
		}
	}

	// From here on a PKCS#11 context may be open, so SIGINT/SIGTERM cancel ctx
	// instead of killing the process; every path below closes the client.
	// Once ctx is cancelled, AfterFunc runs stop (asynchronously), restoring
	// the default action: a later signal kills the process if cleanup stalls.
	// A second signal arriving within microseconds of the first is absorbed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	context.AfterFunc(ctx, stop)

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
	// A signal observed at this check beats an otherwise successful login.
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// loginAndClose authenticates with authClient and always attempts to close it,
// whatever the outcome, before returning.
func loginAndClose(ctx context.Context, authClient VaultAuthClient, appConfig *AppConfig) (string, error) {
	defer func() {
		if cerr := authClient.Close(); cerr != nil {
			log.Printf("closing auth client: %v", cerr)
		}
	}()
	return AuthenticateAndGetToken(ctx, &RealVaultClient{Client: authClient.GetVaultClient()}, appConfig)
}
