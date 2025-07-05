package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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

func main() {
	ctx := context.Background()

	var localFlag = flag.Bool("local", false, "Use cert and key found in ~/.vault/client-cert.pem|key")
	var yubikeyFlag = flag.Bool("yubi", false, "User cert and key stored in a yubikey only")
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

	var tlsConfig = vault.TLSConfiguration{}
	var client *vault.Client

	if *localFlag {
		tlsConfig.ClientCertificate.FromFile = homeDir + "/.vault/" + appConfig.CertAuthPemFile
		tlsConfig.ClientCertificateKey.FromFile = homeDir + "/.vault/" + appConfig.CertAuthKeyFile
		client, err = vault.New(
			vault.WithAddress(appConfig.VaultAddr),
			vault.WithTLS(tlsConfig),
			vault.WithRequestTimeout(30*time.Second),
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *yubikeyFlag {
		tokenPin := os.Getenv("TOKEN_PIN")
		if tokenPin == "" {
			fmt.Print("PIN for " + appConfig.YubikeySerial + ": ")
			bPin, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Fatal("Could not read PIN code:", err)
			}
			tokenPin = string(bPin)
			if tokenPin == "" {
				log.Fatal("Need to enter PIN or set via $TOKEN_PIN")
			}
		}

		cryptoCtx, err := crypto11.Configure(&crypto11.Config{
			Path:        appConfig.OpenScPath,
			TokenSerial: appConfig.YubikeyPivSerial,
			Pin:         tokenPin,
		})
		if err != nil {
			log.Fatal("Could not configure crypto11:", err)
		}
		defer cryptoCtx.Close()

		kps, err := cryptoCtx.FindAllKeyPairs()
		if err != nil || len(kps) == 0 {
			log.Fatalf("Failed to find key pairs: %v", err)
		}
		if appConfig.YubikeyPivIndex >= len(kps) {
			log.Fatalf("YubikeyPivIndex %d out of range", appConfig.YubikeyPivIndex)
		}
		signer := kps[appConfig.YubikeyPivIndex]

		certs, err := cryptoCtx.FindAllPairedCertificates()
		if err != nil {
			log.Fatal("Could not search for certificates: ", err)
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

		client, err = vault.New(
			vault.WithAddress(appConfig.VaultAddr),
			vault.WithHTTPClient(customClient),
		)
		if err != nil {
			log.Fatal("Failed to create Vault client:", err)
		}
	}

	resp, err := client.Auth.CertLogin(ctx, schema.CertLoginRequest{Name: appConfig.CertAuthName}, vault.WithMountPath(appConfig.CertAuthMount))
	if err != nil {
		log.Fatal(err)
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Fatal(err)
	}

	token, err := client.Auth.TokenLookUpSelf(
		context.Background(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token.Data["id"].(string))
}
