package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"gopkg.in/yaml.v2"
)

type AppConfig struct {
	VaultAddr       string `yaml:"vaultAddr"`
	CertAuthName    string `yaml:"certAuthName"`
	CertAuthMount   string `yaml:"certAuthMount"`
	CertAuthPemFile string `yaml:"certAuthPemFile"`
	CertAuthKeyFile string `yaml:"certAuthKeyFile"`
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

	var localFlag = flag.Bool("local", true, "Use cert and key found in ~/.vault/client-cert.pem|key")
	var yubikeyFlag = flag.Bool("yubi", true, "User cert and key stored in a yubikey only")

	homeDir, _ := os.UserHomeDir()

	appConfig, err := LoadConfig(homeDir)

	if err != nil {
		fmt.Println(err)
	}

	tls := vault.TLSConfiguration{}
	if *localFlag {
		tls.ClientCertificate.FromFile = homeDir + "/.vault/" + appConfig.CertAuthPemFile
		tls.ClientCertificateKey.FromFile = homeDir + "/.vault/" + appConfig.CertAuthKeyFile
	}
	if *yubikeyFlag {
		tls.ClientCertificate.FromFile = homeDir + "/.vault/" + appConfig.CertAuthPemFile
		tls.ClientCertificateKey.FromFile = homeDir + "/.vault/" + appConfig.CertAuthKeyFile
	}

	client, err := vault.New(
		vault.WithAddress(appConfig.VaultAddr),
		vault.WithTLS(tls),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
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
