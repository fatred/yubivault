# yubivault

yubivault logs in to [HashiCorp Vault](https://developer.hashicorp.com/vault) or
[OpenBao](https://openbao.org/) with TLS **certificate** authentication and prints the resulting
token. The client certificate and key come from one of two places:

- **`-local`** — a certificate and key file in `~/.yubivault`.
- **`-yubi`** — the PIV applet of a YubiKey, over OpenSC/PKCS#11. The private key is generated on
  the card and cannot be exported.

The token is the only thing written to stdout, so it can be captured directly:

```shell
export VAULT_TOKEN="$(yubivault -yubi)"   # OpenBao: export BAO_TOKEN=...
```

The PIN prompt, warnings and errors all go to stderr, which keeps that capture clean.

## How a login works

1. yubivault loads `~/.yubivault/config.yml` (unknown keys and non-HTTPS addresses are rejected).
2. It obtains a client certificate and key: from `-local` files, or by selecting a certificate on
   the YubiKey with `CKA_ID`-paired key material.
3. It opens a TLS connection to `vaultAddr`, presenting the client certificate, and posts
   `{"name": "<certAuthName>"}` to `/v1/auth/<certAuthMount>/login`.
4. Vault matches the certificate against the constraints of that cert-auth role (organizational
   units, common names, CA) and returns a token.
5. yubivault reads the token back with `auth/token/lookup-self` and prints its `id`. That value is
   the token your shell should hold.

Because the authorisation decision is made from the certificate at login, adding or removing a
person is a PKI operation, not a Vault configuration change: see
[PKI setup](pki-setup.md).

## Documentation map

| Page | Covers |
|---|---|
| [Install](install.md) | Release binaries, supported platforms, OpenSC, building from source |
| [Configuration](configuration.md) | Every `config.yml` field, which are required per mode, parsing rules |
| [Usage](usage.md) | `-local`, `-yubi`, `-version`; PIN handling; stdout/stderr; proxy, timeouts, retries; exit codes |
| [Security](security.md) | What is protected, what the operator must do, credential cleanup, boundaries |
| [Troubleshooting](troubleshooting.md) | Common errors yubivault can print, with causes and fixes |
| [PKI setup](pki-setup.md) | End-to-end CA, YubiKey key/certificate, cert-auth role and policy setup |
| [Maintainer guide](maintainers/architecture.md) | Architecture, repository map, development, tests, release |
| [Agent instructions](agents.md) | Where the code is, invariants, commands, constraints |

## Quick start

```shell
# 1. Install (Linux x86-64 and macOS Apple Silicon binaries are published)
curl -fsSL -o yubivault https://github.com/fatred/yubivault/releases/latest/download/yubivault-linux-amd64
chmod +x yubivault && sudo mv yubivault /usr/local/bin/

# 2. Configure
mkdir -p ~/.yubivault && chmod 700 ~/.yubivault
$EDITOR ~/.yubivault/config.yml       # see Configuration

# 3. Log in
export VAULT_TOKEN="$(yubivault -yubi)"
yubivault -version
```

For `-yubi` you also need OpenSC, and the YubiKey must hold a certificate in PIV slot 9a that the
Vault cert-auth role trusts. [PKI setup](pki-setup.md) walks through all of it.
