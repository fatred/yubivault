# yubivault

yubivault logs in to [HashiCorp Vault](https://developer.hashicorp.com/vault) or
[OpenBao](https://openbao.org/) with TLS **certificate** authentication and prints the resulting
token. The client certificate and key come from one of two places:

- **`-local`** — a certificate and key file in `~/.yubivault`.
- **`-yubi`** — the PIV applet of a YubiKey, over OpenSC/PKCS#11. The private key is generated on
  the card and cannot be exported.

The token is the only thing written to stdout, so it can be captured directly:

```shell
VAULT_TOKEN="$(yubivault -yubi)" && export VAULT_TOKEN   # OpenBao: BAO_TOKEN
```

The PIN prompt, warnings and errors all go to stderr, which keeps that capture clean.

## How a login works

1. yubivault loads `~/.yubivault/config.yml` (unknown keys and non-HTTPS addresses are rejected).
2. It obtains a client certificate and key: from `-local` files, or by selecting a certificate on
   the YubiKey with `CKA_ID`-paired key material.
3. It opens a TLS connection to `vaultAddr`, presenting the client certificate, and posts
   `{"name": "<certAuthName>"}` to `/v1/auth/<certAuthMount>/login`.
4. The server evaluates the certificate against its cert-auth configuration and, if accepted, returns a login response.
5. yubivault uses `auth.client_token` for `auth/token/lookup-self` and prints the response's `data.id`. The successful test deployment accepted the printed value as a token; equality between `data.id` and `auth.client_token` has not been established across deployments.

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
VAULT_TOKEN="$(yubivault -yubi)" && export VAULT_TOKEN
yubivault -version
```

For `-yubi` you also need OpenSC. The PKI guide uses PIV slot 9a, but yubivault selects a paired certificate and key exposed by the configured PKCS#11 module. See [PKI setup](pki-setup.md) for that convention.
