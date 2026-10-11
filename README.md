# yubivault

Logs in to HashiCorp Vault or OpenBao with TLS **certificate** auth and prints the token. The client
certificate and key come either from files on disk (`-local`) or from a YubiKey's PIV applet over
OpenSC/PKCS#11 (`-yubi`). The token is the only thing written to stdout, so it can be captured
directly:

```shell
export VAULT_TOKEN="$(yubivault -yubi)"   # OpenBao: export BAO_TOKEN=...
```

**Documentation: <https://fatred.github.io/yubivault/>**

| | |
|---|---|
| [Install](https://fatred.github.io/yubivault/install/) | Release binaries, platforms, OpenSC, from source |
| [Configuration](https://fatred.github.io/yubivault/configuration/) | Every `~/.yubivault/config.yml` field |
| [Usage](https://fatred.github.io/yubivault/usage/) | Flags, PIN handling, stdout/stderr, proxy, timeouts, exit codes |
| [Security](https://fatred.github.io/yubivault/security/) | What is protected, boundaries, cleanup |
| [Troubleshooting](https://fatred.github.io/yubivault/troubleshooting/) | Common errors and fixes |
| [PKI setup](https://fatred.github.io/yubivault/pki-setup/) | CA, YubiKey key and certificate, cert-auth role and policy |
| [Maintainer guide](https://fatred.github.io/yubivault/maintainers/architecture/) | Architecture, development, tests, release |
| [Agent instructions](https://fatred.github.io/yubivault/agents/) | Where the code is, invariants, verification commands |

In source form the same pages are in [`docs/`](docs/index.md), and the PKI guide is
[`docs/pki-setup.md`](docs/pki-setup.md).

## Install

Download the binary for your platform from the [latest release](https://github.com/fatred/yubivault/releases/latest).
Supported platforms:

- Linux x86-64: Debian 12 and 13, Ubuntu 24.04 and 26.04 (any distribution with glibc 2.34 or newer)
- macOS on Apple Silicon

Linux:

```shell
curl -fsSL -o yubivault https://github.com/fatred/yubivault/releases/latest/download/yubivault-linux-amd64
chmod +x yubivault
sudo mv yubivault /usr/local/bin/
```

macOS:

```shell
curl -fsSL -o yubivault https://github.com/fatred/yubivault/releases/latest/download/yubivault-darwin-arm64
chmod +x yubivault
sudo mv yubivault /usr/local/bin/
```

The macOS binary is not notarized. Downloading it with `curl` as above avoids Gatekeeper; if you
downloaded it with a browser, clear the quarantine flag first:
`xattr -d com.apple.quarantine yubivault`.

For `-yubi` you also need OpenSC, which provides the PKCS#11 module:

```shell
brew install opensc      # macOS
sudo apt install opensc  # Debian/Ubuntu
```

From source, with Go 1.27 or newer and a C compiler (the PKCS#11 bindings use cgo):

```shell
go install github.com/fatred/yubivault@latest
```

## Quick start

```shell
mkdir -p ~/.yubivault && chmod 700 ~/.yubivault
$EDITOR ~/.yubivault/config.yml     # see Configuration
export VAULT_TOKEN="$(yubivault -yubi)"
```

Minimal `~/.yubivault/config.yml` for `-yubi`:

```yaml
vaultAddr: https://vault.example.com:8200   # HTTPS is required
certAuthMount: cert                         # path the cert auth method is mounted at
certAuthName: my-role                       # cert auth role to log in as
openscPath: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so   # Debian/Ubuntu
yubikeyPivSerial: "1234567890123456"        # PKCS#11 token serial, not the device serial
```

For `-local`, use `certAuthPemFile` and `certAuthKeyFile` (names inside `~/.yubivault`) instead of
the last two fields, and `chmod 600` the key. Unknown keys are rejected, so a typo fails with
`field ... not found` instead of being ignored. Full details, including PIN, proxy, timeout and
exit-code behaviour, are in the [documentation](https://fatred.github.io/yubivault/).

## Credits

- Example of reading certificates and keys from a smartcard with crypto11: <https://gist.github.com/mikalv/7d966cd0e3342b067e1784ae3c5b0eb9>
- p11tool: <https://github.com/thales-e-security/p11tool>
