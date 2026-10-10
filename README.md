# yubivault

Logs in to HashiCorp Vault or OpenBao with TLS certificate auth and prints the resulting token. The client certificate and key come either from files on disk (`-local`) or from a YubiKey's PIV applet over PKCS#11 (`-yubi`).

## Install

Download the binary for your platform from the [latest release](https://github.com/fatred/yubivault/releases/latest) and put it on your `PATH`. Supported platforms:

- Linux x86-64: Debian 12 and 13, Ubuntu 24.04 and 26.04 (any distribution with glibc 2.34 or newer should work)
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

The macOS binary is not notarized. Downloading it with `curl` as above avoids Gatekeeper. If you downloaded it with a browser, clear the quarantine flag first: `xattr -d com.apple.quarantine yubivault`.

For `-yubi` you also need OpenSC, which provides the PKCS#11 module:

```shell
brew install opensc      # macOS
sudo apt install opensc  # Debian/Ubuntu
```

### From source

Requires Go 1.27 or newer and a C compiler (the PKCS#11 bindings use cgo):

```shell
go install github.com/fatred/yubivault@latest
```

## Configure

Create the config directory and restrict it to your user:

```shell
mkdir -p ~/.yubivault
chmod 700 ~/.yubivault
```

Then create `~/.yubivault/config.yml`:

```yaml
# always required
vaultAddr: https://vault.example.com:8200
certAuthMount: cert           # path the cert auth method is mounted at
certAuthName: my-role         # cert auth role to log in as

# required for -local: file names inside ~/.yubivault
certAuthPemFile: client-cert.pem
certAuthKeyFile: client-cert.key

# required for -yubi
openscPath: /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so   # macOS
# openscPath: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so    # Debian/Ubuntu
yubikeyPivSerial: "1234567890123456"

# optional: shown in the PIN prompt
yubikeySerial: "12345678"
# optional: only needed if the YubiKey holds more than one certificate;
# set it to the Subject CN of the one to use
# yubikeyCertCN: my-cert-cn
```

Unknown keys are rejected, so a typo fails with `field ... not found` instead of being ignored.

**`-local`:** put the certificate and key in `~/.yubivault` and run `chmod 600` on the key. yubivault refuses a key that group or other can read.

**`-yubi`:** `yubikeyPivSerial` is the PKCS#11 token serial, not the serial printed on the YubiKey. With the YubiKey inserted, find it with:

```shell
pkcs11-tool --module /path/to/opensc-pkcs11.so --list-slots
```

Use the `serial num` value of the slot for your YubiKey.

**Vault / OpenBao:** the cert auth method must be enabled at `certAuthMount`, with a role named `certAuthName` that trusts your client certificate or its CA. [PKI-SETUP.md](PKI-SETUP.md) walks through the whole setup step by step: creating a CA with certstrap, generating the key on the YubiKey, signing and importing the certificate, and configuring the cert auth method and an admin policy.

The server's TLS certificate must be trusted by the system trust store. On Linux you can point `SSL_CERT_FILE` at a CA bundle instead.

## Usage

```shell
yubivault -local     # cert and key from ~/.yubivault
yubivault -yubi      # cert and key from the YubiKey; prompts for the PIN
yubivault -version
```

The token is the only thing written to stdout. The PIN prompt and errors go to stderr, so you can capture the token directly:

```shell
export VAULT_TOKEN="$(yubivault -yubi)"   # OpenBao: export BAO_TOKEN=...
```

- Set `TOKEN_PIN` to skip the PIN prompt in non-interactive use.
- `HTTPS_PROXY` and `NO_PROXY` are honoured in both modes.
- If Vault does not answer, yubivault gives up after about 11 seconds: a 5-second connect timeout, tried twice. The error names the address it tried (`dial tcp 10.0.0.1:8200: i/o timeout`).
- The exit status is non-zero on any failure. On Ctrl-C or SIGTERM during login, yubivault closes the YubiKey session first and then exits 1 (`interrupt signal received` / `terminated signal received`).

## Credits

- Example of reading certificates and keys from a smartcard with crypto11: https://gist.github.com/mikalv/7d966cd0e3342b067e1784ae3c5b0eb9
- p11tool: https://github.com/thales-e-security/p11tool
