# Install

## Release binaries

Every `vX.Y.Z` tag publishes two binaries as GitHub release assets:

| Asset | Platform | Notes |
|---|---|---|
| `yubivault-linux-amd64` | Linux, x86-64 | Debian 12 and 13, Ubuntu 24.04 and 26.04; other distributions with glibc 2.34 or newer should work |
| `yubivault-darwin-arm64` | macOS, Apple Silicon | Not notarized |

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

The macOS binary is not notarized. Downloading it with `curl` as above avoids Gatekeeper. If you
downloaded it with a browser instead, clear the quarantine flag first:

```shell
xattr -d com.apple.quarantine yubivault
```

There is no Windows build and no 32-bit or Intel-macOS build: the YubiKey support needs cgo, and
release binaries are built natively on the matching runner.

Release downloads have no published checksum or attestation: the release workflow publishes none,
so the download is trusted on the strength of GitHub and TLS alone.

## Behaviour on `main`

These pages describe `main`. The latest release (v1.4.2) does not yet include three documented
behaviours: `vaultAddr` must be an HTTPS URL (v1.4.2 accepts `http://`), `TOKEN_PIN` is trimmed of
surrounding whitespace, and an empty login or lookup response and an empty token `id` fail with an
explicit error (`cert login response not found`, `token lookup-self response not found`,
`token id is empty`). Install from source (`go install`) to get them before the next release.

## OpenSC (required for `-yubi`)

`-yubi` loads a PKCS#11 module to reach the card. OpenSC provides it:

```shell
brew install opensc      # macOS
sudo apt install opensc  # Debian/Ubuntu
```

The module path varies by distribution. Typical paths are:

| Platform | Module |
|---|---|
| Debian/Ubuntu | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| Apple Silicon macOS (Homebrew) | `/opt/homebrew/opt/opensc/lib/opensc-pkcs11.so` |

On another distribution, locate the module after installing OpenSC:

```shell
find /usr /opt -name opensc-pkcs11.so 2>/dev/null
```

`-local` needs no OpenSC installation. On macOS, `ykman` (YubiKey Manager) is only needed for the
PKI steps of [PKI setup](pki-setup.md), not for running yubivault.

## From source

Requires Go 1.27 or newer and a C compiler, because the PKCS#11 bindings use cgo:

```shell
go install github.com/fatred/yubivault@latest
```

`go install` produces an untagged binary, so `yubivault -version` prints `dev` rather than a
release version. The release workflow injects the real version with
`-ldflags "-X main.Version=<tag>"`.

## Check the installation

```shell
yubivault -version
```

- Release build: prints the tag it was built from, for example `v1.4.0`.
- `go install` build: prints `dev`.

`-version` never reads the config file and never touches the card.
