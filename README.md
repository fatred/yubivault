# yubivault

simple binary that will use a local cert/key pair on disk or on a yubikey to login to vault and give you a token for subesequent use in automations etc.

## PreReqs

0. install opensc 
  a. macOS: `brew install opensc`
  b. linux: `apt install opensc` # or whatever your package manager is...
1. Make a folder called `mkdir -p ~/.yubivault`
2. Restrict it to you only `chmod 700 ~/.yubivault` (and `chmod 600` the key file)
3. Make a config file:

```yaml
---
# always required
vaultAddr: https://vault.problemofnetwork.com:8200
certAuthName: network_admin_g2
certAuthMount: network_admin
# required for -local (file names inside ~/.yubivault)
certAuthPemFile: client-cert.pem
certAuthKeyFile: client-cert.key
# required for -yubi
openscPath: "/opt/homebrew/Cellar/opensc/0.27.1/lib/pkcs11/opensc-pkcs11.so"
# debian
# openscPath: "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"
yubikeyPivSerial: "1234567890123456"
# optional: only used to label the PIN prompt
yubikeySerial: "12345678"
# optional: only needed when the card holds more than one credential.
# Set it to the certificate Subject CN of the credential you want.
# yubikeyCertCN: "network_admin_g2"
```

Unknown keys are rejected, so a typo or a retired setting (`yubikeyPivIndex`, `yubikeyPivLabel`) fails with `field … not found` instead of being silently ignored.

4a. for local auth: put valid cert/key pair into that path

4b. for yubi auth: 
  i) configure the parameters based on the output from `p11tool  --list-tokens`.
  ii) configure the opensc path based on the package managers outputs. e.g. `brew info opensc` or check your package manager repo like so: https://packages.debian.org/trixie/amd64/opensc-pkcs11/filelist

## How it works

local:
```shell
$ yubivault -local
s.pUeO2Nr3P9aBRHasdfasdfasdfasdf
```

yubikey:
```shell
$ yubivault -yubi
PIN for 12345678: 
s.LtSpaGkxDq0Nrrrxlolasdfsasfdsw
```


### Credits

Needed a lot of help along the way. These were helpful

* an example of using the Thales pkcs11 crypto library to access the certs/keys off a smartcard: https://gist.github.com/mikalv/7d966cd0e3342b067e1784ae3c5b0eb9
* the official p11tool from Thales: https://github.com/thales-e-security/p11tool

### macOS (Apple Silicon)

Releases include `yubivault-darwin-arm64`, built natively on a macOS runner (crypto11 needs cgo, so it cannot be cross-compiled from Linux). The binary is not notarized, so after downloading it with a browser, clear the quarantine flag before running it:

```shell
xattr -d com.apple.quarantine yubivault-darwin-arm64
chmod +x yubivault-darwin-arm64
```

To build from source instead, check out the tag you want and run `go build -ldflags "-X 'main.Version=vX.Y.Z'"`, or just `go build .` on `main`.
