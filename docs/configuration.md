# Configuration

yubivault reads exactly one file: `$HOME/.yubivault/config.yml`. There is no command-line or
environment override for any field (the PIN is the sole environment input, see [Usage](usage.md)).

Create the directory and restrict it to yourself:

```shell
mkdir -p ~/.yubivault
chmod 700 ~/.yubivault
```

## Fields

Every field is a YAML string. There are no defaults: a field that is not set is empty.

| Field | Required | Description |
|---|---|---|
| `vaultAddr` | always | Absolute HTTPS URL of Vault or OpenBao, including the host, e.g. `https://vault.example.com:8200`. The scheme is normalised to lowercase `https`. |
| `certAuthName` | always | Name of the cert-auth role to log in as. Sent as `name` in the login request. |
| `certAuthMount` | always | Path the cert auth method is mounted at, e.g. `cert`. The login goes to `/v1/auth/<certAuthMount>/login`. |
| `certAuthPemFile` | `-local` | File **name** inside `~/.yubivault` holding the client certificate in PEM form (leaf first; further certificates may follow as a chain). |
| `certAuthKeyFile` | `-local` | File name inside `~/.yubivault` holding the matching private key. The file must not be readable by group or other. |
| `openscPath` | `-yubi` | Filesystem path of the PKCS#11 module, e.g. `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`. |
| `yubikeyPivSerial` | `-yubi` | PKCS#11 token serial of the YubiKey. This is **not** the serial printed on the device. |
| `yubikeySerial` | optional | Free-text device serial shown in the PIN prompt (`PIN for <value>: `). Cosmetic only. |
| `yubikeyCertCN` | optional | Subject Common Name of the certificate to use, needed only when the card holds more than one paired credential. |

`vaultAddr`, `certAuthName` and `certAuthMount` are checked for every mode. The two mode-specific
groups are checked only in the mode that needs them, so a `-local` config does not need
`openscPath`/`yubikeyPivSerial`, and a `-yubi` config does not need the two file names.

## Parsing rules

- Unknown keys are rejected: `field <name> not found`. A typo, a retired setting
  (`yubikeyPivIndex`, `yubikeyPivLabel`) or a wrong case fails at startup instead of being
  ignored.
- The file must contain exactly **one** YAML document. A second `---` document is an error.
- An empty file fails with `<path> is empty`.
- `vaultAddr` is accepted only as an absolute `https://` URL. Rejected: `http://`, `unix://`, any
  other scheme, a value with no scheme (`localhost:8200`), an opaque URI (`https:localhost:8200`)
  and a URL with no host (`https:///v1`, `https://:8200`). The error is always
  `vaultAddr must be an absolute HTTPS URL`.

## Example: `-yubi`

```yaml
vaultAddr: https://vault.example.com:8200  # HTTPS is required
certAuthMount: cert                        # path the cert auth method is mounted at
certAuthName: admin                        # cert auth role to log in as

openscPath: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so   # Debian/Ubuntu
# openscPath: /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so   # macOS

yubikeyPivSerial: "1234567890123456"       # PKCS#11 token serial, not the device serial

yubikeySerial: "12345678"                  # optional: shown in the PIN prompt
# yubikeyCertCN: alice                     # optional: only if the card holds several certs
```

Find the PKCS#11 token serial with the YubiKey inserted:

```shell
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots
```

Use the `serial num` line of the slot for your YubiKey. It is a long number (typically 16 digits)
and is unrelated to the serial printed on the device or shown by `ykman`.

## Example: `-local`

```yaml
vaultAddr: https://vault.example.com:8200
certAuthMount: cert
certAuthName: admin
certAuthPemFile: client-cert.pem
certAuthKeyFile: client-cert.key
```

Then place both files in `~/.yubivault` and restrict the key:

```shell
chmod 600 ~/.yubivault/client-cert.key
```

yubivault refuses to start if the key file is readable by group or other, and the check is made on
the file it actually opens. Modes `0600`, `0400` and stricter are accepted; `0640`, `0644` and
`0660` are not.

`certAuthPemFile`/`certAuthKeyFile` are joined to `~/.yubivault`, so keep them plain file names.
A value containing `..` can resolve outside the directory; absolute-looking names are joined
under the config directory by Go's `filepath.Join`. See [Security](security.md).

## Related

- Certificate authority, YubiKey certificate and Vault cert-auth role: [PKI setup](pki-setup.md).
- Flags, PIN, proxy, timeouts and exit codes: [Usage](usage.md).
