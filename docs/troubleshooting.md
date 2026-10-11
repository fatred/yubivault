# Troubleshooting

Errors go to stderr; the exit status is non-zero on any failure (see
[Usage](usage.md#signals-and-exit-codes)). Start with the message you got.

## Configuration and startup

| Message | Cause | Fix |
|---|---|---|
| `open /home/you/.yubivault/config.yml: no such file or directory` | No config file. | Create `~/.yubivault/config.yml` ([Configuration](configuration.md)). |
| `<path> is empty` | The file exists but has no content. | Fill it in. |
| `<path>: field <name> not found` | Unknown key: a typo, wrong case, or a retired setting (`yubikeyPivIndex`, `yubikeyPivLabel`). | Use one of the documented field names. |
| `<path> must contain a single YAML document` | A second `---` document in the file. | Delete everything after the first document. |
| `vaultAddr is required` | Field missing or empty. | Set it. |
| `vaultAddr must be an absolute HTTPS URL` | `http://`, `unix://`, another scheme, no scheme (`localhost:8200`), an opaque URI, or no host (`https:///v1`). | Use `https://host[:port]`. |
| `certAuthName and certAuthMount are required` | One of the two is empty. | Set both. |
| `certAuthPemFile and certAuthKeyFile are required for -local` | `-local` without file names. | Add both fields, or use `-yubi`. |
| `openscPath and yubikeyPivSerial are required for -yubi` | `-yubi` without the module path or token serial. | Add both fields, or use `-local`. |
| `Pick -local or -yubi` | Both flags, or neither. | Pass exactly one. |

## `-local`

| Message | Cause | Fix |
|---|---|---|
| `could not open private key file (certAuthKeyFile in ~/.yubivault/config.yml): no such file or directory` | The key file is not there (or the name is wrong). | Put it in `~/.yubivault` with the configured name. |
| `private key file (certAuthKeyFile in ~/.yubivault/config.yml) is accessible by group/other (mode 0o644); run chmod 600 on it` | The key's mode grants group or other any right. | `chmod 600 ~/.yubivault/<key>`. Modes `0640`, `0660`, `0644` all fail; `0600` and `0400` pass. |
| `could not read certificate file (certAuthPemFile): open ...: no such file or directory` | The certificate file is missing or misnamed. | Fix the name or copy the file in. |
| `could not load client certificate and key: tls: ...` | The PEM cannot be parsed, or the key does not match the certificate. | Check that both files are PEM and that the certificate was issued for that key. |

## `-yubi`

| Message | Cause | Fix |
|---|---|---|
| `could not configure crypto11: ...` | The module in `openscPath` is missing or not a PKCS#11 library, no card with the given `yubikeyPivSerial` is present, or the PIN was rejected. | Check the module path (see [Install](install.md)), run `pkcs11-tool --module <path> --list-slots`, and confirm `yubikeyPivSerial` is the `serial num` line. If it is a PIN error, confirm the PIN with `ykman` before spending another attempt. |
| `could not search for certificates: ...` | Reading the card's objects failed (card removed mid-run, module error). | Reseat the card and retry. |
| `no paired credentials found on YubiKey` | The card exposes no certificate with matching private key. | Generate the slot 9a key and import the certificate ([PKI setup](pki-setup.md), steps 2–4). |
| `multiple credentials on card; set yubikeyCertCN to one of: "a", "b"` | More than one paired credential on the card. | Set `yubikeyCertCN` to the Common Name of the right one. |
| `no credential with CN "x"; available: "a", "b"` | `yubikeyCertCN` matches nothing the card offers. | Correct it, or remove it if only one credential is expected. |
| `multiple credentials with CN "x" on card; cannot disambiguate` | Two credentials share one Common Name. | Regenerate or re-import so the Common Names differ. |
| `could not read PIN code: <cause>` | No `TOKEN_PIN` and stdin is not a terminal (cron, CI, pipe), or the terminal read failed. | Set `TOKEN_PIN` in non-interactive use. |
| `need to enter PIN or set via $TOKEN_PIN` | The prompt got an empty line. | Enter the PIN, or set `TOKEN_PIN`. |
| The card's LED blinks and the login fails while signing | The slot 9a key may require a touch during the TLS handshake. The exact wait and retry behaviour depends on the PKCS#11 stack; a fixed 10-second timeout is not guaranteed. | Touch the card promptly when it blinks. |

If neither PIN nor touch is the problem, confirm the card independently:

```shell
ykman piv info
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots
```

`ykman piv info` on older firmware (5.1.x) can print `Private key type: EMPTY` for a slot that
does hold a key; that line is a firmware metadata limitation, not evidence that the slot is empty.
`ykman piv info` also shows the remaining PIN attempts.

## Connecting to Vault

| Message | Cause | Fix |
|---|---|---|
| `dial tcp <addr>: connection refused` | Nothing is listening at that address and port (wrong port, server down, firewall rejecting). | Check `vaultAddr` and that Vault is up. |
| `dial tcp <addr>: i/o timeout` | The address is blackholed or filtered; the message appears after roughly 11 seconds (a 5-second connect timeout, a retry, and the backoff). | Check routing, firewall and the proxy settings. |
| `x509: certificate signed by unknown authority` | The server's certificate chain is not in the system trust store. | Install the CA in the system store, or point `SSL_CERT_FILE` at the CA bundle. |
| `x509: certificate is valid for X, not Y` | `vaultAddr`'s host name does not match the server certificate. | Use the name the certificate was issued for. |
| TLS handshake failure against a load balancer in front of Vault | The proxy terminated TLS, so your client certificate never reached Vault. | Point yubivault at Vault itself; cert auth requires Vault to terminate TLS. |
| Timeout only when `HTTPS_PROXY` is set | The proxy cannot reach Vault, or it blocks the CONNECT. | Unset the proxy, or fix the proxy; use `NO_PROXY` for the Vault host. |

## Vault rejecting the login

The error body from Vault is reported as-is.

| Message | Cause | Fix |
|---|---|---|
| `failed to match all constraints for this login certificate` (HTTP 400) | The certificate does not satisfy the cert-auth role: wrong role name, an organizational unit the role does not allow, or a certificate signed by a CA the role does not trust. | Compare the certificate's OU/CN with the role's constraints (`vault read auth/<mount>/certs/<role>`), and confirm `certAuthName`/`certAuthMount`. |
| `permission denied` (HTTP 403) | The login worked but the token lacks access to `auth/token/lookup-self`, or the token was revoked between the two calls. | Check the role's `token_policies`; a policy that grants nothing on `auth/token/lookup-self` breaks the lookup step. |
| `client_token not found or empty` or `auth field not found in response` | The login response did not provide a usable token. MFA or response wrapping may affect the response, but compatibility depends on the Vault/OpenBao deployment and is not established here. | Check the server's login response and configuration; yubivault requires `auth.client_token`. |
| `cert login response not found`, `token lookup-self response not found` | The server returned 200 with an empty body. | Check for an interposing proxy that rewrites responses, and the server version. |
| `token id not found or not a string`, `token id is empty` | The lookup response did not contain a usable `id`. | Check that the token belongs to the built-in token store and was not revoked in flight. |

## Signals

| Message | Meaning |
|---|---|
| `interrupt signal received` | SIGINT (Ctrl-C) during a login; the session was closed, exit 1. |
| `terminated signal received` | SIGTERM during a login; the session was closed, exit 1. |
| `closing auth client: ...` | Closing the YubiKey session failed. After a successful login, the token is still printed and the exit status remains 0; if login already failed, the process exits 1 without printing a token. |

## macOS

- `zsh: bad CPU type in executable` — the published macOS binary is arm64 only; it does not run on
  Intel Macs.
- "yubivault cannot be opened because the developer cannot be verified" — the binary is not
  notarized. Clear the quarantine flag: `xattr -d com.apple.quarantine /usr/local/bin/yubivault`.
