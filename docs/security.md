# Security

yubivault handles two credentials: the client key that proves your identity, and the Vault token
it prints. This page states what the program protects, what the operator has to protect, and the
boundaries that are deliberate.

## Credentials

### The private key

- **`-yubi`**: the key lives on the YubiKey and is not exportable (the [PKI setup](pki-setup.md)
  guide generates it in PIV slot 9a by convention). Only the
  certificate is read; the signature happens on the card. A stolen copy of `~/.yubivault` is not
  enough to authenticate without the card and its PIN.
- **`-local`**: the key is a file in `~/.yubivault`. yubivault opens it, checks the mode of the
  *opened* file, and refuses to continue if group or other has any right (`perm & 0o077 != 0`), so
  a world-readable key fails closed before any byte is read. The check is not a substitute for
  correct file ownership on a shared machine: ownership is not inspected.
- The certificate file (`certAuthPemFile`) is read without a mode check; a certificate is public
  data, so this is intentional.
- Errors about the key never contain its path (they say
  `private key file (certAuthKeyFile in ~/.yubivault/config.yml)`), so a path from your config
  cannot end up in a log. Error text for the certificate file does contain the resolved path.

### The PIN

- The PIN is either read from `TOKEN_PIN` (trimmed) or prompted for on stderr with terminal echo
  disabled, and is passed straight to the PKCS#11 module's `C_Login`.
- It is never written to disk, never included in an error message, and never logged.
- A wrong PIN is not retried: the YubiKey counts the attempt. Three failed attempts block the PIN;
  unblock it with the PUK. If the PUK is blocked too, only a destructive PIV reset remains (it wipes the keys on the card), so yubivault never guesses a PIN.
- `TOKEN_PIN` sits in the process environment, readable by other processes of the same user. Use
  the interactive prompt on a shared machine, and keep the PIN out of shell history.

### The issued token

- Held in memory by the Vault client for the lifetime of the process and printed once to stdout.
- Never written to disk, never passed as a command-line argument (arguments are visible in `ps`),
  and not exported to the environment by yubivault itself.
- The token is not cleared from the Vault client before exit; it disappears with the process.

### Cleanup

- The PKCS#11 context (and with it the card's login session) is closed on every path: the
  constructor closes it on any error, and `loginAndClose` closes the auth client after the login
  attempt on whether it succeeded or failed. Closing happens before the process exits, so a
  YubiKey is not left with a session held by a dead process.
- A failure to close the session is reported on stderr (`closing auth client: ...`) and does not
  change the exit status.
- On SIGINT/SIGTERM during a login, yubivault cancels the login, closes the session, and exits 1.
  After the first signal the default disposition is restored, so a stalled cleanup can still be
  killed with a second signal; the trade-off is that a signal arriving microseconds after the
  first is absorbed.

## Trust boundaries

| Component | How it is trusted |
|---|---|
| The invoking user, `~/.yubivault`, `config.yml` | Trusted. The config is operator-controlled; its own permissions are not checked. |
| The Vault/OpenBao server and any redirect target | Authenticated by TLS using the system trust store; there is no certificate pinning or way to disable verification. On Linux, `SSL_CERT_FILE`/`SSL_CERT_DIR` can redirect the trust store. `vault-client-go` follows at most one 301/302/307 to an HTTPS target; on `lookup-self` the request's `X-Vault-Token` is retained and the client certificate may be presented to that target. Trust the endpoint and any redirect destination. |
| The PKCS#11 module (`openscPath`) | Loaded with `dlopen` into the yubivault process and given the PIN. A config that names an untrusted module means running untrusted native code with the PIN. |
| Environment (`TOKEN_PIN`, proxy variables, `SSL_CERT_FILE`, `HOME`) | Caller-controlled. Proxy variables redirect where the Vault request goes (a proxy sees the TLS session, not the plaintext). |
| The shell reading stdout | Trusted by design: stdout carries only the token. |

## Operator responsibilities

- Keep `~/.yubivault` at mode `700` and the `-local` key at `0600` (yubivault enforces the key, not
  the directory).
- Keep `certAuthPemFile`/`certAuthKeyFile` as plain file names. They are joined to
  `~/.yubivault`; a value containing `..` can resolve to a file elsewhere. Absolute-looking names
  are joined under the config directory by Go's `filepath.Join`.
- Never put a PIN, token or private key in the config file, in a command line, or in shell history.
- Keep `certAuthKeyFile` and any CA private key out of backups that leave your control. In
  [PKI setup](pki-setup.md), the CA key is what lets someone mint login certificates.
- Grant the cert-auth role the narrowest constraint that works
  (`allowed_organizational_units` or `allowed_common_names`) and a short `token_ttl`, and revoke
  certificates that are no longer needed.
- This guide assumes Vault receives yubivault's TLS connection directly. A TLS-terminating proxy means Vault does not see the original client-certificate handshake; Vault's listener has a forwarded-client-certificate option (`x_forwarded_for_client_cert_header`; not verified here), but yubivault does not set forwarded-certificate headers.

## Deliberate boundaries

- No plaintext or unix-socket transport: only `https://` addresses are accepted, and the Vault
  client library's `VAULT_*` environment variables are not read, so `VAULT_ADDR` cannot silently
  redirect a login. (The exception is `TOKEN_PIN`, which can only supply a PIN.)
- MFA and response-wrapped login compatibility is not established. yubivault requires a non-empty
  `auth.client_token`; if the server response does not provide one, login fails with
  `client_token not found or empty` or `auth field not found in response`. The exact response
  behavior depends on the Vault/OpenBao deployment.
- No token persistence, caching or renewal; each run is one login.
- yubivault prints `data.id` from `auth/token/lookup-self`. The equality of that field to the login response's `auth.client_token` was not recorded across Vault/OpenBao deployments; verify the behavior of your server.
