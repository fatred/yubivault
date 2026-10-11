# Usage

```shell
yubivault -local     # certificate and key from ~/.yubivault
yubivault -yubi      # certificate and key from the YubiKey; prompts for the PIN
yubivault -version   # print the version and exit
```

## Flags

| Flag | Effect |
|---|---|
| `-local` | Use `certAuthPemFile` and `certAuthKeyFile` from `~/.yubivault`. |
| `-yubi` | Use the certificate and key on the YubiKey through `openscPath`. |
| `-version` | Print the version and exit 0. Standalone: it ignores `-local`/`-yubi` and never reads the config or the card. |

Exactly one of `-local` and `-yubi` is required for a login; passing both or neither fails with
`Pick -local or -yubi`. Positional arguments are ignored. Flag parsing uses the standard library
flag package with `ExitOnError`, so an unknown flag (`-foo`) exits 2 and `-h` exits 0.

## Output contract

- **stdout** carries the token and nothing else — one line, from `auth/token/lookup-self`.
- **stderr** carries the PIN prompt, the warning if closing the YubiKey session fails, and every
  error.

So the token can be captured directly:

```shell
VAULT_TOKEN="$(yubivault -yubi)" && export VAULT_TOKEN   # OpenBao: BAO_TOKEN
```

yubivault does not export `VAULT_ADDR` or anything else: set that yourself (or in your shell
profile) so that the Vault CLI, which does read it, talks to the same server.

## PIN handling (`-yubi`)

1. If `TOKEN_PIN` is set to a non-empty value, it is used. Leading and trailing whitespace is
   trimmed, so `TOKEN_PIN=" 123456 "` works. A whitespace-only value counts as unset.
2. Otherwise yubivault prompts on **stderr**:

   ```text
   PIN for 12345678: 
   ```

   The value after `PIN for ` is `yubikeySerial` if you set it, otherwise empty. Input is read from
   the terminal without echo.
3. An empty (or whitespace-only) input fails with `need to enter PIN or set via $TOKEN_PIN`.
4. If stdin is not a terminal — a cron job, a CI step, a pipe — the prompt cannot be read and the
   run fails with `could not read PIN code: ...`. Use `TOKEN_PIN` there.

To keep a PIN out of shell history, and give it only to the yubivault process rather than to every command:

```shell
printf 'YubiKey PIN: ' >&2
read -rs TOKEN_PIN
printf '\n' >&2
VAULT_TOKEN="$(TOKEN_PIN="$TOKEN_PIN" yubivault -yubi)" && export VAULT_TOKEN
unset TOKEN_PIN
```

`TOKEN_PIN` is visible in the environment of the yubivault process (and to other processes of the
same user while it runs). Prefer the interactive prompt on a shared machine.

**The YubiKey retry counter is a hard limit.** Firmware 5.x allows three PIN attempts; after that
the PIN is blocked. Unblock it with the PUK; if the PUK is blocked too, only a destructive PIV
reset remains, which wipes the keys on the card. yubivault never guesses a PIN and never
retries a failed `C_Login` (a failed attempt is counted by the card, not by yubivault). If the PIN
is unknown, stop and find out before running.

## Network behaviour

Both modes share one HTTP transport:

| Setting | Value |
|---|---|
| Connect (dial) timeout | 5 seconds per attempt, covering DNS and connecting |
| Request timeout | 30 seconds per attempt (HTTP client), and a 30-second cap on the request from the Vault client library |
| Retries | One, after a 1–1.5 second backoff — two attempts per request. Retried: connection errors and the library's retryable statuses (5xx except 501, 429, 412). |
| Redirects | `vault-client-go` follows at most one 301, 302 or 307; HTTPS-to-non-HTTPS redirects are refused. |
| Proxy | Honoured from the environment: `HTTPS_PROXY`/`https_proxy`, `HTTP_PROXY` and `NO_PROXY`/`no_proxy`. |
| TLS | Server verified against the system trust store; minimum TLS 1.2. On Linux, `SSL_CERT_FILE`/`SSL_CERT_DIR` can point at a CA bundle instead; on macOS, add the CA to the keychain. |
| Client certificate | Presented whenever the server asks, regardless of which CA names it advertises. For `-yubi` the leaf certificate only is sent; make sure the cert-auth role trusts the issuing CA. |

What a failure looks like, in wall-clock terms:

- A refused connection fails in about a second.
- A blackholed address (traffic silently dropped) fails after about 11 seconds with
  `dial tcp 10.62.0.1:8200: i/o timeout`. The error names the address that was tried, which tells a
  refused connection (`connection refused`) apart from an unreachable one.
- A TLS-terminating proxy means Vault does not receive yubivault's original client-certificate handshake. Vault's listener has a forwarded-client-certificate option (`x_forwarded_for_client_cert_header`; not verified here), but yubivault does not set forwarded-certificate headers. This guide assumes Vault receives the TLS connection directly.

## Signals and exit codes

Signal handling is installed **after** the PIN has been read. Before that, Ctrl-C keeps its default
meaning.

| Exit code | When |
|---|---|
| 0 | Token printed, or `-version` |
| 1 | Any failure, including a login cancelled by a signal |
| 2 | Flag parsing error (for example an unknown flag) |

During or after a login, SIGINT and SIGTERM do not kill the process immediately: they cancel the
login, yubivault closes the YubiKey session, and it exits 1 with `interrupt signal received` or
`terminated signal received`. A signal that races a successful login still wins — no token is
printed. After the first signal, the default action is restored, so a cleanup that stalls can
still be interrupted by a second signal.

At the PIN prompt there is no handler yet, so Ctrl-C kills the process the usual way (the shell
reports 130).

## Token lifetime

The cert-auth role's `token_ttl`/`token_max_ttl` bound the token. Whether a cert-auth token can be
renewed without presenting the client certificate again depends on the role and server
(unverified here), and yubivault never renews: re-run it when the token expires.
