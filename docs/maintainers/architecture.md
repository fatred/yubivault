# Architecture

yubivault is a single-binary Go CLI, one `package main` in `main.go`. It has no subcommands, no
daemon, no state on disk beyond reading `~/.yubivault`, and no output other than one line on
stdout. The Vault work is two HTTP requests.

## Flow

```text
main
 └── run(args)
      ├── flag.NewFlagSet  -local | -yubi | -version (ExitOnError)
      ├── -version ────────────────────────────────────────► print Version, exit 0
      ├── mode exclusivity check                      ("Pick -local or -yubi")
      ├── os.UserHomeDir ─► LoadConfig(~/.yubivault/config.yml)
      │                        strict YAML: known keys, one document, required fields,
      │                        https:// vaultAddr only
      ├── requireForMode      mode-specific fields
      ├── -yubi: resolvePin   $TOKEN_PIN, else prompt on stderr (term.ReadPassword)
      ├── signal.NotifyContext(INT, TERM) + context.AfterFunc(ctx, stop)
      ├── -local: CreateLocalVaultClient           -yubi: CreateYubikeyVaultClient
      │     ├── readPrivateKey (mode check, fail-closed)      ├── crypto11.Configure(path, serial, pin)
      │     ├── os.ReadFile(cert)                             ├── FindAllPairedCertificates (pairs by CKA_ID)
      │     ├── tls.X509KeyPair                               ├── selectCertificate (by Subject CN)
      │     └── newVaultClient                                └── newVaultClient
      ├── loginAndClose(ctx, authClient, config)  ── defer authClient.Close()  (PKCS#11 Close)
      │     └── AuthenticateAndGetToken
      │           ├── POST /v1/auth/<mount>/login {"name": <role>}
      │           ├── SetToken(auth.client_token)
      │           ├── GET  /v1/auth/token/lookup-self    (X-Vault-Token)
      │           └── return data["id"]
      ├── context.Cause check (a signal beats a successful login)
      └── fmt.Println(token) ─────────────────────────────► stdout
```

`main` does nothing but call `run` and `log.Fatal` on error, so every `defer` in `run` (notably the
PKCS#11 close) completes before the process exits.

## HTTP behaviour

`newVaultClient` builds one `vault.Client` used by both modes:

- `clientTLSConfig` presents the client certificate from `GetClientCertificate` on every
  handshake. Using the plain `Certificates` field instead makes Go skip the certificate when the
  server's advertised CA names do not include the issuer, which breaks cert auth; Vault only
  advertises names when the listener is configured to verify client certificates. `MinVersion` is
  TLS 1.2.
- `newHTTPClient` clones `http.DefaultTransport` (so `ProxyFromEnvironment`, HTTP/2 and the stdlib
  idle/handshake timeouts are inherited), replaces `DialContext` with a 5-second dialer, sets a
  30-second client timeout, and returns 3xx responses to `vault-client-go`, which follows at most one 301/302/307 redirect and refuses HTTPS-to-non-HTTPS downgrades.
- Retries are `RetryMax: 1` with a 1–1.5 second backoff. The library default of two retries stacked
  on connect timeouts is what made an unreachable Vault appear to hang for a minute.
- The server is verified against system trust by default. Linux honors `SSL_CERT_FILE`/`SSL_CERT_DIR`;
  the Go 1.27+ macOS release builds honor them too, using those roots instead of Keychain unless
  `GODEBUG=x509sslcertoverrideplatform=0`. There is no pinning or way to skip verification.

## Repository map

| Path | Contents |
|---|---|
| `main.go` | The whole program; see the symbol table in [Agent instructions](../agents.md#where-the-code-is). |
| `main_test.go` | Unit tests with `MockVaultClient` (interface-level) and `closeRecorder`, plus `httptest` servers for TLS presentation, proxy use and retry counting. |
| `softhsm_test.go` | End-to-end `-yubi` lifecycle test against a disposable SoftHSM token with a local TLS server. |
| `go.mod`, `go.sum` | `crypto11` (PKCS#11), `vault-client-go`, `yaml/v3`, `x/term`; `govulncheck` as a tool dependency. |
| `.github/workflows/ci.yml` | `go mod tidy -diff`, gofmt, `go vet`, `go test -race` on Ubuntu and macOS; Linux installs OpenSC and SoftHSM and requires the SoftHSM test. A separate Ubuntu-only job runs `govulncheck`. |
| `.github/workflows/release.yml` | Native cgo builds on a `vX.Y.Z` tag, artifact upload, GitHub release. |
| `.github/workflows/docs.yml` | `mkdocs build --strict` on PRs and main; Pages deployment on main only. |
| `mkdocs.yml`, `docs/` | The published documentation (`docs/` is the only content root). |
| `.github/dependabot.yml`, `.github/changelog-config.json` | Action pin updates, release changelog categories. |
| Internal review material | Outside `docs_dir`; not copied to the published site. |

## Testability seams

- `VaultAuthClient` (client + `io.Closer`) and `VaultClient` (the three auth calls) exist so tests
  can substitute `closeRecorder`, `MockVaultClient` and `closeCountingYubikeyClient`, and can
  observe that a client is closed on both the success and failure paths.
- `ReadPin(serial, io.Reader, io.Writer)` takes its reader and prompt writer as parameters so the
  prompt path can be tested without a terminal; `resolvePin` is the production wrapper that passes
  `os.Stdin`/`os.Stderr`.
- `selectCertificate(pairs, wantCN)` is pure, so ambiguity and mismatch errors are unit-tested
  without hardware.
- The SoftHSM integration test exercises the real `crypto11` code path (configure, enumerate,
  select, sign through TLS, close) with a throwaway token, which is why CI requires SoftHSM on
  Linux.

## Design decisions worth knowing

| Decision | Rationale |
|---|---|
| HTTPS-only `vaultAddr` | Certificate auth over plaintext, or a unix socket that bypasses the configured dialer, is not a supported configuration; rejecting it early gives one clear error. |
| Strict YAML (`KnownFields`, single document) | A typo silently ignored means logging in with the wrong role or certificate; a second document would escape the unknown-key check. |
| Key mode checked on the opened handle | The file that is checked is the file that is read (no check-then-open race). |
| Key path suppressed in errors | The path comes from config and must not reach logs; the certificate path is not sensitive in the same way and is reported. |
| One retry, short connect timeout | An unreachable Vault must fail in seconds, not a minute. |
| Signal handler installed after the PIN read | `term.ReadPassword` should stay interruptible by the default disposition; later, cancellation must not skip closing the card session. |
| Token read back with `lookup-self` | yubivault prints `data.id` from the authenticated lookup response; equality with the original `auth.client_token` is not established across deployments. |

## Known limits

- yubivault requires a non-empty `auth.client_token`. MFA and response-wrapped login response
  behavior has not been verified against Vault/OpenBao deployments.
- The token is not cleared from the Vault client before exit.
- The SoftHSM test is mandatory only on Linux; the macOS CI job skips it.
- Provenance/chain checks on the `-local` certificate happen on the server side; the client does
  not validate its own certificate before the handshake.
- `~/.yubivault`'s own permissions are documented, not enforced; only the key file is checked.
