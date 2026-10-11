# Agent instructions

Instructions for AI coding agents (and anyone working with one) making changes to this repository.
There is deliberately no root `AGENTS.md`: this page is the agent entry point, so it lives with the
documentation and is versioned with it.

## Read before editing

| File | Why |
|---|---|
| `main.go` | The whole program: flags, config, both auth modes, TLS/transport, login, signals. |
| `main_test.go` | Unit tests: config validation, key mode refusal, PIN resolution, certificate selection, TLS presentation, retry count, close-on-failure. |
| `softhsm_test.go` | The SoftHSM integration test and the child-process harness pattern. |
| `go.mod` | Dependency and toolchain versions (`go 1.27.0`; `govulncheck` is a tool dependency). |
| `.github/workflows/ci.yml` | The commands that must pass, and the Linux-only SoftHSM requirement. |
| `.github/workflows/release.yml` | Build/ldflags/tag expectations. |
| `docs/` | User-facing claims. Any behaviour change updates the matching page. |

`audit-context/` holds internal audit material. It is intentionally outside `docs_dir` and must
never be added to the nav or referenced from published pages.

## Where the code is

All production code is one file, `package main`, in `main.go`.

| Concern | Symbol |
|---|---|
| Flag parsing, mode dispatch, config load, signal setup, output | `run`, `main` |
| Config decode and validation | `LoadConfig`, `requireForMode` |
| `-local` client | `CreateLocalVaultClient`, `readPrivateKey`, `pathErrCause` |
| `-yubi` client | `CreateYubikeyVaultClient`, `selectCertificate`, `certCNs`, `resolvePin`, `ReadPin` |
| Vault client, TLS, transport, timeouts | `newVaultClient`, `clientTLSConfig`, `newHTTPClient`, `dialTimeout`, `requestTimeout` |
| Login and token read-back | `AuthenticateAndGetToken`, `loginAndClose`, `VaultClient`, `RealVaultClient` |
| Client lifetime | `VaultAuthClient`, `LocalVaultClient`, `YubikeyVaultClient` |

## Invariants

Preserve these; each is relied on by tests, docs or the shell contract.

1. **stdout carries the token and nothing else.** Prompts, warnings and errors go to stderr
   (`ReadPin` gets `os.Stderr`; `log` writes to stderr). `VAULT_TOKEN="$(yubivault -yubi)"` depends
   on it.
2. **`run` returns nil exactly when one line was written to stdout** (`-version`, or the token).
3. **Exactly one of `-local`/`-yubi`**; `-version` is handled first and standalone.
4. **`vaultAddr` is an absolute HTTPS URL.** `LoadConfig` rejects every other scheme before a
   client is built; do not relax this without a documented reason.
5. **Config parsing is strict**: `KnownFields(true)`, exactly one YAML document, empty file is an
   error, `vaultAddr`/`certAuthName`/`certAuthMount` always required, mode-specific fields checked
   by `requireForMode`.
6. **The `-local` key check fails closed**: the mode is read from the opened file, group/other bits
   are refused, the key path never appears in an error (`keyFileField`,
   `pathErrCause`).
7. **The key is read before the certificate**, so a bad-permission key fails even when the
   certificate is missing.
8. **One PKCS#11 context, closed exactly once**, on every path: the constructor's deferred error
   guard and `loginAndClose`'s defer are mutually exclusive; `Close` must not be called twice
   (crypto11 panics on a second close).
9. **The client certificate is always presented** (`GetClientCertificate`, ignoring advertised CA
   names) and `MinVersion` stays at TLS 1.2 or higher.
10. **Transport comes from a clone of `http.DefaultTransport`** so proxy support and HTTP/2 are
    inherited; the dial timeout stays 5 seconds, the request timeout 30 seconds, and retries stay
    at one (`RetryMax: 1` with non-zero backoff). Increasing retries on top of connect timeouts is
    what made 1.4.0 hang for a minute.
11. **Signal handling is installed after the PIN is read**, and a cancelled context suppresses the
    token even if the login succeeded.
12. **No secrets in output**: never print a PIN, a token other than the captured one, or key
    material; errors must not include the private key path.

`docs/maintainers/architecture.md` explains why each of these is the way it is.

## Verify a change

```shell
export PATH=$HOME/.go/bin:$HOME/go/bin:$PATH   # if the toolchain is not on PATH
gofmt -l .                                     # must print nothing
go mod tidy -diff                              # must print nothing
go vet ./...
go test -race ./...
go tool govulncheck ./...
```

On Linux with `opensc` and `softhsm2` installed, make the SoftHSM integration test mandatory
exactly as CI does:

```shell
YUBIVAULT_REQUIRE_SOFTHSM=1 go test -race -run SoftHSM ./...
```

For changes to `run`, the transport, or PIN handling, exercise the changed path. A live Vault login
is appropriate only when you are authorized to use that non-production environment; otherwise use
the existing `httptest` and SoftHSM coverage. To check the non-terminal PIN failure without sending
a PIN to the card, use a valid `-yubi` config and run:

```shell
yubivault -yubi </dev/null
```

## Tests

- Table-driven subtests, `t.Run`, and the existing helpers (`writeConfig`, `selfSignedCert`,
  `captureStdout`, `MockVaultClient`, `closeRecorder`).
- Test behaviour and boundaries: config rejection cases, certificate selection, retry count,
  refusal of a readable key, `Close` on failure, the exact error text a user sees.
- Do not add tests that only assert wiring, mock echo, or the source text of a message.
- Process-level state needs the child-process pattern already used three times: TLS roots are
  cached by Go (`TestCreateYubikeyVaultClient_SoftHSM` sets `SSL_CERT_FILE` in a child) and
  `ProxyFromEnvironment` is read once per process
  (`TestNewHTTPClient_UsesProxyFromEnvironment`), while `TestReadPin_TerminalBranch` re-executes the
  test binary to get a non-terminal stdin.
- The SoftHSM test skips unless `YUBIVAULT_REQUIRE_SOFTHSM=1`; do not weaken that gate — it exists
  so the test is mandatory in Linux CI and optional elsewhere.

## Docs, CI and release expectations

- Docs are built with `mkdocs build --strict`, so every page must be in `mkdocs.yml`'s nav and
  every relative link must resolve. Add a page and add it to the nav in the same change.
- `docs/pki-setup.md` is the only copy of the PKI guide; edit it there, never create a second one,
  and keep `README.md` pointing at the published site.
- New or renamed flags, config fields, error messages, timeouts, exit codes or supported platforms
  change user-visible behaviour: update the matching page under `docs/` in the same change.
- GitHub Actions are pinned to full commit SHAs with the tag in a trailing comment; Dependabot
  updates them. Keep new actions pinned and do not widen workflow permissions.
- The release workflow builds natively with cgo, injects `-X main.Version=<tag>` and must not be
  weakened (no cache, pinned actions, native runner assertion).

## Hard constraints

- **Never guess a YubiKey PIN.** Three wrong attempts lock the PIV applet. Do not run anything that
  consumes a PIN attempt (`pkcs11-tool --login`, `ykman piv` operations, repeated `-yubi` runs) to
  "see what happens".
- Do not commit, print or paste PINs, tokens, private keys, or real token serial numbers into code,
  tests, docs or commit messages. Test fixtures use throwaway SoftHSM tokens and self-signed
  certificates.
- Do not run destructive commands against a real card or a live Vault (no PIN changes, no factory
  reset, no token or entity deletion) unless the owner asks for it explicitly.
- Do not add a root `AGENTS.md`, `CLAUDE.md` or similar: instructions belong on this page.
- Do not edit `audit-context/` during ordinary documentation changes. Update it only when that work
  is explicitly in scope; never publish it.
