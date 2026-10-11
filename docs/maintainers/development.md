# Development and tests

## Prerequisites

| Need | Why |
|---|---|
| Go 1.27 or newer | `go.mod` declares `go 1.27.0`, and `govulncheck` is a tool dependency. |
| A C compiler | The PKCS#11 bindings (`miekg/pkcs11`) use cgo, so builds need `CGO_ENABLED=1` and a working `cc`. |
| OpenSC (`opensc`) | Provides `pkcs11-tool` (card inspection) and the PKCS#11 module used by `-yubi`. |
| SoftHSM (`softhsm2`, `softhsm` on macOS) | Provides `softhsm2-util` and `libsofthsm2.so` for the integration test. Without it that test skips locally. |
| A YubiKey | Only for real-hardware smoke testing; the test suite does not need one. |

```shell
sudo apt install opensc softhsm2      # Debian/Ubuntu
brew install opensc softhsm           # macOS
```

If the Go toolchain is installed outside the default prefix, put it on `PATH` first. The rest of
the project is dependency-light; nothing here needs Docker unless you want a live Vault/OpenBao to
log in to, which the test suite does not (it uses `httptest` servers).

## Build and run

```shell
go build -o /tmp/yubivault .
/tmp/yubivault -version
```

A local build reports `dev`; the release workflow injects a version tag. For a one-off run use
`go run . -version`; `go install .` installs the command in `GOBIN` (or the default Go bin directory).

## Checks

These are exactly what CI runs; run all of them before opening a pull request.

```shell
go mod tidy -diff          # must print nothing: go.mod/go.sum are tidy
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
go tool govulncheck ./...
```

On Linux, make the SoftHSM integration test mandatory the same way CI does:

```shell
YUBIVAULT_REQUIRE_SOFTHSM=1 go test -race -run SoftHSM -v ./...
```

Without that variable the test skips if the module or the CLI tools are missing — useful locally,
and the reason the variable exists at all.

## CI

`ci.yml` runs on pushes to `main`, on every pull request, and monthly (so newly published
advisories are found without a code change).

- `build-and-test` runs on `ubuntu-latest` and `macos-latest` (Apple Silicon) with Go 1.27 and four
  checks: `go mod tidy -diff`, gofmt, `go vet` and `go test -race`. The macOS job matters: cgo means
  the darwin/arm64 build cannot be cross-compiled from Linux.
- On Linux only, the job installs `softhsm2` and `opensc` and exports
  `YUBIVAULT_REQUIRE_SOFTHSM=1`, so the integration test is a hard failure there and a skip on
  macOS.
- `vulncheck` runs `go tool govulncheck ./...` in its own job. Because `govulncheck` is a pinned
  tool dependency, its version is updated by Dependabot like any other dependency.

All actions are pinned to full commit SHAs with the tag in a trailing comment. Keep new actions
pinned that way, and keep `permissions:` least-privileged.

## The SoftHSM integration test

`TestCreateYubikeyVaultClient_SoftHSM` is the only test that drives real PKCS#11 code. It:

1. Creates a temporary SoftHSM token (`softhsm2-util --init-token`, PIN `123456`) and writes a
   `softhsm2.conf` in a temp dir.
2. Generates a self-signed client certificate, imports the private key with `softhsm2-util` and the
   certificate with `pkcs11-tool`, both under `CKA_ID` `01` — a stand-in for PIV slot 9a.
3. Re-executes the test binary as a child (`YUBIVAULT_SOFTHSM_TEST_CHILD`) so that
   `SSL_CERT_FILE` can be set before Go caches the system roots; the child starts a TLS server that
   requests a client certificate and answers `cert/login` and `token/lookup-self`.
4. Asserts that the login produced the token from `lookup-self`, that exactly one login and one
   lookup happened, that both requests presented the SoftHSM certificate, and that the client's
   `Close` was called exactly once.

Module discovery order is `/usr/lib/softhsm/`, `/usr/local/lib/softhsm/`,
`/opt/homebrew/lib/softhsm/` and `/usr/lib/*/softhsm/`; set `SOFTHSM2_MODULE` to override it when
your SoftHSM lives somewhere else.

## Modifying code safely

- Read [Agent instructions](../agents.md#invariants) first: the numbered invariants are what tests
  and the shell contract depend on. `run`, `loginAndClose` and the PKCS#11 ownership rules are the
  delicate parts.
- Keep `main.go` one file unless there is a real reason to split: it is small enough to hold in
  view, and the interfaces exist only for testability.
- Match the existing error style: wrapped with `%w` when the cause matters (`errors.Is` depends on
  it), fixed text otherwise, and never a private-key path. Comments explain *why* (an invariant, a
  past bug, an upstream quirk), not *what*.
- Do not add a dependency for something the standard library or an existing dependency does.
- Behaviour changes are a docs change too: flags, config fields, error text, timeouts, exit codes
  and supported platforms all appear under `docs/`.
- New pages must be added to `mkdocs.yml`'s nav and must build under `mkdocs build --strict`.

## Adding and updating tests

Table-driven tests with `t.Run` are the house style. Useful helpers already exist: `writeConfig`,
`selfSignedCert`, `captureStdout`, `MockVaultClient`, `closeRecorder`.

- Test behaviour and boundaries a consumer would notice: config rejection cases and their exact
  error text, key-permission refusal, certificate selection ambiguity, retry count, `Close` on the
  failure path, PIN precedence and trimming.
- Do not add tests for wiring, mock forwarding, or the text of a message that no consumer matches
  on.
- Anything that depends on process-global state needs the child-process pattern already used for
  TLS roots, `ProxyFromEnvironment` and the non-terminal stdin path (`TestReadPin_TerminalBranch`,
  `TestNewHTTPClient_UsesProxyFromEnvironment`, `TestCreateYubikeyVaultClient_SoftHSM`).
- Tests must be deterministic and safe in the full suite: no real card, no live Vault, no real PIN,
  no dependence on test ordering.

## Real-hardware smoke testing

Once per behaviour change to the `-yubi` path, on a card you own:

```shell
VAULT_TOKEN="$(/tmp/yubivault -yubi)" && export VAULT_TOKEN
```

- Never type or invent a PIN you are not certain of: three wrong attempts block the PIN.
  Confirm with `ykman piv info` that attempts remain before testing.
- Do not run card-mutating commands (`ykman piv` writes, `pkcs11-tool --login` loops) to
  investigate a failure.
- A touch-policy key may wait for touch during signing. Exact timeout and retry behaviour depends on
  the PKCS#11 stack; do not assume a fixed limit or retry count.

## Branch, commit and review conventions

- Branch from `main`, one topic per branch (`fix/…`, `feat/…`, `test/…`, `docs/…`), and keep the
  diff to the change and everything it touches (callers, tests, docs).
- Commit messages use a conventional prefix (`fix:`, `feat:`, `test:`, `docs:`, `chore:`); a squash
  merge appends the pull request number, e.g. `fix: preserve YAML errors in extra documents (#37)`.
- Commits must be signed (this repository's maintainer workflow requires it).
- Pull requests run two workflows, `CI` and `Docs`; both should be required checks before merge.
  `Docs` renders the site with `mkdocs build --strict`, so a broken link or a missing nav entry
  fails the pull request.
- Describe the behaviour change and how you verified it; state anything you could not verify (for
  example, a path that needs real hardware or a live Vault).
