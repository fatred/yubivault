## Verification method (what I re-checked myself vs. what stays report-only)

Independently re-verified from source (not taken on trust): `run` body and precedence lines; `AuthenticateAndGetToken`; the test fixture; `README.md:111`; commit `901a239`; `go-retryablehttp@v0.7.8`, `vault-client-go@v0.4.3` (incl. `openapi.json` parsed), `golang.org/x/term@v0.47.0`, GOROOT `os/signal` + `context` on go1.27.2; plus one live smoke of the non-terminal-stdin path (R3), run against a throwaway `HOME` and config, binary built from the working tree.

Report-only (Sonnet's scratch/observed runs; not reproducible from artifacts in the repo — repo-wide search for `TestCancelShape` / `lookup-id-differs` matches only `audit-context/*.md`): `TestCancelShape` output, `lookup-id-differs` output, the FIFO-`os.Open` two-signal observation, and the harness-run rc/stderr captures behind R3/R4. Commit `901a239`'s own 20/20 and 42-run numbers are the maintainer's recorded observations, quoted from the commit, not re-executed by me.

No repo file was modified; `git status` shows only the pre-existing untracked `audit-context/review/`.

---

## R1 — cancellation error shape and which branch of `main.go:495-499` wins

**Sonnet ID:** R1 (origin `run`).
**Original question:** does `CertLogin` surface context cancellation, and which branch wins?

**Sonnet's disposition/evidence:** answered; bare `context canceled` after ~300 ms, `errors.Is(err, context.Canceled)` true, `errors.Is(err, cause)` false; `main.go:495` beats `:498`.

**My assessment — premise is moot inside `run`, conclusion correct.**
- `ctx` (`main.go:474`) is parented on `context.Background` and can be cancelled only by the `signalCtx` goroutine (signal cause) or by the deferred `stop()` at `main.go:475`, which runs after the checks. A second `cancel(nil)` from `signalCtx.stop` cannot erase the cause (`context.WithCancelCause` keeps the first cause). Verified in GOROOT `os/signal/signal.go:293-313` (`c.cancel(signalError(s.String()+" signal received"))`) and `:322-325` (`stop` = `cancel(nil)` then `Stop(c.ch)`).
- Therefore on every mid-request cancellation reachable from `run`, `context.Cause(ctx)` is non-nil, and `main.go:495-497` returns before `:498-500` and before the print at `:501`. Verified by reading `main.go:486-501`.
- **Citation correction to Sonnet's mechanism claim:** the property "the library returns `ctx.Err()`" does not come from `client_configuration.go:224-232` alone. The repo *overrides* the retry configuration (`main.go:329-336`, `RetryMax: 1`, `CheckRetry`/`ErrorHandler` left nil); those defaults survive only because `WithRetryConfiguration` fills nil fields from `DefaultConfiguration().RetryConfiguration` — `vault-client-go@v0.4.3 client_option.go:71-81`, with the values at `client_configuration.go:227-230` (`CheckRetry: DefaultRetryPolicy`, `ErrorHandler: retryablehttp.PassthroughErrorHandler`). Independently confirmed `DefaultRetryPolicy` returns `(false, ctx.Err())` once the context is done: `go-retryablehttp@v0.7.8 client.go:472-475` (Sonnet's `:722`, `:825` are the call sites in `Do`/error selection; `Do` at `:666`, `drainBody` at `:846` — consistent with v0.7.8, the version `go.mod` pins). Net effect: Sonnet's conclusion stands, for a reason its citation only half-shows.
- Repo coverage: no test pins the error text; the cancelled-ctx subtest of `TestLoginAndClose_ClosesOnFailure` (`main_test.go:442-466`) asserts only "error returned + client closed".

**Final disposition: TERMINATE.** Rationale: answered by repo source; no user-visible path depends on the third-party error string, and pinning it would test incidental library text. No owner needed.

---

## R2 — is lookup-self `id` always equal to `Auth.ClientToken`?

**Sonnet IDs:** R2 + A6 (origins `run`, `AuthenticateAndGetToken`).
**Original question:** is the lookup `id` guaranteed to equal `Auth.ClientToken`; do they differ in a real deployment?

**Sonnet's disposition/evidence:** external-unknown; code always returns `data.id`; fixture uses different strings; Vault's generation of `id` is in no pinned module and `openapi.json` carries no semantics.

**My assessment — all three supporting claims verified.**
- `AuthenticateAndGetToken` returns `tokenResp.Data["id"]` (`main.go:416-420`); the login token is installed client-side only (`SetToken`, `main.go:409`) and never returned.
- Fixture deliberately differs: `Auth.ClientToken: "test-token"` vs `Data["id"]: "my-id"`, asserted as `my-id` (`main_test.go:49-58`).
- Parsed `vault-client-go@v0.4.3/openapi.json`: `/auth/token/lookup-self` GET declares `200: {"description": "OK"}` with **no response schema**, and the only `TokenLookUpSelf…` schema is the request. So no `id` semantics are pinned locally — Sonnet's claim holds.
- Scratch `lookup-id-differs` is report-only (not in the repo).

**Final disposition: TRANSFER.**
**Owner/evidence needed:** Vault/OpenBao token-store semantics — upstream source or API documentation for how `/v1/auth/token/lookup-self` populates `data.id`, or one recorded real lookup-self response from a live deployment (the operator's own Vault suffices to produce the latter). Until then the repo cannot settle it.
**Note (not a disposition):** a repo-side alternative exists if the evidence is unobtainable — return the login `ClientToken` (`main.go:405`, `:409`) instead of the lookup `id`. That is a one-line design change for the maintainer, not a question this review can close.

---

## R3 — `x/term.ReadPassword` on a non-terminal stdin

**Sonnet ID:** R3 (origin `run`).
**Original question:** how does `term.ReadPassword` behave when stdin is not a terminal?

**Sonnet's disposition/evidence:** answered; `echo 1234 | yubivault -yubi` and `</dev/null` both rc=1, stderr prompt + newline + `could not read PIN code: inappropriate ioctl for device`, nothing on stdout; the generic-reader branch is unreachable from `run`.

**My assessment — independently reproduced, claim confirmed; one detail explained.**
- Live smoke (built from the working tree, temp `HOME` with a minimal `-yubi` config): `</dev/null` → rc=1, stdout empty, stderr `PIN for : ` + `2026/10/11 … could not read PIN code: inappropriate ioctl for device`; `echo 1234 |` → identical rc/stdout/stderr. Sonnet's `PIN for 123: ` is the same code path with `yubikeySerial` set — the prompt reads `appConfig.YubikeySerial` (`main.go:262`), a *different* field from the `yubikeyPivSerial` that `requireForMode` demands (`main.go:148-151`), and my fixture left it unset. Not a contradiction with Sonnet; a fixture difference.
- Source: `golang.org/x/term@v0.47.0 term_unix.go:74-75` — `readPassword`'s first call is `unix.IoctlGetTermios` → `ENOTTY`. `ReadPin` sends `os.Stdin` down the terminal path (`main.go:380-381`), and `run` only ever passes `os.Stdin` (`main.go:464`), so the generic-reader branch at `main.go:382-394` is unreachable from `run` (it stays reachable from the `ReadPin` tests).

**Final disposition: TERMINATE.** Rationale: behavior is fail-closed, nothing reaches stdout, and the documented non-interactive path is `TOKEN_PIN` (README). No owner.

---

## R4 — exit status 1 for signal-caused failure vs 130/143

**Sonnet ID:** R4 (origin `run`).
**Original question:** is exit 1 intended for a signal-caused failure, rather than 130/143?

**Sonnet's disposition/evidence:** answered; commit `901a239` message, `README` line 111; no test asserts it.

**My assessment — both citations verified verbatim.**
- `git show 901a239` body: "Behaviour change (maintainer's call): a signal during login now exits 1 rather than 128+signo (130/143). NotifyContext's cause type is unexported, so the signal number is not available. README updated."
- `README.md:111`: "The exit status is non-zero on any failure. On Ctrl-C or SIGTERM during login, yubivault closes the YubiKey session first and then exits 1 (`interrupt signal received` / `terminated signal received`)."
- "No test asserts it" verified: `main_test.go` contains no signal/`NotifyContext` test and no test invokes `run` at all; the only cancellation input is the pre-cancelled ctx subtest at `main_test.go:453-466`.

**Final disposition: TERMINATE.** Rationale: the intent is decided and documented by the maintainer's explicit call; there is nothing left to resolve.

**Residual carried (not a question of `run`): R4-residual — no automated coverage of `run`'s signal precedence or exit code.** **TOLERATE.** Reason: `901a239` deliberately deleted `TestCancelOnSignal` ("the stdlib behaviour needs no test of ours"), and a meaningful replacement needs a subprocess/pty test with a stalled login (`httptest` server that never responds) to keep the signal from racing a fast failure — real cost, for a documented constant. Upgrade trigger: if the signal block (`main.go:470-497`) is touched again, add that one subprocess test rather than re-deriving it by hand.

---

## R5 — is absorption of the second signal guaranteed?

**Sonnet ID:** R5 (origin `run`).
**Original question:** is a second SIGINT in the window between the first cancel and the `AfterFunc` goroutine guaranteed to be absorbed?

**Sonnet's disposition/evidence:** partly; source shows the window is scheduler-dependent; observations (incl. a FIFO `os.Open`) plus `901a239`'s 20/20.

**My assessment — Sonnet's "not source-guaranteed" is right, and the reason is exactly one scheduling step.**
- Verified source: `NotifyContext` uses a 1-slot channel and a goroutine that cancels with `signalError(s.String()+" signal received")` (`os/signal/signal.go:301-308`); `stop` is `cancel(nil)` then `Stop(c.ch)` (`:322-325`), and `Stop` (`:193`) is what releases the channel and lets the default action return. `context.AfterFunc` starts `f` "in its own goroutine after ctx is canceled" (`context/context.go:309-326`, used at `main.go:476`).
- Consequence: absorption is guaranteed only for signals that arrive *before* `Stop(c.ch)` executes, i.e. within a scheduler-dependent window; nothing in the stdlib makes the window zero. So "guaranteed" is false as stated — and the repo comment at `main.go:470-473` already claims only "absorbed" plus "a later signal kills the process if cleanup stalls", which is accurate (the first round of `901a239` explicitly removed the word "immediately").
- Worst case is a *delayed*, not lost, kill: once `stop` runs, a further signal takes the default action. Sonnet's FIFO-`os.Open` observation and `901a239`'s 20/20 (+42-run sweep, which measured leaks, not absorption) are report-only from the commit/run records.

**Final disposition: TOLERATE.** Rationale: not fixable in-repo (the window is stdlib scheduling); impact is bounded (second signal absorbed once, then killed); and the code comment plus README promise only what actually holds. No owner, no task; keep the "absorbed / later signal kills" wording if the comment is ever edited.

---

## Adjacent questions not originating in `run` (out of scope, preserved)

Owned by the `AuthenticateAndGetToken` disposition, not disposed here: whether `data["id"]` is always a JSON string for this token versus absent/redacted/numeric-under-`UseNumber()` (`audit-context/functions/05-AuthenticateAndGetToken.md:51`; `DOSSIER.md:151`, `:153`, `:156`). Same external owner as R2 (Vault token store or a recorded real response); listed so it is not mistaken for closed by the R2 transfer.

---

## Counts

| Disposition | Questions | IDs |
|---|---|---|
| TERMINATE | 3 | R1, R3, R4 |
| TOLERATE | 1 | R5 |
| TRANSFER | 1 | R2 (origins `run` + `AuthenticateAndGetToken`) |
| TREAT | 0 | — |

Residuals carried (not questions, not counted above): 1 TOLERATE — R4-residual (no automated coverage of `run`'s signal exit path).

## Recommended worklist

1. **TRANSFER (R2) — only open external item.** Obtain one recorded real `/v1/auth/token/lookup-self` response (or the Vault/OpenBao token-store path populating `data.id`) confirming `id == client_token` in the deployments this tool targets. No repo change before that evidence; if it cannot be pinned, the maintainer's fallback is to print `ClientToken` instead of the lookup `id` (`main.go:405`, `:416-420`).
2. **TOLERATE (R5).** No action. Constraint to preserve: the comment at `main.go:470-473` must not be strengthened to a guarantee.
3. **TOLERATE (R4-residual).** No action now; if `main.go:470-497` is next modified, add the single subprocess test (stalled `httptest` login + signal) instead of re-running manual sweeps.
4. **No TREAT tasks** — nothing in this function's questions produced a repo-owned follow-up that is actionable independently of the R2 evidence.

Skipped/not checked: no live Vault or YubiKey was used, so R2's external semantics and Sonnet's hardware/pty observations remain report-only; I did not re-run the commit's 20/20 or the FIFO-open scenario. Risk: R2 is the only question that could change user-visible output (a printed token that is not the authenticated one); everything else is closed or accepted.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current lower-level status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §3. Real runs now exist (all temporary binaries, configs and traces deleted; no artifact retained):
- **R2** — a live cert login at `https://vault.problemofnetwork.com:8200` succeeded (role `admin`, `lookup-self` HTTP 200, then token revoked 204 / lookup 403), but `data.id == auth.client_token` was **not** recorded and the successful login was not spy-traced. R2 stays TRANSFER (§3a).
- **R3** — the non-terminal path was exercised at app level: `-yubi` with `/dev/null` stdin exits 1 with empty stdout. Row 3 remains TERMINATE.
- **R4-residual** — still no automated test of the signal exit path; the successful login exited 0 with a live HTTPS request, but no signal case was run. TOLERATE unchanged.
- Hardware, live Vault and CI runs still absent for R1/R5; classifications unchanged.
