# newVaultClient (`main.go:326-343`) — question dispositions

**Scope.** Questions raised by `audit-context/functions/12-newVaultClient.md` (open questions 1–5), plus the merged dossier entry whose origin list includes `newVaultClient` (Sonnet item 30, C3+V1). One record question (open question 5, duplicate server-side login) never reached the Sonnet set — see Q6.

**Evidence basis.** I re-read the repo at HEAD and the pinned deps (`vault-client-go@v0.4.3`, `go-retryablehttp@v0.7.8`, `crypto11@v1.6.8`, `pool@v0.0.2`, go1.27.2 stdlib). I **independently reproduced** the `unix://` behaviour with a throwaway program. Sonnet's timing figures, its h2-fixture negotiation and its race run were **not** rerun and are labelled *report-only*. The `e4bfeab` smoke numbers are read from the repo's own commit message, so they are verified-as-recorded.

---

## V1 — Sonnet item 30 (C3+V1; overlapping item 49/H2)

**Original question.** Is `unix://` `vaultAddr` intended, and what happens to the 5s dialer?

**Sonnet's disposition/evidence.** *Answered.* `client.go:97-110` replaces the transport `DialContext` for `unix://`; `parseAddress` (`:153-158`) rewrites the scheme to `http` and moves the socket path into `Host`. Observed: `unix:///abs/path.sock` fails at request creation with `invalid URL escape "%2F"`; `unix://relative.sock` runs end to end over plain HTTP with `serverSawTLS=false`. Remaining: intent is unstated (no doc, test or history).

**My assessment.** Source claim confirmed at the pinned version: `client.go:97-105` replaces `DialContext` on the `*http.Transport` (so `main.go:365`'s 5s dialer is discarded), and the type-assert failure at `:113-116` is unreachable here because `newHTTPClient` always installs an `*http.Transport`. Reproduced independently (throwaway program, `vault-client-go@v0.4.3`):

- `unix:///tmp/does-not-exist.sock` → `could not create 'GET http://%2Ftmp%2Fdoes-not-exist.sock/v1/auth/token/lookup-self' request: parse "…": invalid URL escape "%2F"` — matches Sonnet exactly.
- `unix://relative.sock` → the library dials the socket; my 2s context expired (`context deadline exceeded`) rather than an immediate `ENOENT`, because the replacement dialer **ignores the context** (`client.go:101-103`) and the resulting error is retryable (`go-retryablehttp/client.go:472-540`), so only the 30s library deadline bounds it.

Additional facts neither report states: `grep` finds no `unix` in `main.go`, `README.md` or `PKI-SETUP.md` (both docs show only `https://`, `README.md:58`, `PKI-SETUP.md:169`), and a unix-socket address carries **no TLS**, so the client certificate is never presented — the tool's only auth mechanism cannot work over it. The path is not merely untested, it is unsatisfiable.

**Final disposition: TREAT.**

**Rationale.** `LoadConfig` already rejects bad config up front with a named error rather than a confusing downstream one (`main.go:125-131`: "Reject incomplete config up front rather than producing confusing downstream errors"). A hand-written `unix://` address is exactly that case: the absolute form fails with a parse-internals message, and the relative form silently drops the 5s dial bound and the context cancellation. A one-line guard (or extending the existing scheme comment at `main.go:125-129`) is small and consistent with the file's own pattern. If the maintainer prefers the stated "scheme is not enforced" stance, this collapses to TOLERATE — but that stance was written about `http://` (which fails server-side), not about a transport type that cannot do cert auth at all.

**Suggested future task.** In `LoadConfig`, reject a `vaultAddr` whose scheme is not `http`/`https` (named error, e.g. `unsupported vaultAddr scheme "unix"`), or state explicitly in the `main.go:125-129` comment that unix sockets are unsupported (no TLS ⇒ no cert auth) and the 5s dial bound does not apply. One test for the guard if implemented. Owner: repo maintainer.

---

## V2 — Sonnet item 58 (signer after `Close`)

**Original question.** What state is the crypto11 signer in after `Context.Close`, and can a handshake after `Close` fail or block?

**Sonnet's disposition/evidence.** *Answered.* Signing goes `withSession` → `getSession` (`rsa.go:458`, `:585`; `ecdsa.go:304` via `dsaGeneric`; `sessions.go:58-72`); after `Close`, `pool.Get` returns `ErrClosed` and `getSession` maps it to `context is closed`, so a post-`Close` handshake fails and does not block. Conversely `Close` blocks until in-flight sessions return.

**My assessment.** Confirmed, with citation corrections. `getSession` (`crypto11/sessions.go:58-73`) does return `errors.New("context is closed")` when `pool.Get` yields `pool.ErrClosed` (`:68-73`, string at `:72`). The signing call sites are `rsa.go:584-590` (`Sign` → `withSession`; Sonnet's `:458` is `Decrypt`, a different `withSession` user) and `common.go:104-115` (`dsaGeneric`, reached from `ecdsa.go:304-306`). Pool side (`pool@v0.0.2/resource_pool.go`): `get` returns `ErrClosed` at `:210` when the channel is closed; `Context.Close` (`crypto11/crypto11.go:540-554`) sets the closed flag, then `pool.Close()` → `SetCapacity(0)` (`:140-144`, `:266-301`), which blocks reading the channel until in-flight sessions are `Put` (`:287-296`) and only then closes it (`:298-300`). Both directions therefore hold. Sonnet's `resource_pool.go:302-304` / `~288-300` point into the pool module's *else* branch, not the close; the semantics are right, the lines are not. Reachability: the crypto11 context is closed only by `loginAndClose`'s defer (`main.go:508-512`) after `AuthenticateAndGetToken` has returned, and `run` then prints and exits (`main.go:493-503`); no handshake can start after `Close` in this program.

**Final disposition: TERMINATE.**

**Rationale.** Answerable and answered from the pinned module source; the post-`Close` handshake is unreachable in this repo, so there is no behaviour to fix or test. The one residual ("Close can wait on a hung module call") is a distinct question, disposed separately below.

---

## V2b — residual from Sonnet item 58 ("Remaining")

**Original question.** Can `Close` block indefinitely on a stuck PKCS#11 call?

**Sonnet's disposition/evidence.** Remaining; module behaviour.

**My assessment.** Mechanism confirmed: `Close` blocks inside `SetCapacity(0)` until the in-flight session is returned (`pool :287-296`), and the session is returned only when `f(session)` returns, i.e. when `C_Sign` returns. The repo's timeouts do not bound it: `TLSHandshakeTimeout` is 10s (`transport.go:56`) but `addTLS` waits for the handshake goroutine (Sonnet item 52), and the signer runs outside any context. Whether a real PIV module can block in `C_Sign` is hardware/module behaviour — and Sonnet's own scope note records that the real YubiKey and OpenSC were never touched (SONNET-INVESTIGATION.md, "Not checked").

**Final disposition: TRANSFER.**

**Rationale.** The evidence required (does OpenSC/PIV block in `C_Sign`, and how long) belongs to the module/hardware owner; no repo change can bound it. Cross-reference Sonnet item 52 (H5, `newHTTPClient` origin), which carries the same finding.

**Owner/evidence needed.** OpenSC / PIV applet (plus the card). Evidence: an end-to-end `-yubi` run against real hardware with a deliberately stalled module call, or module documentation on `C_Sign` blocking; note that `loginAndClose`'s defer (`main.go:508-512`) is the code that would wait.

---

## V3 — Sonnet item 59 (reuse after `loginAndClose`)

**Original question.** Can any path reuse the returned `*vault.Client` after `loginAndClose` closes the auth client?

**Sonnet's disposition/evidence.** *Answered.* `GetVaultClient()` is called only at `main.go:513`, and "`Clone(` does not appear in `main.go`"; the library's `Clone` shares the `http.Client` and retry client, but nothing in the repo calls it.

**My assessment.** Conclusion holds; two evidence faults. (a) `Clone(` **does** appear in `main.go` — `main.go:364` `http.DefaultTransport.(*http.Transport).Clone()`; the intended claim (no `vault.Client.Clone`) is true, but the stated grep result is literally wrong. (b) `GetVaultClient` definitions sit at `main.go:53`/`:68` with the sole production call at `:513` (plus a test fake, `main_test.go:437`) — correct. `vault.Client.Clone` (`vault-client-go/client.go:168-186`) does share `client`/`clientWithRetries` (`:172-173`). But the client is only reachable inside `AuthenticateAndGetToken`, which returns before `loginAndClose`'s defer runs; nothing retains it; and for `-yubi` the same `Close` kills the crypto11 context, so a hypothetical reuse could not sign anyway.

**Final disposition: TERMINATE.**

**Rationale.** Answered; the only reuse path requires a repo change that does not exist, so there is no open question to track. Worth remembering if a caller is ever added, but nothing to task now.

---

## V4 — Sonnet item 60 (wall-clock bound)

**Original question.** What is the real wall-clock bound of the full login flow?

**Sonnet's disposition/evidence.** *Partly.* Measured per call: blackholed dial 11.2s, stalled TLS handshake 21s; commit `e4bfeab` reports 11.4s (`-yubi`) / 11.3s (`-local`) for a blackholed address. The two-call total is `[INFERENCE]`; a responsive-login-then-unreachable-lookup case was not measured.

**My assessment.** The per-call numbers check out and the total is derivable from source, but the honest ceiling is higher than the 11s headline. `dialTimeout = 5s` (`main.go:319`) funds one dial per attempt; `RetryMax: 1` (`main.go:333-337`) means two attempts (`go-retryablehttp/client.go:760-763`); backoff is 1–1.5s (`client.go:619`) ⇒ blackhole ≈ 5 + ~1.25 + 5 ≈ 11.2s (matches both reports). `TLSHandshakeTimeout` 10s (`transport.go:56`) ⇒ stalled handshake ≈ 10 + ~1.25 + 10 ≈ 21.2s (matches Sonnet). The hard per-call ceiling is the library's own context deadline, `requestTimeout = 30s` (`main.go:330`; `client_requests.go:170-176`), which covers retries and sleeps; `CertLogin` and `TokenLookUpSelf` each get their own deadline (`main.go:398`, `:412`). So the full flow is bounded by ≈ 2 × 30s ≈ 60s for a server that accepts connections and stalls — not 11s. The `e4bfeab` smoke figures are verified against `git show`; the 11.2s/21s measurements are *report-only*. `main_test.go` contains no timing assertion (only cert validity windows at `:521-522`).

**Final disposition: TOLERATE.**

**Rationale.** The bound is understood, by design, and bounded by two independent 30s deadlines plus `run`'s signal cancellation (`main.go:471-473`). The constants' comment ("fail within seconds rather than after a minute of silence") is accurate about *unreachable* addresses, which is what it claims. Residual accepted: a stalling (not unreachable) server can still hold the CLI ≈30s per call / ≈60s total, and nothing pins the bound in a test. A timing test would be slow and flaky for little value; no change warranted now.

---

## V5 — Sonnet item 61 (HTTP/2 on the real endpoint)

**Original question.** Is HTTP/2 actually negotiated on the real Vault endpoint?

**Sonnet's disposition/evidence.** *Partly.* Against an h2-enabled fixture server, using `SSL_CERT_FILE` for trust, `newVaultClient` negotiated `HTTP/2.0` in every scenario with the client certificate presented. Remaining: the real listener; no test asserts the protocol.

**My assessment.** The client-side precondition is verified from source: `newHTTPClient` clones `DefaultTransport` (`main.go:364`), which carries `ForceAttemptHTTP2: true` and `TLSHandshakeTimeout: 10s` (`transport.go:47-56`). A custom `TLSClientConfig`/`DialContext` would normally suppress automatic h2 (`transport.go:489`), but the `ForceAttemptHTTP2` case short-circuits that conservatism (`transport.go:476-505`), and `configureHTTP2` then writes `NextProtos` into the shared `TLSClientConfig` (`http2.go:284-312`). The fixture negotiation and the `SSL_CERT_FILE` setup are Sonnet's, *report-only* here. The real listener's ALPN set remains an operator property. Note that **no repo behaviour branches on the negotiated protocol** — requests work over h1 too, and the library's own default client is configured the same way.

**Final disposition: TRANSFER.**

**Rationale.** Only the live listener can answer "on the real endpoint"; nothing in the repo depends on the answer, so there is no repo task. If the maintainer decides the question has no consumer, it drops to TOLERATE.

**Owner/evidence needed.** Vault/OpenBao listener operator. Evidence: `openssl s_client -alpn h2 -connect <host>:8200` showing the selected protocol, or the listener's TLS/HTTP2 configuration. Sonnet's fixture result covers only the client half.

---

## Q6 — no Sonnet item (coverage gap)

**Original question** (record open question 5). Can a retried cert-login — the POST body resent from the buffered copy — produce two server-side logins?

**Sonnet's disposition/evidence.** None. The dossier's `newVaultClient` bullet list (`DOSSIER.md:202-208`) omitted this record question, so it never entered Sonnet's 65 raw questions or 61 entries. Only authenticating evidence: `TestNewVaultClient_RetriesOnce` counts two attempts (`main_test.go:567-589`).

**My assessment.** Client-side: yes, verified. `vault-client-go` routes retried requests through retryablehttp (`client_requests.go:346-356`, whose comment documents that retryablehttp reads the whole body into an internal byte array), and the effective policy retries 5xx (except 501), 429 and transport errors (`go-retryablehttp/client.go:472-540`; `vault-client-go/client_configuration.go:349-359` adds 412), so the same login body can be transmitted twice. Server-side: whether the first body issued a token before the failure is Vault behaviour and is untested. Impact bound: at most one extra cert-login per run; the program uses only the final response's token (`main.go:398-409`), and a duplicate token expires on its own. There is no per-request retry opt-out in the library — both internal `send` call sites pass `retry=true` (`client_requests.go:187`, `:225`), so the only lever is a client-wide `CheckRetry`, which would also stop the lookup's retries.

**Final disposition: TOLERATE.**

**Rationale.** The retry is deliberate and bounded (`RetryMax: 1`, `main.go:333-337`) and exists to fix the 60s hang; duplicate cert logins are harmless for this program's purposes, and there is no cheap targeted mitigation. Record the gap: this question should have been in the dossier's `newVaultClient` list.

---

## Citation checks / claims challenged

1. **Item 59:** "`Clone(` does not appear in `main.go`" is false as written — `main.go:364` calls `.Clone()`; the conclusion (no `vault.Client.Clone`) is correct.
2. **Item 58:** the pool citations (`resource_pool.go:302-304`, `~288-300`) name lines that are not the close in `crypto11@v1.6.8`; the pool lives in `pool@v0.0.2` and the behaviour is at `:210` (ErrClosed), `:287-296` (drain), `:298-300` (close). Also `rsa.go:458` is `Decrypt`; the `Sign` path is `rsa.go:584`.
3. **Item 60:** "two-call total is `[INFERENCE]`" — tightened here to a source-derived ceiling of ≈2 × 30s (`main.go:330`, `client_requests.go:170-176`, two calls at `main.go:398`/`:412`); the empirical total and the 11.2s/21s figures remain *report-only*.
4. **Header drift:** `newVaultClient` at `main.go:326-343` is correct; Sonnet's `clientTLSConfig` header (`main.go:345-355`) is off — the function is at `main.go:349-356` (that item is owned by the `clientTLSConfig` report).
5. **Coverage gap:** record open question 5 (Q6 above) is absent from every Sonnet entry and from the dossier's `newVaultClient` list.

---

## Counts

| Disposition | Count | Items |
|---|---|---|
| TREAT | 1 | V1 (`unix://` scheme guard/doc) |
| TOLERATE | 2 | V4 (wall-clock ceiling), Q6 (retried login) |
| TRANSFER | 2 | V2b (hung `C_Sign` stalls `Close`), V5 (real listener ALPN) |
| TERMINATE | 2 | V2 (signer after `Close`), V3 (client reuse) |

## Recommended worklist

1. **TREAT — `LoadConfig` scheme guard** (`main.go:125-131`): reject `unix://`/non-`http(s)` `vaultAddr` with a named error, or extend the existing scheme comment to say unix sockets are unsupported (no TLS ⇒ no cert auth) and the 5s dial bound does not apply. One test if implemented. Only repo-owned action here.
2. **TRANSFER — real listener ALPN (V5)** to the Vault/OpenBao operator; low priority since no behaviour depends on it — and close V2b as a hardware/module question unless a stuck-card incident is ever seen.
3. **TOLERATE with a record** — note (a) the ~30s-per-call / ~60s-total ceiling for a stalling server next to `dialTimeout`/`requestTimeout` in `main.go:317-320`, and (b) that the login POST can be transmitted twice (`main.go:331-337`).
4. **Process fix** — the dossier's per-function bullet lists must carry every record question (Q6 was lost between the record and the dossier).

Skipped: I did not rerun Sonnet's timing (11.2s/21s), h2-fixture or race observations, and did not touch the real YubiKey/OpenSC or any live Vault; those items stay report-only or transferred. Risk to know: the only actionable repo item is the `unix://` guard — if the maintainer keeps the "scheme is not enforced" policy, it becomes an accepted residual rather than a task.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §2–§3. All temporary binaries, configs and traces were deleted; nothing retained.
- **V1 (30)** — resolved, not TOLERATE: `LoadConfig` now accepts only absolute HTTPS URLs and rejects `unix://` (and every other non-HTTPS scheme) before client construction (`main.go:129-142`; `TestLoadConfig_RejectsNonHTTPSVaultAddr`). D-1/T-3. The library `unix://` branch is unreachable from this CLI.
- **V5 (61)** — TRANSFER stays open. `newVaultClient` reached `https://vault.example.invalid:8200` and one cert login succeeded (role `admin`, `lookup-self` HTTP 200, then token revoked 204 / lookup 403), so the client works against one listener; that listener's ALPN set was not observed and no test asserts the negotiated protocol.
- **V2b (58b)** — TRANSFER stays open: no stalled/touch-policy `C_Sign` and no close-time hazard was run.
- **V2, V3, V4, Q6** — unchanged; the retried-login and wall-clock items were not re-measured.
