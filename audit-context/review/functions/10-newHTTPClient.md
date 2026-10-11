# Disposition review — `newHTTPClient` (`main.go:358-374`)

Verification basis: repo at HEAD `7f10998` (clean) — `main.go`, `main_test.go`; Go 1.27.2 stdlib at `~/.go/src/net/http`; `vault-client-go@v0.4.3`, `go-retryablehttp@v0.7.8`, `crypto11@v1.6.8`, `thales-e-security/pool@v0.0.2` from the module cache. I re-read every source claim material to a disposition. Sonnet's runtime observations are **report-only**: their method section states scratch files were removed (`review/SONNET-INVESTIGATION.md`, "Scratch work"), so I could not re-run or audit their harnesses; nothing in this report treats their measurements as independently verified. Where my source read corrects or extends them I say so.

Coverage: 5 questions originate in `newHTTPClient` (dossier `DOSSIER.md:188-194` → Sonnet items 48-52, H1-H5). No merged entry lists `newHTTPClient` as an origin (index at `SONNET-INVESTIGATION.md`, "Index by function"). Cross-references to entries that touch this function's transport but are owned elsewhere are listed at the end, not dispositioned here.

## Summary

| Item(s) | Question | Sonnet | Final |
|---|---|---|---|
| 48 / H1 | ALPN h2 through the `HTTPS_PROXY` tunnel | Answered | **TERMINATE** |
| 49 / H2 | Non-https `vaultAddr` reachable | Partly | **TREAT** |
| 50 / H3 | 3xx body closed on the redirect path | Answered | **TRANSFER** |
| 51 / H4 | socks5 vs the replaced `DialContext` | Partly | **TOLERATE** |
| 52 / H5 | Which bound fires first on `-yubi` | Partly | **TRANSFER** |

---

## 48 / H1 — ALPN h2 through the proxy tunnel

**Original:** Does an `HTTPS_PROXY` tunnel negotiate ALPN h2 through this transport?

**Sonnet:** Answered. Local CONNECT proxy → h2 server gave `resp.Proto=HTTP/2.0`, one CONNECT, one peer certificate. Scope: transparent tunnel only; real corporate proxy untested.

**Assessment:** Source-verified, independently of their run. Post-CONNECT TLS is done for `cm.proxyURL != nil && cm.targetScheme == "https"` (`transport.go:2047-2051`), then the h2 switch keys on `pconn.tlsState.NegotiatedProtocol == "h2"` with no proxy special-case (`transport.go:2053-2070`). h2 is configured at all only because `ForceAttemptHTTP2` survives the clone (`transport.go:53`, `:439-475`; `configureHTTP2` → `adjustNextProtos`), which the record's T5/57 entry already established at source. The repo's own proxy test proves only the CONNECT target (`main_test.go:481-505`; assert at `:504`) — their h2 measurement is report-only, but is exactly what the stdlib implies. An h1-negotiating proxy is handled transparently; no repo code selects a protocol.

**Disposition: TERMINATE** — question answered by source; no residual that is repo-owned or externally decidable. "Real corporate proxies vary" is not an open question about this function.

---

## 49 / H2 — Non-https `vaultAddr`

**Original:** Can `newHTTPClient` be reached with a non-https `vaultAddr`?

**Sonnet:** Partly. No scheme observation (`main.go:126-129`, `:130-135`, `:363-374`); `unix://relative.sock` ran login+lookup over plain HTTP with no client certificate. `http://` not run, same path `[INFERENCE]`. Remaining: whether a real Vault refuses.

**Assessment:** Client-side half is source-verified and correct. `LoadConfig` checks non-empty only (`main.go:130-135`), with the rationale comment at `main.go:126-129`. For `unix://`, `vault-client-go` rewrites the scheme to `http` and repoints the socket (`client.go:150-160`) **and** replaces `DialContext` with `net.Dial("unix", …)`, discarding the 5s dialer set at `main.go:365` (`client.go:97-110`) — that override is filed under newVaultClient/CreateLocalVaultClient (item 30/C3+V1), but it is the mechanism behind Sonnet's observation. New evidence I add: **no yubivault auth mode can succeed over plaintext.** Both modes build the same cert-auth client (`main.go:169`, `:306` → `newVaultClient` → `clientTLSConfig`, `main.go:345-355`) and the only auth call is `CertLogin` (`main.go:398`); over `http://` there is no TLS handshake, so the client certificate is never presented (`transport.TLSClientConfig` unused). The credential is therefore not exposed; the outcome is a failed login. Server-side refusal is Vault/OpenBao cert-auth semantics — `[INFERENCE]`, not tested live by Sonnet either (their fixture accepted it).

Repo-owned residue: the comment's claim that an http endpoint "fails safely on its own" is plausible but unsubstantiated here, and its clause that "local dev Vault (http://localhost:8200) stays usable" cannot hold for either auth mode. That is an unsupported documented rationale in this repo, not a security bug.

**Disposition: TREAT** (repo-owned, no implementation now).
**Rationale:** reachability is by design and harmless (no client cert travels), but the stated justification for the permissive scheme is not supported for cert auth; the trust boundary here is the operator's own config file, so the fix is documentation/validation, not a guard.
**Suggested future task:** In `LoadConfig`, either reject a non-`https` `vaultAddr` (or reject `http://` while keeping any deliberate exception) with a clear message, or rewrite the `main.go:126-129` comment to state what actually happens for cert auth; pin the chosen behaviour with one test asserting the error text — and record separately (TRANSFER, Vault/OpenBao) the unverified server response for a plaintext `CertLogin`.

---

## 50 / H3 — 3xx body on the redirect path

**Original:** Is the 3xx response body ever closed on the redirect path?

**Sonnet:** Answered. `send` reassigns `resp` without closing (`client_requests.go:319-336`); `ErrUseLastResponse` leaves the body open; body-counting `RoundTripper` observed `opened=3 closed=2`, the 307 body never closed.

**Assessment:** Source-verified by me, independent of their count. Chain: `CheckRedirect → ErrUseLastResponse` returns the 3xx with an open body and nil error (`main.go:370-372`; `client.go:713-720`; the "without closing its body" comment is at the sentinel branch). `retryablehttp` does not retry a 3xx (`baseRetryPolicy` returns false for non-5xx/429, `client.go:495-546`) and returns it open on the success-criteria path; the `drainBody` at `client.go:831` is on the error path only, and vault sets `PassthroughErrorHandler` (`client_configuration.go:224-232`). `send`'s loop then reassigns `resp` with no close (`client_requests.go:319-333`), and the only `defer resp.Body.Close()` is downstream in `sendRequestParseResponse` (`client_requests.go:191`), which closes the final response, not the discarded 3xx. Leak confirmed at source; Sonnet's `opened=3/closed=2` is corroborating, report-only.

Impact for yubivault is bounded and small: a standby→active 307 on login and/or lookup leaks ≤2 bodies per process (`main.go:398`, `:412` — note their `:413` is off by one); the process is single-shot and exits, so there is no unbounded growth, only a lost connection reuse for the rest of the run. The defect is in `vault-client-go` and is not reachable for fixing from this repo: no `CheckRedirect`/option surface can close a body the library discards, and disabling redirects (`DisableRedirects`, `client_configuration.go`) would break HA failover.

**Disposition: TRANSFER**
**Rationale:** the question is answered (yes, it leaks) and the fix belongs to a third-party library; repo-side mitigation options are all worse than the leak. The repo inherits the same bug through the library's own default client, so this is not caused by `newHTTPClient`.
**Owner/evidence needed:** `hashicorp/vault-client-go` maintainers; evidence = the source chain above plus a minimal repro (two-hop redirect against a fixture server, counting `Body.Close`). Caveat to state in the report: no live Vault was used, and the redirect hop was exercised only by Sonnet's scratch harness.

---

## 51 / H4 — socks5 vs the replaced `DialContext`

**Original:** How does socks5 interact with the replaced `DialContext`?

**Sonnet:** Partly. Proxy dial goes through `t.dial` → our `DialContext` with its 5s timeout (`transport.go:1920`); SOCKS negotiation runs under the request context, not `dialTimeout` (`:1940-1956`). No repo test; no SOCKS proxy run.

**Assessment:** Fully answerable at source; the mechanics check out with minor citation drift. `t.dial` prefers `t.DialContext` (`transport.go:1372-1379`) and the connection is dialed from the non-proxy branch at `transport.go:1921-1924`; SOCKS is special-cased at `:1940-1941`, `socksNewDialer` at `:1942`, `DialWithConn(ctx, …)` at `:1954`. The `ctx` reaching `dialConn` is `dialCtx = context.WithCancel(context.WithoutCancel(reqCtx))` (`transport.go:1596`, `getCtxForDial` at `:1428-1433`) — deliberately deadline-free, so the TCP connect to the proxy is bounded only by our 5s `Dialer.Timeout`, and the SOCKS negotiation by nothing inside the transport: the only user-visible bound is the request context, whose deadline `getConn` selects on (`transport.go:1650`), i.e. the library's 30s. `ProxyFromEnvironment` can supply such a URL (`transport.go:120-123`; `httpproxy` knows the `socks5` scheme, vendored `proxy.go:279`).

Accepted residual: the repo's own claim "each attempt gets dialTimeout to connect" (`main.go:316-321`) is strictly true for the TCP connect but not for a wedged SOCKS negotiation, which can consume the whole 30s budget. A repo test would assert libstd behaviour, not this repo's code (the repo sets only `DialContext`).

**Disposition: TOLERATE**
**Rationale:** the interaction is well-defined and nothing in the repo is wrong; the divergence from the timeout comment is minor, environment-triggered, and already capped by `requestTimeout`, so the "fail in seconds" intent still holds within one 30s window. No SOCKS fixture is worth its maintenance cost.

---

## 52 / H5 — Which fires first on the `-yubi` path

**Original:** Which fires first — the request context deadline or `Client.Timeout`? (framed as: only the inherited 10s `TLSHandshakeTimeout` covers the crypto11 signature inside the handshake)

**Sonnet:** Partly. Context created before `Do` computes its attempt deadline, so the context fires first; `addTLS` waits for the handshake goroutine after the timer (`transport.go:1811-1813`), so a blocking `C_Sign` "is not bounded by either timeout". Observed: stalled handshake → `TLS handshake timeout` at 21s; blackholed dial → `i/o timeout` at 11.2s. Remaining: whether a real PIV module can block in `C_Sign`.

**Assessment:** Their first sub-claim is confirmed at source, their second needs qualification, and the conclusion matters for the exit path.

- Confirmed: the library installs a context deadline 30s from request start (`client_requests.go:170-176`) before `Do`; `setRequestCancel` only installs `Client.Timeout`'s deadline when it is *earlier* than the existing context deadline (`client.go:358-374`, `timeBeforeContextDeadline` `:314-320`). The context deadline is ≤ the per-attempt deadline on every attempt, so the context always wins — including over the retry budget.
- Correction: a blocking `C_Sign` is unbounded *as a call*, but the **request is not**: `getConn` selects on `treq.ctx.Done()` as well as `w.result` (`transport.go:1650-1655`), so the caller returns at ~30s with the context error while the detached dial goroutine stays inside `addTLS`'s `<-errc` (`transport.go:1809-1815` — Sonnet's `:1811-1813` is ~2 lines early; the `plainConn.Close()` before it is `:1810-1813`). User-visible effect: a wedged module produces `context deadline exceeded` at 30s, not the 10s `TLS handshake timeout` their stalled-handshake run showed (that run's stall was network-bound, so `Close` unblocked the read). Their timer observation is therefore consistent and not in tension, but the "not bounded" phrasing should not be read as "the CLI hangs".
- New, source-supported `[INFERENCE]` for the exit path: the leaked goroutine can be inside a PKCS#11 call when `loginAndClose`'s deferred close runs (`main.go:507-513`, `:509` → `YubikeyVaultClient.Close` `:72-75` → `cryptoCtx.Close()`). `crypto11.Context.Close` documents and implements "blocks until existing operations have finished" (`crypto11.go:538-547`), and signing checks a session out of the pool (`withSession`: `rsa.go:458`, `ecdsa.go:250`). So a module wedged in `C_Sign` with a touch-required PIN policy would move the hang from the request to process exit. Not exercised by anyone: Sonnet's SoftHSM run did not produce a blocking `C_Sign`.

**Disposition: TRANSFER**
**Rationale:** the "which fires first" part is now closed at source (context, always), and the open part is purely module/hardware: whether OpenSC's PIV module can block in `C_Sign` long enough (touch policy, card removal, wedged reader) to hit the 30s deadline, and whether `C_Finalize`/`CloseSession` during a blocked call hangs rather than errors. Repo-side mitigations would be guesses without that evidence (e.g. suppressing the close after a deadline error would trade a hang for a locked card).
**Owner/evidence needed:** OpenSC/YubiKey PIV module (and crypto11's pool behaviour on a stuck call). Required evidence: a `pkcs11-spy` run against real hardware with a PIN policy requiring touch — timestamped `C_Sign` entry/exit versus the 30s request deadline and versus the `C_CloseSession`/`C_Finalize` calls at exit — plus the resulting process exit status. No such run exists today (SoftHSM only, per Sonnet's "Not touched" section).

---

## Errata in the record (source-level, no disposition change)

- `transport.go:1811-1813` → the wait-for-handshake block is `1809-1815`; `transport.go:1920` → the proxy dial call is `1921-1924` (Sonnet item 51).
- Item 50's `client_requests.go:319-336` is the right region; the open-bodied 3xx comes from `client.go:713-720`, not `:716-720` alone.
- Per-function record drift: `TokenLookUpSelf` is at `main.go:412`, not `:413`; stdlib constants are `transport.go:53` (`ForceAttemptHTTP2`), `:56` (`TLSHandshakeTimeout`), `:62` (`DefaultMaxIdleConnsPerHost`) — the record's `:47-57`/`:60-62` are acceptable as ranges.
- Sonnet's own drift note about `go.mod:8` vs `:9` for `gopkg.in/yaml` is confirmed (`go.mod:8` is `go.yaml.in/yaml/v3`); it does not affect this function.

## Cross-references (not newHTTPClient-origin)

- **30 / C3+V1 (`unix://`)** — verifies the `DialContext` override at `vault-client-go client.go:97-110` that discards this function's 5s dialer; also relevant to H2. Owned by newVaultClient/CreateLocalVaultClient.
- **32 / C6 (proxy snapshot)** — `envProxyOnce` (`transport.go:1039`) interacts with the clone at `main.go:364` but is filed under CreateLocalVaultClient.
- **60 / V4 (wall-clock bound)** and **61 / V5 (real-endpoint h2)** — both parameterise this transport; owned by newVaultClient.
- Invariant worth carrying forward, not a question: `MaxIdleConnsPerHost` stays `0` on the clone → effective 2 (`transport.go:62`), versus the library's cleanhttp default; irrelevant for a single-shot CLI.

## Counts

| Disposition | Count | Items |
|---|---|---|
| TREAT | 1 | H2 (49) |
| TOLERATE | 1 | H4 (51) |
| TRANSFER | 2 | H3 (50), H5 (52) |
| TERMINATE | 1 | H1 (48) |
| **Total** | **5** | |

## Recommended worklist

1. **TREAT (H2).** One small task in `LoadConfig`: settle the `vaultAddr` scheme policy and correct the `main.go:126-129` rationale — with a test — plus a TRANSFER note to Vault/OpenBao for the untested plaintext-`CertLogin` server response.
2. **TRANSFER (H3).** Open an upstream issue against `hashicorp/vault-client-go` (send loop re-assigns the redirect response without closing; `ErrUseLastResponse` returns an open body) with the source chain and a fixture-based repro. No repo change; re-check on the next dependency bump.
3. **TRANSFER (H5).** Request the OpenSC/YubiKey evidence — `pkcs11-spy` on real hardware with a touch-required key, comparing `C_Sign` duration against the 30s request deadline and the exit-path `C_Sign`/`C_Finalize` ordering. Record the outcome as "hang moves to `Close`" if the module blocks.
4. **No action (H1, H4).** Keep as watch items only; both are answered at source with accepted, environment-scoped residuals.

---

Skipped: re-running any of Sonnet's five experiments (their scratch harness is gone, so all runtime numbers here are report-only); the real YubiKey, OpenSC and a live Vault/OpenBao were not touched. Risk to know: H3's leaked redirect body and H5's exit-path `C_Finalize` hazard both rest partly on external behaviour or unverified test runs — do not quote either as reproduced here.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §2–§3. All temporary binaries, configs and traces were deleted; nothing retained.
- **H2 (49)** — the TREAT is resolved: `LoadConfig` now rejects every non-HTTPS scheme (including `http` and `unix`), so `newHTTPClient` is only reached with `https` and the "non-https `vaultAddr` reachable" premise no longer holds (`main.go:129-142`; `TestLoadConfig_RejectsNonHTTPSVaultAddr`). D-1/T-3.
- **H1 (48), H4 (51)** — unchanged (TERMINATE/TOLERATE).
- **H3 (50)** — TRANSFER unchanged: the 3xx body is still not closed on the redirect path; the `opened=3 closed=2` count remains an unretained agent run and no fixture reproduction exists.
- **H5 (52)** — TRANSFER stays open. No stalled/touch-policy `C_Sign` was run; the live endpoint was reached over HTTPS with `newHTTPClient(clientTLSConfig(cert))`, so the transport presents the certificate on the one deployment tested, but the touch/deadline case is unobserved.
