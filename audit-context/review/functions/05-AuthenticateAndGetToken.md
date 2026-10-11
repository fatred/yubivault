## Independent verification performed

Repo at HEAD `7f10998` (`git status` clean). I read the sources cited below and ran probes in a throwaway copy of the package (`/tmp/disp`, deleted) against `vault-client-go@v0.4.3` in the module cache. Nothing in the repo was edited.

Reproduced (observed, this session):

| Probe | Result |
|---|---|
| `MockVaultClient{CertLoginResp:nil, CertLoginErr:nil}` → `AuthenticateAndGetToken` | nil-pointer panic at `main.go:402` |
| `TokenLookUpSelfResp:nil, err nil` → same | nil-pointer panic at `main.go:416` |
| lookup `Data{"id":""}` | returns `("", nil)` — empty line, exit 0 contract |
| real client `Auth.CertLogin` vs httptest TLS 200 `{"data":null,"auth":{"client_token":"tok"}}` | `resp.Auth.ClientToken == "tok"` |
| real client, 200 `{"request_id":"x","auth":{...}}` (no `data` key) | `resp.Auth == nil`, whole body in `resp.Data` |
| real client, 200 empty body | `(nil, nil)` |
| `Client.SetToken("")` / `SetToken("s.a\nb")` | `nil` / `vault token contains non-printable characters` |

Source-verified: `parseResponse` returns `(nil,nil)` for a zero-length body (`response.go:126-128`) and its `else` branch decodes the whole body into `Data` leaving `Auth` nil (`response.go:152-159`); library's own `Test_parseResponse_structured` "empty" expects `nil` and "with-no-data" expects body-in-`Data` (`response_test.go`). `sendRequestParseResponse` forwards that pair on 2xx (`client_requests.go:160-197`, `errors.go:60-113`). `SetToken`→`validateToken`→`printable` (`request_modifiers.go:54-62`, `:300-306`, `:327-333`). No `Wrap`/wrap-TTL reference anywhere in `main.go`. `SetTokenErr` declared and returned, never assigned (`main_test.go:33`, `:41-43`).

Not independently verified: Sonnet's fixture-server runs for MFA (A2) and wrap_info (A4) — the `/tmp` scratch is gone. Those two are **report-only**; both are also implied by source and consistent with my probes.

---

## A1 — Sonnet item 23 (dossier: "Can a Vault/OpenBao cert-login or lookup-self return 200 with an empty body?")

**Original question.** 200 + empty body ⇒ `resp`/`tokenResp` nil with nil error at `main.go:402`/`:416`.

**Sonnet's disposition.** *Partly.* Source: `parseResponse` `nil,nil` (`response.go:126-127`), passed through (`client_requests.go:~186-195`). Observed panics on both sites. Remaining: server behaviour.

**My assessment.** Confirmed and strengthened. The library's own test (`response_test.go` "empty" ⇒ `expected: nil`) documents the `(nil,nil)` return, and my real-client probe reproduced it for a 200 with an empty body. Both dereferences (`main.go:402`, `:416`) are unguarded and my mock probes panicked at each. The remaining external unknown (does a real server ever emit an empty 2xx here) is real but only sets severity: the client-side fault is verified, at a network trust boundary, and fixable without the server answer. Sonnet stops at "server behaviour" and leaves the verified crash undispositioned.

**Final disposition: TREAT.**

**Rationale.** The defect ("client dereferences a response the library explicitly allows to be nil") is repo-owned; the fix does not depend on Vault/OpenBao evidence. Not TRANSFER because Vault cannot fix yubivault's dereference; not TOLERATE because a crash is strictly worse than a clean error and the guard is ~2 lines.

**Suggested task.** In `AuthenticateAndGetToken`, return a local error when `resp == nil` (after `main.go:398`) or `tokenResp == nil` (after `:412`), matching the existing `fmt.Errorf` style; add mock cases (`CertLoginResp:nil/err nil`, `TokenLookUpSelfResp:nil/err nil`). Low priority; may be merged with A3 into one mock-driven hardening test.

---

## A2 — Sonnet item 24 ("Is the `client_token not found or empty` branch what an MFA-gated login takes?")

**Original question.** Whether an MFA-gated cert login lands on `main.go:407`, given `resp.Auth.MFARequirement` is never read.

**Sonnet's disposition.** *Partly.* `MFARequirement` defined (`response.go:61`) never read in `main.go`; fixture with empty `client_token` + `mfa_requirement` produced the `main.go:407` error. Remaining: Vault/OpenBao source or a recorded MFA response.

**My assessment.** Client-side mapping is source-certain: an `auth` object with empty `client_token` always reaches `:407` (verified: `SetToken("")` itself would be accepted, `request_modifiers.go`; the `:406` check is the only guard). The client-side observation is report-only here (Sonnet's fixture not rerun) but trivially implied. Whether cert auth under login-MFA returns `auth.client_token:""` + `mfa_requirement` is server-side and unknown; the repo's own setup (`PKI-SETUP.md`) does not mention MFA.

**Final disposition: TRANSFER.**

**Rationale.** The open element is the server's MFA response shape, owned by Vault/OpenBao; the client already fails non-zero, so nothing in the repo is broken — only the diagnostic text would be inaccurate in that deployment.

**Owner / evidence needed.** Vault (Enterprise login-MFA) and OpenBao source, or a recorded MFA-gated cert-login response. Also a maintainer-policy call on whether MFA-enforced deployments are in scope. If in scope and the shape matches, that is a new repo task (emit a specific "MFA required" error instead of `client_token not found or empty`); otherwise the item closes.

---

## A3 — Sonnet item 25 ("Does lookup-self always return a JSON string at `data["id"]`?")

**Original question.** Whether `data.id` can be redacted, absent or non-string (decoder uses `json.Number`).

**Sonnet's disposition.** *Partly.* Numeric id ⇒ `token id not found or not a string`; absent `data` covered by an existing test; **new**: `"id":""` ⇒ empty string, nil error, empty line + exit 0; **new**: body without a `data` key decodes wholesale into `Data`, so a top-level `id` is accepted. Remaining: whether a real server redacts/omits `id`.

**My assessment.** Confirmed. I reproduced `Data{"id":""}` ⇒ `("", nil)`; the existing `TestAuthenticateAndGetToken_NoID` (`main_test.go:108-121`) covers the missing-key case, and a nil `Data` map is equally safe under the comma-ok assertion (`main.go:416`). The `data`-less-body branch is a library quirk (verified: whole body lands in `Data`), but lookup-self always returns a `data` object, so it has no effect here. The `"id":""` case is a genuine client-side gap: the function's whole contract is "print the token or fail", and an empty token printed with exit 0 violates it. Reachability is external (would require lookup-self to return an empty id for a valid, non-empty token), but the guard is repo-owned.

**Final disposition: TREAT.**

**Rationale.** Silent success with empty output is a repo-owned contract violation (the caller's `VAULT_TOKEN="$(...)"` would be set to empty while the command succeeds); not TOLERATE because the failure should be loud, not TRANSFER because no server evidence is needed to reject an empty id.

**Suggested task.** Reject an empty `id` at `main.go:417-419` (fold in the A1 nil guards); add a mock case for `Data{"id":""}`. One small test file change covers both.

---

## A4 — Sonnet item 26 ("Can a deployment force a wrapped login response (`wrap_info` present, `auth` absent)?")

**Original question.** Whether wrapping can be forced server-side, mapping onto `auth field not found in response`.

**Sonnet's disposition.** *Partly.* `main.go` never sets a wrap TTL; grep for Wrap finds nothing. Observed `auth:null` + `wrap_info` ⇒ `auth field not found`; a body with no `data` key gives the same error. Remaining: server-forced wrapping behaviour.

**My assessment.** Premise unsupported. Sonnet itself found no client-side wrap request, and I confirm no `Wrap`/wrap-TTL reference in the repo; Vault response wrapping is requested by the client via the `X-Vault-Wrap-TTL` header (no auth-method or namespace policy forces it on cert login). The only other route is a response-altering intermediary, which is outside the trust model: any party able to rewrite the response body already holds a cert the client trusts and could substitute the token outright. Sonnet's "no `data` key ⇒ same error" observation is correct and I reproduced it (`resp.Auth==nil`), but real Vault sends the standard envelope `{"data":null,...}` (my probe: `data:null` ⇒ `Auth` populated), so this is not a defect — it is the library's documented fallback branch.

**Final disposition: TERMINATE.**

**Rationale.** No mechanism identified by which a deployment forces wrapping; the premise is invalid, and the fallback branch Sonnet observed is a library behaviour with no reachable trigger from a conforming server. (No finding recorded for the `data`-less-body branch.)

---

## A5 — Sonnet item 27 ("Is the `SetToken` non-printable rejection reachable from a server-supplied `client_token`?")

**Original question.** Whether a control-character token can reach `SetToken` (`main.go:409`), given no test assigns `MockVaultClient.SetTokenErr`.

**Sonnet's disposition.** *Partly.* Source: `validateToken`/`printable` (`request_modifiers.go:300-306`, called from `SetToken` `:54-57`). Observed `s.a\nb` ⇒ `vault token contains non-printable characters`. `SetTokenErr` declared/returned, never assigned. Remaining: whether Vault issues tokens with control characters; printable token IDs is `[INFERENCE]`.

**My assessment.** Confirmed independently: `SetToken("s.a\nb")` errors, `SetToken("")` does not. The client behaviour is correct and loud (clean error, non-zero exit). The only residual is that the charset of real Vault/OpenBao token IDs is unverified — external, but non-consequential: if such a token were ever issued, yubivault fails with an accurate message, and no token is produced.

**Final disposition: TOLERATE.**

**Rationale.** Known residual, accepted: the rejection path is correct in every case and needs no repo change. The external charset question is preserved but no decision depends on it. Separately noted (not a finding): `MockVaultClient.SetTokenErr` (`main_test.go:33`) is dead test scaffolding — either exercise it or delete it.

---

## A6 — Sonnet item 2 (merged R2+A6; origins: `run`, `AuthenticateAndGetToken`)

**Original question.** Does the `(login client_token, lookup id)` pair ever differ in a real deployment, and which should the caller's shell hold?

**Sonnet's disposition.** *External-unknown.* Code always returns the lookup `data.id` (`main.go:405-420`); scratch `lookup-id-differs` printed `s.OTHER`; fixture uses different strings (`main_test.go:50-56`). Remaining: Vault/OpenBao token-store source, or a recorded real lookup-self response.

**My assessment.** Client behaviour is source-certain and deliberate: the function returns the lookup value, `Auth.ClientToken` is used only for `SetToken` (`main.go:409`), and `TokenLookUpSelf` is a generic parse (`api_auth.go:5544-5566`). The fixture's differing strings are artificial — `lookup-self` returns the calling token's own record, so equality is expected in practice `[INFERENCE]`, unverified against a live server. If they could differ, the export choice is a maintainer call, not a bug.

**Final disposition: TRANSFER.**

**Rationale.** The evidence (how lookup-self populates `id` for the token this login issues) belongs to Vault/OpenBao; the secondary "which value to export" is maintainer policy. No repo defect is established: the code path is explicit and tested.

**Owner / evidence needed.** Vault/OpenBao token-store source or one recorded real `auth/token/lookup-self` response for a cert-issued token, plus a maintainer statement on the intended exported value. If `id` is always the issued token, the item closes.

---

## Counts

| Disposition | Count | Items |
|---|---|---|
| TREAT | 2 | A1 (23), A3 (25) |
| TOLERATE | 1 | A5 (27) |
| TRANSFER | 2 | A2 (24), A6 (2, R2+A6) |
| TERMINATE | 1 | A4 (26) |
| **Total** | **6** | all `AuthenticateAndGetToken`-origin questions |

## Recommended worklist

1. **TREAT (repo, low priority) — one change:** harden `AuthenticateAndGetToken` against degenerate but library-permitted 2xx responses: `nil` `resp`/`tokenResp` guards (`main.go:398`, `:412`) and rejection of an empty lookup `id` (`main.go:417-419`); add mock cases for both. Rationale: verified panic (A1) and verified silent empty success (A3); independent of any server evidence.
2. **TRANSFER (external) — two questions, one owner:** ask Vault/OpenBao for (a) the cert-login response shape under login-MFA (A2) and (b) `lookup-self` `id` semantics for a cert-issued token (A6). Record answers; if the MFA shape matches and MFA is in scope, open a small repo task for a specific error message; if lookup `id` is always the issued token, close A6.
3. **Optional hygiene (not a finding):** `MockVaultClient.SetTokenErr` (`main_test.go:33`) is never assigned — delete it or add a test that uses it (A5).
4. **No action:** A4 (no mechanism; premise invalid), A5 (behaviour correct; residual accepted).

Skipped: no live Vault/OpenBao contact, so all server-shape conclusions (A2/A6) and the `data:null` envelope assumption rest on source plus `[INFERENCE]`; Sonnet's A2/A4 fixture runs are report-only. Risk: if a real server did return an empty 2xx, the unguarded dereferences panic today (exit non-zero, nothing on stdout) — the A1 guard removes that but is not yet applied.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §2–§3. All temporary artifacts (binaries, configs, raw traces) were deleted; nothing retained.
- **A1 (23), A3 (25)** — TREAT is merged: `resp == nil`, `tokenResp == nil` and empty `id` now return errors (`main.go:412-414`, `:429-431`, `:436-437`; tests `…_NilCertLoginResponse`, `…_NilTokenLookUpSelfResponse`, `…_EmptyID`). The "not yet applied" risk above no longer holds.
- **A6/R2 (2)** — a live cert login with the configured role succeeded (`lookup-self` HTTP 200); whether `data.id == auth.client_token` was **not** recorded, so TRANSFER stands (§3a) and the printed value is still `tokenResp.Data["id"]`.
- **A2 (24), A4 (26)** — no MFA-enabled mount and no wrapping case were exercised; TRANSFER unchanged.
- **A5 (27)** — unchanged (TOLERATE); `MockVaultClient.SetTokenErr` is still never assigned.
