# Treatment status of the open questions

**This is a status snapshot, not a new analysis.** It records what has been done about each disposition in [OPEN-QUESTION-REVIEW.md](OPEN-QUESTION-REVIEW.md) (the "review"), against the checkout at `850215d`. IDs and row numbers are the review's (§1a, §1c). Update this file whenever new evidence arrives; nothing here is a live check.

Inputs: [DOSSIER.md](../DOSSIER.md), the review, the per-function reports in [functions/](functions/) (`01-run.md` … `12-newVaultClient.md`), and the current `main.go`, `main_test.go`, `softhsm_test.go`, `README.md` and `.github/workflows/ci.yml`. The review is an older snapshot, so line numbers it cites for `main.go` have moved. I ran no build, test or binary for this document.

**Evidence tags**
- **[repo]**: read in this checkout (source, tests, CI file, git log).
- **[source]**: pinned module source, as the review cites it. Not re-read here.
- **[agent-run]**: a scratch run on the real YubiKey, a disposable SoftHSM token, or the live Vault. No artifact was retained; all temporary binaries, configs and traces were deleted. These results cannot be re-read, only repeated.
- **[reported]**: stated in the brief for this document, not verified by me (for example "post-merge CI passed").

Secrets are deliberately absent: no PIN, token, raw `pkcs11-spy` trace or serial number is recorded here.

---

## 1. The four dispositions

| Disposition | Meaning | Work it implies | Rows (review §1) |
|---|---|---|---|
| **TREAT** | A repo-owned defect, untested path or wrong rationale. | A repo change (a decision, then a task). | 7 |
| **TRANSFER** | The answer sits outside the repo: the Vault/OpenBao server, the deployment, OpenSC/YubiKey, or `vault-client-go`. | **Evidence from the owner**, not a repo change. Code changes only if the evidence shows a difference (stated per item below). | 15 |
| **TOLERATE** | A known residual, accepted. | None. Re-open only on the condition recorded in review §4. | 17 (+6 extras) |
| **TERMINATE** | Closed by evidence in the review, or a duplicate/invalid premise. | None. | 24 (+6 extras) |

Implementation tasks (TREAT) are separate from external evidence (TRANSFER) and from accepted residuals (TOLERATE). A TRANSFER item does not become a task by receiving evidence; it becomes one only if the evidence contradicts the code's assumption.

---

## 2. TREAT: all seven rows treated and merged

All five tasks and the three decisions of review §3 are on `main` [repo: `git log`]. CI on the merge commits is reported green [reported]; I did not check it.

| Task | Review rows closed | Decision taken | Merge commit | What the checkout shows [repo] |
|---|---|---|---|---|
| **D-1 + T-3** | 30 (C3+V1), 49 (H2) | Option (a): accept only absolute HTTPS | `57d7407` (#31) | `LoadConfig` returns `vaultAddr must be an absolute HTTPS URL` for `http`, `unix`, other schemes, scheme-less, opaque and hostless values, and normalises `HTTPS://` to `https://` (`main.go:129-142`; `TestLoadConfig_RejectsNonHTTPSVaultAddr`, `TestLoadConfig_NormalizesHTTPScheme`). README example uses `https://` (`README.md:57-58`). The unsupported "http stays usable" rationale is gone. |
| **T-1** | 23 (A1), 25 (A3) | n/a | `617ef7a` (#34) | Nil `CertLogin` response, nil `lookup-self` response and empty `id` now return errors (`main.go:412-414`, `:429-431`, `:436-437`). Tests: `…_NilCertLoginResponse`, `…_NilTokenLookUpSelfResponse`, `…_EmptyID`. |
| **T-2** | 22 (L4) | n/a | `850215d` (#37) | A parse error in an extra YAML document is wrapped with `%w`; a bare extra `---` keeps the fixed message (`main.go:123-128`). |
| **D-2 + T-4** | 45 (D4) | Option (b): keep the generic reader branch, test the terminal branch | `cdb8483` (#32) | The generic branch is still present (`main.go:398-404`). `TestReadPin_TerminalBranch` re-executes the test binary with stdin on `/dev/null`, asserts exit 1, empty stdout, and a prompt followed by `could not read PIN code: <non-empty cause>` on stderr. It does not pin the exact `ENOTTY` text that the review's acceptance criterion named. |
| **D-3 + T-5** | 11b (Y6b) | Option (a): SoftHSM test, required in Linux CI | `7c34bbe` (#33) | `TestCreateYubikeyVaultClient_SoftHSM` builds a token, calls `CreateYubikeyVaultClient`, runs `loginAndClose` against a local TLS server, and asserts exactly one `Close`, one login and one `lookup-self`. It skips when SoftHSM is absent unless `YUBIVAULT_REQUIRE_SOFTHSM=1`; CI sets that on Linux only (`ci.yml:39-44`), so the macOS job skips it. |

**Not a review task: `a31e212` (#36), "trim TOKEN_PIN input".** `resolvePin` now trims `TOKEN_PIN` and falls back to the prompt when it is whitespace-only (`main.go:269-271`; `TestResolvePin`). This makes the DOSSIER statement that `TOKEN_PIN` is "returned verbatim" ([DOSSIER.md](../DOSSIER.md), trust boundaries) stale. It bears on row 40 (P2), below.

Residual of the TREAT work: none open. Tests pin the new behaviour with fixtures only. Where a row's real-world answer is external, see §3.

---

## 3. TRANSFER: status by row

Legend: **open** = no evidence received; **partial** = some evidence, listed with its limit; none is marked closed because every received item is scratch evidence with no retained artifact. Closing a row needs the owner's acceptance of the evidence (or a re-run that is retained).

### 3a. Live Vault/OpenBao evidence received

[agent-run, scratch] Real login against `https://vault.example.invalid:8200`:
- A **failed** login with a deliberately nonexistent role returned HTTP 400 `failed to match all constraints for this login certificate`. This run was `pkcs11-spy`-traced.
- A **successful** login with the configured `admin` role exited 0; `lookup-self` returned HTTP 200. The token was then revoked (204) and a later `lookup-self` returned 403. The `example-user` identity entity/alias existed before the test and was left intact. This login was **not** spy-traced.

Limits: the brief does not say whether the server is Vault or OpenBao, nor what mount, role or CA configuration it has. The failed-role response is a **nonexistent-role** response; it is not the wrong-certificate response that row 38 asks for. The brief does not record whether `data.id` from `lookup-self` equals `auth.client_token` (row 2). The live login also implies that this one host's CA is trusted by this one workstation [INFERENCE], because the HTTPS handshake completed; the organization's root and intermediate CAs are in this workstation's trust store [per workstation notes].

### 3b. Vault/OpenBao maintainers or the deployment operator

| Row | ID | Question | Status | Notes |
|---|---|---|---|---|
| 2 | R2+A6 | How `lookup-self` populates `data.id` for a cert-login token | **open** | Live login succeeded but equality of `data.id` and `client_token` was not recorded. Decision only if they can differ: print `Auth.ClientToken` instead. |
| 24 | A2 | Cert-login response shape under login MFA | **open** | No MFA-enabled mount was exercised. Decision pending: whether MFA deployments are in scope; if so, a specific error message. |
| 26 | A4 | Can a deployment force response wrapping on an unauthenticated login? | **open** | Client side is settled: `resp.Auth == nil` gives `auth field not found in response` (`main.go:415-417`) [repo]. Only the accuracy of that message for forced wrapping is open. |
| 38 | S6 | How a **wrong** client certificate surfaces (TLS alert vs 4xx body) | **open** | The 400 above is the wrong role, not the wrong certificate. `TestLoginAndClose_ClosesOnFailure` uses plain HTTP and says nothing about TLS failure. |
| 10 | Y5 | Deployed role and complete CA topology | **open** | Live login worked with whatever chain the module presents (the review states crypto11 presents the leaf only, `certificates.go:164` [source]). The role's trust configuration was not read, so topology is unknown. Decision only if an intermediate CA exists: document the leaf-only behaviour. |
| 61 | V5 | The listener's ALPN set | **open** | No `openssl s_client -alpn h2` evidence. No repo code depends on the answer. |
| 56 | T4 | Each host's trust store and `SSL_CERT_FILE`/`SSL_CERT_DIR` | **partial** | One host (this workstation) trusted the issuing CA for the one Vault tested [INFERENCE from the successful login]. Other hosts and other deployments: open. No repo change expected. |

### 3c. OpenSC / YubiKey (real card)

Card: YubiKey 5 NFC, firmware 5.1.2, PIV slot 9A, certificate CN `example-user`, OU `example-team`, ECC P-384 [agent-run, scratch]. `ykman piv info` continues to report three PIN tries remaining. Its `Private key type: EMPTY` line is a known firmware-metadata limitation and is not evidence that the key is absent.

| Row | ID | Question | Status | Evidence and limit |
|---|---|---|---|---|
| 7 | Y2 | Order of `C_CloseSession`/`C_Finalize`; clean exit after login | **partial** | Failed-role run, spy-traced: two successful `C_Sign` calls, then all three sessions closed, then one `C_Finalize`. The successful login exited 0 but was **not** traced, so close order on the success path is unobserved on hardware. SoftHSM covers the success path structurally (§2, T-5), which says nothing about OpenSC. |
| 9 | Y4 | Which `CKO_PRIVATE_KEY` objects and `CKA_ID`s are exposed; empty-`CKA_ID` matching | **partial** | Application enumeration saw `CKA_ID` `01` on the paired private key, public key and certificate, with one private-key, one public-key and one certificate match. **Not tested:** empty-`CKA_ID` matching, and every other PIV slot (the inventory was not taken). |
| 34 | S2 | Does a `CKO_PUBLIC_KEY` object exist per slot? | **partial** | One public-key match for slot 9A's pair. Other slots not inventoried. |
| 35 | S3 | Which key types the module reports | **partial** | An ECC P-384 key signed twice successfully through the app. Whether other types (RSA, P-256, others) are reported or usable is not tested. The brief does not state the `CKA_KEY_TYPE` value seen. |
| 40 | P2 | `C_Login` `ulPinLen` vs `strlen`; whitespace and NUL in a PIN | **partial** | Real card: `C_Login` succeeded with `ulPinLen=6`; an input with surrounding whitespace was trimmed to the same six bytes. SoftHSM only (not the YubiKey): a PIN with an embedded NUL reached `C_Login` as length 7 and returned `CKR_PIN_INCORRECT`. **No embedded-NUL PIN was sent to the YubiKey**, to protect its retry counter, so OpenSC's NUL handling on the card is open. |
| 52 | H5 | Can `C_Sign` block (touch policy)? | **open** | Both `C_Sign` calls on the card completed. The brief does not say the slot has a touch policy, and no stalled-`C_Sign` case was run. The 30 s deadline and the exit-time `Context.Close` interaction remain the review's source-only argument [INFERENCE]. |
| 58b | V2b | Does `Close` block on a stuck `C_Sign`? | **open** | Shares the evidence package with row 52. The observed close followed completed signs only. |

### 3d. `hashicorp/vault-client-go`

| Row | ID | Question | Status | Notes |
|---|---|---|---|---|
| 50 | H3 | The send loop leaks a 3xx response body (`client_requests.go:319-333`) | **open, optional** | No upstream report filed. Needs a fixture-based reproduction first; the `opened=3 closed=2` count is an unretained [agent-run]. |

---

## 4. TOLERATE: accepted, no work

Unchanged from review §4. Nothing here implies a task. Re-open only on the review's stated condition.

Rows 5 (R5), 12 (K1+C4), 14 (K3+C4), 15 (K4), 16 (K5), 18 (K7), 19 (L1), 21 (L3), 27 (A5), 28 (C1), 36 (S4), 39 (P1), 41 (P3+D2), 47 (D6), 51 (H4), 54 (T2), 60 (V4); extras X-R4, X-K2, X-S5, X-D7, X-D8, X-V6.

Two notes, neither a re-opening:
- Row 28 (C1) and row 14 (K3+C4) rest on `config.yml` being operator-controlled; D-1 did not change that.
- Row 54 (T2) is untouched by D-1: HTTPS-only does not affect an HTTPS proxy asking for a client certificate.

---

## 5. TERMINATE: closed

Closed as recorded in review §6; no change since.

Rows 1, 3, 4, 6, 8, 11a, 13, 17, 20, 29, 31, 32, 33, 37, 42, 43, 44, 46, 48, 53, 55, 57, 58a, 59; extras X-K1, X-S1, X-S2, X-S3, X-S4, X-S6.

Row 30's old premise ("`unix://` fails safely") is now moot rather than answered: the client rejects such addresses at config load (§2).

---

## 6. Reconciliation of review §7 (coverage limits)

| Review §7 limit | Now |
|---|---|
| Hardware and OpenSC: nobody ran OpenSC against the real YubiKey | **Partly superseded.** One real-card traced run exists (§3c). OpenSC source is still unread, and the run is unretained [agent-run]. Rows 7, 9, 34, 35, 40 are partial; 52 and 58b are open. |
| Live Vault/OpenBao never contacted | **Superseded in part.** One failed and one successful login against one deployment (§3a). Still unknown: MFA, wrapping, wrong-certificate, ALPN, CA topology, other deployments. The "server rejects plaintext cert login" inference no longer matters because the client refuses non-HTTPS. |
| External-module citations are as reported | **Unchanged.** Not re-read for this document. |
| No scratch artifacts remain | **Unchanged**, and now also true of the live and real-card runs above. |
| Questions possibly dropped from the dossier | **Unchanged.** Reports 01–06, 08, 10 and 11 were not compared against the per-function records. |
| Units never analysed: `loginAndClose`, `YubikeyVaultClient.Close`, `requireForMode`, `pathErrCause`, `certCNs`, `main`, the two CI jobs | **Still not analysed**, but tests now cover some of them [repo]: `loginAndClose` (`TestLoginAndClose_ClosesOnFailure`, SoftHSM success path), `YubikeyVaultClient.Close` (`TestYubikeyVaultClient_CloseNil`, SoftHSM single-close), `requireForMode` (`TestRequireForMode`). `pathErrCause` is probably exercised by `TestCreateLocalVaultClient_KeyErrorsDoNotLeakPath` [INFERENCE from the name]. No test or analysis for `certCNs` or `main` was found. The CI file has gained a `vulncheck` job and the SoftHSM install step (`ci.yml:39-44`, `:55-70`); these were not analysed. |
| Platform scope: go1.27.2 on linux/amd64 only; macOS and release artifacts not inspected | **Unchanged.** The SoftHSM test is not required on macOS (§2). The real-card and live runs were on this Linux workstation only. |

Remaining audit-completeness limits, stated plainly:
- Every hardware and live result in this file is scratch evidence with no retained artifact.
- The successful Vault login was not spy-traced, and the traced run was a failure path.
- The review and per-function reports retain historical source-file and line citations from their
  audit snapshot. The PKI guide cited there as `PKI-SETUP.md` now lives at `docs/pki-setup.md`.
- The DOSSIER and review include dated evidence addenda. Use those addenda and this status snapshot
  for current status; original claims explicitly superseded by dated notes remain historical.

## 7. Next actions

None are repo changes. Open work is evidence only:
1. A retained spy trace of a **successful** login on the real card (rows 7, 40, 52, 58b), including an empty-`CKA_ID` and all-slot inventory (rows 9, 34, 35). Never guess the PIN.
2. From the Vault/OpenBao operator: MFA shape, forced wrapping, wrong-certificate response, role/CA topology, ALPN, `data.id` vs `client_token` (rows 2, 10, 24, 26, 38, 61), and trust-store checks on other hosts (row 56).
3. Optional: a fixture reproduction for row 50 before any upstream report.
