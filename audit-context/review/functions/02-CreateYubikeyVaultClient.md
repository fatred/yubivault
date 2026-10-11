# Adversarial disposition — `CreateYubikeyVaultClient` (`main.go:273-313`)

**Verified against:** repo HEAD `7f10998`; `github.com/eclipse-keypont/crypto11 v1.6.8`, `github.com/miekg/pkcs11 v1.1.2`, `github.com/thales-e-security/pool v0.0.2` in the module cache; `PKI-SETUP.md`. Every `main.go`/crypto11/keys/certificates/sessions/pool line I cite was read at that path in this session. I ran `go test -race -run 'TestCreateYubikeyVaultClient|TestYubikeyVaultClient_CloseNil|TestLoginAndClose' ./...` (PASS, 1.02s) — that is the only execution I performed. No OpenSC, no YubiKey, no live server. **All SoftHSM / `pkcs11-spy` observations are Sonnet's and are report-only** (not reproducible in-repo, not in-repo evidence).

## Corrections and drift in the Sonnet excerpt (recorded, not dispositions)

1. **`rsa.go:458` is not the signing path.** It is `Decrypt`'s `withSession` (`rsa.go:458`); `Sign` is `rsa.go:584-585`. Sonnet's item V2 (newVaultClient-owned) cites "`rsa.go:458`, `:585`" as the signer. Immaterial to every Y item, but the citation is wrong.
2. **Second-`Close` consequence is understated (Y6).** Sonnet says a second `moduleCtx.Close` "panics with `referenced module not found`". `Context.Close` has no idempotence guard, and before reaching that panic it calls `c.ctx.CloseSession(c.persistentSession)` on the destroyed module; miekg's `Destroy` sets `c.ctx = nil` (`pkcs11.go`, `Destroy`), so the second close is a nil-`Ctx` use (crash) as well as the source panic at `crypto11.go:355-370`. Invariant is load-bearing; failure mode is a crash, not an error.
3. **`PKI-SETUP.md:127-129` conflation.** The `vault write` block with `certificate=@out/Vault_Users_CA.crt` is `:127-133`; the sentence "``certificate`` is the CA certificate" is at `:136`, not `:127-129`.
4. **Y1 "Partly" overstates the residual** (see row). All SoftHSM/`pkcs11-spy` "observed" strings in Y1/Y2/Y3/Y6 are report-only.
5. Sonnet's Y3 and Y6a structural claims ("mutually exclusive by `err`") are **correct** as written; I re-derived them from source.

---

## Y1 — (6) Do crypto11 error strings on the failure paths include the PIN, the module path, or token content?

- **Sonnet disposition:** *Partly* — SoftHSM strings showed none of the three; "remaining: strings from OpenSC and real-hardware output".
- **My assessment:** the code-level answer is a definite **no**, and Sonnet's "remaining" is not about crypto11's error strings at all. Fully enumerated error constructions in `crypto11.go`: `:119, :137, :162, :333, :338, :405, :407, :414, :427, :437, :461, :478, :523, :535`. The only interpolations are `%v` of static field names (`:407`), `%w` of a `pkcs11.Error` (`:338, :427, :437, :461, :478`), and `%w` of wrapped pkcs11 errors (`:137, :162`).
  - `.Pin` appears **only** as the `Login` argument (`crypto11.go:468, :470`); miekg `Login` returns `toError(e)`, i.e. a fixed CKR name from the constant map in `miekg/pkcs11 error.go` (`CKR_PIN_INCORRECT` = `0xA0`) — no PIN text possible.
  - `config.Path` reaches only `openModule`'s `pkcs11.New(path)`; its failures are the constants `"failed to open module"` (`crypto11.go:333`) and `"failed to initialize module: %w"` (`:338`). The module path is never formatted.
  - `errTokenNotFound` = `"could not find PKCS#11 token"` (`crypto11.go:119`) — no serial.
  - Token content: `getKeyPair` discards the card-certificate parse result (`certificate, _ = findCertificate(...)`, `keys.go:176-178`) and `makeKeyPair`'s only variable error is `"unsupported key type: %X"` of a CKK enum (`keys.go:235`); `"key id or label cannot both be empty"` (`keys.go:130`) is constant.
- **Final disposition: TERMINATE.** Rationale: the question is answered negatively at source for the pinned dependency; the wrong-serial and bad-module messages are constants, which is the property the question asks about. Real-hardware output cannot change a string the library constructs from numeric codes.
- **Carried residue (not an open question here):** the PIN is necessarily passed to the module as `C_Login` input, so a loaded module or spy layer sees and can record it — that is the `resolvePin` P1/P4 space and is external.

## Y2 — (7) Is `Context.Close` (`C_Finalize`/`C_Destroy`) safe on this OpenSC build and PIV applet after a logged-in session?

- **Sonnet disposition:** *External-unknown*; SoftHSM closed cleanly (rc=0), spy showed 4× `C_CloseSession`, 1× `C_Finalize` (report-only); "remaining: an OpenSC and YubiKey run".
- **My assessment:** source agrees the ordering is correct by construction — `Context.Close` (`crypto11.go:540-557`) = set `closed` → `pool.Close()` (drains and closes pooled sessions; blocks until in-flight are returned; second call is ignored via `SetCapacity(0)` → `ErrClosed`, `pool@v0.0.2 resource_pool.go:140-146, :266-280`) → `CloseSession(persistentSession)` (error discarded) → `moduleCtx.Close` → `Finalize`+`Destroy` at refCount 1 (`crypto11.go:355-388`). There is nothing repo-side to change. The residual is entirely module/hardware behaviour (OpenSC finalize/instance-lifecycle quirks), which is not observable here.
- **Final disposition: TRANSFER.** Owner: OpenSC upstream (module/applet behaviour); evidence owner: platform operator. Evidence needed: one OpenSC module + real YubiKey end-to-end run with `pkcs11-spy` showing N×`C_CloseSession` then `C_Finalize` and rc=0; plus OpenSC issue history for `C_Finalize`/`CKR_CRYPTOKI_NOT_INITIALIZED` after PIV login. Report-only evidence (Sonnet's SoftHSM) must not be upgraded.

## Y3 — (8) Can `moduleReferences` refCount exceed 1 in this binary?

- **Sonnet disposition:** *Answered* — one `Configure`, registry keyed by path, spy showed 1× `C_Initialize`/`C_Finalize`; refCount stays 1, so `Close` finalizes.
- **My assessment:** confirmed independently. `crypto11.Configure` is called exactly once (`main.go:277`; no other call site in `main.go`, `main_test.go`). `openModule` registers refCount 1 on first open and never re-registers for this process (`crypto11.go:317-347`). The only other in-tree call is `TestCreateYubikeyVaultClient_InvalidModule` (`main_test.go:374-388`), which fails inside `openModule` before registration (`pkcs11.New` → nil for a nonexistent path → `crypto11.go:333`; or a failed `Initialize` → `Destroy` + return at `:338`). I ran it: PASS.
- **Final disposition: TERMINATE.** Rationale: answered, single call site, no second registration path. The consequential fact (refCount 1 ⇒ a second `Close` is unsafe) is disposed under Y6a.

## Y4 — (9) Which PIV slots does the module enumerate for `CKO_PRIVATE_KEY`?

- **Sonnet disposition:** *External-unknown*; crypto11 enumerates whatever the module returns (`certificates.go:125-166`); remaining OpenSC PIV filtering.
- **My assessment:** source correct — `FindAllPairedCertificates` queries `CKA_CLASS = CKO_PRIVATE_KEY` (`certificates.go:130-140`) and pairs by `CKA_ID`; no slot filtering in crypto11 or in this repo. Which slots materialise as private-key objects is OpenSC's PIV card driver plus operator/token config (9a/9c/9d/9e exposure, PIN-protected vs present certificates). Not derivable from anything in this repo.
- **Final disposition: TRANSFER.** Owner: OpenSC PIV driver (module-side object mapping) and the operator's token config. Evidence needed: OpenSC PIV driver documentation/source for the exported `CKO_PRIVATE_KEY` objects and their `CKA_ID`s, or a `pkcs11-spy` object dump on the real card. Repo consequence is already bounded and needs no task: zero pairs → `"no paired credentials found on YubiKey"` (`main.go:219-221`), multiple → `yubikeyCertCN` required (`main.go:224-239`).

## Y5 — (10) Does the Vault server accept a leaf-only client chain?

- **Sonnet disposition:** *External-unknown*; crypto11 supplies only the leaf (`certificates.go:164`); documented topology trusts one root CA directly (`PKI-SETUP.md:127-129`); remaining: the role/CA config of the target server.
- **My assessment:** the client-side half is **answered and closed**: the presented chain is the leaf alone (`tlsCert.Certificate = append(..., certificate.Raw)`, `certificates.go:164`), delivered by `GetClientCertificate` (`main.go:349-360`); crypto11 exposes no API to attach intermediates, so this client can *never* present a chain longer than one cert. The doc half: the described flow is a single self-signed root signing leaves directly — `certstrap init --common-name "Vault Users CA"` (`PKI-SETUP.md:30`), `certstrap sign alice --CA "Vault Users CA"` (`:95`), `certificate=@out/Vault_Users_CA.crt` (`:129`, sentence at `:136`); no intermediate is described anywhere (grep: none). Leaf-only is therefore sufficient for the documented topology (trust anchor = direct issuer of the leaf). What cannot be established in-repo is the target server's actual role/trust config, or whether an operator introduced an intermediate — in which case the deployment is unsupported by this client, which is a maintainer decision, not a bug.
- **Final disposition: TRANSFER.** Owner: platform operator / Vault-OpenBao role owner (server-side config and CA topology). Evidence needed: the deployed role definition (`vault read auth/cert/certs/<role>`) and/or a recorded live login; if an intermediate exists, a maintainer decision on documenting the constraint (this client presents the leaf only and cannot be changed to do otherwise without replacing crypto11's certificate provider).

## Y6 — (11) Is `Close` reachable twice for one context, and is the success-path close exercised?

Two distinct questions in one Sonnet item; disposed separately.

### Y6a — Is `Close` reachable twice for one context?

- **My assessment:** not reachable. The Configure-failure path returns before the defer exists (`main.go:281-284`); the defer (`main.go:289-293`) fires only on the three later error returns (`:297-309`), which carry non-nil `err`; the success return (`main.go:312`) leaves `err == nil`, so the defer is a no-op and ownership passes to the wrapper; the only production close is `loginAndClose`'s defer (`main.go:508-512`), which cannot have run for a constructor failure because `run` returns the constructor error without closing (`main.go:486-492`). One `Close` per context. (Sonnet's "mutually exclusive by `err`" is correct.)
- **Final disposition: TERMINATE.** Rationale: answered in source; no reachable double-close. Consequence recorded for Y6b: because refCount is 1, a second close is a nil-`Ctx` use / `panic("referenced module not found")` (`crypto11.go:355-370`), i.e. a crash.

### Y6b — Is the success-path close exercised anywhere against a real context?

- **Sonnet disposition:** *Partly*; "remaining: a real-card success run. No repo test covers the success-path close."
- **My assessment:** confirmed. `TestYubikeyVaultClient_CloseNil` (`main_test.go:350-356`) only covers `cryptoCtx == nil`; `TestLoginAndClose_ClosesOnFailure` (`:440`) uses a mock and never opens a context; `TestCreateYubikeyVaultClient_InvalidModule` (`:374-388`) never reaches a real `*crypto11.Context` (PASS observed). So the single-close invariant — described in the source as `CRITICAL` (`main.go:286-288`) and load-bearing (crash on violation) — is enforced only by call structure, with no test. Sonnet's SoftHSM success run is report-only, not repo evidence.
- **Final disposition: TREAT.** Rationale: repo-owned gap; the invariant is fragile in the way that matters (a plausible one-line regression — any second `Close` — becomes a crash or a YubiKey lock), and nothing in the suite would catch it.
- **Suggested future task:** add one skip-gated test in `package main` that builds a real context (SoftHSM token via `softhsm2-util`, keypair + self-signed cert; `t.Skip` when the module/token env is absent so the ubuntu/macos CI matrix needs no new hard dependency), drives `CreateYubikeyVaultClient` success → `loginAndClose`, and asserts a clean single close with no panic. Cheaper alternative the maintainer may prefer: a 2-line idempotency guard in `YubikeyVaultClient.Close` (`c.cryptoCtx = nil` after a successful close) so the invariant survives a second call, plus a unit assertion for it.

---

## Counts

| Disposition | Count | Items |
|---|---|---|
| TREAT | 1 | Y6b |
| TOLERATE | 0 | — |
| TRANSFER | 3 | Y2, Y4, Y5 |
| TERMINATE | 3 | Y1, Y3, Y6a |
| **Total** | **7** | 6 Sonnet items (Y6 split into Y6a/Y6b) |

## Recommended worklist

1. **TREAT — Y6b (only repo-owned work).** Skip-gated SoftHSM test for the success-path close; optional `YubikeyVaultClient.Close` idempotency guard. Small, self-contained, guards a crash-class invariant.
2. **TRANSFER — Y2 + Y4 + Y5, one operator session.** With OpenSC + a real YubiKey and `pkcs11-spy`: (a) C_CloseSession/C_Finalize count and clean exit (Y2); (b) `CKO_PRIVATE_KEY` object + `CKA_ID` dump (Y4); (c) a live cert login against the target role (Y5). Record the role definition and CA topology alongside; if an intermediate is present, escalate as a maintainer decision (client cannot present chains).
3. **No action — Y1, Y3, Y6a.** Answered at source; do not re-open or file as findings.

Skipped/did not check: OpenSC internals, real YubiKey, live Vault/OpenBao — all Y2/Y4/Y5 residuals remain external and untested by me; Sonnet's SoftHSM and `pkcs11-spy` results are report-only and were not re-run. Risk: Y6b's TREAT is only worth doing if the maintainer accepts a skip-gated SoftHSM test (or the 2-line guard); otherwise the single-close invariant remains verified by inspection only, and a future second-`Close` regression fails as a crash rather than a test.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §3c. The real card was exercised (YubiKey 5 NFC, fw 5.1.2, PIV slot 9A, leaf CN `jhow`, OU `vault-admins`, ECC P-384; `ykman piv info` reports 3 PIN tries, and its `Private key type: EMPTY` line is a firmware-metadata limitation, not evidence the key is absent). All temporary binaries, configs and raw traces were deleted; no artifact retained.
- **Y2 (row 7)** — partial. A spy-traced failed-role login on the card showed two `C_Sign`, then three sessions closed, then one `C_Finalize`. The successful login exited 0 but was **not** spy-traced, so success-path close order on hardware is unobserved. SoftHSM now covers the success path structurally (D-3/T-5, `TestCreateYubikeyVaultClient_SoftHSM`), which says nothing about OpenSC. TRANSFER unchanged.
- **Y4 (row 9), S2 (34), S3 (35)** — partial for slot 9A only: app enumeration saw one private key, one public key and one certificate, all `CKA_ID` `01`; an ECC P-384 key signed twice. Other slots, empty-`CKA_ID` objects and other key types were **not** inventoried/observed. TRANSFER unchanged.
- **Y5 (row 10)** — one live login accepted the leaf-only chain, but the role/CA topology was not read; this shows one deployment, not the intended topology. TRANSFER unchanged.
- **Y6b (11b)** — the structural invariant now has a test (SoftHSM, D-3/T-5); the real-card success close is still unobserved. TREAT resolved as merged, not re-opened.
- **Y1, Y3, Y6a** — no hardware observation needed; unchanged.
