# Per-function adversarial disposition review — `selectCertificate` (`main.go:217-241`, helper `certCNs` `main.go:243-254`)

Read: `audit-context/functions/07-selectCertificate.md`, `audit-context/DOSSIER.md` (open-questions group for `selectCertificate`), `audit-context/review/SONNET-INVESTIGATION.md` (§`selectCertificate` items 33-38 and index), `main.go`, `main_test.go`, `README.md`, `PKI-SETUP.md`, and the pinned dependency sources.

## Verification basis

- Resolved versions confirmed with `go list -m`: `github.com/miekg/pkcs11 v1.1.2`, `github.com/eclipse-keypont/crypto11 v1.6.8`. The earlier run's citations resolve against these paths (`~/go/pkg/mod/…`).
- Source claims checked directly: `main.go:217-241`, `main.go:243-254`; crypto11 `keys.go:108-186`, `keys.go:191-236`, `certificates.go:36-96`, `certificates.go:125-166`; miekg/pkcs11 `pkcs11.go:303-322` (C helper), `pkcs11.go:1106-1129` (Go side); cgo `out.go:1754-1759` (`//go:linkname _cgo_runtime_gobytes runtime.gobytes`) and `runtime/string.go:358-361`.
- **Adversarial correction, applies to all rows and to both prior reports:** `errNoCkaId` is **dead** in the pinned crypto11 v1.6.8. Its only return sites (`keys.go:119-124`) are commented out; the surviving check is `if len(id) == 0 && len(label) == 0` at `keys.go:130`. So the `err == errNoCkaId` arm of `certificates.go:147` (and `keys.go:353`, `rsa.go:430`) can never fire. The prior reports list "continues only on `errNoCkaId`/`errNoPublicHalf`" as if both are live; only `errNoPublicHalf` is. This does not change any conclusion below, but it sharpens S1's "related guard".
- Report-only (Sonnet runtime observations I cannot reproduce): the SoftHSM end-to-end run (S2), the TLS-alert string (S6), and the claim that the HTTP-400 fixture "surfaces via `ResponseError`" (the test at `main_test.go:440-470` asserts only `err == nil` fails, never the error type).

---

## A. Questions originating in `selectCertificate` in the dossier / Sonnet run

### S1 (item 33) — Does `GetAttributeValue` return nil or an empty non-nil slice for a zero-length `CKA_ID`?

- **Original question (dossier):** "Does `miekg/pkcs11` v1.1.2 `GetAttributeValue` return nil or an empty non-nil slice for a zero-length `CKA_ID`? That decides whether the certificate lookup errors with 'id, label and serial cannot all be nil' (swallowed at `keys.go:176`) or searches with `CKA_ID ""`."
- **Sonnet's disposition/evidence:** *Answered.* C helper `pkcs11.go:303-322`, Go side `:1106-1129`, cgo `runtime/string.go:358-361`. Present zero-length attribute → non-nil empty slice; nil only when `ulValueLen == -1`. Consequence: empty-but-present `CKA_ID` makes `findRawCertificate` (`certificates.go:53-62`) append `CKA_ID=""` and search; the all-nil error is swallowed at `keys.go:176` only when the attribute is unavailable. Related guard: id and label both empty → error that aborts enumeration (`keys.go:130`). Remaining: module-specific matching of an empty `CKA_ID`.
- **My assessment:** Verified end to end. C helper at `pkcs11.go:303-322` `continue`s on `ulValueLen == -1` and otherwise `calloc`s; Go side `pkcs11.go:1116-1122` sets `Value` only when `ulValueLen != -1` and calls `C.GoBytes`; cgo routes `C.GoBytes` to `runtime.gobytes`, which returns `make([]byte, 0)` for `n == 0` (`runtime/string.go:359-361`). The guard `id != nil` at `certificates.go:59-61` treats a non-nil empty slice as present, so the search uses `CKA_ID=""`. The `keys.go:130` abort is real. **Correction:** the working path for a no-`CKA_ID` key is the `keys.go:130` error (label also absent) or the swallowed all-nil error (label present); the `errNoCkaId` continue-arm is dead code (see Verification basis).
- **Final disposition: TERMINATE.**
- **Rationale:** The question as asked is fully settled by pinned source; the answer (search with `CKA_ID ""`, not an error, when a label is present) is definitive. The residual — how a module matches an empty `CKA_ID` — is unreachable in practice on PIV, whose objects carry non-empty slot IDs, and changes nothing in `selectCertificate` (it only decides which pairs exist upstream). Not a repo-relevant open question.

### S2 (item 34) — Does the OpenSC PIV module always expose a `CKO_PUBLIC_KEY` per slot?

- **Original question (dossier):** "Does the OpenSC PIV module always expose a `CKO_PUBLIC_KEY` object per slot? That decides whether `pub` comes from the certificate and whether `errNoPublicHalf` can silently drop a slot."
- **Sonnet's disposition/evidence:** *External-unknown.* Fallback at `keys.go:176-184` uses the certificate's public key when no public-key object exists; a SoftHSM token with only a private key and a certificate worked end to end. Remaining: OpenSC PIV object mapping.
- **My assessment:** The code claim is verified: `keys.go:177-178` sets `pub = certificate.PublicKey` when `certificate != nil && pubHandle == nil`; the only "silent drop" is `errNoPublicHalf` at `keys.go:182-183`. The SoftHSM end-to-end result is **report-only**. The question itself is a fact about OpenSC's PIV object filter, not resolvable from this repo; nothing pinned constrains it (Sonnet Y4, item 9, is the same external gap).
- **Final disposition: TRANSFER.**
- **Rationale:** The answer belongs to OpenSC's PIV object mapping. Repo impact is bounded (the certificate fallback covers a missing public-key object; only a slot exposing neither public-key object nor certificate is skipped), but the evidence is external.
- **Owner / evidence needed:** OpenSC maintainers — OpenSC PKCS#11 PIV source, or a `pkcs11-tool --list-objects` dump from the target card.

### S3 (item 35) — Can the OpenSC PIV mapping report a key type outside DSA/RSA/ECDSA?

- **Original question (dossier):** "Can the OpenSC PIV mapping report a key type outside `CKK_DSA`/`CKK_RSA`/`CKK_ECDSA`? Only those three are handled and the error aborts the whole enumeration before `selectCertificate` runs."
- **Sonnet's disposition/evidence:** *Partly.* `makeKeyPair` handles only DSA/RSA/ECDSA (`keys.go:197-236`); anything else returns `unsupported key type: %X` (`:235`); `FindAllPairedCertificates` continues only on `errNoCkaId`/`errNoPublicHalf` (`certificates.go:147`), so that error aborts enumeration before `selectCertificate`. Remaining: OpenSC key-type mapping.
- **My assessment:** Verified: `keys.go:192` dispatches on `keyType` with cases at `:194`, `:207`, `:222` and `default:` at `:234-235`. `certificates.go:145-153` continues only on the two sentinels and otherwise `return err`. **Correction:** one sentinel (`errNoCkaId`) is dead, so the effective filter is `errNoPublicHalf` alone — the abort conclusion is unchanged. Repo impact: an unexpected key type fails the whole `-yubi` mode with `failed to find paired certificates: unsupported key type: …` rather than skipping that key. Whether OpenSC can emit such a type is external.
- **Final disposition: TRANSFER.**
- **Rationale:** Whether OpenSC's PIV applet can report a fourth key type is OpenSC evidence; the repo cannot pre-empt it (the abort is inside `FindAllPairedCertificates`, which `CreateYubikeyVaultClient` only wraps at `main.go:297-299`). The repo-side facts are settled; the external fact is not.
- **Owner / evidence needed:** OpenSC maintainers — OpenSC PIV key-type mapping source, or a card/module observation.

### S4 (item 36) — Can a real YubiKey surface two pairs with the same `Subject.CommonName`?

- **Original question (dossier):** "Can a real YubiKey configuration surface two pairs with the same `Subject.CommonName`? The code path and a unit test exist; no runtime observation was made."
- **Sonnet's disposition/evidence:** *Partly.* The code path (`main.go:224-239`) and the "multiple pairs, duplicate CN" unit test give `cannot disambiguate`. Remaining: a real card was not observed.
- **My assessment:** Verified: the `default` arm `main.go:238-239` emits `multiple credentials with CN %q on card; cannot disambiguate`; the test case `main_test.go:404` (`pairWithCN("dup")` twice) asserts the substring `cannot disambiguate` at `main_test.go:414-417`. The repo behaviour is therefore defined and tested. Whether real hardware can produce it is unobserved, but **the answer changes no repo behaviour** — there is no alternate discriminator the tool could fall back to, and the operator-visible outcome is a deliberate, named error.
- **Final disposition: TOLERATE.**
- **Rationale:** Known residual accepted. The `-yubi` selection contract requires a unique CN per pair; a duplicate is rejected with a clear error. No current task follows from the unknown hardware fact.

### S5 (item 37) — Is authorization by CN or by OU?

- **Original question (dossier):** "Is authorization by CN or by OU? PKI-SETUP.md:137 states `allowed_organizational_units` while PKI-SETUP.md:138 states the CN appears as `common_name` in token metadata and the audit log — outside this function."
- **Sonnet's disposition/evidence:** *Partly.* CN is used only to pick a local credential (`main.go:229`); nothing in `main.go` authorizes. `PKI-SETUP.md:130,137` configures `allowed_organizational_units`; `:138-139` documents CN as `common_name` metadata and the `allowed_common_names` alternative. Remaining: server-side role semantics.
- **My assessment:** Verified. `main.go` contains no OU, policy, or authorization logic — `Subject.CommonName` appears only at `main.go:229` (selection) and `main.go:251` (`certCNs` rendering); `grep -n "organizational|policy|authoriz|allowed"` over `main.go` is empty. `PKI-SETUP.md:130` (`allowed_organizational_units=example-team`), `:137` (OU admits any matching certificate "whatever its CN"), `:138` (CN as `common_name` metadata), `:139` (`allowed_common_names`) all confirmed.
- **Final disposition: TERMINATE.**
- **Rationale:** Answered, and the repo-side premise is decisive: authorization is the Vault role's (OU-based, per the repo's own recipe); `selectCertificate` performs local credential selection only and never authorizes. Nothing open remains that the repo owns. (The deployment's actual role config is external but already documented, not an open question.)

### S6 (item 38) — Can Vault's cert-login response path distinguish "wrong certificate presented" from other handshake failures?

- **Original question (dossier):** "Can Vault's cert-login response path distinguish 'wrong certificate presented' from other TLS/handshake failures? Only the selection side was inspected."
- **Sonnet's disposition/evidence:** *External-unknown.* Client-side: a TLS alert surfaces as `remote error: tls: unknown certificate authority`; a fixture HTTP 400 JSON error surfaces via `ResponseError` (`TestLoginAndClose_ClosesOnFailure`). Remaining: actual Vault behaviour.
- **My assessment:** The fixture at `main_test.go:440-470` is a **plain `httptest.NewServer`** (HTTP, not TLS) returning 400 JSON, and the test asserts only that an error is returned and the client is closed — it does **not** assert `ResponseError`. So the "surfaces via `ResponseError`" attribution is **report-only**, and this fixture exercises an application rejection, not a handshake failure. The TLS-alert string is also **report-only**. The question is server-side.
- **Final disposition: TRANSFER.**
- **Rationale:** Distinguishing a rejected client certificate from other handshake failures is a property of the Vault/OpenBao listener and cert-auth response path; the client cannot manufacture the distinction. The repo does not depend on it (diagnostics only), but the external evidence is unresolved and should be preserved.
- **Owner / evidence needed:** Vault/OpenBao maintainers — cert-auth source or a recorded live login response (403/400 body) for a wrong-certificate handshake.

---

## B. Questions raised only in the per-function analysis §6 (not carried as dossier items)

### P1 (§6.1) — Reachability of the nil-`Leaf` defences

- **Original question:** Are `p.Leaf != nil` (`main.go:229`) and the `"<no leaf>"` branch (`main.go:247-249`) reachable, given the producer skips nil-certificate pairs (`certificates.go:155-157`) and sets `Leaf` (`certificates.go:159-160`)?
- **Sonnet coverage:** none (not a dossier item).
- **My assessment:** Verified: `certificates.go:155-157` `continue`s on `certificate == nil`, and `Leaf` is set at `certificates.go:160`; every `pairWithCN` test case (`main_test.go:389-391`, `:401-408`) populates `Leaf`. So both guards are dead relative to the shipped producer and untested. They are harmless defensive code.
- **Final disposition: TERMINATE.**
- **Rationale:** The reachability question is answered (unreachable from `FindAllPairedCertificates` in the pinned version); the guards stay as cheap defence against a different producer. Not a meaningful open question and no repo action.

### P2 (§6.2) — Can two private keys share one `CKA_ID`?

- **Original question:** "Whether two private keys can share one `CKA_ID` on the target tokens (OpenSC/PIV), which is what would generate duplicate-`Leaf` pairs handled at `main.go:238-239`."
- **Sonnet coverage:** folded into S4's mechanism.
- **My assessment:** The generation mechanism is verified in source: two private handles with one `CKA_ID` both call `findCertificate(session, id, nil, nil)` (`keys.go:176`) → `findRawCertificate` takes `handles[0]` (`certificates.go:78-82`), so both pairs carry the same DER and hence the same CN, hitting `main.go:238-239`. Whether a token can hold two private objects with one `CKA_ID` is the same external hardware fact as S4.
- **Final disposition: TERMINATE (duplicate of S4).**
- **Rationale:** Same underlying unresolved fact as S4, whose repo response is already disposed as TOLERATE. Recording it separately would double-count one question.

### P3 (§6.3) — Is a single-element chain sufficient for the server's cert-auth path?

- **Original question:** "Whether the single-element chain (`certificates.go:164`) is sufficient for the server's cert-auth path is outside this function."
- **Sonnet coverage:** raised and disposed under `CreateYubikeyVaultClient` item 10 (Y5), external-unknown.
- **My assessment:** Verified that `main.go` never touches `Certificate`; the chain is built once at `certificates.go:164` and consumed by `clientTLSConfig`'s `GetClientCertificate` (`main.go:351-352`). The question is server-side and already carried by Y5.
- **Final disposition: TERMINATE (duplicate).**
- **Rationale:** Duplicate of Y5; no separate disposition needed for `selectCertificate`.

### P4 (§6.4) — "Multi-cert `Leaf` vs `CKA_ID` semantics" / label-vs-CN divergence

- **Original question:** "The doc comment (`main.go:216`) asserts leaf-based selection is preferred over PKCS#11 labels, but the file records no case where a label and a CN disagree."
- **Sonnet coverage:** none.
- **My assessment:** Invalid premise for this function. Verified: `selectCertificate` reads only `p.Leaf.Subject.CommonName` (`main.go:229`); no code in `main.go` reads `CKA_LABEL`/labels (`grep` for label references returns only the doc comment at `main.go:216`). A label/CN divergence therefore cannot affect selection.
- **Final disposition: TERMINATE (invalid premise).**
- **Rationale:** The function is CN-only by construction; there is no label path to test or reconcile.

### P5 (§6.5) — Empty-`Subject.CommonName` addressability

- **Original question:** "`wantCN == ""` is an overloaded sentinel: a card certificate whose `Subject.CommonName` is literally `""` cannot be selected by name."
- **Sonnet coverage:** none directly.
- **My assessment:** Verified from source: `main.go:221` routes an empty `wantCN` to the single-pair default (`main.go:222-223`) or the "set yubikeyCertCN" error (`main.go:225`); the CN comparison at `main.go:229` is therefore unreachable with an empty `wantCN`, so an empty-CN pair is selectable only as the lone pair. An empty subject CN is pathological for PIV/X.509 (the identity is required to carry a CN; PKI-SETUP issues `CN=alice`).
- **Final disposition: TOLERATE.**
- **Rationale:** Known residual accepted: the sentinel is only ambiguous for a certificate with no CN, which the documented workflow never produces. Removing the ambiguity would need a tri-state config (present/absent/empty) — not worth it; no current task.

### P6 (§6.6) — Is `yubikeyCertCN` documented as needed for multi-credential cards?

- **Original question:** "`requireForMode` (`main.go:149-151`) omits it, and `README.md` was not read for this analysis; the only in-code guidance is the error text at `main.go:225`."
- **Sonnet coverage:** none.
- **My assessment:** Answered — `README.md` **does** document it: the config example marks it optional and explains "only needed if the YubiKey holds more than one certificate; set it to the Subject CN of the one to use" (`README.md:72-75`), consistent with the runtime error at `main.go:225`. So the per-function analysis's open question (raised only because `README.md` was not read) is closed.
- **Final disposition: TERMINATE.**
- **Rationale:** Documented in the operator README; config validation correctly leaves it optional (`main.go:149-151`), since it is required only when the card holds more than one pair.

---

## Counts

| Disposition | Count | Items |
|---|---|---|
| TREAT | 0 | — |
| TOLERATE | 2 | S4, P5 |
| TRANSFER | 3 | S2, S3, S6 |
| TERMINATE | 7 | S1, S5, P1, P2 (dup), P3 (dup), P4 (invalid premise), P6 |
| **Total** | **12** | 6 dossier items (S1-S6) + 6 per-function §6 items (P1-P6) |

## Recommended worklist

1. **No TREAT tasks** — nothing in `selectCertificate`/`certCNs` yields a repo-owned follow-up. Do not open implementation work from this review.
2. **Carry three TRANSFERs to the external-owner register**, each with its named evidence source:
   - OpenSC/PIV object mapping for a per-slot `CKO_PUBLIC_KEY` (S2).
   - OpenSC/PIV key-type capability beyond DSA/RSA/ECDSA (S3).
   - Vault/OpenBao cert-auth rejection vs handshake-failure distinction (S6).
3. **Record the two TOLERATEs as accepted residual risk** (duplicate-CN pairs rejected by design; empty-CN certificates unaddressable by name), with no task.
4. **Keep the corpus consistent:** if the dossier is regenerated, mark P2 as a duplicate of S4, and drop P3 (already Y5). Add the verified correction that `errNoCkaId` is dead in crypto11 v1.6.8 — both prior reports state it as a live continue-condition.

Skipped: no live card, OpenSC, or Vault run; S2's SoftHSM, S6's TLS-alert string, and S6's `ResponseError` attribution are labelled report-only and were not independently reproduced. Risk: the three TRANSFERs remain unresolved hardware/server facts by design — this review does not test them.
