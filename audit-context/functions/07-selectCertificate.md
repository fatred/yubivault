# Structural analysis — `selectCertificate` (`main.go:213-241`) and `certCNs` (`main.go:243-254`)

Module: `package main`, single-file program (`main.go`), plus `main_test.go` (584 lines) and prior audit notes in `audit-context/`. crypto11 dependency pinned at `go.mod:6` → `github.com/eclipse-keypont/crypto11 v1.6.8` (module cache path `$GOMODCACHE/github.com/eclipse-keypont/crypto11@v1.6.8/`).

---

## 1. Purpose

Declared intent (doc comment `main.go:213-216`):

- `main.go:213-214`: with no `wantCN` and exactly one pair, that pair is used.
- `main.go:214-215`: otherwise the pair whose certificate `Subject.CommonName` equals `wantCN` is used; ambiguity or no match is an error "that names the fix".
- `main.go:216`: selection is on the parsed x509 cert ("reliable"), "never on PKCS#11 labels".

Signature `main.go:217`: `func selectCertificate(pairs []tls.Certificate, wantCN string) (tls.Certificate, error)` — unexported, package-level, no receiver, no `context`, no I/O.

Role in the call graph: reached only from `CreateYubikeyVaultClient` (`main.go:301`), which is reached only from `run` in `-yubi` mode (`main.go:484`). Local mode never calls it: `CreateLocalVaultClient` builds its credential via `tls.X509KeyPair` (`main.go:165`) and calls `newVaultClient` directly (`main.go:169`).

`certCNs` (`main.go:244`) has exactly one caller: `selectCertificate` at `main.go:225` and `main.go:237`. Its only purpose is error-message rendering (doc comment `main.go:243`).

---

## 2. Inputs & Assumptions

### 2.1 `pairs []tls.Certificate` — provenance and guarantees relied on

Produced by `(*crypto11.Context).FindAllPairedCertificates()` at `main.go:297` (error wrapped at `main.go:299`), on the context built by `crypto11.Configure` (`main.go:277-281`, `crypto11.go:392`).

Construction, in order:

| Step | Location | Structural fact |
|---|---|---|
| Enumerate `CKO_PRIVATE_KEY` objects | `certificates.go:132-143` | Template is class-only; all private keys on the token/session, paged by `maxHandlePerFind = 20` (`keys.go:33`, `keys.go:41-64`) |
| Pair each private key | `certificates.go:145` → `keys.go:191-237` | Returns `(Signer, *x509.Certificate, error)` |
| Read the private key's `CKA_ID`, `CKA_LABEL`, `CKA_KEY_TYPE` | `keys.go:111-126` | `id` is the PIV-slot identifier used for both halves |
| Locate public half | `keys.go:130-168` | By `CKA_ID` first, then `CKA_ID` alone (fallback retry) |
| Locate certificate | `keys.go:176` | `findCertificate(session, id, nil, nil)` — **by `CKA_ID` only**, certificate error deliberately discarded (`_` at `keys.go:176`) |
| Drop unpaired/unparsable private keys | `certificates.go:147-149` (`errNoCkaId`, `errNoPublicHalf` → `continue`), `certificates.go:155-157` (`certificate == nil` → `continue`) | Non-pairing is not an error |
| Build the pair | `certificates.go:159-164` | `Leaf: certificate` (159-160), `PrivateKey: privateKey` (161), `Certificate: append(…, certificate.Raw)` (164) |
| Closed-context guard | `certificates.go:126-128` → `errClosed` (`crypto11.go:122`) | Returns `nil, errClosed` before enumeration |

Consequences the function takes as given:

1. **`Leaf` is always non-nil on the shipped path** — `certificates.go:155-157` skips pairs whose certificate is nil, so the only pairs that reach the slice have a parsed `*x509.Certificate` in `Leaf` (`certificates.go:160`). The `p.Leaf != nil` guard at `main.go:229` and the `"<no leaf>"` branch at `main.go:247-249` are therefore defensive relative to this producer.
2. **Exactly one element in `Certificate`** — `certificates.go:164` appends only `certificate.Raw`; `Leaf` is the parse of that same DER (`certificates.go:36-43`, `keys.go:176`), and `x509.ParseCertificate` retains the input slice as `Raw` (`parser.go:974` `cert.Raw = input` in the module's Go toolchain GOROOT). So `pair.Certificate[0]` and `pair.Leaf.Raw` alias the same bytes [INFERENCE on the aliasing identity; both citations verified].
3. **Pairing is `CKA_ID`-based, with no key/cert cryptographic match** — implied by the two calls above (`keys.go:176`, `certificates.go:136-149`). The caller's comment states this explicitly: `main.go:295-296`.
4. **Order is token-enumeration order**, not sorted — `findKeysWithAttributes` accumulates handles in `FindObjects` order (`keys.go:41-64`). Selection logic relies on position only in the `len(pairs) == 1` case (`main.go:222-223`), where order is immaterial, and in the unique-match case (`main.go:233-235`), where the match set has one element; the loop therefore never depends on enumeration order.
5. **Duplicate `Leaf` contents are representable** — two private-key objects sharing a `CKA_ID` each yield a pair built from the same `findCertificate(session, id, nil, nil)` result (`keys.go:176`), which returns `handles[0]` (`certificates.go:78-83` within `findRawCertificate`). No de-duplication occurs in the function or in crypto11.

Caller-side ownership of the slice: it is a local in `CreateYubikeyVaultClient` (`main.go:297`), used once at `main.go:301`, then discarded; the crypto11 context outlives the call (`main.go:312`) but the slice is not retained by it.

### 2.2 `wantCN string` — config source at the caller

- Argument: `appConfig.YubikeyCertCN` (`main.go:301`).
- Field: `AppConfig.YubikeyCertCN string \`yaml:"yubikeyCertCN"\`` at `main.go:39` (struct `main.go:30-40`).
- Loaded by `LoadConfig` (`main.go:102-139`) from `~/.yubivault/config.yml` (`main.go:100` `configDirName`, `main.go:103` `filepath.Join(homeDir, configDirName, "config.yml")`), via `yaml.NewDecoder` with `KnownFields(true)` (`main.go:109-113`) — an unknown key (e.g. a retired `yubikeyPivLabel`) is an error rather than silently ignored (`main.go:110-112`).
- Validation: `(*AppConfig).requireForMode(local=false)` checks only `OpenScPath` and `YubikeyPivSerial` (`main.go:149-151`). `YubikeyCertCN` is **not** validated anywhere before reaching this function, so it may be empty, or may be a name not present on the card.
- Reached via `run`: `LoadConfig` at `main.go:452`, `requireForMode` at `main.go:456`, `CreateYubikeyVaultClient` at `main.go:484`.

Assumptions this encodes:

1. **Empty string is the "unspecified" sentinel** (`main.go:221`). A card certificate whose `Subject.CommonName` is literally `""` is not addressable by name: matching requires `wantCN != ""` to enter the loop (`main.go:221`, `main.go:229`), and an empty-CN cert is only obtainable as the single-pair default (`main.go:222-223`). With ≥2 pairs and an empty `wantCN`, such a cert can never be selected.
2. **Byte-exact, case-sensitive comparison** — Go `==` on `string` at `main.go:229`; no `strings.TrimSpace` (contrast the PIN path, `main.go:267`), no case folding, no normalization (IDNA/Unicode), no whitespace trimming of the config value beyond what YAML decoding does.
3. **CommonName is the sole discriminator** — no SAN (`DNSNames`, `EmailAddresses`), no issuer, no serial, no `CKA_ID`, no PKCS#11 label, no key usage. This matches the stated intent at `main.go:216`.
4. **Uniqueness of CN is required for a successful named selection** — duplicates are an error (`main.go:238-239`), not a tie-break.

---

## 3. Outputs & Effects

### 3.1 Return-value outcomes (all branches)

| # | Condition | Location | Return |
|---|---|---|---|
| B1 | `len(pairs) == 0` | `main.go:218` | `tls.Certificate{}, error` "no paired credentials found on YubiKey" (`main.go:219`) |
| B2a | `wantCN == "" && len(pairs) == 1` | `main.go:221-222` | `pairs[0], nil` (`main.go:223`) |
| B2b | `wantCN == "" && len(pairs) >= 2` | `main.go:221-222` false-false | `tls.Certificate{}, error` "multiple credentials on card; set yubikeyCertCN to one of: %s" + `certCNs(pairs)` (`main.go:225`) |
| B3 | `wantCN != ""`, loop filters | `main.go:227-232` | builds local `matches`; elements appended are value copies (`main.go:230`) |
| B4a | `len(matches) == 1` | `main.go:234-235` | `matches[0], nil` (`main.go:235`) |
| B4b | `len(matches) == 0` | `main.go:236-237` | zero `tls.Certificate` + error `no credential with CN %q; available: %s` (`main.go:237`) |
| B4c | `len(matches) >= 2` | `main.go:238-239` | zero `tls.Certificate` + error `multiple credentials with CN %q on card; cannot disambiguate` (`main.go:239`) |

Totality: exactly two success branches (B2a, B4a) and four error branches (B1, B2b, B4b, B4c); `switch` at `main.go:233` is exhaustive over `len(matches)` because of `default` (`main.go:238`). Function is total and panics in no case (no index beyond `pairs[0]` guarded by `len == 1` at `main.go:222`; `matches[0]` guarded by `case 1` at `main.go:234`).

`certCNs` branches:

| # | Condition | Location | Output |
|---|---|---|---|
| C1 | `p.Leaf == nil` | `main.go:247` | literal `"<no leaf>"` appended (`main.go:248`), loop continues (`main.go:249`) |
| C2 | `p.Leaf != nil` | `main.go:247` false | `fmt.Sprintf("%q", p.Leaf.Subject.CommonName)` appended (`main.go:251`) |
| C3 | empty `pairs` | `main.go:245`, `main.go:253` | `strings.Join` of empty slice → `""` (unreachable: callers are `main.go:225` with ≥2 pairs and `main.go:237` with ≥1 pair) |

Error strings are built fresh by `fmt.Errorf` (`main.go:219`, `225`, `237`, `239`): no aliasing to card data, no retained references. `wantCN` is rendered quoted (`%q`, `main.go:237`, `main.go:239`); card CNs are rendered quoted by `certCNs` (`main.go:251`).

### 3.2 Effects

- **No side effects**: no writes, no logging, no mutation of `pairs` (iteration at `main.go:228` binds a copy; append target is the local `matches` declared at `main.go:227`), no global state, no allocation except `matches` (`main.go:227`, `main.go:230`), `names` (`main.go:245`) and the error values.
- **Error propagation**: `CreateYubikeyVaultClient` returns the error **unwrapped and without added text** (`main.go:302-304`), so the messages above are what the user sees; `run` may substitute a signal cause if one raced the failure (`main.go:485-490`).
- **Zero-value safety on error paths**: every error branch returns `tls.Certificate{}` (`main.go:219`, `225`, `237`, `239`), and no caller consumes the value together with a non-nil error — `CreateYubikeyVaultClient` returns at `main.go:303` before `newVaultClient` (`main.go:306`). In particular `clientTLSConfig` (`main.go:349`) is never handed a zero/empty certificate from this path.

### 3.3 Data ownership

| Data | Owner / lifetime | Evidence |
|---|---|---|
| `pairs` slice + elements | Caller (`main.go:297`); function borrows read-only; not retained or mutated | `main.go:228` (value copy per iteration), `main.go:227`/`230` (separate accumulator) |
| Returned `tls.Certificate` | Shallow **value** copy of an element — `pairs[0]` (`main.go:223`) or `matches[0]` (`main.go:235`), where `matches[0]` is itself a copy of the first matching element (`main.go:230`) | `main.go:223`, `230`, `235` |
| `Leaf *x509.Certificate` | **Shared pointer**, not copied; also shared with crypto11's original slice element | `certificates.go:160`; returned value copies only the pointer |
| `PrivateKey` interface value | **Shared** underlying `*pkcs11PrivateKey`, which holds `context: c` → the crypto11 `*Context` | `certificates.go:161`; `keys.go:169-174` |
| `Certificate[0]` DER bytes | Shared backing array: `certificate.Raw` appended at `certificates.go:164`; `Leaf.Raw` is the same input slice (`parser.go:974`) | `certificates.go:164`, `parser.go:974` |
| `matches` | Function-local, discarded on return | `main.go:227`, `main.go:235` |
| Error strings | Fresh allocations; contain only `wantCN` (`%q`) and card CNs (quoted) | `main.go:225`, `237`, `239`, `251` |

Lifetime chain of the returned value: `selectCertificate` → `tlsCert` local (`main.go:301`) → by-value parameter `cert` of `newVaultClient` (`main.go:306` → `main.go:326`) → by-value parameter `cert` of `clientTLSConfig` (`main.go:329` → `main.go:349`) → `&cert` captured by the `GetClientCertificate` closure (`main.go:351-352`) stored in the returned `*tls.Config` (`main.go:350-354`) → `newHTTPClient`'s `Transport.TLSClientConfig` (`main.go:363-366`) → `http.Client` → `vault.Client` (`main.go:327-330`) → `YubikeyVaultClient.VaultClient` (`main.go:312`). No clone/validation step exists between selection and use. The pair is thus kept alive for the process lifetime of the client, and the PKCS#11 signer inside it remains valid only while the crypto11 context lives: context closed on error path via the deferred close (`main.go:289-293`), on success via `YubikeyVaultClient.Close` (`main.go:72-77`) invoked from `loginAndClose`'s defer (`main.go:507-514`).

---

## 4. Block-by-Block

### `selectCertificate` (`main.go:217-241`)

- **`main.go:218-220`** — emptiness gate. `len(pairs) == 0` covers both `nil` and empty-non-nil slices (single built-in `len`). Returns before `certCNs`, so no message rendering for this case; the error text is static (`main.go:219`).
- **`main.go:221`** — `if wantCN == ""`: splits the "unspecified" mode from the "by name" mode. Everything below `main.go:226` assumes a non-empty `wantCN`.
  - **`main.go:222-224`** — single-pair default: `len(pairs) == 1` → return the element by position (`pairs[0]`, `main.go:223`). No CN check at all: a lone pair with a mismatched or empty CN is returned successfully.
  - **`main.go:225`** — ≥2 pairs, no name: error listing all CNs via `certCNs(pairs)`; message names the config key (`yubikeyCertCN`) and the fix. Returns `tls.Certificate{}`.
  - **`main.go:226`** — closes the `wantCN == ""` block; flow continues to the filter.
- **`main.go:227-232`** — filter loop.
  - `main.go:227`: `var matches []tls.Certificate` — nil slice; capacity grows on append.
  - `main.go:228`: `for _, p := range pairs` — `p` is a copy per iteration; `matches` elements are copies of `p` (shallow).
  - `main.go:229`: guard is short-circuit `p.Leaf != nil && p.Leaf.Subject.CommonName == wantCN`. A pair with nil `Leaf` is silently non-matching (not an error, and not surfaced here — only in `certCNs` output when an error message is built).
  - `main.go:230`: append of the matching pair.
- **`main.go:233-240`** — exhaustive switch on `len(matches)`:
  - `main.go:234-235`: `case 1` → return the sole match, `nil` error.
  - `main.go:236-237`: `case 0` → "no credential with CN %q" plus the full available list from `certCNs(pairs)` (the whole card, not just the CN-bearing entries).
  - `main.go:238-239`: `default` (>1) → "cannot disambiguate"; note the message does not list the duplicated CN's owners or any other discriminator.
- **`main.go:241`** — function end.

### `certCNs` (`main.go:244-254`)

- **`main.go:245`** — `names := make([]string, 0, len(pairs))`: pre-sized to the input length; the length of the rendered string is not bounded by anything else (each element contributes its CN length + 2 quote bytes, plus ", " separators at `main.go:253`).
- **`main.go:246-252`** — one pass, two branches: nil `Leaf` → literal `"<no leaf>"` (`main.go:247-249`); otherwise `%q` of `Leaf.Subject.CommonName` (`main.go:251`). No sorting, no de-duplication: duplicate CNs appear twice.
- **`main.go:253`** — `strings.Join(names, ", ")`, single separator style; returns `""` for an empty input (`main.go:245`, unreachable from the two call sites at `main.go:225`, `237`).

---

## 5. Cross-Function Dependencies

| Dependency | Direction | Location | Structural coupling |
|---|---|---|---|
| `CreateYubikeyVaultClient` | only caller | `main.go:273-313`, call at `main.go:301` | Supplies both arguments; receives `(pairs, wantCN)` from crypto11 and config; returns error verbatim (`main.go:302-304`) |
| `crypto11.Configure` | caller's prior step | `main.go:277-281`; `crypto11.go:392` | Determines which module (`OpenScPath`, `main.go:278`), token (`YubikeyPivSerial`, `main.go:279`), and session login (`tokenPin`, `main.go:280`) the pairs come from; failure aborts before selection (`main.go:282-284`) |
| `(*crypto11.Context).FindAllPairedCertificates` | producer of `pairs` | `main.go:297`; `certificates.go:125-170` | Fixes element shape: `Leaf` non-nil (`certificates.go:160`), `PrivateKey` set (`main.go:161`), `Certificate` = one DER (`certificates.go:164`) |
| `findCertificate` / `findRawCertificate` | transitive producer | `certificates.go:36-56`, `certificates.go:57-96`; invoked at `keys.go:176` | CKA_ID-only lookup; first `FindObjects` handle wins (`certificates.go:78-83`) |
| `getKeyPair` / `makeKeyPair` | transitive producer | `keys.go:110-184`, `keys.go:191-237` | Swallows certificate lookup errors (`keys.go:176` `_`), so a missing/unparsable cert yields no pair rather than an error |
| `withSession` | transitive | `sessions.go:46`; `certificates.go:130` | Session pooling/close semantics determine when `errClosed` (`certificates.go:126-128`) can occur |
| `certCNs` | only callee | `main.go:244-254`; calls at `main.go:225`, `main.go:237` | Owns all message rendering; the sole reason card CNs are read twice (also inside the filter at `main.go:229`) |
| `AppConfig` / `LoadConfig` / `requireForMode` | config source | `main.go:30-40`, `main.go:102-139`, `main.go:142-153` | `YubikeyCertCN` (`main.go:39`), file `~/.yubivault/config.yml` (`main.go:100`, `103`), `KnownFields(true)` (`main.go:112`); not required by `main.go:149-151` |
| `run` | top-level driver | `main.go:432`; `LoadConfig` `452`, `requireForMode` `456`, `CreateYubikeyVaultClient` `484` | Chooses `-yubi` mode; error-cause precedence at `main.go:485-490` |
| `newVaultClient` → `clientTLSConfig` → `newHTTPClient` | consumer of the returned value | `main.go:306`, `326`, `349-355`, `363-373` | Value-passed three times, then address-taken into the closure at `main.go:352`; `Certificates` field of `tls.Config` is not used (only `GetClientCertificate`, `main.go:351-352`) |
| `YubikeyVaultClient.Close` / `loginAndClose` | lifetime end of the pair's signer | `main.go:72-77`, `main.go:505-514` | Closes the crypto11 context that owns `PrivateKey` (`keys.go:169-174`) |
| `TestSelectCertificate` | test harness | `main_test.go:393-427`; helper `pairWithCN` `main_test.go:389-391`; call at `main_test.go:413` | Constructs `tls.Certificate` values with only `Leaf` populated (no `Certificate`/`PrivateKey`), so it exercises branches B2a/B2b/B4a/B4b/B4c plus B1 (`main_test.go:401`, `402-408`), asserting error substrings (`main_test.go:415`), errors-free results (`main_test.go:421`), and returned CN (`main_test.go:424`) |
| Local mode (`CreateLocalVaultClient`) | non-consumer | `main.go:155-172` | Confirms `selectCertificate` is on the YubiKey path only |

Note on the earlier audit notes: `audit-context/DOSSIER.md:247` records a citation drift between `crypto11 keys.go:176` and `keys.go:173`. The module currently resolved for `go.mod:6` places `certificate, _ = findCertificate(session, id, nil, nil)` at `keys.go:176`, matching the `176` citation.

---

## 6. Open Questions

1. **Reachability of the nil-`Leaf` defences.** `main.go:229` and `main.go:247-249` cannot trigger for pairs from `certificates.go:125-170` (Leaf set at `certificates.go:160`, nil-cert pairs skipped at `certificates.go:155-157`), and no test case supplies a nil-`Leaf` pair (`main_test.go:401-408` all use `pairWithCN`, `main_test.go:389-391`). Whether these guards exist for an alternate producer (e.g. a different crypto11 release, or a hand-built pair) is not evident from the call sites. [INFERENCE]
2. **Whether two private keys can share one `CKA_ID` on the target tokens** (OpenSC/PIV), which is what would generate duplicate-`Leaf` pairs handled at `main.go:238-239`. Not verified against hardware; nothing in the repo constrains this.
3. **Chain content implications.** Selection reads only `Leaf` (`main.go:229`), while the credential presented to TLS carries `Certificate[0]` from `certificates.go:164` (a single DER). Whether a single-element chain is sufficient for the server's cert-auth path is outside this function and not visible from these call sites.
4. **Multi-cert `Leaf` vs `CKA_ID` semantics** — the doc comment (`main.go:216`) asserts leaf-based selection is preferred over PKCS#11 labels, but the file records no case where a label and a CN disagree, so the practical distinction is untested.
5. **Empty-CN addressability.** Assumption in §2.2(1) follows from `main.go:221` + `main.go:229`; whether any real card certificate has an empty `Subject.CommonName` (making the `wantCN == ""` sentinel overloaded) is unknown.
6. **Whether `YubikeyCertCN` is documented anywhere as required for multi-credential cards** — `requireForMode` (`main.go:149-151`) omits it, and `README.md` was not read for this analysis; the only in-code guidance is the error text at `main.go:225`.

Skipped: `README.md`/`PKI-SETUP.md`, the other `audit-context/functions/*.md` notes, and any live YubiKey/OpenSC run (analysis is source-only, no hardware verification). Risk: duplicates-vs-`CKA_ID` and the label-vs-CN divergence in §6 come from crypto11 source reasoning, not from observing a real card.
