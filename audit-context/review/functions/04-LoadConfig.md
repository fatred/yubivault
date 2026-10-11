# LoadConfig (`main.go:102-137`) — adversarial disposition review

**Scope.** Four questions originate in `LoadConfig` per the Sonnet index (`audit-context/review/SONNET-INVESTIGATION.md:467`: `LoadConfig | L1 (19), L2 (20), L3 (21), L4 (22)`), matching the dossier's four bullets at `audit-context/DOSSIER.md:144-147`. No merged entry lists `LoadConfig` as a co-origin; L1-L4 are each single-origin. Nothing in this function depends on live hardware, a live Vault, OpenSC or a platform operator — all four items are local (file + pinned parser), so no `TRANSFER` is warranted.

**Independent verification performed (not report-only).** I re-derived the behaviour rather than trusting either prior report:
- Replicated `LoadConfig` **verbatim** (`main.go:102-137`) in a throwaway `/tmp` module with `go.yaml.in/yaml/v3 v3.0.5` (the version pinned at `go.mod:9`), offline (`GOPROXY=off`). Scratch dir deleted; no repo file touched (`git status`: only the pre-existing untracked `audit-context/review/`).
- Ran the repo's own suite: `go test -run TestLoadConfig -v` → 5/5 pass, including `empty second document` and `unknown key in second document` (`main_test.go:179-199`).
- Re-derivation caveat: `LoadConfig` is in `package main` and cannot be imported, so the probe copies the body exactly; the behaviour under test is entirely stdlib + the pinned parser.

Both prior reports' material claims for L1-L4 reproduced. Sonnet's *unverified* claim ("a real concurrent writer and reader race was not exercised") is now closed by deterministic interleaving tests, not by a live race — see L1.

## Dispositions

| Item | Sonnet ID | Original question | Sonnet | Final disposition |
|---|---|---|---|---|
| L1 | 19 | What happens if config is truncated/replaced while read? | Partly | **TOLERATE** |
| L2 | 20 | Does anything depend on accepting `...`? | Answered | **TERMINATE** |
| L3 | 21 | Is a BOM-prefixed config intended to be supported? | Partly | **TOLERATE** |
| L4 | 22 | Is dropping the second-document parse error intended? | Partly | **TREAT** |

### L1 (19) — truncation/replacement during read → **TOLERATE**

- **Original question:** what a truncation or replacement of `config.yml` while being read produces — partial-parse error, `io.EOF` as `is empty`, or a silently short decode (`DOSSIER.md:145`).
- **Sonnet's evidence:** decoder streams from an open fd, no lock/stat (`main.go:104-113`); mid-value cut accepted (`certAuthName: we`, `vaultAddr: https://vault.exam`); mid-key cut → `could not find expected ':'`; empty/comment-only → `is empty`; rename-replace assumed safe "not tested".
- **My assessment (verified).** Reproduced all four outcomes, plus the two cases Sonnet left open:
  - Truncation to a **valid short prefix with all three required keys present** → `OK addr="https://vault.exam" name="we" mount="cert"`. Sonnet's "the required-field check still passes" is confirmed.
  - Truncation **mid-value with no trailing newline** is also accepted (a 30-byte prefix of the base file decoded with `err=nil`, `vaultAddr="https://localhost:8"`), so the silent-acceptance class is wider than "lands at a value boundary"; the file need not end on a value boundary.
  - **rename-replace is safe and I tested it**: open the fd, `os.Rename` a new file over the path, decode from the old fd → original content, `err=nil`, while the path held the new content. POSIX inode semantics, per-read, not a race.
  - **in-place truncate of the same inode** followed by decode from the already-open fd → short value, `err=nil`; second decode `io.EOF`.
  - Sonnet's `Remaining` ("real concurrent writer/reader race not exercised") is not a meaningful residual: the reader consumes a fixed fd, so every observable state is a **prefix** of the file, and the classes of outcome are exactly the three observed (short-but-valid decode / parse error / `is empty`). A live race cannot produce a fourth class. Only mid-write visibility of a prefix is added, which is the same set.
- **Disposition: TOLERATE.** No repo-owned fix exists for the load-bearing case: a truncated value such as `we` is byte-indistinguishable from an intended `we`; detecting it requires out-of-band state (size/checksum metadata or an atomic-write convention) that no requirement asks for and that the config format cannot carry. Impact is bounded and stays inside the trust boundary: `config.yml` is operator-authored in a `0700` dir (`README.md:49-54`), read once at startup (`main.go:452`) before any network I/O; a short `vaultAddr` fails the cert-login TLS handshake (the reason scheme checking is deliberately absent, `main.go:126-129`), and a short role/mount fails server-side cert auth. No privilege boundary is crossed, and empty values are already caught (`main.go:130-135`). `TRANSFER` was considered (write discipline is the operator's) and rejected: the repo's own behaviour is fully determined and safe-by-inspection, so there is nothing to hand to an external owner; the atomic-rename convention is already the case that works.
- **Owner/evidence needed:** none.

### L2 (20) — `...` document-end marker → **TERMINATE**

- **Original question:** whether any consumer depends on `LoadConfig` accepting `...` (`DOSSIER.md:146`).
- **Sonnet's evidence:** base + `...` loads; `...` then `---`/`x: 1` rejected as `must contain a single YAML document`; leading `---` loads; commit `66f70b9` says "A leading `---`, a trailing `...` and comments still work"; no test pins it.
- **My assessment (verified).** Confirmed every case, including the raw causes Sonnet did not state: `...\n---` → probe decode returns a Document node (`Kind=1`), `...\nx: 1` → probe error `yaml: line 4: did not find expected <document start>`. Commit `66f70b9fe9f6bc9f3ffd7da978a4a1302a38091b` (PR #19) message verified verbatim, including the round-2 bullet that introduced the rule. `TestLoadConfig_Rejects` (`main_test.go:189-194`) has 5 cases, none with `...` — accurate. Sonnet's `Remaining` — "consumers outside the repo are unknowable" — is **void on evidence**: grep for `config.yml` across `*.go` returns only `main.go:103` (plus test fixtures), so `LoadConfig` is the sole reader of the file; an external consumer has no read path. The premise "does anything depend" is answered *no*, and the tolerance can only widen acceptance (it is a YAML stream terminator), with the second-document rule intact because `...`-then-content is still rejected.
- **Disposition: TERMINATE.** Answered; intended (documented in the commit that introduced the rule); no dependency and no failure mode. Not converted into a finding. Cost of an untested tolerance is nil: acceptance of a superset of the documented format, asserted only through the library.
- **Owner/evidence needed:** none.

### L3 (21) — BOM-prefixed `config.yml` → **TOLERATE**

- **Original question:** whether a BOM-prefixed config is intended to be supported (`DOSSIER.md:147`).
- **Sonnet's evidence:** UTF-8 BOM loads; UTF-16LE with BOM loads; UTF-16LE without BOM fails `control characters are not allowed`; CRLF loads; no doc/test/commit mention.
- **My assessment (verified).** All four reproduced exactly. History grep confirms no product mention: `git log --all -S'BOM'` returns only `7f10998` (the audit-context commit itself, i.e. the dossier'); `grep -i utf README.md PKI-SETUP.md` → no hits; the config docs at `README.md:47-78` say nothing about encoding. So intent is genuinely unstated — Sonnet is right there.
- **Disposition: TOLERATE.** The tolerance is not repo code: it is the pinned parser's (`go.yaml.in/yaml/v3 v3.0.5`, `go.mod:9`), it is a *superset* of the documented UTF-8 contract, and it has no failure mode — the only broken input class (UTF-16 without BOM) fails loudly with a clear message, and BOM'd inputs decode to correct values. Residual accepted: acceptance is inherited and untested, so a future yaml bump could change it unnoticed; that is the price of pinning dependency behaviour we never promised, and it is cheaper than writing a test that pins library behaviour (which §5 of the working rules forbids: a BOM test would assert incidental parser behaviour, not repo logic). `TRANSFER` to "maintainer policy" was considered and rejected: no external evidence needs gathering and no decision blocks shipping — a doc promise could be added later at zero risk, but nothing requires it.
- **Owner/evidence needed:** none.

### L4 (22) — cause discarded in the single-document error → **TREAT**

- **Original question:** whether dropping the underlying yaml parse error in the second-document branch (`main.go:123-124`) is intended (`DOSSIER.md:148`).
- **Sonnet's evidence:** any non-EOF probe result (including a parse error) maps to the fixed message; the comment `main.go:120-122` and commit `66f70b9` explain the single-document rule only; observed `...` then `---` gives the fixed message.
- **My assessment (verified).** Two distinct non-EOF shapes confirmed, which matters for the fix:
  - nil error with a Document node (`...\n---`, bare `---\n`, unknown key in the second document) → `Kind=1`, so **`err` is nil** in this branch;
  - genuine parse error (`---\n]`) → raw probe error `yaml: line 4: did not find expected node content`, dropped by `main.go:124`.
  The rule is intentional (comment + commit); the **discard is not** — the comment explains why one document is required, never why a parse failure is suppressed. Sonnet's "intent not stated" is correct, and the discard is the only place in the function where a cause is thrown away: `main.go:118` wraps the first-decode error with `%w`, and PR #19's own follow-up rounds institutionalised cause preservation (`main.go:186, 191, 198` via `pathErrCause`, commit `66f70b9` round 2/3 messages). So this contradicts house error-text style rather than expressing it.
- **Disposition: TREAT.** Repo-owned, actionable, no implementation now. Impact is diagnostic only (low severity: the rejection direction and the named rule are already correct), so it should be scheduled last — but the fix is small and removes the one inconsistency in the function's error policy.
- **Suggested future task (only TREAT item).** In the probe branch, preserve a non-nil cause and keep the current message when the second decode legitimately returned a Document node:
  `if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) { if err != nil { return nil, fmt.Errorf("%s must contain a single YAML document: %w", path, err) } ; return nil, fmt.Errorf("%s must contain a single YAML document", path) }`
  — the `err != nil` guard is required: `%w` of nil renders `%!w(<nil>)` and the nil case is real (bare `---`). Add one row to `TestLoadConfig_Rejects` (`main_test.go:179-199`) for `base + "---\n]\n"` asserting **both** `single YAML document` and the cause text `did not find expected node content`, so the test fails without the change (asserting the rule text alone would pass either way). No doc change: the message text is not documented, and the existing tests use `strings.Contains`, so appending `: <cause>` breaks nothing.
  Verify with `go test -run TestLoadConfig -v`.

## Counts

| Disposition | Count | Items |
|---|---|---|
| **TREAT** | 1 | L4 (22) |
| **TOLERATE** | 2 | L1 (19), L3 (21) |
| **TRANSFER** | 0 | — |
| **TERMINATE** | 1 | L2 (20) |
| Total | 4 | — |

## Recommended worklist

1. **L4 (TREAT, low severity, one file + one test row):** keep the probe-decode cause in the single-document error, guarded on `err != nil`; add the discriminating table case. This is the only repo-owned action in this function.
2. **No action, record as accepted:** L1 truncation/short-decode (a truncated-but-valid value is undetectable without out-of-band metadata; failure lands in Vault-side auth errors inside the operator's own trust boundary) and L3 BOM tolerance (inherited from the pinned parser, superset of the documented UTF-8 contract, loud failure for the broken input).
3. **Close L2** as answered/intended (commit `66f70b9`); no test or doc needed.

**Adjacent question, out of scope (origin `readPrivateKey`, item 15/K4):** whether `~/.yubivault` permissions should be enforced anywhere cites `LoadConfig` only as negative evidence (`main.go` stats only at `:189`; `TestLoadConfig_ValidFile` deliberately uses dir `0755`/file `0644`, `main_test.go:129-151`). Not dispositioned here; it belongs to the `readPrivateKey`/`CreateLocalVaultClient` review.

---
Skipped: no live hardware, Vault server, proxy or CI run was touched — none of L1-L4 needs one. Not re-verified: yaml *type-mismatch* diagnostics (my probe case accidentally duplicated a key, so it exercised duplicate-key detection instead; irrelevant to all four items). Risk to know: L3's accepted residual is real — BOM acceptance is dependency behaviour with no repo test, so a yaml upgrade could change it silently; L4's fix must branch on `err != nil` or it will print `%!w(<nil>)` for a bare second `---`.
