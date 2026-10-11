# `readPrivateKey` — adversarial disposition review

**Verification basis.** Repo HEAD `7f10998` (working tree clean except untracked `audit-context/`); toolchain `go1.27.2` (`$GOROOT/VERSION`); binary built from HEAD to `/tmp/yv-dispo` (`go build`, 1.9s) and exercised against synthetic `$HOME`s. Claims below marked **[live]** are my own executions; **[report-only]** = Sonnet's observation I did not reproduce; **[INFERENCE]** = source-derived, not executed.

Source/line facts re-verified against the tree, not taken on trust:
- `readPrivateKey` spans `main.go:183-201`; `keyFileField` `main.go:178`; `pathErrCause` `main.go:205-211`; caller `CreateLocalVaultClient` `main.go:155-174`; `os.UserHomeDir()` `main.go:448`; `signal.NotifyContext` `main.go:474`; `main` error print `log.Fatal` `main.go:425`.
- **Citation correction:** `tls.X509KeyPair` is called at `main.go:165`, not `:166` as both prior reports state (the per-function analysis repeats `:166` in four places). Immaterial to every conclusion, but the two documents disagree with the tree.
- No `Sys()`/`syscall.Stat_t`/`Uid`/`Geteuid` token anywhere in `main.go`; no zeroing/wipe tokens; no `O_NOFOLLOW`/`O_NONBLOCK`/`IsRegular` anywhere. `README.md:51` = `chmod 700 ~/.yubivault`; `README.md:80` = "…run `chmod 600` on the key. yubivault refuses a key that group or other can read." `go.mod:3` = `go 1.27.0`; `ci.yml:37,57` and `release.yml:37` = `go-version: '1.27'`. Commits `253799a` and `66f70b9` exist; `253799a`'s body contains the bullet "Refuse group/other-readable client key in -local mode" (Sonnet quotes the bullet, not the squash subject), and `66f70b9`'s body states the empty-`certAuthKeyFile` case "pass[ed] the 0600 check because the dir is 0700" — i.e. dir 0700 is treated as an operator precondition.

---

## K1 (+C4, merged) — ownership (`Stat_t.Uid`) / is an owner policy stated?
**Origins:** `readPrivateKey`, `CreateLocalVaultClient`.
**Original question:** `info.Mode().Perm()` is the only attribute consulted (`main.go:193`); is an owner/uid requirement intended, and is any owner policy stated?
**Sonnet:** *Answered.* Only the perm mask is tested; `README.md:80` says nothing about ownership; commit history and `PKI-SETUP.md` contain no ownership policy. "Whether one is wanted is a maintainer decision."
**My assessment:** Confirmed. No uid/`Sys()` reference exists in `main.go` (repo-wide grep empty). **[live]** key owned by uid 1000, mode 0600, binary run via `sudo` (euid 0) → passed the mode check (`could not read certificate file (certAuthPemFile): …`); a uid-vs-euid comparison, which is pure source logic and would fire regardless of DAC_OVERRIDE, demonstrably does not exist. **[live]** the `-local` mode check also passes on a 0600 key inside a 0755 `.yubivault`, i.e. only the file's own bits count. The residual is policy, not mechanism: a uid check would add no confidentiality on non-root systems (a non-owner 0600 file is unreadable anyway) and would *break* the plausible `sudo yubivault -local` use pattern, which my second test shows is technically reachable today.
**Final disposition:** **TOLERATE.**
**Rationale:** The stated policy is the mode rule (`README.md:80`, in-source intent `main.go:180-182`); that rule is enforced correctly on the opened inode. Ownership is deliberately unconsulted, and enforcing it would reject a working use case for no measured gain. No docs claim an owner requirement, so nothing is violated.
**Owner / evidence needed (TRANSFER only):** n/a.
**Suggested future task (TREAT only):** n/a.

## K2 — symlink as final path component vs the "checked == read" property
**Origins:** `readPrivateKey`.
**Original question:** Is a symlink at the final path component inside the "file checked equals file read" property; is there a stated intent?
**Sonnet:** *Answered.* Symlink → 0600 accepted, symlink → 0644 rejected; `os.Open` follows symlinks and `f.Stat` is `fstat`, so the checked file is the read file; no doc/history states symlink intent.
**My assessment:** Independently reproduced in full. **[live]** `k.key` → symlink → 0600 real file ⇒ mode check passed (failure surfaced at the certificate read); `k.key` → symlink → 0644 ⇒ `… is accessible by group/other (mode 0644)`, i.e. the *target's* mode was checked on the opened descriptor; `k.key` → symlink → `/dev/null` ⇒ rejected as `mode 0666`. That is exactly the invariant at `main.go:183-201`: one `*os.File`, `fstat` on the fd, read from the same fd — no path-based window exists, symlink or not. The property therefore holds *because* of the symlink-following open, not despite it. Substitution is not a confidentiality break: the caller never writes the key, and a substituted key/cert pair only authenticates the substituter's own identity to Vault. Untested intent (history grep found no symlink/`O_NOFOLLOW` discussion) is now irrelevant, since no behavioural gap remains.
**Final disposition:** **TERMINATE.**
**Rationale:** Question answered; the invariant is demonstrated rather than assumed, and the remaining "no documented symlink policy" is not a gap because nothing in the documented contract depends on symlink refusal.
**Owner / evidence needed:** n/a.
**Suggested future task:** n/a.

## K3 (+C4, merged) — non-regular files (FIFO, device, socket)
**Origins:** `readPrivateKey`, `CreateLocalVaultClient`.
**Original question:** No `IsRegular` guard exists (`main.go:184-198`); is a regular-file requirement intended?
**Sonnet:** *Partly.* A 0600 FIFO blocks in `os.Open`; first SIGINT absorbed, second killed it; `/dev/null` (0666) rejected by the mode check; a directory yields a read error covered by `main_test.go` "directory"; `io.ReadAll` on a writer-fed FIFO/socket has no size bound (not run); intent undocumented.
**My assessment:** Confirmed, and one step further. **[live]** 0600 FIFO, no writer ⇒ `timeout -s KILL 4` exit 137 (still alive at 4s); `timeout -s TERM -k 3` ⇒ exit 137 after 4s, i.e. **SIGTERM is also absorbed**, not just SIGINT (`signal.NotifyContext(..., os.Interrupt, syscall.SIGTERM)` at `main.go:474` cancels the context, but the main goroutine is parked inside `open(2)` and can never observe it); `timeout -s INT -k 4` ⇒ 137. Only SIGKILL ends it. In the failed first run the process ran to the harness's 120s limit with no output — the binary's errors go through `log.Fatal` (`main.go:425`, timestamped), and no such line appeared, so the hang is not a logged error path. The discriminating experiment: **[live]** a **0666** FIFO hangs identically (exit 137) instead of emitting the group/other rejection — this proves the block is inside `os.Open`, i.e. `f.Stat` at `main.go:189` and the fail-secure branch at `:193-195` are never reached for a FIFO. **[live]** `/dev/null` via symlink ⇒ `mode 0666` rejection, matching Sonnet. Consequence the prior reports did not state: the non-regular case does not merely skip a guard, it bypasses the documented promise ("yubivault refuses a key that group or other can read", `README.md:80`) and the in-source intent (`main.go:180-182`), because the open blocks before the check. A post-open `IsRegular` check alone would **not** fix it — the hang precedes the check — so any fix must use `O_NONBLOCK` on the open (then clear the flag) or a pre-open `Lstat`, noting that the latter reintroduces the path/TOCTOU window the code deliberately avoids. A 0600 character device that streams without EOF would also be read unbounded by `io.ReadAll` (source: `$GOROOT/src/io/io.go:709-752`; not exercised — **[INFERENCE]**). Threat model: the path comes from the user's own `~/.yubivault/config.yml`, so this is self-inflicted misconfiguration, not a crossed privilege boundary.
**Final disposition:** **TREAT.**
**Rationale:** The behaviour is verified and it contradicts a stated, documented promise; the fix is repository-owned and small, but needs the non-blocking-open caveat, so it deserves a scoped follow-up rather than a hand-wave. Not a security finding — no confidentiality or integrity loss — hence a task, not an incident.
**Owner / evidence needed:** n/a (repo-owned).
**Suggested future task (TREAT only):** In `readPrivateKey`, make the open non-blocking (`syscall.O_NONBLOCK|O_RDONLY`, clear after `fstat`) and reject `!info.Mode().IsRegular()` with the existing `keyFileField` wording; this restores fail-secure rejection for FIFOs/devices/sockets, bounds the read, and removes the SIGINT/SIGTERM-immune hang. Acceptance evidence: 0666 FIFO ⇒ group/other rejection (not a hang); 0600 FIFO ⇒ regular-file rejection; existing `main_test.go` cases unchanged. Optionally add a `main_test.go` case with `os.Mkfifo` and a deadline.

## K4 — `~/.yubivault` 0700 documented but unenforced
**Origins:** `readPrivateKey` (function does no directory check).
**Original question:** Directory permissions are documented (`README.md:51`) but not enforced; is enforcement intended elsewhere?
**Sonnet:** *Answered.* `main.go` stats only at `:189`; `LoadConfig` does no stat; `TestLoadConfig_ValidFile` deliberately creates the dir 0755 and file 0644 and expects success; `README.md:51` says `chmod 700`; `66f70b9` treats "the dir is 0700" as an operator precondition.
**My assessment:** Confirmed verbatim. `main_test.go:131-139` does `os.Mkdir(configPath, 0755)` and `os.WriteFile(file, content, 0644)` and asserts success, so non-enforcement is *pinned by a test*, not merely absent. `LoadConfig` (`main.go:102-130`) opens `config.yml` and decodes; no `Stat`/mode/ownership consult. **[live]** dir 0755 (+ home dir `mktemp` 0700) with a 0600 key ⇒ mode check passes, failure at the certificate read. Residual exposure is `config.yml` contents (`vaultAddr`, mount, role — no secrets) plus defense-in-depth: the key itself is independently protected at 0600, so an over-permissive directory exposes nothing readable. Enforcing 0700 would contradict `TestLoadConfig_ValidFile` and add scope nobody asked for.
**Final disposition:** **TOLERATE.**
**Rationale:** Documented operator precondition, independently enforced where it matters (the key's own bits), with a test that deliberately encodes the non-enforcement. No stated requirement is broken.
**Owner / evidence needed:** n/a.
**Suggested future task:** n/a.

## K5 — are the key bytes retained or zeroed after `tls.X509KeyPair`?
**Origins:** `readPrivateKey` (returns the slice).
**Original question:** Is `keyPEM` zeroed after use?
**Sonnet:** *Partly.* `keyPEM` is a local in `CreateLocalVaultClient` (`main.go:157-165`); no zeroing code in `main.go`; the parsed key lives in the `tls.Certificate` for the process lifetime; `io.ReadAll` growth leaves earlier backing arrays to the GC (stdlib-semantics `[INFERENCE]`); remaining item: heap inspection.
**My assessment:** Confirmed. `main.go:157` binds `keyPEM`; `:165` consumes it; no zeroing/wiping token anywhere in `main.go` (grep for `Zero|zero|wipe|clear(|subtle` is empty). `tls.X509KeyPair` retains the parsed `crypto.PrivateKey` inside the returned `tls.Certificate` — required, since the handshake signs with it — so the key is unavoidably live for the whole process. That process is a single-shot CLI that prints a token and exits (`main.go:423-426` + `fmt.Println(token)`), so the exposure window is one login. Copying/zeroing `keyPEM` is not a guarantee in Go (compiler may copy, GC may relocate), and it would leave the live parsed form untouched anyway.
**Final disposition:** **TOLERATE.**
**Rationale:** Known residual with a short, bounded window; partial-mitigation code would create a false sense of assurance while the authoritative copy stays live by necessity.
**Owner / evidence needed:** n/a.
**Suggested future task:** n/a.

## K6 — can a `tls.X509KeyPair` error embed key material?
**Origins:** `readPrivateKey`.
**Original question:** Can the error at `main.go:165` put key bytes into the `log.Fatal` line?
**Sonnet:** *Answered.* `crypto/tls/tls.go` ~259-355 and `parsePrivateKey` use constant strings; the only variable text is the list of PEM block-type labels from the file, plus `%w` of the PKCS#8 parse error; `x509/pkcs8.go` and `sec1.go` messages hold constants, lengths and OIDs. Scope: go1.27.2.
- **My assessment:** Read directly in the installed toolchain. Every `fail(...)` in `X509KeyPair` is a constant string except `fmt.Errorf("… after skipping PEM blocks of the following types: %v", skippedBlockTypes)` — and `skippedBlockTypes` is the PEM `Block.Type` labels *from the key file itself* (`$GOROOT/src/crypto/tls/tls.go:259-330`). `parsePrivateKey` (`tls.go:361-379`) wraps `pkcs8Err` with a constant prefix. `pkcs8.go` messages are constants, lengths, algorithm OIDs, and the one non-constant PEM-type list; no key bytes or file paths are interpolated. **TERMINATE; no path-leakage or secret-disclosure issue.**
**Final disposition:** **TERMINATE.**
**Rationale:** Answered at source level for the cited toolchain; no key material, no path. The single tag byte is a DER structural byte, not key material, and would only appear with an already-malformed ML-DSA key.
**Owner / evidence needed:** n/a.
**Suggested future task:** n/a.

## K7 — stdlib citations read from go1.27.2; are other Go versions covered?
**Origins:** `readPrivateKey` (all stdlib citations).
**Original question:** Behaviour under other Go releases.
**Sonnet:** *Partly.* `go.mod:3` is `go 1.27.0`; README says "Go 1.27 or newer"; CI/release use `go-version: '1.27'` (floating minor); only 1.27.2 exercised.
- **[INFERENCE]**. A 0600 character device that streams without EOF would also be read unbounded by `io.ReadAll` (source: `$GOROOT/src/io/io.go:709-752`; not exercised). Threat model: the path comes from the user's own `~/.yubivault/config.yml`, so this is self-inflicted misconfiguration, not a crossed privilege boundary.
**Final disposition:** **TOLERATE.**
**Rationale:** Version-conditional residual with no known divergence; CI automatically tracks the newest 1.27.x, and re-validating the K6 error-text reading on a new Go minor is ordinary maintenance rather than a repo defect.
**Owner / evidence needed:** n/a (if maintainers ever want future-minor coverage, the owner is the repo's own CI config — `ci.yml:37,57` — not an external party).
**Suggested future task:** n/a.

---

## Additional observations surfaced by the prior analysis (not in Sonnet's list)
Disposed here so no `readPrivateKey` question is left dangling; both are stated as facts in the per-function analysis rather than listed open questions.

| ID | Observation | Assessment | Disposition | Rationale |
|---|---|---|---|---|
| A1 | `filepath.Join` is lexical, so `certAuthKeyFile: ../outside.key` leaves `~/.yubivault`; no containment check (`main.go:157`) | **[live]** confirmed: config with `../outside.key` (0600) is accepted, failure surfaces at the certificate read | **TOLERATE** | The value comes from the operator's own `config.yml` in their own home; no privilege boundary is crossed, and `$HOME` itself is caller-controlled (`main.go:448`). Containment would be new scope with no gain. |
| A2 | Only the 9 perm bits are masked (`main.go:193`), so setuid/setgid/sticky do not fail the check (a 04600/02600 mode passes) | **[live]** confirmed: `chmod 2600` key accepted, failure at the certificate read | **TOLERATE** | Deliberate and correct: the rule is "refuse group/other-readable" (`README.md:80`), and setuid/setgid on a file that is only ever read grants nothing. A broader mask would reject modes that are not actually group/other-readable. |

## Counts

| Disposition | Count | Items |
|---|---|---|
| **TREAT** | 1 | K3 |
| **TOLERATE** | 4 | K1, K4, K5, K7 |
| **TRANSFER** | 0 | — |
| **TERMINATE** | 2 | K2, K6 |
| Total (Sonnet items) | 7 | K1–K7 |

Extra observations A1–A2: 2 × TOLERATE (outside the Sonnet numbering).

## Recommended worklist
1. **K3 — the only task.** Non-blocking open + `IsRegular` rejection in `readPrivateKey`, with the caveat recorded: the current post-open `fstat` cannot see a FIFO because `os.Open` blocks first, so a post-open guard alone changes nothing. Acceptance: 0666 FIFO ⇒ group/other rejection; 0600 FIFO ⇒ regular-file rejection; 0600 character device ⇒ regular-file rejection; existing `main_test.go:240-311` unchanged. Owner: repo.
2. **No action** for K1, K2, K4, K5, K6, K7, A1, A2. K6's error-text reading is the one item to re-verify opportunistically when CI moves off the 1.27 line.
3. **Housekeeping (optional, not a question):** both prior reports cite `tls.X509KeyPair` at `main.go:166`; the tree says `:165`.

Skipped: no heap inspection for K5, no writer-fed FIFO/socket read for K3 (labelled `[INFERENCE]`), no SIGINT reproduction of Sonnet's exact "second signal kills it" sequence beyond my `INT -k` variant, and nothing touching Vault, OpenSC or real hardware — no item here required it. Risk to know: TREAT for K3 is based on a self-inflicted-misconfiguration threat model, so if maintainers consider a blocked `open` acceptable, downgrade K3 to TOLERATE rather than implementing a non-blocking open.
