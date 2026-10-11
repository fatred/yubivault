# ReadPin disposition report

**Scope.** All questions originating in `ReadPin` (`main.go:376-395`), including merged entries listing it as an origin. 8 per-function questions in `audit-context/functions/09-ReadPin.md`; 6 have dossier/D-IDs (disposed by Sonnet items 43-47 plus item 41), 2 do not.

**Verification basis.** Re-read `main.go:139-165, 249-300, 370-400, 424-503`, `main_test.go:299-378`, `README.md:60-80,95-115`; `go.mod:1-10`; `x/term@v0.47.0` `term.go`, `term_unix.go`, `terminal.go` at the cited lines; `git log -S`, `git show 6e3418b:main.go`, `git show bfa9e36`. Ran a standalone `/tmp/ds09` replica of the generic path (`main.go:388-394`) for the `n` and single-`Read` behaviors — a replica, not the binary (`package main` is not importable). Sonnet's pty/SIGINT and piped-stdin runs were not re-executed; they are labeled **report-only**.

**Mapping.**

| Origin | Per-function OQ | Sonnet item | Registry |
|---|---|---|---|
| D1 | 3 (`bPin[:n]`) | 43 | dossier bullet 1 |
| D2 | 2 (`read(2)` `(0,nil)`) | 41 (merged, also `resolvePin`/P3) | bullet 2 |
| D3 | 4 (why 64) | 44 | bullet 3 |
| D4 | 6 (non-terminal reader in production) | 45 | bullet 4 |
| D5 | 5 (newline placement) | 46 | bullet 5 |
| D6 | 1 (signal at prompt) | 47 | bullet 6 |
| — | 7 (prompt-label content) | none | **absent** |
| — | 8 (buffer zeroization) | none | **absent** |

---

## D1 — item 43 (per-function OQ3): what `n` may a non-conforming reader return; what does `bPin[:n]` do?

**Sonnet.** *Answered.* n=100 panics `slice bounds out of range [:100] with capacity 64`; n=-1 panics `[:-1]`; contract `0 <= n <= len(p)`; `package main` not importable so only in-repo callers matter. Also observed: single `Read`; split `"12"`/`"34\n"` → `"12"`; `"1234\nextra"` → `"1234\nextra"`; 100 bytes → 64.

**My assessment.** All five observations reproduced exactly in the `/tmp/ds09` replica: `n=100` → `slice bounds out of range [:100] with capacity 64`, `n=-1` → `slice bounds out of range [:-1]`, split read → `"12"`, `"1234\nextra"` → `"1234\nextra"`, 100 bytes → 64 chars. Contract confirmed in the stdlib (`$GOROOT/src/io/io.go:58`, Go 1.27.2). Module is `github.com/fatred/yubivault` (`go.mod:1`) declaring `package main` (`main.go:1`), so no external caller can hand `ReadPin` a reader; the in-repo non-conforming case is unreachable — callers are `main.go:262`, `main_test.go:313` (`bytes.Buffer`), `main_test.go:361,368` (`strings.Reader`), all conforming. Sonnet's item is accurate; framing detail only: "hostile reader" postulates a trust boundary that does not exist.

**Final: TERMINATE.** Answered and the premise is invalid — `n` is bounded by the `io.Reader` contract, no non-conforming reader is reachable, and `ReadPin` is in an unimportable `package main` whose generic branch only tests reach. A clamp at `main.go:394` would defend dead code. (If the branch ever became production-reachable, this becomes an input-truncation defect — see D4.)

---

## D2 — item 41, merged `P3 + D2` (per-function OQ2): can `readPasswordLine` spin without blocking on Ctrl-D or hangup; can `read(2)` return `(0, nil)`?

**Sonnet.** *Partly.* Source: `readPasswordLine` loops on `n==0 && err==nil` (`terminal.go:1050-1083`), `passwordReader.Read` passes `unix.Read` through. **Report-only** pty runs on Linux 6.12: Ctrl-D at an empty prompt → process alive in state S, 0 CPU ticks over 2 s, next typed line accepted; master closed with SIGHUP default → killed by SIGHUP; master closed with SIGHUP ignored → rc=1 promptly, no spin. Remaining: `vhangup`/`tty_hung_up_p`.

**My assessment.** Source claim verified, with citation drift: `passwordReader.Read` is `term_unix.go:70-71`, not "~64-68". Loop verified at `terminal.go:1050-1083`: `n > 0` → byte handling and `continue` (`:1057-1074`); otherwise `if err != nil` (`:1077`) is false for `(0,nil)`, so control falls to the loop top and the next `unix.Read` blocks — `(0,nil)` cannot busy-spin on a blocking fd **by construction**, which corroborates Sonnet's 0-CPU observation without needing to re-run it. Hangup surfaces as SIGHUP or a read error, not a repeating `(0,nil)` [INFERENCE on the kernel detail; Sonnet's pty results themselves are report-only].

**Final: TOLERATE.** Behavior understood and benign on every exercised input; a spin needs a descriptor that returns `(0,nil)` forever, which no observed tty path produces. The loop is upstream `x/term`, not repo-owned, so hardening would be an upstream change, not a repo task. Unresolved external evidence preserved: the `vhangup`/`tty_hung_up_p` path is unexercised; the `resolvePin`/P3 half of this merged entry is disposed in the `resolvePin` report, not here.

---

## D3 — item 44 (per-function OQ4): why 64 bytes?

**Sonnet.** *Answered.* `git log -S'make([]byte, 64)'` shows only the initial commit `6e3418b`; no comment or constant; "no rationale exists".

**My assessment.** Reproduced: `git log -S'make([]byte, 64)' -- main.go` yields only `6e3418b`, where the line is `bPin := make([]byte, 64)` at `main.go:162` of that revision; no constant, no comment. Terminal path confirmed capless (`main.go:381-386`).

**Final: TERMINATE.** Answered: the rationale does not exist and cannot be recovered; the value is arbitrary and bounds only a branch unreachable in production (D4). Not a defect in itself, and no action follows from "why 64".

---

## D4 — item 45 (per-function OQ6): does any deployment pass a non-terminal reader in production?

**Sonnet.** *Answered.* Only caller is `resolvePin` (`main.go:262`), reached from `run` with `os.Stdin` (`:464`); other callers are tests (`main_test.go:312`, `:358`); `package main` not importable; production uses only the terminal branch; piped stdin errors (item 3).

**My assessment.** Verified: `ReadPin(` occurs only at `main.go:262` and `main_test.go:315`; `run` passes `os.Stdin`/`os.Stderr` at `main.go:464`; module/package as in D1; no test passes `os.Stdin` (`main_test.go` mentions only `os.Stdout`, in `captureStdout`). Cross-ref item 3 (origin `run`) is report-only on the runtime, but its source half checks out: piped stdin reaches the terminal branch and `IoctlGetTermios` fails → `could not read PIN code: inappropriate ioctl for device`, rc 1, empty stdout. Additional verified consequence: the branch the binary runs (`main.go:380-386`) has **no** test, while the tests cover only the unreachable generic branch — `main_test.go:315` passes a `bytes.Buffer`; `main_test.go:361` never reaches `ReadPin` (`TOKEN_PIN` short-circuits at `main.go:259-261`); only `main_test.go:368` does, with `strings.NewReader("")` → `(0, io.EOF)`.

**Final: TREAT.** The reachability question is answered (no production caller), but the answer leaves a repo-owned decision: `main.go:388-394` (single `Read`, 64-byte cap, silent truncation) is test-only code, and the shipped terminal path is unpinned. Owner: repo maintainer.

**Suggested future task.** *"ReadPin branch/test alignment: decide the fate of the unreachable generic path (`main.go:388-394`) — delete it with its generic-path tests, or keep it and pin the production terminal path. Note for whichever is chosen: an in-process test must intervene on fd 0, because `term.ReadPassword` reads fd 0 via `syscall.Stdin` (= 0, `syscall_unix.go:23`) and ignores the `r` argument (dup2 `/dev/null` over fd 0), or use an exec-based test running the built binary with stdin at `/dev/null`, asserting rc 1, the wrapped ioctl error on stderr, and empty stdout."*

---

## D5 — item 46 (per-function OQ5): is the newline written before the error check (`main.go:382`/`:390`) intended?

**Sonnet.** *Partly.* Newline appears before the error text; `fmt.Println()` existed from the initial commit; `bfa9e36` only redirected it to `w`; no comment states intent.

**My assessment.** History verified exactly: `6e3418b:main.go` has `fmt.Println()` after the read on both branches (lines 156 and 164 of that revision) and `fmt.Print` for the prompt; `bfa9e36` replaced them with `fmt.Fprint(w, …)`/`fmt.Fprintln(w)` and added the doc comment (`main.go:376-377`) without touching ordering. The ordering produces prompt → newline → error on its own line; the error text is never concatenated to the prompt.

**Final: TERMINATE.** The substantive content is settled: the ordering is benign and arguably correct (the error starts on a fresh line), and it predates the current signature. Unrecorded authorial intent for a cosmetic line break is not a meaningful open question.

---

## D6 — item 47 (per-function OQ1): can a second `ReadPin` follow termios restore; can an early return precede the deferred restore?

**Sonnet.** *Partly.* `readPassword` defers the restore; one call site so no second call in this binary. **Report-only** observation: Ctrl-C at the prompt (default disposition, before `NotifyContext`) killed the process by SIGINT and left the slave termios with ECHO off, since the deferred restore does not run on death by signal. Remaining: EINTR behavior at runtime.

**My assessment.** Both source halves verified, with citation drift: the defer is `term_unix.go:88` (Sonnet: "~92-99"); the mutation is `:79-83` (ECHO cleared, `ICANON|ISIG`, `ICRNL`), so the restore runs only on a function return. One call site (`main.go:381`) and one production caller (`main.go:464`) → no second `ReadPin` in the binary's lifetime; no early return exists between mutation and defer except process death, so the first half of OQ1 is answered: SIGINT kills by default disposition rather than returning an error. The residual is Sonnet's tty observation — report-only here. It follows from the deliberate design at `main.go:460-461` (the prompt must stay killable by Ctrl-C): the mechanism that keeps Ctrl-C working is the one that skips the deferred restore. Blast radius is small — readline-based shells re-establish their own termios at the next prompt; a non-readline shell or pty harness can be left echo-off and recovered with `stty sane`. README documents signal behavior during login (`README.md:110-111`) but not at the prompt.

**Final: TOLERATE.** Question answered (no second call, no early return short of death); the residual (ECHO off after a signal death) is accepted because every fix costs the deliberately killable prompt or adds pre-prompt signal handling, and the state is recoverable. Preserved as unverified: EINTR behavior at runtime (report-only).

---

## Unmapped question — per-function OQ7: prompt-label content (`yubikeySerial` unescaped; may be empty)

**Sonnet.** Absent — no D-ID in the index (`ReadPin` row lists D1-D6 only), so no disposition exists.

**My assessment.** Verified `main.go:379` concatenates the value unescaped; `main.go:149-152` (`requireForMode`) requires only `OpenScPath` and `YubikeyPivSerial` for `-yubi`, so `YubikeySerial` may be empty and the prompt then reads `PIN for : `; `README.md:71` documents the field only as "optional: shown in the PIN prompt". The only source of the value is the invoking user's own `$HOME/.yubivault/config.yml` (`main.go:37`). Control characters in a prompt label therefore cross no trust boundary: the author writes them to their own stderr.

**Final: TOLERATE.** Security premise invalid (self-owned config → own terminal); the accepted cosmetic residual is `PIN for : ` when the optional field is unset. No task — a conditional prompt or a README clause could be added later, but nothing here requires it. Registry gap: this question was dropped from the canonical six-bullet dossier list, hence no D-ID; it is disposed here rather than left undecided.

---

## Unmapped question — per-function OQ8: intermediate buffers not zeroized

**Sonnet.** Absent — no D-ID.

**My assessment.** Verified by source: neither `bPin` (`main.go:381`) nor the 64-byte buffer (`main.go:388`) is cleared anywhere in `main.go`; both are converted with `string(bPin)` (`main.go:386,394`), which copies the bytes into an immutable string that cannot be zeroized; the PIN also proceeds to `crypto11.Config.Pin` (`main.go:280`) and into the PKCS#11 module's C string (miekg `Login`), outside this repo.

**Final: TOLERATE.** Known residual accepted: with an unzeroizable string copy and a downstream C copy already in place, slice zeroization is best-effort at best and would not remove the existing copies; no memory-disclosure path is claimed or observed. Registry gap as in OQ7.

---

## Counts

| Disposition | Count | Questions |
|---|---|---|
| TREAT | **1** | D4 |
| TOLERATE | **4** | D2, D6, OQ7, OQ8 |
| TRANSFER | **0** | — |
| TERMINATE | **3** | D1, D3, D5 |
| **Total** | **8** | 6 with D-IDs + 2 unmapped |

Cross-references: item 41 is merged (`P3 + D2`) and appears once here for its `ReadPin` half; the `resolvePin` half belongs to that function's report. Item 3 (origin `run`) is referenced from D4 for the piped-stdin outcome but is not a `ReadPin`-origin question.

## Recommended worklist

1. **D4 (TREAT)** — decide the fate of the test-only generic branch (`main.go:388-394`) and the coverage inversion: the production terminal path (`main.go:380-386`) is untested while both tests exercise code `run` never reaches (`main.go:464` always passes `os.Stdin`). Either delete the branch, or pin the production path via fd-0 redirection (`term.ReadPassword` ignores `r` and reads fd 0, `syscall_unix.go:23`) or an exec-based test.
2. No other questions require repo work; D2/D6/OQ7/OQ8 residuals are recorded as accepted, and their remaining evidence (kernel `vhangup` path, runtime EINTR) is external or upstream.
3. **Registry hygiene (not a question disposition):** per-function OQ7 and OQ8 never received D-IDs, so a `ReadPin`-origin question is silently missing from the dossier index (`SONNET-INVESTIGATION.md:472`); fold them back so the registry matches the per-function record.

**Citation notes on the Sonnet excerpt:** its `x/term` line numbers drift — item 41 "`term_unix.go:~64-68`" vs actual `:70-71`; item 47 "`term_unix.go:~92-99`" vs actual `:88`. Item 43's panic texts, item 44's `git log -S` result, item 45's call sites, item 46's history, item 47's defer/single-call-site, and OQ7/OQ8 source facts all check out. Sonnet's item 3, 41 and 47 runtime results (pty, SIGINT, piped stdin) are un-re-executed here and are report-only.

Skipped: no pty/SIGINT or hardware runs (relied on Sonnet's report-only observations and on source); the generic-path behaviors were verified with a standalone replica, not the unimportable `package main`. Risk: D6's accepted residual (tty left echo-off after Ctrl-C at the prompt) is observed only on Sonnet's pty and is unverified against a real terminal + shell combination.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §2–§3. All temporary binaries, configs and traces were deleted; nothing retained.
- **D4 (45, row 45)** — TREAT is merged as option (b) for D-2/T-4: `TestReadPin_TerminalBranch` re-executes the test binary with stdin on `/dev/null`, asserting exit 1, empty stdout, and a prompt followed by `could not read PIN code: <non-empty cause>` on stderr. It does not pin the exact `ENOTTY` text. The generic branch was kept.
- **D2 (row 41)** — TOLERATE unchanged; `read(2)` returning `(0,nil)` forever after a root `vhangup` with SIGHUP ignored (the hot-spin path) remains third-party `x/term` and unfixed.
- The app-level PIN path was exercised on the real card (`ulPinLen=6` once) and over a live HTTPS login (exit 0); no `ReadPin`-specific hardware behaviour was observed.
