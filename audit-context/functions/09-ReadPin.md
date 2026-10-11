# ReadPin

## Function and source line range

- Doc comment: `main.go:376-377`; signature: `main.go:378`; body: `main.go:379-394`; closing brace: `main.go:395`.
- Declared in `package main` alongside the rest of the program (`main.go:1`), in the repo's only non-test Go file (`main.go` and `main_test.go` are the two Go files present).
- Imports used by the body: `fmt`, `io`, `os`, `strings`, `syscall`, `golang.org/x/term` (`main.go:3-23`; `x/term` pinned `go.mod:9`, `go.sum:53-54`).

## Purpose

Obtain a YubiKey PIV PIN as a string, from `-yubi` mode only. Two mutually exclusive read strategies, selected by an identity test on the reader argument (`main.go:380`):

1. terminal path — delegate to `term.ReadPassword` on fd 0 (`main.go:381`);
2. generic path — one `Read` into a 64-byte buffer (`main.go:388-389`).

The doc comment states the caller contract for the writer: prompt goes to `w`, and callers pass `os.Stderr`, so stdout carries only the token for `TOKEN=$(yubivault -yubi)` (`main.go:376-377`). The same contract is stated for users in `README.md:102` and asserted by a test (`main_test.go:319-323`).

The value produced here is the PIN the rest of `-yubi` mode uses: it is forwarded by the sole production caller `resolvePin` (`main.go:262`) and later reaches `crypto11.Config.Pin` in `CreateYubikeyVaultClient` (`main.go:484` → `main.go:280`). `ReadPin` itself performs no PKCS#11 work, no validation of PIN content, and no logging.

## Inputs & Assumptions (including trust sources)

Inputs, all parameters/local in scope:

- `yubikeySerial string` (`main.go:378`) — display label only; interpolated unescaped into the prompt string (`main.go:379`). Production value is `appConfig.YubikeySerial` (`main.go:262`), the YAML key `yubikeySerial` (`main.go:37`), read from `$HOME/.yubivault/config.yml` (`main.go:103-114`). **Established:** `requireForMode` does not require this field for `-yubi` (it requires only `openscPath` and `yubikeyPivSerial`, `main.go:149-152`), so the label may be empty and the prompt then reads `"PIN for : "`. **Established:** this is a different field from `YubikeyPivSerial`, which selects the PKCS#11 token (`main.go:279`).
- `r io.Reader` (`main.go:378`) — used **only** in the identity comparison `r == os.Stdin` (`main.go:380`) and as `r.Read` receiver on the generic path (`main.go:389`). Production value is `os.Stdin` (`main.go:464`, inside the `if *yubikeyFlag` guard at `main.go:463-467`). Trust: the invoking user's terminal / stdin stream. **Established:** tests pass non-`os.Stdin` readers (`bytes.NewBufferString` at `main_test.go:313`; `strings.NewReader` at `main_test.go:361,368`), so both paths exist in-repo; no test exercises the terminal path (no test call with `os.Stdin`; grep over `main.go`, `main_test.go` shows `ReadPin(` only at `main.go:262`, `main_test.go:315`).
- `w io.Writer` (`main.go:378`) — sole output sink (`main.go:379,382,390`). Production value `os.Stderr` (`main.go:464`). Trust: caller-supplied; `ReadPin` never writes to `os.Stdout` itself, which the test verifies by redirecting stdout (`main_test.go:315,321-323`).
- Implicit input: file descriptor 0. On the terminal path, `term.ReadPassword(int(syscall.Stdin))` reads fd 0, not `r` (`main.go:381`); `syscall.Stdin = 0` on unix (`$HOME/.go/src/syscall/syscall_unix.go:23`). **Established.**
- No environment variable is read inside `ReadPin`. `TOKEN_PIN` bypasses this function entirely, one level up (`main.go:259-261`).

Assumptions the body rests on:

- `r` is non-nil and satisfies the `io.Reader` contract, including `0 <= n <= len(bPin)` (`main.go:389`); `bPin[:n]` at `main.go:394` is sliced without a bounds check. **Assumed** (no validation in the function).
- One `Read` returns the whole PIN line on the generic path. **Assumed**; a reader delivering the line in chunks is silently truncated to the first chunk and to 64 bytes (`main.go:388-389,394`).
- On the terminal path, fd 0 is a terminal. **Assumed**; otherwise `unix.IoctlGetTermios` fails and `readPassword` returns the error without reading (`x/term@v0.47.0/term_unix.go:74-78`). `README.md:108` documents `TOKEN_PIN` as the non-interactive route, consistent with that.
- Write errors are non-events: the `error` results of `fmt.Fprint` (`main.go:379`) and `fmt.Fprintln` (`main.go:382,390`) are discarded (return values not captured), so a failed prompt cannot be reported. **Established by the source; the doc comment does not discuss it.**
- The caller supplies a prompt label safe to print. **Assumed**: the value from config is concatenated into the prompt with no escaping (`main.go:379`).

## Outputs & Effects

Return values:

- Terminal path, `ReadPassword` error → `("", err)` with the error returned unwrapped (`main.go:383-385`).
- Terminal path, success → `(strings.TrimSpace(string(bPin)), nil)` (`main.go:386`).
- Generic path, error other than `io.EOF` → `("", err)` unwrapped (`main.go:391-393`).
- Generic path, `io.EOF` (with any `n`, including `n == 0`) → `(strings.TrimSpace(string(bPin[:n])), nil)` (`main.go:391` excludes `io.EOF`, `main.go:394`).
- **Established invariant:** no path returns a non-empty PIN together with a non-nil error; both error paths pair `""` with the error (`main.go:384,392`). Wrapping into `could not read PIN code: %w` happens in the caller (`main.go:264`), not here.
- **Established:** every successful return is trimmed with `strings.TrimSpace`, so no leading/trailing Unicode whitespace; interior bytes are preserved verbatim.

Side effects:

- Writes `"PIN for " + yubikeySerial + ": "` to `w` before any read (`main.go:379`), unconditionally, on both paths.
- Writes a `"\n"` to `w` after the read attempt on both paths (`main.go:382,390`) — **including** the error paths, because the newline is emitted before the error check.
- Terminal path: transient termios mutation on fd 0 — ECHO cleared, `ICANON|ISIG` set, `ICRNL` set before reading, restored via `defer` on return (`x/term@v0.47.0/term_unix.go:80-88`). Terminal input is therefore not echoed while the PIN is typed, and `ISIG` means Ctrl-C generates SIGINT rather than a byte (`term_unix.go:82`).
- No package-level mutable state is touched; the only package-level var in `main.go` is `Version` (`main.go:26`), used solely by the `-version` branch (`main.go:436,439-441`), unreachable from `ReadPin`.
- No persistence, no env mutation, no logging of the PIN, and no zeroization of the intermediate `bPin` byte slice from `term.ReadPassword` (`main.go:381,386`) or of the 64-byte buffer (`main.go:388`). **Established by source** — the buffers are left to the GC.

## Block-by-Block

**L379 — prompt.** `fmt.Fprint(w, "PIN for "+yubikeySerial+": ")`. Runs before any read, on both paths. Return values ignored. No newline; the newline comes after the read.

**L380 — path selection.** `if r == os.Stdin`. Pointer identity of the package-level `*os.File` (`main.go:380`), not fd comparison and not `term.IsTerminal`. Comment/doc do not describe this branch condition; it is established only by the source and by the call sites (`main.go:464` passes `os.Stdin`; tests pass other readers).

**L381-386 — terminal path.**

- `term.ReadPassword(int(syscall.Stdin))` (`main.go:381`): argument is fd 0 via `syscall.Stdin` (= 0, `syscall_unix.go:23`), so `r` itself is never read on this path even when it is `os.Stdin`.
- Callee chain (external, source-available): `term.ReadPassword` → `readPassword(fd)` (`x/term@v0.47.0/term.go:58-60`) → `unix.IoctlGetTermios(fd, ioctlReadTermios)` (`term_unix.go:75`), which returns `(nil, err)` without reading when fd 0 is not a terminal (`term_unix.go:76-78`); ECHO cleared and `ICANON|ISIG`/`ICRNL` set (`term_unix.go:80-83`); termios restored by `defer` on return (`term_unix.go:88`); then `readPasswordLine(passwordReader(fd))` (`term_unix.go:90`), where `passwordReader.Read` is `unix.Read(int(r), buf)` on a 1-byte buffer (`term_unix.go:68-71`, `terminal.go:1051`).
- `readPasswordLine` (`terminal.go:1050-1083`) loop behavior: `\b` deletes the last accumulated byte (`1058-1061`); `\n` returns the accumulated bytes with `nil` on non-Windows (`1062-1065`); `\r` is ignored off Windows (`1067-1071`); other bytes are appended (`1072-1074`); `n == 0 && err == nil` loops again (`1075-1083`); on `err == io.EOF` with accumulated bytes it returns them with `nil` (`1078-1080`); any other error returns `(ret, err)` (`1081`). Consequently the terminal result excludes the terminating newline and applies backspace; the `TrimSpace` at `main.go:386` is defensive for the normal case.
- `fmt.Fprintln(w)` (`main.go:382`) emits the newline before the error branch, so the error path also moves the terminal cursor to the next line.
- `if err != nil { return "", err }` (`main.go:383-385`): error is returned as-is, unwrapped; no partial PIN is returned. Sources of this error include termios failures (`term_unix.go:76-78,84-86`) and read errors surfaced by `readPasswordLine` (`terminal.go:1081`), e.g. an interrupted read.
- Success: `strings.TrimSpace(string(bPin))` (`main.go:386`). No length cap is imposed by this function on this path; the kernel tty line discipline constrains how much is accumulated [INFERENCE: canonical-mode line limit, not in this source].
- Interaction with signals: `run` calls this path *before* installing any signal handler (`main.go:460-467` precedes `signal.NotifyContext` at `main.go:474`), and the comment at `main.go:460-461` records that this ordering is deliberate so the blocking prompt stays killable by Ctrl-C. Because `ISIG` is set (`term_unix.go:82`), Ctrl-C at the prompt does not produce a byte; whether the process dies by default SIGINT disposition (skipping the `defer` termios restore at `term_unix.go:88`) or the read returns an error instead is not decided by `ReadPin`'s source — see Open Questions.

**L388-394 — generic path (any `r` that is not the `os.Stdin` pointer).**

- `bPin := make([]byte, 64)` (`main.go:388`): one fixed 64-byte heap buffer; **the size has no named constant and no comment explaining the choice**.
- `n, err := r.Read(bPin)` (`main.go:389`): exactly one `Read`; no loop, no retry, no `io.ReadFull`, so short reads are accepted as-is. The returned `n` is trusted for the slice at `main.go:394`.
- `fmt.Fprintln(w)` (`main.go:390`): newline written before the error branch, same as the terminal path.
- `if err != nil && err != io.EOF { return "", err }` (`main.go:391-393`): `io.EOF` is the only tolerated error. With `io.EOF` and `n > 0`, the bytes read are still returned (`main.go:394`); with `io.EOF` and `n == 0`, the empty string is returned with a nil error, and the caller's empty check then rejects it (`main.go:266-268`).
- Success: `strings.TrimSpace(string(bPin[:n]))` (`main.go:394`) — at most 64 bytes of the reader's first chunk, trimmed. Truncation of a longer line is silent.
- Reachability: production never reaches this path (`run` always passes `os.Stdin`, `main.go:464`); the in-repo exercisers are tests (`main_test.go:315` with `bytes.NewBufferString("123456\n")` expecting `"123456"`, `main_test.go:361,368` with `strings.NewReader`). **Established** by grep over the repository: `ReadPin(` occurs only at `main.go:262` and `main_test.go:315`.

## Cross-Function Dependencies

Callees (all leaf-level; `ReadPin` calls nothing else):

- `fmt.Fprint` / `fmt.Fprintln` (`main.go:379,382,390`) — stdlib; errors ignored.
- `os.Stdin` (`main.go:380`) — package-level `*os.File` for fd 0; used for pointer identity only.
- `term.ReadPassword` (`main.go:381`) — `golang.org/x/term v0.47.0` (`go.mod:9`); behavior as detailed above, including the `unix.*` syscalls it makes through `golang.org/x/sys v0.49.0` (`go.mod:24`, indirect).
- `syscall.Stdin` (`main.go:381`) — constant `0` on unix (`$HOME/.go/src/syscall/syscall_unix.go:23`).
- `strings.TrimSpace` (`main.go:386,394`) — stdlib; no error path.
- `r.Read` (`main.go:389`) — interface dispatch; dynamic type is caller-supplied (`*os.File`, `bytes.Buffer`, `strings.Reader` in-repo).

Callers:

- `resolvePin` (`main.go:258-271`) — sole production/in-repo caller of `ReadPin`, at `main.go:262`, forwarding `appConfig.YubikeySerial`, `in`, `prompt`. It wraps `ReadPin` errors as `could not read PIN code: %w` (`main.go:263-265`), re-applies `strings.TrimSpace` (`main.go:266`) and rejects the empty result with `need to enter PIN or set via $TOKEN_PIN` (`main.go:267-269`). It short-circuits on a non-empty `TOKEN_PIN` (`main.go:259-261`), so `ReadPin` is not reached at all in that case. Its own trimming is redundant with `ReadPin`'s for the current implementation.
- `run` → `resolvePin` (`main.go:463-467`), only under `-yubi` (`main.go:435,463`), passing `os.Stdin` and `os.Stderr`; errors propagate out of `run` unchanged (`main.go:464-466`) and are printed by `log.Fatal` in `main` (`main.go:423-426`).
- Tests: `TestReadPin_Mock` (`main_test.go:312-328`, generic path, call at `main_test.go:315`, asserts `"123456"`, asserts stdout stayed empty via `captureStdout` at `main_test.go:331-347`, asserts the prompt writer received the label at `main_test.go:324-326`); `TestResolvePin` (`main_test.go:358-371`) exercises `ReadPin`'s generic path indirectly through `resolvePin` (`main_test.go:361,368`). No test drives the terminal path.

Shared state and downstream flow:

- The only shared state touched is the process's fd 0 termios while `ReadPassword` runs (`term_unix.go:80-88`); no file, env var, or package variable is mutated.
- The produced PIN string is passed by value into `CreateYubikeyVaultClient(appConfig, tokenPin)` (`main.go:484` → `main.go:273`) and becomes `crypto11.Config.Pin` (`main.go:280`), which crypto11 passes to `C_Login`. `ReadPin` has no knowledge of that consumer; the contract it must satisfy is only "non-empty after the caller's checks".

## Open Questions

1. **Signal behavior at the prompt.** `run` installs `signal.NotifyContext` only after `resolvePin` returns (`main.go:463-467` vs `main.go:474`), and the comment at `main.go:460-461` says this is so the prompt remains killable by Ctrl-C. Whether SIGINT during `readPasswordLine`'s `unix.Read` terminates the process by default disposition (leaving fd 0 with ECHO cleared, since the `defer` at `term_unix.go:88` would not run) or returns an error through `main.go:383-385` is not established by the repository source; no test or comment records the observed runtime behavior.
2. **Zero-length reads on a tty.** `passwordReader.Read` is a raw `unix.Read` (`term_unix.go:70-71`), and `readPasswordLine` continues the loop when `n == 0 && err == nil` (`terminal.go:1075-1083`). Whether a tty hangup or Ctrl-D can produce a repeating `(0, nil)` read — and whether `ReadPassword` can therefore fail to terminate — is not established here. **[2026-10-11: `(0,nil)` is possible — after a root `vhangup` with SIGHUP ignored, `read(2)` returns it indefinitely and the loop spins (≈1 core). Third-party `x/term`, not repo-owned; row 41 (P3+D2), TOLERATE. The path was not re-run against the binary for this note.]**
3. **`bPin[:n]` bounds.** What `n` a non-conforming `io.Reader` may return relative to `len(bPin) == 64` is unchecked (`main.go:389,394`); the behavior for `n < 0` or `n > 64` is not established by this source.
4. **Why 64 bytes.** The 64-byte cap on the generic path (`main.go:388`) has no constant, comment, or documented limit, and has no counterpart on the terminal path, which imposes no cap of its own.
5. **Newline on the error path.** `fmt.Fprintln(w)` at `main.go:382` and `main.go:390` precedes the error checks, so a failed read still writes a newline. Whether that is intended is not stated in the doc comment (`main.go:376-377`).
6. **Reachability of the generic path in deployments.** One `Read` into 64 bytes is meaningfully different from a terminal line read, and the only in-repo callers of the generic path are tests (`main_test.go:315,361,368`); whether any external consumer uses the exported function (it is exported at `main.go:378`) with a non-`os.Stdin` reader is unknown.
7. **Prompt-label content.** `yubikeySerial` reaches `w` unescaped (`main.go:379`) and, per `requireForMode` (`main.go:149-152`), may be empty; whether config authors are expected to keep it control-character-free is not stated anywhere found (`README.md:71` describes the field only as "shown in the PIN prompt").
8. **Buffer lifetime.** The intermediate `[]byte` from `ReadPassword` (`main.go:381`) and the 64-byte buffer (`main.go:388`) are not zeroized; whether callers consider that acceptable is not recorded in code or docs.

---

Ponytail note: I did not execute the binary at an interactive prompt (no tty PIN entry exercised), so all terminal-path runtime claims come from `x/term@v0.47.0` source, and the SIGINT-at-prompt behavior in Open Question 1 is the main unverified risk.
