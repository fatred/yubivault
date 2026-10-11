# resolvePin

## Function and scope

`resolvePin` (main.go:258-271, documented at 256-257) has one job: produce the YubiKey PIV PIN for `-yubi` mode. It has two and only two sources, in fixed order — the `TOKEN_PIN` environment variable (main.go:259-261) and an interactive prompt handled by `ReadPin` (main.go:262-265, 266-270). It is unexported and has exactly one production caller, `run` (main.go:464), which invokes it only when the `-yubi` flag is set (main.go:435, 463-467). It performs no I/O of its own beyond `os.Getenv`; all prompting and reading happen in `ReadPin`.

The scope that matters for behaviour is the trio: precedence (env wins unconditionally), normalisation (trim on the prompt path only), and the empty-result check (main.go:266-269). Nothing here validates the PIN's length or alphabet; that is left to the card.

## Inputs and outputs

Inputs:
- `appConfig *AppConfig` (main.go:258) — used for one field only, `appConfig.YubikeySerial`, forwarded to `ReadPin` as the prompt label (main.go:262). This is not the same field as `YubikeyPivSerial`, which selects the token later (main.go:279).
- `in io.Reader` (main.go:258) — forwarded to `ReadPin`; in production it is `os.Stdin` (main.go:464). `ReadPin` compares it against `os.Stdin` by identity (main.go:380) and, on a match, reads fd 0 through `term.ReadPassword` instead of reading `in`.
- `prompt io.Writer` (main.go:258) — forwarded to `ReadPin`; in production `os.Stderr` (main.go:464).
- Implicit: the process environment (main.go:259).

Outputs:
- `(string, error)`. Environment path: the raw `TOKEN_PIN` value with `nil` error (main.go:260). Prompt path: the `ReadPin` result after `strings.TrimSpace`, `nil` error (main.go:266,270). Errors: `could not read PIN code: %w` when `ReadPin` fails (main.go:264) and `need to enter PIN or set via $TOKEN_PIN` when the trimmed result is empty (main.go:268). Both are produced by `fmt.Errorf` with `%w`, and neither embeds the PIN (main.go:264,268). The caller returns the error unchanged (main.go:464-466) and `log.Fatal` prints it to stderr with a non-zero exit (main.go:424-425).

The result flows into `CreateYubikeyVaultClient` (main.go:484) and becomes `crypto11.Config.Pin` (main.go:280).

## Invariants

1. Precedence: a non-empty `TOKEN_PIN` short-circuits before any prompt or read (main.go:259-261); `in` and `prompt` are not referenced on that path, and no prompt text is emitted. The subtest at main_test.go:359-365 encodes this by putting `999999\n` on stdin and asserting the env value `654321` comes back.
2. Non-emptiness on every successful return (main.go:259, 266-269). Downstream, `ResolvePin`'s result is therefore feedable to `C_Login` without a zero-length PIN; the pkcs11 shim's `pinLen == 0 ⇒ NULL` conversion (pkcs11.go:258-262) is not reachable from here.
3. Prompt-path trimming: the value has no leading/trailing Unicode whitespace, because `strings.TrimSpace` runs inside `ReadPin` (main.go:386 terminal path, main.go:394 generic path) and again in `resolvePin` (main.go:266).
4. Environment path is verbatim: no trimming, no length cap, no charset check (main.go:260). A whitespace-only `TOKEN_PIN` therefore passes the guard and is returned as-is, whereas the same string typed at the prompt is rejected at main.go:267. **[2026-10-11: superseded — the env path now `strings.TrimSpace`s the value (`main.go:269`) and, when whitespace-only, falls through to the prompt (`TestResolvePin`). No length or charset check was added. A whitespace-padded PIN therefore reaches `C_Login` trimmed; on the real card it arrived as six bytes (`ulPinLen=6`), and an embedded-NUL PIN (`ulPinLen=7`, `CKR_PIN_INCORRECT`) was sent only to a disposable SoftHSM token, never the card. Row 40 (P2).]**
5. Env unset and env-set-to-empty are indistinguishable (main.go:259 fills `""` in both cases); the test at main_test.go:366-370 exercises the empty case.
6. No environment mutation, and no removal of `TOKEN_PIN` after use (only `os.Getenv` at main.go:259; no `Setenv`/`Unsetenv` in main.go).
7. stdout stays clean: the prompt is written to `prompt` only (main.go:379), and production passes stderr (main.go:464); asserted at main_test.go:315-323.

## Assumptions

- `appConfig` is non-nil: `run` returns early on `LoadConfig` failure (main.go:453-456) and `LoadConfig` returns a non-nil `*AppConfig` whenever it returns a nil error (main.go:103-136).
- `YubikeySerial` is a label, not a selector: the code only interpolates it into the prompt (main.go:379) and README:71 calls it 'optional: shown in the PIN prompt'.
- A caller-set `TOKEN_PIN` already is the exact PIN; the code strips nothing on that path (main.go:260), and the docs make no whitespace claim (README:108).
- The value of `TOKEN_PIN` is chosen by whoever controls the environment; nothing in the program validates or authenticates it (main.go:259; no other reader of the variable in the repo).
- On the generic (non-`os.Stdin`) path, `ReadPin` performs exactly one `Read` into a 64-byte buffer (main.go:388-389) and slices `bPin[:n]` (main.go:394), so 'the full typed line' holds only up to 64 bytes there; that path is reached only from tests (main_test.go:361,368), since production always passes `os.Stdin` (main.go:464).
- `in` and `prompt` are non-nil and distinct from each other; `in` is compared by identity to `os.Stdin` (main.go:380).
- On released builds the terminal path is the unix one: release.yml:18-27 builds only linux/amd64 and darwin/arm64.

## Calls

- `os.Getenv` (main.go:259) — cannot fail; `""` means either unset or empty, and both fall through.
- `ReadPin` (main.go:262, internal main.go:378-395):
  - writes the prompt to `w` and ignores that write error (main.go:379);
  - if `r == os.Stdin`, calls `term.ReadPassword(int(syscall.Stdin))` (main.go:381), prints a newline to `w` (main.go:382), returns the error unchanged if any (main.go:383-385), else `strings.TrimSpace(string(bPin))` (main.go:386);
  - otherwise reads once into 64 bytes, prints a newline, treats `err != nil && err != io.EOF` as fatal (main.go:391-393), and returns `strings.TrimSpace(string(bPin[:n]))` (main.go:394).
  - contract resolvePin relies on: an error whenever no PIN could be obtained (terminal path) and a whitespace-trimmed value otherwise. The error is wrapped at main.go:264.
- `term.ReadPassword` (external, golang.org/x/term v0.47.0, pinned at go.mod:8): `term.go:58-60` calls `readPassword(fd)`; `term_unix.go:74-91` reads termios (failing at 75-78 when fd 0 is not a terminal — so piped stdin without TOKEN_PIN always errors, which is what README:108 tells users to work around), clears ECHO and sets ICANON|ISIG|ICRNL (80-83), restores termios via defer (88), and reads a line in `terminal.go:1050-1084` (newline excluded, backspace handled, `\r` ignored off Windows).
- `strings.TrimSpace` (main.go:266, and inside ReadPin at 386/394) — no error path; makes the check at main.go:267 catch whitespace-only input.
- `fmt.Errorf` (main.go:264,268) — `%w` wrapping; no PIN in either message.
- Downstream, not called here: `run` (main.go:484) → `CreateYubikeyVaultClient` (main.go:273) → `crypto11.Configure` (main.go:277-281) → `Ctx.Login` on the persistent session (crypto11.go:467-471, with `UserType` defaulted to 1 at crypto11.go:115 and 417-418) → `pkcs11.Ctx.Login` → `C.Login` with `CString(pin)`/`len(pin)` (pkcs11.go:1049-1053; C shim at pkcs11.go:258-266). Failure closes the crypto11 context and returns an error (crypto11.go:472-480) that surfaces as `could not configure crypto11: %w` (main.go:282-284).

## Callers and shared state

Only `run` (main.go:463-466) calls `resolvePin` in production, under `-yubi`; the two test subtests (main_test.go:361,368) call it directly. `run` installs its `signal.NotifyContext` handler only after `resolvePin` returns (main.go:460-471) — a deliberate ordering, since the prompt blocks inside `term.ReadPassword` and must remain killable by Ctrl-C.

Shared state touched: the process environment (`TOKEN_PIN`, read-only here, set by tests via `t.Setenv`); fd 0's termios during the terminal read, changed and restored inside `term.ReadPassword` (term_unix.go:80-88); and, indirectly, the card's PIN retry counter, which is spent by the single `C_Login` that consumes the returned value (crypto11.go:467-471). stdout is not part of the shared state on either path (main.go:379, 464).

## Open questions

- Does any in-process code other than `resolvePin` read `TOKEN_PIN` — notably the PKCS#11 module at `appConfig.OpenScPath` (main.go:278)? unclear; need to inspect the module binary or OpenSC source, neither of which is in this repository (the doc comment/README only document the variable for the prompt (README:108)).
- How does OpenSC's PIV module treat a PIN containing spaces, newlines or NUL bytes coming from the environment (main.go:260 forwards them verbatim)? unclear; need to inspect OpenSC's `C_Login`/ykcs11 implementation. **[2026-10-11: the env value is now trimmed (`main.go:269`). On the real card a whitespace-padded PIN reached `C_Login` as six bytes (`ulPinLen=6`); an embedded-NUL PIN (`ulPinLen=7`, `CKR_PIN_INCORRECT`) went only to a disposable SoftHSM token, never the card. Row 40 (P2), TRANSFER.]**
- Can `readPasswordLine`'s retry loop (terminal.go:1050-1084) spin without blocking after a pty hangup or Ctrl-D on Linux? unclear; needs a pty-level experiment.
- Do crypto11's pooled sessions log in again with the configured `Pin`? unclear; the package shows only two `Ctx.Login` sites (crypto11.go:468,470), but the session-pool code was not read in full.

_Unchecked: the pinned PKCS#11 module binary and OpenSC behaviour, and the crypto11 session pool. Risk: both `TOKEN_PIN` and prompt input reach the card byte-for-byte with no validation beyond the non-empty check, so any stray whitespace or terminator in the variable is passed on as typed._
