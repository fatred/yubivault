# resolvePin — adversarial disposition review (Sonnet items 39–42)

Scope: all open questions originating in `resolvePin` (`main.go:258-271`), including item 41 which is merged with `ReadPin`. Dispositions assigned; no repo edits.

## Verification pass (what I re-derived myself, not taken from either report)

Source, re-read and confirmed:
- `resolvePin` body: env path verbatim `return tokenPin, nil` (`main.go:259-261`); prompt path `ReadPin` → `strings.TrimSpace` → `tokenPin == ""` guard (`main.go:262-270`). Whitespace-only `TOKEN_PIN` passes the guard because the test is `!= ""` (`main.go:259`) with no trim on that path. Confirmed by reading source.
- Only reader of `TOKEN_PIN` in the repo is `main.go:259`; the only other occurrences are `main_test.go:360,367` (`t.Setenv`) and docs (`README.md:108`, `audit-context/`). No `Setenv`/`Unsetenv` in `main.go` — confirmed by `grep -rn "TOKEN_PIN|Unsetenv|Setenv"`.
- Repo callers: `run` under `-yubi` (`main.go:463-467`), which installs `signal.NotifyContext` only *after* `resolvePin` returns (`main.go:474-476`) — confirmed.
- `miekg/pkcs11@v1.1.2` (in `go.mod:16` as indirect): `Ctx.Login` at `pkcs11.go:1049-1053` — `p := C.CString(pin)` … `C.Login(..., p, C.CK_ULONG(len(pin)))`; C shim `pkcs11.go:258-266` converts `pinLen == 0` to `NULL`. Exact, matches Sonnet.
- `github.com/eclipse-keypont/crypto11@v1.6.8` (direct, `go.mod:6`): the **only** `Login` call sites in the module are `crypto11.go:468,470`, both on `instance.persistentSession`; `Configure` opens that session then logs in unless `LoginNotSupported` (`crypto11.go:461-481`); `UserType` default 1 (`crypto11.go:115`, `400-418`). Session-pool factory at `sessions.go:81-88` calls only `OpenSession` (`sessions.go:83`) — confirmed; there is no second login path.
- `golang.org/x/term@v0.47.0` (pinned `go.mod:9`): `readPasswordLine` at `terminal.go:1050-1084`; the loop `continue`s only when `n == 0 && err == nil` (`terminal.go:1078-1082`); `passwordReader.Read` = `unix.Read` (`term_unix.go:70-72`; Sonnet's "~64-68" is off by a few lines, immaterial); `readPassword` at `term_unix.go:74-91` fails at `75-78` if fd 0 is not a terminal, clears ECHO / sets ICANON|ISIG|ICRNL at `81-83`, restores at `88`.

Local experiments I ran (pty-level, no YubiKey, no Vault/server; scratch harness deleted afterwards):
- **Ctrl-D (VEOF) at an empty prompt, raw `unix.Read` on a pty:** `read#0 n=0 err=<nil>`, then the next read blocks and later returns the typed line; process CPU delta **0 ticks over 2 s**. So `read(2)` *does* return `(0,nil)`, but the x/term loop does **not** spin on a live terminal.
- **Master close (pty hangup):** default SIGHUP → child killed; SIGHUP ignored → `read#1 n=-1 err=input/output error`, loop exits. No spin.
- **`vhangup()` (root) with SIGHUP ignored:** `read(2)` returned `(0,nil)` **forever** — 573,197 iterations in 2.0 s, cpu 186 ticks ≈ one core. This is the path Sonnet left un-exercised, and it is a genuine hot loop.
- **Typed NUL on the prompt path (Ctrl-@):** `term.ReadPassword` returned `raw="\x00123456" len=7`; `strings.TrimSpace` does not strip NUL, so the value reaching `resolvePin` still contains it.

Report-only (from Sonnet, not reproduced here): the `pkcs11-spy`/SoftHSM observation of 1× `C_Login` across 4× `C_OpenSession`, and the spy module logging the PIN as the `C_Login` argument. Hardware/card behaviour was not tested by me or, per the excerpt, by Sonnet.

---

## Item 39 — P1: does anything else loaded into the process read `TOKEN_PIN`?

- **Sonnet ID / origin:** 39 (P1, origin `resolvePin`). Sonnet mark: *External-unknown*.
- **Original question:** Does any in-process code other than `resolvePin` read `TOKEN_PIN` — notably the PKCS#11 module at `appConfig.OpenScPath` (`main.go:278`)?
- **Sonnet's disposition/evidence:** repo reads it only at `main.go:259`; no `os.Unsetenv`, so it persists for process lifetime; a spy module received the PIN as the `C_Login` argument and logged it. Remaining: OpenSC source or behaviour.
- **My assessment:** Sonnet's repo claim is correct (verified: single read site; no env mutation). I closed most of the external residue:
  - `grep -rIl "TOKEN_PIN"` over the entire Go module cache (`/home/jhow/go/pkg/mod`) returned **only** `github.com/fatred/yubivault@v1.3.0/main.go` and `.../main_test.go` — i.e. yubivault itself. None of `crypto11@v1.6.8`, `miekg/pkcs11@v1.1.2`, `x/term@v0.47.0`, `vault-client-go@v0.4.3` references it.
  - Installed OpenSC **0.26.1-2**: neither `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` nor `libopensc.so.12.0.2` contains the string `TOKEN_PIN`; `libopensc`'s only env knobs are `OPENSC_DEBUG`, `OPENSC_CONF`, `OPENSC_DRIVER`. So the documented module does not read it.
  - Sonnet's spy observation shows the PIN arriving as the `C_Login` argument, i.e. the module already receives the secret by design; reading `TOKEN_PIN` would add nothing.
  - Note the module path is **operator-supplied config** (`OpenScPath`), so a non-OpenSC module could in principle read the env; but the env is inherited by exactly the module that already gets the PIN as a plaintext argument, so the incremental exposure is nil, and TOKEN_PIN's persistence is a deliberate property (it is read, not unset, and no child processes are spawned).
- **Final disposition: TOLERATE**
- **Rationale:** Question answered for every library and module actually loaded (repo, all direct+indirect Go deps, shipped OpenSC). Residual (arbitrary operator-chosen module + intentional env persistence) is a non-incremental exposure with no repo-side action; unsetting the variable is not required to close any real gap.
- **Owner/evidence needed:** n/a (residual owner would be the operator who substitutes `OpenScPath`).

## Item 40 — P2: how does OpenSC's PIV module treat a PIN with spaces, newlines or NULs?

- **Sonnet ID / origin:** 40 (P2, origin `resolvePin`). Sonnet mark: *External-unknown*.
- **Original question:** How does OpenSC's PIV module treat a PIN containing spaces, newlines or NUL bytes, given the env path forwards the raw value?
- **Sonnet's disposition/evidence:** env value forwarded verbatim (`main.go:259-260`); `miekg Login` passes full `len(pin)` and a C string copy (`pkcs11.go:1049-1053`); NUL cannot occur in an environment value; a typed NUL on the prompt path is possible `[INFERENCE]`. Remaining: module `C_Login` behaviour.
- **My assessment:** The repo-side half is verified exactly (`main.go:259-260` raw; `pkcs11.go:1050-1052` `CString` + `len(pin)`; C shim `pkcs11.go:258-266` passes `pinLen` through, using `NULL` only for length 0). The "NUL cannot occur in an env value" claim is correct (execve env strings are NUL-terminated), and the typed-NUL inference is now **verified locally**: Ctrl-@ yields `raw="\x00123456" len=7` through `term.ReadPassword`, and neither `ReadPin`'s nor `resolvePin`'s `TrimSpace` removes NUL — so the C string handed to `C_Login` has an embedded NUL at offset 0 while `pinLen` counts the trailing bytes. What the module/card does with that (strlen vs `pinLen`, trailing-whitespace handling, PIV VERIFY padding) is not determinable from this repo and was not hardware-tested. This is not a repo defect: the repo has no validation because the PIN alphabet/length is a card property.
- **Final disposition: TRANSFER**
- **Rationale:** The decision and the evidence belong to the module/card owner: whether `C_Login` honours `pinLen` or `strlen`, and whether a PIN with trailing whitespace/NUL is rejected as `CKR_PIN_INCORRECT` (which would spend a YubiKey retry attempt). Nothing in the repo can answer or change it beyond the (repo-owned, deliberately absent) choice to validate the env value.
- **Owner/evidence needed:** OpenSC maintainers/card owner — read `ykcs11`/`pkcs15-login` handling of `pPin`/`ulPinLen` (does it use `strlen`, does it pad the PIV PIN to 8 bytes), plus PIV applet behaviour on whitespace-padded PINs; the local evidence to supply is the Ctrl-@ NUL reproduction above (pty-level, no card needed) and a `pkcs11-spy` capture of a whitespace-suffixed `TOKEN_PIN`.

## Item 41 — P3 + D2: `readPasswordLine` retry-loop spin / `read(2)` returning `(0,nil)`

- **Sonnet ID / origin:** 41 (P3 + merged D2; origins `resolvePin`, `ReadPin`). Sonnet mark: *Partly*.
- **Original question:** Can the retry loop spin without blocking on Ctrl-D or after a pty hangup, and can `read(2)` return `(0,nil)`?
- **Sonnet's disposition/evidence:** loop `continue`s on `n==0 && err==nil` (`terminal.go:1050-1083`), reader is `unix.Read`; observed Ctrl-D → alive, 0 CPU ticks, later accepted a line; master close with default SIGHUP → killed; with SIGHUP ignored → rc=1 promptly, no spin. Remaining: a `vhangup`/`tty_hung_up_p` path was not exercised.
- **My assessment:** Sonnet's source reading and its three Linux observations are **reproduced independently** by my clean pty harness (Ctrl-D: 0 CPU ticks then the line accepted; master close: SIGHUP kill, or `EIO` with SIGHUP ignored → loop exits). The un-exercised path turns out to be the one that matters: after `vhangup()` (root-only, e.g. deliberate session teardown) with SIGHUP ignored, `read(2)` returns `(0,nil)` indefinitely and the loop becomes a hot spin — 573,197 iterations in 2.0 s, ≈1 core (cpu 186 ticks). Logically this is also required for account-teardown workflows: `vhangup()` exists to stop a superseded terminal's reader. Trigger requirements: (i) a root/`CAP_SYS_TTY_CONFIG` `vhangup` of the controlling terminal, and (ii) SIGHUP not killing the process — which happens when the disposition is inherited `SIG_IGN` (e.g. launched from a SIGHUP-ignoring parent such as `nohup`-style wrappers), since yubivault never installs a `SIGHUP` handler and the default action would otherwise kill it. Consequence: a pegged CPU until the process is killed or the fd changes; no data loss, no card interaction (the spin precedes `C_Login`). The fix cannot live in this repo — the loop is third-party code (`x/term@v0.47.0/terminal.go:1078-1082`) and vendoring it to add an `n==0 && err==nil` break is disproportionate for a root-triggered scenario.
- **Final disposition: TOLERATE**
- **Rationale:** Answered by source + local pty evidence; the only residual is a third-party infinite loop reachable solely via root `vhangup` plus an inherited `SIG_IGN` on SIGHUP, with a benign failure mode. No repo-owned action is proportionate; a one-line process-level mitigation is available to maintainers if they ever want it, but it is a policy decision, not a required task. Sonnet's "no spin" conclusion is correct for the paths it tested but incomplete: the spin is real on the untested path, and this is the one material correction to its report.
- **Owner/evidence needed:** n/a. (If ever escalated, the evidence is the recorded `vhangup` reproduction: repeated `(0,nil)` reads + CPU ticks, above.)

## Item 42 — P4: do PKCS#11 pool sessions log in again with the same `Pin`?

- **Sonnet ID / origin:** 42 (P4, origin `resolvePin`). Sonnet mark: *Answered*.
- **Original question:** Do crypto11's pooled sessions log in again with the configured `Pin` (spending further retry-counter attempts)?
- **Sonnet's disposition/evidence:** only login sites are `crypto11.go:468,470` on the persistent session; the pool factory only calls `OpenSession` (`sessions.go:82-88`); observed via `pkcs11-spy`/SoftHSM exactly 1× `C_Login` across 4× `C_OpenSession`. Scope: SoftHSM semantics; OpenSC login-state sharing not checked.
- **My assessment:** Source claim fully verified: the module contains exactly two `Login` call sites (`crypto11.go:468,470`), both on `instance.persistentSession` inside `Configure`, guarded by `LoginNotSupported`; the pool factory is `sessions.go:81-88` and calls `OpenSession` only (`sessions.go:83`). No other code path logs in, so no re-login and no additional retry-counter spend. The spy observation is Sonnet's, reported only — but the conclusion does not depend on it: it follows from the source, and the module explicitly maintains a persistent logged-in session precisely so that pooled sessions inherit the token's login state (`crypto11.go:461-463` comment). Cross-module login-state sharing is PKCS#11 spec behaviour (login state is per application+token, shared by that application's sessions); OpenSC-specific confirmation remains external but carries no repo risk, because a module that does *not* share state cannot cause a re-login — it would fail the operation with `CKR_USER_NOT_LOGGED_IN` instead.
- **Final disposition: TERMINATE**
- **Rationale:** Answered (and now source-verified, not merely observed): exactly one `C_Login` per process, on the persistent session, from the single use of the PIN. The question is closed; no residual that affects the retry counter.
- **Owner/evidence needed:** n/a.

---

## Counts per disposition

| Disposition | Count | Items |
|---|---|---|
| TREAT | 0 | — |
| TOLERATE | 2 | 39, 41 |
| TRANSFER | 1 | 40 |
| TERMINATE | 1 | 42 |

## Recommended worklist

1. **No TREAT items** — nothing in `resolvePin` requires a repo-owned follow-up task.
2. **Transfer (40):** raise with OpenSC/card owner: how `C_Login` uses `pinLen` vs NUL termination, and how PIV VERIFY treats trailing whitespace. Supplying evidence, not asking: the local Ctrl-@ reproduction (`raw="\x00123456" len=7` via `x/term`) plus a `pkcs11-spy` capture of a `TOKEN_PIN` with a trailing space. Until answered, keep the documented advice as-is (README:108) and do not "fix" it by trimming the env path — that is a maintainer policy decision, not a defect.
3. **Note only (41):** record the exact `vhangup` + inherited-`SIG_IGN` trigger for the `x/term` hot loop in the audit notes; the loop is third-party and unfixable here without vendoring. Escalate only if maintainers want the process-level SIGHUP-disposition mitigation.
4. **Close (39, 42):** no action; evidence is in-repo/dependency/binary-checkable.

Skipped: no YubiKey, card, OpenSC `C_Login`, or live Vault interaction was exercised — item 40's card-side and module-side behaviour remains transfer-only, and Sonnet's SoftHSM spy observation is reproduced nowhere here (report-only). Risk to note: the one behaviour I found that neither report states is the real `vhangup`-triggered CPU spin, benign but unbounded.
