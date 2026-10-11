# Open-question review: aggregate disposition

**Inputs read:** `audit-context/DOSSIER.md`, `audit-context/review/SONNET-INVESTIGATION.md`, and all 12 reports in `audit-context/review/functions/` (`01-run.md` … `12-newVaultClient.md`, called "DeepSeek reports" below).

**Evidence tags used in this review:**
- **[repo]**: repository source, tests, docs or commits. Anyone can re-read these.
- **[mod]**: pinned module source in the local module cache. It can be re-read, but it is not part of the repo.
- **[agent]**: a scratch or live run that an agent reports. No artifact of the run exists in the repo. Sonnet states that its scratch files were removed. The DeepSeek scratch directories were also deleted.
- **[synth]**: I re-read it myself for this synthesis. I only read files. I ran no tests or binaries.

**My spot checks [synth]:**
- `main.go:60-80`, `:100-215`, `:273-375`, `:376-515`
- `README.md:45-115`
- `go.mod:1-12`
- `main_test.go` grep for `SetTokenErr`, `TestLoadConfig_ValidFile`, `TestLoginAndClose_ClosesOnFailure` and `TestNewVaultClient_RetriesOnce`
- `vault-client-go@v0.4.3 response.go:118-162` and `client.go:94-118`
- `crypto11@v1.6.8 crypto11.go:350-390` and `:535-555`
- that commits `901a239`, `66f70b9`, `6497885` and `e4bfeab` exist

---

## 1. Executive disposition

The dossier has 65 raw questions. Sonnet merged them into **61 entries**: R2+A6 → 2, C3+V1 → 30, P3+D2 → 41, and C4 folded into both 12 and 14. Two entries carry two separate questions, so they are split here: 11 → 11a/11b and 58 → 58a/58b. That gives **63 disposition rows**. The DeepSeek reports also raised **12 questions or residuals outside Sonnet's numbering**, listed in table 1c.

**Counts, Sonnet's 61 entries (63 rows):**

| Category | Rows |
|---|---|
| TREAT | 7 |
| TRANSFER | 15 |
| TOLERATE | 17 |
| TERMINATE | 24 |
| Unresolved (no category forced) | 0 |

**Counts, DeepSeek-only extras:** TOLERATE 6, TERMINATE 6.

**Sonnet status against final category (63 rows):**

| Sonnet status | TREAT | TRANSFER | TOLERATE | TERMINATE |
|---|---|---|---|---|
| Answered (23 entries, 24 rows) | 2 | 2 | 3 | 17 |
| Partly (27 entries, 28 rows) | 5 | 5 | 12 | 6 |
| External-unknown (11) | 0 | 8 | 2 | 1 |

### 1a. Every entry, mapped

DS = the DeepSeek report that disposed of the entry. **Bold** = I changed the DeepSeek category or chose between two reports that disagreed (see §2).

| # | ID(s) | Sonnet | DS (report) | Final |
|---|---|---|---|---|
| 1 | R1 | answered | TERMINATE (01) | TERMINATE |
| 2 | R2+A6 | ext-unknown | TRANSFER (01, 05) | TRANSFER |
| 3 | R3 | answered | TERMINATE (01) | TERMINATE |
| 4 | R4 | answered | TERMINATE (01) | TERMINATE |
| 5 | R5 | partly | TOLERATE (01) | TOLERATE |
| 6 | Y1 | partly | TERMINATE (02) | TERMINATE |
| 7 | Y2 | ext-unknown | TRANSFER (02) | TRANSFER |
| 8 | Y3 | answered | TERMINATE (02) | TERMINATE |
| 9 | Y4 | ext-unknown | TRANSFER (02) | TRANSFER |
| 10 | Y5 | ext-unknown | TRANSFER (02) | TRANSFER |
| 11a | Y6a: is Close reachable twice? | partly | TERMINATE (02) | TERMINATE |
| 11b | Y6b: success-path close never exercised | partly | TREAT (02) | TREAT |
| 12 | K1+C4 | answered | TOLERATE (03, 06) | TOLERATE |
| 13 | K2 | answered | TERMINATE (03) | TERMINATE |
| 14 | K3+C4 | partly | 03: TREAT / 06: TOLERATE | **TOLERATE** |
| 15 | K4 | answered | TOLERATE (03) | TOLERATE |
| 16 | K5 | partly | TOLERATE (03) | TOLERATE |
| 17 | K6 | answered | TERMINATE (03) | TERMINATE |
| 18 | K7 | partly | TOLERATE (03) | TOLERATE |
| 19 | L1 | partly | TOLERATE (04) | TOLERATE |
| 20 | L2 | answered | TERMINATE (04) | TERMINATE |
| 21 | L3 | partly | TOLERATE (04) | TOLERATE |
| 22 | L4 | partly | TREAT (04) | TREAT |
| 23 | A1 | partly | TREAT (05) | TREAT |
| 24 | A2 | partly | TRANSFER (05) | TRANSFER |
| 25 | A3 | partly | TREAT (05) | TREAT |
| 26 | A4 | partly | TERMINATE (05) | **TRANSFER** |
| 27 | A5 | partly | TOLERATE (05) | TOLERATE |
| 28 | C1 | answered | TOLERATE (06; also 03 extra "A1") | TOLERATE |
| 29 | C2 | partly | TERMINATE (06) | TERMINATE |
| 30 | C3+V1 | answered | 06: TOLERATE / 12: TREAT | **TREAT** |
| 31 | C5 | answered | TERMINATE (06) | TERMINATE |
| 32 | C6 | answered | TERMINATE (06) | TERMINATE |
| 33 | S1 | answered | TERMINATE (07) | TERMINATE |
| 34 | S2 | ext-unknown | TRANSFER (07) | TRANSFER |
| 35 | S3 | partly | TRANSFER (07) | TRANSFER |
| 36 | S4 | partly | TOLERATE (07) | TOLERATE |
| 37 | S5 | partly | TERMINATE (07) | TERMINATE |
| 38 | S6 | ext-unknown | TRANSFER (07) | TRANSFER |
| 39 | P1 | ext-unknown | TOLERATE (08) | TOLERATE |
| 40 | P2 | ext-unknown | TRANSFER (08) | TRANSFER |
| 41 | P3+D2 | partly | TOLERATE (08, 09) | TOLERATE |
| 42 | P4 | answered | TERMINATE (08) | TERMINATE |
| 43 | D1 | answered | TERMINATE (09) | TERMINATE |
| 44 | D3 | answered | TERMINATE (09) | TERMINATE |
| 45 | D4 | answered | TREAT (09) | TREAT |
| 46 | D5 | partly | TERMINATE (09) | TERMINATE |
| 47 | D6 | partly | TOLERATE (09) | TOLERATE |
| 48 | H1 | answered | TERMINATE (10) | TERMINATE |
| 49 | H2 | partly | TREAT (10) | TREAT |
| 50 | H3 | answered | TRANSFER (10) | TRANSFER |
| 51 | H4 | partly | TOLERATE (10) | TOLERATE |
| 52 | H5 | partly | TRANSFER (10) | TRANSFER |
| 53 | T1 | ext-unknown | TERMINATE (11) | TERMINATE |
| 54 | T2 | ext-unknown | TOLERATE (11) | TOLERATE |
| 55 | T3 | partly | TERMINATE (11) | TERMINATE |
| 56 | T4 | ext-unknown | TRANSFER (11) | TRANSFER |
| 57 | T5 | answered | TERMINATE (11) | TERMINATE |
| 58a | V2: signer state after Close | answered | TERMINATE (12) | TERMINATE |
| 58b | V2b: Close blocks on a stuck `C_Sign` | (Sonnet's "remaining") | TRANSFER (12) | TRANSFER, shares an evidence package with 52 |
| 59 | V3 | answered | TERMINATE (12) | TERMINATE |
| 60 | V4 | partly | TOLERATE (12) | TOLERATE |
| 61 | V5 | partly | TRANSFER (12) | TRANSFER |

### 1b. Raw IDs absorbed by merges

| Raw ID | Absorbed into | Final |
|---|---|---|
| A6 | 2 | TRANSFER |
| V1 | 30 | TREAT |
| D2 | 41 | TOLERATE |
| C4 | 12 and 14 | TOLERATE (both) |

### 1c. Questions outside Sonnet's numbering

These came from the DeepSeek reports. I renamed them because the reports reused IDs: 03 used "A1/A2", 07 used "P1–P6", and the originals clash with the A and P series above.

| New ID | Source | Question | Final |
|---|---|---|---|
| X-R4 | 01 "R4-residual" | Nothing tests `run`'s signal exit code or precedence | TOLERATE |
| X-K1 | 03 "A1" | `..` in a key path escapes `~/.yubivault` | TERMINATE (duplicate of 28) |
| X-K2 | 03 "A2" | setuid/setgid/sticky bits are not masked (`main.go:193`) | TOLERATE |
| X-S1 | 07 "P1" | Are the nil-`Leaf` guards reachable (`main.go:229`, `:247-249`)? | TERMINATE |
| X-S2 | 07 "P2" | Can two private keys share one `CKA_ID`? | TERMINATE (duplicate of 36) |
| X-S3 | 07 "P3" | Is a single-element chain enough? | TERMINATE (duplicate of 10) |
| X-S4 | 07 "P4" | Can a label and the CN disagree? | TERMINATE (invalid premise) |
| X-S5 | 07 "P5" | A certificate with an empty CN cannot be selected by name | TOLERATE |
| X-S6 | 07 "P6" | Is `yubikeyCertCN` documented? | TERMINATE (`README.md:72-75`) |
| X-D7 | 09 "OQ7" | Prompt label is unescaped and may be empty | TOLERATE |
| X-D8 | 09 "OQ8" | PIN buffers are not zeroed | TOLERATE |
| X-V6 | 12 "Q6" | A retried cert login can produce two logins on the server | TOLERATE |

Three questions (X-D7, X-D8 and X-V6) were in the per-function records but never reached the dossier. Reports 07, 09 and 12 compared their questions against the per-function records. The other nine reports did not, so the dossier may have dropped more (§7).

---

## 2. Adjudication

### 2a. Where I changed the outcome or chose between reports

**Entry 14 (K3+C4, non-regular key file). Report 03 says TREAT, report 06 says TOLERATE. Final: TOLERATE.**
- 03's TREAT depends on two claims. The source contradicts both.
  - **Claim 1: a FIFO "bypasses the documented promise" in `README.md:80`.** The promise is to refuse a key that group or other can read. A FIFO blocks inside `os.Open` (`main.go:184`), so no bytes are ever read. If a writer later opens it, `f.Stat` and the `0o077` check (`main.go:189-195`) still run before `io.ReadAll` (`:196`). The program can hang, but it never accepts a group- or other-readable key [synth].
  - **Claim 2: the hang survives SIGTERM and only SIGKILL ends it.** `NotifyContext` is installed at `main.go:474`, before `CreateLocalVaultClient` at `:480`. The first SIGINT or SIGTERM cancels `ctx`. `AfterFunc(ctx, stop)` (`:476`) then restores the default signal action, so a second signal kills the process. The code comment says so at `:470-473` [synth]. 03's `timeout -s TERM -k 3` sends exactly one TERM before KILL, so its run cannot show that a second signal is ignored [agent]. Sonnet saw the second SIGINT kill the process [agent].
- What remains is the case 06 describes: a hang that takes two signals to stop. It only happens when the operator writes a FIFO or device path into their own config, and it crosses no privilege boundary.
- Re-open as TREAT if a hang is reported in the field or if `config.yml` stops being operator-controlled. 03's warning still applies to any future fix: an `IsRegular` check after the open does nothing, because the hang happens before it. A fix needs `O_NONBLOCK`.

**Entry 26 (A4, server-forced response wrapping). Report 05 says TERMINATE. Final: TRANSFER.**
- 05 calls the premise invalid because wrapping is requested by the client through `X-Vault-Wrap-TTL` and no auth method forces it. That is a claim about how Vault and OpenBao behave. 05 cites no source, docs or recorded response for it. That makes it unresolved external evidence, and the brief says not to terminate on that basis.
- The client side is settled: `resp.Auth == nil` produces `auth field not found in response` (`main.go:402-404`) [synth]. So the open part is only whether the error message is accurate. It is bundled with A2 under the Vault/OpenBao owner (§5).

**Entry 30 (C3+V1, `unix://`). Report 06 says TOLERATE, report 12 says TREAT. Entry 49 (H2) is TREAT in report 10. Final: TREAT, as one maintainer-decision task (D-1) that closes both 30 and 49.**
- Both reports agree on the facts:
  - For `unix://`, vault-client-go replaces the transport's `DialContext` with `net.Dial("unix", …)`. The replacement ignores the context and throws away the 5s dialer (`vault-client-go client.go:98-104`) [synth].
  - The connection carries no TLS, so no client certificate is ever presented.
- The comment at `main.go:126-129` states the current policy. Part of it is unsupported. "Fails safely on its own" depends on server behaviour that nobody has checked. "Local dev Vault (http://localhost:8200) stays usable" cannot hold for cert login in either mode, because `GetClientCertificate` only runs inside a TLS handshake (`main.go:351`) [synth]. The server-side rejection itself is [INFERENCE].
- The comment is the maintainer's stated rationale, the maintainer clearly owns it, and part of it is wrong. That is a repo-owned decision, so TREAT rather than TOLERATE.
- `TestLoadConfig_ValidFile` uses `vaultAddr: "http://localhost:8200"` (`main_test.go:135`). That fixture only shows the config parses. It does not show that http works for cert auth.

**Entry 41 (P3+D2, `readPasswordLine` loop). Both reports say TOLERATE, but their facts conflict.**
- 09 says a `(0,nil)` read "cannot busy-spin on a blocking fd by construction".
- 08 reports a hot loop after a root `vhangup()` with SIGHUP ignored: 573,197 iterations in 2 s, about one core [agent].
- The source shows only that the loop `continue`s on `(0,nil)` (`x/term terminal.go:1050-1083`) [mod, per 08 and 09]. Whether the kernel keeps returning `(0,nil)` without blocking is kernel behaviour, and the source cannot rule it out. 09's "by construction" claim is therefore unsupported. 08's observation is unverified [agent].
- The category stays TOLERATE either way. Triggering it needs root `vhangup`, an inherited SIG_IGN on SIGHUP, and the bug is in third-party code.

### 2b. Upheld against Sonnet's status

| Entry | Sonnet | Final | Why the change holds |
|---|---|---|---|
| 6 Y1 | partly | TERMINATE | crypto11's error strings are constants, or `%w` of a `pkcs11.Error` that prints a CKR name. `.Pin` appears only as the `Login` argument (`crypto11.go:468,470`) [mod, per 02]. Output from OpenSC hardware cannot get into these strings. |
| 11a Y6a | partly | TERMINATE | The error defer runs only when `err != nil` (`main.go:289-293`). On constructor failure, `run` returns without calling Close (`:486-491`) [synth]. |
| 53 T1 | ext-unknown | TERMINATE | The advertised CA names have no effect: `GetClientCertificate` ignores `cri` (`main.go:351`) [synth]. The ALPN half duplicates 61 and stays TRANSFER there. |
| 55 T3 | partly | TERMINATE | The FIPS version list is {TLS12, TLS13}, the same as `MinVersion` allows [mod, per 11]. The answer does not depend on runtime `GODEBUG`. 11's `go version -m` ran on a local build, not a release artifact [agent]. That matters only for whether FIPS mode is on, not for the version question. |
| 46 D5 | partly | TERMINATE | The newline order dates from `6e3418b`. The error text always starts on a new line. No decision depends on the original author's intent. |
| 29 C2 | partly | TERMINATE | The intent is recorded in-repo: commit `6497885` scopes path suppression to the CodeQL alert about the key path [synth: commit exists]. A certificate path is not a secret. |
| 45 D4, 30 C3+V1 | answered | TREAT | The answers expose repo-owned decisions: a production path with no test coverage (D4), and a wrong rationale comment (30). |
| 50 H3 | answered | TRANSFER | It is answered (the 3xx body leaks), but the fix belongs to `vault-client-go`. |

### 2c. Answers that rest only on test fixtures

- **38 (S6).** Sonnet credits `TestLoginAndClose_ClosesOnFailure` with showing a `ResponseError`. The test uses a plain-HTTP `httptest.NewServer` (`main_test.go:442`) and checks only that an error is returned and the client is closed [synth]. That says nothing about how a TLS handshake fails, so S6 stays TRANSFER.
- **2 (R2+A6).** The fixture uses different strings on purpose (`test-token` vs `my-id`, `main_test.go:49-58`). That proves nothing about a real deployment. TRANSFER.
- **36 (S4).** The duplicate-CN case is shown only by a unit test. It is not called answered: it stays TOLERATE because a real card has never been seen to produce it.
- **15 (K4).** 03 says `TestLoadConfig_ValidFile` "pins non-enforcement" of the 0700 directory mode. Its `0755` directory (`main_test.go:133`) looks like test-setup convenience, not policy. The intent evidence is `README.md:51-54` (an operator instruction) and commit `66f70b9` (directory mode treated as a precondition). TOLERATE stands on that evidence, not on the fixture.
- **48 (H1).** The repo's proxy test only checks the CONNECT target (`main_test.go:481-505`). The h2-over-tunnel result is Sonnet's [agent]. TERMINATE rests on the stdlib source path cited by 10 [mod].
- **23–26 (A1–A4).** All the server-response shapes come from fixture servers [agent] or mocks. They settle only how the client maps a response. The server-side shape questions (A2, A4) stay TRANSFER.

### 2d. Claims that are agent-reported only

None of these runs left an artifact in the repo:
- **Sonnet:** `TestCancelShape`, `lookup-id-differs`, every SoftHSM/`pkcs11-spy` run (Y1/Y2/Y3/Y6/P1/P4/S2/T3), the FIFO and signal runs, the pty runs, the CONNECT/h2 runs, the redirect body count `opened=3 closed=2`, and the 11.2s/21s timings.
- **DeepSeek:**
  - 01: R3 smoke run
  - 03: binary runs (FIFO, symlink, sudo, `chmod 2600`)
  - 04: YAML replica, including the rename-replace test
  - 05: nil-response, empty-id and `SetToken` probes
  - 06: `filepath.Join` and `unix://` scratch runs
  - 08: pty Ctrl-D, `vhangup` and Ctrl-@ NUL runs, and the scan of the OpenSC 0.26.1 binary's strings
  - 09: `/tmp/ds09` replica
  - 11: `go version -m`
  - 12: `unix://` probe

Where a category depends on one of these runs, a [repo] or [mod] citation also supports it. The exceptions are 41 (TOLERATE either way) and 39: its TOLERATE relies partly on 08's scan of the installed OpenSC binary [agent].

### 2e. Citation corrections

None of these changes a category.
- `go.mod:8` is yaml and `:9` is x/term [synth]. Report 04 repeats the dossier's wrong `go.mod:9` for yaml.
- `tls.X509KeyPair` is called at `main.go:165`, not `:166` (03) [synth].
- `rsa.go:458` is `Decrypt`. `Sign` is at `:584-585` (02, 12).
- `Clone(` does appear in `main.go`, at `:364` (transport clone) [synth]. Sonnet's item 59 grep claim is wrong, but its conclusion (no `vault.Client.Clone`) holds.
- `errNoCkaId` is dead code in crypto11 v1.6.8 (07) [mod, per 07].
- x/term line drift: `term_unix.go:70-71` and `:88` (09).
- Line drift in `transport.go` (10, 11) and `PKI-SETUP.md:136` (02).
- Commits `901a239`, `66f70b9`, `6497885` and `e4bfeab` exist [synth].

---

## 3. Candidate task list (TREAT only)

### Maintainer decisions (no code until decided)

**D-1. `vaultAddr` scheme policy.** Closes 30 and 49 together with T-3.
- **Why:**
  - Part of the stated policy comment at `main.go:126-129` is unsupported (§2a).
  - `unix://` cannot carry cert auth.
  - With an absolute socket path it fails inside the library's URL parsing (`invalid URL escape "%2F"`) [agent: 06, 12, Sonnet].
  - With a relative path it drops both the 5s dial bound and context cancellation (`client.go:98-104`) [synth].
- **Options:**
  - (a) Reject any scheme other than `https`.
  - (b) Reject schemes other than `http(s)` and correct what the comment says about http.
  - (c) Keep it permissive and rewrite the comment to describe the actual behaviour.
- **Output:** a recorded choice.

**D-2. Fate of `ReadPin`'s generic-reader branch.** Closes 45 together with T-4.
- **Why:**
  - `main.go:388-394` runs only in tests.
  - `run` always passes `os.Stdin` (`main.go:464`), so production always takes the terminal branch (`:380-386`), and no test covers that branch [synth].
- **Options:**
  - (a) Delete the generic branch and its tests.
  - (b) Keep it, and add a test of the terminal branch.

**D-3. Whether to test with a real crypto11 context.** Closes 11b together with T-5.
- **Why:** the single-Close invariant is marked `CRITICAL` at `main.go:286-288`. A second Close panics: `moduleCtx.Close` panics with `referenced module not found` (`crypto11.go:369-371`), and `Context.Close` has no guard against repeat calls (`:543-555`) [synth]. Today only the call structure protects the invariant.
- **Options:**
  - (a) A SoftHSM-backed test, run in the Linux CI job (adds `softhsm2` to CI).
  - (b) The same test, skipped when SoftHSM is absent and run locally only.
  - (c) Decline. 11b then becomes TOLERATE.
- Report 02's alternative, a guard so `YubikeyVaultClient.Close` is safe to call twice, is a separate choice. Do not do both.

### Code tasks

**T-1. Guard against degenerate 2xx responses in `AuthenticateAndGetToken`.** Closes 23 and 25. No dependencies.
- **Rationale:**
  - On an empty body, the library returns `(nil, nil)` (`response.go:128-130`) [synth]. `resp.Auth` (`main.go:402`) and `tokenResp.Data` (`:416`) are then dereferenced without a check: a nil-pointer panic.
  - `"id": ""` passes the comma-ok check (`:416-420`), and `run` prints an empty line and exits 0 (`:501-502`) [synth].
- **Scope:** `main.go:397-421` and `main_test.go` mock cases only.
- **Acceptance criteria:**
  - `CertLoginResp: nil, CertLoginErr: nil` → error, no panic.
  - `TokenLookUpSelfResp: nil, err nil` → error, no panic.
  - `Data{"id": ""}` → error.
  - Existing `TestAuthenticateAndGetToken*` tests still pass.
  - `go test -race ./...` passes.

**T-2. Keep the parse error in `LoadConfig`'s single-document check.** Closes 22. No dependencies.
- **Rationale:** `main.go:123-124` drops a real parse error. That is the only place the function discards a cause; elsewhere it wraps with `%w` (`:118`) [synth].
- **Scope:** `main.go:120-125`, plus one row in `TestLoadConfig_Rejects`.
- **Acceptance criteria:**
  - `base + "---\n]\n"` produces an error containing both `single YAML document` and the YAML cause text.
  - A bare second `---` still gives the fixed message, with no `%!w(<nil>)`. A guard on `err != nil` is required (04).
  - The existing 5 `TestLoadConfig_Rejects` cases still pass.
- If the maintainer prefers the current behaviour, this becomes TOLERATE.

**T-3. Implement D-1.** Closes 30 and 49. Depends on D-1.
- **Acceptance criteria:**
  - Options (a) or (b): `LoadConfig` rejects the disallowed schemes with an error that names the field. One table test covers `unix://`, plus `http://` for option (a). Any fixture using `http://localhost:8200` (`main_test.go:135`) is updated.
  - Option (c): the comment at `main.go:126-129` states that a non-TLS address never presents the client certificate, and that `unix://` bypasses `dialTimeout` and context cancellation. No test.

**T-4. Implement D-2.** Closes 45. Depends on D-2.
- **Acceptance criteria:**
  - Option (a): the generic branch and the tests that reach only that branch are deleted, and `ReadPin`'s signature and doc comment match.
  - Option (b): a test runs the terminal branch, either by redirecting fd 0 to `/dev/null` or by executing the built binary. It asserts exit status 1, `could not read PIN code: inappropriate ioctl for device` on stderr, and empty stdout.

**T-5. Implement D-3.** Closes 11b. Depends on D-3.
- **Acceptance criteria:**
  - The test creates a SoftHSM token with a key pair and a self-signed certificate.
  - `CreateYubikeyVaultClient` succeeds against it.
  - `loginAndClose` runs against a fixture TLS server and closes exactly once, with no panic.
  - The test is skipped when the module is absent.
  - It runs in CI if option (a) was chosen.

---

## 4. TOLERATE (accepted residuals, no task)

| ID | Accepted residual | Why no task |
|---|---|---|
| 5 R5 | Absorbing a second signal depends on scheduler timing | The window is stdlib scheduling. The comment at `main.go:470-473` claims no more than what holds. If the second signal is not absorbed, the kill is delayed, not lost. |
| X-R4 | No automated test of signal exit 1 | `901a239` removed that test on purpose. Add a subprocess test only if `main.go:470-497` changes. |
| 12 K1+C4 | Key file owner (uid) is not checked | Mode 0600 already limits reads to the owner. A uid check only matters when running as root. No owner policy is documented anywhere. |
| 14 K3+C4 | A FIFO or device key path hangs (two signals end it); a device as the cert path is read without limit (06) | Fails closed, self-inflicted (§2a). Re-open if reported in the field or if config stops being operator-controlled. |
| 15 K4 | `~/.yubivault` mode 0700 is documented but not enforced | `README.md:51-54` presents it as an operator step. The key has its own mode gate. |
| 16 K5 | Key bytes are not zeroed | The parsed key has to stay live for the handshake. Zeroing in Go gives no guarantee. The CLI runs once and exits. |
| 18 K7 | Only go1.27.2 was read | CI floats on `'1.27'` (`ci.yml:37,57`). Re-check K6's error text when moving to a new Go minor. |
| X-K2 | setuid/setgid bits pass the mode check | Reading a file does not use those bits. The rule is "group/other readable". |
| 19 L1 | A config truncated at a value boundary decodes as a short value | Without out-of-band metadata it cannot be detected. The resulting failure lands inside the operator's own trust boundary. |
| 21 L3 | BOM / UTF-16-with-BOM files are accepted | Inherited from the parser, a superset of what is documented. A test would only pin library behaviour. |
| 27 A5 | Server token character set is unknown | A non-printable token fails loudly in `SetToken`. `SetTokenErr` (`main_test.go:33`) is never assigned anywhere: noted, no task. |
| 28 C1 | `..` escapes `~/.yubivault`; an absolute path gets re-rooted under it | `config.yml` is trusted and operator-owned. Re-open if config stops being operator-controlled. |
| 36 S4 | A real card might produce a duplicate CN | The case is rejected with a named error (`main.go:238-239`). The tool has no other way to tell the certificates apart. |
| X-S5 | A certificate with an empty CN cannot be selected by name | The documented workflow never issues one. Fixing it would need tri-state config. |
| 39 P1 | An arbitrary module set as `OpenScPath` could read `TOKEN_PIN` | The module already receives the PIN through `C_Login`, so nothing new is exposed. The scan of the installed OpenSC binary is [agent]. |
| 41 P3+D2 | A possible hot loop in x/term after `vhangup` | Third-party code. Needs root `vhangup` plus SIG_IGN on SIGHUP (§2a). |
| 47 D6 | Terminal echo stays off after Ctrl-C at the prompt | A consequence of keeping the prompt killable (`main.go:460-461`). The terminal recovers. [agent] |
| X-D7 | Prompt label is unescaped and may be empty | The text comes from the user's own config and goes to their own stderr. |
| X-D8 | PIN buffers are not zeroed | The string and C copies cannot be zeroed. Zeroing the buffers would be a gesture only. |
| 51 H4 | SOCKS negotiation is bounded by the 30s request deadline, not the 5s dial timeout | Limited by `requestTimeout`. The stdlib owns this. |
| 54 T2 | An HTTPS proxy that asks for a client certificate gets this one | Go 1.27 has no separate TLS config for the proxy. Only the public certificate is sent. |
| 60 V4 | A stalling server can take about 30s per call, about 60s in total | Each call has its own 30s deadline. The 11s figure in README covers unreachable hosts only (`README.md:110`). |
| X-V6 | A retried login body can be sent twice | Deliberate `RetryMax: 1` (`main.go:331-337`). The duplicate token expires on its own. |

---

## 5. TRANSFER (external owner and evidence needed)

**Vault/OpenBao maintainers, or the deployment operator.** Evidence: recorded live responses or upstream source.
- **2 R2+A6:** how `lookup-self` populates `data.id` for a token issued by cert login. Accept one recorded response or the token-store source. **Maintainer decision only if the values can differ:** whether to print `Auth.ClientToken` instead (`main.go:405`, `:416-420`).
- **24 A2:** the cert-login response shape under login MFA. **Maintainer decision:** whether MFA deployments are in scope. If they are, write a specific error message.
- **26 A4:** whether a deployment can force wrapping on an unauthenticated login. Accept a source citation or a recorded response.
- **38 S6:** how a wrong client certificate shows up (TLS alert vs a 4xx body). Accept a recorded wrong-certificate login.
- **10 Y5:** the deployed role and CA topology (`vault read auth/<mount>/certs/<role>`). **Maintainer decision only if an intermediate CA exists:** document that crypto11 presents the leaf only (`certificates.go:164`).
- **61 V5:** the listener's ALPN set (`openssl s_client -alpn h2`). No code in the repo depends on the answer.
- **56 T4:** each host's trust store and `SSL_CERT_FILE`/`SSL_CERT_DIR`, confirming the issuing CA is trusted. No repo change is expected.

**OpenSC maintainers, plus a holder of a real YubiKey and its PIN.** One spy-traced session (via OpenSC's `pkcs11-spy`) on the real card can collect all of these. Never guess the PIN.
- **7 Y2:** the order of `C_CloseSession`/`C_Finalize` and a clean exit after login.
- **9 Y4:** which `CKO_PRIVATE_KEY` objects and `CKA_ID`s are exposed. This also covers the empty-`CKA_ID` matching left over from 33.
- **34 S2:** whether a `CKO_PUBLIC_KEY` object exists for each slot.
- **35 S3:** which key types the module reports.
- **40 P2:** how `C_Login` treats `ulPinLen` vs `strlen`, and trailing whitespace or NUL in a PIN. 08's Ctrl-@ result is [agent].
- **52 H5 + 58b V2b:** whether `C_Sign` can block, for example under a touch policy. Capture timestamps against the 30s deadline and the exit-time `Context.Close`. Report 10 argues from source that a wedged `C_Sign` moves the hang to `loginAndClose`'s Close (`crypto11.go:543-546`) [INFERENCE].

**`hashicorp/vault-client-go` maintainers.**
- **50 H3:** the send loop overwrites the 3xx response without closing its body (`client_requests.go:319-333`) [mod, per 10]. The leak is small (at most 2 bodies per run). Filing upstream is optional and needs a fixture-based reproduction first: the `opened=3 closed=2` count is [agent].

---

## 6. TERMINATE (what closes each question)

| ID | Closing evidence |
|---|---|
| 1 R1 | `context.Cause` is checked before `err` (`main.go:495-499`) [synth]. The cause is always set on any cancellation reachable inside `run`. The defaults come from `client_option.go:71-81` [mod, per 01]. |
| 3 R3 | The terminal path fails with ENOTTY (`term_unix.go:74-78`) [mod]. `run` only ever passes `os.Stdin` (`main.go:464`) [synth]. The run itself is [agent]. |
| 4 R4 | Commit `901a239` records it as the maintainer's call. `README.md:111` [synth]. |
| 6 Y1 | §2b. |
| 8 Y3 | There is one `Configure` call site (`main.go:277`) [synth]. The registry is keyed by path [mod]. |
| 11a Y6a | §2b. |
| 13 K2 | `os.Open` → `f.Stat` (fstat) → read, all on one fd (`main.go:184-196`) [synth]. A symlink is followed, and the target's mode is what gets checked. |
| 17 K6 | `X509KeyPair` and pkcs8 error messages contain constants, PEM labels and OIDs only [mod, per 03]. Scope: go1.27.2. |
| 20 L2 | Commit `66f70b9` keeps a trailing `...` on purpose. `LoadConfig` is the file's only reader. |
| 29 C2 | §2b. |
| 31 C5 | A client does not validate its own certificate. `X509KeyPair` runs no `Verify` [mod]. |
| 32 C6 | `envProxyOnce` and lazy loading of the root CAs [mod]. Nothing in the repo assumes either is resolved at construction time. |
| 33 S1 | `GetAttributeValue` → `gobytes` returns a non-nil empty slice [mod, per 07]. The residual about module matching moves to Y4. |
| 37 S5 | `main.go` contains no authorization logic. `PKI-SETUP.md:130-139` puts authorization in the role (by OU). |
| 42 P4 | crypto11 has exactly two `Login` call sites, both on the persistent session. The session pool only calls `OpenSession` [mod, per 08]. |
| 43 D1 | Holds under the `io.Reader` contract. `package main` cannot be imported, so no outside reader exists. |
| 44 D3 | `git log -S` shows only `6e3418b`. There was no recorded reason, and no code depends on one. |
| 46 D5 | §2b. |
| 48 H1 | ALPN after CONNECT goes through the same path as a direct connection [mod, per 10]. |
| 53 T1 | §2b. |
| 55 T3 | §2b. |
| 57 T5 | The write happens inside `sync.Once` before any dial. Each handshake reads a clone of the config [mod, per 11]. The `-race` runs are [agent]. |
| 58a V2 | After Close, `pool.Get` returns `ErrClosed`, which surfaces as `context is closed` (`sessions.go:68-73`) [mod, per 12]. |
| 59 V3 | `GetVaultClient()` is called only at `main.go:513`, and `vault.Client.Clone` is never called [synth]. |
| X-K1, X-S2, X-S3 | Duplicates of 28, 36 and 10 respectively. |
| X-S1 | The producer skips nil certificates and sets `Leaf` (`certificates.go:155-160`) [mod]. |
| X-S4 | Selection reads only `Leaf.Subject.CommonName` (`main.go:229`) [synth]. |
| X-S6 | `README.md:72-75` [synth]. |

---

## 7. Coverage and confidence limits

- **Hardware and OpenSC.** Nobody ran OpenSC against the real YubiKey, and nobody read OpenSC source. Every SoftHSM and `pkcs11-spy` result is [agent] and tells you about crypto11 only. Everything in the hardware group of §5 is open.
- **Live Vault/OpenBao.** Never contacted. Every server-response shape comes from a fixture [agent] or from library source. Server rejection of plaintext cert login (the 30/49 rationale) is [INFERENCE].
- **External modules.** The citations into vault-client-go, crypto11, miekg/pkcs11, pool, x/term and the stdlib are [mod] as read by the reporting agents. I re-read only `response.go:118-162`, `client.go:94-118` and `crypto11.go:350-390`/`:535-555`. The rest of those citations are as reported, with the line drift listed in §2e.
- **Scratch artifacts.** None remain (§2d). I ran no tests, binaries or experiments for this synthesis.
- **Questions possibly dropped.** X-D7, X-D8 and X-V6 show that some per-function record questions never reached the dossier. Reports 01–06, 08, 10 and 11 did not compare their questions against the per-function records under `audit-context/functions/`, so more may be missing.
- **Units never analysed:**
  - `loginAndClose`
  - `YubikeyVaultClient.Close`
  - `requireForMode`
  - `pathErrCause`
  - `certCNs`
  - `main`
  - the two CI jobs

  They appear here only as other questions touch them.
- **Platform scope.** go1.27.2 on linux/amd64 only. The macOS CI target and release artifacts were not inspected. T3's build metadata comes from a local build, not a release binary.

Not checked: none of the agent-reported runs were re-executed, and I compiled or ran nothing.

Main risks in the categories: K3 (14) and C3+V1 (30) are my resolutions of disagreements between reports, and A4 (26) overrides report 05. A maintainer may reasonably flip any of them. A1/A3 (23/25) are the only verified defects a user could see: a panic, and an empty token printed with exit 0.
