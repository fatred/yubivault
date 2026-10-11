# Disposition review — `CreateLocalVaultClient` (`main.go:155-174`)

**Scope.** Every question whose origin list includes `CreateLocalVaultClient`: C1 (Sonnet 28), C2 (29), C3+V1 (30), C4 → split into K1 (12) and K3 (14), C5 (31), C6 (32) = 6 questions / 7 entries. Repo state: `7f10998`, read-only (scratch work under `/tmp`, removed). No edits.

**Independent verification I performed (this session), so my assessment is not a restatement of Sonnet:**

| Claim | How checked | Result |
|---|---|---|
| `filepath.Join` re-roots absolute names, `..` escapes | go1.27.2 scratch run | `../elsewhere/k600` → `/home/u/elsewhere/k600`; `/tmp/yvl/elsewhere/k600` → `/home/u/.yubivault/tmp/yvl/elsewhere/k600`; `..` → `/home/u` — matches Sonnet 28 |
| cert error text composition | same scratch run | `could not read certificate file (certAuthPemFile): open /tmp/…/nopem.pem: no such file or directory` — matches Sonnet 29 verbatim |
| `unix://` handling in pinned `vault-client-go@v0.4.3` | source + scratch module calling the real library | `client.go:97-110` (DialContext replaced at `:99-103`, `net.Dial("unix", …)` at `:102`), `parseAddress` `client.go:147-163` (scheme→`http` at `:157`); `url.String()` = `http://%2Ftmp%2Fx.sock`; `CertLogin` → `could not create 'POST http://%2Ftmp%2Fx.sock/v1/auth/cert/login' request: parse …: invalid URL escape "%2F"` (via `client_requests.go:238`, `:252`); relative form → `dial unix rel.sock: connect: no such file or directory` |
| `tls.X509KeyPair` does no validity/chain check | installed stdlib source read in full | collects all `CERTIFICATE` blocks, requires ≥1, picks first `*PRIVATE KEY` block, parses `Certificate[0]` as `Leaf`, compares public keys only — no `Verify`, no time check |
| proxy/roots resolved on first use | `net/http/transport.go:1030-1044` (`envProxyOnce.Do`), `crypto/x509/root.go:28-42` (`once.Do(initSystemRoots)`) | confirmed |
| README wording, comment scope, tests | `README.md:62`, `:80`; `main.go:175-178`; `main_test.go:240,264` | confirmed: README:62 "# required for -local: file names inside ~/.yubivault"; tests are key-only and both **pass** here (I ran them, plus `TestNewHTTPClient_UsesProxyFromEnvironment`) |
| CodeQL config not in repo; history | `.github/` = ci.yml, release.yml, changelog-config.json, dependabot.yml; `gh issue list --state all` → `[]`; PR bodies 11/14/19/21/26 read | confirmed; `gh api …/code-scanning/default-setup` → **403** (needs `admin:repo_hook`) |

**Report-only (Sonnet ran it, I did not):** the fixture-server `-local` runs, the FIFO/SIGINT experiment, the proxy re-exec mechanism, and the SoftHSM evidence elsewhere in their report. I verified the sources those rest on and the repo tests, not their end-to-end runs.

---

## 1. Sonnet 12 — K1 (+C4) — key-file ownership (`Stat_t.Uid`)

**Original question.** Should ownership be checked, and is an owner policy stated?
**Sonnet.** *Answered*: only `Mode().Perm()&0o077` is tested (`main.go:189-195`); `README.md:80` documents only group/other; commit `253799a` and `PKI-SETUP.md` state no owner policy; "whether one is wanted is a maintainer decision".
**My assessment.** Corroborated (`main.go:193-195`; README:80 verbatim; `253799a` exists — "Security hardening: fail-secure config/key handling…"; PR 11 lists its out-of-scope items and ownership is not among them). I add the reason the question is technically moot rather than merely unanswered: mode `0600` means only the owner can read, and a POSIX ACL grant surfaces through the group/mask bits, so a foreign-owner file readable by us is already excluded by the existing check. A uid check would only change behaviour when the tool runs as root, where the mode gate is meaningless anyway.
**Final disposition. TOLERATE.**
**Rationale.** Known residual ("no uid check") accepted: the `0o077` gate already restricts reads to the file's owner, the tool is invoked by the owner, and the only case a uid check adds is a root invocation that is outside the threat model. No maintainer decision is pending on risk grounds; README documents exactly what the code enforces, so there is no doc/code gap to close.
**Owner/evidence needed.** n/a. **Suggested task.** None.

## 2. Sonnet 14 — K3 (+C4) — non-regular files (FIFO/device/socket)

**Original question.** Should the key's *type* be part of the contract?
**Sonnet.** *Partly*: no `IsRegular` check (`main.go:184-198`); observed a mode-0600 FIFO blocking `os.Open`, `/dev/null` rejected by the mode check, a directory failing with a read error (`main_test.go` "directory"); `io.ReadAll` unbounded on a writer-fed FIFO (source-read, not run); no README regular-file requirement.
**My assessment.** Corroborated on the source side (`main.go:183-201` checks only `Perm`; the "directory" subtest passes — I ran it). The FIFO-blocking observation matches POSIX (`open(2)` of a FIFO read-only blocks until a writer opens it) without needing a rerun. Two additions: (a) the *certificate* path (`os.ReadFile`, `main.go:161`) has neither mode nor type check, so a character device such as `/dev/zero` there reads unboundedly; (b) any trigger for either requires local write access to `~/.yubivault`, an attacker who can already delete the key, corrupt the config, or DoS the tool outright — and the mode check still precedes the key read, so no read of another user's key becomes possible, and supplying key bytes is no worse than writing the key file.
**Final disposition. TOLERATE.**
**Rationale.** Residual accepted: hang-instead-of-error for stream files and unbounded reads demand write access to the (documented 0700) config directory, which already implies total DoS; no confidentiality or authentication boundary is crossed. Upgrade trigger: if the directory mode ever becomes tool-enforced *and* hostile writes enter the threat model, or a non-regular-file hang is reported in the field — then require `info.Mode().IsRegular()` in `readPrivateKey` and bound the cert read.
**Owner/evidence needed.** n/a. **Suggested task.** None.

## 3. Sonnet 28 — C1 — are the config file names confined to `~/.yubivault`?

**Original question.** Is confinement intended (docs show plain names; nothing enforces it)?
**Sonnet.** *Answered*: binary observation of `../` escaping and absolute names re-rooting; source is `filepath.Join` only (`main.go:156`, `:161`); README comment says file names inside `~/.yubivault`; "nothing on behaviour", no containment discussion in history.
**My assessment.** Behaviour reproduced exactly (see table). Intent corroborated as never discussed: zero issues in the repo, and PR bodies 11/14/19/21/26 are silent on path containment. Where I stop short of Sonnet's blanket "Answered": the question asks *intent*, and "no in-repo discussion found" settles evidence, not intent — but the intent half is also low-stakes, because the config is operator input and the `0o077` gate limits reads to files the invoking user can already read. Residual worth recording: README:62 implies plain names while `..` silently escapes and a leading `/` is silently re-rooted; an escaping `certAuthPemFile` additionally prints the resolved path in the error (the key side does not).
**Final disposition. TOLERATE.**
**Rationale.** Behaviour settled by source + reproduction; impact bounded (trusted config; mode-gated key read; path disclosure only to the operator's own stderr). No evidence of intended confinement beyond a usage comment, so nothing is broken — but the silent escape is a real trippable edge, hence "accepted residual" rather than "answered". Upgrade trigger: if `config.yml` ever stops being operator-controlled (fetched, or a shared/writable config dir), re-open as TREAT — reject components that `Clean` out of the directory or state the rule.
**Owner/evidence needed.** n/a. **Suggested task.** None.

## 4. Sonnet 29 — C2 — certificate path in the error vs the key's suppression

**Original question.** Is the cert error's resolved path intended, given the key's path suppression?
**Sonnet.** *Partly*: observed the exact cert error with path; commit `6497885` is the CodeQL `go/clear-text-logging` fix; the comment scopes the policy to the key; tests cover only key errors; CodeQL configuration is not in the repo, so intent is unstated.
**My assessment.** I resolved the "unstated" half from in-repo evidence Sonnet cited but did not quote: PR 14 / commit `6497885` say the change exists because "CodeQL alert #4 flags `CertAuthKeyFile` flowing into the permissions error … Name the config field instead of echoing the resolved key path." That is a scanner-driven fix to a field CodeQL treats as a credential, not a stated path-secrecy policy — so the cert asymmetry is *explained*, not mysterious. Independently confirmed: the cert wrapper text (reproduced), `.github/` has no CodeQL config, and the GitHub-side code-scanning configuration is unreadable from this session (`403`, needs `admin:repo_hook`). Nothing in the message is sensitive: a client certificate is public and its path is the operator's own; the key path was the only flagged flow.
**Final disposition. TERMINATE.**
**Rationale.** Question answered: the suppression is CodeQL-alert-scoped (recorded in commit/PR 14, i.e. in-repo history), the certificate and its path are not secrets, and no repo decision is pending. Sonnet's "remaining: whether it is intentional is unstated" is accurate as far as the *code comment* goes, but the rationale is recorded in the commits, so there is no open question and no residual a user can trip over. The external CodeQL configuration is not needed to close this and is not re-opened here.
**Owner/evidence needed.** Not transferred; recorded for completeness: GitHub code-scanning settings/alert state (owner: repo admin; evidence: `admin:repo_hook`-scoped API or the maintainer's UI). **Suggested task.** None.

## 5. Sonnet 30 — C3 + V1 — `unix://` `vaultAddr` and the 5s dialer

**Original question.** Is `unix://` intended, and what happens to the 5 `s` dialer?
**Sonnet.** *Answered*: library replaces the transport `DialContext` for `unix://`, rewrites scheme to `http`, sets `Host` to the socket path; absolute path fails at request creation with the `%2F` escape error; relative path works end-to-end with no TLS seen and the library dialer in use; intent unstated (no doc/test/history).
**My assessment.** Reproduced against the pinned library, with exact citations (table above). Sonnet's technical answer stands. One substantive addition: because `parseAddress` rewrites the scheme to `http` (`client.go:157`), a `unix://` address is plaintext HTTP, so the certificate installed by `clientTLSConfig` (`main.go:349-356`) is never presented and **cert login cannot succeed over a unix socket in either mode** — Sonnet's "works end to end" refers to a fixture echoing the request, not to authentication (their own `serverSawTLS=false` note is consistent with this). So `unix://` is not an alternative transport for this tool; it is an undocumented form that fails, either at request build (absolute) or at the server (relative). Secondary residual: the replaced `DialContext` drops `main.go:365`'s 5 `s` budget (`net.Dial("unix", …)` has no timeout), so README:110's "about 11 seconds" promise would not hold for that form — reachable only via an undocumented address, and a blocked connect needs a full-backlog socket in the CWD for the relative form.
**Final disposition. TOLERATE.**
**Rationale.** The technical question is settled (source + live reproduction against `v0.4.3`); `unix://` is undocumented, untested, absent from README's `https://` examples (`README.md:58`) and from all issue/PR history, and it is structurally incapable of delivering this tool's one function (cert auth), so no operator can be relying on it. Upgrade trigger: Vault does support unix listeners, so if that form is ever advertised or reported, re-open as TREAT — reject a `unix://` (or non-`http(s)`) `vaultAddr` in `LoadConfig`/`requireForMode` with a field-naming error, or document it plus a bounded dial.
**Owner/evidence needed.** n/a. **Suggested task.** None.

## 6. Sonnet 31 — C5 — client-side certificate validity/chain checking

**Original question.** Is client-side validity or chain checking expected before the handshake?
**Sonnet.** *Answered*: `tls.X509KeyPair` parses the leaf and checks type/key match, no `NotBefore`/`NotAfter` or chain check; the first handshake is in `AuthenticateAndGetToken`; Go's client does not validate its own certificate; the server's reaction is server-side.
**My assessment.** Verified by reading the entire `X509KeyPair` in the installed toolchain: all `CERTIFICATE` blocks collected, first `* PRIVATE KEY` block selected, `Certificate[0]` parsed as `Leaf`, public keys compared (RSA/ECDSA/Ed25519/ML-DSA mismatch → error). No `Verify`, no time check, no chain build — so an expired, not-yet-valid or CA-untrusted client certificate loads and is presented unchanged, and only the server's TLS stack plus Vault's cert-auth role decide. Repo behaviour matches: `GetClientCertificate` returns the certificate unconditionally (`main.go:351-352`), `MinVersion: TLS12` (`:354`), no `RootCAs`/`InsecureSkipVerify`.
**Final disposition. TERMINATE.**
**Rationale.** Answered at the repo boundary: a client cannot and should not validate its own certificate (Go presents it; the server is the only authority), the repo claims nothing to the contrary, and no code path is missing. A client-side expiry pre-check would be a UX feature duplicating the server's verdict, not a correctness fix — sonnet's appended "how the server reacts" belongs to the Vault/OpenBao operator's PKI configuration and does not gate any decision in this function. No residual worth recording.
**Owner/evidence needed.** Not transferred; recorded only: server-side reaction to an expired client cert (owner: Vault/OpenBao operator; evidence: a live server or the cert-auth role configuration). **Suggested task.** None.

## 7. Sonnet 32 — C6 — construction-time vs request-time env/CA resolution

**Original question.** Does anything depend on construction returning before proxies or CA bundles are resolved?
**Sonnet.** *Answered*: `envProxyOnce.Do` snapshots proxy variables at the first `Proxy` call; system roots load once on first use honouring `SSL_CERT_FILE`; the repo's own proxy test re-execs because of the once-per-process snapshot; nothing in the repo assumes construction-time resolution.
**My assessment.** Verified from the installed stdlib (`transport.go:1030-1044`, `root.go:28-42`) and from the repo: `newHTTPClient` (`main.go:363-375`) only clones `http.DefaultTransport` and swaps `DialContext`/`TLSClientConfig`; the only place a trust location is mentioned is `README.md:87` (`SSL_CERT_FILE`), which is consistent with per-verification root loading. `TestNewHTTPClient_UsesProxyFromEnvironment` exists (`main_test.go:473`) and passes in this checkout (ran it); its re-exec mechanism I did not re-derive, so that detail stays report-only. PR 21 documents the same once-per-process property as a known constraint.
**Final disposition. TERMINATE.**
**Rationale.** Fully answered by stdlib source plus the repo's own test; no repo code, test or doc depends on construction-time resolution, and the once-per-process snapshot is a known, accommodated property (documented in PR 21), not a defect. No residual.
**Owner/evidence needed.** n/a. **Suggested task.** None.

---

## Counts

| Disposition | Count | Items |
|---|---|---|
| **TREAT** | 0 | — |
| **TOLERATE** | 4 | 12 (K1+C4), 14 (K3+C4), 28 (C1), 30 (C3+V1) |
| **TRANSFER** | 0 | — |
| **TERMINATE** | 3 | 29 (C2), 31 (C5), 32 (C6) |
| **Total** | 7 entries / 6 questions | C4 split across 12 and 14 as Sonnet merged it |

## Recommended worklist

- **Nothing to schedule.** No TREAT and no TRANSFER: every question is either closed by source + reproduction or is an accepted residual under the current threat model (trusted `config.yml`; 0700 config directory; mode-gated key read).
- **Watch triggers (re-open as TREAT, do not implement now):** (1) `config.yml` ceasing to be operator-controlled → enforce path containment in `CreateLocalVaultClient`; (2) a reported non-regular-file hang, or tool-enforced directory mode plus a hostile-write threat model → `IsRegular` check in `readPrivateKey`, bounded cert read; (3) unix-socket Vault addresses becoming in scope → reject/reject-and-document in `LoadConfig`/`requireForMode`.
- **External facts left on record, not gating any verdict:** GitHub code-scanning configuration/alert state for `fatred/yubivault` (owner: repo admin; needs `admin:repo_hook` — my attempt returned 403) and the real server's reaction to an expired client certificate (owner: Vault/OpenBao operator).
- **Citation accuracy of the Sonnet excerpt:** all `main.go`, README and test citations I spot-checked are correct; `parseAddress` is `client.go:147-163` with the unix rewrite at `:153-160` (Sonnet's ":153-158" points at the right block, one line short), and its `crypto/tls/tls.go` ranges are approximate but correct in substance.

*Skipped: I did not re-run Sonnet's fixture-server, FIFO/SIGINT, SoftHSM or proxy re-exec experiments (report-only above), and I could not read the GitHub-side CodeQL configuration (403, missing `admin:repo_hook`). Risk to the reader: the three TOLERATE verdicts for items 28/12/14 assume the config directory and `config.yml` remain operator-controlled; if that assumption changes, all three become TREATs.*
