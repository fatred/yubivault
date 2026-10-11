# Audit-context follow-up: open-question investigation

## Method and conventions

- **Repo state.** `/home/jhow/git/yubivault` at HEAD `7f10998`. `git status` is clean.
- **Toolchain and modules.** Go 1.27.2, cgo enabled. Module versions are the pinned ones from `go.mod`:
  - `crypto11` v1.6.8
  - `miekg/pkcs11` v1.1.2
  - `vault-client-go` v0.4.3
  - `go-retryablehttp` v0.7.8
  - `x/term` v0.47.0
  - `thales-e-security/pool` v0.0.2
  - stdlib under `~/.go/src`
- **Scratch work.** I copied `main.go`, `go.mod` and `go.sum` to `/tmp` and ran experiments against the copy. I also built a binary to `/tmp`. All scratch files are removed.
- **Experiments.**
  - Local TLS servers, including HTTP/2 and a CONNECT proxy.
  - Pty and signal runs of the built binary, as the `-yubi` prompt and `-local` paths.
  - A SoftHSM 2.6.1 token driven through `-yubi`, with `pkcs11-spy` tracing. This is not OpenSC and not a YubiKey.
- **Not touched.** The real YubiKey, a live Vault or OpenBao, and OpenSC internals (only the binary is installed, no source).
- **Provenance.** "Observed" means I ran it in this session. "Source" means read from code at the cited path:line. `[INFERENCE]` means neither.
- **Statuses.**
  - *answered*: the question as asked is settled.
  - *partly*: a factual part is settled and the rest is intent or external.
  - *external-unknown*: it needs hardware, a live server, module internals or production settings.
  - *not checked*: nothing in the dossier fell in this bucket. The only item I examined without exercising it is T2, filed under external-unknown.
- **Merging.**
  - The dossier has 65 raw questions. I merged four duplicate groups, leaving **61 entries**.
  - Merged entries list every originating function.
  - The merges are R2+A6, C3+V1, P3+D2, and C4 (folded into K1 and K3, listed as an extra origin of both).
- **Citation drift in the dossier.** Every `main.go` citation I spot-checked is correct. One is off: the dossier gives `go.mod:9` for `go.yaml.in/yaml/v3`, but it is at `go.mod:8` (`go.mod:9` is `x/term`).

---

## run (`main.go:432-503`)

**1. R1 — Does `CertLogin` surface context cancellation, and which branch of `main.go:495-499` wins?** *Answered.*
- **Evidence:**
  - `client_requests.go:160-203` and `:292-346`.
  - `go-retryablehttp client.go:472-476`, `:722`, `:825`.
  - `vault-client-go client_configuration.go:224-232`. The vault-client-go config uses `PassthroughErrorHandler` and wraps `DefaultRetryPolicy`, which returns `ctx.Err()` once the context is done.
  - Scratch `TestCancelShape`.
- **Observed:** cancelling mid-request returned after 300 ms with the bare error `context canceled`. `errors.Is(err, context.Canceled)` was true; `errors.Is(err, cause)` was false; `context.Cause(ctx)` returned the signal-style cause.
- **Source:** in `run`, `context.Cause(ctx)` is checked at `main.go:495` before `if err != nil` at `:498`. The cause wins whatever error type the library returns. The library's error shape only matters for the text when no cause is set.
- **Remaining:** nothing for this question.

**2. R2 + A6 — Is the lookup-self `id` guaranteed to equal `Auth.ClientToken`? Do they differ in a real deployment?** (origins: `run`, `AuthenticateAndGetToken`) *External-unknown.*
- **Evidence:**
  - Observed code behaviour: `main.go:405-420` always returns the lookup `data.id`, not the login token.
  - Scratch `lookup-id-differs` printed `s.OTHER`.
  - The test fixture deliberately uses different strings (`main_test.go:50-56`).
- **Result:** Vault's generation of `data.id` is not in any pinned module or the repo. `openapi.json` carries no semantics for this.
- **Remaining:** Vault/OpenBao token-store source, or a recorded real lookup-self response.

**3. R3 — How does `x/term.ReadPassword` behave when stdin is not a terminal?** *Answered.*
- **Evidence:**
  - Source: `term_unix.go readPassword` (first call is `IoctlGetTermios`), `main.go:381`, `:464`.
  - Observed: `echo 1234 | yubivault -yubi` and `</dev/null` both returned rc=1 with stderr `PIN for 123: ` then a newline, then `could not read PIN code: inappropriate ioctl for device`. Nothing went to stdout.
- **Source:** the generic-reader branch (`main.go:388-394`) is unreachable from `run`, because `run` always passes `os.Stdin` (`main.go:464`) and `ReadPin` tests `r == os.Stdin` (`:380`).
- **Remaining:** nothing.

**4. R4 — Is exit status 1 for a signal-caused failure intended, versus 130/143?** *Answered.*
- **Evidence:**
  - Commit `901a239` message: "Behaviour change (maintainer's call): a signal during login now exits 1 rather than 128+signo (130/143). NotifyContext's cause type is unexported, so the signal number is not available. README updated."
  - README line 111 says "non-zero … exits 1".
  - Observed: SIGINT gave rc=1 `interrupt signal received`; SIGTERM gave rc=1 `terminated signal received`.
- **Remaining:** no test asserts it. The decision itself is the maintainer's.

**5. R5 — Is a second SIGINT in the window between the first cancel and `AfterFunc`'s goroutine guaranteed to be absorbed?** *Partly.*
- **Evidence:**
  - Source, `os/signal/signal.go`: `NotifyContext` (~l.289-306) registers a 1-slot channel. `signalCtx.stop` is `cancel` then `Stop`, and `Stop` (`:193`) is the point where the default action returns.
  - Observed: two back-to-back SIGINTs gave a single message and rc=1.
  - Observed: a first SIGINT during a blocked `os.Open` (FIFO key) was absorbed, and a second SIGINT killed the process (rc=-2). That shows the default is restored after `stop`.
  - Commit `901a239` reports 20/20 absorbed runs.
- **Result:** absorption holds for signals that arrive before `Stop` executes. The size of that window depends on goroutine scheduling, so "all cases" is not source-guaranteed.
- **Remaining:** a stress or stalled-`Close` test.

---

## CreateYubikeyVaultClient (`main.go:273-313`)

**6. Y1 — Do crypto11 error strings on the failure paths include the PIN, the module path, or token content?** *Partly.*
- **Evidence:**
  - Source: `crypto11.go:394-482` (Configure errors); `:119` (`errTokenNotFound`, which carries no serial); `error.go` (`pkcs11.Error` prints a CKR name); `keys.go:130`, `:235`.
  - `grep '\.Pin'` finds only the two login calls at `crypto11.go:468` and `:470`. `config.Path` is only passed to `openModule`.
  - Observed with SoftHSM: wrong PIN gave `failed to log into long term session: pkcs11: 0xA0: CKR_PIN_INCORRECT`. A wrong serial gave `could not find PKCS#11 token`. A nonexistent module gave `failed to create module context: failed to open module`. None of the three echoed the PIN, the serial or the module path.
- **Observed side fact:** `pkcs11-spy` wrote the PIN to its log as the `C_Login` argument, so a loaded module sees and can record it.
- **Remaining:** strings from OpenSC and real-hardware output.

**7. Y2 — Is `Context.Close` (`C_Finalize`/`C_Destroy`) safe on this OpenSC build and PIV applet after a logged-in session?** *External-unknown.*
- **Evidence:** the SoftHSM run closed cleanly (rc=0). `pkcs11-spy` showed 4× `C_CloseSession` and 1× `C_Finalize`. Source: `crypto11.go:540-557` and `:355-388`.
- **Remaining:** an OpenSC and YubiKey run.

**8. Y3 — Can `moduleReferences` refCount exceed 1 in this binary?** *Answered.*
- **Evidence:**
  - `crypto11.Configure` is called once (`main.go:277`).
  - The registry is keyed by module path (`crypto11.go:317-347`).
  - `pkcs11-spy` showed 1× `C_Initialize` and 1× `C_Finalize`.
  - The only test call (`main_test.go:374`) fails inside `openModule` before registering.
- **Result:** refCount stays at 1, so `Close` finalizes.

**9. Y4 — Which PIV slots does the module enumerate for `CKO_PRIVATE_KEY`?** *External-unknown.*
- **Evidence:** crypto11 enumerates whatever private-key objects the module returns (`certificates.go:125-166`).
- **Remaining:** OpenSC PIV object filtering.

**10. Y5 — Does the Vault server accept a leaf-only client chain?** *External-unknown.*
- **Evidence:**
  - Source: crypto11 supplies only the leaf (`certificates.go:164`).
  - The documented topology trusts a single root CA directly: `PKI-SETUP.md:127-129`, with `certificate=@out/Vault_Users_CA.crt` and the line "`certificate` is the CA certificate". No intermediates are described.
- **Remaining:** the actual role and CA configuration of the target server.

**11. Y6 — Is `Close` reachable twice for one context, and is the success-path close exercised?** *Partly.*
- **Evidence:**
  - Source: the error-path guard `err != nil && cryptoCtx != nil` (`main.go:289-293`) and `loginAndClose`'s defer (`:508-512`) are mutually exclusive by `err`. `run` does not call `Close` on constructor failure (`:486-491`).
  - A second `moduleCtx.Close` panics with `referenced module not found` (`crypto11.go:355-370`), because refCount 1 deletes the registry entry. `pool.Close` itself is idempotent (`SetCapacity(0)` returns `ErrClosed`, ignored).
  - Observed: the SoftHSM success path closed once and printed the token with rc=0.
- **Remaining:** a real-card success run. No repo test covers the success-path close.

---

## readPrivateKey (`main.go:183-201`)

**12. K1 (+C4) — Should ownership (`Stat_t.Uid`) be checked, and is an owner policy stated?** (origins: `readPrivateKey`, `CreateLocalVaultClient`) *Answered.*
- **Evidence:**
  - Source: only `Mode().Perm()&0o077` is tested (`main.go:189-195`).
  - Docs: `README.md:80` documents only "refuses a key that group or other can read".
  - History: commit `253799a` says "Refuse group/other-readable client key". Commit messages contain no ownership policy. `PKI-SETUP.md` contains none.
- **Result:** no owner policy is stated anywhere. Whether one is wanted is a maintainer decision.

**13. K2 — Is a symlink as the final path component within the "checked == read" property?** *Answered.*
- **Evidence:**
  - Observed with the binary: a symlink to a 0600 key was followed and accepted. A symlink to a 0644 key was rejected with `accessible by group/other (mode 0644)`.
  - Source: `os.Open` follows symlinks and `f.Stat` is `fstat`, so the file whose mode is checked is the file that is read.
- **Remaining:** no doc or history states symlink intent. A history grep for symlink/`O_NOFOLLOW` terms found nothing.

**14. K3 (+C4) — Behaviour on non-regular files (FIFO, device, socket).** (origins: `readPrivateKey`, `CreateLocalVaultClient`) *Partly.*
- **Evidence:**
  - No `IsRegular` check (`main.go:184-198`).
  - Observed: a mode-0600 FIFO makes `os.Open` block. The first SIGINT was absorbed; the second killed the process.
  - Observed: `/dev/null` (mode 0666) was rejected by the mode check.
  - A directory yields a read error, covered at `main_test.go` "directory".
  - Source: `io.ReadAll` on a writer-fed FIFO or socket has no size bound. I did not run this.
- **Remaining:** intent. No README requirement for a regular file exists.

**15. K4 — `~/.yubivault` permissions are documented but not enforced; is enforcement intended elsewhere?** *Answered.*
- **Evidence:**
  - Source: `main.go` calls `Stat` only at `:189`. `LoadConfig` does no stat.
  - Tests: `TestLoadConfig_ValidFile` deliberately creates the directory 0755 and the file 0644 and expects success (`main_test.go` ~129-150).
  - Docs: `README.md:51` says `chmod 700`. Commit `66f70b9` treats "the dir is 0700" as an operator precondition.
- **Result:** it is not enforced anywhere, and no enforcement is described anywhere else.

**16. K5 — Are the key bytes retained or zeroed after `tls.X509KeyPair`?** *Partly.*
- **Evidence:**
  - Source: `keyPEM` is a local variable in `CreateLocalVaultClient` (`main.go:157-165`). `main.go` has no zeroing code.
  - The parsed private key lives in the `tls.Certificate` for the process lifetime.
- **Result:** `io.ReadAll` growth leaves earlier backing arrays to the GC. That is a stdlib-semantics `[INFERENCE]`.
- **Remaining:** a heap inspection.

**17. K6 — Can a `tls.X509KeyPair` error embed key material?** *Answered.*
- **Evidence:**
  - `crypto/tls/tls.go` ~259-355 and `parsePrivateKey` (`:361-379`) use constant strings.
  - The only variable text is the list of PEM block-type labels from the file, and `%w` of the PKCS#8 parse error.
  - `crypto/x509/pkcs8.go:43-124` and `sec1.go:48-119` messages contain constants, lengths and OIDs, not key bytes.
- **Scope:** go1.27.2 only.

**18. K7 — All stdlib citations were read from go1.27.2; are other Go versions covered?** *Partly.*
- **Evidence:** `go.mod:3` is `go 1.27.0`. README says "Go 1.27 or newer". CI and release use `go-version: '1.27'` (`ci.yml:37,57`, `release.yml:37`), a floating minor.
- **Remaining:** I only exercised 1.27.2. Other 1.27.x patch levels are unchecked.

---

## LoadConfig (`main.go:102-137`)

**19. L1 — What happens if the config is truncated or replaced while being read?** *Partly.*
- **Evidence:** the decoder streams from an open fd with no lock or stat (`main.go:104-113`). Observed, via files that were already in the truncated state:
  - A value cut mid-line is accepted silently: `certAuthName: we` loaded, and `vaultAddr: https://vault.exam` loaded.
  - A cut inside a key gives a parse error: `could not find expected ':'`.
  - An empty or comment-only file gives `is empty`.
- **Result:** a truncation that lands at a value boundary decodes as a short value, and the required-field check still passes. A rename-replace leaves the open inode intact (POSIX semantics, not tested).
- **Remaining:** a real concurrent writer and reader race was not exercised.

**20. L2 — Does anything depend on `LoadConfig` accepting a `...` document-end marker?** *Answered.*
- **Evidence:**
  - Observed: base config plus `...` loads. `...` followed by `---`/`x: 1` is rejected as `must contain a single YAML document`. A leading `---` loads.
  - Commit `66f70b9` message says "A leading `---`, a trailing `...` and comments still work."
- **Result:** the behaviour is intended. No test pins it (`TestLoadConfig_Rejects` covers `---` cases only).
- **Remaining:** consumers outside the repo are unknowable.

**21. L3 — Is a BOM-prefixed `config.yml` intended to be supported?** *Partly.*
- **Evidence (observed):**
  - UTF-8 BOM loads.
  - UTF-16LE with BOM loads.
  - UTF-16LE without BOM fails with `control characters are not allowed`.
  - CRLF loads.
- **Result:** no doc, test or commit message mentions BOM (history grep). Intent is unstated.

**22. L4 — Is dropping the underlying second-document parse error (`main.go:123-124`) intended?** *Partly.*
- **Evidence:**
  - Source: any non-EOF result from the probe decode, including a parse error, maps to the fixed message. The comment at `:120-122` and commit `66f70b9` explain the single-document rule, not the error discard.
  - Observed: `...` then `---` gives the fixed message.
- **Remaining:** the intent behind discarding the parse error is not stated.

---

## AuthenticateAndGetToken (`main.go:397-421`)

**23. A1 — Can login or lookup-self return 200 with an empty body, making `resp` or `tokenResp` nil with a nil error?** *Partly.*
- **Evidence:**
  - Source: `parseResponse` returns `nil, nil` for a zero-length body (`response.go:126-127`). `sendRequestParseResponse` passes it through (`client_requests.go:~186-195`).
  - Observed: a 200 with an empty login body gave a nil-pointer panic (`resp.Auth`, `main.go:402`). An empty lookup body gave a nil-pointer panic (`tokenResp.Data`, `:416`).
- **Result:** the library does not exclude it. Whether Vault or OpenBao ever sends an empty 2xx for these endpoints is server behaviour.
- **Remaining:** server behaviour.

**24. A2 — Is the `client_token not found or empty` branch what an MFA-gated login takes?** *Partly.*
- **Evidence:**
  - Source: `ResponseAuth.MFARequirement` is defined in `response.go` but never read in `main.go`.
  - Observed: a login body with `auth.client_token:""` plus an `mfa_requirement` produced `client_token not found or empty`.
- **Result:** the client mapping is established.
- **Remaining:** Vault and OpenBao source or a recorded MFA response, to know whether the server uses that shape.

**25. A3 — Does lookup-self always return a JSON string at `data["id"]`?** *Partly.*
- **Evidence (observed against fixture servers):**
  - A numeric id gave `token id not found or not a string`.
  - An absent `data` is covered by an existing test.
  - **New:** `"id": ""` returns an empty string with a nil error, so the program prints an empty line and exits 0.
  - **New:** a lookup body with no `data` key is decoded wholesale into `Data` (`response.go`, the `else` branch), so a top-level `"id"` is accepted.
- **Remaining:** whether a real server redacts or omits `id`.

**26. A4 — Can a deployment force a wrapped login response (`wrap_info` present, `auth` absent)?** *Partly.*
- **Evidence:**
  - Source: `main.go` never sets a wrap TTL. `grep` for Wrap finds nothing relevant, so wrapping would have to be forced by the server.
  - Observed: `auth:null` plus `wrap_info` gave `auth field not found in response`. A login body with no `data` key at all also gave that error, because the whole body lands in `Data`.
- **Remaining:** server-forced wrapping behaviour.

**27. A5 — Is the `SetToken` non-printable rejection reachable from a server-supplied `client_token`?** *Partly.*
- **Evidence:**
  - Source: `validateToken`/`printable` at `request_modifiers.go:300-306`, called from `SetToken` (`:54-57`).
  - Observed: a `client_token` of `s.a\nb` gave `vault token contains non-printable characters`.
  - `SetTokenErr` is declared and returned in the mock (`main_test.go:33`, `:42`) but never assigned in any test.
- **Result:** it is reachable client-side.
- **Remaining:** whether Vault issues tokens with control characters. Vault token IDs being printable is `[INFERENCE]`.

---

## CreateLocalVaultClient (`main.go:155-174`)

**28. C1 — Is `CertAuthKeyFile`/`CertAuthPemFile` intended to be confined to `~/.yubivault`?** *Answered.*
- **Observed (binary):**
  - `certAuthKeyFile: ../elsewhere/k600` loaded the key from outside the directory and proceeded to dial.
  - An absolute name is re-rooted under `.yubivault`: `/tmp/yvl/elsewhere/k600` produced `no such file or directory`.
- **Source:** `filepath.Join` only (`main.go:156`, `:161`). Join results: `../k.key` gives `/home/u/k.key`, and `/etc/passwd` gives `/home/u/.yubivault/etc/passwd`.
- **Docs:** the README config comment says "file names inside ~/.yubivault", but no check enforces it.
- **Remaining:** nothing on behaviour. The history has no containment discussion.

**29. C2 — Is the certificate file's path-in-error (`main.go:163`) intended, given the key-path suppression?** *Partly.*
- **Evidence:**
  - Observed: `could not read certificate file (certAuthPemFile): open /tmp/yvl/.yubivault/nopem.pem: no such file or directory`.
  - Commit `6497885`: CodeQL `go/clear-text-logging` flagged `CertAuthKeyFile` flowing to `log.Fatal`.
  - The comment at `main.go:176-177` scopes the policy to the key. Tests cover only key errors (`TestCreateLocalVaultClient_KeyErrorsDoNotLeakPath`).
- **Remaining:**
  - Whether the cert asymmetry is intentional is unstated.
  - The CodeQL configuration is not in the repo (`.github/` has only `ci.yml` and `release.yml`).

**30. C3 + V1 — Is `unix://` `vaultAddr` intended, and what happens to the 5s dialer?** (origins: `CreateLocalVaultClient`, `newVaultClient`) *Answered.*
- **Source:** `vault-client-go client.go:97-110` replaces the transport `DialContext` for `unix://`. `parseAddress` (`:153-158`) rewrites the scheme to `http` and sets `Host` to the socket path.
- **Observed:**
  - `unix:///abs/path.sock` fails at request creation: `parse "http://%2Ftmp%2F...": invalid URL escape "%2F"`.
  - `unix://relative.sock` works end to end. The fixture server saw no TLS (`serverSawTLS=false`), so the client certificate was unused, and the dialer is the library's `net.Dial("unix", …)`.
- **Remaining:** no doc, test or history mentions unix sockets (grep), so intent is unstated.

**31. C5 — Is client-side certificate validity or chain checking expected before the handshake?** *Answered.*
- **Source:** `tls.X509KeyPair` parses the leaf and checks type and key match (`crypto/tls/tls.go` ~305-352). It does no `NotBefore`/`NotAfter` or chain check.
- **Result:** the first handshake is in `AuthenticateAndGetToken`. Go's client does not validate its own certificate.
- **Remaining:** how the server reacts to an expired certificate is server-side.

**32. C6 — Does anything depend on construction returning before proxies or CA bundles are resolved?** *Answered.*
- **Source:** `envProxyOnce.Do` (`net/http/transport.go:1039`), so proxy variables are read at the first `Proxy` call, not at construction. `x509/root.go:28-37` loads system roots once on first use, honouring `SSL_CERT_FILE`.
- **Observed:** `TestNewHTTPClient_UsesProxyFromEnvironment` re-execs itself because of this once-per-process snapshot.
- **Result:** no repo code or test assumes construction-time resolution.

---

## selectCertificate (`main.go:217-241`)

**33. S1 — Does `GetAttributeValue` return nil or an empty non-nil slice for a zero-length `CKA_ID`?** *Answered.*
- **Evidence:**
  - `miekg/pkcs11 pkcs11.go:303-322` (C helper) and `:1106-1129` (Go side).
  - `runtime/string.go:358-361`: `gobytes` returns `make([]byte,0)` for n==0.
- **Result:** a present zero-length attribute gives a non-nil empty slice. The value stays nil only when `ulValueLen == -1` (unavailable).
- **Consequence:** with an empty non-nil `CKA_ID`, `findRawCertificate` (`certificates.go:53-62`) appends `CKA_ID=""` and searches. The "all nil" error is swallowed at `keys.go:176` only when the attribute is unavailable.
- **Related guard:** an id and label that are both empty returns an error that aborts the whole enumeration (`keys.go:130`).
- **Remaining:** how a given module matches an empty `CKA_ID` is module-specific.

**34. S2 — Does the OpenSC PIV module always expose a `CKO_PUBLIC_KEY` per slot?** *External-unknown.*
- **Evidence:** the fallback in `keys.go:176-184` uses the certificate's public key when no public-key object exists. A SoftHSM token with only a private key and a certificate (no public-key object) worked end to end.
- **Remaining:** OpenSC PIV object mapping.

**35. S3 — Can the OpenSC PIV mapping report a key type outside DSA/RSA/ECDSA?** *Partly.*
- **Source:** `makeKeyPair` handles only DSA/RSA/ECDSA (`keys.go:197-236`). Anything else returns `unsupported key type: %X` (`:235`). `FindAllPairedCertificates` continues only on `errNoCkaId`/`errNoPublicHalf` (`certificates.go:147`), so the one error aborts all enumeration before `selectCertificate`.
- **Remaining:** OpenSC's key-type mapping.

**36. S4 — Can a real YubiKey surface two pairs with the same `Subject.CommonName`?** *Partly.*
- **Evidence:** the code path (`main.go:224-239`) and the "multiple pairs, duplicate CN" unit test give `cannot disambiguate`.
- **Remaining:** a real card was not observed.

**37. S5 — Is authorization by CN or by OU?** *Partly.*
- **Evidence:**
  - CN is used only to pick a local credential (`main.go:229`). Nothing in `main.go` authorizes.
  - `PKI-SETUP.md:130,137` configures `allowed_organizational_units`, and `:138-139` documents CN as `common_name` metadata and the `allowed_common_names` alternative.
- **Remaining:** server-side role semantics.

**38. S6 — Can Vault's cert-login response path distinguish "wrong certificate presented" from other handshake failures?** *External-unknown.*
- **Client-side shapes observed:** a TLS alert surfaces as `remote error: tls: unknown certificate authority`. A fixture HTTP 400 JSON error surfaces via `ResponseError` (`TestLoginAndClose_ClosesOnFailure`).
- **Remaining:** actual Vault behaviour.

---

## resolvePin (`main.go:256-271`)

**39. P1 — Does anything else loaded into the process read `TOKEN_PIN`?** *External-unknown.*
- **Evidence:**
  - Source: the repo reads it only at `main.go:259`. There is no `os.Unsetenv`, so it stays in the process environment for the process lifetime.
  - Observed: a spy module received the PIN as the `C_Login` argument and logged it.
- **Remaining:** OpenSC source or behaviour.

**40. P2 — How does OpenSC's PIV module treat a PIN containing spaces, newlines or NULs?** *External-unknown.*
- **Evidence:**
  - The env value is forwarded verbatim (`main.go:259-260`).
  - `miekg Login` (`pkcs11.go:1049-1053`) passes the full `len(pin)` and a C string copy.
  - A NUL cannot occur in an environment value; a typed NUL on the prompt path is possible [INFERENCE].
- **Remaining:** module `C_Login` behaviour.

**41. P3 + D2 — Can the `readPasswordLine` retry loop spin without blocking on Ctrl-D or after a pty hangup, and can `read(2)` return `(0,nil)`?** (origins: `resolvePin`, `ReadPin`) *Partly.*
- **Source:** `readPasswordLine` loops on `n==0 && err==nil` (`x/term terminal.go:1050-1083`). `passwordReader.Read` passes `unix.Read` through (`term_unix.go:~64-68`).
- **Observed on Linux 6.12 pty:**
  - **Ctrl-D at an empty prompt:** the process stayed alive in state S with 0 CPU ticks over 2s, and then accepted the next typed line.
  - **Master closed with SIGHUP default:** killed by SIGHUP.
  - **Master closed with SIGHUP ignored:** exited rc=1 promptly, with no spin.
- **Remaining:** a `vhangup`/`tty_hung_up_p` path was not exercised.

**42. P4 — Do PKCS#11 pool sessions log in again with the same Pin?** *Answered.*
- **Evidence:**
  - Source: the only login sites are `crypto11.go:468,470` on the persistent session. The pool factory only calls `OpenSession` (`sessions.go:82-88`).
  - Observed (`pkcs11-spy`, SoftHSM): exactly 1× `C_Login` across 4 `C_OpenSession`.
- **Scope:** SoftHSM semantics; OpenSC login-state sharing across sessions is not checked here.

---

## ReadPin (`main.go:376-395`)

**43. D1 — What `n` can a non-conforming reader return, and what does `bPin[:n]` do?** *Answered.*
- **Observed:** a reader returning n=100 panics with `slice bounds out of range [:100] with capacity 64`. n=-1 panics with `[:-1]`.
- **Contract:** valid `io.Reader` implementations return 0 ≤ n ≤ len(p). `package main` cannot be imported, so only in-repo callers matter.
- **Also observed:**
  - A single `Read` is used. A split read `"12"` then `"34\n"` returns `"12"`.
  - `"1234\nextra"` returns `"1234\nextra"`.
  - A 100-byte input is truncated to 64.

**44. D3 — Why 64 bytes?** *Answered.*
- **Evidence:** `git log -S'make([]byte, 64)'` shows only the initial commit `6e3418b`. No comment or constant explains it.
- **Result:** no rationale exists.

**45. D4 — Does any deployment pass a non-terminal reader in production?** *Answered.*
- **Evidence:** the only caller of `ReadPin` is `resolvePin` (`main.go:262`), reached from `run` with `os.Stdin` (`:464`). Other callers are tests (`main_test.go:312`, `:358`). `package main` is not importable.
- **Result:** production only uses the terminal branch. Piped stdin errors (see item 3).

**46. D5 — Is the newline written before the error check (`main.go:382`/`:390`) intended?** *Partly.*
- **Observed:** the newline appears before the error text (`PIN for 123: \n…could not read PIN code: …`).
- **History:** `fmt.Println()` existed from the initial commit; `bfa9e36` only redirected it to `w`. No comment states intent.

**47. D6 — Can a second `ReadPin` occur after termios restore, and can an early return precede the deferred restore?** *Partly.*
- **Source:** `readPassword` defers `IoctlSetTermios` restore (`term_unix.go:~92-99`). There is one call site, so no second call in this binary.
- **Observed:** Ctrl-C at the prompt (default disposition, before `NotifyContext`) killed the process by SIGINT. The slave termios was left with ECHO off, because the deferred restore does not run on death by signal.
- **Remaining:** EINTR behaviour at runtime was not verified.

---

## newHTTPClient (`main.go:358-374`)

**48. H1 — Does an `HTTPS_PROXY` tunnel negotiate ALPN h2 through this transport?** *Answered.*
- **Observed:** `newHTTPClient(clientTLSConfig(cert))` through a local CONNECT proxy, to an h2-enabled TLS server, gave `resp.Proto=HTTP/2.0`, one CONNECT, and the server saw 1 peer certificate.
- **Scope:** a transparent CONNECT tunnel. A real corporate proxy was not tested.

**49. H2 — Can `newHTTPClient` be reached with a non-https `vaultAddr`?** *Partly.*
- **Source:** nothing observes the scheme (`main.go:126-129` comment; `:130-135` check non-empty only; `:363-374`).
- **Observed:** `unix://relative.sock` ran the full login plus lookup over plain HTTP with no client certificate use.
- **Not run:** a literal `http://` address. It follows the same code path [INFERENCE].
- **Remaining:** whether a real Vault refuses the resulting login. The `LoadConfig` comment says it "fails safely on its own", which depends on server behaviour.

**50. H3 — Is the 3xx response body ever closed on the redirect path?** *Answered.*
- **Source:** `send` reassigns `resp` in its loop without closing the previous one (`client_requests.go:319-336`). With `ErrUseLastResponse`, `http.Client` leaves the 3xx body open.
- **Observed:** a body-counting `RoundTripper` over a 307→200→200 flow counted `opened=3 closed=2`. The 307 body was never closed.

**51. H4 — How does socks5 interact with the replaced `DialContext`?** *Partly.*
- **Source:** `transport.go:1920` dials the proxy through `t.dial`, which uses our `DialContext` and its 5s dial timeout. The SOCKS negotiation (`:1940-1956`, `DialWithConn(ctx …)`) runs under the request context, not `dialTimeout`.
- **Remaining:** no repo test, and I did not run a SOCKS proxy.

**52. H5 — Which fires first on the `-yubi` path: the request context deadline or `Client.Timeout`?** *Partly.*
- **Source:**
  - The 30s context is created at `client_requests.go:172`, before `http.Client.Do` computes its own per-attempt deadline. So the context deadline fires first on every attempt.
  - The signer runs inside the handshake. `TLSHandshakeTimeout` is 10s (`transport.go:56`). After the timer fires, `addTLS` waits for the handshake goroutine to return (`transport.go:1811-1813`), so a PKCS#11 `C_Sign` that blocks is not bounded by either timeout.
- **Observed:** a stalled TLS handshake gave `TLS handshake timeout` at 21s total (two 10s timeouts plus backoff). A blackholed dial gave an `i/o timeout` at 11.2s.
- **Remaining:** whether a real PIV module can block in `C_Sign` is a module and hardware question.

---

## clientTLSConfig (`main.go:345-355`)

**53. T1 — What are the real listener's ALPN set and advertised CA names?** *External-unknown.*
- **Evidence:** the callback ignores the CA list either way (`main.go:351-352`). `TestClientTLSConfig_PresentsCertDespiteAdvertisedCAs` covers a server advertising an unrelated CA.
- **Remaining:** a live Vault listener.

**54. T2 — Does a TLS-terminating `https://` proxy draw the same client certificate?** *External-unknown.*
- **Source:** for an https proxy, `dialConn` runs `addTLS` for the proxy hop using the same `TLSClientConfig` (`transport.go:1913-1932`). A proxy `CertificateRequest` would therefore reach `GetClientCertificate` [INFERENCE from source; not exercised].
- **Docs:** `PKI-SETUP.md:155` says that when a load balancer or proxy terminates TLS in front of Vault, the client cert never reaches Vault.
- **Remaining:** a TLS-terminating proxy.

**55. T3 — Is `fips140tls.Required()` true for the built binary, and does it restrict versions independently of `MinVersion`?** *Partly.*
- **Source:**
  - `fipstls.go:17-37`: `Required()` is true only when `fips140.Enabled()`.
  - `tls/common.go:1236`: when required, the allowed version list is filtered.
- **Observed:** the built binary has no `GOFIPS140` build setting (`go version -m`). Running with `GODEBUG=fips140=on` against a local TLS 1.3 server still completed the `-yubi` login (SoftHSM, P-256) with rc=0.
- **Remaining:** production environment and `GODEBUG` are unknown.

**56. T4 — What are the operator's trust store contents and `SSL_CERT_FILE`?** *External-unknown.*
- **Evidence:** the config sets no `RootCAs` (`main.go:349-356`).

**57. T5 — Can the h2 `NextProtos` write interleave with a handshake read of the same config object?** *Answered.*
- **Source:**
  - The write happens inside `nextProtoOnce.Do(onceSetNextProtoDefaults)` (`transport.go:345`, `:612`, `:950`). `configureHTTP2` runs `NextProtos = adjustNextProtos(…)` at `http2.go:284-312`.
  - `Once` completes before any dial.
  - Each handshake reads `cloneTLSConfig(pconn.t.TLSClientConfig)` (`transport.go:1783`).
- **Observed:** `go test -race` of the existing TLS and proxy tests passed. A scratch run of 40 concurrent h2 requests also showed no race report.
- **Scope:** go1.27.2 on linux/amd64.

---

## newVaultClient (`main.go:326-343`)

**58. V2 — What state is the crypto11 signer in after `Context.Close`, and can a handshake after Close fail or block?** *Answered.*
- **Source:**
  - Signing goes through `withSession` then `getSession` (`rsa.go:458`, `:585`; `ecdsa.go:304` via `dsaGeneric`; `sessions.go:58-72`).
  - After `Close`, `pool.Get` returns `ErrClosed` (the pool's channel is closed at `resource_pool.go:302-304`).
  - `getSession` turns `ErrClosed` into `context is closed`. So a handshake after `Close` fails and does not block.
  - In the other direction, `Close` blocks until in-flight sessions are returned (`SetCapacity(0)` drains the channel, `resource_pool.go:~288-300`).
- **Remaining:** a stuck PKCS#11 call would stall `Close` (module behaviour).

**59. V3 — Can any path reuse the returned `*vault.Client` after `loginAndClose` closes the auth client?** *Answered.*
- **Evidence:** `GetVaultClient()` is called only at `main.go:513`, and `Clone(` does not appear in `main.go`. The library's `Clone` shares the `http.Client` and the retry client (`client.go` `Clone` docs), but nothing in the repo calls it.

**60. V4 — What is the real wall-clock bound of the full login flow?** *Partly.*
- **Measured per call:** blackholed dial 11.2s (`dial tcp 192.0.2.1:8200: i/o timeout`), stalled TLS handshake 21s. Commit `e4bfeab` reports 11.4s (`-yubi`) and 11.3s (`-local`) for a blackholed address.
- **Result:** the two-call (login then lookup) worst-case total is `[INFERENCE]`. A responsive login followed by an unreachable lookup was not measured.

**61. V5 — Is HTTP/2 actually negotiated on the real Vault endpoint?** *Partly.*
- **Observed:** `newVaultClient` against an h2-enabled test server, using `SSL_CERT_FILE` for trust, negotiated `HTTP/2.0` in every scenario, with the client certificate presented.
- **Remaining:** the real Vault listener. No test in the repo asserts the negotiated protocol.

---

## Index by function

| Function | Entries (item numbers) |
|---|---|
| run | R1 (1), R2/A6 (2), R3 (3), R4 (4), R5 (5) |
| CreateYubikeyVaultClient | Y1 (6), Y2 (7), Y3 (8), Y4 (9), Y5 (10), Y6 (11) |
| readPrivateKey | K1 (12), K2 (13), K3 (14), K4 (15), K5 (16), K6 (17), K7 (18) |
| LoadConfig | L1 (19), L2 (20), L3 (21), L4 (22) |
| AuthenticateAndGetToken | A1 (23), A2 (24), A3 (25), A4 (26), A5 (27), A6→(2) |
| CreateLocalVaultClient | C1 (28), C2 (29), C3/V1 (30), C4→(12, 14), C5 (31), C6 (32) |
| selectCertificate | S1 (33), S2 (34), S3 (35), S4 (36), S5 (37), S6 (38) |
| resolvePin | P1 (39), P2 (40), P3/D2 (41), P4 (42) |
| ReadPin | D1 (43), D2→(41), D3 (44), D4 (45), D5 (46), D6 (47) |
| newHTTPClient | H1 (48), H2 (49), H3 (50), H4 (51), H5 (52) |
| clientTLSConfig | T1 (53), T2 (54), T3 (55), T4 (56), T5 (57) |
| newVaultClient | V1→(30), V2 (58), V3 (59), V4 (60), V5 (61) |

## Totals (61 merged entries from 65 raw dossier questions)

| Status | Count | Item numbers |
|---|---|---|
| Answered | **23** | 1, 3, 4, 8, 12, 13, 15, 17, 20, 28, 30, 31, 32, 33, 42, 43, 44, 45, 48, 50, 57, 58, 59 |
| Partly answered | **27** | 5, 6, 11, 14, 16, 18, 19, 21, 22, 23, 24, 25, 26, 27, 29, 35, 36, 37, 41, 46, 47, 49, 51, 52, 55, 60, 61 |
| External-unknown | **11** | 2, 7, 9, 10, 34, 38, 39, 40, 53, 54, 56 |
| Not checked | **0** | — |

## Not checked, and what shaped these results

- **Hardware and OpenSC.** I did not touch the real YubiKey or OpenSC, so anything that rests on them stays external. The SoftHSM and `pkcs11-spy` results are evidence about crypto11's own behaviour only, not about OpenSC or the PIV applet.
- **Live Vault.** Everything marked external or partly for server-shape reasons rests on fixture servers I wrote. They match the library's parsing but are not real Vault or OpenBao output.
- **The eight units without dedicated records.** The dossier lists them as not separately analysed: `loginAndClose`, `YubikeyVaultClient.Close`, `requireForMode`, `pathErrCause`, `certCNs`, `main`, and the two CI jobs. `loginAndClose` and `YubikeyVaultClient.Close` were read here only as they bear on these questions.
