# run

## Function and scope

`run(args []string) error` occupies main.go:432-503; `main` (main.go:423-427) is its only caller and converts any returned error into `log.Fatal` (main.go:425), i.e. a stderr message and exit status 1. The doc comment states the split's purpose: deferred cleanup runs while still inside `run`, so `log.Fatal` cannot skip it (main.go:429-431). The function is a linear pipeline: flag parse → version short-circuit → mode XOR check → home dir → config load → per-mode config check → optional PIN read → signal capture → client construction → login+close → signal-cause check → error check → single token write.

## Inputs and outputs

Inputs: `args` (supplied as `os.Args[1:]`, main.go:424), the process environment (`HOME` main.go:448, `TOKEN_PIN` main.go:259, `HTTPS_PROXY`/`NO_PROXY` main.go:364, TLS roots main.go:349-356), `os.Stdin`/`os.Stderr` for the prompt (main.go:464), and the files `<home>/.yubivault/config.yml` plus the `-local` cert/key (main.go:103, 157, 161).

Outputs: on `-version`, one stdout line containing `Version` and a nil error (main.go:439-442). On success, exactly one stdout line containing the token from `AuthenticateAndGetToken` (main.go:501) and a nil error. Otherwise a non-nil error and no stdout write. Three flags are defined; there are no positional arguments and no other options (main.go:433-437). Because the FlagSet uses `flag.ExitOnError` (main.go:433), a bad flag calls `os.Exit(2)` and `-h`/`-help` calls `os.Exit(0)` from inside `fs.Parse` (main.go:437; exit logic at flag.go:1164-1174) — neither is observable by `main`.

Ordering detail: `-version` returns before the exclusivity check (main.go:439-442 vs 444-446), so `-version` combined with `-local`/`-yubi` or with no flag at all prints the version and exits 0 without touching config.

## Invariants

1. Nil error ⟺ exactly one stdout line. The only `return nil` statements sit immediately after the two prints (main.go:441, 502); all other exits return an error (main.go:445, 450, 454, 457, 466, 489, 490, 497, 499).
2. Mode exclusivity: `*localFlag == *yubikeyFlag` is rejected (main.go:444-446), which covers both "neither" and "both".
3. `-local` and `-yubi` share one client constructor and one transport: `newVaultClient(appConfig.VaultAddr, cert)` (main.go:169, 306), which builds the HTTP client from the cloned default transport (main.go:363-374) with `RetryMax: 1` and `requestTimeout` (main.go:329-336).
4. The printed value is the lookup id, not the login token (main.go:405 vs 416-420).
5. Signal wins over both construction error and login error: `context.Cause(ctx)` is checked before returning the constructor error (main.go:487-489) and before returning the login error or printing (main.go:494-497).
6. PIN read precedes signal capture (main.go:462-467 before 474-476), so during the prompt the default SIGINT/SIGTERM disposition still applies; after registration, the first signal cancels ctx (`signalError(s.String()+" signal received")`, os/signal/signal.go:306) instead of killing the process, `defer stop()` (main.go:475) and `context.AfterFunc(ctx, stop)` (main.go:476) restore the default action once ctx is done (signalCtx.stop → cancel+Stop, os/signal/signal.go:322-325), and — per the comment at main.go:471-473 — signals in the window before the AfterFunc goroutine runs are absorbed rather than fatal.
7. Cleanup on every path after successful construction: `loginAndClose` always calls `authClient.Close()` (main.go:508-512), a no-op for local (main.go:56-58) and a crypto11 close for `-yubi` (main.go:71-76); on constructor failure the crypto11 context is closed by `CreateYubikeyVaultClient`'s own defer (main.go:289-293) because run does not call `Close` on the error path (main.go:486-491).
8. `authClient` is never a nil dereference at main.go:513: both constructors return literal `nil` with every error (main.go:159, 163, 167, 171, 283, 299, 303, 308) and the error is checked first (main.go:486-491).
9. No deadline on ctx: the parent is `context.Background` (main.go:474); all time bounds come from `dialTimeout`/`requestTimeout`/one retry (main.go:319-320, 329-336, 365, 369).

## Assumptions

- `$HOME` defines the config location and is caller-controlled; `os.UserHomeDir` returns `$HOME` verbatim on Unix (os/file.go:605-623) and run only errors when it is unset (main.go:448-451).
- `~/.yubivault`'s own mode is not checked on run's path; only the `-local` key file's `0o077` bits are (main.go:193-195), while the cert file is read without a mode check (main.go:161). README.md tells the operator to `chmod 700` the directory.
- The Vault address scheme is deliberately unenforced (main.go:126-129).
- Server trust comes from the system store/`SSL_CERT_FILE`; `clientTLSConfig` sets no `RootCAs` and only injects the client certificate (main.go:349-356).
- Vault's lookup `id` is assumed to be the same string as `Auth.ClientToken`; a server with different lookup semantics would make the printed value differ from the authenticated token (main.go:405-420). The client token set at main.go:409 is in-memory only and is not revoked on failure paths.
- PKCS#11 work is local and trusted and not ctx-aware (main.go:482-483); a module that blocks would not be interrupted by the signal path, since cancellation is only inspected after the call returns (main.go:487).
- On a signal that races a successful login, output is suppressed and the process exits 1 with the signal cause, per main.go:494-497 and README.md's documented `interrupt signal received` / `terminated signal received` messages.

## Calls

Per the `calls` array: stdlib calls are `flag.NewFlagSet`/`Bool`/`Parse` (main.go:433-437), `fmt.Println` (main.go:440, 501), `errors.New` (main.go:445), `os.UserHomeDir` (main.go:448), `signal.NotifyContext` (main.go:474), `context.AfterFunc` (main.go:476), `context.Cause` (main.go:487, 495), and, via main, `log.Fatal` (main.go:425). Internal callees: `LoadConfig` (main.go:452 → 102-139, config-path-qualified errors), `(*AppConfig).requireForMode` (main.go:456 → 142-153), `resolvePin` (main.go:464 → 258-271, `TOKEN_PIN` short-circuit at 259-261), `ReadPin` (378-395, prompt on the writer it is given, which is `os.Stderr` from main.go:464, `term.ReadPassword` for `os.Stdin` at 381), `CreateLocalVaultClient` (480 → 155-174 → `readPrivateKey` 183-200 → `newVaultClient`), `CreateYubikeyVaultClient` (484 → 273-313 → `crypto11.Configure` 277, `FindAllPairedCertificates` 297, `selectCertificate` 301, `newVaultClient` 306, defer close 289-293), `loginAndClose` (493 → 507-513), `AuthenticateAndGetToken` (397-420). External black-box calls: the Vault cert-login and token-lookup HTTP calls through `RealVaultClient` (main.go:93-98, 397-416) and the PKCS#11 module/card operations (main.go:277-300); their error text passes through the wraps listed in the `calls` array, and outcomes not excluded are recorded in `assumptions`/`openQuestions`.

## Callers and shared state

`main` alone (main.go:423-427); the repository has two Go files (main.go, main_test.go) and no test invokes `run` — every test targets a callee (main_test.go:48-119 for `AuthenticateAndGetToken`, 121-200 for `LoadConfig`, 202 for `requireForMode`, 240-310 for `CreateLocalVaultClient`, 312 for `ReadPin`, 350 for `YubikeyVaultClient.Close`, 358 for `resolvePin`, 374 for `CreateYubikeyVaultClient`, 393 for `selectCertificate`, 440 for `loginAndClose`, 473 for `newHTTPClient`, 538 for `clientTLSConfig`, 567 for `newVaultClient`). Shared state touched by run: `os.Args`; process signal disposition (registration main.go:474, restoration via `Stop(c.ch)` in signalCtx.stop, os/signal/signal.go:322-325, triggered by main.go:475-476); the ctx/cancel-cause pair (main.go:474); stdout (main.go:440, 501) and stderr (main.go:379 via 464, 425, 510, plus flag output); environment variables `HOME`, `TOKEN_PIN`, `HTTPS_PROXY`/`NO_PROXY`, TLS-root settings; the config file and `-local` key/cert files (main.go:103, 157, 161); `main.Version` (main.go:28) as set by release.yml's `-X 'main.Version=$VERSION'`; the in-memory Vault token (main.go:409); and the PKCS#11 session (main.go:277, closed at 291/312 → 509).

## Open questions

Open questions: vault-client-go's error shape under mid-request cancellation; whether Vault's lookup `id` always equals `Auth.ClientToken`; `term.ReadPassword` behaviour on non-terminal `os.Stdin`; the intended exit status for signal-caused failure; and whether the second-signal absorption described by the code is guaranteed.
