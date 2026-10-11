# CreateLocalVaultClient

## Function and scope

`CreateLocalVaultClient(appConfig *AppConfig, homeDir string) (*LocalVaultClient, error)` occupies main.go:155-174. It builds the `-local` auth client from two files on disk and nothing else: it reads the private key (main.go:157), reads the certificate (main.go:161), pairs them with `tls.X509KeyPair` (main.go:165) and hands the resulting `tls.Certificate` to `newVaultClient` (main.go:169), returning a `*LocalVaultClient` wrapping the `*vault.Client` (main.go:173).

Scope boundaries, verified against the callees: the function performs no network I/O and starts no goroutines — `newVaultClient` (main.go:326-341) only calls `vault.New`, which applies options and builds structs (`client.go:48-60`, `client.go:82-140` in vault-client-go@v0.4.3) plus `parseAddress` → `url.Parse` (`client.go:147-163`); the `http.DefaultTransport` clone at main.go:364 does not resolve proxy environment variables. The first TLS handshake happens in `AuthenticateAndGetToken` (main.go:393-397), reached from `run` after this call. No files are left open: `readPrivateKey` closes its descriptor with a defer (main.go:188) and `os.ReadFile` closes internally (main.go:161).

The ordering inside the function is a stated design decision: the comment at main.go:156 says the key is read first because "its permission check must fail closed even if the cert is missing". That property is observable in `TestCreateLocalVaultClient_RejectsWorldReadableKey` (main_test.go:240-262), which creates a 0644 key and no certificate at all and asserts the error mentions "group/other"; I ran that test and its sibling `TestCreateLocalVaultClient_KeyErrorsDoNotLeakPath` in this checkout and both passed, so the key-mode rejection does pre-empt the cert-read failure.

## Inputs and outputs

Inputs: `appConfig *AppConfig` — the struct is defined at main.go:29-38 and only `CertAuthPemFile`, `CertAuthKeyFile` and `VaultAddr` are read here (main.go:157, :161, :169); and `homeDir string`, produced by `os.UserHomeDir()` at main.go:448 and passed unchanged (main.go:480). `AppConfig` is expected non-nil.

Output: a `*LocalVaultClient` (main.go:173), a wrapper holding one field, `VaultClient *vault.Client` (main.go:49-51), with `GetVaultClient` (main.go:53-55) and a `Close` that returns nil (main.go:57-59) because local auth owns no external resource — the contrast with `YubikeyVaultClient`, which owns the PKCS#11 context (main.go:63-76), is explicit in both the struct and the comment at main.go:58.

Error paths, each examined:

1. Key failure — the error from `readPrivateKey` is returned unwrapped (main.go:158-159), so its message is composed only of `keyFileField` (main.go:178) plus the stripped cause from `pathErrCause` (main.go:186, :191, :194, :198, :203-211). Four internal paths exist there: open failure, stat failure, mode rejection (which returns before any read, main.go:193-195) and read failure.
2. Certificate failure — `os.ReadFile`'s error is wrapped with `%w` at main.go:163. Unlike the key path, the text carries the resolved path; I reproduced the exact composition on go1.27.2 (`could not read certificate file (certAuthPemFile): open /tmp/definitely-missing-client-cert.pem: no such file or directory`).
3. Pairing failure — wrapped at main.go:167. The stdlib messages are static strings plus PEM block type names (crypto/tls/tls.go:276-303), so the wrapper cannot carry key material or a path.
4. Client construction failure — returned verbatim (main.go:170-171); the only wrapping is inside `newVaultClient` (main.go:338).

On success there are no side effects beyond memory: no writes, no token, no state persisted.

## Invariants

**Key-before-cert ordering.** The key is opened, stat'ed and mode-checked before the certificate is read (main.go:157 → :161; mode check main.go:193-195). A group/other-accessible key therefore wins over a missing or unreadable certificate. Confirmed by test behaviour and by reading main.go:155-174 in order.

**Path construction.** Both paths are `filepath.Join(homeDir, ".yubivault", <config value>)` (main.go:157, :161), where `.yubivault` is the shared constant at main.go:100. Consequences I verified empirically on this toolchain, since the assignment asks about path handling:

- A leading `/` in the config value does not reset to root: `Join("$HOME", ".yubivault", "/etc/shadow")` → `$HOME/.yubivault/etc/shadow`. Absolute config values are re-rooted under `.yubivault`, not honoured.
- `..` is resolved lexically by Clean: `Join("$HOME", ".yubivault", "../../etc/shadow")` → `$HOME/../etc/shadow`, and a value of ".." yields `$HOME` itself. There is no containment check anywhere in main.go:155-201.
- Interior `..` is also cleaned (`sub/../client-cert.key` → `.../client-cert.key`), and a trailing slash is dropped.

The function holds the invariant that a *bare* name resolves inside `<homeDir>/.yubivault`; it does not hold any invariant that the resolved path stays there.

**Non-empty names.** `requireForMode` rejects empty `CertAuthKeyFile`/`CertAuthPemFile` for local mode (main.go:141-145), and `run` calls it at main.go:463-465 before dispatching at main.go:479-480; `TestRequireForMode` cases at main_test.go:214-215 cover both. `CreateLocalVaultClient` itself re-checks nothing, so this invariant belongs to the caller, not the function (the comment at main.go:138-140 records why it exists: an empty name used to resolve to the `.yubivault` directory).

**Check-what-you-read for the key.** open → fstat on the fd → read from the same fd (main.go:184 → :189 → :196), matching the claim in the comment at main.go:180-182.

**Asymmetric error hygiene.** Key errors carry a constant field description and the bare cause, never the path or name (main.go:186, :191, :194, :198 with main.go:203-211; asserted by main_test.go:258-261 and main_test.go:301-309). Cert errors carry the resolved path (main.go:163, reproduced empirically).

**Only the key is mode-checked.** `os.ReadFile` for the certificate (main.go:161) has no mode or type check; the sole permission enforcement in the function is inside `readPrivateKey` (main.go:193-195).

**Pairing guarantees from the callee.** `tls.X509KeyPair` selects the first `CERTIFICATE` block as leaf (crypto/tls/tls.go:263-274, leaf parsed at :311), selects the first PEM block whose type ends in ` PRIVATE KEY` (crypto/tls/tls.go:287-303), and refuses a key whose public part does not match (crypto/tls/tls.go:318-352). All certificate blocks found are retained in `Certificate` while only the first is parsed as `Leaf`. No validity-window, EKU or chain-verification work happens at load time.

**Certificate presentation.** The cert is delivered via `GetClientCertificate` returning `&cert` unconditionally (main.go:351-352) with `MinVersion` TLS 1.2 (main.go:354), installed as `transport.TLSClientConfig` (main.go:366). Because the transport is supplied through `vault.WithHTTPClient` and `vault.WithTLS` is never used, vault-client-go's own TLS-application branch (client.go:118-131) is not entered; `RootCAs` and `Certificates` remain unset, so trust and hostname verification follow net/http defaults.

**No key material released.** `keyPEM` (main.go:196) is not zeroed; after pairing, the private key lives on in the closure-captured certificate inside the transport for the process lifetime (main.go:351-352, :366); `LocalVaultClient.Close` releases nothing (main.go:57-59).

## Assumptions

- `appConfig` is non-nil with non-empty file names — established by `run` calling `requireForMode` first (main.go:463-465); not re-established here.
- `homeDir` is the user's real home — `os.UserHomeDir()` at main.go:448, error returned at 449-451; used unvalidated.
- config.yml, and thereby both names and `vaultAddr`, is trusted operator input. `LoadConfig` enforces strict decoding (KnownFields at main.go:112, single document at main.go:122-125) but applies no permission or ownership check to the file or directory; README.md:51 documents `chmod 700 ~/.yubivault` as an operator practice only.
- The config values are plain filenames located directly in `~/.yubivault`, per README.md:63-64 and README.md:80. No statement covers absolute or `..` values, so containment is an unstated assumption rather than an enforced rule.
- The fstat mode bits are the intended confidentiality signal; there is no uid check, ACL inspection or regular-file check in main.go:183-201.
- The key is a single unencrypted PEM private key whose public part matches the certificate; `tls.X509KeyPair` is the only validator (main.go:165), and no code handles encrypted PEM.
- scheme is deliberately not enforced (comment at main.go:126-129; checks at main.go:130-134 are non-emptiness only), so a non-TLS or opaque address is assumed to fail on its own at request time.
- Signals do not interrupt these syscalls: `signal.NotifyContext` is armed before the call (main.go:474-476) and a signal that arrived during it is reported afterwards by `run` (main.go:486-490); this function has no `ctx` parameter.

## Calls

Internal: `readPrivateKey` (main.go:183-201, error propagated verbatim at main.go:158-159); `newVaultClient` (main.go:326-341, error propagated verbatim at main.go:170-171, shared with `CreateYubikeyVaultClient` at main.go:306 so transport, timeouts and retry settings are identical for both modes); `clientTLSConfig` (main.go:349-356, no error path); `newHTTPClient` (main.go:363-375, no error path; clone of DefaultTransport at :364, 5s dialer at :365, TLS config at :366, 30s timeout at :369, redirects returned as ErrUseLastResponse at :370-372); `pathErrCause` (main.go:203-211, used only inside readPrivateKey).

Stdlib: `filepath.Join` (main.go:157, :161 — lexical join plus Clean, no containment guarantee, behaviour verified empirically); `os.Open` (main.go:184) and `os.ReadFile` (main.go:161); `(*os.File).Stat` (main.go:189, fd-based); `fs.FileMode.Perm` (main.go:193); `io.ReadAll` (main.go:196, unbounded); `(*os.File).Close` via defer (main.go:188, result discarded); `tls.X509KeyPair` (main.go:165; crypto/tls/tls.go:258-355, semantics enumerated in Invariants); `fmt.Errorf` with `%w` throughout for wrapping.

Black-box: `vault.New` (vault-client-go v0.4.3). Options used do not validate much: `WithAddress` stores the string verbatim (client_option.go:21-25), `WithHTTPClient` stores the client (client_option.go:33-37), `WithRequestTimeout` rejects only negatives (client_option.go:46-53), `WithRetryConfiguration` fills defaults for the checks it is not given (client_option.go:66-91). `newClient` copies the HTTP client and wraps it in a retryablehttp client (client.go:82-110) and parses the address once (client.go:95; parseAddress at client.go:147-163). Outcomes not excluded: an address that `url.Parse` accepts but net/http cannot use — verified on go1.27.2 that `url.Parse("localhost:8200")` succeeds with Scheme `localhost` and Opaque `8200`, whereas `http://[::1` and `https://a b/` fail, so a scheme-less address is accepted here and fails later when the base URL is re-parsed per request (client_requests.go:238-242); and a `unix://` address, which takes the branch at client.go:98-116 and replaces the transport's `DialContext` with a plain unix dial, superseding the 5s dialer installed at main.go:365.

## Callers and shared state

`run` is the only production caller (main.go:479-480), reached only with `-local` (the two mode flags are mutually exclusive by main.go:444-446). On success the client is passed to `loginAndClose` at main.go:493, which defers `Close` (main.go:507-512) and calls `GetVaultClient` (main.go:511) to hand the raw client to `AuthenticateAndGetToken`; `LocalVaultClient.Close` being a no-op (main.go:57-59) means no resource is released there and no error can be logged. On error, `run` substitutes `context.Cause(ctx)` when a signal arrived (main.go:486-490) and `main` writes the message to stderr via `log.Fatal` (main.go:424-425).

The two tests are the only other callers: main_test.go:254 (no cert file, expects the group/other rejection and no path leakage) and main_test.go:294 (per-case missing / mode 000 / directory key, expecting `errors.Is` against `fs.ErrNotExist` / `fs.ErrPermission` and no name leakage).

Shared state: the config file at `<homeDir>/.yubivault/config.yml` (main.go:102-137, fields main.go:35-36); the key and certificate files under the same directory (main.go:157, :161), written outside the program; the `.yubivault` constant itself (main.go:100), shared with `LoadConfig`; the returned client and its transport-embedded certificate; the key bytes, never wiped; the process signal state armed just before the call (main.go:474-476).

## Open questions

- Whether the config-supplied file names are meant to be confined to `~/.yubivault`: README.md:63-64 and README.md:80 show plain names in that directory, but no doc statement or code check covers absolute or `..` values, and `filepath.Join` resolves `..` out of the directory (verified empirically). unclear; need to inspect issue/PR history outside this repo.
- Whether the certificate error's inclusion of the resolved path (main.go:163) is intended given the deliberate suppression for the key (main.go:176-178, main.go:203-211). No test or comment addresses the cert message; unclear; need to inspect the CodeQL configuration referenced at main.go:177.
- Whether support for a `unix://` `vaultAddr` in `-local` is intended, since vault-client-go would replace the 5s dialer from main.go:365 (client.go:98-116). unclear; need to inspect docs for any unix-socket intent.
- Whether key-file ownership or file type should be part of the contract: main.go:183-201 tests mode bits only, and README.md:80 documents only the group/other rule. unclear; need to inspect the intended threat model for `~/.yubivault`.
- Where certificate expiry is expected to be enforced, since `tls.X509KeyPair` does not check it (crypto/tls/tls.go:307-352) and the first handshake is in `AuthenticateAndGetToken` (main.go:393-397). unclear; need to inspect PKI-SETUP.md and the server-side cert-auth configuration.
- Whether anything relies on environment (proxy, CA bundle) being resolved at construction rather than at request time: the cloned transport inherits `DefaultTransport`'s Proxy func (main.go:364, comment at main.go:358-362). unclear; need to inspect tests/docs for such an expectation.
