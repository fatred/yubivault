# readPrivateKey

## Function and scope

`readPrivateKey(keyPath string) ([]byte, error)` occupies main.go:183-201 and returns the `-local` client private-key bytes. Supporting declarations: the `keyFileField` constant (main.go:176-178) and `pathErrCause` (main.go:203-211). Its sole caller is `CreateLocalVaultClient` (main.go:155-174), which calls it first (main.go:157) and forwards the bytes to `tls.X509KeyPair` (main.go:166); the error is propagated unchanged (main.go:158-159).

The function performs three steps in a fixed order over one open file description: open the path read-only (main.go:184), fstat that descriptor and reject the file if any group/other rwx bit is set (main.go:189-195), then read the descriptor to EOF (main.go:196-200). The comment at main.go:180-182 states the intent: the check is fail-secure and applies to the opened file, "so the file that is checked is the file that is read". The comment at main.go:176-177 states the second intent: errors never echo the path, because it comes from `CertAuthKeyFile` and must not reach logs (CodeQL `go/clear-text-logging`). Documentation of the policy for users is README.md:80.

## Inputs and outputs

Input: one string, the already-joined key path. It is built by the caller as `filepath.Join(homeDir, configDirName, appConfig.CertAuthKeyFile)` (main.go:157), where `homeDir` comes from `os.UserHomeDir()` (main.go:448, which on Unix returns `$HOME`, /home/jhow/.go/src/os/file.go:605-615) and `configDirName` is the constant `.yubivault` (main.go:100). `filepath.Join` is lexical: the unix implementation joins with `/` and calls `Clean` (/home/jhow/.go/src/path/filepath/path_unix.go:32-39, reached through `Join` at /home/jhow/.go/src/path/filepath/path.go:130), so `..` elements in the configured name are resolved lexically and can leave the directory; no containment check exists in this function.

Output on success: the exact bytes returned by `io.ReadAll` (main.go:196, main.go:200) — no parsing, no validation against the certificate, no length check. Output on every failure path: `nil` bytes plus a wrapped error (main.go:186, main.go:191, main.go:194, main.go:198).

Four distinct failures are reachable:

1. `os.Open` fails (main.go:184-187): read-only open rejected (missing file, wrong mode on a restrictive directory, permission denied, ELOOP, and so on). The stdlib returns `*fs.PathError{Op: "open", Path: name, Err: e}` (/home/jhow/.go/src/os/file_unix.go:267); `pathErrCause` reduces it to `Err` (main.go:205-209) and main.go:186 wraps that with `%w`.
2. `f.Stat` fails (main.go:189-192): fstat on the descriptor; the stdlib wraps with `f.wrapErr("stat", err)` producing a `*fs.PathError` (/home/jhow/.go/src/os/stat_unix.go:15-25); path stripped the same way (main.go:191). The deferred `f.Close` (main.go:188) still runs.
3. Group/other permission present (main.go:193-195): `info.Mode().Perm()` returns only the low 9 bits because `Perm` is `m & ModePerm` (/home/jhow/.go/src/io/fs/fs.go:254-256); `perm&0o077 != 0` returns before any content is read, and the message carries the octal mode via `%#o` (main.go:194). Because only `Perm()` is consulted, setuid/setgid/sticky bits (surfaced separately as `ModeSetuid`/`ModeSetgid`/`ModeSticky`, /home/jhow/.go/src/os/stat_linux.go:13-44) do not satisfy the mask, so a mode such as 0o4600 passes.
4. `io.ReadAll` fails (main.go:196-199): a non-EOF error from reading the descriptor, path stripped (main.go:198). `ReadAll` maps EOF to a nil error and grows buffers from an initial 512 bytes (/home/jhow/.go/src/io/io.go:709-752, :712, :722), so size is unbounded and other data than a size check bounds the read.

The open itself is `os.Open` → `OpenFile(name, O_RDONLY, 0)` (/home/jhow/.go/src/os/file.go:389-391) → `openFileNolog` (/home/jhow/.go/src/os/file.go:410-412), which opens with `flag|syscall.O_CLOEXEC` (/home/jhow/.go/src/os/file_unix.go:261) via `syscall.Open(path, flag, perm)` (/home/jhow/.go/src/os/file_open_unix.go:14-16). No `O_NOFOLLOW`, `O_NONBLOCK`, `O_DIRECTORY` or size flags are added anywhere in that chain.

## Invariants

- Check and read share one file description. `os.Open` (main.go:184), `f.Stat` (main.go:189) and `io.ReadAll(f)` (main.go:196) all act on the same `*os.File`; `(*File).Stat` is an fstat on the fd (/home/jhow/.go/src/os/stat_unix.go:15-25, :20), not a path stat. There is therefore no path-based window between the mode check and the read inside this function.
- The rejection precedes the read: the `perm&0o077` branch returns at main.go:194, before main.go:196.
- The mask is 0o077 against the 9 permission bits only (main.go:193; /home/jhow/.go/src/io/fs/fs.go:254-256).
- Every error names the key only as `keyFileField` (main.go:178; used at main.go:186, :191, :194, :198) and never the path; path-bearing `*fs.PathError` values are decomposed by `pathErrCause` (main.go:205-211).
- Wrapping uses `%w` (main.go:186, :191, :198), so `errors.Is` still matches the underlying cause; `pathErrCause` returns `pathErr.Err` for `*fs.PathError` and the input otherwise (main.go:206-209).
- Failure returns `nil` bytes (main.go:186, :191, :194, :198); success returns exactly the `ReadAll` slice (main.go:200).
- One descriptor at most, released by the deferred `Close`, whose error is discarded (main.go:184, main.go:188).
- The mode consulted describes the opened target, since the open follows symlinks and fstat reports that inode; no `O_NOFOLLOW` exists in the open chain (/home/jhow/.go/src/os/file_unix.go:261, /home/jhow/.go/src/os/file_open_unix.go:14-16). [INFERENCE: Linux open(2) follows a symlink at the final component.]

## Assumptions

- `keyPath` is trusted config data. It derives from `AppConfig.CertAuthKeyFile` (main.go:42, read from `~/.yubivault/config.yml` by `LoadConfig`, main.go:103-108) joined at main.go:157, and `filepath.Join` only cleans lexically (/home/jhow/.go/src/path/filepath/path_unix.go:32-39). The function itself performs no containment or validation of the name.
- `$HOME` is caller-controlled (main.go:448; /home/jhow/.go/src/os/file.go:605-615), so the directory prefix is session-controlled.
- The permission bits are taken as sufficient evidence of group/other access: only `Mode().Perm()` is inspected (main.go:193-195); ACLs, capabilities, and the parent directory's mode are not consulted anywhere in main.go, even though README.md:51 documents `chmod 700 ~/.yubivault`.
- No concurrent modification is assumed between main.go:189 and main.go:196: one fd, no locking, no re-check after the read.
- The path is assumed to name something openable read-only; file type and size are not policed (no `IsRegular`, no size limit at main.go:189-195). The directory case is treated as an error by the integration test (main_test.go:283-287, assertions in the loop at main_test.go:292-307).
- The returned bytes are assumed to be PEM that `tls.X509KeyPair` accepts; validation lives at main.go:166, not here.
- Rejection is preferred to reading: the caller deliberately reads the key before the certificate so the permission failure surfaces first (comment main.go:156), and the test `TestCreateLocalVaultClient_RejectsWorldReadableKey` (main_test.go:240-262) runs with no certificate file present, asserting the message contains "group/other" (main_test.go:255) and not the key path or configured name (main_test.go:260).
- Under euid 0 an open of a mode-000 file succeeds, so the mode check is not the only gate in practice; the suite encodes this as a skip (main_test.go:273-274).

## Calls

External, source-available in the installed toolchain (go1.27.2, /home/jhow/.go/VERSION):

- `os.Open` (/home/jhow/.go/src/os/file.go:389-391 → os/file_unix.go:246-267). Assumption: the resolved path is reachable and the open is permitted; outcomes not excluded: symlink traversal at any component, FIFO open blocking until a writer appears, device nodes, and any `open(2)` error. Propagates nothing on success; on failure it yields a path-bearing `*fs.PathError` whose path is stripped before it leaves this function (main.go:186).
- `(*os.File).Stat` (/home/jhow/.go/src/os/stat_unix.go:15-25). Assumption: the fd is valid (it is, post-open). Failure form is again a `*fs.PathError`, stripped at main.go:191.
- `info.Mode().Perm()` (/home/jhow/.go/src/io/fs/fs.go:254-256), error-free.
- `io.ReadAll` (/home/jhow/.go/src/io/io.go:709-752). Assumption: the descriptor reaches EOF. Bounded by neither size nor time (:712, :722); a read error other than EOF is propagated (main.go:198), EOF is not (io/io.go:724-726).
- `(*os.File).Close`, deferred (main.go:188); error discarded.
- `fmt.Errorf` (main.go:186, :191, :194, :198); `%w` preserves the chain, `%#o` renders the mode.

Internal:

- `pathErrCause` (main.go:205-211). Pure; matches `*fs.PathError` with `errors.As` and returns `pathErr.Err` (main.go:206-209), else the input unchanged (main.go:209). Non-nil in for non-nil in, so `%w` always wraps a non-nil error.

## Callers and shared state

Sole caller: `CreateLocalVaultClient` (main.go:155-174). It calls this function before reading the certificate (main.go:157, per the comment at main.go:156), returns the error unwrapped (main.go:158-159), and passes the bytes to `tls.X509KeyPair` (main.go:166) — so a `readPrivateKey` failure prevents the certificate from being touched at all. The certificate read (main.go:161) uses plain `os.ReadFile` and its error does include that path (main.go:163); path suppression is specific to the key.

Upstream: `run` (main.go:432) reaches this path only under `-local` (main.go:480), with `homeDir` from `os.UserHomeDir()` (main.go:448). It propagates out of `CreateLocalVaultClient` into `run`, which substitutes `context.Cause(ctx)` if a signal arrived (main.go:494-503), and `main` writes the result to stderr with `log.Fatal` (main.go:423-426).

Tests that reach it, always through `CreateLocalVaultClient`: `TestCreateLocalVaultClient_RejectsWorldReadableKey` (main_test.go:240-262, key forced to 0644 at main_test.go:246-247, asserts "group/other" at :255 and absence of the path at :260) and `TestCreateLocalVaultClient_KeyErrorsDoNotLeakPath` (main_test.go:264-311, cases missing / mode 000 / directory at :269-287, asserts `errors.Is` at :302 and absence of the configured name at :306). No test calls `readPrivateKey` or `pathErrCause` directly (no matches for either identifier in main_test.go).

Shared state: the key file itself (path from `AppConfig.CertAuthKeyFile`, main.go:42, joined at main.go:157) — read only, never written; `$HOME` (main.go:448); the `configDirName` constant (main.go:100), shared with `LoadConfig` and the certificate read; and `keyFileField` (main.go:178), shared by the four error paths and relied on by the tests. No package-level variable is read or written by this function, and its only output to the rest of the program is the returned slice, consumed at main.go:166. Process-wide, it takes one descriptor and releases it via the defer at main.go:188.

## Open questions

- Ownership is never inspected (main.go:189-195 uses only `Perm()`). Whether an owner/uid requirement is intended is unclear; need to inspect README.md:80 and PKI-SETUP.md for a stated owner policy.
- Whether a symlink at the final path component is in scope for the "file checked equals file read" property is unclear; `os.Open` adds no `O_NOFOLLOW` (/home/jhow/.go/src/os/file_unix.go:261, /home/jhow/.go/src/os/file_open_unix.go:14-16). unclear; need to inspect repo docs or history for a stated intent.
- Non-regular files (FIFO, device, socket) are not excluded by main.go:189-195; whether a regular-file requirement is intended is unclear; need to inspect README.md.
- The containing directory's permissions are documented (README.md:51) but not enforced by this function or `LoadConfig` (main.go:103-108 opens the config with no stat or mode check); whether enforcement is intended elsewhere is unclear; need to inspect the `LoadConfig` tests in main_test.go.
- Whether `keyPEM` (main.go:196, returned at :200) is retained or zeroed after `tls.X509KeyPair` (main.go:166) is unclear; this function keeps no reference after returning. unclear; need to inspect crypto/tls/tls.go:258 and its callers.
- Whether `tls.X509KeyPair` error text at main.go:166 can embed key material before it reaches `log.Fatal` (main.go:423-425) is unclear; need to inspect crypto/tls source.
- All stdlib citations are from the installed go1.27.2 toolchain (/home/jhow/.go/VERSION); behaviour under other Go releases is not covered.
