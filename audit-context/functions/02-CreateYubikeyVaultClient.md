# CreateYubikeyVaultClient

## Function and scope

`CreateYubikeyVaultClient(appConfig *AppConfig, tokenPin string) (*YubikeyVaultClient, error)` (main.go:273-313) is the `-yubi` constructor. It (1) configures crypto11 against the config-supplied PKCS#11 module and YubiKey PIV serial, passing the caller-supplied PIN (main.go:277-284), (2) enumerates the card's paired certificates and selection-picks one using the config CN (main.go:297-304), (3) builds the Vault client that will present that certificate (main.go:306-309), and (4) transfers ownership of the crypto11.Context into the returned wrapper (main.go:312). It has no `context.Context` parameter and no timeout of its own; the caller documents it as not ctx-aware (main.go:482-483).

## Inputs and outputs

Inputs: `appConfig` — read fields are `OpenScPath` (main.go:278), `YubikeyPivSerial` (main.go:279), `YubikeyCertCN` (main.go:301) and `VaultAddr` (main.go:306); `tokenPin` — passed unchanged as `Config.Pin` (main.go:280). Outputs: on success a `*YubikeyVaultClient` holding both the `*vault.Client` and the `*crypto11.Context` (main.go:312, struct at main.go:62-66); on any failure `nil, err` (main.go:283, 299, 303, 308). Errors from the two crypto11 calls are wrapped with `%w` and fixed prefixes (main.go:283, main.go:299); the selectCertificate and newVaultClient errors are returned verbatim (main.go:303, main.go:308).

## Invariants

Cleanup split. Configure failure returns before the defer exists (main.go:282-284 vs main.go:289) and Configure itself returns a nil context on failure (crypto11.go:425-427, 458-463, 474-482). After a successful Configure, all three later error returns (main.go:299, 303, 308) run the defer at main.go:289-293, which closes the context once.

Success path. The guard at main.go:290 reads the function-scope `err` declared at main.go:274; because `pairs, err :=`, `tlsCert, err :=` and `client, err :=` (main.go:297, 301, 306) assign to that same variable, `err` is nil at main.go:312, so the defer does not close, and ownership passes to the wrapper. The wrapper's `Close` closes only when `cryptoCtx != nil` (main.go:72-77), and the only production call is loginAndClose's defer (main.go:508-512) around the single consumer (main.go:493). One close per context is load-bearing: a second `Context.Close` panics via "referenced module not found" (crypto11.go:355-370, 381).

Lifetime coupling. The private key inside the returned `tls.Certificate` holds the `*Context` (keys.go:161-172) and signs through pooled sessions (rsa.go:458; sessions.go:46-54); after Close, session checkout fails with "context is closed" (sessions.go:58-72). The certificate therefore remains valid only while the wrapper is unclosed, which matches the caller closing after the whole login attempt (main.go:493).

Content invariants. Each pair is non-nil-Leaf and has `Certificate[0] == Leaf.Raw` (certificates.go:155-165); the chain presented is the leaf alone (certificates.go:164) delivered via `GetClientCertificate` (main.go:349-360). Selection is one pair when `yubikeyCertCN` is empty and there is exactly one pair, otherwise CN equality on the parsed leaf (main.go:217-243). Nothing here reads files, environment, or the clock (body main.go:273-313).

## Assumptions

The module path is loadable and the serial selects exactly one token: Configure enforces exactly one selector and fails otherwise (crypto11.go:394-406); the mode-required fields are checked by requireForMode (main.go:142-152) before the call (main.go:456, 484). The PIN is non-empty by the time it arrives (main.go:259-269). Configure logs in immediately on the persistent session and retains the Config (including the PIN) for the context lifetime (crypto11.go:429-432, 458-479), tolerating `CKR_USER_ALREADY_LOGGED_IN` (crypto11.go:474-479). Pairing of key to certificate is by CKA_ID with no public-key comparison (keys.go:108-186, main.go:295-296). That the selected credential is the one the operator provisioned and that the server accepts a leaf-only chain are properties outside this repo.

## Calls

`crypto11.Configure` (external, crypto11.go:392) — module load, token selection by serial, session, PIN login; errors wrapped at main.go:283. `(*crypto11.Context).FindAllPairedCertificates` (external, certificates.go:125) — CKO_PRIVATE_KEY enumeration paired by CKA_ID under a pooled session; errors wrapped at main.go:299, and a closed context yields `errClosed` (certificates.go:126-128). `selectCertificate` (internal, main.go:217) — card-supplied pairs + config CN, error verbatim at main.go:303. `newVaultClient` (internal, main.go:326) with `newHTTPClient` (main.go:363) and `clientTLSConfig` (main.go:349) — builds the client that presents the card certificate. Deferred `(*crypto11.Context).Close` (external, crypto11.go:540) — discards its error at main.go:291; on the success path the error surfaces through `YubikeyVaultClient.Close` and is only logged (main.go:509-512).

## Callers and shared state

Only `run` calls it in production (main.go:484, `-yubi` branch), and `TestCreateYubikeyVaultClient_InvalidModule` covers the Configure-failure path (main_test.go:374-388). Shared state touched: crypto11's `moduleReferences` registry and its mutex (crypto11.go:307-308, 317-347, 355-388) through Configure and the two close sites; the token's persistent, logged-in PKCS#11 session (crypto11.go:458-479, released at 540-557); the wrapper's unexported `cryptoCtx` ownership field (main.go:62-66, 72-77); and the `*vault.Client` with its transport and certificate provider (main.go:312, 326-376).

## Open questions

Whether any reachable crypto11 error string embeds the PIN, module path or token content (unclear; need to inspect each error construction with real output); whether `Context.Close`'s `C_Finalize`/`C_Destroy` is safe on this OpenSC/YubiKey combination after a login (unclear; need a real-card end-to-end run); whether `refCount > 1` is reachable so that Close merely decrements (unclear; grep finds Configure only at main.go:277); which PIV slots the module enumerates for CKO_PRIVATE_KEY (unclear; module configuration outside this repo); whether the Vault role accepts a leaf-only chain (unclear; server-side configuration); whether a success-path Close is exercised anywhere against a real context (unclear; only the nil-context Close is unit-tested, main_test.go:350-356).
