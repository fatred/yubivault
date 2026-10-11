# newVaultClient

## Function and scope

`newVaultClient(addr string, cert tls.Certificate) (*vault.Client, error)` (main.go:326-343) is the single construction point for the Vault API client used by both authentication modes. It does not touch the network: it only assembles configuration and returns a `*vault.Client` (main.go:342). Two internal helpers are part of its scope: `clientTLSConfig` (main.go:349-356), which produces the TLS settings, and `newHTTPClient` (main.go:363-374), which produces the `*http.Client`; both are called inline in the option list (main.go:329). The two timeouts it feeds into both layers are package constants: `dialTimeout = 5 * time.Second` and `requestTimeout = 30 * time.Second` (main.go:319-320).

Its documented purpose is exactly this sharing: the doc comment states that `-local` and `-yubi` both use it "so they share transport, timeouts and retries" (main.go:322-325).

## Inputs and outputs

Inputs: `addr` (from `appConfig.VaultAddr`, a hand-written `~/.yubivault/config.yml` value, passed by both callers at main.go:169 and main.go:306) and `cert` (a `tls.Certificate` either parsed from PEM files at main.go:164-168 or paired from the YubiKey at main.go:284-300). There is no context, no timeout parameter and no retry parameter — all four behaviours are fixed inside the function.

Output: `*vault.Client` on success; on failure `nil` plus an error wrapping the library error with the fixed prefix `failed to create Vault client: ` (main.go:340). The address is not included in that message. No token is present on the returned client; it is added later by `AuthenticateAndGetToken` (main.go:407-409).

## Invariants

- Address, HTTP client, request timeout and retry policy are set in one `vault.New` call and are not independently adjustable (main.go:327-338). Options are applied over `DefaultConfiguration()` in order (vault-client-go@v0.4.3/client.go:56-62).
- `RetryMax: 1` (main.go:334) means **two** attempts per request: `remain := c.RetryMax - i; if remain <= 0 { break }` (go-retryablehttp@v0.7.8/client.go:761-763). The library default it replaces is 2 retries, documented as "three tries" (vault-client-go@v0.4.3/client_configuration.go:174-177), matching the in-code rationale about stacking retries on connect timeouts (main.go:331-332). The test at main_test.go:565-585 asserts the server sees exactly 2 requests.
- Because `CheckRetry`, `Backoff` and `ErrorHandler` are left nil, the library substitutes `DefaultRetryPolicy` (retryablehttp default plus 412), `LinearJitterBackoff` and `PassthroughErrorHandler` (vault-client-go@v0.4.3/client_option.go:66-89, client_configuration.go:226-231, 349-358). The base policy retries 5xx except 501, 429, and most `*url.Error` values, and refuses to retry once the context is done (go-retryablehttp@v0.7.8/client.go:472-539).
- Retry waits are 1s..1.5s scaled by attempt number (main.go:335-336; `LinearJitterBackoff` at go-retryablehttp@v0.7.8/client.go:619-637).
- Two independent 30s budgets exist: `http.Client.Timeout` (main.go:369) is evaluated per `Do` (net/http/client.go:199-204, 264), while the library's `RequestTimeout` becomes a context deadline covering the whole call including retries and sleeps (main.go:330, vault-client-go@v0.4.3/client_requests.go:170-176). The tighter of the two wins. Each of the two requests in the login flow gets its own budget (main.go:398 and 412).
- Dial time is bounded per attempt by `dialTimeout` through an explicit `net.Dialer` (main.go:365), overriding the cloned transport's 30s dialer (net/http/transport.go:47-52). Transport-level settings come from the clone: proxy function, HTTP/2 attempt flag, idle/handshake timeouts (net/http/transport.go:47-58).
- Redirects are not consumed by net/http (`ErrUseLastResponse`, main.go:370-372), identical to the library's own default client (client_configuration.go:222-231); the library's `send` loop performs at most one redirect and rejects downgrades (client_requests.go:292-333, 369-428).
- The client certificate is presented regardless of advertised CA names (main.go:349-353), verified by main_test.go:533-563.
- TLS verification settings are untouched: no `RootCAs`, `ServerName` or `InsecureSkipVerify`, and the library's TLS block stays empty so it is not applied (client_configuration.go:378-402, client.go:114-126).
- No `VAULT_*` environment value reaches the configuration, because `WithEnvironment` is never passed (client_option.go:167-171; the env tags at client_configuration.go:44-58, 177 are inert here).
- The transport is a fresh clone per call (main.go:364), so the connection pool is private to each client instance.

## Assumptions

- The private key in `cert` is a working signer for the whole lifetime of the client. `newVaultClient` never inspects it; for `-yubi` the key is backed by the PKCS#11 session whose lifetime is owned by `YubikeyVaultClient` (main.go:77-82, 306-313).
- `vaultAddr` is a URL `url.Parse` accepts; scheme correctness is deliberately not enforced upstream (`LoadConfig` comment at main.go:118-121). Only genuine parse failures (vault-client-go@v0.4.3/client.go:147-151) or a non-`*http.Transport` transport for a `unix://` address (client.go:100-113) can make construction fail.
- `http.DefaultTransport` is still a `*http.Transport`, required by the unchecked assertion at main.go:364; nothing in this program reassigns it.
- Proxy use through `HTTPS_PROXY`/`NO_PROXY` is intended and its lookup is cached process-wide (main_test.go:469-472 documents the caching; main_test.go:473-505 asserts the proxy is used).
- Callers use the client for one short login sequence and then close it (main.go:454-463, 505-514).

## Calls

- `vault.New` — the only call that can fail in a way this function reports (main.go:327, 339-341).
- `vault.WithAddress` (main.go:328) — assignment only, no validation (client_option.go:21-25).
- `newHTTPClient(clientTLSConfig(cert))` (main.go:329) — both internal, neither returns an error; together they always produce a non-nil client whose transport has the dial timeout and the client certificate wired in (main.go:349-374).
- `vault.WithRequestTimeout(requestTimeout)` (main.go:330) — rejects only negative values (client_option.go:46-53); unreachable here.
- `vault.WithRetryConfiguration` (main.go:333-337) — cannot fail; fills the three nil policy fields from defaults (client_option.go:66-89).
- Transitive, at first request: `retryablehttp.Client.Do` -> `http.Client.Do` per attempt, with the body buffered for resends (vault-client-go@v0.4.3/client_requests.go:349-356; go-retryablehttp@v0.7.8/client.go:666-719), body drained between attempts and backoff aborted by context cancellation (go-retryablehttp@v0.7.8/client.go:772-790). Errors that reach the caller are `*vault.ResponseError` for non-2xx/3xx (errors.go:37-51, isResponseError at errors.go:66-73) or the underlying `*url.Error`/context error.

## Callers and shared state

Callers: `CreateLocalVaultClient` (main.go:169), `CreateYubikeyVaultClient` (main.go:306) and `TestNewVaultClient_RetriesOnce` (main_test.go:574). Both production callers pass `appConfig.VaultAddr` unchanged.

Shared state: the two timeout constants (main.go:319-320); the process-global, once-cached proxy environment lookup reached through the cloned `ProxyFromEnvironment` (main.go:364, net/http/transport.go:47-48, main_test.go:469-472); the certificate captured in the `GetClientCertificate` closure (main.go:350-353), whose `-yubi` private key is a PKCS#11-backed signer tied to the session owned by `YubikeyVaultClient` (main.go:77-82); and the returned client's own `clientRequestModifiers.headers.token`, written later by `SetToken` (request_modifiers.go:54-64 via main.go:91-93 and 407-409) under `clientRequestModifiersLock` (client_requests.go:242-246). `vault.Client.Clone` would share the same `http.Client` and `retryablehttp.Client` pointers (client.go:168-174), so a clone of this client shares its transport and retry wrapper — relevant because the library's redirect handling can extend a call past a single attempt.

## Open questions

1. `unix://` vaultAddr is not covered by tests or docs; the library swaps in its own `DialContext` for that scheme (client.go:153-160, 100-113), which would drop the `dialTimeout` installed at main.go:365. Behaviour of this path is unclear; need to inspect/test it.
2. crypto11@v1.6.8 was not read; whether a `tls.Certificate` signer fails cleanly or blocks if a handshake runs after `Context.Close` is unclear; need to inspect that module.
3. No timing test exists for the reachable worst case (dial timeout + backoff + dial timeout, and two sequential 30s library budgets). The 11-11.5s per-call figure is [INFERENCE] from main.go:319-320, 334-336 and client_requests.go:170-176.
4. HTTP/2 negotiation on the real endpoint is asserted nowhere; `ForceAttemptHTTP2` is inherited (net/http/transport.go:53) while `TLSClientConfig` is replaced (main.go:366). Need a live check to confirm.
5. Whether a retried cert-login (POST body resent from the buffered copy, client_requests.go:349-356) can produce two server-side logins is not observed by any test; only the final response's token is used (main.go:398-409). Need to inspect Vault-side behaviour or instrument a fake server.
