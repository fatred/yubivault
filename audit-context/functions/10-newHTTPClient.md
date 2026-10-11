# newHTTPClient

## Function and scope

`newHTTPClient(tlsConfig *tls.Config) *http.Client` is defined at main.go:363-374 with its rationale comment at main.go:358-362. It builds the HTTP transport and client used for all Vault traffic: it clones `http.DefaultTransport` (main.go:364), replaces `DialContext` with a fresh dialer bounded by `dialTimeout` (main.go:365), installs the caller's TLS config (main.go:366), and returns an `*http.Client` with `Timeout: requestTimeout` and a `CheckRedirect` that refuses every redirect (main.go:367-373). It has exactly one production caller, `newVaultClient` (main.go:329), and two test callers (main_test.go:477, main_test.go:554). The function owns no state of its own: the transport, the client and the closure are all created per call.

## Inputs and outputs

Input: one non-nil `*tls.Config` (dereferenced only as `GetClientCertificate`/`MinVersion` by the caller's `clientTLSConfig`, main.go:349-356; the pointer is stored, not copied). Output: a non-nil `*http.Client`; there is no error return and no failure mode inside the body. The two package-level constants that parameterise it are `dialTimeout = 5 * time.Second` and `requestTimeout = 30 * time.Second` (main.go:318-321).

## Invariants

- No fallible work: main.go:363-374 cannot fail and cannot return nil; the only panic path is the type assertion at main.go:364, which holds for the stdlib default (net/http/transport.go:47).
- Transport identity: fields come from the DefaultTransport clone (net/http/transport.go:47-57, Clone at :344): `Proxy=ProxyFromEnvironment`, `ForceAttemptHTTP2=true`, `MaxIdleConns=100`, `IdleConnTimeout=90s`, `TLSHandshakeTimeout=10s`, `ExpectContinueTimeout=1s`. A throwaway replica of the function confirmed proxyFunc=true, idle=1m30s, tlsHandshake=10s, expectContinue=1s, maxIdleConns=100, forceH2=true, respHeaderTimeout=0s, maxIdlePerHost=0.
- Dial bound: `DialContext` is replaced at main.go:365, so the only connect bound is `net.Dialer.Timeout` = `dialTimeout` (main.go:319). `dialCtx` turns that Timeout into one context deadline for the whole call (net/dial.go:563-582, :254-268), covering DNS resolution and all candidate addresses (net/dial.go:529-558). Observed: dial to an unroutable address returned `i/o timeout` after exactly 5s.
- TLS config replacement and aliasing: main.go:366 discards the clone's TLS config and stores the caller's pointer. On first use, with `ForceAttemptHTTP2` true (net/http/transport.go:439-475), the transport configures the bundled HTTP/2 implementation and writes `adjustNextProtos(...)` into `t.TLSClientConfig.NextProtos` (net/http/http2.go:284-310; net/http/server.go:3694-3714), i.e. it mutates the caller's object - observed `NextProtos` becoming `[h2 http/1.1]`. No RootCAs, ServerName, Certificates or InsecureSkipVerify are set here.
- Timeouts: `Client.Timeout` = 30s bounds each `http.Client.Do`, body reads included (main.go:369; net/http/client.go:92). `ResponseHeaderTimeout` remains 0. On the library parse path the same 30s is also installed as a request-context deadline (client_requests.go:170-173), and the retry loop consults that context (go-retryablehttp/client.go:722-725), so the retry budget shares it.
- Redirect refusal at the transport layer: `CheckRedirect` returns `http.ErrUseLastResponse` (main.go:370-372), which http.Client consumes rather than propagating - the 3xx response is returned with a nil error and an open body (net/http/client.go:73, :496-500, :716-720). Observed: status 302, err=nil, `Location: /next`. Retry policy therefore sees a non-error response and does not retry it (go-retryablehttp/client.go:495-546, :722).
- Redirect policy is not 'none': vault-client-go's `send` loop handles 301/302/307 itself with at most one hop, refusing an https->http hop, and re-issues the same request with `req.URL = redirectTo` (client_requests.go:319-334, :369-424, :398-410, :421), so the outstanding `X-Vault-Token` header set at client_requests.go:263 travels with the single allowed hop when that hop stays on https.
- Pool shape: `MaxIdleConnsPerHost` stays 0 on the clone, i.e. net/http uses `DefaultMaxIdleConnsPerHost = 2` (net/http/transport.go:60-62, :1118-1121); this differs from the library's own cleanhttp default of GOMAXPROCS+1 (go-cleanhttp@v0.5.2/cleanhttp.go DefaultPooledTransport), which the clone replaces.
- Single client instance: the same `*http.Client` becomes both the plain and the retryable client inside vault-client-go (client.go:65, :69), so every bound above applies to retries too (client_requests.go:352-364).

## Assumptions

- `http.DefaultTransport` is and stays an `*http.Transport`; nothing in the repo reassigns it (only reference: main.go:364).
- The overall unreachable-host budget is around dialTimeout + backoff(1-1.5s) + dialTimeout, as the comment at main.go:316-321 claims: `RetryMax: 1`, `RetryWaitMin: 1s`, `RetryWaitMax: 1500ms` (main.go:333-338) with `LinearJitterBackoff` yielding 1-1.5s at attempt 1 (go-retryablehttp/client.go:525-546); this sits inside the 30s context. Commit e4bfeab ('fail in ~11s instead of 60s when Vault is unreachable (#26)') documents the intent, and `TestNewVaultClient_RetriesOnce` passes (observed, 1.13s).
- Proxy environment is snapshotted once per process (net/http/transport.go:519-520, :1032-1042), which the repo's own test documents (main_test.go:469-472) and which passes (observed).
- Proxy egress dials through the same custom `DialContext` and, after a 200 CONNECT, does TLS and adopts HTTP/2 when ALPN yields h2 (net/http/transport.go:2046-2071).
- Server authentication depends on Go's system root pool, which honours SSL_CERT_FILE/SSL_CERT_DIR (crypto/x509/root.go:127-132, cert_pool.go:108-113).
- Nothing forces https: the scheme comes from `appConfig.VaultAddr` (main.go:31) via `vault.WithAddress` (main.go:328) and is not inspected by this function; an http:// address would leave TLSClientConfig unused. [INFERENCE]
- Vault env overrides (VAULT_SKIP_VERIFY, VAULT_DISABLE_REDIRECTS, VAULT_MAX_RETRIES, ...) are not active here because only `vault.WithEnvironment` populates them (client_option.go:166-170) and `newVaultClient` does not pass it (main.go:327-338).

## Calls

`http.DefaultTransport.(*http.Transport).Clone()` (main.go:364; net/http/transport.go:344) - no error to propagate; panic only if the global is not an *http.Transport. `(&net.Dialer{...}).DialContext` (main.go:365) - dial errors surface as `*url.Error` from `Client.Do`. The `http.Client` literal (main.go:367-373) performs no calls. The `CheckRedirect` closure (main.go:370-372) is executed by http.Client for each 3xx and its sentinel is consumed there (net/http/client.go:716-720), never returned to the Vault caller. `ProxyFromEnvironment` is inherited through the clone, not called here (net/http/transport.go:519-520), and is snapshotted once (transport.go:1032-1042). Everything else is black-box: the request itself is issued by vault-client-go via `c.client.Do` / `c.clientWithRetries.Do` (client_requests.go:352-364), so h1-vs-h2, ALPN and CONNECT details are decided inside net/http and are not observable from this function.

## Callers and shared state

Callers: `newVaultClient` (main.go:326-338; call at main.go:329) reaches here for both auth modes (-local via main.go:169, -yubi via main.go:306); tests call it directly at main_test.go:477 and main_test.go:554. Shared state: the caller's `*tls.Config` pointer is aliased and mutated by the transport (main.go:366; net/http/http2.go:284-310) - fresh per call here (main.go:329 with main.go:349-356); the process-global `http.DefaultTransport` is cloned, never written (main.go:364); process environment (proxy vars, SSL_CERT_FILE/SSL_CERT_DIR) influences behaviour at first-request time; and the returned client, plus its pool, is owned by the vault.Client and shared by CertLogin (main.go:398) and TokenLookUpSelf (main.go:413) - stored twice inside the library (client.go:65, :69).

## Open questions

- Whether the HTTPS_PROXY tunnel in a real deployment negotiates h2: the stdlib adopts HTTP/2 after CONNECT only when ALPN returns h2 (net/http/transport.go:2046-2071); the repo's proxy test proxy rejects the tunnel (main_test.go:481-489), so that path is unexercised here.
- Whether a non-https vaultAddr is reachable in practice: nothing in main.go:363-374 or main.go:102-139 constrains the scheme, so plaintext egress with an unused client certificate is not excluded. [INFERENCE, not observed]
- unclear; need to inspect whether the 3xx response body is closed on the redirect path: http.Client leaves it open with ErrUseLastResponse (net/http/client.go:716-720) and the vault send loop re-issues without closing (client_requests.go:319-334, :369-424).
- unclear; need to inspect socks5 proxy handling combined with the replaced DialContext (net/http/transport.go:1938-1944); not covered by any repo test.
- unclear whether the 30s context deadline or the 5s/10s TLS path bounds the -yubi handshake first, since the crypto11 signature happens during the handshake (main.go:296-306) and only TLSHandshakeTimeout (10s, inherited) covers it.
