# Disposition report — `clientTLSConfig` (`main.go:349-356`)

**Questions in scope:** T1–T5 (Sonnet items 53–57). Verified from the index (`SONNET-INVESTIGATION.md:474`): `clientTLSConfig` originates five entries and appears as an origin of **no merged entry** (merges R2+A6, C3+V1, P3+D2, C4 have different origins). Nothing else to dispose.

**Verification basis (this session):** repo `7f10998`, go1.27.2 linux/amd64, GOROOT `~/.go/src`. Source read of `main.go`, `main_test.go`, `PKI-SETUP.md`, `README.md`, stdlib (`crypto/tls`, `net/http`), `vault-client-go@v0.4.3`; `go list -deps`; `go build -o /tmp/yubivault-disp .` + `go version -m`. Hardware, live Vault/OpenBao, proxies and OpenSC were **not** exercised; Sonnet "Observed" runs are reproduced only as quoted claims and are labelled report-only below.

---

## T1 (53) — What are the real listener's ALPN set and advertised CA names?

- **Sonnet:** external-unknown; callback ignores the CA list either way; `TestClientTLSConfig_PresentsCertDespiteAdvertisedCAs` covers an unrelated advertised CA.
- **My assessment — source verified:**
  - `crypto/tls/handshake_client.go:1274-1276`: `getClientCertificate` returns `c.config.GetClientCertificate(cri)` directly; `SupportsCertificate` (`common.go:1549-1576`, `RawIssuer` comparison at `:1570`) is only reached on the `Certificates`-field path. So the advertised CA names are inert for this config — confirmed, not inferred.
  - The client's ALPN set is stdlib-owned, not listener-owned: `newHTTPClient` clones `DefaultTransport` (`main.go:364`), whose `ForceAttemptHTTP2: true` (`transport.go:53`) survives the `TLSClientConfig` replacement — the "custom TLS config disables h2" case at `transport.go:489` does not apply. The write is `t.TLSClientConfig.NextProtos = adjustNextProtos(...)` (`http2.go:311`, definition `server.go:3694+`), i.e. h2 and/or http/1.1.
  - Whichever the listener selects, the certificate is presented by the *same* stage: the TLS handshake happens in net/http's `dialConn`/`addTLS` (`transport.go:1925-1933`), and an h2 connection is then handed the already-handshaken conn (`transport.go:2062-2085`, `http2AddConn`/`NewClientConn`). Internal h2 cannot dial with our config at all: `internal/http2/api.go:96-105` exposes no TLS accessor, and `internal/http2/transport.go:561-568` `newTLSConfig` builds a *fresh* `tls.Config` (see citation note below).
- **Final: TERMINATE.** The premise — that the listener's ALPN set or CA names can change this function's behaviour — is false for this code. Neither feeds any branch: the callback ignores the request info, and ALPN only picks which stdlib transport carries the same config. The live-listener evidence stays unavailable, but it is non-load-bearing, so it does not deserve a residual disposition.
- **Correction to the record:** the per-function analysis lists `internal/http2/transport.go:563-564` as a write to the shared config. Verified otherwise: that is `newTLSConfig(host)` mutating a locally constructed `tls.Config`, not our object. Citation drift, no behavioural consequence.

## T2 (54) — Does a TLS-terminating `https://` proxy draw the same client certificate?

- **Sonnet:** external-unknown; `dialConn` runs `addTLS` for the proxy hop with the same `TLSClientConfig` (`transport.go:1913-1932`) → a proxy `CertificateRequest` would reach `GetClientCertificate` [INFERENCE, not exercised]; `PKI-SETUP.md:155` documents LB-termination; remaining: a TLS-terminating proxy.
- **My assessment — source verified, citation corrected:**
  - `cm.scheme()` returns `proxyURL.Scheme` whenever a proxy is configured (`transport.go:2200-2205`). So an `https://` proxy makes the **first** hop TLS: `transport.go:1925-1933`, `addTLS` call at `:1930` (Sonnet's `1913-1932` is off by ~12 lines; the socs5/`t.dial` lines it probably meant are `:1920-1928`). For an `https` target through that proxy there is a second TLS hop after CONNECT at `:2046-2049`. Both go through `pconn.addTLS`, which clones `pconn.t.TLSClientConfig` (`:1783`) — the object built here. The inference is therefore sound at source level.
  - The configs cannot be separated: `grep ProxyTLSClientConfig` over go1.27.2 `net/http` is empty, so the proxy hop and the target hop necessarily share `GetClientCertificate`.
  - `PKI-SETUP.md:155` verified verbatim. Note the direction differs: that line covers a proxy in front of **Vault**; T2 covers an outbound `HTTPS_PROXY`. Neither the repo's `H1` test (item 48) nor Sonnet's proxy run discharges T2 — that was a plaintext CONNECT tunnel, so the *server*, not the proxy, saw the certificate.
  - Risk content: a proxy that requests a client cert receives public certificate material; the private key stays in the file/PKCS#11 token, so no credential disclosure. Worst case is a handshake refusal by a middlebox whose `ClientCAs` we cannot satisfy — the same failure mode that already exists against Vault itself, and the reason `GetClientCertificate` exists here.
- **Final: TOLERATE.** Known residual, inherent to this toolchain, no repo-fixable action (`ProxyTLSClientConfig` absent), no secret exposed, reverse-direction caveat already documented. Not a transfer: the only external party is a proxy that the operator either has or does not have, and its behaviour cannot change any code.

## T3 (55) — Is `fips140tls.Required()` true for the built binary, and does it restrict versions independently of `MinVersion`?

- **Sonnet:** *partly*; `fipstls.go:17-37` `Required()` true only when `fips140.Enabled()`; `tls/common.go:1236` filters the version list when required; observed no `GOFIPS140` build setting, and `GODEBUG=fips140=on` still completed a SoftHSM P-256 `-yubi` login (rc=0); remaining: production environment and `GODEBUG`.
- **My assessment — source verified, one premise corrected:**
  - Path corrected: the file is **`$GOROOT/src/crypto/tls/internal/fips140tls/fipstls.go`** — stdlib internal, not HashiCorp's `go-secure-stdlib/fips140tls`. `go list -deps ./...` shows only `crypto/internal/fips140*` and `crypto/tls/internal/fips140tls`; no HashiCorp FIPS package is in the graph. Content matches: `init()` at `:15-19` calls `Force()` when `fips140.Enabled()`; `Required()` at `:31-33` reads the flag; the doc comment at `:29-30` also names the `crypto/tls/fipsonly` + BoringCrypto route.
  - **`go version -m /tmp/yubivault-disp`** (built here): `go1.27.2`, no `GOFIPS140` build setting, no GOEXPERIMENT=boringcrypto line. So `Required()` is false for a binary built the way CI builds it.
  - The "independently of `MinVersion`" premise does not survive: `allowedSupportedVersionsFIPS = {TLS12, TLS13}` in **both** policies (`defaults_fips140.go:31-34`, `defaults_boring.go:25-28`), and the unconfigured client floor is already TLS 1.2 (`common.go:1239-1241` drops `v < VersionTLS12` when `MinVersion == 0`). The FIPS filter (`common.go:1236-1238`) can only delete versions we do not offer. `MinVersion: tls.VersionTLS12` (`main.go:354`) and FIPS mode are mutually compatible by construction.
- **Final: TERMINATE.** The question is answered by source plus the actual binary's build metadata: `Required()` is false today, and if an operator turns `GODEBUG=fips140=on` the version list is unchanged. Sonnet's run is **report-only** (SoftHSM, not OpenSC/YubiKey), but it is not load-bearing — no version, and no P-256/ECDSA signature scheme (`defaults_fips140.go:41-50`), is removed by FIPS mode.
- **Adjacent residual, explicitly *not* this question (operator-owned):** under `GODEBUG=fips140=on`, the cipher-suite and signature-algorithm filters (`defaults_fips140.go:60+`) apply to the whole config; a production server whose chain or negotiated cipher falls outside SP 800-140C/D would fail for reasons unrelated to this function. No repo action; it belongs with the operator's runtime environment, not with T3's version question.

## T4 (56) — What are the operator's trust store contents and `SSL_CERT_FILE`?

- **Sonnet:** external-unknown; the config sets no `RootCAs` (`main.go:349-356`).
- **My assessment — source verified:**
  - `main.go:349-356` sets exactly two fields; no `RootCAs`, `ServerName`, `InsecureSkipVerify`, `Certificates`, `CipherSuites`. Confirmed by reading the literal.
  - No dependency injects CAs either: the `vault-client-go` TLS branch runs only when `!configuration.TLS.empty()` (`client.go:112`), `empty()` at `client_configuration.go:363`, and `rootcerts.ConfigureTLS` is reached only from `TLSConfiguration.applyTo` (`client_configuration.go:407-412`). Since `newVaultClient` passes no `WithTLS` (`main.go:328-330`), verification is system-store only.
  - `README.md:92` states this verbatim and names `SSL_CERT_FILE` as the Linux override.
- **Final: TRANSFER.** The evidence — per-host `SSL_CERT_FILE`/`SSL_CERT_DIR` and system trust-store inventory, and whether the deployment's Vault/OpenBao issuing CA is installed — is entirely the platform operator's and gates whether a real login verifies at all. The repo's decision (use the system store; document it) is already made, so no local task follows. *TOLERATE would also be defensible* ("accepted residual, documented at README.md:92"); TRANSFER is chosen because the unresolved item is external evidence that can still change the deployment outcome.
- **Owner / evidence needed:** deployment owner(s) for each host that runs yubivault. Record: (a) whether `SSL_CERT_FILE`/`SSL_CERT_DIR` is set; (b) the trust-store inventory; (c) explicit confirmation the OpenBao/Vault issuing CA (organization root + intermediate per the workstation trust store) is present, including for OpenBao deployments; (d) any host using a private CA not installed system-wide. No repo change expected from any answer.

## T5 (57) — Can the h2 `NextProtos` write interleave with a handshake read of the same config object?

- **Sonnet:** answered; the write is inside `nextProtoOnce.Do(onceSetNextProtoDefaults)` (`transport.go:345`, `:612`, `:950`), `configureHTTP2` writes at `http2.go:284-312`, the `Once` completes before any dial, and each handshake reads `cloneTLSConfig(pconn.t.TLSClientConfig)` (`transport.go:1783`); `-race` tests plus a 40-request scratch run showed no race; scope go1.27.2/amd64.
- **My assessment — source verified:**
  - All three `nextProtoOnce.Do(t.onceSetNextProtoDefaults)` sites confirmed at `:345` (inside `Clone`), `:612` (top of `roundTrip`, which precedes `getConn` at `:1583` and any dial), `:950` (`CloseIdleConnections`). `onceSetNextProtoDefaults` at `:439`; `configureHTTP2` at `http2.go:284-312` with the assignment at `:311`. `sync.Once` gives the required happens-before for both the same-goroutine roundTrip→dial order and cross-goroutine visibility.
  - Reader side confirmed: `transport.go:1783` clones the config per handshake; no other site reads our pointer concurrently (see the T1 correction — internal h2 neither dials with it nor has an accessor for it).
  - Sonnet's `-race` runs are **report-only** (not re-run here); the source ordering above is the load-bearing evidence.
- **Final: TERMINATE.** Answered — a closed question, not a finding. The premises (`Once` completes before any dial; every handshake reads a clone) are verified in go1.27.2, and the only writer is inside the `Once`. Residual scope stays exactly go1.27.2/linux-amd64; a future toolchain bump that moves the write outside `onceSetNextProtoDefaults` would reopen it, but that is a toolchain watch, not an open question now.

---

## Counts

| Disposition | Items | Count |
|---|---|---|
| TREAT | — | **0** |
| TOLERATE | T2 (54) | **1** |
| TRANSFER | T4 (56) | **1** |
| TERMINATE | T1 (53), T3 (55), T5 (57) | **3** |
| **Total** | | **5** |

## Recommended worklist

1. **T4 — TRANSFER, do now (non-code).** Ask each deployment owner for the `SSL_CERT_FILE`/`SSL_CERT_DIR` setting and trust-store inventory, and confirmation the Vault/OpenBao issuing CA is trusted; record the answers in the deployment doc next to `README.md:92`. This is the only item with an external action, and it is the one that can still explain a "works here, not there" login failure.
2. **T2 — TOLERATE, optional one line.** Only if an `HTTPS_PROXY` actually appears in a deployment, add one README sentence: an HTTPS proxy that requests a client certificate receives this client certificate (no private key), and `PKI-SETUP.md:155` covers the reverse direction. Not required; no code change is possible in this toolchain.
3. **T1, T3, T5 — TERMINATE, close in the tracker** with the citations above, and fold in the two record corrections: `fips140tls` is `crypto/tls/internal/fips140tls` (stdlib, no HashiCorp FIPS dependency in the graph), and `internal/http2/transport.go:561-568` writes a fresh config, not the shared one.
4. **No TREAT items**, so `clientTLSConfig` generates no implementation task; keep the extra FIPS cipher/signature caveat (T3 note) with the operator-environment entry, not as a repo task.

---

Skipped: no hardware, live Vault/OpenBao, TLS-terminating proxy or OpenSC was exercised — Sonnet's proxy, `GODEBUG=fips140=on` and `-race` runs are carried as report-only; his citations were re-checked in source instead. Risk the user must know: T2's residual (an HTTPS proxy that requests a client cert gets yours, inescapable in go1.27.2) and T4's unanswered trust-store question are the only two items whose real-world outcome this audit cannot settle.

---

**Evidence addendum [agent-run, scratch, 2026-10-11].** Current status: [../TREATMENT-STATUS.md](../TREATMENT-STATUS.md) §3a. All temporary binaries, configs and traces were deleted; nothing retained.
- **T1 (53), T3 (55), T5 (57)** — unchanged (TERMINATE); source answers stand.
- **T2 (54)** — unchanged (TOLERATE); no TLS-terminating HTTPS proxy was exercised.
- **T4 (56)** — partial. A live cert login at `https://vault.example.invalid:8200` completed over TLS, so this certificate's chain is accepted by that listener and this workstation trusts its issuing CA [INFERENCE from the completed handshake; the CA is in this workstation's trust store]. That is one host and one deployment: other hosts and `SSL_CERT_FILE`/`SSL_CERT_DIR` settings stay open, and the listener's advertised CA names were not observed. TRANSFER stands.
