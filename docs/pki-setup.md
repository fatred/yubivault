# PKI setup for YubiKey login

This guide sets up certificate login to Vault (or OpenBao) with a key that is generated on, and never leaves, the user's YubiKey:

1. The issuer creates a certificate authority (CA) with [certstrap](https://github.com/square/certstrap).
2. The user generates a key in PIV slot 9a on their YubiKey and sends the issuer a certificate signing request (CSR).
3. The issuer checks and signs the CSR, and sends back the certificate.
4. The user imports the certificate into slot 9a.
5. The issuer adds the CA to Vault's cert auth method, with a role that admits a team, identified by the certificate's organizational unit (OU), and gives it admin access.

The examples use `alice` as the user, `vault-admins` as the team (OU) and `Vault Users CA` as the CA name. Replace them with your own. For OpenBao, use `bao` instead of `vault` in every command.

## Tools

| Who | Needs |
|---|---|
| Issuer | `certstrap`, and the `vault` CLI with an admin token (or the Vault web UI) |
| User | `ykman` (YubiKey Manager), OpenSC, yubivault |

```shell
go install github.com/square/certstrap@latest   # issuer; or download a release binary
brew install ykman opensc                       # user, macOS
sudo apt install yubikey-manager opensc         # user, Debian/Ubuntu
```

## 1. Issuer: create the CA

```shell
mkdir vault-users-ca && cd vault-users-ca
certstrap init --common-name "Vault Users CA" --expires "10 years"
```

certstrap asks for a passphrase to encrypt the CA key. Set one.

certstrap keeps everything in a directory called `out/` under the current directory (its "depot"). Run every later certstrap command from this same directory, or pass `--depot-path /path/to/out`. After `init` it contains:

- `out/Vault_Users_CA.crt`: the CA certificate. This is public, and it is what Vault trusts.
- `out/Vault_Users_CA.key`: the CA private key. Anyone holding it can mint certificates that log in, so keep it offline and backed up.
- `out/Vault_Users_CA.crl`: the certificate revocation list, used under [Revocation](#revocation).

## 2. User: generate a key on the YubiKey and create a CSR

If the YubiKey still has the factory PIV credentials (PIN `123456`, PUK `12345678`, default management key), change them first:

```shell
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

`--protect` stores the new management key on the YubiKey behind the PIN, so the commands below ask for the PIN rather than the management key.

Generate the key in slot 9a (PIV Authentication). The private key is created on the YubiKey and cannot be exported. Only the public key is written to `alice.pub`:

```shell
ykman piv keys generate --algorithm ECCP256 9a alice.pub
```

`ECCP384` works too.

**Optional: require a touch.** By default, the PIN alone unlocks the key. To also require a physical touch of the YubiKey, add `--touch-policy` when generating the key:

```shell
ykman piv keys generate --algorithm ECCP256 --touch-policy CACHED 9a alice.pub
```

- `ALWAYS` asks for a touch on every use of the key. `CACHED` remembers a touch for 15 seconds.
- The touch policy is fixed when the key is generated. Changing it later means generating a new key and going through steps 2 to 4 again.
- Creating the CSR and each yubivault login use the key. With a touch policy set, the YubiKey
  blinks when the key is used. The exact wait timeout and retry behaviour during login depend on
  the PKCS#11 stack; touch promptly and do not assume a fixed limit.

Create the CSR. Put your name in `CN` and your team in `OU`. The YubiKey signs the CSR with the slot 9a key, so you are asked for the PIN:

```shell
ykman piv certificates request --subject "CN=alice,OU=vault-admins" 9a alice.pub alice.csr
```

Send `alice.csr` to the issuer. It contains no secrets.

## 3. Issuer: check and sign the CSR

The user chose the CN and OU in the CSR, and the OU decides what the certificate can log in to. **The OU in a CSR is a claim, not proof of membership.** Before signing, confirm the requester's identity and team membership through a source you trust (not the CSR itself), and check the subject contains exactly the expected CN and a single OU.

Copy the CSR into the depot as `<name>.csr`, and make it read-only. certstrap refuses depot files that are writable (`permissions too lax ... required no more than -r--r--r--`), so `chmod 600` is not enough:

```shell
cp /path/to/alice.csr out/alice.csr
chmod 400 out/alice.csr
openssl req -in out/alice.csr -noout -subject   # expect: subject=OU=vault-admins, CN=alice
```

Sign it:

```shell
certstrap sign alice --CA "Vault Users CA" --expires "1 year"
```

certstrap asks for the CA passphrase and writes `out/alice.crt`. Send that file back to the user. Leave the copy in `out/`: `certstrap revoke` looks certificates up there.

## 4. User: import the certificate into slot 9a

```shell
ykman piv certificates import --verify 9a alice.crt
```

`--verify` checks that the certificate matches the key in slot 9a before writing it.

## 5. Issuer: configure Vault

Run these with `VAULT_ADDR` set and a token that can manage policies and auth methods. The commands read `out/Vault_Users_CA.crt` from the CA directory. If you run `vault` on another machine, copy that file over first; it is the only CA file Vault needs.

Create a policy that grants full access to everything. This is admin access, so only attach it to roles for trusted administrators:

```shell
vault policy write yubivault-admin - <<'EOF'
path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
EOF
```

Enable the cert auth method and add a role that trusts the certstrap CA for the `vault-admins` team:

```shell
vault auth enable -path=cert cert

vault write auth/cert/certs/admin \
    display_name=admin \
    certificate=@out/Vault_Users_CA.crt \
    allowed_organizational_units=vault-admins \
    token_policies=yubivault-admin \
    token_ttl=1h \
    token_max_ttl=8h
```

- `certificate` is the CA certificate. Any certificate it signed is accepted by this role, subject to the constraints below.
- `allowed_organizational_units` admits any certificate with `OU=vault-admins`, whatever its CN. Vault accepts a certificate if **at least one** of its OUs matches, so a certificate with `OU=finance` and `OU=vault-admins` gets in, while one with no OU, or no matching OU, is refused. Adding someone to the team means issuing them a certificate with that OU; nothing changes in Vault. Without a constraint, every certificate the CA has ever signed gets admin access.
- The CN still identifies the person: it appears as `common_name` in the token's metadata (`vault token lookup`) and in the audit log.
- To admit specific people instead of a team, use `allowed_common_names=alice,bob`.
- For another team with different access, create another policy and another role, with that team's OU.
- `token_ttl` and `token_max_ttl` bound how long the issued token lives.

### Same steps in the Vault web UI

1. **Access control > ACL policies > Create ACL policy**: name it `yubivault-admin` and paste the policy above.
2. **Access control > Authentication methods**: enable a new method, choose **TLS Certificates**, leave the path as `cert`, then click **Enable method**.
3. Open the method (**View method**) and click **Create certificate**:
   - **Name**: `admin`
   - **Certificate**: choose **Enter as text** and paste the contents of `out/Vault_Users_CA.crt`
   - **Display name**: `admin`
   - Under **Tokens**, set **Generated Token's Policies** to `yubivault-admin`. Turn on **Generated Token's Initial TTL** and set it to 1 hour, then turn on **Generated Token's Maximum TTL** and set it to 8 hours. Without these, tokens get the mount's default lifetime, which is usually much longer than you want for admin access.
   - Under **Constraints**, set **Allowed organizational units** to `vault-admins`.
   - Click **Save**.

This guide assumes Vault receives yubivault's TLS connection directly. A TLS-terminating proxy means Vault does not see the original client-certificate handshake; Vault's listener has a forwarded-client-certificate option (`x_forwarded_for_client_cert_header`; not verified here), but yubivault does not set forwarded-certificate headers.

## 6. User: configure yubivault

Find the PKCS#11 token serial of the YubiKey:

```shell
pkcs11-tool --module /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so --list-slots   # macOS
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots     # Debian/Ubuntu
```

Then write `~/.yubivault/config.yml`, using the `serial num` value from that output:

```yaml
vaultAddr: https://vault.example.com:8200  # HTTPS is required
certAuthMount: cert
certAuthName: admin
openscPath: /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so   # or the Debian/Ubuntu path above
yubikeyPivSerial: "<serial num from pkcs11-tool>"
```

Log in:

```shell
VAULT_TOKEN="$(yubivault -yubi)" && export VAULT_TOKEN
vault token lookup
```

`vault token lookup` should show `display_name` `cert-admin`, `policies` including `yubivault-admin`, and your CN as `common_name` under `meta`.

## Renewal

Before the certificate expires, the issuer moves the old certificate aside and signs the same CSR again, or a new CSR if the key was replaced. certstrap will not overwrite `out/alice.crt`.

```shell
mv out/alice.crt out/alice-2026.crt
certstrap sign alice --CA "Vault Users CA" --expires "1 year"
```

The user imports the new `out/alice.crt` as in step 4.

The old certificate stays valid until it expires. Once the new one works, revoke the old one. `certstrap revoke` takes the file name in `out/`, without `.crt`, as its `--CN`:

```shell
certstrap revoke --CN alice-2026 --CA "Vault Users CA"
vault write auth/cert/crls/vault-users-ca crl=@out/Vault_Users_CA.crl
```

## Revocation

With a team role, removing someone is done on the CA side: revoke their certificate and give Vault the updated revocation list:

```shell
certstrap revoke --CN alice --CA "Vault Users CA"
vault write auth/cert/crls/vault-users-ca crl=@out/Vault_Users_CA.crl
```

`certstrap revoke` adds the certificate in `out/alice.crt` to `out/Vault_Users_CA.crl`. Entries are cumulative. Run the `vault write` again after every revocation, because Vault only knows about the CRL you last uploaded.

To shut out the whole team at once, delete the role: `vault delete auth/cert/certs/admin`.

Either way, tokens that were already issued stay valid until they expire (`token_ttl`/`token_max_ttl`), unless you also revoke them with `vault token revoke`.
