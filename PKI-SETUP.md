# PKI setup for YubiKey login

This guide sets up certificate login to Vault (or OpenBao) with a key that is generated on, and never leaves, the user's YubiKey:

1. The issuer creates a certificate authority (CA) with [certstrap](https://github.com/square/certstrap).
2. The user generates a key in PIV slot 9a on their YubiKey and sends the issuer a certificate signing request (CSR).
3. The issuer signs the CSR with the CA and sends back the certificate.
4. The user imports the certificate into slot 9a.
5. The issuer adds the CA to Vault's cert auth method, with a role and policy that give the user admin access.

The examples use `alice` as the user and `Vault Users CA` as the CA name. Replace them with your own. For OpenBao, use `bao` instead of `vault` in every command.

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
certstrap init --common-name "Vault Users CA" --expires "10 years"
```

certstrap asks for a passphrase to encrypt the CA key. Set one. The files are written to `out/`:

- `out/Vault_Users_CA.crt`: the CA certificate. This is public, and it is what Vault trusts.
- `out/Vault_Users_CA.key`: the CA private key. Anyone holding it can mint certificates that log in, so keep it offline and backed up.

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

Create the CSR. The YubiKey signs it with the slot 9a key, so you are asked for the PIN:

```shell
ykman piv certificates request --subject "CN=alice" 9a alice.pub alice.csr
```

Send `alice.csr` to the issuer. It contains no secrets.

## 3. Issuer: sign the CSR

```shell
certstrap sign alice --CA "Vault Users CA" --csr alice.csr --cert alice.crt --expires "1 year"
```

certstrap asks for the CA passphrase. Send `alice.crt` back to the user, and keep a copy if you want a record of what was issued.

## 4. User: import the certificate into slot 9a

```shell
ykman piv certificates import --verify 9a alice.crt
```

`--verify` checks that the certificate matches the key in slot 9a before writing it.

## 5. Issuer: configure Vault

Run these with `VAULT_ADDR` set and a token that can manage policies and auth methods.

Create a policy that grants full access to everything. This is admin access, so only attach it to roles for trusted administrators:

```shell
vault policy write yubivault-admin - <<'EOF'
path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
EOF
```

Enable the cert auth method and add a role that trusts the certstrap CA:

```shell
vault auth enable -path=cert cert

vault write auth/cert/certs/admin \
    display_name=admin \
    certificate=@out/Vault_Users_CA.crt \
    allowed_common_names=alice \
    token_policies=yubivault-admin \
    token_ttl=1h \
    token_max_ttl=8h
```

- `certificate` is the CA certificate. Any certificate it signed is accepted by this role, subject to the constraints below.
- `allowed_common_names` limits the role to certificates with `CN=alice`. Without it, every certificate the CA has ever signed gets admin access. List several names separated by commas, or create one role per user.
- `token_ttl` and `token_max_ttl` bound how long the issued token lives.

### Same steps in the Vault web UI

1. **Access control > ACL policies > Create ACL policy**: name it `yubivault-admin` and paste the policy above.
2. **Access control > Authentication methods**: enable a new method, choose **TLS Certificates**, leave the path as `cert`, then click **Enable method**.
3. Open the method (**View method**) and click **Create certificate**:
   - **Name**: `admin`
   - **Certificate**: choose **Enter as text** and paste the contents of `out/Vault_Users_CA.crt`
   - **Display name**: `admin`
   - Under **Tokens**, set **Generated Token's Policies** to `yubivault-admin`. Turn on **Generated Token's Initial TTL** and set it to 1 hour, then turn on **Generated Token's Maximum TTL** and set it to 8 hours. Without these, tokens get the mount's default lifetime, which is usually much longer than you want for admin access.
   - Under **Constraints**, set **Allowed common names** to `alice`.
   - Click **Save**.

Cert auth needs Vault itself to terminate TLS. If a load balancer or proxy terminates TLS in front of Vault, the client certificate never reaches Vault and login fails.

## 6. User: configure yubivault

Find the PKCS#11 token serial of the YubiKey:

```shell
pkcs11-tool --module /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so --list-slots   # macOS
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots     # Debian/Ubuntu
```

Then write `~/.yubivault/config.yml`, using the `serial num` value from that output:

```yaml
vaultAddr: https://vault.example.com:8200
certAuthMount: cert
certAuthName: admin
openscPath: /opt/homebrew/opt/opensc/lib/opensc-pkcs11.so   # or the Debian/Ubuntu path above
yubikeyPivSerial: "<serial num from pkcs11-tool>"
```

Log in:

```shell
export VAULT_TOKEN="$(yubivault -yubi)"
vault token lookup
```

`vault token lookup` should show `display_name` `cert-admin`, and `policies` should include `yubivault-admin`.

## Renewal and revocation

- **Renewal:** before the certificate expires, the issuer signs the same CSR again (or a new one if the key was replaced) into a **new** file, and the user imports it as in step 4:

  ```shell
  certstrap sign alice --CA "Vault Users CA" --csr alice.csr --cert alice-2027.crt --expires "1 year"
  ```

  certstrap does not overwrite an existing certificate file. It prints `Save certificate error` and still exits 0, so do not reuse the old file name.
- **Revoking one user:** remove their name from `allowed_common_names` on the role. To revoke everyone using a role, delete it: `vault delete auth/cert/certs/admin`. Either way, tokens already issued stay valid until they expire (`token_ttl`/`token_max_ttl`) unless you revoke them with `vault token revoke`.
