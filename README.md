# yubivault

simple binary that will use a local cert/key pair on disk or on a yubikey to login to vault and give you a token for subesequent use in automations etc.

## PreReqs

1. Make a folder called `mkdir -p ~/.vault`
2. Chown that to you only `chown -R 700 ~/.vault`
3. Make a config file:

```yaml
---
vaultAddr: https://vault.problemofnetwork.com:8200
certAuthName: network_admin_g2
certAuthMount: network_admin
certAuthPemFile: client-cert.pem
certAuthKeyFile: client-cert.key
openscPath: "/opt/homebrew/Cellar/opensc/0.26.1/lib/pkcs11/opensc-pkcs11.so"
yubikeySerial: "12345678"
yubikeyPivSerial: "1234567890123456"
yubikeyPivLabel: "jhow-yubikey-12345678"
yubikeyPivIndex: 0
```

4a. for local auth: put valid cert/key pair into that path

4b. for yubi auth: put your key into your laptop and run the command as below


## How it works

local:
```shell
$ yubivault -local
s.pUeO2Nr3P9aBRHasdfasdfasdfasdf
```

yubikey:
```shell
$ yubivault -yubi
PIN for 12345678: 
s.LtSpaGkxDq0Nrrrxlolasdfsasfdsw
```