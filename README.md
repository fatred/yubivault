# yubivault

simple binary that will use a local cert/key pair on disk or on a yubikey (tbc) to login to vault and give you a token for subesequent use in automations etc.

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
```

4. put valid cert/key pair into that path

## How it works

```shell
$ yubivault -local
s.pUeO2Nr3P9aBRHasdfasdfasdfasdf
```