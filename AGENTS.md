# Repository guidance

Read [`docs/agents.md`](docs/agents.md) before changing code or documentation; it contains the repository workflow, invariants, and verification commands.

Never guess or submit a YubiKey PIN. A wrong attempt can lock the PIV applet. Do not run a command that consumes a PIN attempt unless the owner explicitly authorizes that attempt.

Never commit or print a PIN, token, private key, or real token serial number. Use disposable SoftHSM fixtures for tests.