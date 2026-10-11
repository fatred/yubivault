# Release

Releases are built by `.github/workflows/release.yml` when a tag matching `v*.*.*` is pushed. There
is no manual build step and no version file: the tag is the version.

## What the workflow does

| Job | Runner | Steps |
|---|---|---|
| `build-release` | `ubuntu-latest` (linux/amd64) and `macos-latest` (darwin/arm64) | Check out, set up Go 1.27 with caching **disabled**, then build natively with `CGO_ENABLED=1` and `-ldflags "-X 'main.Version=${{ github.ref_name }}'"` into `dist/yubivault-$GOOS-$GOARCH`, print `file` output, and upload the binary as an artifact named `yubivault-$GOOS-$GOARCH`. |
| `release` | `ubuntu-latest` | Download all artifacts, generate the changelog with `.github/changelog-config.json`, and create the GitHub release `Release <tag>` with `files: dist/**`, not a draft and not a prerelease. |

Details that are load-bearing:

- **Native builds only.** The build fails unless `go env GOHOSTOS/GOHOSTARCH` matches the target,
  because cgo (via `miekg/pkcs11`) cannot be cross-compiled from Linux to darwin/arm64.
- **No cache.** A release build must not pick up a module or build cache written by another
  workflow run.
- **Pinned actions.** Every action is pinned to a full commit SHA, because this workflow produces
  the shipped binaries and holds a write token in the release job.
- **Least privilege.** The workflow default is `contents: read`; only the `release` job adds
  `contents: write` and `pull-requests: read` (the changelog builder lists merged pull requests).
- **Signed tags.** Tag signing is part of the maintainer workflow; the tag drives what is published.

## Cutting a release

1. Make sure `CI` is green on `main` — the release build runs no tests.
2. Pick the version and create a signed tag:

   ```shell
   git switch main && git pull
   git tag -s vX.Y.Z -m 'vX.Y.Z'
   git push origin vX.Y.Z
   ```

3. Watch the `Release` workflow run; the `release` job needs the build artifacts from both
   runners.
4. Verify the published assets: `yubivault-linux-amd64` and `yubivault-darwin-arm64` must both be
   attached to the release.

## Verifying a release

```shell
curl -fsSL -o /tmp/yubivault https://github.com/fatred/yubivault/releases/latest/download/yubivault-linux-amd64
chmod +x /tmp/yubivault
/tmp/yubivault -version          # must print the tag, e.g. v1.4.0, not "dev"
file /tmp/yubivault              # ELF 64-bit ... x86-64, statically linked is not expected (glibc build)
```

On a machine with a YubiKey and a matching cert-auth role, a `-yubi` login is the end-to-end check;
a `-version` that prints `dev` means the ldflags injection did not happen.

## Notes

- The macOS binary is not notarized; users clear the quarantine attribute (see
  [Install](../install.md)).
- The changelog categories come from `.github/changelog-config.json`; without a checkout the
  changelog builder silently falls back to its defaults and everything lands under "Uncategorized",
  which is why the release job checks out the repository first.
- Documentation is published separately by `.github/workflows/docs.yml` on every push to `main`;
  a release does not trigger a docs build. The Pages setup is one-time and is described in
  [Enable GitHub Pages](pages-runbook.md).
