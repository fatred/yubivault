# Enable GitHub Pages (one-time, owner action)

`docs.yml` publishes the site with GitHub's Pages actions: the build job uploads an artifact and
the deploy job calls `actions/deploy-pages`. That only works once the repository has Pages enabled
with **GitHub Actions** as the source. Until then the deploy job fails (typically
`Get Pages site failed … Not Found` / `Create Pages site failed`), while the build job succeeds.

Enabling Pages is a repository **admin** setting. If you do not have admin permission, a repository
owner must complete the one-time setup in the browser or with an admin-scoped token. The workflow
requests `pages: write` and `id-token: write` only for its deploy job.

Enable Pages before merging to `main`: otherwise the `Docs` run on `main` fails and the published-site links in `README.md` return 404.

## Steps

1. Open <https://github.com/fatred/yubivault/settings/pages>.
   (Navigation from the repository page: **Settings** → **Pages**, in the *Code and automation*
   section of the left sidebar.)
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.
   Do **not** choose *Deploy from a branch*: that mode serves a branch, not the artifact this
   workflow produces. If a branch source (for example `gh-pages`) is currently selected, changing
   the source to *GitHub Actions* is all that is needed; no branch has to exist or be deleted.
3. Leave everything else at its default. There is no theme, CNAME or custom-domain setting for the
   project site; it is served at `https://fatred.github.io/yubivault/`, which is the `site_url`
   in `mkdocs.yml`.
4. Optional but recommended: **Settings** → **Environments** → `github-pages` → **Deployment
   branches and tags** → *Selected branches and tags* → add `main`. The environment is created by
   the first deployment; if it does not exist yet, deploy once and then restrict it. This keeps
   only `main` able to publish, which the workflow already enforces with its
   `if: github.event_name == 'push' && github.ref == 'refs/heads/main'` conditions.

For an owner with an admin-scoped token, use `POST` if Pages is not configured yet:

```shell
gh api -X POST repos/fatred/yubivault/pages -f build_type=workflow
```

If a Pages site already exists and uses a branch source, update it with `PUT`:

```shell
gh api -X PUT repos/fatred/yubivault/pages -f build_type=workflow
```

## Verify the first deployment

1. Merge (or re-run) a push to `main`: **Actions** → **Docs** → the run for that commit. The
   `build` job must be green (`mkdocs build --strict`) and `deploy` must be green.
2. Confirm the site is live and that the deploy job's environment URL resolves:

   ```shell
   gh api repos/fatred/yubivault/pages --jq '{status,html_url}'
   # {"status":"built","html_url":"https://fatred.github.io/yubivault/"}

   curl -sS -o /dev/null -w '%{http_code}\n' https://fatred.github.io/yubivault/
   ```

   A `status` of `built` and a `200` mean the first deployment worked. Deployments are also listed
   under the repository's **Deployments** (right-hand sidebar on the code page).
3. Confirm the normal docs pages return `200`:

   ```shell
   for p in "" "install/" "usage/" "pki-setup/" "agents/" "maintainers/architecture/"; do
     printf '%s -> ' "$p"
     curl -sS -o /dev/null -w '%{http_code}\n' "https://fatred.github.io/yubivault/$p"
   done
   # each must print 200
   ```

4. From then on, every merge to `main` publishes automatically. Pull requests only build the site
   (`mkdocs build --strict`); they never deploy.
