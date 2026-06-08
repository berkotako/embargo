# Releasing & deploying a released build

Embargo ships as three published container images on GHCR:

- `ghcr.io/berkotako/embargo-engine`
- `ghcr.io/berkotako/embargo-gateway`
- `ghcr.io/berkotako/embargo-console`

## Deploy a released build (operators)

No build toolchain required — pull pinned images and run:

```bash
git clone https://github.com/berkotako/embargo && cd embargo
cp .env.example .env            # set POSTGRES_PASSWORD, EMBARGO_VERSION, auth, host
docker compose -f compose.prod.yml pull
docker compose -f compose.prod.yml up -d
make health                     # or: curl http://localhost:9090/health/ready
```

Then onboard a client (`scripts/onboard.sh`) exactly as in the
[README](../README.md). Harden for real production — your own mTLS CA, OIDC,
managed Postgres/Redis — per [`DEPLOYMENT.md`](../DEPLOYMENT.md).

> The `compose.prod.yml` images are pinned to `${EMBARGO_VERSION}` (default the
> current release). Bump that in `.env` to upgrade; the engine runs DB
> migrations automatically on startup.

> GHCR packages are private until made public in the repo's package settings.
> If a pull is denied, either make the packages public or
> `docker login ghcr.io` with a token that has `read:packages`.

## Cut a release (maintainers)

Versioning is [SemVer](https://semver.org/). The engine workspace and the
TypeScript packages all carry the same version.

1. Make sure `main` is green and the version strings are bumped
   (`engine/Cargo.toml` `[workspace.package].version`, each `package.json`,
   `VERSION`) and `CHANGELOG.md` has a section for the new version.
2. Tag and push:

   ```bash
   git tag -a v0.1.0 -m "Embargo v0.1.0"
   git push origin v0.1.0
   ```

3. The [`release` workflow](../.github/workflows/release.yml) triggers on the
   `v*` tag and:
   - builds + pushes the three images to GHCR, tagged `0.1.0`, `0.1`, and
     `latest`;
   - creates the GitHub Release with auto-generated notes.

That's the whole release. The published `latest`/version tags are what
`compose.prod.yml` consumes.

### Notes on the console image

Vite inlines the auth mode at build time, so the published `embargo-console`
image is built with `VITE_AUTH_MODE=dev` (role picker) to keep the released
stack runnable out of the box. For an OIDC deployment, rebuild the console with
your `VITE_OIDC_*` build args and point `compose.prod.yml` at your own image.
