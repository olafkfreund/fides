# Contributing to Fides

## Branch protection & pull-request flow

`main` is **protected** — you cannot push to it directly. All changes go through a
pull request:

1. Branch off `main`: `git checkout -b feat/my-change main`.
2. Make small, non-breaking changes; commit and push the branch.
3. Open a PR against `main` (a template is provided).
4. Wait for the required status checks to pass, then merge (you can merge your own
   PR — no second approval is required for this solo repo, but the checks must be
   green and administrators are **not** exempt).

Merging a PR to `main` triggers the deploy job (`Go Build & Test` → build image →
roll out to EKS `sarc-aws`).

### Required status checks (must pass before merge)

| Check | Workflow |
|-------|----------|
| `build-and-test` | `.github/workflows/go-build.yml` |
| `rls-integration` | `.github/workflows/go-build.yml` (Postgres RLS integration tests) |
| `build` | `.github/workflows/portal-build.yml` (portal static export) |

Force-pushes and deletion of `main` are blocked.

## Local pre-merge gate

Run these before opening a PR (they mirror CI):

```bash
go build ./...
go vet ./...
go test ./...
# gosec (blocking in CI): gosec -severity medium -confidence high ./...
# Postgres integration tests: set FIDES_TEST_DB_DSN (a postgres:15-alpine container)
```

For portal (`portal/`) changes:

```bash
cd portal
npm ci
npm run lint
npm run build   # static export → out/ ; a `prebuild` step copies Monaco into public/monaco
```

> Note: `next build` (static export) is validated in CI on **Node 22**. Building
> locally on Node 24 can fail with an unrelated `_global-error`/`_not-found`
> Turbopack prerender error — use Node 22 (`nix shell nixpkgs#nodejs_22`) to match CI.

## Emergency bypass (admins)

Branch protection can be temporarily lifted by an admin, then re-applied:

```bash
gh api -X DELETE repos/olafkfreund/fides/branches/main/protection   # bypass
# … push the fix …
# then re-apply the protection rule (PR + the three required checks + enforce_admins)
```
