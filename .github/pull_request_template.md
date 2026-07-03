<!--
Thanks for the PR. Keep changes small and non-breaking. main is protected:
merge requires the required status checks (build-and-test, rls-integration, build)
to pass. Fill in the sections below and delete anything that doesn't apply.
-->

## What & why

<!-- One or two sentences: what does this change do, and why? Link issues with "Closes #123". -->

## Changes

-

## How tested

<!-- Commands run and their result. The repo's pre-merge gate is:
     go build ./... · go vet ./... · go test ./... · gosec (-severity medium -confidence high)
     · Postgres integration tests (FIDES_TEST_DB_DSN). Portal changes: npm run build && npm run lint. -->

- [ ] `go build ./...` / `go vet ./...` / `go test ./...`
- [ ] gosec (`-severity medium -confidence high`)
- [ ] Postgres integration tests
- [ ] Portal: `npm run build` && `npm run lint` (if `portal/` touched)

## Checklist

- [ ] Small, non-breaking change
- [ ] Docs updated if behaviour/config changed (root `*.md` + `web/*.md` kept in sync)
- [ ] No secrets, credentials, or generated binaries committed
