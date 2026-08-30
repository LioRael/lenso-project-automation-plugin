# Release and Trusted Publishing

This repository publishes two public crates in dependency order:

1. `lenso-capability-project-automation`
2. `lenso-project-automation-postgres-plugin`

Publication is manual-only from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. A push may refresh a Release-plz PR but does
not publish. A live run requires `main`, `live=true`, and the literal
confirmation `publish`.

## Trusted Publisher

Configure one crates.io Trusted Publisher per crate:

- owner: `LioRael`
- repository: `lenso-project-automation-plugin`
- workflow: `release-plz.yml`
- environment: unset

Only the confirmed live job requests `id-token: write`, and there is no Cargo
registry-token fallback. Trusted Publishing cannot allocate a new crate name.
For the first release, allocate each unowned name in dependency order with a
temporary, tightly scoped crates.io token, revoke it immediately, then use only
OIDC for later releases.

## Required evidence

Run the full README verification gate, including the exact package source-set
check. The Plugin archive depends on public Capability versions, so confirm all
versioned dependencies referenced by `Cargo.lock` are available before the live
release. The external PostgreSQL acceptance suite remains a separate required
production-readiness check when a dedicated test database is available.
