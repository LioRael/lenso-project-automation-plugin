#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

metadata="$($cargo_bin metadata --no-deps --format-version=1)"
for package in lenso-capability-project-automation lenso-project-automation-postgres-plugin; do
  publish="$(jq -r --arg package "$package" '.packages[] | select(.name == $package) | .publish | if . == null then "public" elif length == 0 then "public" else join(",") end' <<<"$metadata")"
  if [[ "$publish" != "public" ]]; then
    printf '%s is not publicly publishable: %s\n' "$package" "$publish" >&2
    exit 1
  fi
done
if ! jq -e '
  [.packages[] | select(
    (.name == "lenso-capability-project-automation" or .name == "lenso-project-automation-postgres-plugin") and
    .license == "MIT" and
    .repository == "https://github.com/LioRael/lenso-project-automation-plugin" and
    .edition == "2024" and
    .rust_version == "1.94" and
    (.description | type == "string" and length > 0)
  )] | length == 2
' <<<"$metadata" >/dev/null; then
  printf 'public package metadata is incomplete or inconsistent\n' >&2
  exit 1
fi
if ! jq -e '
  .packages[] |
  select(.name == "lenso-project-automation-postgres-plugin") |
  .metadata.lenso["plugin-id"] == "lenso.project-automation.postgres" and
  .metadata.lenso["root-slot"] == "project-automation"
' <<<"$metadata" >/dev/null; then
  printf 'Plugin package metadata does not identify its exact Lenso slot\n' >&2
  exit 1
fi

# The portable Capability has no unpublished local dependency and must pass
# Cargo's normalized-consumer verification, not only archive enumeration.
$cargo_bin package --locked --allow-dirty -p lenso-capability-project-automation >/dev/null

capability_files="$($cargo_bin package --locked --allow-dirty --list -p lenso-capability-project-automation | LC_ALL=C sort)"
for required in Cargo.toml Cargo.lock build.rs capability.json src/generated.rs src/lib.rs; do
  rg -qx "$required" <<<"$capability_files"
done
for schema in crates/lenso-capability-project-automation/schemas/*.json; do
  rg -qx "schemas/$(basename "$schema")" <<<"$capability_files"
done
if rg -v '^(\.cargo_vcs_info\.json|Cargo\.lock|Cargo\.toml|Cargo\.toml\.orig|build\.rs|capability\.json|schemas/[^/]+\.schema\.json|src/generated\.rs|src/lib\.rs)$' <<<"$capability_files"; then
  printf 'Capability package includes an unexpected source path\n' >&2
  exit 1
fi

plugin_files="$($cargo_bin package --locked --allow-dirty --list -p lenso-project-automation-postgres-plugin | LC_ALL=C sort)"
for required in Cargo.toml Cargo.lock configuration.schema.json migrations/001_create_project_automation.sql src/lib.rs src/operator.rs src/postgres_tests.rs src/schema.rs src/storage.rs; do
  rg -qx "$required" <<<"$plugin_files"
done
if rg -v '^(\.cargo_vcs_info\.json|Cargo\.lock|Cargo\.toml|Cargo\.toml\.orig|configuration\.schema\.json|migrations/001_create_project_automation\.sql|src/lib\.rs|src/operator\.rs|src/postgres_tests\.rs|src/schema\.rs|src/storage\.rs)$' <<<"$plugin_files"; then
  printf 'Plugin package includes an unexpected source path\n' >&2
  exit 1
fi
