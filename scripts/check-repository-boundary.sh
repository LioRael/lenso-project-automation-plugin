#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

expected_crates=$'lenso-capability-project-automation\nlenso-project-automation-agent-tools-plugin\nlenso-project-automation-postgres-plugin'
actual_crates="$({
  find crates -mindepth 1 -maxdepth 1 -type d -exec basename {} \;
} | LC_ALL=C sort)"
if [[ "$actual_crates" != "$expected_crates" ]]; then
  printf 'unexpected crate ownership:\n%s\n' "$actual_crates" >&2
  exit 1
fi

test -f crates/lenso-capability-project-automation/capability.json
test -f crates/lenso-project-automation-agent-tools-plugin/src/lib.rs
test -f crates/lenso-project-automation-postgres-plugin/configuration.schema.json
test -f crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
test -f docs/plugin-card.md
test -f docs/release-process.md

if rg -n --glob '!Cargo.lock' --glob '!scripts/check-repository-boundary.sh' \
  'lenso-http-auth|std::process|Command::new|eval\(|exactly-once' crates; then
  printf 'forbidden dependency or arbitrary/exactly-once execution claim found\n' >&2
  exit 1
fi

if rg -n \
  '^[[:space:]]*lenso-(contracts|module-auth|platform-(core|http|module|runtime|testing))[[:space:]]*=' \
  Cargo.toml crates --glob 'Cargo.toml'; then
  printf 'legacy Lenso dependency returned\n' >&2
  exit 1
fi

if rg -n 'sqlx|postgres|lenso-auth|lenso-capability-(secrets|access-control|organization)' \
  crates/lenso-capability-project-automation/Cargo.toml \
  crates/lenso-capability-project-automation/src \
  --glob '!generated.rs'; then
  printf 'portable Project Automation Capability gained implementation authority\n' >&2
  exit 1
fi

if rg -ni 'CREATE TABLE (issues|projects|comments|users|organizations|memberships|jobs)' \
  crates/lenso-project-automation-postgres-plugin/migrations; then
  printf 'Project Automation migration crossed an external data owner boundary\n' >&2
  exit 1
fi

rg -q '"id": "lenso.project-automation@1"' \
  crates/lenso-capability-project-automation/capability.json
rg -q 'lenso-capability-projects' Cargo.toml
rg -q 'lenso-capability-agent-tool-provider' Cargo.toml
rg -q 'lenso-capability-jobs' Cargo.toml
rg -q 'lenso-auth-sdk = "0.2.1"' Cargo.toml
rg -q 'RuntimeFailure::ProtocolViolation' \
  crates/lenso-project-automation-postgres-plugin/src/lib.rs
rg -q 'next_fire_at TIMESTAMPTZ' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
rg -q 'automation_action_receipts' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
rg -q 'actions JSONB NOT NULL' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
