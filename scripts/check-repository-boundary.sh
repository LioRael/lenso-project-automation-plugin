#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

expected_crates=$'lenso-capability-project-automation\nlenso-project-automation-postgres-plugin'
actual_crates="$({
  find crates -mindepth 1 -maxdepth 1 -type d -exec basename {} \;
} | LC_ALL=C sort)"
if [[ "$actual_crates" != "$expected_crates" ]]; then
  printf 'unexpected crate ownership:\n%s\n' "$actual_crates" >&2
  exit 1
fi

test -f crates/lenso-capability-project-automation/capability.json
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

required_pins=(
  b763a63adc20f1ccc9955e784c0d04c21489126b
  cd35675a191d815b690c8889756dfe859a0e4d7b
  b4a2f53df882ae51021aa3d5922d8ee41bf97c72
  de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420
  a8be81775df951fd8c958615519dea0ef179620d
  9572afd465ba2f952b646ec16935c0274f66c82a
  70d1d6fb9ba5b05ff0100273ddfd10a424030edf
  c31aa142ff59b4536e2bf3e9785ccbb5bb5c0e6a
  9769bc5dc828fd9111da6d28a4ecd5f1bb198ab4
  525c1012c789e6f54c3c2fdaf8507a626c93e65f
)
for pin in "${required_pins[@]}"; do
  if ! rg -q "$pin" Cargo.toml; then
    printf 'required exact Lenso dependency pin is missing: %s\n' "$pin" >&2
    exit 1
  fi
done

rg -q '"id": "lenso.project-automation@1"' \
  crates/lenso-capability-project-automation/capability.json
rg -q 'lenso-capability-projects' Cargo.toml
rg -q 'lenso-capability-jobs' Cargo.toml
rg -q 'lenso-auth-sdk = \{ version = "0.2.1"' Cargo.toml
rg -q 'RuntimeFailure::ProtocolViolation' \
  crates/lenso-project-automation-postgres-plugin/src/lib.rs
rg -q 'next_fire_at TIMESTAMPTZ' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
rg -q 'automation_action_receipts' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
rg -q 'actions JSONB NOT NULL' \
  crates/lenso-project-automation-postgres-plugin/migrations/001_create_project_automation.sql
