# Lenso Project Automation Plugin

Bounded, durable automation for `lenso.projects@1`. This repository publishes:

- `lenso-capability-project-automation`: the descriptor-first portable
  `lenso.project-automation@1` contract;
- `lenso-project-automation-postgres-plugin`: the linked native Rust Provider.

## Product boundary

The Plugin owns automation rules, revisions, caller-scoped command receipts,
trigger deduplication, executions, attempts, per-action receipts, recurring
schedule state, and one-shot Jobs enqueue receipts. It never owns Projects
entities. Every issue, project, and comment read or mutation goes through the
typed Projects capabilities.

The rule language is data, not code. Conditions are limited to known issue and
project event fields. Actions are limited to:

- assign an issue to a team (the current Projects contract has no person-level
  assignee field);
- update bounded issue fields;
- move an issue to a team/workflow state;
- add a comment;
- update bounded project fields.

There is no shell, expression interpreter, HTTP callback, dynamic capability
name, or arbitrary payload execution.

## Capability

`lenso.project-automation@1`, descriptor `1.0.0`, provides:

- rule `create_rule`, `get_rule`, `list_rules`, `update_rule`,
  `set_rule_enabled`, and `delete_rule` operations;
- durable `receive_event` and `receive_timer` trigger intake;
- bounded `reconcile` and cursor-paginated, receipt-rich `inspect_execution`.

Rule updates, enable/disable, and deletion use revision compare-and-swap. Rule
commands use the exact `(caller Instance, actor subject, operation,
idempotency_key)` scope. Trigger intake is unique per organization, source, and
dedupe key. Each accepted execution owns an immutable action snapshot, so later
rule revisions do not alter work already recorded by a trigger.

## Required capabilities

- `lenso.secrets@1`
- `lenso.organization-membership@1`
- `lenso.access-control@1`
- `lenso.projects@1`
- `lenso.projects-collaboration@1`
- `lenso.jobs@1`

Auth is intentionally not a Port. The Plugin verifies the Auth 0.2.1
`ActorAssertion` carried by `InvocationContext` against the configured issuer
and public verification key. Management callers additionally require active
organization membership and either `projects.automation.read` or
`projects.automation.manage` from Access Control.

`execution_callers` is an independent, non-overlapping exact Instance
allowlist. Reconcile also requires an assertion with the exact
`lenso.project-automation@1/reconcile` audience. Because the same context is
forwarded with `_with_context`, the Host-issued assertion must also contain the
exact Projects operations the rule may invoke. Dependency Runtime Failures are
never converted into business errors.

The linked Host supplies immutable configuration similar to:

```json
{
  "schema": "project_automation",
  "database_url_secret": "project-automation/database-url",
  "auth_issuer": "auth.production",
  "auth_assertion_public_key": "<base64-ed25519-public-key>",
  "admin_callers": ["projects-api"],
  "event_callers": ["projects-events"],
  "timer_callers": ["project-automation-timer-worker"],
  "execution_callers": ["project-automation-executor"],
  "jobs_queue": "project-automation",
  "execution_lease_seconds": 60,
  "job_max_attempts": 5,
  "max_reconcile_items": 20
}
```

All four caller lists are non-empty, exact, unique, and mutually disjoint. The
Auth verification key is public material; the database URL remains a Secrets
reference.

## Recurring schedules and delivery semantics

Jobs is a one-shot queue. This Plugin therefore owns `next_fire_at` and a
durable schedule-dispatch ledger. Creating, updating, enabling, or completing a
scheduled execution creates the next one-shot enqueue intent. A failed terminal
action advances and enqueues the next recurrence just like a successful one;
an ambiguous Runtime Failure leaves the current execution retryable and the
schedule unadvanced.

The queued job kind is `lenso.project-automation.timer`. Its payload contains
`organization_id`, `rule_id`, `scheduled_for`, and `dedupe_key`. A Host-owned
Jobs worker must deliver that payload to `receive_timer` using an exact
`timer_callers` Instance. Event producers similarly call `receive_event` using
an exact `event_callers` Instance.

Delivery is at-least-once. Stable trigger dedupe and action idempotency keys make
retries safe at the documented boundaries, but the Plugin does not claim
exactly-once execution.

Scheduled rules must place an explicit `issue_id` or `project_id` on every
action because no event entity is present. Event rules may use the event entity
or an explicit action target.

On create, edit, or re-enable, a past `start_at` advances to the first future
interval instead of replaying an unbounded backlog or colliding with an older
dispatch receipt.

## PostgreSQL ownership

PostgreSQL is the only production persistent state. Activation only validates
an explicitly prepared schema. Operators run setup and upgrades out of band:

```rust
use lenso_project_automation_postgres_plugin::ProjectAutomationOperator;

ProjectAutomationOperator::setup(database_url, "project_automation").await?;
ProjectAutomationOperator::upgrade(database_url, "project_automation").await?;
```

The database URL is resolved through Secrets. The Plugin never creates a
database, migrates during activation, or stores credentials in configuration.

## Verification

Use the workspace wrapper locally:

```bash
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --workspace --all-targets --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/check-repository-boundary.sh
scripts/check-package-source-set.sh
```

The optional PostgreSQL acceptance test requires a dedicated database whose
name starts with `lenso_project_automation_test`:

```bash
LENSO_PROJECT_AUTOMATION_TEST_DATABASE_URL='postgres://.../lenso_project_automation_test' \
  /Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test \
  -p lenso-project-automation-postgres-plugin --features postgres-acceptance
```

Kernel tests compose the actual automation endpoint and Ports with fake
Membership, Access Control, Projects, Collaboration, Secrets, and Jobs
Providers. A separate deletion proof composes and invokes Projects after the
Automation Plugin is absent.
