# Plugin card: PostgreSQL Project Automation

## Job

Let an organization administrator define safe, inspectable issue/project rules,
then execute them durably without turning automation into a code-execution or
Projects data-ownership boundary.

## Owns

- rule definitions, revisions, enablement, and `next_fire_at`;
- caller/actor/operation-scoped command idempotency receipts;
- event/timer dedupe receipts;
- execution, attempt, and per-action receipts;
- recurring schedule state and one-shot Jobs enqueue receipts.

## Does not own

- users, Auth credentials, organizations, membership, or authorization policy;
- issues, projects, teams, workflow states, labels, or comments;
- Jobs worker leases or delivery;
- arbitrary programs, expressions, webhooks, or dynamic Capability calls;
- ingress, UI, or Console navigation.

## Required typed Ports

- Secrets
- Organization Membership
- Access Control
- Projects
- Projects Collaboration
- Jobs

Auth 0.2.1 assertion verification is direct from `InvocationContext`; there is
no legacy HTTP Auth dependency or Auth Provider Port.

## Failure policy

Management authorization is fail-closed. Dependency Runtime Failures remain
Runtime Failures. A Projects domain rejection is a terminal action/execution
receipt. An ambiguous Runtime Failure returns the execution to retryable state
under the same action idempotency key. Recurring schedules advance after both
successful and terminally failed executions, but not while an action outcome is
ambiguous. Delivery is at-least-once, never advertised as exactly-once.

## Replaceability proof

Removing this Plugin removes rules, trigger intake, reconciliation, and its
owned PostgreSQL schema. Projects and its data remain independently composed
and callable; the Kernel deletion test proves that boundary.
