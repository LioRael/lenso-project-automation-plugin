# Architecture boundary

## Management path

1. Match an exact `admin_callers` Instance.
2. Verify the Auth 0.2.1 ActorAssertion for the exact automation operation.
3. Check active organization membership.
4. Check `projects.automation.read` or `projects.automation.manage`.
5. Validate the bounded rule and commit PostgreSQL state using revision CAS and
   scoped idempotency.

Any dependency Domain error in steps 3-4 is a protocol violation, because these
checks are infrastructure obligations rather than rule business outcomes.

## Trigger and execution path

- Event and timer intake have separate exact caller allowlists and durable
  dedupe keys.
- `reconcile` has a fourth, disjoint exact caller allowlist and an exact actor
  assertion audience.
- The reconcile limit is bounded by immutable Plugin configuration.
- Execution inspection returns at most 100 attempt receipts per cursor page;
  action receipts remain bounded by the rule's 32-action maximum.
- Each dependency call forwards the InvocationContext so the ActorAssertion
  reaches Projects unchanged.
- Trigger intake snapshots the matched action list into each execution; later
  rule edits cannot rewrite already accepted work or misalign its receipts.
- Projects domain errors create terminal action and execution receipts.
- Runtime Failures release the execution for an idempotent retry and propagate
  unchanged.

## Schedule state machine

`enabled schedule rule -> pending dispatch -> enqueued one-shot job -> timer
receipt -> pending execution -> terminal success/failure -> next pending
dispatch`

If Jobs enqueue fails, the dispatch remains pending and a later rule command or
reconcile retries it with the same idempotency key. If a stale already-enqueued
job arrives after rule update/disable, `receive_timer` records the dedupe receipt
but rejects it as not accepted because `scheduled_for != next_fire_at`.
Timer intake also derives and verifies the expected rule/time dedupe key rather
than trusting an arbitrary key from the delivery payload.
Superseded pending dispatches become durable `cancelled` receipts rather than
being deleted; an enqueue racing with cancellation cannot re-open that intent.

## Host prerequisites

The Host must link this native Plugin, bind every exact Capability requirement,
prepare its PostgreSQL schema, and operate a Jobs worker that delivers
`lenso.project-automation.timer` payloads to `receive_timer`. Nothing in this
repository registers a Console surface or generic `lenso run` distribution.
