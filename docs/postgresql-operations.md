# PostgreSQL operations

Project Automation owns one configured schema. Use a dedicated schema name per
Plugin Instance and resolve the database URL through Secrets.

Run `ProjectAutomationOperator::setup` once, then
`ProjectAutomationOperator::upgrade` before deploying a binary that contains a
new migration. Activation validates the migration ledger and refuses an
unprepared or stale schema; it does not run DDL.

Back up these state classes together:

- rules and command receipts;
- trigger and execution receipts;
- attempt/action receipts;
- schedule-dispatch receipts.

Restore them transactionally. Restoring only rules can lose dedupe history and
cause valid at-least-once deliveries to execute again. Restoring only receipts
without rules makes executions non-actionable.

The optional acceptance suite refuses databases whose name does not start with
`lenso_project_automation_test` and drops only its generated schema at the end.
