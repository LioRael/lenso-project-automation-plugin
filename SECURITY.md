# Security policy

Report vulnerabilities privately to the repository maintainers. Do not include
production database URLs, Auth keys, actor assertions, rule payloads, or action
receipts in public issues.

Project Automation deliberately excludes arbitrary code, commands, URLs, and
dynamic Capability selection. Treat any path that bypasses exact caller checks,
ActorAssertion audience verification, membership, Access Control, revision CAS,
or stable dependency idempotency as security-sensitive.
