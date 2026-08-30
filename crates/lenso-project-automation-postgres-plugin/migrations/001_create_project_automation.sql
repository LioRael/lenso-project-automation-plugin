CREATE TABLE automation_commands (
    caller_instance TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    response JSONB,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (caller_instance, actor_subject, operation, idempotency_key),
    CHECK ((response IS NULL AND completed_at IS NULL) OR (response IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE TABLE automation_rules (
    rule_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    trigger JSONB NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    next_fire_at TIMESTAMPTZ,
    row_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT automation_rules_active_name_key UNIQUE NULLS NOT DISTINCT (organization_id, name, deleted_at),
    CHECK (jsonb_typeof(trigger) = 'object'),
    CHECK (jsonb_typeof(conditions) = 'array'),
    CHECK (jsonb_typeof(actions) = 'array')
);

CREATE INDEX automation_rules_list_idx
    ON automation_rules (organization_id, row_seq, rule_id)
    WHERE deleted_at IS NULL;
CREATE INDEX automation_rules_due_idx
    ON automation_rules (next_fire_at, rule_id)
    WHERE enabled AND deleted_at IS NULL AND next_fire_at IS NOT NULL;

CREATE TABLE automation_triggers (
    trigger_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('event','timer')),
    dedupe_key TEXT NOT NULL,
    rule_id TEXT,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, source, dedupe_key),
    FOREIGN KEY (rule_id) REFERENCES automation_rules(rule_id)
);

CREATE TABLE automation_executions (
    execution_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    trigger_id UUID NOT NULL,
    actions JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_failure TEXT,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (rule_id, trigger_id),
    FOREIGN KEY (rule_id) REFERENCES automation_rules(rule_id),
    FOREIGN KEY (trigger_id) REFERENCES automation_triggers(trigger_id),
    CHECK (jsonb_typeof(actions) = 'array')
);

CREATE INDEX automation_executions_claim_idx
    ON automation_executions (organization_id, status, lease_until, created_at, execution_id);

CREATE TABLE automation_attempts (
    execution_id UUID NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    worker_instance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','retryable')),
    failure TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (execution_id, attempt),
    FOREIGN KEY (execution_id) REFERENCES automation_executions(execution_id) ON DELETE CASCADE
);

CREATE TABLE automation_action_receipts (
    execution_id UUID NOT NULL,
    action_index INTEGER NOT NULL CHECK (action_index >= 0),
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','succeeded','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    idempotency_key TEXT NOT NULL,
    last_failure TEXT,
    response JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (execution_id, action_index),
    UNIQUE (idempotency_key),
    FOREIGN KEY (execution_id) REFERENCES automation_executions(execution_id) ON DELETE CASCADE
);

CREATE TABLE automation_schedule_dispatches (
    rule_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','enqueued','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    job_id TEXT,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (rule_id, scheduled_for),
    FOREIGN KEY (rule_id) REFERENCES automation_rules(rule_id)
);

CREATE INDEX automation_schedule_dispatches_pending_idx
    ON automation_schedule_dispatches (organization_id, state, scheduled_for, rule_id);
