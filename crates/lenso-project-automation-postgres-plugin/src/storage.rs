#![allow(clippy::too_many_lines)]

use std::fmt;

use lenso_kernel::RuntimeFailure;
use lenso_postgres_kit::OwnedPostgres;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Postgres, QueryBuilder, Row, Transaction, postgres::PgRow, types::Json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    InvalidRequest,
    NotFound,
    RevisionConflict,
    IdempotencyConflict,
    RuleIdConflict,
    RuleNameConflict,
}

#[derive(Debug)]
pub(crate) enum StorageError {
    Domain(DomainFailure),
    Runtime(RuntimeFailure),
}

impl From<DomainFailure> for StorageError {
    fn from(value: DomainFailure) -> Self {
        Self::Domain(value)
    }
}

fn runtime(operation: &'static str, source: impl fmt::Display) -> StorageError {
    StorageError::Runtime(RuntimeFailure::PluginFailure {
        detail: format!("Project Automation PostgreSQL operation `{operation}` failed: {source}"),
    })
}

fn encode<T: Serialize>(operation: &'static str, value: &T) -> Result<Value, StorageError> {
    serde_json::to_value(value).map_err(|error| runtime(operation, error))
}

fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    value
        .format(&Rfc3339)
        .map_err(|error| runtime("format timestamp", error))
}

pub(crate) fn parse_time(value: &str) -> Result<OffsetDateTime, DomainFailure> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| DomainFailure::InvalidRequest)
}

pub(crate) fn parse_revision(value: &str) -> Result<i64, DomainFailure> {
    let revision = value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(DomainFailure::InvalidRequest)?;
    if revision.to_string() != value {
        return Err(DomainFailure::InvalidRequest);
    }
    Ok(revision)
}

enum CommandStart {
    New,
    Replay(Value),
    Conflict,
}

async fn reserve_command<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request: &T,
) -> Result<CommandStart, StorageError> {
    let request = serde_json::to_vec(request).map_err(|error| runtime("encode command", error))?;
    let hash = Sha256::digest(request).to_vec();
    let inserted = sqlx::query("INSERT INTO automation_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(caller)
        .bind(actor)
        .bind(operation)
        .bind(idempotency_key)
        .bind(&hash)
        .execute(&mut **transaction)
        .await
        .map_err(|error| runtime("reserve command", error))?;
    if inserted.rows_affected() == 1 {
        return Ok(CommandStart::New);
    }
    let row = sqlx::query("SELECT request_hash,response FROM automation_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE")
        .bind(caller)
        .bind(actor)
        .bind(operation)
        .bind(idempotency_key)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| runtime("read command", error))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|error| runtime("decode command", error))?;
    if stored_hash != hash {
        return Ok(CommandStart::Conflict);
    }
    let response: Option<Json<Value>> = row
        .try_get("response")
        .map_err(|error| runtime("decode command", error))?;
    Ok(response.map_or(CommandStart::Conflict, |value| {
        CommandStart::Replay(value.0)
    }))
}

async fn complete_command(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    response: &Value,
) -> Result<(), StorageError> {
    let completed = sqlx::query("UPDATE automation_commands SET response=$5,completed_at=transaction_timestamp() WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4 AND response IS NULL")
        .bind(caller)
        .bind(actor)
        .bind(operation)
        .bind(idempotency_key)
        .bind(Json(response))
        .execute(&mut **transaction)
        .await
        .map_err(|error| runtime("complete command", error))?;
    if completed.rows_affected() != 1 {
        return Err(runtime(
            "complete command",
            "command reservation is missing or already completed",
        ));
    }
    Ok(())
}

fn json_column(row: &PgRow, name: &'static str) -> Result<Value, StorageError> {
    row.try_get::<Json<Value>, _>(name)
        .map(|value| value.0)
        .map_err(|error| runtime("decode json column", error))
}

fn rule_json(row: &PgRow) -> Result<Value, StorageError> {
    let next_fire_at: Option<OffsetDateTime> = row
        .try_get("next_fire_at")
        .map_err(|error| runtime("decode rule", error))?;
    let created_at: OffsetDateTime = row
        .try_get("created_at")
        .map_err(|error| runtime("decode rule", error))?;
    let updated_at: OffsetDateTime = row
        .try_get("updated_at")
        .map_err(|error| runtime("decode rule", error))?;
    Ok(json!({
        "rule_id": row.try_get::<String,_>("rule_id").map_err(|error| runtime("decode rule", error))?,
        "organization_id": row.try_get::<String,_>("organization_id").map_err(|error| runtime("decode rule", error))?,
        "name": row.try_get::<String,_>("name").map_err(|error| runtime("decode rule", error))?,
        "enabled": row.try_get::<bool,_>("enabled").map_err(|error| runtime("decode rule", error))?,
        "trigger": json_column(row, "trigger")?,
        "conditions": json_column(row, "conditions")?,
        "actions": json_column(row, "actions")?,
        "revision": row.try_get::<i64,_>("revision").map_err(|error| runtime("decode rule", error))?.to_string(),
        "next_fire_at": next_fire_at.map(format_time).transpose()?,
        "created_at": format_time(created_at)?,
        "updated_at": format_time(updated_at)?,
    }))
}

const RULE_COLUMNS: &str = "rule_id,organization_id,name,enabled,trigger,conditions,actions,revision,next_fire_at,created_at,updated_at";

fn trigger_kind(trigger: &Value) -> Option<&str> {
    trigger.get("kind").and_then(Value::as_str)
}

fn interval_seconds(trigger: &Value) -> Option<i64> {
    trigger.get("interval_seconds").and_then(Value::as_i64)
}

fn initial_next_fire(
    trigger: &Value,
    enabled: bool,
) -> Result<Option<OffsetDateTime>, StorageError> {
    if !enabled || trigger_kind(trigger) != Some("schedule") {
        return Ok(None);
    }
    let interval = interval_seconds(trigger).ok_or(DomainFailure::InvalidRequest)?;
    let start = trigger
        .get("start_at")
        .and_then(Value::as_str)
        .map(parse_time)
        .transpose()?;
    let now = OffsetDateTime::now_utc();
    let next = match start {
        Some(start) if start > now => start,
        Some(start) => {
            let elapsed_intervals = (now - start).whole_seconds() / interval;
            let seconds = interval
                .checked_mul(elapsed_intervals.saturating_add(1))
                .ok_or(DomainFailure::InvalidRequest)?;
            start
                .checked_add(Duration::seconds(seconds))
                .ok_or(DomainFailure::InvalidRequest)?
        }
        None => now
            .checked_add(Duration::seconds(interval))
            .ok_or(DomainFailure::InvalidRequest)?,
    };
    Ok(Some(next))
}

fn stable_uuid(namespace: Uuid, value: &str) -> Uuid {
    Uuid::new_v5(&namespace, value.as_bytes())
}

fn schedule_key(rule_id: &str, scheduled_for: OffsetDateTime) -> String {
    format!(
        "pa-schedule-{}",
        stable_uuid(
            Uuid::NAMESPACE_OID,
            &format!("{rule_id}:{}", scheduled_for.unix_timestamp_nanos())
        )
    )
}

async fn replace_pending_schedule(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    rule_id: &str,
    next_fire_at: Option<OffsetDateTime>,
) -> Result<(), StorageError> {
    if let Some(scheduled_for) = next_fire_at {
        sqlx::query("UPDATE automation_schedule_dispatches SET state='cancelled',updated_at=transaction_timestamp() WHERE rule_id=$1 AND state='pending' AND scheduled_for<>$2")
            .bind(rule_id)
            .bind(scheduled_for)
            .execute(&mut **transaction)
            .await
            .map_err(|error| runtime("cancel superseded schedule", error))?;
        sqlx::query("INSERT INTO automation_schedule_dispatches(rule_id,organization_id,scheduled_for,idempotency_key) VALUES($1,$2,$3,$4) ON CONFLICT(rule_id,scheduled_for) DO UPDATE SET state='pending',last_failure=NULL,updated_at=transaction_timestamp() WHERE automation_schedule_dispatches.state='cancelled'")
            .bind(rule_id)
            .bind(organization_id)
            .bind(scheduled_for)
            .bind(schedule_key(rule_id, scheduled_for))
            .execute(&mut **transaction)
            .await
            .map_err(|error| runtime("create schedule dispatch", error))?;
    } else {
        sqlx::query("UPDATE automation_schedule_dispatches SET state='cancelled',updated_at=transaction_timestamp() WHERE rule_id=$1 AND state='pending'")
            .bind(rule_id)
            .execute(&mut **transaction)
            .await
            .map_err(|error| runtime("cancel pending schedule", error))?;
    }
    Ok(())
}

pub(crate) struct CreateRuleInput<'a, T> {
    pub(crate) caller: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) idempotency_key: &'a str,
    pub(crate) organization_id: &'a str,
    pub(crate) rule_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) enabled: bool,
    pub(crate) trigger: Value,
    pub(crate) conditions: Value,
    pub(crate) actions: Value,
    pub(crate) request: &'a T,
}

pub(crate) async fn create_rule<T: Serialize>(
    postgres: &OwnedPostgres,
    input: CreateRuleInput<'_, T>,
) -> Result<Value, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin create rule", error))?;
    match reserve_command(
        &mut transaction,
        input.caller,
        input.actor,
        input.operation,
        input.idempotency_key,
        input.request,
    )
    .await?
    {
        CommandStart::Replay(response) => return Ok(response),
        CommandStart::Conflict => return Err(DomainFailure::IdempotencyConflict.into()),
        CommandStart::New => {}
    }
    let next_fire_at = initial_next_fire(&input.trigger, input.enabled)?;
    let query = format!(
        "INSERT INTO automation_rules(rule_id,organization_id,name,enabled,trigger,conditions,actions,next_fire_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {RULE_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(input.rule_id)
        .bind(input.organization_id)
        .bind(input.name)
        .bind(input.enabled)
        .bind(Json(&input.trigger))
        .bind(Json(&input.conditions))
        .bind(Json(&input.actions))
        .bind(next_fire_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            match error
                .as_database_error()
                .and_then(|value| value.constraint())
            {
                Some("automation_rules_pkey") => DomainFailure::RuleIdConflict.into(),
                Some("automation_rules_active_name_key") => DomainFailure::RuleNameConflict.into(),
                _ => runtime("insert rule", error),
            }
        })?;
    replace_pending_schedule(
        &mut transaction,
        input.organization_id,
        input.rule_id,
        next_fire_at,
    )
    .await?;
    let response = rule_json(&row)?;
    complete_command(
        &mut transaction,
        input.caller,
        input.actor,
        input.operation,
        input.idempotency_key,
        &response,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit create rule", error))?;
    Ok(response)
}

pub(crate) async fn get_rule(
    postgres: &OwnedPostgres,
    organization_id: &str,
    rule_id: &str,
) -> Result<Value, StorageError> {
    let query = format!(
        "SELECT {RULE_COLUMNS} FROM automation_rules WHERE organization_id=$1 AND rule_id=$2 AND deleted_at IS NULL"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(organization_id)
        .bind(rule_id)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|error| runtime("get rule", error))?
        .ok_or(DomainFailure::NotFound)?;
    rule_json(&row)
}

pub(crate) async fn list_rules(
    postgres: &OwnedPostgres,
    organization_id: &str,
    enabled: Option<bool>,
    limit: i64,
    after: Option<&str>,
) -> Result<Value, StorageError> {
    let after = after.map(parse_revision).transpose()?.unwrap_or(0);
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT {RULE_COLUMNS},row_seq FROM automation_rules WHERE organization_id="
    ));
    query.push_bind(organization_id);
    query.push(" AND deleted_at IS NULL AND row_seq > ");
    query.push_bind(after);
    if let Some(enabled) = enabled {
        query.push(" AND enabled = ");
        query.push_bind(enabled);
    }
    query.push(" ORDER BY row_seq,rule_id LIMIT ");
    query.push_bind(limit + 1);
    let rows = query
        .build()
        .fetch_all(postgres.pool())
        .await
        .map_err(|error| runtime("list rules", error))?;
    let has_more = i64::try_from(rows.len()).is_ok_and(|length| length > limit);
    let kept = usize::try_from(limit).unwrap_or(0).min(rows.len());
    let items = rows[..kept]
        .iter()
        .map(rule_json)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if has_more {
        rows.get(kept.saturating_sub(1))
            .map(|row| row.try_get::<i64, _>("row_seq"))
            .transpose()
            .map_err(|error| runtime("decode list cursor", error))?
            .map(|value| value.to_string())
    } else {
        None
    };
    Ok(json!({"items": items, "next_cursor": next_cursor}))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_rule<T: Serialize>(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    organization_id: &str,
    rule_id: &str,
    expected_revision: i64,
    name: &str,
    trigger: Value,
    conditions: Value,
    actions: Value,
    request: &T,
) -> Result<Value, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin update rule", error))?;
    match reserve_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        request,
    )
    .await?
    {
        CommandStart::Replay(response) => return Ok(response),
        CommandStart::Conflict => return Err(DomainFailure::IdempotencyConflict.into()),
        CommandStart::New => {}
    }
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM automation_rules WHERE organization_id=$1 AND rule_id=$2 AND deleted_at IS NULL FOR UPDATE")
        .bind(organization_id).bind(rule_id).fetch_optional(&mut *transaction).await.map_err(|error| runtime("lock rule", error))?.ok_or(DomainFailure::NotFound)?;
    let next_fire_at = initial_next_fire(&trigger, enabled)?;
    let query = format!(
        "UPDATE automation_rules SET name=$4,trigger=$5,conditions=$6,actions=$7,next_fire_at=$8,revision=revision+1,updated_at=transaction_timestamp() WHERE organization_id=$1 AND rule_id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING {RULE_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(organization_id)
        .bind(rule_id)
        .bind(expected_revision)
        .bind(name)
        .bind(Json(&trigger))
        .bind(Json(&conditions))
        .bind(Json(&actions))
        .bind(next_fire_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|value| value.constraint())
                == Some("automation_rules_active_name_key")
            {
                DomainFailure::RuleNameConflict.into()
            } else {
                runtime("update rule", error)
            }
        })?
        .ok_or(DomainFailure::RevisionConflict)?;
    replace_pending_schedule(&mut transaction, organization_id, rule_id, next_fire_at).await?;
    let response = rule_json(&row)?;
    complete_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        &response,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit update rule", error))?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn set_enabled<T: Serialize>(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    organization_id: &str,
    rule_id: &str,
    expected_revision: i64,
    enabled: bool,
    request: &T,
) -> Result<Value, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin set rule enabled", error))?;
    match reserve_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        request,
    )
    .await?
    {
        CommandStart::Replay(response) => return Ok(response),
        CommandStart::Conflict => return Err(DomainFailure::IdempotencyConflict.into()),
        CommandStart::New => {}
    }
    let trigger: Json<Value> = sqlx::query_scalar("SELECT trigger FROM automation_rules WHERE organization_id=$1 AND rule_id=$2 AND deleted_at IS NULL FOR UPDATE")
        .bind(organization_id).bind(rule_id).fetch_optional(&mut *transaction).await.map_err(|error| runtime("lock rule", error))?.ok_or(DomainFailure::NotFound)?;
    let next_fire_at = initial_next_fire(&trigger.0, enabled)?;
    let query = format!(
        "UPDATE automation_rules SET enabled=$4,next_fire_at=$5,revision=revision+1,updated_at=transaction_timestamp() WHERE organization_id=$1 AND rule_id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING {RULE_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(organization_id)
        .bind(rule_id)
        .bind(expected_revision)
        .bind(enabled)
        .bind(next_fire_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| runtime("set rule enabled", error))?
        .ok_or(DomainFailure::RevisionConflict)?;
    replace_pending_schedule(&mut transaction, organization_id, rule_id, next_fire_at).await?;
    let response = rule_json(&row)?;
    complete_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        &response,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit set rule enabled", error))?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn delete_rule<T: Serialize>(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    organization_id: &str,
    rule_id: &str,
    expected_revision: i64,
    request: &T,
) -> Result<Value, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin delete rule", error))?;
    match reserve_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        request,
    )
    .await?
    {
        CommandStart::Replay(response) => return Ok(response),
        CommandStart::Conflict => return Err(DomainFailure::IdempotencyConflict.into()),
        CommandStart::New => {}
    }
    let updated = sqlx::query("UPDATE automation_rules SET enabled=FALSE,next_fire_at=NULL,deleted_at=transaction_timestamp(),revision=revision+1,updated_at=transaction_timestamp() WHERE organization_id=$1 AND rule_id=$2 AND revision=$3 AND deleted_at IS NULL")
        .bind(organization_id).bind(rule_id).bind(expected_revision).execute(&mut *transaction).await.map_err(|error| runtime("delete rule", error))?;
    if updated.rows_affected() == 0 {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM automation_rules WHERE organization_id=$1 AND rule_id=$2 AND deleted_at IS NULL)")
            .bind(organization_id).bind(rule_id).fetch_one(&mut *transaction).await.map_err(|error| runtime("inspect delete conflict", error))?;
        return Err(if exists {
            DomainFailure::RevisionConflict
        } else {
            DomainFailure::NotFound
        }
        .into());
    }
    replace_pending_schedule(&mut transaction, organization_id, rule_id, None).await?;
    let response = json!({"deleted": true});
    complete_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        &response,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit delete rule", error))?;
    Ok(response)
}

fn conditions_match(conditions: &Value, event: &Value) -> bool {
    let Some(conditions) = conditions.as_array() else {
        return false;
    };
    conditions.iter().all(|condition| {
        let Some(field) = condition.get("field").and_then(Value::as_str) else {
            return false;
        };
        let Some(operator) = condition.get("operator").and_then(Value::as_str) else {
            return false;
        };
        let Some(expected) = condition.get("value").and_then(Value::as_str) else {
            return false;
        };
        let matches = if field == "label_id" {
            event
                .get("label_ids")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
        } else {
            event.get(field).and_then(Value::as_str) == Some(expected)
        };
        match operator {
            "equals" | "contains" => matches,
            "not_equals" => !matches,
            _ => false,
        }
    })
}

async fn insert_execution(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    rule_id: &str,
    trigger_id: Uuid,
    actions: &Value,
) -> Result<Uuid, StorageError> {
    let execution_id = Uuid::new_v4();
    let inserted = sqlx::query("INSERT INTO automation_executions(execution_id,organization_id,rule_id,trigger_id,actions) VALUES($1,$2,$3,$4,$5) ON CONFLICT(rule_id,trigger_id) DO NOTHING")
        .bind(execution_id).bind(organization_id).bind(rule_id).bind(trigger_id).bind(Json(actions)).execute(&mut **transaction).await.map_err(|error| runtime("create execution", error))?;
    if inserted.rows_affected() == 0 {
        return sqlx::query_scalar(
            "SELECT execution_id FROM automation_executions WHERE rule_id=$1 AND trigger_id=$2",
        )
        .bind(rule_id)
        .bind(trigger_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| runtime("read execution", error));
    }
    for (index, action) in actions
        .as_array()
        .ok_or(DomainFailure::InvalidRequest)?
        .iter()
        .enumerate()
    {
        let index = i32::try_from(index).map_err(|error| runtime("action index", error))?;
        let kind = action
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(DomainFailure::InvalidRequest)?;
        let idempotency_key = format!(
            "pa-action-{}",
            stable_uuid(Uuid::NAMESPACE_URL, &format!("{execution_id}:{index}"))
        );
        sqlx::query("INSERT INTO automation_action_receipts(execution_id,action_index,kind,idempotency_key) VALUES($1,$2,$3,$4)")
            .bind(execution_id).bind(index).bind(kind).bind(idempotency_key).execute(&mut **transaction).await.map_err(|error| runtime("create action receipt", error))?;
    }
    Ok(execution_id)
}

async fn existing_trigger_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    source: &str,
    dedupe_key: &str,
) -> Result<Value, StorageError> {
    let rows = sqlx::query("SELECT e.execution_id FROM automation_triggers t LEFT JOIN automation_executions e ON e.trigger_id=t.trigger_id WHERE t.organization_id=$1 AND t.source=$2 AND t.dedupe_key=$3 ORDER BY e.execution_id")
        .bind(organization_id).bind(source).bind(dedupe_key).fetch_all(&mut **transaction).await.map_err(|error| runtime("read duplicate trigger", error))?;
    let execution_ids = rows
        .into_iter()
        .filter_map(|row| {
            row.try_get::<Option<Uuid>, _>("execution_id")
                .ok()
                .flatten()
        })
        .map(|id| id.to_string())
        .collect::<Vec<_>>();
    Ok(json!({"accepted": true, "duplicate": true, "execution_ids": execution_ids}))
}

pub(crate) async fn receive_event<T: Serialize>(
    postgres: &OwnedPostgres,
    organization_id: &str,
    dedupe_key: &str,
    occurred_at: OffsetDateTime,
    request: &T,
) -> Result<Value, StorageError> {
    let payload = encode("encode event", request)?;
    let event_type = payload
        .get("event_type")
        .and_then(Value::as_str)
        .ok_or(DomainFailure::InvalidRequest)?;
    let trigger_id = Uuid::new_v4();
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin receive event", error))?;
    let inserted = sqlx::query("INSERT INTO automation_triggers(trigger_id,organization_id,source,dedupe_key,payload,occurred_at) VALUES($1,$2,'event',$3,$4,$5) ON CONFLICT(organization_id,source,dedupe_key) DO NOTHING")
        .bind(trigger_id).bind(organization_id).bind(dedupe_key).bind(Json(&payload)).bind(occurred_at).execute(&mut *transaction).await.map_err(|error| runtime("insert event", error))?;
    if inserted.rows_affected() == 0 {
        return existing_trigger_receipt(&mut transaction, organization_id, "event", dedupe_key)
            .await;
    }
    let rows = sqlx::query("SELECT rule_id,trigger,conditions,actions FROM automation_rules WHERE organization_id=$1 AND enabled AND deleted_at IS NULL AND trigger->>'kind'='event' FOR SHARE")
        .bind(organization_id).fetch_all(&mut *transaction).await.map_err(|error| runtime("match event rules", error))?;
    let mut execution_ids = Vec::new();
    for row in rows {
        let trigger = json_column(&row, "trigger")?;
        let event_allowed = trigger
            .get("event_types")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|value| value.as_str() == Some(event_type)));
        let conditions = json_column(&row, "conditions")?;
        if event_allowed && conditions_match(&conditions, &payload) {
            let rule_id: String = row
                .try_get("rule_id")
                .map_err(|error| runtime("decode matched rule", error))?;
            let actions = json_column(&row, "actions")?;
            execution_ids.push(
                insert_execution(
                    &mut transaction,
                    organization_id,
                    &rule_id,
                    trigger_id,
                    &actions,
                )
                .await?
                .to_string(),
            );
        }
    }
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit receive event", error))?;
    Ok(json!({"accepted": true, "duplicate": false, "execution_ids": execution_ids}))
}

pub(crate) async fn receive_timer<T: Serialize>(
    postgres: &OwnedPostgres,
    organization_id: &str,
    rule_id: &str,
    dedupe_key: &str,
    scheduled_for: OffsetDateTime,
    request: &T,
) -> Result<Value, StorageError> {
    if dedupe_key != schedule_key(rule_id, scheduled_for) {
        return Err(DomainFailure::InvalidRequest.into());
    }
    let payload = encode("encode timer", request)?;
    let trigger_id = Uuid::new_v4();
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin receive timer", error))?;
    let inserted = sqlx::query("INSERT INTO automation_triggers(trigger_id,organization_id,source,dedupe_key,rule_id,payload,occurred_at) VALUES($1,$2,'timer',$3,$4,$5,$6) ON CONFLICT(organization_id,source,dedupe_key) DO NOTHING")
        .bind(trigger_id).bind(organization_id).bind(dedupe_key).bind(rule_id).bind(Json(&payload)).bind(scheduled_for).execute(&mut *transaction).await.map_err(|error| runtime("insert timer", error))?;
    if inserted.rows_affected() == 0 {
        return existing_trigger_receipt(&mut transaction, organization_id, "timer", dedupe_key)
            .await;
    }
    let row = sqlx::query("SELECT enabled,trigger,actions,next_fire_at FROM automation_rules WHERE organization_id=$1 AND rule_id=$2 AND deleted_at IS NULL FOR SHARE")
        .bind(organization_id).bind(rule_id).fetch_optional(&mut *transaction).await.map_err(|error| runtime("read timer rule", error))?;
    let Some(row) = row else {
        transaction
            .commit()
            .await
            .map_err(|error| runtime("commit stale timer", error))?;
        return Ok(json!({"accepted": false, "duplicate": false, "execution_ids": []}));
    };
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|error| runtime("decode timer rule", error))?;
    let next_fire_at: Option<OffsetDateTime> = row
        .try_get("next_fire_at")
        .map_err(|error| runtime("decode timer rule", error))?;
    let trigger = json_column(&row, "trigger")?;
    if !enabled || trigger_kind(&trigger) != Some("schedule") || next_fire_at != Some(scheduled_for)
    {
        transaction
            .commit()
            .await
            .map_err(|error| runtime("commit ignored timer", error))?;
        return Ok(json!({"accepted": false, "duplicate": false, "execution_ids": []}));
    }
    let actions = json_column(&row, "actions")?;
    let execution_id = insert_execution(
        &mut transaction,
        organization_id,
        rule_id,
        trigger_id,
        &actions,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit receive timer", error))?;
    Ok(json!({"accepted": true, "duplicate": false, "execution_ids": [execution_id.to_string()]}))
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedExecution {
    pub execution_id: Uuid,
    pub rule_id: String,
    pub trigger_id: Uuid,
    pub attempt: i32,
    pub worker: String,
    pub payload: Value,
    pub actions: Vec<Value>,
}

pub(crate) async fn claim_executions(
    postgres: &OwnedPostgres,
    organization_id: &str,
    worker: &str,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<ClaimedExecution>, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin claim executions", error))?;
    let rows = sqlx::query("SELECT e.execution_id,e.rule_id,e.trigger_id,e.attempts,t.payload,e.actions FROM automation_executions e JOIN automation_triggers t ON t.trigger_id=e.trigger_id WHERE e.organization_id=$1 AND (e.status='pending' OR (e.status='running' AND e.lease_until < transaction_timestamp())) ORDER BY e.created_at,e.execution_id FOR UPDATE OF e SKIP LOCKED LIMIT $2")
        .bind(organization_id).bind(limit).fetch_all(&mut *transaction).await.map_err(|error| runtime("select executions", error))?;
    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
        let execution_id: Uuid = row
            .try_get("execution_id")
            .map_err(|error| runtime("decode execution", error))?;
        let previous_attempt: i32 = row
            .try_get::<i32, _>("attempts")
            .map_err(|error| runtime("decode execution", error))?;
        if previous_attempt > 0 {
            sqlx::query("UPDATE automation_attempts SET status='retryable',failure='lease_expired',completed_at=transaction_timestamp() WHERE execution_id=$1 AND attempt=$2 AND status='running'")
                .bind(execution_id)
                .bind(previous_attempt)
                .execute(&mut *transaction)
                .await
                .map_err(|error| runtime("expire previous attempt", error))?;
        }
        let attempt = previous_attempt
            .checked_add(1)
            .ok_or_else(|| runtime("claim execution", "attempt counter exhausted"))?;
        sqlx::query("UPDATE automation_executions SET status='running',attempts=$2,lease_owner=$3,lease_until=transaction_timestamp()+make_interval(secs => $4),updated_at=transaction_timestamp() WHERE execution_id=$1")
            .bind(execution_id).bind(attempt).bind(worker).bind(f64::from(i32::try_from(lease_seconds).map_err(|error| runtime("lease duration", error))?)).execute(&mut *transaction).await.map_err(|error| runtime("claim execution", error))?;
        sqlx::query("INSERT INTO automation_attempts(execution_id,attempt,worker_instance,status) VALUES($1,$2,$3,'running')")
            .bind(execution_id).bind(attempt).bind(worker).execute(&mut *transaction).await.map_err(|error| runtime("create attempt", error))?;
        claimed.push(ClaimedExecution {
            execution_id,
            rule_id: row
                .try_get("rule_id")
                .map_err(|error| runtime("decode execution", error))?,
            trigger_id: row
                .try_get("trigger_id")
                .map_err(|error| runtime("decode execution", error))?,
            attempt,
            worker: worker.to_owned(),
            payload: json_column(&row, "payload")?,
            actions: json_column(&row, "actions")?
                .as_array()
                .cloned()
                .ok_or(DomainFailure::InvalidRequest)?,
        });
    }
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit claim executions", error))?;
    Ok(claimed)
}

pub(crate) async fn action_status(
    postgres: &OwnedPostgres,
    execution_id: Uuid,
    action_index: i32,
) -> Result<(String, String), StorageError> {
    let row = sqlx::query("UPDATE automation_action_receipts SET attempts=attempts+1,updated_at=transaction_timestamp() WHERE execution_id=$1 AND action_index=$2 RETURNING status,idempotency_key")
        .bind(execution_id).bind(action_index).fetch_optional(postgres.pool()).await.map_err(|error| runtime("begin action attempt", error))?.ok_or(DomainFailure::NotFound)?;
    Ok((
        row.try_get("status")
            .map_err(|error| runtime("decode action receipt", error))?,
        row.try_get("idempotency_key")
            .map_err(|error| runtime("decode action receipt", error))?,
    ))
}

pub(crate) async fn complete_action(
    postgres: &OwnedPostgres,
    execution_id: Uuid,
    action_index: i32,
    succeeded: bool,
    response: Option<&Value>,
    failure: Option<&str>,
) -> Result<(), StorageError> {
    let status = if succeeded { "succeeded" } else { "failed" };
    sqlx::query("UPDATE automation_action_receipts SET status=$3,response=$4,last_failure=$5,updated_at=transaction_timestamp() WHERE execution_id=$1 AND action_index=$2")
        .bind(execution_id).bind(action_index).bind(status).bind(response.map(Json)).bind(failure).execute(postgres.pool()).await.map_err(|error| runtime("complete action", error))?;
    Ok(())
}

pub(crate) async fn release_execution_for_retry(
    postgres: &OwnedPostgres,
    execution: &ClaimedExecution,
    failure: &str,
) -> Result<(), StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin release execution", error))?;
    let updated = sqlx::query("UPDATE automation_executions SET status='pending',last_failure=$4,lease_owner=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE execution_id=$1 AND attempts=$2 AND status='running' AND lease_owner=$3 AND lease_until >= transaction_timestamp()")
        .bind(execution.execution_id).bind(execution.attempt).bind(&execution.worker).bind(failure).execute(&mut *transaction).await.map_err(|error| runtime("release execution", error))?;
    if updated.rows_affected() != 1 {
        return Err(runtime(
            "release execution",
            "execution lease is no longer owned by this worker",
        ));
    }
    sqlx::query("UPDATE automation_attempts SET status='retryable',failure=$3,completed_at=transaction_timestamp() WHERE execution_id=$1 AND attempt=$2")
        .bind(execution.execution_id).bind(execution.attempt).bind(failure).execute(&mut *transaction).await.map_err(|error| runtime("complete retryable attempt", error))?;
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit release execution", error))?;
    Ok(())
}

pub(crate) async fn complete_execution(
    postgres: &OwnedPostgres,
    execution: &ClaimedExecution,
    succeeded: bool,
    failure: Option<&str>,
) -> Result<(), StorageError> {
    let status = if succeeded { "succeeded" } else { "failed" };
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin complete execution", error))?;
    let updated = sqlx::query("UPDATE automation_executions SET status=$4,last_failure=$5,lease_owner=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE execution_id=$1 AND attempts=$2 AND status='running' AND lease_owner=$3 AND lease_until >= transaction_timestamp()")
        .bind(execution.execution_id).bind(execution.attempt).bind(&execution.worker).bind(status).bind(failure).execute(&mut *transaction).await.map_err(|error| runtime("complete execution", error))?;
    if updated.rows_affected() != 1 {
        return Err(runtime(
            "complete execution",
            "execution lease is no longer owned by this worker",
        ));
    }
    sqlx::query("UPDATE automation_attempts SET status=$3,failure=$4,completed_at=transaction_timestamp() WHERE execution_id=$1 AND attempt=$2")
        .bind(execution.execution_id).bind(execution.attempt).bind(status).bind(failure).execute(&mut *transaction).await.map_err(|error| runtime("complete attempt", error))?;
    let source: String =
        sqlx::query_scalar("SELECT source FROM automation_triggers WHERE trigger_id=$1")
            .bind(execution.trigger_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| runtime("read trigger source", error))?;
    if source == "timer" {
        let row = sqlx::query("SELECT organization_id,enabled,trigger,next_fire_at FROM automation_rules WHERE rule_id=$1 AND deleted_at IS NULL FOR UPDATE")
            .bind(&execution.rule_id).fetch_optional(&mut *transaction).await.map_err(|error| runtime("lock recurring rule", error))?;
        if let Some(row) = row {
            let enabled: bool = row
                .try_get("enabled")
                .map_err(|error| runtime("decode recurring rule", error))?;
            let trigger = json_column(&row, "trigger")?;
            let current: Option<OffsetDateTime> = row
                .try_get("next_fire_at")
                .map_err(|error| runtime("decode recurring rule", error))?;
            let scheduled_for = execution
                .payload
                .get("scheduled_for")
                .and_then(Value::as_str)
                .map(parse_time)
                .transpose()?;
            if enabled && trigger_kind(&trigger) == Some("schedule") && current == scheduled_for {
                let interval = interval_seconds(&trigger).ok_or(DomainFailure::InvalidRequest)?;
                let next = scheduled_for
                    .ok_or(DomainFailure::InvalidRequest)?
                    .checked_add(Duration::seconds(interval))
                    .ok_or_else(|| {
                        runtime("advance recurring rule", "next fire is out of range")
                    })?;
                let organization_id: String = row
                    .try_get("organization_id")
                    .map_err(|error| runtime("decode recurring rule", error))?;
                sqlx::query("UPDATE automation_rules SET next_fire_at=$2,updated_at=transaction_timestamp() WHERE rule_id=$1")
                    .bind(&execution.rule_id).bind(next).execute(&mut *transaction).await.map_err(|error| runtime("advance recurring rule", error))?;
                replace_pending_schedule(
                    &mut transaction,
                    &organization_id,
                    &execution.rule_id,
                    Some(next),
                )
                .await?;
            }
        }
    }
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit complete execution", error))?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ScheduleDispatch {
    pub rule_id: String,
    pub organization_id: String,
    pub scheduled_for: OffsetDateTime,
    pub idempotency_key: String,
}

pub(crate) async fn pending_dispatches(
    postgres: &OwnedPostgres,
    organization_id: &str,
    limit: i64,
) -> Result<Vec<ScheduleDispatch>, StorageError> {
    let rows = sqlx::query("SELECT rule_id,organization_id,scheduled_for,idempotency_key FROM automation_schedule_dispatches WHERE organization_id=$1 AND state='pending' ORDER BY scheduled_for,rule_id LIMIT $2")
        .bind(organization_id).bind(limit).fetch_all(postgres.pool()).await.map_err(|error| runtime("list schedule dispatches", error))?;
    rows.into_iter()
        .map(|row| {
            Ok(ScheduleDispatch {
                rule_id: row
                    .try_get("rule_id")
                    .map_err(|error| runtime("decode schedule dispatch", error))?,
                organization_id: row
                    .try_get("organization_id")
                    .map_err(|error| runtime("decode schedule dispatch", error))?,
                scheduled_for: row
                    .try_get("scheduled_for")
                    .map_err(|error| runtime("decode schedule dispatch", error))?,
                idempotency_key: row
                    .try_get("idempotency_key")
                    .map_err(|error| runtime("decode schedule dispatch", error))?,
            })
        })
        .collect()
}

pub(crate) async fn mark_dispatch_enqueued(
    postgres: &OwnedPostgres,
    dispatch: &ScheduleDispatch,
    job_id: &str,
) -> Result<bool, StorageError> {
    let updated = sqlx::query("UPDATE automation_schedule_dispatches SET state='enqueued',attempts=attempts+1,job_id=$3,last_failure=NULL,updated_at=transaction_timestamp() WHERE rule_id=$1 AND scheduled_for=$2 AND state='pending'")
        .bind(&dispatch.rule_id).bind(dispatch.scheduled_for).bind(job_id).execute(postgres.pool()).await.map_err(|error| runtime("complete schedule dispatch", error))?;
    if updated.rows_affected() == 1 {
        return Ok(true);
    }
    sqlx::query("UPDATE automation_schedule_dispatches SET attempts=attempts+1,job_id=$3,last_failure='cancelled_after_enqueue',updated_at=transaction_timestamp() WHERE rule_id=$1 AND scheduled_for=$2 AND state='cancelled'")
        .bind(&dispatch.rule_id).bind(dispatch.scheduled_for).bind(job_id).execute(postgres.pool()).await.map_err(|error| runtime("record cancelled schedule enqueue", error))?;
    Ok(false)
}

pub(crate) async fn record_dispatch_failure(
    postgres: &OwnedPostgres,
    dispatch: &ScheduleDispatch,
    failure: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE automation_schedule_dispatches SET attempts=attempts+1,last_failure=$3,updated_at=transaction_timestamp() WHERE rule_id=$1 AND scheduled_for=$2 AND state='pending'")
        .bind(&dispatch.rule_id).bind(dispatch.scheduled_for).bind(failure).execute(postgres.pool()).await.map_err(|error| runtime("record schedule dispatch failure", error))?;
    Ok(())
}

pub(crate) async fn pending_dispatch_count(
    postgres: &OwnedPostgres,
    organization_id: &str,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("SELECT count(*) FROM automation_schedule_dispatches WHERE organization_id=$1 AND state='pending'")
        .bind(organization_id).fetch_one(postgres.pool()).await.map_err(|error| runtime("count schedule dispatches", error))
}

pub(crate) async fn inspect_execution(
    postgres: &OwnedPostgres,
    organization_id: &str,
    execution_id: Uuid,
    attempt_limit: i64,
    attempt_after: Option<&str>,
) -> Result<Value, StorageError> {
    let row = sqlx::query("SELECT execution_id,rule_id,trigger_id,status,attempts,last_failure,created_at,updated_at FROM automation_executions WHERE organization_id=$1 AND execution_id=$2")
        .bind(organization_id).bind(execution_id).fetch_optional(postgres.pool()).await.map_err(|error| runtime("inspect execution", error))?.ok_or(DomainFailure::NotFound)?;
    let attempt_after = attempt_after.map(parse_revision).transpose()?.unwrap_or(0);
    let mut attempts = sqlx::query("SELECT attempt,worker_instance,status,failure,started_at,completed_at FROM automation_attempts WHERE execution_id=$1 AND attempt>$2 ORDER BY attempt LIMIT $3")
        .bind(execution_id).bind(attempt_after).bind(attempt_limit + 1).fetch_all(postgres.pool()).await.map_err(|error| runtime("inspect attempt receipts", error))?;
    let has_more = i64::try_from(attempts.len()).is_ok_and(|length| length > attempt_limit);
    let kept = usize::try_from(attempt_limit)
        .unwrap_or(0)
        .min(attempts.len());
    attempts.truncate(kept);
    let next_attempt_cursor = if has_more {
        attempts
            .last()
            .map(|attempt| attempt.try_get::<i32, _>("attempt"))
            .transpose()
            .map_err(|error| runtime("decode attempt cursor", error))?
            .map(|attempt| attempt.to_string())
    } else {
        None
    };
    let attempt_receipts = attempts
        .into_iter()
        .map(|attempt| {
            let started_at: OffsetDateTime = attempt
                .try_get("started_at")
                .map_err(|error| runtime("decode attempt receipt", error))?;
            let completed_at: Option<OffsetDateTime> = attempt
                .try_get("completed_at")
                .map_err(|error| runtime("decode attempt receipt", error))?;
            Ok(json!({
                "attempt": attempt.try_get::<i32,_>("attempt").map_err(|error| runtime("decode attempt receipt", error))?,
                "worker_instance": attempt.try_get::<String,_>("worker_instance").map_err(|error| runtime("decode attempt receipt", error))?,
                "status": attempt.try_get::<String,_>("status").map_err(|error| runtime("decode attempt receipt", error))?,
                "failure": attempt.try_get::<Option<String>,_>("failure").map_err(|error| runtime("decode attempt receipt", error))?,
                "started_at": format_time(started_at)?,
                "completed_at": completed_at.map(format_time).transpose()?,
            }))
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    let actions = sqlx::query("SELECT action_index,kind,status,attempts,idempotency_key,last_failure,updated_at FROM automation_action_receipts WHERE execution_id=$1 ORDER BY action_index")
        .bind(execution_id).fetch_all(postgres.pool()).await.map_err(|error| runtime("inspect action receipts", error))?;
    let actions = actions.into_iter().map(|action| {
        let updated_at: OffsetDateTime = action.try_get("updated_at").map_err(|error| runtime("decode action receipt", error))?;
        Ok(json!({
            "action_index": action.try_get::<i32,_>("action_index").map_err(|error| runtime("decode action receipt", error))?,
            "kind": action.try_get::<String,_>("kind").map_err(|error| runtime("decode action receipt", error))?,
            "status": action.try_get::<String,_>("status").map_err(|error| runtime("decode action receipt", error))?,
            "attempts": action.try_get::<i32,_>("attempts").map_err(|error| runtime("decode action receipt", error))?,
            "idempotency_key": action.try_get::<String,_>("idempotency_key").map_err(|error| runtime("decode action receipt", error))?,
            "last_failure": action.try_get::<Option<String>,_>("last_failure").map_err(|error| runtime("decode action receipt", error))?,
            "updated_at": format_time(updated_at)?,
        }))
    }).collect::<Result<Vec<_>, StorageError>>()?;
    let created_at: OffsetDateTime = row
        .try_get("created_at")
        .map_err(|error| runtime("decode execution", error))?;
    let updated_at: OffsetDateTime = row
        .try_get("updated_at")
        .map_err(|error| runtime("decode execution", error))?;
    Ok(json!({
        "execution_id": row.try_get::<Uuid,_>("execution_id").map_err(|error| runtime("decode execution", error))?.to_string(),
        "rule_id": row.try_get::<String,_>("rule_id").map_err(|error| runtime("decode execution", error))?,
        "trigger_id": row.try_get::<Uuid,_>("trigger_id").map_err(|error| runtime("decode execution", error))?.to_string(),
        "status": row.try_get::<String,_>("status").map_err(|error| runtime("decode execution", error))?,
        "attempts": row.try_get::<i32,_>("attempts").map_err(|error| runtime("decode execution", error))?,
        "last_failure": row.try_get::<Option<String>,_>("last_failure").map_err(|error| runtime("decode execution", error))?,
        "created_at": format_time(created_at)?,"updated_at": format_time(updated_at)?,"attempt_receipts": attempt_receipts,"next_attempt_cursor": next_attempt_cursor,"actions": actions,
    }))
}
