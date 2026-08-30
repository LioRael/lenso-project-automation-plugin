use super::*;

use lenso_postgres_kit::OwnedPostgres;
use sqlx::AssertSqlSafe;

async fn prepare() -> Option<(String, String, OwnedPostgres)> {
    let Some(database_url) = std::env::var("LENSO_PROJECT_AUTOMATION_TEST_DATABASE_URL").ok()
    else {
        eprintln!(
            "skipping PostgreSQL acceptance; LENSO_PROJECT_AUTOMATION_TEST_DATABASE_URL is unset"
        );
        return None;
    };
    let database_name = database_url
        .split('?')
        .next()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or_default();
    assert!(
        database_name.starts_with("lenso_project_automation_test"),
        "PostgreSQL acceptance requires a dedicated database whose name starts with lenso_project_automation_test"
    );
    let schema_name = format!("project_automation_test_{}", Uuid::new_v4().simple());
    ProjectAutomationOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    Some((database_url, schema_name, postgres))
}

async fn cleanup(database_url: &str, schema_name: &str, postgres: OwnedPostgres) {
    postgres.pool().close().await;
    let pool = sqlx::PgPool::connect(database_url).await.unwrap();
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema_name}\" CASCADE"
    )))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

fn action() -> automation::Action {
    automation::Action {
        comment_body: Some("Scheduled reminder".to_owned()),
        description: None,
        issue_id: Some("issue_1".to_owned()),
        kind: automation::ActionKind::AddComment,
        label_ids: Vec::new(),
        priority: None,
        project_id: None,
        project_name: None,
        project_summary: None,
        replace_labels: false,
        status_id: None,
        team_id: None,
        title: None,
        workflow_state_id: None,
    }
}

fn request(idempotency_key: &str) -> automation::CreateRuleRequest {
    automation::CreateRuleRequest {
        actions: vec![action()],
        conditions: Vec::new(),
        enabled: true,
        idempotency_key: idempotency_key.to_owned(),
        name: "Scheduled reminder".to_owned(),
        organization_id: "org_1".to_owned(),
        rule_id: "rule_1".to_owned(),
        trigger: automation::Trigger {
            event_types: Vec::new(),
            interval_seconds: Some(300),
            kind: automation::TriggerKind::Schedule,
            start_at: Some("2030-01-01T00:00:00Z".to_owned()),
        },
    }
}

#[tokio::test]
async fn postgres_preserves_idempotency_cas_dedupe_receipts_and_recurring_state() {
    let Some((database_url, schema_name, postgres)) = prepare().await else {
        return;
    };
    let create = request("create-rule");
    let value = storage::create_rule(
        &postgres,
        storage::CreateRuleInput {
            caller: "admin-api",
            actor: "usr_admin",
            operation: automation::CREATE_RULE_OPERATION,
            idempotency_key: &create.idempotency_key,
            organization_id: &create.organization_id,
            rule_id: &create.rule_id,
            name: &create.name,
            enabled: create.enabled,
            trigger: serde_json::to_value(&create.trigger).unwrap(),
            conditions: serde_json::to_value(&create.conditions).unwrap(),
            actions: serde_json::to_value(&create.actions).unwrap(),
            request: &create,
        },
    )
    .await
    .unwrap();
    assert_eq!(value["revision"], "1");
    assert_eq!(
        value,
        storage::create_rule(
            &postgres,
            storage::CreateRuleInput {
                caller: "admin-api",
                actor: "usr_admin",
                operation: automation::CREATE_RULE_OPERATION,
                idempotency_key: &create.idempotency_key,
                organization_id: &create.organization_id,
                rule_id: &create.rule_id,
                name: &create.name,
                enabled: create.enabled,
                trigger: serde_json::to_value(&create.trigger).unwrap(),
                conditions: serde_json::to_value(&create.conditions).unwrap(),
                actions: serde_json::to_value(&create.actions).unwrap(),
                request: &create,
            },
        )
        .await
        .unwrap()
    );
    let initial_dispatch = storage::pending_dispatches(&postgres, "org_1", 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        storage::mark_dispatch_enqueued(&postgres, &initial_dispatch, "job_initial")
            .await
            .unwrap()
    );
    let mut conflicting = create.clone();
    conflicting.name = "Different".to_owned();
    assert!(matches!(
        storage::create_rule(
            &postgres,
            storage::CreateRuleInput {
                caller: "admin-api",
                actor: "usr_admin",
                operation: automation::CREATE_RULE_OPERATION,
                idempotency_key: &conflicting.idempotency_key,
                organization_id: &conflicting.organization_id,
                rule_id: &conflicting.rule_id,
                name: &conflicting.name,
                enabled: conflicting.enabled,
                trigger: serde_json::to_value(&conflicting.trigger).unwrap(),
                conditions: serde_json::to_value(&conflicting.conditions).unwrap(),
                actions: serde_json::to_value(&conflicting.actions).unwrap(),
                request: &conflicting,
            },
        )
        .await,
        Err(storage::StorageError::Domain(
            storage::DomainFailure::IdempotencyConflict
        ))
    ));

    let mut rule_id_conflict = request("rule-id-conflict");
    rule_id_conflict.name = "Different name".to_owned();
    assert!(matches!(
        storage::create_rule(
            &postgres,
            storage::CreateRuleInput {
                caller: "admin-api",
                actor: "usr_admin",
                operation: automation::CREATE_RULE_OPERATION,
                idempotency_key: &rule_id_conflict.idempotency_key,
                organization_id: &rule_id_conflict.organization_id,
                rule_id: &rule_id_conflict.rule_id,
                name: &rule_id_conflict.name,
                enabled: rule_id_conflict.enabled,
                trigger: serde_json::to_value(&rule_id_conflict.trigger).unwrap(),
                conditions: serde_json::to_value(&rule_id_conflict.conditions).unwrap(),
                actions: serde_json::to_value(&rule_id_conflict.actions).unwrap(),
                request: &rule_id_conflict,
            },
        )
        .await,
        Err(storage::StorageError::Domain(
            storage::DomainFailure::RuleIdConflict
        ))
    ));

    let mut rule_name_conflict = request("rule-name-conflict");
    rule_name_conflict.rule_id = "rule_2".to_owned();
    assert!(matches!(
        storage::create_rule(
            &postgres,
            storage::CreateRuleInput {
                caller: "admin-api",
                actor: "usr_admin",
                operation: automation::CREATE_RULE_OPERATION,
                idempotency_key: &rule_name_conflict.idempotency_key,
                organization_id: &rule_name_conflict.organization_id,
                rule_id: &rule_name_conflict.rule_id,
                name: &rule_name_conflict.name,
                enabled: rule_name_conflict.enabled,
                trigger: serde_json::to_value(&rule_name_conflict.trigger).unwrap(),
                conditions: serde_json::to_value(&rule_name_conflict.conditions).unwrap(),
                actions: serde_json::to_value(&rule_name_conflict.actions).unwrap(),
                request: &rule_name_conflict,
            },
        )
        .await,
        Err(storage::StorageError::Domain(
            storage::DomainFailure::RuleNameConflict
        ))
    ));

    let timer = automation::ReceiveTimerRequest {
        dedupe_key: initial_dispatch.idempotency_key.clone(),
        organization_id: "org_1".to_owned(),
        rule_id: "rule_1".to_owned(),
        scheduled_for: "2030-01-01T00:00:00Z".to_owned(),
    };
    let first = storage::receive_timer(
        &postgres,
        &timer.organization_id,
        &timer.rule_id,
        &timer.dedupe_key,
        storage::parse_time(&timer.scheduled_for).unwrap(),
        &timer,
    )
    .await
    .unwrap();
    assert_eq!(first["accepted"], true);
    let duplicate = storage::receive_timer(
        &postgres,
        &timer.organization_id,
        &timer.rule_id,
        &timer.dedupe_key,
        storage::parse_time(&timer.scheduled_for).unwrap(),
        &timer,
    )
    .await
    .unwrap();
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(first["execution_ids"], duplicate["execution_ids"]);

    let mut changed_action = action();
    changed_action.comment_body = Some("Changed after trigger intake".to_owned());
    let update = automation::UpdateRuleRequest {
        actions: vec![changed_action],
        conditions: Vec::new(),
        expected_revision: "1".to_owned(),
        idempotency_key: "update-after-trigger".to_owned(),
        name: create.name.clone(),
        organization_id: create.organization_id.clone(),
        rule_id: create.rule_id.clone(),
        trigger: create.trigger.clone(),
    };
    let updated = storage::update_rule(
        &postgres,
        "admin-api",
        "usr_admin",
        automation::UPDATE_RULE_OPERATION,
        &update.idempotency_key,
        &update.organization_id,
        &update.rule_id,
        1,
        &update.name,
        serde_json::to_value(&update.trigger).unwrap(),
        serde_json::to_value(&update.conditions).unwrap(),
        serde_json::to_value(&update.actions).unwrap(),
        &update,
    )
    .await
    .unwrap();
    assert_eq!(updated["revision"], "2");

    let first_claim = storage::claim_executions(&postgres, "org_1", "executor-1", 10, 60)
        .await
        .unwrap();
    assert_eq!(first_claim.len(), 1);
    sqlx::query("UPDATE automation_executions SET lease_until=transaction_timestamp()-interval '1 second' WHERE execution_id=$1")
        .bind(first_claim[0].execution_id)
        .execute(postgres.pool())
        .await
        .unwrap();
    let claimed = storage::claim_executions(&postgres, "org_1", "executor-2", 10, 60)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt, 2);
    assert_eq!(
        claimed[0].actions[0]["comment_body"], "Scheduled reminder",
        "accepted executions retain the action snapshot from trigger intake"
    );
    assert!(matches!(
        storage::complete_execution(&postgres, &first_claim[0], true, None).await,
        Err(storage::StorageError::Runtime(_))
    ));
    storage::complete_execution(&postgres, &claimed[0], false, Some("projects_not_found"))
        .await
        .unwrap();
    let first_attempt_page =
        storage::inspect_execution(&postgres, "org_1", claimed[0].execution_id, 1, None)
            .await
            .unwrap();
    assert_eq!(
        first_attempt_page["attempt_receipts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(first_attempt_page["next_attempt_cursor"], "1");
    let receipt =
        storage::inspect_execution(&postgres, "org_1", claimed[0].execution_id, 100, None)
            .await
            .unwrap();
    assert_eq!(receipt["status"], "failed");
    assert_eq!(receipt["attempt_receipts"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["attempt_receipts"][0]["status"], "retryable");
    assert_eq!(receipt["attempt_receipts"][0]["failure"], "lease_expired");
    assert_eq!(receipt["attempt_receipts"][1]["status"], "failed");
    assert_eq!(receipt["next_attempt_cursor"], Value::Null);
    assert_eq!(receipt["actions"].as_array().unwrap().len(), 1);
    let rule = storage::get_rule(&postgres, "org_1", "rule_1")
        .await
        .unwrap();
    assert_eq!(rule["next_fire_at"], "2030-01-01T00:05:00Z");
    assert_eq!(
        storage::pending_dispatch_count(&postgres, "org_1")
            .await
            .unwrap(),
        1
    );
    let schedule_receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM automation_schedule_dispatches")
            .fetch_one(postgres.pool())
            .await
            .unwrap();
    assert_eq!(
        schedule_receipts, 2,
        "the accepted one-shot receipt and the next recurring receipt remain auditable"
    );

    cleanup(&database_url, &schema_name, postgres).await;
}
