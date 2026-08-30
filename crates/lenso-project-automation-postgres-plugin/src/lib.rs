//! PostgreSQL-backed, bounded automation for Lenso Projects.

#![allow(
    clippy::items_after_test_module,
    clippy::ref_option,
    clippy::too_many_lines
)]

mod operator;
mod schema;
mod storage;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    time::Duration as StdDuration,
};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_jobs as jobs;
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_project_automation as automation;
use lenso_capability_projects as projects;
use lenso_capability_projects_collaboration as collaboration;
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use operator::{ProjectAutomationOperator, ProjectAutomationOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_RULE_ACTIONS: usize = 32;
const MAX_RULE_CONDITIONS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAutomationConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    admin_callers: Vec<String>,
    event_callers: Vec<String>,
    timer_callers: Vec<String>,
    execution_callers: Vec<String>,
    jobs_queue: String,
    execution_lease_seconds: i64,
    job_max_attempts: i64,
    max_reconcile_items: i64,
}

impl ProjectAutomationConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        admin_callers: Vec<String>,
        event_callers: Vec<String>,
        timer_callers: Vec<String>,
        execution_callers: Vec<String>,
        jobs_queue: impl Into<String>,
        execution_lease_seconds: i64,
        job_max_attempts: i64,
        max_reconcile_items: i64,
    ) -> Result<Self, ProjectAutomationConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            admin_callers,
            event_callers,
            timer_callers,
            execution_callers,
            jobs_queue: jobs_queue.into(),
            execution_lease_seconds,
            job_max_attempts,
            max_reconcile_items,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ProjectAutomationConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| ProjectAutomationConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(ProjectAutomationConfigError::InvalidSecretReference);
        }
        if !valid_id(&self.auth_issuer) {
            return Err(ProjectAutomationConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| ProjectAutomationConfigError::InvalidAuthPublicKey)?;
        let roles = [
            &self.admin_callers,
            &self.event_callers,
            &self.timer_callers,
            &self.execution_callers,
        ];
        if roles.into_iter().any(|callers| !valid_callers(callers)) {
            return Err(ProjectAutomationConfigError::InvalidCallers);
        }
        let total = self.admin_callers.len()
            + self.event_callers.len()
            + self.timer_callers.len()
            + self.execution_callers.len();
        let distinct = self
            .admin_callers
            .iter()
            .chain(&self.event_callers)
            .chain(&self.timer_callers)
            .chain(&self.execution_callers)
            .collect::<BTreeSet<_>>()
            .len();
        if distinct != total {
            return Err(ProjectAutomationConfigError::OverlappingCallers);
        }
        if !valid_id(&self.jobs_queue) {
            return Err(ProjectAutomationConfigError::InvalidJobsQueue);
        }
        if !(30..=3_600).contains(&self.execution_lease_seconds) {
            return Err(ProjectAutomationConfigError::InvalidLease);
        }
        if !(1..=100).contains(&self.job_max_attempts) {
            return Err(ProjectAutomationConfigError::InvalidJobAttempts);
        }
        if !(1..=100).contains(&self.max_reconcile_items) {
            return Err(ProjectAutomationConfigError::InvalidReconcileLimit);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Project Automation Auth verification key is invalid".to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProjectAutomationConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("caller lists must contain 1 to 64 unique exact Instance keys")]
    InvalidCallers,
    #[error("management, event, timer, and execution callers must be disjoint")]
    OverlappingCallers,
    #[error("invalid Jobs queue")]
    InvalidJobsQueue,
    #[error("execution lease must be between 30 and 3600 seconds")]
    InvalidLease,
    #[error("Jobs max attempts must be between 1 and 100")]
    InvalidJobAttempts,
    #[error("maximum reconcile items must be between 1 and 100")]
    InvalidReconcileLimit,
}

fn validate_config(config: &ProjectAutomationConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Project Automation configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedAutomation {
    postgres: OwnedPostgres,
}

#[lenso::plugin(lifecycle,configuration_schema="configuration.schema.json",validate=validate_config)]
#[derive(Clone)]
struct ProjectAutomationPlugin {
    #[config]
    config: ProjectAutomationConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    projects: Port<projects::ProjectsClient>,
    collaboration: Port<collaboration::ProjectsCollaborationClient>,
    jobs: Port<jobs::JobsClient>,
    prepared: Rc<RefCell<Option<PreparedAutomation>>>,
}

impl fmt::Debug for ProjectAutomationPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectAutomationPlugin")
            .field("schema", &self.config.schema)
            .field("jobs_queue", &self.config.jobs_queue)
            .field("prepared", &self.prepared.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(automation::ProjectAutomation)]
impl ProjectAutomationPlugin {}

#[derive(Clone, Debug)]
struct Authorized {
    caller: String,
    actor: String,
}

#[derive(Debug)]
enum AuthorizationFailure {
    Unauthenticated,
    Forbidden,
    Runtime(RuntimeFailure),
}

impl ProjectAutomationPlugin {
    fn prepared(&self) -> Result<PreparedAutomation, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Project Automation Plugin is not prepared".to_owned(),
            })
    }

    async fn authorize_management(
        &self,
        context: &Ctx,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<Authorized, AuthorizationFailure> {
        let caller = allowed_caller(context, &self.config.admin_callers)
            .ok_or(AuthorizationFailure::Forbidden)?;
        let actor = self
            .config
            .verifier()
            .map_err(AuthorizationFailure::Runtime)?
            .project_context::<AutomationActor>(
                context,
                automation::CAPABILITY_ID,
                operation,
                &UtcClock,
            )
            .map_err(|_| AuthorizationFailure::Unauthenticated)?
            .subject;
        if !valid_id(organization_id) || !valid_id(&actor) {
            return Err(AuthorizationFailure::Forbidden);
        }
        let membership = self
            .membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: actor.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                OrganizationMembershipInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: membership::CAPABILITY_ID,
                    })
                }
            })?;
        if !membership.active {
            return Err(AuthorizationFailure::Forbidden);
        }
        let decision = self
            .access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: actor.clone(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                AccessControlInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                AccessControlInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: access::CAPABILITY_ID,
                    })
                }
            })?;
        if !decision.allowed {
            return Err(AuthorizationFailure::Forbidden);
        }
        Ok(Authorized { caller, actor })
    }

    fn authorize_execution(&self, context: &Ctx) -> Result<Authorized, AuthorizationFailure> {
        let caller = allowed_caller(context, &self.config.execution_callers)
            .ok_or(AuthorizationFailure::Forbidden)?;
        let actor = self
            .config
            .verifier()
            .map_err(AuthorizationFailure::Runtime)?
            .project_context::<AutomationActor>(
                context,
                automation::CAPABILITY_ID,
                automation::RECONCILE_OPERATION,
                &UtcClock,
            )
            .map_err(|_| AuthorizationFailure::Unauthenticated)?
            .subject;
        if !valid_id(&actor) {
            return Err(AuthorizationFailure::Forbidden);
        }
        Ok(Authorized { caller, actor })
    }
}

trait AutomationError: Sized {
    fn unauthenticated() -> Self;
    fn forbidden() -> Self;
    fn invalid_request() -> Self;
    fn not_found() -> Self;
    fn revision_conflict() -> Self;
    fn idempotency_conflict() -> Self;
    fn rule_id_conflict() -> Self;
    fn rule_name_conflict() -> Self;
}

macro_rules! impl_automation_error {
    ($($kind:path),+ $(,)?) => {
        $(impl AutomationError for $kind {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn not_found() -> Self { Self::NotFound }
            fn revision_conflict() -> Self { Self::RevisionConflict }
            fn idempotency_conflict() -> Self { Self::IdempotencyConflict }
            fn rule_id_conflict() -> Self { Self::RuleIdConflict }
            fn rule_name_conflict() -> Self { Self::RuleNameConflict }
        })+
    };
}

impl_automation_error!(
    automation::CreateRuleError,
    automation::DeleteRuleError,
    automation::GetRuleError,
    automation::InspectExecutionError,
    automation::ListRulesError,
    automation::ReceiveEventError,
    automation::ReceiveTimerError,
    automation::ReconcileError,
    automation::SetRuleEnabledError,
    automation::UpdateRuleError,
);

fn auth_result<E: AutomationError>(
    result: Result<Authorized, AuthorizationFailure>,
) -> PluginResult<Authorized, E> {
    match result {
        Ok(value) => Ok(value),
        Err(AuthorizationFailure::Unauthenticated) => {
            Err(PluginError::domain(E::unauthenticated()))
        }
        Err(AuthorizationFailure::Forbidden) => Err(PluginError::domain(E::forbidden())),
        Err(AuthorizationFailure::Runtime(error)) => Err(PluginError::runtime(error)),
    }
}

fn map_storage<T, E: AutomationError>(
    result: Result<T, storage::StorageError>,
) -> PluginResult<T, E> {
    match result {
        Ok(value) => Ok(value),
        Err(storage::StorageError::Runtime(error)) => Err(PluginError::runtime(error)),
        Err(storage::StorageError::Domain(failure)) => Err(PluginError::domain(match failure {
            storage::DomainFailure::InvalidRequest => E::invalid_request(),
            storage::DomainFailure::NotFound => E::not_found(),
            storage::DomainFailure::RevisionConflict => E::revision_conflict(),
            storage::DomainFailure::IdempotencyConflict => E::idempotency_conflict(),
            storage::DomainFailure::RuleIdConflict => E::rule_id_conflict(),
            storage::DomainFailure::RuleNameConflict => E::rule_name_conflict(),
        })),
    }
}

fn decode<T: DeserializeOwned, E>(operation: &'static str, value: Value) -> PluginResult<T, E> {
    serde_json::from_value(value).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Project Automation `{operation}` projection failed: {error}"),
        })
    })
}

impl ProjectAutomationPlugin {
    async fn create_rule(
        &self,
        context: Ctx,
        request: automation::CreateRuleRequest,
    ) -> PluginResult<automation::CreateRuleResponse, automation::CreateRuleError> {
        let auth = auth_result(
            self.authorize_management(
                &context,
                automation::CREATE_RULE_OPERATION,
                &request.organization_id,
                "projects.automation.manage",
            )
            .await,
        )?;
        if !valid_create_rule(&request) {
            return Err(PluginError::domain(
                automation::CreateRuleError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let trigger = serde_json::to_value(&request.trigger).map_err(serialization_runtime)?;
        let conditions =
            serde_json::to_value(&request.conditions).map_err(serialization_runtime)?;
        let actions = serde_json::to_value(&request.actions).map_err(serialization_runtime)?;
        let value = map_storage(
            storage::create_rule(
                &prepared.postgres,
                storage::CreateRuleInput {
                    caller: &auth.caller,
                    actor: &auth.actor,
                    operation: automation::CREATE_RULE_OPERATION,
                    idempotency_key: &request.idempotency_key,
                    organization_id: &request.organization_id,
                    rule_id: &request.rule_id,
                    name: &request.name,
                    enabled: request.enabled,
                    trigger,
                    conditions,
                    actions,
                    request: &request,
                },
            )
            .await,
        )?;
        self.flush_schedules(
            &prepared,
            &context,
            &request.organization_id,
            self.config.max_reconcile_items,
        )
        .await
        .map_err(PluginError::runtime)?;
        decode("create_rule", value)
    }

    async fn get_rule(
        &self,
        context: Ctx,
        request: automation::GetRuleRequest,
    ) -> PluginResult<automation::GetRuleResponse, automation::GetRuleError> {
        let _auth = auth_result(
            self.authorize_management(
                &context,
                automation::GET_RULE_OPERATION,
                &request.organization_id,
                "projects.automation.read",
            )
            .await,
        )?;
        if !valid_id(&request.organization_id) || !valid_id(&request.rule_id) {
            return Err(PluginError::domain(
                automation::GetRuleError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "get_rule",
            map_storage(
                storage::get_rule(
                    &prepared.postgres,
                    &request.organization_id,
                    &request.rule_id,
                )
                .await,
            )?,
        )
    }

    async fn list_rules(
        &self,
        context: Ctx,
        request: automation::ListRulesRequest,
    ) -> PluginResult<automation::ListRulesResponse, automation::ListRulesError> {
        let _auth = auth_result(
            self.authorize_management(
                &context,
                automation::LIST_RULES_OPERATION,
                &request.organization_id,
                "projects.automation.read",
            )
            .await,
        )?;
        if !valid_id(&request.organization_id)
            || !(1..=100).contains(&request.limit)
            || request
                .after
                .as_ref()
                .is_some_and(|value| storage::parse_revision(value).is_err())
        {
            return Err(PluginError::domain(
                automation::ListRulesError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "list_rules",
            map_storage(
                storage::list_rules(
                    &prepared.postgres,
                    &request.organization_id,
                    request.enabled,
                    request.limit,
                    request.after.as_deref(),
                )
                .await,
            )?,
        )
    }

    async fn update_rule(
        &self,
        context: Ctx,
        request: automation::UpdateRuleRequest,
    ) -> PluginResult<automation::UpdateRuleResponse, automation::UpdateRuleError> {
        let auth = auth_result(
            self.authorize_management(
                &context,
                automation::UPDATE_RULE_OPERATION,
                &request.organization_id,
                "projects.automation.manage",
            )
            .await,
        )?;
        if !valid_update_rule(&request) {
            return Err(PluginError::domain(
                automation::UpdateRuleError::InvalidRequest,
            ));
        }
        let expected = storage::parse_revision(&request.expected_revision)
            .map_err(|_| PluginError::domain(automation::UpdateRuleError::InvalidRequest))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let value = map_storage(
            storage::update_rule(
                &prepared.postgres,
                &auth.caller,
                &auth.actor,
                automation::UPDATE_RULE_OPERATION,
                &request.idempotency_key,
                &request.organization_id,
                &request.rule_id,
                expected,
                &request.name,
                serde_json::to_value(&request.trigger).map_err(serialization_runtime)?,
                serde_json::to_value(&request.conditions).map_err(serialization_runtime)?,
                serde_json::to_value(&request.actions).map_err(serialization_runtime)?,
                &request,
            )
            .await,
        )?;
        self.flush_schedules(
            &prepared,
            &context,
            &request.organization_id,
            self.config.max_reconcile_items,
        )
        .await
        .map_err(PluginError::runtime)?;
        decode("update_rule", value)
    }

    async fn set_rule_enabled(
        &self,
        context: Ctx,
        request: automation::SetRuleEnabledRequest,
    ) -> PluginResult<automation::SetRuleEnabledResponse, automation::SetRuleEnabledError> {
        let auth = auth_result(
            self.authorize_management(
                &context,
                automation::SET_RULE_ENABLED_OPERATION,
                &request.organization_id,
                "projects.automation.manage",
            )
            .await,
        )?;
        if !valid_command_identity(
            &request.organization_id,
            &request.rule_id,
            &request.idempotency_key,
        ) {
            return Err(PluginError::domain(
                automation::SetRuleEnabledError::InvalidRequest,
            ));
        }
        let expected = storage::parse_revision(&request.expected_revision)
            .map_err(|_| PluginError::domain(automation::SetRuleEnabledError::InvalidRequest))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let value = map_storage(
            storage::set_enabled(
                &prepared.postgres,
                &auth.caller,
                &auth.actor,
                automation::SET_RULE_ENABLED_OPERATION,
                &request.idempotency_key,
                &request.organization_id,
                &request.rule_id,
                expected,
                request.enabled,
                &request,
            )
            .await,
        )?;
        self.flush_schedules(
            &prepared,
            &context,
            &request.organization_id,
            self.config.max_reconcile_items,
        )
        .await
        .map_err(PluginError::runtime)?;
        decode("set_rule_enabled", value)
    }

    async fn delete_rule(
        &self,
        context: Ctx,
        request: automation::DeleteRuleRequest,
    ) -> PluginResult<automation::DeleteRuleResponse, automation::DeleteRuleError> {
        let auth = auth_result(
            self.authorize_management(
                &context,
                automation::DELETE_RULE_OPERATION,
                &request.organization_id,
                "projects.automation.manage",
            )
            .await,
        )?;
        if !valid_command_identity(
            &request.organization_id,
            &request.rule_id,
            &request.idempotency_key,
        ) {
            return Err(PluginError::domain(
                automation::DeleteRuleError::InvalidRequest,
            ));
        }
        let expected = storage::parse_revision(&request.expected_revision)
            .map_err(|_| PluginError::domain(automation::DeleteRuleError::InvalidRequest))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "delete_rule",
            map_storage(
                storage::delete_rule(
                    &prepared.postgres,
                    &auth.caller,
                    &auth.actor,
                    automation::DELETE_RULE_OPERATION,
                    &request.idempotency_key,
                    &request.organization_id,
                    &request.rule_id,
                    expected,
                    &request,
                )
                .await,
            )?,
        )
    }

    async fn receive_event(
        &self,
        context: Ctx,
        request: automation::ReceiveEventRequest,
    ) -> PluginResult<automation::ReceiveEventResponse, automation::ReceiveEventError> {
        if allowed_caller(&context, &self.config.event_callers).is_none() {
            return Err(PluginError::domain(
                automation::ReceiveEventError::Forbidden,
            ));
        }
        if !valid_event(&request) {
            return Err(PluginError::domain(
                automation::ReceiveEventError::InvalidRequest,
            ));
        }
        let occurred_at = storage::parse_time(&request.occurred_at)
            .map_err(|_| PluginError::domain(automation::ReceiveEventError::InvalidRequest))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "receive_event",
            map_storage(
                storage::receive_event(
                    &prepared.postgres,
                    &request.organization_id,
                    &request.dedupe_key,
                    occurred_at,
                    &request,
                )
                .await,
            )?,
        )
    }

    async fn receive_timer(
        &self,
        context: Ctx,
        request: automation::ReceiveTimerRequest,
    ) -> PluginResult<automation::ReceiveTimerResponse, automation::ReceiveTimerError> {
        if allowed_caller(&context, &self.config.timer_callers).is_none() {
            return Err(PluginError::domain(
                automation::ReceiveTimerError::Forbidden,
            ));
        }
        if !valid_id(&request.organization_id)
            || !valid_id(&request.rule_id)
            || !valid_id(&request.dedupe_key)
        {
            return Err(PluginError::domain(
                automation::ReceiveTimerError::InvalidRequest,
            ));
        }
        let scheduled_for = storage::parse_time(&request.scheduled_for)
            .map_err(|_| PluginError::domain(automation::ReceiveTimerError::InvalidRequest))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "receive_timer",
            map_storage(
                storage::receive_timer(
                    &prepared.postgres,
                    &request.organization_id,
                    &request.rule_id,
                    &request.dedupe_key,
                    scheduled_for,
                    &request,
                )
                .await,
            )?,
        )
    }

    async fn inspect_execution(
        &self,
        context: Ctx,
        request: automation::InspectExecutionRequest,
    ) -> PluginResult<automation::InspectExecutionResponse, automation::InspectExecutionError> {
        let _auth = auth_result(
            self.authorize_management(
                &context,
                automation::INSPECT_EXECUTION_OPERATION,
                &request.organization_id,
                "projects.automation.read",
            )
            .await,
        )?;
        let execution_id = Uuid::parse_str(&request.execution_id)
            .map_err(|_| PluginError::domain(automation::InspectExecutionError::InvalidRequest))?;
        if !valid_id(&request.organization_id)
            || !(1..=100).contains(&request.attempt_limit)
            || request
                .attempt_after
                .as_ref()
                .is_some_and(|value| storage::parse_revision(value).is_err())
        {
            return Err(PluginError::domain(
                automation::InspectExecutionError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        decode(
            "inspect_execution",
            map_storage(
                storage::inspect_execution(
                    &prepared.postgres,
                    &request.organization_id,
                    execution_id,
                    request.attempt_limit,
                    request.attempt_after.as_deref(),
                )
                .await,
            )?,
        )
    }

    async fn reconcile(
        &self,
        context: Ctx,
        request: automation::ReconcileRequest,
    ) -> PluginResult<automation::ReconcileResponse, automation::ReconcileError> {
        let auth = auth_result(self.authorize_execution(&context))?;
        if !valid_id(&request.organization_id)
            || !(1..=self.config.max_reconcile_items).contains(&request.limit)
        {
            return Err(PluginError::domain(
                automation::ReconcileError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let mut schedule_enqueued = self
            .flush_schedules(&prepared, &context, &request.organization_id, request.limit)
            .await
            .map_err(PluginError::runtime)?;
        let executions = map_storage::<_, automation::ReconcileError>(
            storage::claim_executions(
                &prepared.postgres,
                &request.organization_id,
                &auth.caller,
                request.limit,
                self.config.execution_lease_seconds,
            )
            .await,
        )?;
        let claimed = i64::try_from(executions.len()).unwrap_or(i64::MAX);
        let mut succeeded = 0_i64;
        let mut failed = 0_i64;
        for execution in &executions {
            match self.execute_actions(&prepared, &context, execution).await {
                Ok(()) => {
                    map_storage::<_, automation::ReconcileError>(
                        storage::complete_execution(&prepared.postgres, execution, true, None)
                            .await,
                    )?;
                    succeeded += 1;
                }
                Err(ActionFailure::Domain(detail)) => {
                    map_storage::<_, automation::ReconcileError>(
                        storage::complete_execution(
                            &prepared.postgres,
                            execution,
                            false,
                            Some(&detail),
                        )
                        .await,
                    )?;
                    failed += 1;
                }
                Err(ActionFailure::Runtime(error)) => {
                    map_storage::<_, automation::ReconcileError>(
                        storage::release_execution_for_retry(
                            &prepared.postgres,
                            execution,
                            "dependency_runtime_failure",
                        )
                        .await,
                    )?;
                    return Err(PluginError::runtime(error));
                }
            }
        }
        schedule_enqueued += self
            .flush_schedules(&prepared, &context, &request.organization_id, request.limit)
            .await
            .map_err(PluginError::runtime)?;
        let schedule_pending = map_storage::<_, automation::ReconcileError>(
            storage::pending_dispatch_count(&prepared.postgres, &request.organization_id).await,
        )?;
        Ok(automation::ReconcileResponse {
            claimed,
            succeeded,
            failed,
            schedule_enqueued,
            schedule_pending,
        })
    }

    async fn execute_actions(
        &self,
        prepared: &PreparedAutomation,
        context: &Ctx,
        execution: &storage::ClaimedExecution,
    ) -> Result<(), ActionFailure> {
        for (index, action) in execution.actions.iter().enumerate() {
            let index = i32::try_from(index)
                .map_err(|_| ActionFailure::Domain("too_many_actions".to_owned()))?;
            let (status, idempotency_key) =
                storage::action_status(&prepared.postgres, execution.execution_id, index)
                    .await
                    .map_err(storage_action_failure)?;
            if status == "succeeded" {
                continue;
            }
            let action: automation::Action =
                serde_json::from_value(action.clone()).map_err(|_| {
                    ActionFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: automation::CAPABILITY_ID,
                    })
                })?;
            match self
                .execute_action(
                    context,
                    execution.execution_id,
                    index,
                    &idempotency_key,
                    &execution.payload,
                    &action,
                )
                .await
            {
                Ok(response) => storage::complete_action(
                    &prepared.postgres,
                    execution.execution_id,
                    index,
                    true,
                    Some(&response),
                    None,
                )
                .await
                .map_err(storage_action_failure)?,
                Err(ActionFailure::Domain(detail)) => {
                    storage::complete_action(
                        &prepared.postgres,
                        execution.execution_id,
                        index,
                        false,
                        None,
                        Some(&detail),
                    )
                    .await
                    .map_err(storage_action_failure)?;
                    return Err(ActionFailure::Domain(detail));
                }
                Err(ActionFailure::Runtime(error)) => return Err(ActionFailure::Runtime(error)),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_action(
        &self,
        context: &Ctx,
        execution_id: Uuid,
        action_index: i32,
        idempotency_key: &str,
        payload: &Value,
        action: &automation::Action,
    ) -> Result<Value, ActionFailure> {
        let organization_id = payload
            .get("organization_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ActionFailure::Domain("invalid_trigger_payload".to_owned()))?;
        let entity_kind = payload
            .get("entity_kind")
            .and_then(Value::as_str)
            .unwrap_or("schedule");
        let event_entity_id = payload.get("entity_id").and_then(Value::as_str);
        match action.kind {
            automation::ActionKind::AssignIssueToTeam | automation::ActionKind::MoveIssue => {
                let issue_id = action
                    .issue_id
                    .as_deref()
                    .or_else(|| {
                        (entity_kind == "issue")
                            .then_some(event_entity_id)
                            .flatten()
                    })
                    .ok_or_else(|| ActionFailure::Domain("issue_target_required".to_owned()))?;
                let issue = self
                    .projects
                    .get_issue_with_context(
                        context.clone(),
                        projects::GetIssueRequest {
                            organization_id: organization_id.to_owned(),
                            issue_ref: issue_id.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_get_issue_failure)?;
                let response = self
                    .projects
                    .move_issue_with_context(
                        context.clone(),
                        projects::MoveIssueRequest {
                            organization_id: organization_id.to_owned(),
                            issue_id: issue.issue_id,
                            expected_revision: issue.revision,
                            team_id: action.team_id.clone().unwrap_or(issue.team_id),
                            workflow_state_id: action
                                .workflow_state_id
                                .clone()
                                .unwrap_or(issue.workflow_state_id),
                            idempotency_key: idempotency_key.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_move_issue_failure)?;
                serde_json::to_value(response).map_err(serialization_action_failure)
            }
            automation::ActionKind::UpdateIssue => {
                let issue_id = action
                    .issue_id
                    .as_deref()
                    .or_else(|| {
                        (entity_kind == "issue")
                            .then_some(event_entity_id)
                            .flatten()
                    })
                    .ok_or_else(|| ActionFailure::Domain("issue_target_required".to_owned()))?;
                let issue = self
                    .projects
                    .get_issue_with_context(
                        context.clone(),
                        projects::GetIssueRequest {
                            organization_id: organization_id.to_owned(),
                            issue_ref: issue_id.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_get_issue_failure)?;
                let priority = action
                    .priority
                    .as_ref()
                    .map(|value| serde_json::to_value(value).and_then(serde_json::from_value))
                    .transpose()
                    .map_err(serialization_action_failure)?
                    .unwrap_or(issue.priority);
                let response = self
                    .projects
                    .update_issue_with_context(
                        context.clone(),
                        projects::UpdateIssueRequest {
                            organization_id: organization_id.to_owned(),
                            issue_id: issue.issue_id,
                            expected_revision: issue.revision,
                            title: action.title.clone().unwrap_or(issue.title),
                            description: action.description.clone().or(issue.description),
                            priority,
                            workflow_state_id: issue.workflow_state_id,
                            cycle_id: issue.cycle_id,
                            milestone_id: issue.milestone_id,
                            parent_issue_id: issue.parent_issue_id,
                            label_ids: if action.replace_labels {
                                action.label_ids.clone()
                            } else {
                                issue.label_ids
                            },
                            idempotency_key: idempotency_key.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_update_issue_failure)?;
                serde_json::to_value(response).map_err(serialization_action_failure)
            }
            automation::ActionKind::AddComment => {
                let issue_id = action
                    .issue_id
                    .as_deref()
                    .or_else(|| {
                        (entity_kind == "issue")
                            .then_some(event_entity_id)
                            .flatten()
                    })
                    .ok_or_else(|| ActionFailure::Domain("issue_target_required".to_owned()))?;
                let body = action
                    .comment_body
                    .clone()
                    .ok_or_else(|| ActionFailure::Domain("comment_body_required".to_owned()))?;
                let response = self
                    .collaboration
                    .add_comment_with_context(
                        context.clone(),
                        collaboration::AddCommentRequest {
                            organization_id: organization_id.to_owned(),
                            issue_id: issue_id.to_owned(),
                            comment_id: format!("automation-comment-{execution_id}-{action_index}"),
                            body,
                            idempotency_key: idempotency_key.to_owned(),
                        },
                    )
                    .await
                    .map_err(collaboration_add_comment_failure)?;
                serde_json::to_value(response).map_err(serialization_action_failure)
            }
            automation::ActionKind::UpdateProject => {
                let project_id = action
                    .project_id
                    .as_deref()
                    .or_else(|| {
                        (entity_kind == "project")
                            .then_some(event_entity_id)
                            .flatten()
                    })
                    .or_else(|| payload.get("project_id").and_then(Value::as_str))
                    .ok_or_else(|| ActionFailure::Domain("project_target_required".to_owned()))?;
                let project = self
                    .projects
                    .get_project_with_context(
                        context.clone(),
                        projects::GetProjectRequest {
                            organization_id: organization_id.to_owned(),
                            project_id: project_id.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_get_project_failure)?;
                let response = self
                    .projects
                    .update_project_with_context(
                        context.clone(),
                        projects::UpdateProjectRequest {
                            organization_id: organization_id.to_owned(),
                            project_id: project.project_id,
                            expected_revision: project.revision,
                            name: action.project_name.clone().unwrap_or(project.name),
                            summary: action.project_summary.clone().or(project.summary),
                            lead_team_id: project.lead_team_id,
                            team_ids: project.team_ids,
                            status_id: action.status_id.clone().unwrap_or(project.status_id),
                            milestone_id: project.milestone_id,
                            start_date: project.start_date,
                            target_date: project.target_date,
                            idempotency_key: idempotency_key.to_owned(),
                        },
                    )
                    .await
                    .map_err(projects_update_project_failure)?;
                serde_json::to_value(response).map_err(serialization_action_failure)
            }
        }
    }

    async fn flush_schedules(
        &self,
        prepared: &PreparedAutomation,
        context: &Ctx,
        organization_id: &str,
        limit: i64,
    ) -> Result<i64, RuntimeFailure> {
        let dispatches = storage::pending_dispatches(&prepared.postgres, organization_id, limit)
            .await
            .map_err(storage_runtime)?;
        let mut enqueued = 0_i64;
        for dispatch in dispatches {
            let available_at = dispatch.scheduled_for.format(&Rfc3339).map_err(|error| {
                RuntimeFailure::PluginFailure {
                    detail: format!(
                        "Project Automation schedule time cannot be formatted: {error}"
                    ),
                }
            })?;
            let payload = BTreeMap::from([
                (
                    "organization_id".to_owned(),
                    json!(dispatch.organization_id),
                ),
                ("rule_id".to_owned(), json!(dispatch.rule_id)),
                ("scheduled_for".to_owned(), json!(available_at)),
                ("dedupe_key".to_owned(), json!(dispatch.idempotency_key)),
            ]);
            match self
                .jobs
                .enqueue_with_context(
                    context.clone(),
                    jobs::EnqueueRequest {
                        queue: self.config.jobs_queue.clone(),
                        kind: "lenso.project-automation.timer".to_owned(),
                        payload,
                        idempotency_key: dispatch.idempotency_key.clone(),
                        available_at,
                        max_attempts: self.config.job_max_attempts,
                    },
                )
                .await
            {
                Ok(response) => {
                    let recorded = storage::mark_dispatch_enqueued(
                        &prepared.postgres,
                        &dispatch,
                        &response.job_id,
                    )
                    .await
                    .map_err(storage_runtime)?;
                    if recorded {
                        enqueued += 1;
                    }
                }
                Err(jobs::JobsEnqueueInvocationError::Runtime(error)) => {
                    storage::record_dispatch_failure(
                        &prepared.postgres,
                        &dispatch,
                        "jobs_runtime_failure",
                    )
                    .await
                    .map_err(storage_runtime)?;
                    return Err(error);
                }
                Err(jobs::JobsEnqueueInvocationError::Domain(_)) => {
                    storage::record_dispatch_failure(
                        &prepared.postgres,
                        &dispatch,
                        "jobs_contract_rejected",
                    )
                    .await
                    .map_err(storage_runtime)?;
                    return Err(RuntimeFailure::ProtocolViolation {
                        capability: jobs::CAPABILITY_ID,
                    });
                }
            }
        }
        Ok(enqueued)
    }
}

#[derive(Debug)]
enum ActionFailure {
    Domain(String),
    Runtime(RuntimeFailure),
}

fn storage_action_failure(error: storage::StorageError) -> ActionFailure {
    match error {
        storage::StorageError::Domain(error) => {
            ActionFailure::Runtime(RuntimeFailure::PluginFailure {
                detail: format!("Project Automation receipt invariant failed: {error:?}"),
            })
        }
        storage::StorageError::Runtime(error) => ActionFailure::Runtime(error),
    }
}

fn storage_runtime(error: storage::StorageError) -> RuntimeFailure {
    match error {
        storage::StorageError::Runtime(error) => error,
        storage::StorageError::Domain(error) => RuntimeFailure::PluginFailure {
            detail: format!("Project Automation state invariant failed: {error:?}"),
        },
    }
}

// These adapters intentionally match `Result::map_err`, which transfers the error by value.
#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: format!("Project Automation serialization failed: {error}"),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_action_failure(error: serde_json::Error) -> ActionFailure {
    ActionFailure::Runtime(RuntimeFailure::PluginFailure {
        detail: format!("Project Automation dependency projection failed: {error}"),
    })
}

macro_rules! dependency_failure_mapper {
    ($function:ident,$module:ident,$error:ident) => {
        fn $function(error: $module::$error) -> ActionFailure {
            match error {
                $module::$error::Runtime(error) => ActionFailure::Runtime(error),
                $module::$error::Domain(error) => ActionFailure::Domain(format!("{error:?}")),
            }
        }
    };
}

dependency_failure_mapper!(
    projects_get_issue_failure,
    projects,
    ProjectsGetIssueInvocationError
);
dependency_failure_mapper!(
    projects_move_issue_failure,
    projects,
    ProjectsMoveIssueInvocationError
);
dependency_failure_mapper!(
    projects_update_issue_failure,
    projects,
    ProjectsUpdateIssueInvocationError
);
dependency_failure_mapper!(
    projects_get_project_failure,
    projects,
    ProjectsGetProjectInvocationError
);
dependency_failure_mapper!(
    projects_update_project_failure,
    projects,
    ProjectsUpdateProjectInvocationError
);
dependency_failure_mapper!(
    collaboration_add_comment_failure,
    collaboration,
    ProjectsCollaborationAddCommentInvocationError
);

impl Lifecycle for ProjectAutomationPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedAutomation { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AutomationActor {
    subject: String,
}

impl TypedActor for AutomationActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

async fn resolve_secret(
    secrets: &secrets::SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("Project Automation database secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn allowed_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
    context.caller_instance().and_then(|caller| {
        allowed
            .iter()
            .any(|candidate| candidate == caller)
            .then(|| caller.to_owned())
    })
}

fn valid_callers(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_CALLERS
        && values.iter().all(|value| valid_id(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.contains('\0')
}

fn valid_optional_text(value: &Option<String>, max: usize) -> bool {
    value.as_ref().is_none_or(|value| valid_text(value, max))
}

fn valid_secret_reference(value: &str) -> bool {
    valid_id(value) && !value.starts_with('/') && !value.ends_with('/') && !value.contains("//")
}

fn valid_command_identity(organization_id: &str, rule_id: &str, idempotency_key: &str) -> bool {
    [organization_id, rule_id, idempotency_key]
        .into_iter()
        .all(valid_id)
}

fn valid_trigger(trigger: &automation::Trigger) -> bool {
    match trigger.kind {
        automation::TriggerKind::Event => {
            !trigger.event_types.is_empty()
                && trigger.event_types.len() <= 16
                && trigger.interval_seconds.is_none()
                && trigger.start_at.is_none()
        }
        automation::TriggerKind::Schedule => {
            trigger.event_types.is_empty()
                && trigger
                    .interval_seconds
                    .is_some_and(|value| (60..=31_536_000).contains(&value))
                && trigger
                    .start_at
                    .as_ref()
                    .is_none_or(|value| storage::parse_time(value).is_ok())
        }
    }
}

fn valid_conditions(conditions: &[automation::Condition]) -> bool {
    conditions.len() <= MAX_RULE_CONDITIONS
        && conditions.iter().all(|condition| {
            valid_text(&condition.value, 256)
                && (!matches!(condition.operator, automation::ConditionOperator::Contains)
                    || matches!(condition.field, automation::ConditionField::LabelId))
        })
}

fn valid_actions(actions: &[automation::Action]) -> bool {
    !actions.is_empty() && actions.len() <= MAX_RULE_ACTIONS && actions.iter().all(valid_action)
}

fn valid_action(action: &automation::Action) -> bool {
    let ids_valid = [
        &action.issue_id,
        &action.project_id,
        &action.team_id,
        &action.workflow_state_id,
        &action.status_id,
    ]
    .into_iter()
    .all(|value| value.as_ref().is_none_or(|value| valid_id(value)))
        && action.label_ids.len() <= 64
        && action.label_ids.iter().all(|value| valid_id(value))
        && action.label_ids.iter().collect::<BTreeSet<_>>().len() == action.label_ids.len();
    if !ids_valid
        || !valid_optional_text(&action.title, 1_000)
        || !valid_optional_text(&action.description, 20_000)
        || !valid_optional_text(&action.comment_body, 20_000)
        || !valid_optional_text(&action.project_name, 300)
        || !valid_optional_text(&action.project_summary, 4_000)
    {
        return false;
    }
    match action.kind {
        automation::ActionKind::AssignIssueToTeam => {
            action.team_id.is_some()
                && action.project_id.is_none()
                && action.workflow_state_id.is_none()
                && issue_update_fields_empty(action)
        }
        automation::ActionKind::MoveIssue => {
            (action.team_id.is_some() || action.workflow_state_id.is_some())
                && action.project_id.is_none()
                && issue_update_fields_empty(action)
        }
        automation::ActionKind::UpdateIssue => {
            action.team_id.is_none()
                && action.workflow_state_id.is_none()
                && action.project_id.is_none()
                && (action.title.is_some()
                    || action.description.is_some()
                    || action.priority.is_some()
                    || action.replace_labels)
                && action.comment_body.is_none()
                && project_update_fields_empty(action)
        }
        automation::ActionKind::AddComment => {
            action.comment_body.is_some()
                && action.project_id.is_none()
                && action.team_id.is_none()
                && action.workflow_state_id.is_none()
                && action.title.is_none()
                && action.description.is_none()
                && action.priority.is_none()
                && !action.replace_labels
                && action.label_ids.is_empty()
                && project_update_fields_empty(action)
        }
        automation::ActionKind::UpdateProject => {
            (action.project_name.is_some()
                || action.project_summary.is_some()
                || action.status_id.is_some())
                && action.issue_id.is_none()
                && action.team_id.is_none()
                && action.workflow_state_id.is_none()
                && action.title.is_none()
                && action.description.is_none()
                && action.priority.is_none()
                && !action.replace_labels
                && action.label_ids.is_empty()
                && action.comment_body.is_none()
        }
    }
}

fn issue_update_fields_empty(action: &automation::Action) -> bool {
    action.title.is_none()
        && action.description.is_none()
        && action.priority.is_none()
        && !action.replace_labels
        && action.label_ids.is_empty()
        && action.comment_body.is_none()
        && project_update_fields_empty(action)
}

fn project_update_fields_empty(action: &automation::Action) -> bool {
    action.project_name.is_none() && action.project_summary.is_none() && action.status_id.is_none()
}

fn valid_create_rule(request: &automation::CreateRuleRequest) -> bool {
    valid_command_identity(
        &request.organization_id,
        &request.rule_id,
        &request.idempotency_key,
    ) && valid_text(&request.name, 300)
        && valid_trigger(&request.trigger)
        && valid_conditions(&request.conditions)
        && valid_actions_for_trigger(&request.trigger, &request.actions)
}

fn valid_update_rule(request: &automation::UpdateRuleRequest) -> bool {
    valid_command_identity(
        &request.organization_id,
        &request.rule_id,
        &request.idempotency_key,
    ) && storage::parse_revision(&request.expected_revision).is_ok()
        && valid_text(&request.name, 300)
        && valid_trigger(&request.trigger)
        && valid_conditions(&request.conditions)
        && valid_actions_for_trigger(&request.trigger, &request.actions)
}

fn valid_actions_for_trigger(
    trigger: &automation::Trigger,
    actions: &[automation::Action],
) -> bool {
    valid_actions(actions)
        && (!matches!(trigger.kind, automation::TriggerKind::Schedule)
            || actions.iter().all(|action| match action.kind {
                automation::ActionKind::AssignIssueToTeam
                | automation::ActionKind::UpdateIssue
                | automation::ActionKind::MoveIssue
                | automation::ActionKind::AddComment => action.issue_id.is_some(),
                automation::ActionKind::UpdateProject => action.project_id.is_some(),
            }))
}

fn valid_event(request: &automation::ReceiveEventRequest) -> bool {
    [
        request.organization_id.as_str(),
        request.dedupe_key.as_str(),
        request.entity_id.as_str(),
    ]
    .into_iter()
    .all(valid_id)
        && [
            &request.project_id,
            &request.team_id,
            &request.workflow_state_id,
            &request.status_id,
        ]
        .into_iter()
        .all(|value| value.as_ref().is_none_or(|value| valid_id(value)))
        && request.label_ids.len() <= 64
        && request.label_ids.iter().all(|value| valid_id(value))
        && request.label_ids.iter().collect::<BTreeSet<_>>().len() == request.label_ids.len()
        && storage::parse_time(&request.occurred_at).is_ok()
        && matches!(
            (&request.entity_kind, &request.event_type),
            (
                automation::ReceiveEventRequestEntityKind::Issue,
                automation::ReceiveEventRequestEventType::IssueCreated
                    | automation::ReceiveEventRequestEventType::IssueUpdated
                    | automation::ReceiveEventRequestEventType::IssueMoved
                    | automation::ReceiveEventRequestEventType::IssueArchived
                    | automation::ReceiveEventRequestEventType::CommentAdded
            ) | (
                automation::ReceiveEventRequestEntityKind::Project,
                automation::ReceiveEventRequestEventType::ProjectCreated
                    | automation::ReceiveEventRequestEventType::ProjectUpdated
                    | automation::ReceiveEventRequestEventType::ProjectArchived
            )
        )
}

#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;

#[cfg(test)]
mod tests {
    use std::{any::Any, cell::Cell};

    use futures::future::LocalBoxFuture;
    use lenso_app_plan::{
        AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
        PluginInstancePlan, ResolvedAppPlan,
    };
    use lenso_auth_sdk::{ActorAssertionIssuer, FixedClock, Validity, audience};
    use lenso_kernel::{
        ActivateContext, CancellationToken, DeterministicDriver, InvocationContext, Kernel,
        NativeRequestEndpoint, NativeRequestFuture, PluginFuture, PluginLifecycle, ShutdownOutcome,
    };
    use lenso_native_adapter::{
        NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
    };
    use time::Duration;

    use super::*;

    const CALLER_PACKAGE: &str = "test.project-automation-caller";
    const DEPENDENCIES_PACKAGE: &str = "test.project-automation-dependencies";
    const PROJECTS_ONLY_PACKAGE: &str = "test.project-automation-projects-only";

    const AUTOMATION_OPERATIONS: &[&str] = &[
        automation::CREATE_RULE_OPERATION,
        automation::DELETE_RULE_OPERATION,
        automation::GET_RULE_OPERATION,
        automation::INSPECT_EXECUTION_OPERATION,
        automation::LIST_RULES_OPERATION,
        automation::RECEIVE_EVENT_OPERATION,
        automation::RECEIVE_TIMER_OPERATION,
        automation::RECONCILE_OPERATION,
        automation::SET_RULE_ENABLED_OPERATION,
        automation::UPDATE_RULE_OPERATION,
    ];
    const PROJECT_OPERATIONS: &[&str] = &[
        projects::ARCHIVE_ISSUE_OPERATION,
        projects::ARCHIVE_PROJECT_OPERATION,
        projects::CREATE_ISSUE_OPERATION,
        projects::CREATE_PROJECT_OPERATION,
        projects::GET_ISSUE_OPERATION,
        projects::GET_PROJECT_OPERATION,
        projects::LIST_ACTIVITY_OPERATION,
        projects::LIST_ISSUES_OPERATION,
        projects::LIST_PROJECTS_OPERATION,
        projects::MOVE_ISSUE_OPERATION,
        projects::PUT_EXTERNAL_LINK_OPERATION,
        projects::UPDATE_ISSUE_OPERATION,
        projects::UPDATE_PROJECT_OPERATION,
    ];
    const COLLABORATION_OPERATIONS: &[&str] = &[
        collaboration::ADD_COMMENT_OPERATION,
        collaboration::ADD_ISSUE_RELATION_OPERATION,
        collaboration::CREATE_PROJECT_UPDATE_OPERATION,
        collaboration::DELETE_COMMENT_OPERATION,
        collaboration::LIST_COMMENTS_OPERATION,
        collaboration::LIST_PROJECT_UPDATES_OPERATION,
        collaboration::REMOVE_ISSUE_RELATION_OPERATION,
        collaboration::UPDATE_COMMENT_OPERATION,
    ];
    const JOBS_OPERATIONS: &[&str] = &[
        jobs::CLAIM_OPERATION,
        jobs::COMPLETE_OPERATION,
        jobs::ENQUEUE_OPERATION,
        jobs::FAIL_OPERATION,
        jobs::INSPECT_OPERATION,
        jobs::RENEW_OPERATION,
    ];

    #[derive(Clone, Copy, Debug)]
    enum MembershipMode {
        Active,
        Domain,
    }

    #[derive(Clone, Copy, Debug)]
    enum AccessMode {
        Allowed,
        Denied,
    }

    #[derive(Clone, Copy, Debug)]
    enum ProjectsMode {
        Success,
        Domain,
        Runtime,
    }

    #[derive(Clone, Debug)]
    struct HarnessAutomationFactory {
        plugin: Rc<RefCell<Option<ProjectAutomationPlugin>>>,
    }

    impl NativePluginFactory for HarnessAutomationFactory {
        fn package_id(&self) -> &'static str {
            PACKAGE_ID
        }

        fn instantiate(
            &self,
            context: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            let plugin = ProjectAutomationPlugin::__lenso_construct(context)?;
            self.plugin.borrow_mut().replace(plugin.clone());
            let endpoint = Rc::new(automation::ProjectAutomationEndpoint::new(plugin.clone()))
                as Rc<dyn NativeRequestEndpoint>;
            Ok(NativePluginInstance::with_lifecycle(
                vec![endpoint],
                HarnessLifecycle { plugin },
            ))
        }
    }

    #[derive(Clone, Debug)]
    struct HarnessLifecycle {
        plugin: ProjectAutomationPlugin,
    }

    impl PluginLifecycle for HarnessLifecycle {
        fn activate(&self, context: ActivateContext) -> PluginFuture {
            let result = (|| {
                self.plugin.secrets.connect(context.dependencies())?;
                self.plugin.membership.connect(context.dependencies())?;
                self.plugin.access.connect(context.dependencies())?;
                self.plugin.projects.connect(context.dependencies())?;
                self.plugin.collaboration.connect(context.dependencies())?;
                self.plugin.jobs.connect(context.dependencies())?;
                Ok(())
            })();
            Box::pin(std::future::ready(result))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct EmptyFactory;

    impl NativePluginFactory for EmptyFactory {
        fn package_id(&self) -> &'static str {
            CALLER_PACKAGE
        }

        fn instantiate(
            &self,
            _: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::default())
        }
    }

    #[derive(Clone, Debug)]
    struct DependenciesFactory {
        membership: MembershipMode,
        access: AccessMode,
        projects: ProjectsMode,
        verifier: ActorAssertionVerifier,
        now: OffsetDateTime,
        observed_actor: Rc<Cell<bool>>,
    }

    impl NativePluginFactory for DependenciesFactory {
        fn package_id(&self) -> &'static str {
            DEPENDENCIES_PACKAGE
        }

        fn instantiate(
            &self,
            _: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::new(vec![
                Rc::new(PassiveEndpoint {
                    capability: secrets::CAPABILITY_ID,
                    descriptor: secrets::DESCRIPTOR_VERSION,
                    operations: &[secrets::RESOLVE_OPERATION],
                }),
                Rc::new(membership::OrganizationMembershipEndpoint::new(
                    FakeMembership(self.membership),
                )),
                Rc::new(access::AccessControlEndpoint::new(FakeAccess(self.access))),
                Rc::new(FakeProjectsEndpoint {
                    mode: self.projects,
                    verifier: self.verifier.clone(),
                    now: self.now,
                    observed_actor: Rc::clone(&self.observed_actor),
                    require_actor: true,
                }),
                Rc::new(PassiveEndpoint {
                    capability: collaboration::CAPABILITY_ID,
                    descriptor: collaboration::DESCRIPTOR_VERSION,
                    operations: COLLABORATION_OPERATIONS,
                }),
                Rc::new(PassiveEndpoint {
                    capability: jobs::CAPABILITY_ID,
                    descriptor: jobs::DESCRIPTOR_VERSION,
                    operations: JOBS_OPERATIONS,
                }),
            ]))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FakeMembership(MembershipMode);

    impl membership::OrganizationMembershipProvider for FakeMembership {
        fn check_membership(
            &self,
            _context: InvocationContext,
            _request: membership::CheckMembershipRequest,
        ) -> NativeRequestFuture<membership::OrganizationMembership> {
            let result = match self.0 {
                MembershipMode::Active => Ok(Ok(membership::CheckMembershipResponse {
                    active: true,
                    owner: false,
                })),
                MembershipMode::Domain => {
                    Ok(Err(membership::CheckMembershipError::OrganizationNotFound))
                }
            };
            Box::pin(std::future::ready(result))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FakeAccess(AccessMode);

    impl access::AccessControlProvider for FakeAccess {
        fn check_permission(
            &self,
            _context: InvocationContext,
            _request: access::CheckPermissionRequest,
        ) -> NativeRequestFuture<access::AccessControl> {
            Box::pin(std::future::ready(Ok(Ok(
                access::CheckPermissionResponse {
                    allowed: matches!(self.0, AccessMode::Allowed),
                    policy_revision: "1".to_owned(),
                },
            ))))
        }
    }

    #[derive(Debug)]
    struct PassiveEndpoint {
        capability: &'static str,
        descriptor: &'static str,
        operations: &'static [&'static str],
    }

    impl NativeRequestEndpoint for PassiveEndpoint {
        fn capability_id(&self) -> &'static str {
            self.capability
        }

        fn descriptor_version(&self) -> &'static str {
            self.descriptor
        }

        fn operations(&self) -> &'static [&'static str] {
            self.operations
        }

        fn invoke(
            &self,
            operation: &str,
            _request: Box<dyn Any>,
            _context: InvocationContext,
        ) -> LocalBoxFuture<'static, Result<Result<Box<dyn Any>, Box<dyn Any>>, RuntimeFailure>>
        {
            Box::pin(std::future::ready(Err(RuntimeFailure::UnknownOperation {
                capability: self.capability,
                operation: operation.to_owned(),
            })))
        }
    }

    #[derive(Debug)]
    struct FakeProjectsEndpoint {
        mode: ProjectsMode,
        verifier: ActorAssertionVerifier,
        now: OffsetDateTime,
        observed_actor: Rc<Cell<bool>>,
        require_actor: bool,
    }

    impl NativeRequestEndpoint for FakeProjectsEndpoint {
        fn capability_id(&self) -> &'static str {
            projects::CAPABILITY_ID
        }

        fn descriptor_version(&self) -> &'static str {
            projects::DESCRIPTOR_VERSION
        }

        fn operations(&self) -> &'static [&'static str] {
            PROJECT_OPERATIONS
        }

        fn invoke(
            &self,
            operation: &str,
            request: Box<dyn Any>,
            context: InvocationContext,
        ) -> LocalBoxFuture<'static, Result<Result<Box<dyn Any>, Box<dyn Any>>, RuntimeFailure>>
        {
            if operation == projects::LIST_PROJECTS_OPERATION {
                if request.downcast::<projects::ListProjectsRequest>().is_err() {
                    return Box::pin(std::future::ready(Err(RuntimeFailure::ProtocolViolation {
                        capability: projects::CAPABILITY_ID,
                    })));
                }
                return Box::pin(std::future::ready(Ok(Ok(
                    Box::new(projects::ListProjectsResponse {
                        items: Vec::new(),
                        next_cursor: None,
                    }) as Box<dyn Any>,
                ))));
            }
            if operation != projects::GET_ISSUE_OPERATION
                || request.downcast::<projects::GetIssueRequest>().is_err()
            {
                return Box::pin(std::future::ready(Err(RuntimeFailure::UnknownOperation {
                    capability: projects::CAPABILITY_ID,
                    operation: operation.to_owned(),
                })));
            }
            if self.require_actor
                && self
                    .verifier
                    .project_context::<TestProjectsActor>(
                        &context,
                        projects::CAPABILITY_ID,
                        projects::GET_ISSUE_OPERATION,
                        &FixedClock::new(self.now),
                    )
                    .is_err()
            {
                return Box::pin(std::future::ready(Ok(Err(Box::new(
                    projects::GetIssueError::Unauthenticated,
                )
                    as Box<dyn Any>))));
            }
            self.observed_actor.set(true);
            let result = match self.mode {
                ProjectsMode::Success => Ok(Ok(Box::new(projects::GetIssueResponse {
                    archived: false,
                    created_at: "2026-08-31T00:00:00Z".to_owned(),
                    cycle_id: None,
                    description: None,
                    identifier: "ENG-1".to_owned(),
                    issue_id: "issue_1".to_owned(),
                    label_ids: Vec::new(),
                    milestone_id: None,
                    organization_id: "org_1".to_owned(),
                    parent_issue_id: None,
                    previous_identifiers: Vec::new(),
                    priority: projects::Priority::High,
                    project_id: "project_1".to_owned(),
                    revision: "1".to_owned(),
                    team_id: "team_1".to_owned(),
                    title: "Issue".to_owned(),
                    updated_at: "2026-08-31T00:00:00Z".to_owned(),
                    workflow_state_id: "state_1".to_owned(),
                }) as Box<dyn Any>)),
                ProjectsMode::Domain => Ok(Err(
                    Box::new(projects::GetIssueError::NotFound) as Box<dyn Any>
                )),
                ProjectsMode::Runtime => Err(RuntimeFailure::Unavailable {
                    capability: projects::CAPABILITY_ID,
                }),
            };
            Box::pin(std::future::ready(result))
        }
    }

    #[derive(Debug)]
    struct TestProjectsActor;

    impl TypedActor for TestProjectsActor {
        fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
            if assertion.subject() != "service_automation" {
                return Err(ActorProjectionError::UnexpectedActorKind {
                    expected: "service".to_owned(),
                    actual: assertion.actor_kind().to_owned(),
                });
            }
            Ok(Self)
        }
    }

    #[derive(Clone, Debug)]
    struct ProjectsOnlyFactory;

    impl NativePluginFactory for ProjectsOnlyFactory {
        fn package_id(&self) -> &'static str {
            PROJECTS_ONLY_PACKAGE
        }

        fn instantiate(
            &self,
            _: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            let issuer = ActorAssertionIssuer::new("auth.test", b"projects-only-key");
            Ok(NativePluginInstance::new(vec![Rc::new(
                FakeProjectsEndpoint {
                    mode: ProjectsMode::Success,
                    verifier: issuer.verifier(),
                    now: OffsetDateTime::now_utc(),
                    observed_actor: Rc::new(Cell::new(false)),
                    require_actor: false,
                },
            )]))
        }
    }

    fn configuration(issuer: &ActorAssertionIssuer) -> String {
        serde_json::json!({
            "schema": "project_automation",
            "database_url_secret": "project-automation/database-url",
            "auth_issuer": "auth.test",
            "auth_assertion_public_key": issuer.public_key_base64(),
            "admin_callers": ["admin"],
            "event_callers": ["event-ingress"],
            "timer_callers": ["timer-ingress"],
            "execution_callers": ["automation-executor"],
            "jobs_queue": "project-automation",
            "execution_lease_seconds": 60,
            "job_max_attempts": 5,
            "max_reconcile_items": 20
        })
        .to_string()
    }

    fn composition(issuer: &ActorAssertionIssuer) -> ResolvedAppPlan {
        let admin = PluginInstancePlan::new("admin", CALLER_PACKAGE).with_requirement(
            CapabilityRequirementPlan::one(
                automation::CAPABILITY_ID,
                automation::DESCRIPTOR_VERSION,
            ),
        );
        let wrong = PluginInstancePlan::new("wrong", CALLER_PACKAGE).with_requirement(
            CapabilityRequirementPlan::one(
                automation::CAPABILITY_ID,
                automation::DESCRIPTOR_VERSION,
            ),
        );
        let plugin = PluginInstancePlan::new("automation", PACKAGE_ID)
            .with_configuration(configuration(issuer))
            .with_capability(CapabilityEndpointPlan::new(
                automation::CAPABILITY_ID,
                automation::DESCRIPTOR_VERSION,
                AUTOMATION_OPERATIONS.iter().copied(),
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                membership::CAPABILITY_ID,
                membership::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                access::CAPABILITY_ID,
                access::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                projects::CAPABILITY_ID,
                projects::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                collaboration::CAPABILITY_ID,
                collaboration::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                jobs::CAPABILITY_ID,
                jobs::DESCRIPTOR_VERSION,
            ));
        let dependencies = PluginInstancePlan::new("dependencies", DEPENDENCIES_PACKAGE)
            .with_capability(CapabilityEndpointPlan::new(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
                [secrets::RESOLVE_OPERATION],
            ))
            .with_capability(CapabilityEndpointPlan::new(
                membership::CAPABILITY_ID,
                membership::DESCRIPTOR_VERSION,
                [membership::CHECK_MEMBERSHIP_OPERATION],
            ))
            .with_capability(CapabilityEndpointPlan::new(
                access::CAPABILITY_ID,
                access::DESCRIPTOR_VERSION,
                [access::CHECK_PERMISSION_OPERATION],
            ))
            .with_capability(CapabilityEndpointPlan::new(
                projects::CAPABILITY_ID,
                projects::DESCRIPTOR_VERSION,
                PROJECT_OPERATIONS.iter().copied(),
            ))
            .with_capability(CapabilityEndpointPlan::new(
                collaboration::CAPABILITY_ID,
                collaboration::DESCRIPTOR_VERSION,
                COLLABORATION_OPERATIONS.iter().copied(),
            ))
            .with_capability(CapabilityEndpointPlan::new(
                jobs::CAPABILITY_ID,
                jobs::DESCRIPTOR_VERSION,
                JOBS_OPERATIONS.iter().copied(),
            ));
        let mut bindings = vec![
            CapabilityBinding::new(
                "admin",
                automation::CAPABILITY_ID,
                automation::DESCRIPTOR_VERSION,
                "automation",
            ),
            CapabilityBinding::new(
                "wrong",
                automation::CAPABILITY_ID,
                automation::DESCRIPTOR_VERSION,
                "automation",
            ),
        ];
        for (capability, descriptor) in [
            (secrets::CAPABILITY_ID, secrets::DESCRIPTOR_VERSION),
            (membership::CAPABILITY_ID, membership::DESCRIPTOR_VERSION),
            (access::CAPABILITY_ID, access::DESCRIPTOR_VERSION),
            (projects::CAPABILITY_ID, projects::DESCRIPTOR_VERSION),
            (
                collaboration::CAPABILITY_ID,
                collaboration::DESCRIPTOR_VERSION,
            ),
            (jobs::CAPABILITY_ID, jobs::DESCRIPTOR_VERSION),
        ] {
            bindings.push(CapabilityBinding::new(
                "automation",
                capability,
                descriptor,
                "dependencies",
            ));
        }
        AppComposition::new(vec![admin, wrong, plugin, dependencies], bindings)
            .resolve()
            .expect("Project Automation fake-provider Composition resolves")
    }

    fn signed_context(
        app: &lenso_kernel::NativeApp,
        issuer: &ActorAssertionIssuer,
        subject: &str,
        capability: &str,
        operation: &str,
    ) -> InvocationContext {
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            subject,
            "service",
            "test",
            [audience(capability, operation)],
            Validity::new(now - Duration::seconds(1), now + Duration::minutes(1)).unwrap(),
            BTreeMap::new(),
        );
        assertion
            .attach(app.invocation_context(None, CancellationToken::new()))
            .unwrap()
    }

    fn get_rule_request() -> automation::GetRuleRequest {
        automation::GetRuleRequest {
            organization_id: "org_1".to_owned(),
            rule_id: "rule_1".to_owned(),
        }
    }

    fn start_harness(
        driver: &DeterministicDriver,
        issuer: &ActorAssertionIssuer,
        membership: MembershipMode,
        access: AccessMode,
        projects: ProjectsMode,
        observed_actor: Rc<Cell<bool>>,
    ) -> (
        lenso_kernel::NativeApp,
        Rc<RefCell<Option<ProjectAutomationPlugin>>>,
    ) {
        let plugin = Rc::new(RefCell::new(None));
        let app = driver
            .run(Kernel::start_native(
                composition(issuer),
                driver.clone(),
                NativePluginRegistry::new()
                    .with_factory(EmptyFactory)
                    .with_factory(HarnessAutomationFactory {
                        plugin: Rc::clone(&plugin),
                    })
                    .with_factory(DependenciesFactory {
                        membership,
                        access,
                        projects,
                        verifier: issuer.verifier(),
                        now: OffsetDateTime::now_utc(),
                        observed_actor,
                    }),
            ))
            .unwrap();
        (app, plugin)
    }

    #[test]
    fn descriptor_is_exact_and_auth_is_direct_not_a_stale_port() {
        let descriptor: Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(provided, BTreeSet::from([automation::CAPABILITY_ID]));
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            descriptor["required_capabilities"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert!(
            descriptor["required_capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .all(|value| value["cardinality"] == "one")
        );
        assert_eq!(
            required,
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                membership::CAPABILITY_ID,
                access::CAPABILITY_ID,
                projects::CAPABILITY_ID,
                collaboration::CAPABILITY_ID,
                jobs::CAPABILITY_ID,
            ])
        );
        assert_eq!(automation::DESCRIPTOR_VERSION, "1.0.0");
    }

    #[test]
    fn configuration_requires_independent_exact_execution_authority() {
        let issuer = ActorAssertionIssuer::new("auth.test", b"automation-test-key");
        let mut config: ProjectAutomationConfig =
            serde_json::from_str(&configuration(&issuer)).unwrap();
        config.execution_callers = config.admin_callers.clone();
        assert_eq!(
            config.validate(),
            Err(ProjectAutomationConfigError::OverlappingCallers)
        );
    }

    #[test]
    fn kernel_maps_direct_auth_membership_and_access_without_touching_storage() {
        let driver = DeterministicDriver::new();
        let issuer = ActorAssertionIssuer::new("auth.test", b"automation-test-key");
        let (app, _) = start_harness(
            &driver,
            &issuer,
            MembershipMode::Active,
            AccessMode::Allowed,
            ProjectsMode::Success,
            Rc::new(Cell::new(false)),
        );
        let unauthenticated = driver
            .run(app.invoke::<automation::ProjectAutomationGetRule>(
                "admin",
                automation::GET_RULE_OPERATION,
                get_rule_request(),
            ))
            .unwrap();
        assert_eq!(
            unauthenticated,
            Err(automation::GetRuleError::Unauthenticated)
        );
        let context = signed_context(
            &app,
            &issuer,
            "admin_1",
            automation::CAPABILITY_ID,
            automation::GET_RULE_OPERATION,
        );
        let forbidden = driver
            .run(
                app.invoke_with_context::<automation::ProjectAutomationGetRule>(
                    "wrong",
                    automation::GET_RULE_OPERATION,
                    context,
                    get_rule_request(),
                ),
            )
            .unwrap();
        assert_eq!(forbidden, Err(automation::GetRuleError::Forbidden));
        assert_eq!(
            driver.run(app.shutdown(StdDuration::from_secs(1))),
            ShutdownOutcome::Clean
        );

        let (app, _) = start_harness(
            &driver,
            &issuer,
            MembershipMode::Active,
            AccessMode::Denied,
            ProjectsMode::Success,
            Rc::new(Cell::new(false)),
        );
        let context = signed_context(
            &app,
            &issuer,
            "admin_1",
            automation::CAPABILITY_ID,
            automation::GET_RULE_OPERATION,
        );
        let denied = driver
            .run(
                app.invoke_with_context::<automation::ProjectAutomationGetRule>(
                    "admin",
                    automation::GET_RULE_OPERATION,
                    context,
                    get_rule_request(),
                ),
            )
            .unwrap();
        assert_eq!(denied, Err(automation::GetRuleError::Forbidden));
        assert_eq!(
            driver.run(app.shutdown(StdDuration::from_secs(1))),
            ShutdownOutcome::Clean
        );

        let (app, _) = start_harness(
            &driver,
            &issuer,
            MembershipMode::Domain,
            AccessMode::Allowed,
            ProjectsMode::Success,
            Rc::new(Cell::new(false)),
        );
        let context = signed_context(
            &app,
            &issuer,
            "admin_1",
            automation::CAPABILITY_ID,
            automation::GET_RULE_OPERATION,
        );
        let runtime = driver.run(
            app.invoke_with_context::<automation::ProjectAutomationGetRule>(
                "admin",
                automation::GET_RULE_OPERATION,
                context,
                get_rule_request(),
            ),
        );
        assert!(matches!(
            runtime,
            Err(RuntimeFailure::ProtocolViolation { capability })
                if capability == membership::CAPABILITY_ID
        ));
        assert_eq!(
            driver.run(app.shutdown(StdDuration::from_secs(1))),
            ShutdownOutcome::Clean
        );
    }

    #[test]
    fn kernel_ports_forward_actor_and_preserve_projects_domain_and_runtime() {
        let driver = DeterministicDriver::new();
        let issuer = ActorAssertionIssuer::new("auth.test", b"automation-test-key");
        for mode in [ProjectsMode::Domain, ProjectsMode::Runtime] {
            let observed_actor = Rc::new(Cell::new(false));
            let (app, handle) = start_harness(
                &driver,
                &issuer,
                MembershipMode::Active,
                AccessMode::Allowed,
                mode,
                Rc::clone(&observed_actor),
            );
            let plugin = handle.borrow().clone().unwrap();
            let context = signed_context(
                &app,
                &issuer,
                "service_automation",
                projects::CAPABILITY_ID,
                projects::GET_ISSUE_OPERATION,
            );
            let action = automation::Action {
                comment_body: None,
                description: None,
                issue_id: Some("issue_1".to_owned()),
                kind: automation::ActionKind::MoveIssue,
                label_ids: Vec::new(),
                priority: None,
                project_id: None,
                project_name: None,
                project_summary: None,
                replace_labels: false,
                status_id: None,
                team_id: Some("team_2".to_owned()),
                title: None,
                workflow_state_id: None,
            };
            let result = driver.run(plugin.execute_action(
                &context,
                Uuid::nil(),
                0,
                "pa-action-test",
                &json!({"organization_id":"org_1","entity_kind":"issue","entity_id":"issue_1"}),
                &action,
            ));
            match mode {
                ProjectsMode::Domain => {
                    assert!(
                        matches!(result, Err(ActionFailure::Domain(detail)) if detail.contains("NotFound"))
                    );
                }
                ProjectsMode::Runtime => assert!(matches!(
                    result,
                    Err(ActionFailure::Runtime(RuntimeFailure::Unavailable { capability }))
                        if capability == projects::CAPABILITY_ID
                )),
                ProjectsMode::Success => unreachable!(),
            }
            assert!(observed_actor.get());
            assert_eq!(
                driver.run(app.shutdown(StdDuration::from_secs(1))),
                ShutdownOutcome::Clean
            );
        }
    }

    #[test]
    fn removing_automation_leaves_projects_composed_and_callable() {
        let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE).with_requirement(
            CapabilityRequirementPlan::one(projects::CAPABILITY_ID, projects::DESCRIPTOR_VERSION),
        );
        let projects_provider = PluginInstancePlan::new("projects", PROJECTS_ONLY_PACKAGE)
            .with_capability(CapabilityEndpointPlan::new(
                projects::CAPABILITY_ID,
                projects::DESCRIPTOR_VERSION,
                PROJECT_OPERATIONS.iter().copied(),
            ));
        let plan = AppComposition::new(
            vec![caller, projects_provider],
            vec![CapabilityBinding::new(
                "caller",
                projects::CAPABILITY_ID,
                projects::DESCRIPTOR_VERSION,
                "projects",
            )],
        )
        .resolve()
        .unwrap();
        assert!(
            plan.plugin_instances()
                .iter()
                .all(|instance| instance.package_id() != PACKAGE_ID)
        );
        let driver = DeterministicDriver::new();
        let app = driver
            .run(Kernel::start_native(
                plan,
                driver.clone(),
                NativePluginRegistry::new()
                    .with_factory(EmptyFactory)
                    .with_factory(ProjectsOnlyFactory),
            ))
            .unwrap();
        let response = driver
            .run(app.invoke::<projects::ProjectsListProjects>(
                "caller",
                projects::LIST_PROJECTS_OPERATION,
                projects::ListProjectsRequest {
                    after: None,
                    include_archived: false,
                    limit: 10,
                    organization_id: "org_1".to_owned(),
                    team_id: None,
                },
            ))
            .unwrap()
            .unwrap();
        assert!(response.items.is_empty());
        assert_eq!(
            driver.run(app.shutdown(StdDuration::from_secs(1))),
            ShutdownOutcome::Clean
        );
    }

    #[test]
    fn rules_are_bounded_and_schedule_actions_require_explicit_targets() {
        let trigger = automation::Trigger {
            event_types: Vec::new(),
            interval_seconds: Some(300),
            kind: automation::TriggerKind::Schedule,
            start_at: None,
        };
        let action = automation::Action {
            comment_body: Some("Scheduled reminder".to_owned()),
            description: None,
            issue_id: None,
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
        };
        assert!(!valid_actions_for_trigger(
            &trigger,
            std::slice::from_ref(&action)
        ));
        let mut targeted = action;
        targeted.issue_id = Some("issue_1".to_owned());
        assert!(valid_actions_for_trigger(&trigger, &[targeted]));
    }
}
