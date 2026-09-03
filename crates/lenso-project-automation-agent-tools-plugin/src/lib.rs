//! Agent-facing Tools over an explicitly bound Project Automation capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_project_automation::{
    self as automation, CreateRuleRequest, DeleteRuleRequest, GetRuleRequest,
    InspectExecutionRequest, ListRulesRequest, SetRuleEnabledRequest, UpdateRuleRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const CREATE_RULE_TOOL: &str = "project_automation_create_rule";
pub const GET_RULE_TOOL: &str = "project_automation_get_rule";
pub const LIST_RULES_TOOL: &str = "project_automation_list_rules";
pub const UPDATE_RULE_TOOL: &str = "project_automation_update_rule";
pub const SET_RULE_ENABLED_TOOL: &str = "project_automation_set_rule_enabled";
pub const DELETE_RULE_TOOL: &str = "project_automation_delete_rule";
pub const INSPECT_EXECUTION_TOOL: &str = "project_automation_inspect_execution";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct ProjectAutomationAgentToolsPlugin {
    automation: Port<automation::ProjectAutomationClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl ProjectAutomationAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($future:expr, $tool:expr, $domain:path, $runtime:path) => {
                match $future.await {
                    Ok(response) => success($tool, &response),
                    Err($domain(error)) => Err(PluginError::domain(map_domain_error(&error))),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }

        match request.name.as_str() {
            GET_RULE_TOOL => {
                let arguments = decode::<GetRuleRequest>(&request)?;
                invoke!(
                    self.automation.get_rule_with_context(context, arguments),
                    GET_RULE_TOOL,
                    automation::ProjectAutomationGetRuleInvocationError::Domain,
                    automation::ProjectAutomationGetRuleInvocationError::Runtime
                )
            }
            LIST_RULES_TOOL => {
                let arguments = decode::<ListRulesRequest>(&request)?;
                invoke!(
                    self.automation.list_rules_with_context(context, arguments),
                    LIST_RULES_TOOL,
                    automation::ProjectAutomationListRulesInvocationError::Domain,
                    automation::ProjectAutomationListRulesInvocationError::Runtime
                )
            }
            INSPECT_EXECUTION_TOOL => {
                let arguments = decode::<InspectExecutionRequest>(&request)?;
                invoke!(
                    self.automation
                        .inspect_execution_with_context(context, arguments),
                    INSPECT_EXECUTION_TOOL,
                    automation::ProjectAutomationInspectExecutionInvocationError::Domain,
                    automation::ProjectAutomationInspectExecutionInvocationError::Runtime
                )
            }
            CREATE_RULE_TOOL => {
                let arguments = decode::<CreateRuleRequest>(&request)?;
                invoke!(
                    self.automation.create_rule_with_context(context, arguments),
                    CREATE_RULE_TOOL,
                    automation::ProjectAutomationCreateRuleInvocationError::Domain,
                    automation::ProjectAutomationCreateRuleInvocationError::Runtime
                )
            }
            UPDATE_RULE_TOOL => {
                let arguments = decode::<UpdateRuleRequest>(&request)?;
                invoke!(
                    self.automation.update_rule_with_context(context, arguments),
                    UPDATE_RULE_TOOL,
                    automation::ProjectAutomationUpdateRuleInvocationError::Domain,
                    automation::ProjectAutomationUpdateRuleInvocationError::Runtime
                )
            }
            SET_RULE_ENABLED_TOOL => {
                let arguments = decode::<SetRuleEnabledRequest>(&request)?;
                invoke!(
                    self.automation
                        .set_rule_enabled_with_context(context, arguments),
                    SET_RULE_ENABLED_TOOL,
                    automation::ProjectAutomationSetRuleEnabledInvocationError::Domain,
                    automation::ProjectAutomationSetRuleEnabledInvocationError::Runtime
                )
            }
            DELETE_RULE_TOOL => {
                let arguments = decode::<DeleteRuleRequest>(&request)?;
                invoke!(
                    self.automation.delete_rule_with_context(context, arguments),
                    DELETE_RULE_TOOL,
                    automation::ProjectAutomationDeleteRuleInvocationError::Domain,
                    automation::ProjectAutomationDeleteRuleInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_RULE_TOOL,
            "Get one automation rule and its current revision.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/get-rule-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_RULES_TOOL,
            "List automation rule summaries with an optional enabled filter and bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/list-rules-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            INSPECT_EXECUTION_TOOL,
            "Inspect one durable execution and a bounded cursor page of its attempts and action receipts.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/inspect-execution-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        rule_tool(
            CREATE_RULE_TOOL,
            "Create a bounded automation rule. Reuse the same idempotency_key when retrying the same intent.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/create-rule-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        rule_tool(
            UPDATE_RULE_TOOL,
            "Replace a rule definition using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/update-rule-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            SET_RULE_ENABLED_TOOL,
            "Enable or disable a rule using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/set-rule-enabled-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            DELETE_RULE_TOOL,
            "Delete a rule using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-project-automation/schemas/delete-rule-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Project Automation Tool schema must be valid JSON");
    definition(name, description, &schema, execution)
}

fn rule_tool(
    name: &str,
    description: &str,
    request_schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let mut schema: serde_json::Value = serde_json::from_str(
        &request_schema.replace("rule-response.schema.json#/$defs/", "#/$defs/"),
    )
    .expect("Project Automation rule Tool schema must be valid JSON");
    let rule_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../lenso-capability-project-automation/schemas/rule-response.schema.json"
    ))
    .expect("Project Automation rule response schema must be valid JSON");
    schema["$defs"] = rule_schema["$defs"].clone();
    definition(name, description, &schema, execution)
}

fn definition(
    name: &str,
    description: &str,
    schema: &serde_json::Value,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Project Automation Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "Project Automation Tool could not serialize its typed response: {error}"
            ),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Project Automation Tool metadata must be valid JSON"),
    })
}

trait DomainToolError {
    fn to_tool_error(&self) -> ExecuteError;
}

fn map_domain_error(error: &impl DomainToolError) -> ExecuteError {
    error.to_tool_error()
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Project Automation rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Project Automation Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_automation_error {
    ($($error:ty),+ $(,)?) => {
        $(
            impl DomainToolError for $error {
                fn to_tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::NotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::RuleIdConflict => rejected("rule_id_conflict"),
                        Self::RuleNameConflict => rejected("rule_name_conflict"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}

impl_automation_error!(
    automation::CreateRuleError,
    automation::GetRuleError,
    automation::ListRulesError,
    automation::UpdateRuleError,
    automation::SetRuleEnabledError,
    automation::DeleteRuleError,
    automation::InspectExecutionError,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_is_a_removable_adapter_with_one_business_requirement() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.project-automation.agent-tools"
        );
        let provided = descriptor["provided_capabilities"].as_array().unwrap();
        assert_eq!(provided.len(), 1);
        assert_eq!(provided[0]["capability_id"], "lenso.agent.tool-provider@2");
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.project-automation@1");
    }

    #[test]
    fn catalog_has_three_parallel_reads_and_four_exclusive_mutations() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 7);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            3
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            4
        );
        assert!(tools.iter().all(|tool| {
            let schema = tool.input_schema_json.as_str();
            !schema.contains("rule-response.schema.json")
                && !matches!(
                    tool.name.as_str(),
                    "project_automation_receive_event"
                        | "project_automation_receive_timer"
                        | "project_automation_reconcile"
                )
        }));
    }

    #[test]
    fn exact_capability_requests_decode_without_adapter_owned_business_fields() {
        let get = decode::<GetRuleRequest>(&request(
            GET_RULE_TOOL,
            r#"{"organization_id":"org-1","rule_id":"rule-1"}"#,
        ))
        .unwrap();
        assert_eq!(get.rule_id, "rule-1");

        assert!(decode::<GetRuleRequest>(&request(GET_RULE_TOOL, r#"{"rule_id":42}"#)).is_err());
    }

    #[test]
    fn authorization_not_found_and_revision_failures_remain_distinct() {
        assert_eq!(
            map_domain_error(&automation::GetRuleError::Forbidden),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&automation::GetRuleError::NotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&automation::UpdateRuleError::RevisionConflict)
        else {
            panic!("revision conflict must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "revision_conflict");
    }
}
