use lenso_postgres_kit::{PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome};
use thiserror::Error;

use crate::schema::schema_plan;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectAutomationOperator;

impl ProjectAutomationOperator {
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, ProjectAutomationOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, schema_plan(schema.to_owned())?)
                .await?
                .setup()
                .await?,
        )
    }

    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, ProjectAutomationOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, schema_plan(schema.to_owned())?)
                .await?
                .upgrade()
                .await?,
        )
    }
}

#[derive(Debug, Error)]
pub enum ProjectAutomationOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
}
