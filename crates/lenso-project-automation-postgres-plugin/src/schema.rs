use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-project-automation",
    "migrations/001_create_project_automation.sql",
)];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}
