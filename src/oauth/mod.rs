pub mod database;
pub mod endpoint;
pub mod error;
pub mod models;
pub mod primitives;
pub mod rhodos_scopes;
pub mod routes;
pub mod solicitor;
pub mod state;
pub mod templates;

#[derive(serde::Deserialize)]
#[serde(tag = "consent", rename_all = "lowercase")]
pub enum Consent {
    Allow,
    Deny,
}
