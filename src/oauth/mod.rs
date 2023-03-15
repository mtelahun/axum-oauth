use serde::Deserialize;

pub mod database;
pub mod endpoint;
pub mod error;
pub mod models;
pub mod primitives;
pub mod routes;
pub mod scopes;
pub mod solicitor;
pub mod state;
pub mod templates;

#[derive(Debug, Deserialize)]
#[serde(tag = "consent", rename_all = "lowercase")]
pub enum Consent {
    Allow,
    Deny,
}
