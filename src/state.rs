use async_session::MemoryStore;

use crate::oauth::{database::Database, state::State as AuthState};

#[derive(Clone, axum_macros::FromRef)]
pub struct AppState {
    pub sessions: MemoryStore,
    pub state: AuthState,
    pub database: Database,
}
