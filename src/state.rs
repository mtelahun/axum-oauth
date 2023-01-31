use async_session::MemoryStore;
use axum::extract::FromRef;

use crate::oauth::{state::State as AuthState, database::Database};

#[derive(Clone, axum_macros::FromRef)]
pub struct AppState {
    pub sessions: MemoryStore,
    pub state: AuthState,
    pub database: Database,
}

// impl FromRef<AppState> for Database {
//     fn from_ref(state: &AppState) -> Self {
//         Self::from_ref(&state.database)
//     }
// }
