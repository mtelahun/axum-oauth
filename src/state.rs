use async_session::MemoryStore;

use crate::oauth::state::State as AuthState;

#[derive(Clone, axum_macros::FromRef)]
pub struct AppState {
    store: MemoryStore,
    state: AuthState,
}
