use async_session::MemoryStore;
use axum::Router;
use std::net::TcpListener;
use tower_http::services::ServeDir;

pub mod oauth;
pub mod routes;
pub mod state;

use oauth::database::Database as AuthDB;
use secrecy::Secret;
use state::AppState;

pub async fn build_service(
    bind_address: Option<String>,
    server_port: u16,
) -> (Router, TcpListener) {
    let router = get_router().await;

    let addr = bind_address.unwrap_or_else(|| format!("0.0.0.0:{server_port}"));
    let listener = TcpListener::bind(addr)
        .map_err(|e| {
            eprintln!("unable to parse local address: {e}");
        })
        .unwrap();

    (router, listener)
}

pub async fn serve(app: Router, listener: TcpListener) {
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| eprintln!("{e}"))
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_router() -> Router {
    let mut auth_db = AuthDB::new();
    let _ = auth_db
        .register_user("bob", Secret::from("secret".to_string()), "Robert")
        .await;
    let _ = auth_db
        .register_public_client(
            "LocalClient",
            "https://www.thunderclient.com/oauth/callback",
            "account::read",
        )
        .await;
    let state = oauth::state::State::new(auth_db.clone());
    let sessions = MemoryStore::new();
    let state = AppState {
        sessions,
        state,
        database: auth_db,
    };

    Router::new()
        .nest_service("/assets", ServeDir::new("assets"))
        .nest("/oauth", crate::oauth::routes::routes())
        .nest("/api", routes::routes())
        .with_state(state)
}
