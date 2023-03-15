use async_session::MemoryStore;
use axum::Router;
use std::net::TcpListener;

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

    let mut addr = format!("0.0.0.0:{server_port}");
    if bind_address.is_some() {
        addr = bind_address.unwrap();
    }
    let listener = TcpListener::bind(addr)
        .map_err(|e| {
            eprintln!("unable to parse local address: {e}");
        })
        .unwrap();

    (router, listener)
}

pub async fn serve(app: Router, listener: TcpListener) {
    axum::Server::from_tcp(listener)
        .map_err(|e| eprintln!("{e}"))
        .unwrap()
        .serve(app.into_make_service())
        .await
        .unwrap();
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
        .nest("/oauth", crate::oauth::routes::routes())
        .nest("/api", routes::routes())
        .with_state(state)
}
