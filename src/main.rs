use std::{
    fmt::Display,
    net::SocketAddr,
};

use async_session::{async_trait, MemoryStore};
use axum::{
    extract::{FromRequestParts},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse},
    routing::{get},
    Json, RequestPartsExt, Router, TypedHeader,
};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use once_cell::sync::Lazy;
use oxide_auth::{
    endpoint::{OwnerConsent, Solicitation}, 
    primitives::registrar::RegisteredUrl
};
use oxide_auth::primitives::prelude::*;
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod oauth;
pub mod state;
use oauth::database::Database as AuthDB;
use state::AppState;

use crate::oauth::database::UserRecord;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut auth_db = AuthDB::new();
    let user = UserRecord::new("foo", "secret");
    let username = user.username().unwrap_or("foo".to_string());
    auth_db.register_user(user).await;
    let _ = auth_db.register_client(
        "LocalClient",
        Client::public(
            "LocalClient",
            RegisteredUrl::Semantic(
                "https://www.thunderclient.com/oauth/callback".parse().unwrap(),
            ),
            "account::read".parse().unwrap(),
        ),
        "LocalClient",
        &username,
    ).await;
    let state = oauth::state::State::new(auth_db.clone());
    let sessions = MemoryStore::new();
    let state = AppState {
        sessions,
        state,
        database: auth_db,
    };

    let app = Router::new()
        .nest("/oauth", crate::oauth::routes::routes())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    Unexecpected(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid token"),
            AuthError::Unexecpected(_) => (StatusCode::INTERNAL_SERVER_ERROR, "unknown internal error"),
        };
        let body = Json(serde_json::json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl From<WebError> for AuthError {
    fn from(err: WebError) -> Self {
        match err {
            WebError::Endpoint(_) => AuthError::Unexecpected("internal authorization error".to_string()),
            WebError::Header(h) => AuthError::Unexecpected(h.to_string()),
            WebError::Encoding => AuthError::MissingCredentials,
            WebError::Form => AuthError::MissingCredentials,
            WebError::Query => AuthError::MissingCredentials,
            WebError::Body => AuthError::MissingCredentials,
            WebError::Authorization => AuthError::InvalidToken,
            WebError::InternalError(opt) => match opt {
                Some(e) => AuthError::Unexecpected(e),
                None => AuthError::Unexecpected("unknown authentication error".to_string())
            },
        }
    }
}

fn consent_form(
    _: &mut OAuthRequest, solicitation: Solicitation,
) -> OwnerConsent<OAuthResponse> {
    let r = OAuthResponse::default()
            .body(
                consent_page_html(
                    "/authorize",
                    solicitation,
                ).as_str()
            )
            .content_type("text/html")
            .unwrap();
    OwnerConsent::InProgress(r)
}

// fn consent_decision(allowed: bool, _: Solicitation) -> OwnerConsent<impl WebResponse> {
//     if allowed {
//         OwnerConsent::Authorized("dummy user".into())
//     } else {
//         OwnerConsent::Denied
//     }
// }

pub fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
    tracing::debug!("enter consent_page_html()");
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
</form>
</html>"
        };
    }

    tracing::debug!("    solicitation.pre_grant()");
    let grant = solicitation.pre_grant();
    tracing::debug!("    solicitation.state()");
    let state = solicitation.state();

    let mut extra = vec![
        ("response_type", "code"),
        ("client_id", grant.client_id.as_str()),
        ("redirect_uri", grant.redirect_uri.as_str()),
    ];

    if let Some(state) = state {
        extra.push(("state", state));
    }
    
    tracing::debug!("    displaying template...");
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        serde_urlencoded::to_string(extra).unwrap(),
        &route,
    )
}
