use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_oauth::{build_service, serve};
use oxide_auth_axum::WebError;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod oauth;
pub mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (app, listener) = build_service(None, 3000).await;
    serve(app, listener).await;
}

#[derive(Debug)]
enum AuthError {
    #[allow(dead_code)]
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    Unexecpected(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "missing credentials"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid token"),
            AuthError::Unexecpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "unknown internal error")
            }
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
            WebError::Endpoint(_) => {
                AuthError::Unexecpected("internal authorization error".to_string())
            }
            WebError::Header(h) => AuthError::Unexecpected(h.to_string()),
            WebError::Encoding => AuthError::MissingCredentials,
            WebError::Form => AuthError::MissingCredentials,
            WebError::Query => AuthError::MissingCredentials,
            WebError::Body => AuthError::MissingCredentials,
            WebError::Authorization => AuthError::InvalidToken,
            WebError::InternalError(opt) => match opt {
                Some(e) => AuthError::Unexecpected(e),
                None => AuthError::Unexecpected("unknown authentication error".to_string()),
            },
        }
    }
}
