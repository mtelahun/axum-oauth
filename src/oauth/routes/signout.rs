use axum::{http::StatusCode, response::IntoResponse, routing::post, Router};
use tower_sessions::Session;

pub fn routes() -> Router {
    Router::new().route("/", post(post_signout))
}

async fn post_signout(session: Session) -> impl IntoResponse {
    match session.flush().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
