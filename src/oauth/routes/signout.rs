use axum::{http::StatusCode, response::IntoResponse, routing::post, Router};
use axum_sessions::extractors::WritableSession;

pub fn routes() -> Router {
    Router::new().route("/", post(post_signout))
}

async fn post_signout(mut session: WritableSession) -> impl IntoResponse {
    session.destroy();

    StatusCode::OK
}
