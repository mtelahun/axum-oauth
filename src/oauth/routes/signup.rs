use super::{Callback, SignUpForm};
use crate::oauth::{
    database::Database,
    error::{Error, Result},
};
use axum::{
    extract::{Form, FromRef, Query, State},
    http::StatusCode,
    routing::post,
    Router,
};
use secrecy::Secret;

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/", post(post_signup))
}

async fn post_signup(
    State(mut db): State<Database>,
    _query: Option<Query<Callback<'_>>>,
    Form(user): Form<SignUpForm>,
) -> Result<StatusCode, Error> {
    if db.contains_user_name(&user.username).await {
        return Err(Error::ResourceConflict);
    }

    db.register_user(
        &user.username,
        Secret::from(user.password),
        &user.given_name,
    )
    .await;

    Ok(StatusCode::CREATED)
}
